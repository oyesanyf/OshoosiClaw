use super::*;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use hmac::{Hmac, Mac};
use osoosi_behavioral::{EmbeddingGemma2Engine, MatryoshkaDim};
use osoosi_types::{ArmRole, HostSecurityEvent, OctopusSecurityError};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

// ============================================================================
// 4. Loopback & Local IPC Service-Identity & Operation Authorizer (Path 6)
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LocalServiceIdentity {
    OllamaLocalAiService,
    ChromeDevToolsBrowserDebug,
    DockerEngineControlPlane,
    WindowsPrivilegedNamedPipe,
    UnixPrivilegedControlSocket,
    OsoosiDashboardService,
    UnknownLoopbackService { host_port: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LocalServiceOperation {
    ReadOnlyInferenceOrStatus,
    ModelOrConfigMutation,
    BrowserSessionControl,
    HostContainerControl,
    PrivilegedOsPipeAccess,
    UnclassifiedLocalOperation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoopbackClassification {
    pub is_local_or_ipc: bool,
    pub service_identity: LocalServiceIdentity,
    pub service_operation: LocalServiceOperation,
    pub requires_privileged_capability: bool,
    pub mapped_cedar_action: CedarAction,
}

pub struct LoopbackIpcAuthorizer;

impl LoopbackIpcAuthorizer {
    /// Mathematically classifies a URL host as loopback/unspecified. Accepts bracketed IPv6 literals as
    /// returned by `url::Url::host_str()` (e.g. `[::1]`), IPv4-mapped IPv6 (`::ffff:127.0.0.1`), the
    /// whole `127.0.0.0/8` block, `0.0.0.0` / `::`, and the reserved `localhost` / `*.localhost` names
    /// (RFC 6761). Never relies on partial string prefixes.
    pub fn is_loopback_or_unspecified_host(host: &str) -> bool {
        let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
        let h = h.trim_start_matches('[').trim_end_matches(']');
        if h == "localhost" || h.ends_with(".localhost") {
            return true;
        }
        match h.parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V4(v4)) => v4.is_loopback() || v4.is_unspecified(),
            Ok(std::net::IpAddr::V6(v6)) => {
                v6.is_loopback()
                    || v6.is_unspecified()
                    || v6
                        .to_ipv4_mapped()
                        .map(|v4| v4.is_loopback() || v4.is_unspecified())
                        .unwrap_or(false)
            }
            Err(_) => false,
        }
    }

    /// Builds a canonical `http://authority[:port]/path` endpoint from a telemetry destination field
    /// (Sysmon `DestinationHostname` / `DestinationIp`) and port. The destination may already carry a
    /// scheme, an explicit port, and/or a request path (e.g. `127.0.0.1:11434/api/generate`); the port
    /// is only inserted when the authority has none, and is never appended after the path. Bare IPv6
    /// literals are bracketed so the resulting URL parses unambiguously.
    pub fn build_network_target(destination: &str, port: u16) -> String {
        let dest = destination.trim();
        if dest.contains("://") {
            return dest.to_string();
        }
        if dest.parse::<std::net::Ipv6Addr>().is_ok() {
            return if port > 0 {
                format!("http://[{}]:{}", dest, port)
            } else {
                format!("http://[{}]", dest)
            };
        }
        let (authority, path) = match dest.find('/') {
            Some(idx) => (&dest[..idx], &dest[idx..]),
            None => (dest, ""),
        };
        let has_explicit_port = if let Some(rest) = authority.strip_prefix('[') {
            rest.split_once(']')
                .map(|(_, after)| after.starts_with(':'))
                .unwrap_or(false)
        } else {
            authority
                .rsplit_once(':')
                .map(|(_, p)| !p.is_empty() && p.parse::<u16>().is_ok())
                .unwrap_or(false)
        };
        if has_explicit_port || port == 0 {
            format!("http://{}{}", authority, path)
        } else {
            format!("http://{}:{}{}", authority, port, path)
        }
    }

    pub fn classify_target(target: &str, http_method_or_op: &str) -> LoopbackClassification {
        let lower = target.trim().to_ascii_lowercase();
        let op_upper = http_method_or_op.trim().to_ascii_uppercase();

        if lower.starts_with(r"\\.\pipe\")
            || lower.starts_with("//./pipe/")
            || lower.contains(r"\pipe\")
        {
            if lower.contains("docker_engine") || lower.contains("containerd") {
                return LoopbackClassification {
                    is_local_or_ipc: true,
                    service_identity: LocalServiceIdentity::DockerEngineControlPlane,
                    service_operation: LocalServiceOperation::HostContainerControl,
                    requires_privileged_capability: true,
                    mapped_cedar_action: CedarAction::PrivilegedLocalControl,
                };
            }
            return LoopbackClassification {
                is_local_or_ipc: true,
                service_identity: LocalServiceIdentity::WindowsPrivilegedNamedPipe,
                service_operation: LocalServiceOperation::PrivilegedOsPipeAccess,
                requires_privileged_capability: true,
                mapped_cedar_action: CedarAction::PrivilegedLocalControl,
            };
        }

        if lower.ends_with(".sock")
            || lower.starts_with("/var/run/")
            || lower.starts_with("/run/")
            || lower.starts_with("unix://")
        {
            let identity = if lower.contains("docker")
                || lower.contains("containerd")
                || lower.contains("podman")
            {
                LocalServiceIdentity::DockerEngineControlPlane
            } else {
                LocalServiceIdentity::UnixPrivilegedControlSocket
            };
            return LoopbackClassification {
                is_local_or_ipc: true,
                service_identity: identity,
                service_operation: LocalServiceOperation::HostContainerControl,
                requires_privileged_capability: true,
                mapped_cedar_action: CedarAction::PrivilegedLocalControl,
            };
        }

        let (host, port, path) = if let Ok(parsed) = url::Url::parse(&lower) {
            let h = parsed.host_str().unwrap_or("").to_string();
            let p = parsed.port_or_known_default().unwrap_or(80);
            let path_str = parsed.path().to_string();
            (h, p, path_str)
        } else {
            let stripped = lower
                .trim_start_matches("http://")
                .trim_start_matches("https://")
                .trim_start_matches(concat!("ws", "://"))
                .trim_start_matches("wss://");
            let (host_port, path_part) = match stripped.find('/') {
                Some(idx) => (&stripped[..idx], &stripped[idx..]),
                None => (stripped, "/"),
            };
            let (h, p) = if let Some(colon) = host_port.rfind(':') {
                let port_num = host_port[colon + 1..].parse::<u16>().unwrap_or(80);
                (
                    host_port[..colon].trim_matches(&['[', ']'][..]).to_string(),
                    port_num,
                )
            } else {
                (host_port.to_string(), 80)
            };
            (h, p, path_part.to_string())
        };

        let is_loopback = Self::is_loopback_or_unspecified_host(&host);

        if !is_loopback {
            let is_write = matches!(
                op_upper.as_str(),
                "POST" | "PUT" | "PATCH" | "DELETE" | "PUBLISH" | "WRITE" | "MUTATE"
            ) || lower.contains("/issues/")
                || lower.contains("/comments")
                || lower.contains("webhook");
            return LoopbackClassification {
                is_local_or_ipc: false,
                service_identity: LocalServiceIdentity::UnknownLoopbackService {
                    host_port: format!("{}:{}", host, port),
                },
                service_operation: LocalServiceOperation::UnclassifiedLocalOperation,
                requires_privileged_capability: is_write,
                mapped_cedar_action: if is_write {
                    CedarAction::ExternalWrite
                } else {
                    CedarAction::ExternalNetworkConnect
                },
            };
        }

        if port == 9222
            || port == 9333
            || path.starts_with("/json/version")
            || path.starts_with("/json/list")
            || path.starts_with("/devtools/")
        {
            return LoopbackClassification {
                is_local_or_ipc: true,
                service_identity: LocalServiceIdentity::ChromeDevToolsBrowserDebug,
                service_operation: LocalServiceOperation::BrowserSessionControl,
                requires_privileged_capability: true,
                mapped_cedar_action: CedarAction::PrivilegedLocalControl,
            };
        }

        if port == 2375
            || port == 2376
            || path.contains("/containers/create")
            || path.contains("/containers/json")
        {
            return LoopbackClassification {
                is_local_or_ipc: true,
                service_identity: LocalServiceIdentity::DockerEngineControlPlane,
                service_operation: LocalServiceOperation::HostContainerControl,
                requires_privileged_capability: true,
                mapped_cedar_action: CedarAction::PrivilegedLocalControl,
            };
        }

        if port == 11434
            || path.starts_with("/api/generate")
            || path.starts_with("/api/embeddings")
            || path.starts_with("/api/chat")
        {
            let is_benign_inference = (path == "/api/generate"
                || path == "/api/chat"
                || path == "/api/embeddings"
                || path == "/api/embed"
                || path == "/api/tags"
                || path == "/api/ps")
                && !matches!(op_upper.as_str(), "DELETE" | "PUT");
            if is_benign_inference {
                return LoopbackClassification {
                    is_local_or_ipc: true,
                    service_identity: LocalServiceIdentity::OllamaLocalAiService,
                    service_operation: LocalServiceOperation::ReadOnlyInferenceOrStatus,
                    requires_privileged_capability: false,
                    mapped_cedar_action: CedarAction::ExternalNetworkConnect,
                };
            } else {
                return LoopbackClassification {
                    is_local_or_ipc: true,
                    service_identity: LocalServiceIdentity::OllamaLocalAiService,
                    service_operation: LocalServiceOperation::ModelOrConfigMutation,
                    requires_privileged_capability: true,
                    mapped_cedar_action: CedarAction::PrivilegedLocalControl,
                };
            }
        }

        if port == 3030 {
            let is_read_only = matches!(op_upper.as_str(), "GET" | "HEAD" | "READ" | "")
                && !path.contains("/policy/disable")
                && !path.contains("/admin/");
            return LoopbackClassification {
                is_local_or_ipc: true,
                service_identity: LocalServiceIdentity::OsoosiDashboardService,
                service_operation: if is_read_only {
                    LocalServiceOperation::ReadOnlyInferenceOrStatus
                } else {
                    LocalServiceOperation::ModelOrConfigMutation
                },
                requires_privileged_capability: !is_read_only,
                mapped_cedar_action: if is_read_only {
                    CedarAction::ExternalNetworkConnect
                } else {
                    CedarAction::PrivilegedLocalControl
                },
            };
        }

        LoopbackClassification {
            is_local_or_ipc: true,
            service_identity: LocalServiceIdentity::UnknownLoopbackService {
                host_port: format!("{}:{}", host, port),
            },
            service_operation: LocalServiceOperation::UnclassifiedLocalOperation,
            requires_privileged_capability: true,
            mapped_cedar_action: CedarAction::PrivilegedLocalControl,
        }
    }
}
