//! Host-Mediated Capability Gate (`crates/osoosi-sandbox/src/host_capability_gate.rs`).
//!
//! Enforces:
//! 1. Strict Domain Allowlisting (`export.arxiv.org`, `arxiv.org`, `api.github.com`, and conditional `127.0.0.1:11434`).
//! 2. Mathematical IPv4/IPv6 SSRF & DNS Rebinding Protection via `SocketAddr` pinning.
//! 3. Boundary Secret Injection outside guest linear memory.

use crate::native_host::build_ssrf_safe_http_client;
use std::collections::HashMap;
use std::sync::atomic::{compiler_fence, Ordering};
use std::sync::{Arc, RwLock};
use tracing::info;

/// In-memory secret buffer that zeroes its backing heap allocation via volatile writes
/// whenever a grant is revoked or dropped (`Drop`).
#[derive(Clone)]
pub struct ZeroizingLockedSecret {
    bytes: Arc<Vec<u8>>,
}

impl ZeroizingLockedSecret {
    pub fn new(secret: &[u8]) -> Self {
        Self {
            bytes: Arc::new(secret.to_vec()),
        }
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for ZeroizingLockedSecret {
    fn drop(&mut self) {
        if let Some(vec_mut) = Arc::get_mut(&mut self.bytes) {
            for b in vec_mut.iter_mut() {
                unsafe { std::ptr::write_volatile(b, 0) };
            }
            compiler_fence(Ordering::SeqCst);
        }
    }
}

/// Hardened sealed grant binding an OS environment variable stand-in token
/// to allowed binary hash, optional entrypoint script hash, pinned upstream host,
/// and volatile zeroizing secret.
#[derive(Clone)]
pub struct HardenedSealedGrant {
    pub env_var_name: String,
    pub standin_token: String,
    pub allowed_binary_sha256: [u8; 32],
    pub allowed_script_sha256: Option<[u8; 32]>,
    pub pinned_upstream_host: String,
    pub secret: ZeroizingLockedSecret,
}

impl HardenedSealedGrant {
    pub fn new(
        env_var_name: impl Into<String>,
        standin_token: impl Into<String>,
        allowed_binary_sha256: [u8; 32],
        allowed_script_sha256: Option<[u8; 32]>,
        pinned_upstream_host: impl Into<String>,
        secret: ZeroizingLockedSecret,
    ) -> Self {
        Self {
            env_var_name: env_var_name.into(),
            standin_token: standin_token.into(),
            allowed_binary_sha256,
            allowed_script_sha256,
            pinned_upstream_host: pinned_upstream_host.into(),
            secret,
        }
    }
}

/// Provider trait for swapping synthetic stand-in tokens with actual secrets on the host.
pub trait SecretSwapProvider: Send + Sync {
    fn verify_and_swap_outbound(
        &self,
        caller_pid: u32,
        upstream_host: &str,
        http_payload: &[u8],
    ) -> Result<Vec<u8>, String>;
}

/// Errors returned by the host capability gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateError {
    DomainDenied(String),
    SsrfBlocked(String),
    DnsRebindingBlocked(String),
    CredentialDenied(String),
    NetworkError(String),
    Timeout,
}

impl std::fmt::Display for GateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GateError::DomainDenied(msg) => write!(f, "Domain Denied: {}", msg),
            GateError::SsrfBlocked(msg) => write!(f, "SSRF Blocked: {}", msg),
            GateError::DnsRebindingBlocked(msg) => write!(f, "DNS Rebinding Blocked: {}", msg),
            GateError::CredentialDenied(msg) => write!(f, "Credential Denied: {}", msg),
            GateError::NetworkError(msg) => write!(f, "Network Error: {}", msg),
            GateError::Timeout => write!(f, "Request Timed Out"),
        }
    }
}

impl std::error::Error for GateError {}

/// Host-mediated capability gate controlling network access and secret boundaries for Wasm guests.
#[derive(Clone)]
pub struct HostCapabilityGate {
    grants: Arc<RwLock<HashMap<String, HardenedSealedGrant>>>,
    custom_swap_provider: Option<Arc<dyn SecretSwapProvider>>,
    ollama_bridge_enabled: bool,
    caller_pid: u32,
}

impl HostCapabilityGate {
    pub fn new(
        ollama_bridge_enabled: bool,
        caller_pid: u32,
    ) -> Self {
        Self {
            grants: Arc::new(RwLock::new(HashMap::new())),
            custom_swap_provider: None,
            ollama_bridge_enabled,
            caller_pid,
        }
    }

    /// Attaches an external secret swap provider (such as ReaVoterEnvGateway).
    pub fn with_secret_provider(mut self, provider: Arc<dyn SecretSwapProvider>) -> Self {
        self.custom_swap_provider = Some(provider);
        self
    }

    /// Registers a sealed grant directly with the capability gate.
    pub fn register_grant(&self, grant: HardenedSealedGrant) {
        let mut lock = self.grants.write().unwrap_or_else(|p| p.into_inner());
        lock.insert(grant.standin_token.clone(), grant);
    }

    /// Canonical Domain Allowlist Verification.
    /// Strictly permits:
    /// - `export.arxiv.org`
    /// - `arxiv.org`
    /// - `api.github.com`
    /// - `127.0.0.1:11434` (ONLY IF `ollama_bridge_enabled == true`)
    pub fn verify_domain_allowlist(&self, host: &str, port: u16) -> Result<(), GateError> {
        let normalized_host = host.trim().to_ascii_lowercase();
        let stripped_host = normalized_host.trim_end_matches('.');

        // Special handling for local Ollama bridge
        if (stripped_host == "127.0.0.1" || stripped_host == "localhost") && port == 11434 {
            if self.ollama_bridge_enabled {
                return Ok(());
            } else {
                return Err(GateError::DomainDenied(
                    "Local Ollama inference bridge is disabled".to_string(),
                ));
            }
        }

        match stripped_host {
            "export.arxiv.org" | "arxiv.org" | "api.github.com" => Ok(()),
            other => Err(GateError::DomainDenied(format!(
                "Host '{}' is not in the authoritative research allowlist",
                other
            ))),
        }
    }

    /// Internal helper to swap standin tokens with real secrets.
    fn swap_secret(&self, host: &str, payload: &[u8]) -> Result<Vec<u8>, String> {
        if let Some(ref provider) = self.custom_swap_provider {
            return provider.verify_and_swap_outbound(self.caller_pid, host, payload);
        }

        let grants = self.grants.read().unwrap_or_else(|p| p.into_inner());
        for (standin, grant) in grants.iter() {
            let token_bytes = standin.as_bytes();
            if let Some(pos) = find_subslice(payload, token_bytes) {
                let normalized_host = normalize_host_gate(host);
                let pinned_host = normalize_host_gate(&grant.pinned_upstream_host);
                if normalized_host != pinned_host {
                    return Err(format!(
                        "Confused-deputy host mismatch: target '{}' vs pinned grant '{}'",
                        normalized_host, pinned_host
                    ));
                }

                let mut out = Vec::with_capacity(
                    payload.len() - token_bytes.len() + grant.secret.as_slice().len(),
                );
                out.extend_from_slice(&payload[..pos]);
                out.extend_from_slice(grant.secret.as_slice());
                out.extend_from_slice(&payload[pos + token_bytes.len()..]);
                return Ok(out);
            }
        }

        Err("No registered stand-in token matched".to_string())
    }

    /// Dispatches an outbound HTTP request through the host-mediated capability gate.
    ///
    /// Sequence:
    /// 1. Parse and validate URL scheme (https only, except http for local Ollama).
    /// 2. Enforce strict domain allowlist.
    /// 3. Verify DNS resolution and enforce mathematical SSRF blocking with SocketAddr pinning.
    /// 4. Boundary secret injection: swap `OSHOOSI_STANDIN_*` tokens strictly inside host memory.
    /// 5. Scrub sensitive response headers before returning bytes to the caller.
    pub async fn dispatch_request(
        &self,
        method: &str,
        url_str: &str,
        headers: &[(String, String)],
        body: Option<&[u8]>,
    ) -> Result<(u16, Vec<(String, String)>, Vec<u8>), GateError> {
        let parsed_url = reqwest::Url::parse(url_str).map_err(|e| {
            GateError::DomainDenied(format!("Malformed URL '{}': {}", url_str, e))
        })?;

        let host = parsed_url
            .host_str()
            .ok_or_else(|| GateError::DomainDenied("Missing host in URL".to_string()))?;
        let port = parsed_url.port_or_known_default().unwrap_or(443);

        // 1. Strict Domain Allowlist
        self.verify_domain_allowlist(host, port)?;

        // 2. Scheme check
        let is_local_ollama = (host == "127.0.0.1" || host == "localhost") && port == 11434;
        if parsed_url.scheme() == "http" && !is_local_ollama {
            return Err(GateError::DomainDenied(
                "Insecure HTTP scheme rejected for external hosts (HTTPS required)".to_string(),
            ));
        }

        // 3. Client initialization
        let client = if is_local_ollama {
            if !self.ollama_bridge_enabled {
                return Err(GateError::DomainDenied(
                    "Local Ollama inference bridge is disabled".to_string(),
                ));
            }
            reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .map_err(|e| GateError::NetworkError(e.to_string()))?
        } else {
            // SSRF & DNS Pinning via build_ssrf_safe_http_client
            let (c, pinned_socket) = build_ssrf_safe_http_client(url_str)
                .await
                .map_err(|e| match e {
                    osoosi_types::OctopusSecurityError::SsrfBlocked(msg) => {
                        if msg.contains("DNS REBINDING") {
                            GateError::DnsRebindingBlocked(msg)
                        } else {
                            GateError::SsrfBlocked(msg)
                        }
                    }
                    other => GateError::NetworkError(other.to_string()),
                })?;

            info!(
                "HostCapabilityGate: outbound fetch '{}' pinned to '{}'",
                url_str, pinned_socket
            );
            c
        };

        // 4. Boundary Secret Injection
        let mut request_builder = match method.to_ascii_uppercase().as_str() {
            "GET" => client.get(url_str),
            "POST" => client.post(url_str),
            "HEAD" => client.head(url_str),
            other => {
                return Err(GateError::NetworkError(format!(
                    "Unsupported HTTP method '{}'",
                    other
                )))
            }
        };

        for (k, v) in headers {
            if v.contains("OSHOOSI_STANDIN_") {
                let swapped = self
                    .swap_secret(host, v.as_bytes())
                    .map_err(|e| {
                        GateError::CredentialDenied(format!(
                            "Boundary secret swap failed for header '{}': {}",
                            k, e
                        ))
                    })?;
                let swapped_str = String::from_utf8(swapped).map_err(|_| {
                    GateError::CredentialDenied("Non-UTF8 secret byte representation".to_string())
                })?;
                request_builder = request_builder.header(k, swapped_str);
            } else {
                request_builder = request_builder.header(k, v);
            }
        }

        if let Some(payload) = body {
            if payload.windows(16).any(|w| w == b"OSHOOSI_STANDIN_") {
                let swapped_body = self
                    .swap_secret(host, payload)
                    .map_err(|e| {
                        GateError::CredentialDenied(format!(
                            "Boundary secret swap failed in payload: {}",
                            e
                        ))
                    })?;
                request_builder = request_builder.body(swapped_body);
            } else {
                request_builder = request_builder.body(payload.to_vec());
            }
        }

        // 5. Execute Request
        let resp = request_builder
            .send()
            .await
            .map_err(|e| GateError::NetworkError(e.to_string()))?;

        let status = resp.status().as_u16();
        let mut resp_headers = Vec::new();
        for (k, v) in resp.headers() {
            let key = k.as_str().to_string();
            // Scrub sensitive response headers to prevent echo back into guest
            if key.eq_ignore_ascii_case("set-cookie")
                || key.eq_ignore_ascii_case("authorization")
                || key.eq_ignore_ascii_case("proxy-authorization")
            {
                continue;
            }
            if let Ok(val) = v.to_str() {
                resp_headers.push((key, val.to_string()));
            }
        }

        let resp_body = resp
            .bytes()
            .await
            .map_err(|e| GateError::NetworkError(e.to_string()))?
            .to_vec();

        Ok((status, resp_headers, resp_body))
    }
}

fn normalize_host_gate(host: &str) -> String {
    let trimmed = host.trim().to_ascii_lowercase();
    trimmed
        .strip_suffix(":443")
        .unwrap_or(&trimmed)
        .trim_end_matches('.')
        .to_string()
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}
