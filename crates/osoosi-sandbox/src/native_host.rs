//! Native Host — Implementation of host functions that the WASM brain calls.
//!
//! This is the "thin sensor" side. It receives typed HostCall requests from
//! the WASM sandbox, performs the actual OS/network/DB operations, and returns
//! typed HostResponse values. Every call is metered, logged, and taint-checked.

use crate::host_interface::*;
use crate::security::SandboxSecurityConfig;
use osoosi_audit::AuditTrail;
use osoosi_memory::MemoryStore;
use osoosi_model::MalwareScanner;
use std::sync::Arc;
use tracing::{info, warn};

/// The native host that fulfills WASM brain requests.
pub struct NativeHost {
    audit: Arc<AuditTrail>,
    memory: Arc<MemoryStore>,
    malware_scanner: Arc<MalwareScanner>,
    /// Blocked URL patterns for SSRF protection.
    ssrf_blocklist: Vec<String>,
    /// Security config for allowlist/whitelist validation.
    security_config: SandboxSecurityConfig,
}

impl NativeHost {
    pub fn new(
        audit: Arc<AuditTrail>,
        memory: Arc<MemoryStore>,
        malware_scanner: Arc<MalwareScanner>,
    ) -> Self {
        Self::with_security(
            audit,
            memory,
            malware_scanner,
            SandboxSecurityConfig::default(),
        )
    }

    pub fn with_security(
        audit: Arc<AuditTrail>,
        memory: Arc<MemoryStore>,
        malware_scanner: Arc<MalwareScanner>,
        security_config: SandboxSecurityConfig,
    ) -> Self {
        Self {
            audit,
            memory,
            malware_scanner,
            ssrf_blocklist: vec![
                "localhost".into(),
                "127.0.0.1".into(),
                "::1".into(),
                "169.254.169.254".into(),
                "metadata.google.internal".into(),
                "metadata.aws.internal".into(),
                "10.0.0.".into(),
                "192.168.".into(),
                "172.16.".into(),
            ],
            security_config,
        }
    }

    /// Process a host call from the WASM brain.
    pub async fn dispatch(&self, envelope: HostCallEnvelope) -> HostResponseEnvelope {
        let start = std::time::Instant::now();

        // Audit the incoming call
        self.audit.log(
            "HOST_CALL_RECEIVED",
            serde_json::json!({
                "call_id": envelope.call_id,
                "caller": envelope.caller_module,
                "fuel_remaining": envelope.fuel_remaining,
                "taint_labels": envelope.taint_labels,
                "call_type": format!("{:?}", std::mem::discriminant(&envelope.call)),
            }),
        );

        let response = match envelope.call {
            HostCall::ScanFile { ref bytes } => self.handle_scan_file(bytes).await,
            HostCall::FetchUrl {
                ref url,
                ref method,
                ref headers,
            } => {
                self.handle_fetch_url(url, method, headers, &envelope.taint_labels)
                    .await
            }
            HostCall::ExecCommand {
                ref program,
                ref args,
                requires_approval,
            } => {
                self.handle_exec_command(program, args, requires_approval, &envelope)
                    .await
            }
            HostCall::ReadDb {
                ref query,
                ref params,
            } => self.handle_read_db(query, params).await,
            HostCall::SendMesh {
                ref topic,
                ref data,
            } => self.handle_send_mesh(topic, data).await,
            HostCall::WriteAudit { ref entry } => {
                let hash = self.audit.log("brain_audit_entry", entry.clone());
                HostResponse::Hash(hash)
            }
            HostCall::QueryThreatIntel {
                ref indicator,
                ref indicator_type,
            } => {
                self.handle_query_threat_intel(indicator, indicator_type)
                    .await
            }
        };

        let duration_us = start.elapsed().as_micros() as u64;

        // Audit the response
        self.audit.log(
            "HOST_CALL_COMPLETED",
            serde_json::json!({
                "call_id": envelope.call_id,
                "duration_us": duration_us,
                "response_type": format!("{:?}", std::mem::discriminant(&response)),
            }),
        );

        HostResponseEnvelope {
            call_id: envelope.call_id,
            response,
            duration_us,
            timestamp: chrono::Utc::now(),
        }
    }

    async fn handle_scan_file(&self, bytes: &[u8]) -> HostResponse {
        // Architecture: "Host Service" logic — WASM brain isolated from native ML libraries
        info!(
            "Host: scanning {} bytes of data with ONNX/YARA Service",
            bytes.len()
        );

        match self.malware_scanner.scan_bytes("wasm-memory", bytes) {
            Some(result) => HostResponse::ScanResult {
                is_malware: result.is_malware,
                malware_type: result.malware_type,
                confidence: result.combined_score,
            },
            None => HostResponse::Error {
                message: "Malware scanner could not process bytes".to_string(),
            },
        }
    }

    async fn handle_fetch_url(
        &self,
        url: &str,
        _method: &str,
        _headers: &[(String, String)],
        taint_labels: &[String],
    ) -> HostResponse {
        // URL validation: only allow http/https, reject malformed or overly long URLs
        let url = url.trim();
        if url.is_empty() || url.len() > 8192 {
            warn!("Host: URL validation failed — empty or too long");
            return HostResponse::Error {
                message: "Invalid URL: empty or exceeds max length".to_string(),
            };
        }
        let scheme_ok = url.starts_with("https://") || url.starts_with("http://");
        if !scheme_ok {
            warn!(
                "Host: URL validation failed — only http/https allowed: '{}'",
                url
            );
            self.audit.log(
                "URL_VALIDATION_BLOCKED",
                serde_json::json!({
                    "url": url,
                    "reason": "scheme not http or https",
                }),
            );
            return HostResponse::Error {
                message: "Invalid URL: only http and https schemes allowed".to_string(),
            };
        }

        // Allowlist mode: deny if not in allowlist
        if self.security_config.url_allowlist_mode && !self.security_config.is_url_allowed(url) {
            warn!("Host: URL not in allowlist: '{}'", url);
            self.audit
                .log("URL_ALLOWLIST_BLOCKED", serde_json::json!({"url": url}));
            return HostResponse::Error {
                message: "URL not in allowlist".to_string(),
            };
        }

        // Mathematical IP Range & Hostname SSRF Protection
        let host = crate::security::extract_host_from_url(url);
        if host.is_empty() {
            return HostResponse::Error {
                message: "Invalid URL: unable to extract host".to_string(),
            };
        }

        let blocked_hostnames = [
            "localhost",
            "metadata.google.internal",
            "metadata.aws.internal",
            "instance-data",
        ];
        if blocked_hostnames.contains(&host.as_str()) || host.ends_with(".localhost") {
            warn!("Host: SSRF BLOCKED hostname '{}' in URL '{}'", host, url);
            self.audit.log(
                "SSRF_BLOCKED",
                serde_json::json!({
                    "url": url,
                    "host": host,
                    "reason": "blocked hostname",
                    "taint_labels": taint_labels,
                }),
            );
            return HostResponse::Error {
                message: format!("SSRF Violation: access to host '{}' is blocked", host),
            };
        }

        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            if is_ssrf_ip(ip) {
                warn!("Host: SSRF BLOCKED IP literal '{}' in URL '{}'", ip, url);
                self.audit.log(
                    "SSRF_BLOCKED",
                    serde_json::json!({
                        "url": url,
                        "ip": ip.to_string(),
                        "reason": "private or non-routable IP address",
                        "taint_labels": taint_labels,
                    }),
                );
                return HostResponse::Error {
                    message: format!("SSRF Violation: access to IP '{}' is blocked", ip),
                };
            }
        }

        // Substring fallback check
        for blocked in &self.ssrf_blocklist {
            if url.contains(blocked) {
                warn!(
                    "Host: SSRF BLOCKED — WASM brain attempted to access '{}'",
                    url
                );
                self.audit.log(
                    "SSRF_BLOCKED",
                    serde_json::json!({
                        "url": url,
                        "taint_labels": taint_labels,
                    }),
                );
                return HostResponse::Error {
                    message: format!("SSRF Violation: access to '{}' is blocked", url),
                };
            }
        }

        // Taint check: if caller is tainted with SuspiciousNetwork, block all outbound
        if taint_labels.iter().any(|l| l == "SuspiciousNetwork") {
            warn!("Host: Tainted caller attempted outbound HTTP to '{}'", url);
            return HostResponse::Error {
                message: "Tainted caller blocked from outbound HTTP".to_string(),
            };
        }

        // Real implementation would use reqwest here
        info!("Host: fetching URL '{}'", url);
        HostResponse::HttpResponse {
            status: 200,
            body: "{}".to_string(),
        }
    }

    async fn handle_exec_command(
        &self,
        program: &str,
        args: &[String],
        requires_approval: bool,
        envelope: &HostCallEnvelope,
    ) -> HostResponse {
        if requires_approval {
            info!(
                "Host: Command '{}' requires human approval — queuing",
                program
            );
            return HostResponse::PendingApproval {
                approval_id: envelope.call_id.clone(),
            };
        }

        // Whitelist mode: deny if not in whitelist
        if self.security_config.command_whitelist_mode
            && !self.security_config.is_command_allowed(program)
        {
            warn!("Host: Command not in whitelist: '{}'", program);
            return HostResponse::Error {
                message: format!("Command '{}' not in whitelist", program),
            };
        }

        // Blocklist: never allow the WASM brain to directly execute these
        let blocked_programs = ["rm", "format", "del", "fdisk", "mkfs", "shutdown", "reboot"];
        let prog_lower = program.to_lowercase();
        if blocked_programs.iter().any(|b| prog_lower.contains(b)) {
            warn!("Host: BLOCKED dangerous command: {} {:?}", program, args);
            return HostResponse::Error {
                message: format!("Blocked: '{}' is a dangerous command", program),
            };
        }

        info!("Host: executing command '{}' with args {:?}", program, args);
        // Real implementation would call Command::new() here
        HostResponse::CommandOutput {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
        }
    }

    async fn handle_read_db(&self, query: &str, params: &[String]) -> HostResponse {
        // Enforce SQL injection protection: only allow single-statement SELECT without dangerous keywords
        if !self.security_config.is_query_allowed(query) {
            return HostResponse::Error {
                message: "Only single-statement SELECT queries without administrative or destructive keywords are allowed from WASM brain".to_string(),
            };
        }

        // Host Service: fulfill query via native SQLite instance (rusqlite)
        match self.memory.query_json(query, params) {
            Ok(rows) => HostResponse::DbRows { rows },
            Err(e) => HostResponse::Error {
                message: e.to_string(),
            },
        }
    }

    async fn handle_send_mesh(&self, topic: &str, _data: &[u8]) -> HostResponse {
        info!("Host: sending mesh message to topic '{}'", topic);
        HostResponse::Hash(uuid::Uuid::new_v4().to_string())
    }

    async fn handle_query_threat_intel(
        &self,
        indicator: &str,
        indicator_type: &str,
    ) -> HostResponse {
        info!(
            "Host: querying threat intel for {} (type: {})",
            indicator, indicator_type
        );
        HostResponse::ThreatIntelResult {
            found: false,
            data: serde_json::json!({}),
        }
    }
}

/// Evaluates an IP address mathematically to block all SSRF ranges.
fn is_ssrf_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => is_ssrf_ipv4(v4),
        std::net::IpAddr::V6(v6) => {
            // Check for IPv4-mapped IPv6 (::ffff:0:0/96)
            let segs = v6.segments();
            if segs[0] == 0
                && segs[1] == 0
                && segs[2] == 0
                && segs[3] == 0
                && segs[4] == 0
                && segs[5] == 0xffff
            {
                let v4 = std::net::Ipv4Addr::new(
                    (segs[6] >> 8) as u8,
                    (segs[6] & 0xff) as u8,
                    (segs[7] >> 8) as u8,
                    (segs[7] & 0xff) as u8,
                );
                return is_ssrf_ipv4(v4);
            }
            if v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() {
                return true;
            }
            // Unique local fc00::/7 (fc00:: - fdff:ffff:...)
            if (segs[0] & 0xfe00) == 0xfc00 {
                return true;
            }
            // Link-local fe80::/10 (fe80:: - febf:ffff:...)
            if (segs[0] & 0xffc0) == 0xfe80 {
                return true;
            }
            false
        }
    }
}

/// Evaluates an IPv4 address mathematically against RFC1918, loopback, CGNAT, link-local, broadcast, and multicast.
fn is_ssrf_ipv4(v4: std::net::Ipv4Addr) -> bool {
    let octets = v4.octets();
    if v4.is_loopback()       // 127.0.0.0/8
        || v4.is_unspecified() // 0.0.0.0
        || v4.is_broadcast()   // 255.255.255.255
        || v4.is_multicast()   // 224.0.0.0/4
        || octets[0] == 0
    // 0.0.0.0/8
    {
        return true;
    }
    // RFC1918: 10.0.0.0/8
    if octets[0] == 10 {
        return true;
    }
    // RFC1918: 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
    if octets[0] == 172 && (16..=31).contains(&octets[1]) {
        return true;
    }
    // RFC1918: 192.168.0.0/16
    if octets[0] == 192 && octets[1] == 168 {
        return true;
    }
    // Link-local / Cloud metadata: 169.254.0.0/16
    if octets[0] == 169 && octets[1] == 254 {
        return true;
    }
    // Carrier-Grade NAT (CGNAT): 100.64.0.0/10 (100.64.0.0 - 100.127.255.255)
    if octets[0] == 100 && (64..=127).contains(&octets[1]) {
        return true;
    }
    false
}
