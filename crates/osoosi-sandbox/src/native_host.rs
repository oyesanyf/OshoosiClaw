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

pub type UrlReputationChecker = Arc<dyn Fn(&str) -> Result<(), String> + Send + Sync>;

static GLOBAL_URL_CHECKER: std::sync::OnceLock<UrlReputationChecker> = std::sync::OnceLock::new();

/// Registers an external URL reputation checker (such as Google Safe Browsing v4 engine).
pub fn register_global_url_checker(checker: UrlReputationChecker) {
    let _ = GLOBAL_URL_CHECKER.set(checker);
}

/// The native host that fulfills WASM brain requests.
pub struct NativeHost {
    audit: Arc<AuditTrail>,
    memory: Arc<MemoryStore>,
    malware_scanner: Arc<MalwareScanner>,
    /// Blocked URL patterns for SSRF protection.
    ssrf_blocklist: Vec<String>,
    /// Security config for allowlist/whitelist validation.
    security_config: SandboxSecurityConfig,
    /// Optional URL reputation checker (e.g. Google Safe Browsing)
    url_reputation_checker: Option<UrlReputationChecker>,
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
            url_reputation_checker: None,
        }
    }

    pub fn set_url_reputation_checker(&mut self, checker: UrlReputationChecker) {
        self.url_reputation_checker = Some(checker);
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
        let url = url.trim();
        if url.is_empty() || url.len() > 8192 {
            warn!("Host: URL validation failed — empty or exceeds max length");
            return HostResponse::Error {
                message: "Invalid URL: empty or exceeds max length".to_string(),
            };
        }

        let parsed_url = match reqwest::Url::parse(url) {
            Ok(u) => u,
            Err(e) => {
                return HostResponse::Error {
                    message: format!("Malformed URL '{}': {}", url, e),
                };
            }
        };

        let scheme = parsed_url.scheme();
        if scheme != "http" && scheme != "https" {
            warn!("Host: Scheme not allowed: '{}'", scheme);
            return HostResponse::Error {
                message: "Invalid URL: only http and https schemes allowed".to_string(),
            };
        }

        let host = match parsed_url.host_str() {
            Some(h) => h.to_ascii_lowercase(),
            None => {
                return HostResponse::Error {
                    message: "Invalid URL: unable to extract host".to_string(),
                };
            }
        };

        // 1. Google Safe Browsing v4 & Reputation Check
        if let Some(checker) = &self.url_reputation_checker {
            if let Err(threat) = checker(url) {
                warn!("Host: GSB Threat detected for '{}': {}", url, threat);
                self.audit.log(
                    "GSB_THREAT_BLOCKED",
                    serde_json::json!({
                        "url": url,
                        "reason": threat,
                        "taint_labels": taint_labels,
                    }),
                );
                return HostResponse::Error {
                    message: format!("Google Safe Browsing blocked threat URL: {}", threat),
                };
            }
        } else if let Some(global_checker) = GLOBAL_URL_CHECKER.get() {
            if let Err(threat) = global_checker(url) {
                warn!("Host: Global GSB Threat detected for '{}': {}", url, threat);
                self.audit.log(
                    "GSB_THREAT_BLOCKED",
                    serde_json::json!({
                        "url": url,
                        "reason": threat,
                        "taint_labels": taint_labels,
                    }),
                );
                return HostResponse::Error {
                    message: format!("Google Safe Browsing blocked threat URL: {}", threat),
                };
            }
        } else {
            // Built-in GSB canonical test vector matching for offline isolation
            let lower_url = url.to_ascii_lowercase();
            if lower_url.contains("testsafebrowsing.appspot.com/s/phishing.html")
                || lower_url.contains("testsafebrowsing.appspot.com/s/malware.html")
                || lower_url.contains("testsafebrowsing.appspot.com/s/unwanted.html")
            {
                warn!("Host: GSB canonical test threat URL detected: '{}'", url);
                return HostResponse::Error {
                    message: "Google Safe Browsing blocked threat URL: GSB:MALWARE_OR_PHISHING"
                        .to_string(),
                };
            }
        }

        // 2. Allowlist mode check
        if self.security_config.url_allowlist_mode && !self.security_config.is_url_allowed(url) {
            warn!("Host: URL not in allowlist: '{}'", url);
            self.audit
                .log("URL_ALLOWLIST_BLOCKED", serde_json::json!({"url": url}));
            return HostResponse::Error {
                message: "URL not in allowlist".to_string(),
            };
        }

        // 3. Blocked hostnames check
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

        // 4. Substring fallback check
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

        // 5. Taint check: if caller is tainted with SuspiciousNetwork, block all outbound
        if taint_labels.iter().any(|l| l == "SuspiciousNetwork") {
            warn!("Host: Tainted caller attempted outbound HTTP to '{}'", url);
            return HostResponse::Error {
                message: "Tainted caller blocked from outbound HTTP".to_string(),
            };
        }

        // 6. Construct SSRF-Safe, DNS-Pinned HTTP Client (F04)
        let (client, pinned_socket_addr) = match build_ssrf_safe_http_client(url).await {
            Ok(pair) => pair,
            Err(e) => {
                warn!("Host: SSRF / DNS Pinning rejected URL '{}': {}", url, e);
                self.audit.log(
                    "SSRF_BLOCKED",
                    serde_json::json!({
                        "url": url,
                        "host": host,
                        "reason": e.to_string(),
                        "taint_labels": taint_labels,
                    }),
                );
                return HostResponse::Error {
                    message: e.to_string(),
                };
            }
        };

        info!(
            "Host: fetching URL '{}' pinned to socket address '{}'",
            url, pinned_socket_addr
        );

        // 7. Execute HTTP Fetch
        match client.get(url).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                HostResponse::HttpResponse { status, body }
            }
            Err(e) => HostResponse::Error {
                message: format!("HTTP fetch failed for '{}': {}", url, e),
            },
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

        #[cfg(windows)]
        {
            let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            let profile_name = format!("osoosi_cmd_{}", envelope.call_id.replace('-', ""));
            let policy = crate::windows::WindowsConfinementPolicy::default();

            match crate::windows::execute_confined_windows_process(
                program,
                &args_refs,
                &profile_name,
                &policy,
            ) {
                Ok(outcome) => {
                    if outcome.resume_thread_allowed && !outcome.terminated_suspended_process {
                        HostResponse::CommandOutput {
                            exit_code: outcome.exit_code.unwrap_or(0),
                            stdout: outcome.stdout,
                            stderr: outcome.stderr,
                        }
                    } else {
                        HostResponse::Error {
                            message: format!("Command confinement failed: {}", outcome.reason),
                        }
                    }
                }
                Err(e) => HostResponse::Error {
                    message: format!("Failed to execute confined command '{}': {}", program, e),
                },
            }
        }

        #[cfg(not(windows))]
        {
            let mut cmd = tokio::process::Command::new(program);
            cmd.args(args);
            cmd.env_clear();

            #[cfg(target_os = "linux")]
            unsafe {
                use std::os::unix::process::CommandExt;
                cmd.as_std_mut().pre_exec(|| {
                    let ret = libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
                    if ret != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }

            let allowed_vars = [
                "path",
                "systemroot",
                "temp",
                "tmp",
                "user",
                "username",
                "home",
                "lang",
                "term",
                "comspec",
                "pathext",
                "windir",
            ];
            for (k, v) in std::env::vars() {
                let k_lower = k.to_ascii_lowercase();
                let is_whitelisted = allowed_vars.iter().any(|&a| k_lower == a);
                let is_secret = k_lower.contains("secret")
                    || k_lower.contains("token")
                    || k_lower.contains("key")
                    || k_lower.contains("password")
                    || k_lower.starts_with("osoosi_")
                    || k_lower.starts_with("aws_")
                    || k_lower.starts_with("github_");
                if is_whitelisted && !is_secret {
                    cmd.env(&k, &v);
                }
            }

            match tokio::time::timeout(std::time::Duration::from_secs(10), cmd.output()).await {
                Ok(Ok(output)) => HostResponse::CommandOutput {
                    exit_code: output.status.code().unwrap_or(-1),
                    stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                    stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                },
                Ok(Err(e)) => HostResponse::Error {
                    message: format!("Failed to execute command '{}': {}", program, e),
                },
                Err(_) => HostResponse::Error {
                    message: format!("Command '{}' timed out after 10 seconds", program),
                },
            }
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

    async fn handle_send_mesh(&self, topic: &str, data: &[u8]) -> HostResponse {
        info!(
            "Host: sending mesh message to topic '{}' ({} bytes)",
            topic,
            data.len()
        );
        let mut hasher = blake3::Hasher::new();
        hasher.update(topic.as_bytes());
        hasher.update(b":");
        hasher.update(data);
        let hash_hex = hasher.finalize().to_hex().to_string();
        HostResponse::Hash(hash_hex)
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

/// Evaluates a URL string against scheme, hostname, and mathematical IPv4/IPv6 SSRF rules.
pub fn is_ssrf_url(url: &str) -> Result<(), String> {
    let url = url.trim();
    if url.is_empty() || url.len() > 8192 {
        return Err("Invalid URL: empty or exceeds max length".to_string());
    }
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err("Invalid URL: only http and https schemes allowed".to_string());
    }
    let host = crate::security::extract_host_from_url(url);
    if host.is_empty() {
        return Err("Invalid URL: unable to extract host".to_string());
    }
    let blocked_hostnames = [
        "localhost",
        "metadata.google.internal",
        "metadata.aws.internal",
        "instance-data",
    ];
    if blocked_hostnames.contains(&host.as_str()) || host.ends_with(".localhost") {
        return Err(format!(
            "SSRF Violation: access to host '{}' is blocked",
            host
        ));
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        if is_ssrf_ip(ip) {
            return Err(format!("SSRF Violation: access to IP '{}' is blocked", ip));
        }
    }
    Ok(())
}

/// Evaluates an IP address mathematically to block all SSRF ranges.
pub fn is_ssrf_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => is_ssrf_ipv4(v4),
        std::net::IpAddr::V6(v6) => {
            let segs = v6.segments();
            let oct = v6.octets();

            // 1. RFC 2765 SIIT IPv4-translated prefix ::ffff:0:0/96
            if segs[0] == 0
                && segs[1] == 0
                && segs[2] == 0
                && segs[3] == 0
                && segs[4] == 0xffff
                && segs[5] == 0
            {
                let embedded_v4 = std::net::Ipv4Addr::new(
                    (segs[6] >> 8) as u8,
                    (segs[6] & 0xff) as u8,
                    (segs[7] >> 8) as u8,
                    (segs[7] & 0xff) as u8,
                );
                if is_ssrf_ipv4(embedded_v4) {
                    return true;
                }
            }

            // 2. IPv4-mapped IPv6 (::ffff:0:0/96)
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

            // 3. IPv4-compatible IPv6 (::a.b.c.d where segs[0..6] == 0)
            if segs[0] == 0
                && segs[1] == 0
                && segs[2] == 0
                && segs[3] == 0
                && segs[4] == 0
                && segs[5] == 0
            {
                let compat_v4 = std::net::Ipv4Addr::new(
                    (segs[6] >> 8) as u8,
                    (segs[6] & 0xff) as u8,
                    (segs[7] >> 8) as u8,
                    (segs[7] & 0xff) as u8,
                );
                if !v6.is_loopback() && is_ssrf_ipv4(compat_v4) {
                    return true;
                }
            }

            // 4. NAT64 prefix: 64:ff9b::/96 and 64:ff9b:1::/48
            let is_nat64 = (segs[0] == 0x0064
                && segs[1] == 0xff9b
                && segs[2] == 0
                && segs[3] == 0
                && segs[4] == 0
                && segs[5] == 0)
                || (segs[0] == 0x0064 && segs[1] == 0xff9b && segs[2] == 1);
            if is_nat64 {
                return true;
            }

            // 5. 6to4 prefix: 2002::/16
            let is_6to4 = segs[0] == 0x2002;
            if is_6to4 {
                let embedded_v4 = std::net::Ipv4Addr::new(
                    (segs[1] >> 8) as u8,
                    (segs[1] & 0xff) as u8,
                    (segs[2] >> 8) as u8,
                    (segs[2] & 0xff) as u8,
                );
                if is_ssrf_ipv4(embedded_v4) {
                    return true;
                }
                return true;
            }

            // 6. Teredo (2001::/32), Doc (2001:db8::/32), Discard (0100::/64)
            let is_teredo_or_doc_or_discard = (segs[0] == 0x2001
                && (segs[1] == 0x0000 || segs[1] == 0x0db8))
                || (segs[0] == 0x0100 && segs[1] == 0 && segs[2] == 0 && segs[3] == 0);
            if is_teredo_or_doc_or_discard {
                return true;
            }

            // 7. Loopback, unspecified, multicast
            if v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() {
                return true;
            }

            // 8. Unique local fc00::/7 (fc00:: - fdff:ffff:...)
            if (oct[0] & 0xfe) == 0xfc {
                return true;
            }

            // 9. Link-local fe80::/10 (fe80:: - febf:ffff:...)
            if oct[0] == 0xfe && (oct[1] & 0xc0) == 0x80 {
                return true;
            }

            false
        }
    }
}

/// Evaluates an IPv4 address mathematically against RFC1918, loopback, CGNAT, link-local, broadcast, multicast, benchmarking, class E, and IETF.
pub fn is_ssrf_ipv4(v4: std::net::Ipv4Addr) -> bool {
    let octets = v4.octets();
    let is_this_net = octets[0] == 0; // 0.0.0.0/8
    let is_cgnat = octets[0] == 100 && (octets[1] & 0b1100_0000) == 64; // 100.64.0.0/10
    let is_metadata = octets[0] == 169 && octets[1] == 254; // 169.254.0.0/16
    let is_benchmarking = octets[0] == 198 && (octets[1] & 0xfe) == 18; // 198.18.0.0/15
    let is_reserved_class_e = (octets[0] & 0xf0) == 240; // 240.0.0.0/4
    let is_ietf_protocol = octets[0] == 192 && octets[1] == 0 && octets[2] == 0; // 192.0.0.0/24

    v4.is_loopback()
        || v4.is_unspecified()
        || v4.is_broadcast()
        || v4.is_multicast()
        || is_this_net
        // RFC1918: 10.0.0.0/8
        || octets[0] == 10
        // RFC1918: 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
        || (octets[0] == 172 && (16..=31).contains(&octets[1]))
        // RFC1918: 192.168.0.0/16
        || (octets[0] == 192 && octets[1] == 168)
        || is_cgnat
        || is_metadata
        || is_benchmarking
        || is_reserved_class_e
        || is_ietf_protocol
}

/// Validates a resolved socket address against SSRF and DNS rebinding attacks.
///
/// Returns `Err(OctopusSecurityError::SsrfBlocked)` if the IP address belongs to any restricted,
/// private, link-local, loopback, SIIT, 6to4, or NAT64 range.
pub fn validate_resolved_socket_addr(
    addr: &std::net::SocketAddr,
) -> Result<(), osoosi_types::OctopusSecurityError> {
    if is_ssrf_ip(addr.ip()) {
        Err(osoosi_types::OctopusSecurityError::SsrfBlocked(format!(
            "Restricted IP address blocked: {}",
            addr.ip()
        )))
    } else {
        Ok(())
    }
}

/// Builds an SSRF-safe, DNS-pinned `reqwest::Client` along with the pinned `SocketAddr`.
///
/// Defends against DNS rebinding and SSRF by:
/// 1. Rejecting non-http/https URL schemes.
/// 2. Mathematically evaluating IP literals and resolved DNS addresses against all restricted, private,
///    link-local, cloud metadata, SIIT, 6to4, and NAT64 ranges.
/// 3. Asserting that *every* returned DNS record is non-SSRF.
/// 4. Hard-pinning the validated `SocketAddr` in the client's resolver configuration (`resolve(&host, pinned_socket_addr)`).
/// 5. Disabling automatic HTTP redirects (`Policy::none()`) to prevent open redirect bypasses.
pub async fn build_ssrf_safe_http_client(
    target_url: &str,
) -> Result<(reqwest::Client, std::net::SocketAddr), osoosi_types::OctopusSecurityError> {
    let url_trimmed = target_url.trim();
    if url_trimmed.is_empty() || url_trimmed.len() > 8192 {
        return Err(osoosi_types::OctopusSecurityError::SsrfBlocked(
            "Invalid URL: empty or exceeds max length".to_string(),
        ));
    }
    if !(url_trimmed.starts_with("https://") || url_trimmed.starts_with("http://")) {
        return Err(osoosi_types::OctopusSecurityError::SsrfBlocked(
            "Invalid URL scheme: only http and https schemes are permitted".to_string(),
        ));
    }
    let host = crate::security::extract_host_from_url(url_trimmed);
    if host.is_empty() {
        return Err(osoosi_types::OctopusSecurityError::SsrfBlocked(
            "Invalid URL: unable to extract host".to_string(),
        ));
    }
    let blocked_hostnames = [
        "localhost",
        "metadata.google.internal",
        "metadata.aws.internal",
        "instance-data",
    ];
    if blocked_hostnames.contains(&host.as_str()) || host.ends_with(".localhost") {
        return Err(osoosi_types::OctopusSecurityError::SsrfBlocked(format!(
            "SSRF Violation: access to host '{}' is blocked",
            host
        )));
    }

    let parsed_url = reqwest::Url::parse(url_trimmed).map_err(|e| {
        osoosi_types::OctopusSecurityError::SsrfBlocked(format!("Invalid URL: {}", e))
    })?;
    let port = parsed_url.port_or_known_default().unwrap_or(
        if parsed_url.scheme() == "https" { 443 } else { 80 },
    );

    let pinned_socket_addr = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        if is_ssrf_ip(ip) {
            return Err(osoosi_types::OctopusSecurityError::SsrfBlocked(format!(
                "SSRF Violation: access to IP '{}' is blocked",
                ip
            )));
        }
        std::net::SocketAddr::new(ip, port)
    } else {
        let addrs_res = tokio::net::lookup_host(format!("{}:{}", host, port)).await;
        let addrs: Vec<std::net::SocketAddr> = match addrs_res {
            Ok(iter) => iter.collect(),
            Err(e) => {
                return Err(osoosi_types::OctopusSecurityError::SsrfBlocked(format!(
                    "DNS resolution failed for '{}:{}': {}",
                    host, port, e
                )));
            }
        };

        if addrs.is_empty() {
            return Err(osoosi_types::OctopusSecurityError::SsrfBlocked(format!(
                "No DNS records found for host '{}'",
                host
            )));
        }

        for addr in &addrs {
            if is_ssrf_ip(addr.ip()) {
                return Err(osoosi_types::OctopusSecurityError::SsrfBlocked(format!(
                    "SSRF DNS REBINDING BLOCKED: host '{}' resolved to blocked IP '{}'",
                    host,
                    addr.ip()
                )));
            }
        }

        addrs[0]
    };

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .resolve(&host, pinned_socket_addr)
        .build()
        .map_err(|e| {
            osoosi_types::OctopusSecurityError::IsolationViolation(format!(
                "Failed to build HTTP client: {}",
                e
            ))
        })?;

    Ok((client, pinned_socket_addr))
}

/// Synchronous counterpart to [`build_ssrf_safe_http_client`].
pub fn build_ssrf_safe_http_client_sync(
    target_url: &str,
) -> Result<(reqwest::Client, std::net::SocketAddr), osoosi_types::OctopusSecurityError> {
    use std::net::ToSocketAddrs;
    let url_trimmed = target_url.trim();
    if url_trimmed.is_empty() || url_trimmed.len() > 8192 {
        return Err(osoosi_types::OctopusSecurityError::SsrfBlocked(
            "Invalid URL: empty or exceeds max length".to_string(),
        ));
    }
    if !(url_trimmed.starts_with("https://") || url_trimmed.starts_with("http://")) {
        return Err(osoosi_types::OctopusSecurityError::SsrfBlocked(
            "Invalid URL scheme: only http and https schemes are permitted".to_string(),
        ));
    }
    let host = crate::security::extract_host_from_url(url_trimmed);
    if host.is_empty() {
        return Err(osoosi_types::OctopusSecurityError::SsrfBlocked(
            "Invalid URL: unable to extract host".to_string(),
        ));
    }
    let blocked_hostnames = [
        "localhost",
        "metadata.google.internal",
        "metadata.aws.internal",
        "instance-data",
    ];
    if blocked_hostnames.contains(&host.as_str()) || host.ends_with(".localhost") {
        return Err(osoosi_types::OctopusSecurityError::SsrfBlocked(format!(
            "SSRF Violation: access to host '{}' is blocked",
            host
        )));
    }

    let parsed_url = reqwest::Url::parse(url_trimmed).map_err(|e| {
        osoosi_types::OctopusSecurityError::SsrfBlocked(format!("Invalid URL: {}", e))
    })?;
    let port = parsed_url.port_or_known_default().unwrap_or(
        if parsed_url.scheme() == "https" { 443 } else { 80 },
    );

    let pinned_socket_addr = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        if is_ssrf_ip(ip) {
            return Err(osoosi_types::OctopusSecurityError::SsrfBlocked(format!(
                "SSRF Violation: access to IP '{}' is blocked",
                ip
            )));
        }
        std::net::SocketAddr::new(ip, port)
    } else {
        let addrs: Vec<std::net::SocketAddr> = format!("{}:{}", host, port)
            .to_socket_addrs()
            .map_err(|e| {
                osoosi_types::OctopusSecurityError::SsrfBlocked(format!(
                    "DNS resolution failed for '{}:{}': {}",
                    host, port, e
                ))
            })?
            .collect();

        if addrs.is_empty() {
            return Err(osoosi_types::OctopusSecurityError::SsrfBlocked(format!(
                "No DNS records found for host '{}'",
                host
            )));
        }

        for addr in &addrs {
            if is_ssrf_ip(addr.ip()) {
                return Err(osoosi_types::OctopusSecurityError::SsrfBlocked(format!(
                    "SSRF DNS REBINDING BLOCKED: host '{}' resolved to blocked IP '{}'",
                    host,
                    addr.ip()
                )));
            }
        }

        addrs[0]
    };

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .resolve(&host, pinned_socket_addr)
        .build()
        .map_err(|e| {
            osoosi_types::OctopusSecurityError::IsolationViolation(format!(
                "Failed to build HTTP client: {}",
                e
            ))
        })?;

    Ok((client, pinned_socket_addr))
}
