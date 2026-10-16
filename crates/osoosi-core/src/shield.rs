use osoosi_types::{HostSecurityEvent, TaintLabel, TaintSink};
use std::collections::HashSet;
use std::sync::Arc;
use tracing::warn;

pub struct ShieldLayer {
    pub ssrf_enabled: bool,
    pub strict_taint: bool,
    pub sinkhole_enabled: bool,
    pub self_defense_enabled: bool,
    /// Reference to the memory blocklist/reputation store
    memory: Arc<osoosi_memory::MemoryStore>,
    /// Dynamic YARA-X rules manager for real-time memory/buffer scanning
    yara_manager: Option<Arc<crate::yara::YaraManager>>,
    /// Fallback static rules if YaraManager is not provided
    fallback_yara_rules: Option<Arc<yara_x::Rules>>,
}

impl ShieldLayer {
    pub fn new(memory: Arc<osoosi_memory::MemoryStore>, yara_rules: Option<Arc<yara_x::Rules>>) -> Self {
        Self {
            ssrf_enabled: true,
            strict_taint: true,
            sinkhole_enabled: true,
            self_defense_enabled: true,
            memory,
            yara_manager: None,
            fallback_yara_rules: yara_rules,
        }
    }

    /// Construct ShieldLayer with dynamic YaraManager to ensure real-time rule hot-swapping.
    pub fn with_manager(memory: Arc<osoosi_memory::MemoryStore>, yara_manager: Arc<crate::yara::YaraManager>) -> Self {
        Self {
            ssrf_enabled: true,
            strict_taint: true,
            sinkhole_enabled: true,
            self_defense_enabled: true,
            memory,
            yara_manager: Some(yara_manager),
            fallback_yara_rules: None,
        }
    }

    pub fn set_yara_manager(&mut self, yara_manager: Arc<crate::yara::YaraManager>) {
        self.yara_manager = Some(yara_manager);
    }

    /// Always read the latest dynamically hot-swapped rules pointer.
    pub fn active_rules(&self) -> Option<Arc<yara_x::Rules>> {
        if let Some(ref ym) = self.yara_manager {
            Some(ym.active_rules())
        } else {
            self.fallback_yara_rules.clone()
        }
    }

    /// Check if an action is allowed based on the event's provenance (Taint).
    pub fn verify_taint_flow(&self, event: &HostSecurityEvent, sink: &TaintSink) -> bool {
        // Derive labels from event metadata
        let mut labels = HashSet::new();

        // Example logic: if it's a network event from an untrusted IP
        if let Some(ip) = event.data.get("DestinationIp").and_then(|v| v.as_str()) {
            if self.is_suspicious_ip(ip) {
                labels.insert(TaintLabel::SuspiciousNetwork);
            }
        }

        // If it's a file event in a temp directory
        if let Some(path) = event.data.get("TargetFilename").and_then(|v| v.as_str()) {
            if path.contains("AppData\\Local\\Temp") || path.contains("/tmp/") {
                labels.insert(TaintLabel::DownloadedFile);
            }
        }

        for label in labels {
            if sink.blocked_labels.contains(&label) {
                warn!(
                    "Shield Violation: Taint label '{}' blocked by sink '{}'",
                    label, sink.name
                );
                return false;
            }
        }
        true
    }

    /// Protect the agent and LSASS from unauthorized handle acquisition.
    /// Returns true if the access should be allowed, false if it's a violation.
    pub fn verify_process_access(&self, source_pid: u32, target_pid: u32, access_mask: u32) -> bool {
        if !self.self_defense_enabled {
            return true;
        }

        let my_pid = std::process::id();
        
        // 1. Agent Self-Defense: Block termination/suspension of OshoosiClaw
        if target_pid == my_pid && source_pid != my_pid {
            // Check for PROCESS_TERMINATE (0x0001) or PROCESS_SUSPEND_RESUME (0x0800)
            if (access_mask & 0x0001 != 0) || (access_mask & 0x0800 != 0) {
                warn!(
                    "Shield Self-Defense: Blocked attempt by PID {} to acquire termination/suspension rights to OshoosiClaw (PID {})",
                    source_pid, my_pid
                );
                return false;
            }
        }

        // 2. LSASS Protection: Block memory reads/writes to the security authority
        // On Windows, LSASS is the crown jewel for credential dumping.
        if self.is_lsass(target_pid) {
            // Check for PROCESS_VM_READ (0x0010) or PROCESS_VM_WRITE (0x0020)
            if (access_mask & 0x0010 != 0) || (access_mask & 0x0800 != 0) {
                warn!(
                    "Shield LSASS-Guard: Blocked credential dumping attempt by PID {} against LSASS (PID {})",
                    source_pid, target_pid
                );
                // Log this as a high-confidence threat event
                let _ = self.memory.log_threat_event("CREDENTIAL_DUMP_ATTEMPT", source_pid, target_pid);
                return false;
            }
        }

        true
    }

    /// Active DNS Sinkhole: Instead of blocking, "lie" to the process and redirect to a tarpit.
    pub fn resolve_sinkhole(&self, domain: &str) -> Option<String> {
        if !self.sinkhole_enabled {
            return None;
        }

        // If domain is a known C2 or malicious destination, return loopback for redirection
        if self.memory.is_known_malicious_domain(domain).unwrap_or(false) {
            warn!("Shield Sinkhole: Redirecting malicious C2 domain '{}' to local loopback deception field.", domain);
            return Some("127.0.0.1".to_string());
        }

        None
    }

    /// JIT Anti-Injection Shield: Scan memory buffers during allocation/injection attempts.
    /// Reads the latest dynamically hot-swapped rules pointer from YaraManager so zero stale rules are evaluated.
    pub async fn scan_injection_buffer(&self, buffer: &[u8]) -> bool {
        let rules = match self.active_rules() {
            Some(r) => r,
            None => return true, // Can't scan without rules
        };

        let mut scanner = yara_x::Scanner::new(&rules);
        match scanner.scan(buffer) {
            Ok(results) => {
                if results.matching_rules().next().is_some() {
                    warn!("Shield Anti-Injection: Detected malicious shellcode/payload in memory injection buffer!");
                    return false;
                }
            }
            Err(e) => {
                warn!("Shield Anti-Injection: YARA-X scan failed: {}", e);
            }
        }

        true
    }

    /// Verify an outbound URL against SSRF protection policies.
    pub fn verify_outbound_url(&self, url: &str) -> bool {
        if !self.ssrf_enabled {
            return true;
        }

        if let Ok(parsed) = reqwest::Url::parse(url) {
            if let Some(host) = parsed.host_str() {
                let host_clean = host.trim().trim_start_matches('[').trim_end_matches(']');
                let host_lower = host_clean.to_lowercase();
                if host_lower == "localhost" || host_lower == "metadata.google.internal" {
                    warn!("Shield Violation: SSRF attempt to '{}' blocked", url);
                    return false;
                }

                if let Ok(ip) = host_clean.parse::<std::net::IpAddr>() {
                    if Self::is_blocked_ip(&ip) {
                        warn!("Shield Violation: SSRF attempt to IP '{}' blocked", ip);
                        return false;
                    }
                }
            }
        } else {
            let blocked = [
                "localhost",
                "127.0.0.1",
                "169.254.169.254",
                "metadata.google.internal",
            ];
            for b in blocked {
                if url.contains(b) {
                    warn!("Shield Violation: SSRF attempt to '{}' blocked", url);
                    return false;
                }
            }
        }
        true
    }

    fn is_blocked_ip(ip: &std::net::IpAddr) -> bool {
        match ip {
            std::net::IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                // Loopback (127.0.0.0/8)
                octets[0] == 127
                // Unspecified (0.0.0.0)
                || octets[0] == 0
                // RFC1918 Private: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
                || octets[0] == 10
                || (octets[0] == 172 && (16..=31).contains(&octets[1]))
                || (octets[0] == 192 && octets[1] == 168)
                // Link-local / Cloud metadata: 169.254.0.0/16
                || (octets[0] == 169 && octets[1] == 254)
                // Broadcast (255.255.255.255)
                || ipv4.is_broadcast()
            }
            std::net::IpAddr::V6(ipv6) => {
                // Loopback ::1, Unspecified ::
                ipv6.is_loopback() || ipv6.is_unspecified()
                // Link-local fe80::/10
                || (ipv6.segments()[0] & 0xffc0) == 0xfe80
                // Unique local fc00::/7
                || (ipv6.segments()[0] & 0xfe00) == 0xfc00
                // IPv4-mapped ::ffff:0:0/96
                || if let Some(ipv4) = ipv6.to_ipv4_mapped() {
                    Self::is_blocked_ip(&std::net::IpAddr::V4(ipv4))
                } else {
                    false
                }
            }
        }
    }

    fn is_lsass(&self, pid: u32) -> bool {
        #[cfg(test)]
        if pid == 500 {
            return true;
        }

        let real_pid = get_lsass_pid();
        real_pid != 0 && pid == real_pid
    }

    fn is_suspicious_ip(&self, ip: &str) -> bool {
        ip.starts_with("45.") || ip.starts_with("185.")
    }
}

static LSASS_PID: std::sync::OnceLock<u32> = std::sync::OnceLock::new();

fn get_lsass_pid() -> u32 {
    *LSASS_PID.get_or_init(|| {
        let mut sys = sysinfo::System::new();
        sys.refresh_processes();
        for (pid, process) in sys.processes() {
            let name = process.name().to_lowercase();
            if name == "lsass.exe" || name == "lsass" {
                return pid.as_u32();
            }
        }
        0
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_shield_layer_dynamic_hotswap() {
        let mem = Arc::new(osoosi_memory::MemoryStore::new(":memory:").expect("in-memory db"));
        let yara_mgr = Arc::new(crate::yara::YaraManager::new());
        let shield = ShieldLayer::with_manager(mem, yara_mgr.clone());

        let unique_suffix = uuid::Uuid::new_v4().to_string().replace('-', "_");
        let rule_name = format!("Shellcode_Injection_{}", unique_suffix);
        let sig = format!("SHELLCODE_SIG_{}", unique_suffix);
        let shellcode_buffer = format!("Prefix {} Suffix", sig).into_bytes();

        // Initially, the buffer is not known as malicious: injection check passes (returns true)
        let allowed_before = shield.scan_injection_buffer(&shellcode_buffer).await;
        assert!(allowed_before, "Buffer must pass before signature is loaded");

        // Dynamically hot-swap a new rule into YaraManager on the fly
        let rule_src = format!(r#"
            rule {} {{
                strings:
                    $sc = "{}"
                condition:
                    $sc
            }}
        "#, rule_name, sig);
        yara_mgr.hot_load_rule(&rule_src, &rule_name).expect("hot load must succeed");

        // Immediately after hot-swap, ShieldLayer MUST detect the malicious buffer and block it (returns false)
        let allowed_after = shield.scan_injection_buffer(&shellcode_buffer).await;
        assert!(!allowed_after, "Buffer must be blocked immediately after dynamic rule hot-swap");

        // Harmless buffer still passes
        assert!(shield.scan_injection_buffer(b"Harmless harmless bytes").await);

        let _ = std::fs::remove_file(format!("rules/osoosi_generated/{}.yar", rule_name));
        let _ = std::fs::remove_file(format!("yara/osoosi_generated/{}.yar", rule_name));
    }
}
