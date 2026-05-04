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
    /// YARA-X rules for real-time memory/buffer scanning
    yara_rules: Option<Arc<yara_x::Rules>>,
}

impl ShieldLayer {
    pub fn new(memory: Arc<osoosi_memory::MemoryStore>, yara_rules: Option<Arc<yara_x::Rules>>) -> Self {
        Self {
            ssrf_enabled: true,
            strict_taint: true,
            sinkhole_enabled: true,
            self_defense_enabled: true,
            memory,
            yara_rules,
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
            if (access_mask & 0x0010 != 0) || (access_mask & 0x0020 != 0) {
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
    pub async fn scan_injection_buffer(&self, buffer: &[u8]) -> bool {
        let rules = match &self.yara_rules {
            Some(r) => r,
            None => return true, // Can't scan without rules
        };

        let mut scanner = yara_x::Scanner::new(rules);
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
        true
    }

    fn is_lsass(&self, pid: u32) -> bool {
        // In a real implementation, we'd lookup the process name by PID.
        // For now, we rely on the orchestrator passing verified LSASS PIDs.
        pid == 500 // Placeholder for standard system PID
    }

    fn is_suspicious_ip(&self, ip: &str) -> bool {
        ip.starts_with("45.") || ip.starts_with("185.")
    }
}
