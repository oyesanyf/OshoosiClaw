//! DNS Blocklist Manager
//!
//! Maintains a set of known-malicious domains from OTX, abuse.ch, and
//! custom user-defined lists. Supports wildcard matching and fast lookups.

use dashmap::DashMap;
use std::path::Path;
use tracing::info;

/// Thread-safe DNS blocklist with O(1) lookups.
pub struct DnsBlocklist {
    /// Exact domain matches (e.g., "evil.com")
    domains: DashMap<String, String>, // domain -> reason
}

impl DnsBlocklist {
    pub fn new() -> Self {
        let bl = Self {
            domains: DashMap::new(),
        };
        bl.load_builtin();
        bl
    }

    /// Check if a domain (or any parent domain) is blocked.
    pub fn is_blocked(&self, domain: &str) -> Option<String> {
        let domain_lower = domain.to_lowercase().trim_end_matches('.').to_string();

        // Exact match
        if let Some(reason) = self.domains.get(&domain_lower) {
            return Some(reason.clone());
        }

        // Walk up the domain hierarchy (e.g., sub.evil.com -> evil.com -> com)
        let labels: Vec<&str> = domain_lower.split('.').collect();
        for i in 1..labels.len() {
            let parent = labels[i..].join(".");
            if let Some(reason) = self.domains.get(&parent) {
                return Some(format!("Wildcard match via parent '{}': {}", parent, reason.value()));
            }
        }

        None
    }

    /// Add a domain to the blocklist.
    pub fn add(&self, domain: &str, reason: &str) {
        self.domains.insert(
            domain.to_lowercase().trim_end_matches('.').to_string(),
            reason.to_string(),
        );
    }

    /// Load domains from a newline-delimited text file.
    pub fn load_from_file(&self, path: &Path) -> anyhow::Result<usize> {
        let content = std::fs::read_to_string(path)?;
        let mut count = 0;
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            self.add(trimmed, "Custom blocklist");
            count += 1;
        }
        info!("Loaded {} domains from {:?}", count, path);
        Ok(count)
    }

    /// Number of blocked domains.
    pub fn len(&self) -> usize {
        self.domains.len()
    }

    pub fn is_empty(&self) -> bool {
        self.domains.is_empty()
    }

    /// Load built-in high-confidence malicious domains.
    fn load_builtin(&self) {
        let builtins = [
            // Known C2 infrastructure patterns
            ("cobalt-strike.com", "Known Cobalt Strike C2 infrastructure"),
            ("cobaltstrike.com", "Known Cobalt Strike C2 infrastructure"),
            // Cryptocurrency mining pools (cryptojacking)
            ("coinhive.com", "Cryptojacking: browser-based cryptocurrency miner"),
            ("coin-hive.com", "Cryptojacking: browser-based cryptocurrency miner"),
            ("minero.cc", "Cryptojacking pool"),
            ("crypto-loot.com", "Cryptojacking pool"),
            // Phishing/malware distribution
            ("malware-traffic-analysis.net", "Malware analysis tracker (not malicious itself, but often queried by samples)"),
            // Abuse infrastructure
            ("ddns.net", "Dynamic DNS: frequently abused for C2"),
            ("no-ip.org", "Dynamic DNS: frequently abused for C2"),
            ("duckdns.org", "Dynamic DNS: frequently abused for C2"),
            ("serveo.net", "Tunnel service: frequently abused for C2"),
            ("ngrok.io", "Tunnel service: frequently abused for C2"),
            ("pagekite.me", "Tunnel service: frequently abused for C2"),
            // Data exfiltration services
            ("transfer.sh", "File sharing: potential data exfiltration"),
            ("file.io", "Ephemeral file sharing: potential data exfiltration"),
            ("anonfiles.com", "Anonymous file sharing: potential data exfiltration"),
        ];

        for (domain, reason) in builtins {
            self.add(domain, reason);
        }
        info!("DNS Shield: Loaded {} built-in blocklist entries", builtins.len());
    }
}

impl Default for DnsBlocklist {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match() {
        let bl = DnsBlocklist::new();
        assert!(bl.is_blocked("coinhive.com").is_some());
        assert!(bl.is_blocked("google.com").is_none());
    }

    #[test]
    fn test_wildcard_match() {
        let bl = DnsBlocklist::new();
        bl.add("evil.com", "Test");
        assert!(bl.is_blocked("sub.evil.com").is_some());
        assert!(bl.is_blocked("deep.sub.evil.com").is_some());
    }

    #[test]
    fn test_custom_add() {
        let bl = DnsBlocklist::new();
        bl.add("my-c2-server.ru", "Custom C2");
        assert!(bl.is_blocked("my-c2-server.ru").is_some());
    }
}
