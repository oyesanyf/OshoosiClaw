//! Atomic IOC Detection Engine (Adapted from Rustinel).
//!
//! Supports matching against Domain, IP/CIDR, Hash, and Path Regex indicators.

use osoosi_types::HostSecurityEvent;
use std::collections::HashSet;
use std::net::IpAddr;
use ipnetwork::IpNetwork;
use regex::RegexSet;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IocKind {
    Domain,
    Ip,
    Md5,
    Sha1,
    Sha256,
    PathRegex,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocMatch {
    pub kind: IocKind,
    pub indicator: String,
    pub matched_value: String,
    pub source: String,
}

pub struct IocEngine {
    domain_exact: HashSet<String>,
    domain_suffix: Vec<String>,
    ip_exact: HashSet<IpAddr>,
    ip_cidr: Vec<IpNetwork>,
    path_regex: Option<RegexSet>,
    path_patterns: Vec<String>,
    hashes: HashSet<String>,
    pub total_detections: std::sync::atomic::AtomicU64,
}

impl Default for IocEngine {
    fn default() -> Self { Self::new() }
}

impl IocEngine {
    pub fn new() -> Self {
        Self {
            domain_exact: HashSet::new(),
            domain_suffix: Vec::new(),
            ip_exact: HashSet::new(),
            ip_cidr: Vec::new(),
            path_regex: None,
            path_patterns: Vec::new(),
            hashes: HashSet::new(),
            total_detections: std::sync::atomic::AtomicU64::new(0),
        }
    }

    pub fn indicator_count(&self) -> usize {
        self.domain_exact.len() + self.domain_suffix.len() + self.ip_exact.len() + self.ip_cidr.len() + self.path_patterns.len() + self.hashes.len()
    }

    pub fn load_from_files(&mut self, base_path: &std::path::Path) {
        // In a real EDR, we'd load from text files. 
        // For OshoosiClaw, we'll look for domains.txt, ips.txt, etc.
        if let Ok(d) = std::fs::read_to_string(base_path.join("domains.txt")) {
            for line in d.lines().filter(|l| !l.is_empty()) {
                if line.starts_with('.') {
                    self.domain_suffix.push(line[1..].to_lowercase());
                } else {
                    self.domain_exact.insert(line.to_lowercase());
                }
            }
        }

        if let Ok(i) = std::fs::read_to_string(base_path.join("ips.txt")) {
            for line in i.lines().filter(|l| !l.is_empty()) {
                if let Ok(ip) = line.parse::<IpAddr>() {
                    self.ip_exact.insert(ip);
                } else if let Ok(net) = line.parse::<IpNetwork>() {
                    self.ip_cidr.push(net);
                }
            }
        }

        if let Ok(h) = std::fs::read_to_string(base_path.join("hashes.txt")) {
            for line in h.lines().filter(|l| !l.is_empty()) {
                self.hashes.insert(line.to_lowercase());
            }
        }
    }

    pub fn check_event(&self, event: &HostSecurityEvent) -> Vec<IocMatch> {
        let mut matches = Vec::new();

        // 1. Check Domains
        if let Some(domain) = event.data.get("DestinationHostname").and_then(|v| v.as_str()) {
            let d = domain.to_lowercase();
            if self.domain_exact.contains(&d) || self.domain_suffix.iter().any(|s| d.ends_with(s)) {
                matches.push(IocMatch {
                    kind: IocKind::Domain,
                    indicator: d.clone(),
                    matched_value: d,
                    source: "local-ioc".to_string(),
                });
            }
        }

        // 2. Check IPs
        if let Some(ip_str) = event.data.get("DestinationIp").and_then(|v| v.as_str()) {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                if self.ip_exact.contains(&ip) || self.ip_cidr.iter().any(|net| net.contains(ip)) {
                    matches.push(IocMatch {
                        kind: IocKind::Ip,
                        indicator: ip.to_string(),
                        matched_value: ip_str.to_string(),
                        source: "local-ioc".to_string(),
                    });
                }
            }
        }

        // 3. Check Hashes
        if let Some(hashes) = event.data.get("Hashes").and_then(|v| v.as_str()) {
            for part in hashes.split(',') {
                if let Some(hash) = part.split('=').last() {
                    let h = hash.to_lowercase();
                    if self.hashes.contains(&h) {
                        matches.push(IocMatch {
                            kind: if h.len() == 64 { IocKind::Sha256 } else { IocKind::Md5 },
                            indicator: h.clone(),
                            matched_value: h,
                            source: "local-ioc".to_string(),
                        });
                    }
                }
            }
        }
        
        if !matches.is_empty() {
            self.total_detections.fetch_add(matches.len() as u64, std::sync::atomic::Ordering::Relaxed);
        }

        matches
    }
}
