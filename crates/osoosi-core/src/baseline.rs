//! Behavioral baselining: per-host norms for process/network activity.
//! Flags anomalies (e.g. first outbound connection from a process).

use dashmap::DashMap;
use std::collections::HashSet;
use std::sync::Arc;

pub fn baseline_enabled() -> bool {
    std::env::var("OSOOSI_BASELINE_ENABLED")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(true)
}

/// Per-host baseline: process -> (seen destinations, seen domains).
type HostBaseline = DashMap<String, (HashSet<String>, HashSet<String>)>;

#[derive(Clone, Default)]
pub struct BehavioralBaseline {
    /// host -> (process -> (dest_ips, query_domains))
    hosts: Arc<DashMap<String, HostBaseline>>,
}

impl BehavioralBaseline {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a network connection. Returns true if this is the first outbound from this process (anomaly).
    pub fn record_network(&self, host: &str, process: &str, dest_ip: &str) -> bool {
        if !baseline_enabled() || dest_ip.is_empty() {
            return false;
        }
        let host_map = self.hosts.entry(host.to_string()).or_default();
        let mut entry = host_map
            .entry(process.to_string())
            .or_insert_with(|| (HashSet::new(), HashSet::new()));
        let is_first = !entry.0.contains(dest_ip);
        entry.0.insert(dest_ip.to_string());
        is_first && entry.0.len() == 1
    }

    /// Record a DNS query. Returns true if this is the first query to this domain from this process (anomaly).
    pub fn record_dns(&self, host: &str, process: &str, query_name: &str) -> bool {
        if !baseline_enabled() || query_name.is_empty() {
            return false;
        }
        let domain = query_name.trim_end_matches('.').to_lowercase();
        if domain.is_empty() {
            return false;
        }
        let host_map = self.hosts.entry(host.to_string()).or_default();
        let mut entry = host_map
            .entry(process.to_string())
            .or_insert_with(|| (HashSet::new(), HashSet::new()));
        let is_first = !entry.1.contains(&domain);
        entry.1.insert(domain);
        is_first && entry.1.len() == 1
    }

    /// Check if process has been seen before on this host.
    pub fn is_known_process(&self, host: &str, process: &str) -> bool {
        self.hosts
            .get(host)
            .map(|m| {
                m.get(process)
                    .map(|e| !e.0.is_empty() || !e.1.is_empty())
                    .unwrap_or(false)
            })
            .unwrap_or(false)
    }
}
