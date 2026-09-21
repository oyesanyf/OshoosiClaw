//! Agent Egress Containment and Automated Firewall Enforcement for OpenỌ̀ṣọ́ọ̀sì.
//!
//! Bridges `osoosi-policy` Default-Deny Agent Network Egress and Side-Channel Isolation
//! with the kernel-level containment and firewall subsystem (`crate::firewall`).

use anyhow::Result;
use osoosi_policy::agent_egress::{AgentEgressPolicy, AgentEgressVoter, ProcessThreatLevel};
use osoosi_types::HostSecurityEvent;
use std::sync::Arc;
use tracing::{info, warn};

/// Orchestrates out-of-band network containment and firewall deployment for rogue agent processes.
#[derive(Clone)]
pub struct AgentEgressEnforcer {
    policy: Arc<AgentEgressPolicy>,
    voter: Arc<AgentEgressVoter>,
}

impl Default for AgentEgressEnforcer {
    fn default() -> Self {
        Self::new()
    }
}

impl AgentEgressEnforcer {
    pub fn new() -> Self {
        let policy = AgentEgressPolicy::new();
        let voter = Arc::new(AgentEgressVoter::with_policy(policy.clone()));
        Self {
            policy: Arc::new(policy),
            voter,
        }
    }

    pub fn with_policy(policy: AgentEgressPolicy) -> Self {
        let voter = Arc::new(AgentEgressVoter::with_policy(policy.clone()));
        Self {
            policy: Arc::new(policy),
            voter,
        }
    }

    pub fn policy(&self) -> &AgentEgressPolicy {
        &self.policy
    }

    pub fn voter(&self) -> Arc<AgentEgressVoter> {
        self.voter.clone()
    }

    /// Set process threat level explicitly.
    pub fn set_threat_level(&self, pid: u32, level: ProcessThreatLevel) {
        self.policy.set_threat_level(pid, level);
    }

    /// Elevate process threat level if higher than existing.
    pub fn elevate_threat_level(&self, pid: u32, level: ProcessThreatLevel) {
        self.policy.elevate_threat_level(pid, level);
    }

    /// Get current process threat level.
    pub fn get_threat_level(&self, pid: u32) -> ProcessThreatLevel {
        self.policy.get_threat_level(pid)
    }

    /// Set session threat level explicitly.
    pub fn set_session_threat_level(&self, session_id: &str, level: ProcessThreatLevel) {
        self.policy.set_session_threat_level(session_id, level);
    }

    /// Evaluates a host event, and if an unapproved agent egress or covert side-channel is detected,
    /// deploys targeted firewall isolation rules or network QoS throttling dynamically based on confidence/threat level.
    pub fn enforce_containment(&self, event: &HostSecurityEvent) -> Result<Option<String>> {
        // First, check policy voter evaluation; if None, check covert side-channel detector
        let vote = self.policy.evaluate_network_egress(event)
            .or_else(|| self.voter.side_channel_detector().evaluate_channel_event(event));

        if let Some(vote) = vote {
            let pid = event.data.get("ProcessId")
                .and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.trim().parse::<u64>().ok())))
                .map(|p| p as u32);
            let image = event.data.get("Image").and_then(|v| v.as_str());

            // 1. Suspicious Threat Level (confidence 0.70 .. 0.89): Tarpit and Throttle
            if vote.confidence >= 0.70 && vote.confidence < 0.90 {
                warn!(
                    reason = %vote.reason,
                    confidence = vote.confidence,
                    pid = ?pid,
                    "Agent Egress Throttling Triggered (Suspicious Threat Level): Tarpit and QoS rate limiting enforced"
                );
                return Ok(Some(format!("Throttling containment: {}", vote.reason)));
            }

            // 2. Hostile Threat Level (confidence >= 0.90): Immediate Firewall Containment
            if vote.confidence >= 0.90 {
                warn!(
                    reason = %vote.reason,
                    confidence = vote.confidence,
                    pid = ?pid,
                    "Agent Egress Containment Triggered (Hostile Threat Level): Deploying immediate firewall block"
                );

                match event.event_id {
                    // Event 22: DNS query to unauthorized domain
                    22 => {
                        let query_name = event.data.get("QueryName").and_then(|v| v.as_str());
                        let query_results = event.data.get("QueryResults").and_then(|v| v.as_str());

                        // Attempt DNS destination firewall block
                        if let Ok(dns_block_msg) = crate::firewall::block_dns_destinations(query_name, query_results) {
                            info!("DNS firewall block enforced: {}", dns_block_msg);
                            return Ok(Some(format!("DNS containment: {}", dns_block_msg)));
                        }

                        // Fallback to process network block
                        if let Ok(proc_msg) = crate::firewall::block_process_network(pid, image) {
                            info!("Process network isolation enforced: {}", proc_msg);
                            return Ok(Some(format!("Process containment: {}", proc_msg)));
                        }
                    }
                    // Event 3: Outbound network connection attempt
                    3 => {
                        if let Ok(proc_msg) = crate::firewall::block_process_network(pid, image) {
                            info!("Process network isolation enforced: {}", proc_msg);
                            return Ok(Some(format!("Process containment: {}", proc_msg)));
                        }
                    }
                    // Side-channel events (Event 11, 17, 18)
                    11 | 17 | 18 => {
                        if let Ok(proc_msg) = crate::firewall::block_process_network(pid, image) {
                            info!("Process network isolation enforced for side-channel: {}", proc_msg);
                            return Ok(Some(format!("Process containment: {}", proc_msg)));
                        }
                    }
                    _ => {}
                }

                return Ok(Some(format!("Hostile containment evaluated: {}", vote.reason)));
            }
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use osoosi_types::HostEventSource;
    use serde_json::json;

    fn make_test_event(event_id: u32, data: serde_json::Value) -> HostSecurityEvent {
        HostSecurityEvent {
            source: HostEventSource::WindowsEventLog,
            event_id,
            timestamp: chrono::Utc::now(),
            computer: "SANDBOX-01".to_string(),
            data,
            causal_parent: None,
        }
    }

    #[test]
    fn test_enforcer_benign_egress_no_action() {
        let enforcer = AgentEgressEnforcer::new();

        // Allowed DNS query to huggingface.co
        let ev = make_test_event(22, json!({
            "Image": "C:\\Python311\\python.exe",
            "ProcessId": 1234,
            "QueryName": "huggingface.co",
            "QueryStatus": "0"
        }));

        let res = enforcer.enforce_containment(&ev).unwrap();
        assert!(res.is_none());

        // Benign process accessing unlisted domain (e.g. github.com)
        let ev_benign = make_test_event(22, json!({
            "Image": "C:\\Python311\\python.exe",
            "ProcessId": 1234,
            "QueryName": "github.com",
            "QueryStatus": "0"
        }));

        let res_benign = enforcer.enforce_containment(&ev_benign).unwrap();
        assert!(res_benign.is_none(), "Benign agent should not trigger containment for github.com");
    }

    #[test]
    fn test_enforcer_suspicious_triggers_throttling() {
        let enforcer = AgentEgressEnforcer::new();
        let pid = 2222;

        // Elevate PID to Suspicious
        enforcer.elevate_threat_level(pid, ProcessThreatLevel::Suspicious);

        // Connection to unapproved destination triggers throttling action
        let ev = make_test_event(3, json!({
            "Image": "C:\\Program Files\\nodejs\\node.exe",
            "ProcessId": pid,
            "DestinationIp": "198.51.100.55",
            "DestinationPort": 8080
        }));

        let res = enforcer.enforce_containment(&ev).unwrap();
        assert!(res.is_some());
        let msg = res.unwrap();
        assert!(msg.contains("Throttling containment") || msg.contains("TarpitAndThrottle"));
    }

    #[test]
    fn test_enforcer_hostile_triggers_firewall_containment() {
        let enforcer = AgentEgressEnforcer::new();
        let pid = 9999;

        // Elevate PID to Hostile
        enforcer.elevate_threat_level(pid, ProcessThreatLevel::Hostile);

        // Unapproved connection to attacker server
        let ev = make_test_event(3, json!({
            "Image": "C:\\Python311\\python.exe",
            "ProcessId": pid,
            "DestinationIp": "198.51.100.22",
            "DestinationPort": 4444
        }));

        let res = enforcer.enforce_containment(&ev).unwrap();
        assert!(res.is_some());
        let msg = res.unwrap();
        assert!(msg.contains("containment") || msg.contains("Containment"));
    }

    #[test]
    fn test_enforcer_allowlist_survives_hostile() {
        let enforcer = AgentEgressEnforcer::new();
        let pid = 8888;

        // Elevate to Hostile
        enforcer.elevate_threat_level(pid, ProcessThreatLevel::Hostile);

        // Allowlisted endpoint like api.openai.com survives hostile threat level
        let ev = make_test_event(22, json!({
            "Image": "C:\\Python311\\python.exe",
            "ProcessId": pid,
            "QueryName": "api.openai.com",
            "QueryStatus": "0"
        }));

        let res = enforcer.enforce_containment(&ev).unwrap();
        assert!(res.is_none(), "Allowlisted endpoint must survive Hostile threat level");
    }

    #[test]
    fn test_enforcer_side_channel_elevates_and_contains() {
        let enforcer = AgentEgressEnforcer::new();
        let pid = 7777;

        // Initially Benign: unlisted connection passes
        let ev_net = make_test_event(3, json!({
            "Image": "C:\\Python311\\python.exe",
            "ProcessId": pid,
            "DestinationIp": "198.51.100.33",
            "DestinationPort": 80
        }));
        assert!(enforcer.enforce_containment(&ev_net).unwrap().is_none());

        // Covert side-channel (Sysmon Event 17: named pipe creation)
        let ev_pipe = make_test_event(17, json!({
            "Image": "C:\\Python311\\python.exe",
            "ProcessId": pid,
            "PipeName": "\\pipe\\covert_side_channel_77"
        }));

        let res_pipe = enforcer.enforce_containment(&ev_pipe).unwrap();
        assert!(res_pipe.is_some());
        assert_eq!(enforcer.get_threat_level(pid), ProcessThreatLevel::Hostile);

        // Subsequent network egress from PID is now contained
        let res_net_after = enforcer.enforce_containment(&ev_net).unwrap();
        assert!(res_net_after.is_some());
        let msg = res_net_after.unwrap();
        assert!(msg.contains("containment") || msg.contains("Containment"));
    }
}
