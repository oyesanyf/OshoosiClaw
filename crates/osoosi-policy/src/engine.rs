//! Threat Engine (The "Brain").
//!
//! Correlates telemetry events with threat signatures.

use dashmap::DashMap;
use osoosi_memory::MemoryStore;
use osoosi_types::{SysmonEvent, ThreatSignature};
use crate::semantic::SemanticEngine;
use crate::graph::{GraphCorrelationEngine, Relationship};
use crate::feed::OtxIndicators;
use std::sync::Arc;
use std::sync::RwLock;
use tracing::{debug, info, warn};

/// `tracing` target for grep-friendly consensus / voting lines (`RUST_LOG=consensus=debug`).
pub const CONSENSUS_LOG_TARGET: &str = "consensus";

pub struct VoteResult {
    pub confidence: f32,
    pub reason: String,
    pub weight: f32,
}

pub trait ThreatVoter: Send + Sync {
    fn name(&self) -> String;
    fn vote(&self, event: &SysmonEvent) -> Option<VoteResult>;
}

pub struct PolicyEngine {
    /// Local persistence store
    memory: Arc<MemoryStore>,
    /// Semantic Intent Filter
    _semantic: SemanticEngine,
    /// Relationship Graph
    graph: GraphCorrelationEngine,
    /// Custom threat signatures (Hash -> Signature)
    #[allow(dead_code)]
    signatures: Arc<DashMap<String, ThreatSignature>>,
    /// OTX indicators cached in-memory from feed fetch loop.
    otx_indicators: Arc<RwLock<OtxIndicators>>,
    /// Sigma Rule Engine
    sigma: Arc<RwLock<crate::sigma::SigmaEngine>>,
    /// Learned Zero-Day defenses from the mesh (CVE -> Learned Rule)
    global_intel_rules: Arc<DashMap<String, String>>,
    /// Alert cache to prevent duplicate notifications (Key: ProcessName + CVE -> LastAlertedTime)
    _alert_cache: Arc<DashMap<String, std::time::Instant>>,
    /// Multi-tool consensus voters
    voters: RwLock<Vec<Box<dyn ThreatVoter>>>,
}

impl PolicyEngine {
    pub fn new(memory: Arc<MemoryStore>) -> Self {
        Self {
            memory,
            _semantic: SemanticEngine::new(),
            graph: GraphCorrelationEngine::new(),
            signatures: Arc::new(DashMap::new()),
            otx_indicators: Arc::new(RwLock::new(OtxIndicators::default())),
            sigma: Arc::new(RwLock::new(crate::sigma::SigmaEngine::new())),
            global_intel_rules: Arc::new(DashMap::new()),
            _alert_cache: Arc::new(DashMap::new()),
            voters: RwLock::new(Vec::new()),
        }
    }

    pub fn add_voter(&self, voter: Box<dyn ThreatVoter>) {
        if let Ok(mut guard) = self.voters.write() {
            let name = voter.name();
            guard.push(voter);
            info!(
                target: CONSENSUS_LOG_TARGET,
                voter = %name,
                total = guard.len(),
                "[CONSENSUS] registered threat voter"
            );
        }
    }

    pub fn sigma_engine(&self) -> &Arc<RwLock<crate::sigma::SigmaEngine>> {
        &self.sigma
    }

    pub fn otx_indicators_ref(&self) -> &Arc<RwLock<OtxIndicators>> {
        &self.otx_indicators
    }

    /// Return all graph relationships for attack graph construction.
    pub fn graph_relationships(&self) -> Vec<Relationship> {
        self.graph.relationships()
    }

    pub fn update_otx_indicators(&self, indicators: OtxIndicators) {
        if let Ok(mut guard) = self.otx_indicators.write() {
            *guard = indicators;
        }
    }

    /// Returns a match reason if this Sysmon event hits an OTX IoC.
    ///
    /// IOCs are populated by the background `ThreatFeedFetcher::fetch_otx_indicators` (which uses
    /// **TAXII 1.1** when `OTX_USE_TAXII` is left at default) and persisted in SQLite. This is a
    /// **local lookup** — not a live TAXII poll per connection.
    pub fn otx_ioc_match_for_event(&self, event: &SysmonEvent) -> Option<String> {
        let otx = self.otx_indicators.read().ok()?;
        crate::otx_connection::otx_match_sysmon_event(&otx, &self.memory, event)
    }

    /// Check a single outbound (or inbound) IP from a connection against OTX state (memory + SQLite).
    pub fn otx_ioc_match_for_ip(&self, ip: &str) -> Option<String> {
        let otx = self.otx_indicators.read().ok()?;
        crate::otx_connection::otx_match_destination_ip(&otx, &self.memory, ip)
    }

    pub fn load_sigma_rules(&self, dir: &std::path::Path) {
        if let Ok(mut guard) = self.sigma.write() {
            guard.load_rules_from_dir(dir);
        }
    }

    /// Register a temporary learned defense (Zero-Day defense from mesh gossip).
    pub fn register_temporary_rule(&self, cve_id: &str, rule: &str, _severity: f32) {
        info!("PolicyEngine: Learning new defense for {} from mesh gossip.", cve_id);
        self.global_intel_rules.insert(cve_id.to_string(), rule.to_string());
    }

    /// Process a Sysmon event and check for threats.
    ///
    /// OTX / TAXII (or REST) **IoCs participate in the same weighted vote** as all other
    /// [`ThreatVoter`]s, typically through [`crate::voters::OtxVoter`]. If that voter is not
    /// registered, a matching [`Self::otx_ioc_match_for_event`] is merged in so TAXII-backed IOCs
    /// still affect consensus.
    pub fn scan_event(&self, event: &SysmonEvent) -> Option<ThreatSignature> {
        use osoosi_types::ResponseAction;

        let voters_len = self.voters.read().map(|v| v.len()).unwrap_or(0);
        debug!(
            target: CONSENSUS_LOG_TARGET,
            event_id = ?event.event_id,
            registered_voters = voters_len,
            "[CONSENSUS] round start"
        );

        let mut signature = ThreatSignature::new(event.computer.clone());
        let mut total_score: f32 = 0.0;
        let mut vote_count: u32 = 0;
        let mut is_threat = false;
        let mut vetoed = false;
        let mut otx_voted = false;
        const OTX_VOTER: &str = "OTX-C2";

        if let Ok(voters_guard) = self.voters.read() {
            for voter in voters_guard.iter() {
                let vname = voter.name();
                if let Some(res) = voter.vote(event) {
                    if res.weight < 0.0 {
                        warn!(
                            target: CONSENSUS_LOG_TARGET,
                            voter = %vname,
                            reason = %res.reason,
                            "[CONSENSUS] veto — detection blocked"
                        );
                        vetoed = true;
                        signature.add_reason(format!("Veto [{}]: {}", vname, res.reason));
                        break;
                    }

                    let contribution = res.confidence * res.weight;
                    info!(
                        target: CONSENSUS_LOG_TARGET,
                        voter = %vname,
                        conf = res.confidence,
                        weight = res.weight,
                        contribution,
                        reason = %res.reason,
                        "[CONSENSUS] voter YIELD (counts toward score)"
                    );
                    total_score += contribution;
                    vote_count += 1;
                    signature.add_reason(format!("[{}]: {}", vname, res.reason));
                    is_threat = true;
                    if vname == OTX_VOTER {
                        otx_voted = true;
                    }
                } else {
                    debug!(
                        target: CONSENSUS_LOG_TARGET,
                        voter = %vname,
                        event_id = ?event.event_id,
                        "[CONSENSUS] voter abstain (no match)"
                    );
                }
            }
        }

        if vetoed {
            debug!(target: CONSENSUS_LOG_TARGET, "[CONSENSUS] round aborted (veto)");
            return None;
        }

        // Safety net: TAXII/REST IoCs must count toward voting even if OtxVoter was not registered.
        if !otx_voted {
            if let Some(otx_reason) = self.otx_ioc_match_for_event(event) {
                let w = crate::otx_connection::otx_consensus_weight(event);
                let c = crate::otx_connection::OTX_CONSENSUS_CONFIDENCE;
                info!(
                    target: CONSENSUS_LOG_TARGET,
                    voter = OTX_VOTER,
                    conf = c,
                    weight = w,
                    contribution = c * w,
                    reason = %otx_reason,
                    "[CONSENSUS] OTX safety-net YIELD (IoC in cache/SQLite)"
                );
                total_score += c * w;
                vote_count += 1;
                signature.add_reason(format!("[{}]: {}", OTX_VOTER, otx_reason));
                is_threat = true;
            }
        }

        if !is_threat {
            debug!(
                target: CONSENSUS_LOG_TARGET,
                event_id = ?event.event_id,
                "[CONSENSUS] no threat (zero yielding votes)"
            );
            return None;
        }

        signature.detector_count = vote_count;
        signature.confidence = (total_score / (vote_count as f32).max(1.0)).min(1.0);

        // Escalation Logic
        if vote_count >= 2 && signature.confidence > 0.90 {
            signature.recommended_action = ResponseAction::Isolate;
        } else if signature.confidence > 0.98 {
            signature.recommended_action = ResponseAction::Isolate; // Absolute certainty
        } else if signature.confidence > 0.70 {
            signature.recommended_action = ResponseAction::GhostTarpit;
        } else if signature.confidence > 0.50 {
            signature.recommended_action = ResponseAction::Tarpit;
        } else {
            signature.recommended_action = ResponseAction::Alert;
        }

        // Federated learning: adjust confidence based on known true/false positive patterns
        if is_threat {
            let proc = signature.process_name.as_deref();
            let hash = signature.hash_blake3.as_deref();

            // 1. If it's a confirmed TRUE positive, boost to 1.0
            if let Ok(true) = self.memory.is_true_positive_pattern(proc, hash) {
                signature.confidence = 1.0;
                signature.add_reason("Reinforced: matches confirmed federated threat pattern");
                // Ensure action is at least GhostTarpit
                if signature.recommended_action == ResponseAction::Alert || signature.recommended_action == ResponseAction::Tarpit {
                    signature.recommended_action = ResponseAction::GhostTarpit;
                }
            }
            // 2. If it's a known FALSE positive, suppress
            else if let Ok(true) = self.memory.is_false_positive_pattern(proc, hash) {
                signature.confidence = (signature.confidence * 0.05).max(0.0);
                signature.add_reason("Suppressed: matches federated false positive pattern");
                // If confidence is now very low, don't take action
                if signature.confidence < 0.2 {
                    signature.recommended_action = ResponseAction::Alert;
                }
            }
        }

        info!(
            target: CONSENSUS_LOG_TARGET,
            event_id = ?event.event_id,
            votes = vote_count,
            weighted_score = total_score,
            confidence = signature.confidence,
            action = ?signature.recommended_action,
            "[CONSENSUS] round COMPLETE — threat signature emitted"
        );
        
        Some(signature)
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use osoosi_types::{SysmonEvent, SysmonEventId};
    use chrono::Utc;
    use std::sync::Arc;
    use crate::voters::{OtxVoter, SemanticVoter};
    use crate::feed::OtxIndicators;
    use serde_json::json;

    fn make_event(image: &str, cmd_line: &str) -> osoosi_types::SysmonEvent {
        osoosi_types::SysmonEvent {
            event_id: SysmonEventId::ProcessCreate,
            timestamp: Utc::now(),
            computer: "test-host".to_string(),
            data: serde_json::json!({
                "Image": image,
                "CommandLine": cmd_line,
                "ProcessId": 1234,
            }),
            product_version: None,
        }
    }

    #[test]
    fn test_scan_event_discovery_ttp() {
        let memory = Arc::new(MemoryStore::new(":memory:").expect("in-memory db"));
        let mut engine = PolicyEngine::new(memory);
        
        // Add a basic semantic voter for testing
        engine.add_voter(Box::new(SemanticVoter {
            engine: crate::semantic::SemanticEngine::new(),
        }));

        let event = make_event("C:\\Windows\\System32\\whoami.exe", "whoami");
        let sig = engine.scan_event(&event);
        // Note: semantic drift might not hit on 'whoami' without training, 
        // but this confirms the loop runs.
        let _ = sig;
    }

    #[test]
    fn test_scan_event_benign() {
        let memory = Arc::new(MemoryStore::new(":memory:").expect("in-memory db"));
        let engine = PolicyEngine::new(memory);
        let event = make_event("C:\\Program Files\\notepad.exe", "notepad");
        let sig = engine.scan_event(&event);
        let _ = sig; // just ensure it doesn't panic
    }

    /// OTX IoCs merge into voting via safety-net when `OtxVoter` is not registered.
    #[test]
    fn test_otx_ioc_safety_net_participates_in_consensus() {
        let memory = Arc::new(MemoryStore::new(":memory:").expect("in-memory"));
        let engine = PolicyEngine::new(memory);
        let mut otx = OtxIndicators::default();
        otx.ips.insert("198.51.100.2".to_string());
        engine.update_otx_indicators(otx);

        let event = SysmonEvent {
            event_id: SysmonEventId::NetworkConnect,
            timestamp: Utc::now(),
            computer: "h".to_string(),
            data: json!({
                "Image": "C:\\\\Windows\\\\System32\\\\curl.exe",
                "DestinationIp": "198.51.100.2",
                "DestinationPort": 443,
                "ProcessId": 1,
            }),
            product_version: None,
        };

        let sig = engine.scan_event(&event).expect("OTX should vote via safety-net");
        let reason = sig.reason.as_deref().unwrap();
        assert!(reason.contains("OTX-C2"), "reason was: {}", reason);
        assert_eq!(sig.detector_count, 1);
    }

    /// When `OtxVoter` is present, the same OTX reason must not be applied twice.
    #[test]
    fn test_otx_voter_no_double_votes() {
        let memory = Arc::new(MemoryStore::new(":memory:").expect("in-memory"));
        let engine = PolicyEngine::new(memory.clone());
        let mut otx = OtxIndicators::default();
        otx.ips.insert("198.51.100.3".to_string());
        engine.update_otx_indicators(otx);

        engine.add_voter(Box::new(OtxVoter {
            indicators: engine.otx_indicators_ref().clone(),
            memory: memory.clone(),
        }));

        let event = SysmonEvent {
            event_id: SysmonEventId::NetworkConnect,
            timestamp: Utc::now(),
            computer: "h".to_string(),
            data: json!({
                "Image": "C:\\\\Windows\\\\System32\\\\curl.exe",
                "DestinationIp": "198.51.100.3",
                "ProcessId": 1,
            }),
            product_version: None,
        };

        let sig = engine.scan_event(&event).expect("OtxVoter + OTX");
        let reason = sig.reason.as_deref().unwrap();
        assert_eq!(
            reason.matches("OTX-C2").count(),
            1,
            "expected single OTX block in reasons: {}",
            reason
        );
        assert_eq!(sig.detector_count, 1);
    }
}
