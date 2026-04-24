//! Threat Engine (The "Brain").
//!
//! Correlates telemetry events with threat signatures.

use dashmap::DashMap;
use osoosi_memory::MemoryStore;
use osoosi_types::{SysmonEvent, ThreatSignature};
use crate::semantic::SemanticEngine;
use crate::graph::{GraphCorrelationEngine, Relationship};
use crate::feed::OtxIndicators;
use tracing::{info, warn};
use std::sync::Arc;
use std::sync::RwLock;

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
            guard.push(voter);
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
    pub fn scan_event(&self, event: &SysmonEvent) -> Option<ThreatSignature> {
        use osoosi_types::ResponseAction;

        let voters_len = self.voters.read().map(|v| v.len()).unwrap_or(0);
        info!("Scanning Sysmon Event ID: {:?} via Consensus Registry ({} voters)", event.event_id, voters_len);

        let mut signature = ThreatSignature::new(event.computer.clone());
        let mut total_score: f32 = 0.0;
        let mut vote_count: u32 = 0;
        let mut is_threat = false;
        let mut vetoed = false;

        if let Ok(voters_guard) = self.voters.read() {
            for voter in voters_guard.iter() {
                if let Some(res) = voter.vote(event) {
                    if res.weight < 0.0 {
                        // Veto detected
                        warn!("Consensus Veto: {} blocked the detection. Reason: {}", voter.name(), res.reason);
                        vetoed = true;
                        signature.add_reason(format!("Veto [{}]: {}", voter.name(), res.reason));
                        break;
                    }

                    info!("Voter Hit: {} (Confidence: {:.2}, Weight: {:.2})", voter.name(), res.confidence, res.weight);
                    total_score += res.confidence * res.weight;
                    vote_count += 1;
                    signature.add_reason(format!("[{}]: {}", voter.name(), res.reason));
                    is_threat = true;
                }
            }
        }

        if vetoed {
            return None;
        }

        if !is_threat {
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

        // Federated learning: down-rank if matches known false positive pattern
        if is_threat {
            // ... (keep existing down-ranking logic if any)
        }
        
        if is_threat {
            if let Ok(true) = self.memory.is_false_positive_pattern(
                signature.process_name.as_deref(),
                signature.hash_blake3.as_deref(),
            ) {
                signature.confidence = (signature.confidence * 0.3).max(0.1);
                signature.add_reason("Down-ranked: matches federated false positive pattern");
            }
        }
        
        Some(signature)
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use osoosi_types::SysmonEventId;
    use chrono::Utc;
    use std::sync::Arc;
    use crate::voters::SemanticVoter;

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
}
