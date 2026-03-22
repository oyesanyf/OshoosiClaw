//! Threat Engine (The "Brain").
//!
//! Correlates telemetry events with threat signatures.

use dashmap::DashMap;
use osoosi_memory::MemoryStore;
use osoosi_types::{SysmonEvent, ThreatSignature};
use crate::semantic::SemanticEngine;
use crate::graph::{GraphCorrelationEngine, Relationship};
use crate::feed::OtxIndicators;
use crate::traffic_adapter;
use tracing::{info, warn};
use std::sync::Arc;
use std::sync::RwLock;

pub struct PolicyEngine {
    /// Local persistence store
    memory: Arc<MemoryStore>,
    /// Semantic Intent Filter
    semantic: SemanticEngine,
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
}

impl PolicyEngine {
    pub fn new(memory: Arc<MemoryStore>) -> Self {
        Self {
            memory,
            semantic: SemanticEngine::new(),
            graph: GraphCorrelationEngine::new(),
            signatures: Arc::new(DashMap::new()),
            otx_indicators: Arc::new(RwLock::new(OtxIndicators::default())),
            sigma: Arc::new(RwLock::new(crate::sigma::SigmaEngine::new())),
            global_intel_rules: Arc::new(DashMap::new()),
        }
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

        info!("Scanning Sysmon Event ID: {:?}", event.event_id);

        let mut signature = ThreatSignature::new(event.computer.clone());
        let mut is_threat = false;

        // 1. Correlate with image and command line (TTP Detection)
        if let Some(image) = event.data.get("Image").and_then(|i| i.as_str()) {
            let cmd_line = event.data.get("CommandLine").and_then(|c| c.as_str()).unwrap_or("");
            let basename = std::path::Path::new(image).file_name()?.to_str()?.to_lowercase();

            // Self-exclusion: prevent agent from flagging itself
            if basename == "osoosi-cli.exe" || basename == "osoosi-core.exe" || basename == "osoosi.exe" || basename == "osoosi-core" {
                return None;
            }

            // Algorithm 2: Semantic Intent Verification
            let semantic_drift = self.semantic.verify_intent(cmd_line);
            if semantic_drift > 0.8 {
                warn!("Semantic Drift Detected: {} (Confidence: {})", cmd_line, semantic_drift);
                signature.confidence = semantic_drift;
                signature.recommended_action = ResponseAction::Tarpit;
                signature.add_reason(format!("Semantic drift in command line (score {:.2}): intent deviates from expected process behavior", semantic_drift));
                is_threat = true;
            }

            // Algorithm 1: Spatio-Temporal Graph Correlation
            self.graph.track(&event.computer, image, "exec");
            let graph_anomaly = self.graph.score_anomaly(&event.computer, image, "exec");
            if graph_anomaly > 0.8 {
                warn!("Graph Anomaly (Lateral Movement/Drift): {} accessed {}", event.computer, image);
                signature.confidence = graph_anomaly;
                signature.recommended_action = ResponseAction::Alert;
                signature.add_reason(format!("Graph anomaly (score {:.2}): host {} executing {} is unusual for this environment", graph_anomaly, event.computer, image));
                is_threat = true;
            }

            // Discovery & TTPs
            if basename.contains("whoami") || basename.contains("net.exe") || cmd_line.contains("dir /s") {
                signature.confidence = 0.5;
                signature.process_name = Some(basename.clone());
                signature.recommended_action = ResponseAction::Deception;
                signature.add_reason("Discovery TTP: whoami/net/dir /s indicates reconnaissance");
                is_threat = true;
            }

            if basename.contains("vssadmin") && cmd_line.contains("delete shadows") {
                signature.confidence = 0.9;
                signature.recommended_action = ResponseAction::Tarpit;
                signature.add_reason("Shadow copy deletion: vssadmin delete shadows is a common ransomware TTP");
                if let Some(pred) = crate::predictive::predict_next_step(Some(&basename), Some(cmd_line), signature.cve_id.as_deref()) {
                    signature.set_predicted_next(pred);
                }
                is_threat = true;
            }

            // CVE Correlation — exact product-name matching to avoid false positives
            // (git.exe was matching KEV entries for "Git" product CVEs)
            const EXEMPT_PROCESSES: &[&str] = &[
                "git.exe", "git", "python.exe", "python", "python3",
                "node.exe", "node", "java.exe", "java", "javaw.exe",
                "curl.exe", "curl", "wget.exe", "wget",
                "powershell.exe", "pwsh.exe", "cmd.exe",
                "code.exe", "code", "cargo.exe", "cargo", "rustc.exe", "rustc",
            ];
            let is_exempt = EXEMPT_PROCESSES.iter().any(|&p| basename == p);

            if !is_exempt {
                for kev in self.memory.get_all_kevs().unwrap_or_default() {
                    let product_lower = kev.product.to_lowercase();
                    let base_no_ext = basename.trim_end_matches(".exe");
                    let is_exact = basename == product_lower || base_no_ext == product_lower;
                    if is_exact {
                        warn!("CVE Correlation: Process {} matches product in CISA KEV ({})", basename, kev.cve_id);
                        signature.confidence = 0.85;
                        signature.cve_id = Some(kev.cve_id.clone());
                        signature.recommended_action = ResponseAction::GhostTarpit;
                        signature.add_reason(format!("CISA KEV: process {} matches known exploited product ({})", basename, kev.cve_id));
                        is_threat = true;
                        break;
                    }
                }
            }

            // OTX IoC correlation (IPs, domains, hashes, URLs, command line)
            if let Some(reason) = self.match_otx_ioc(event) {
                warn!("OTX Correlation: {}", reason);
                signature.confidence = signature.confidence.max(0.92);
                if signature.process_name.is_none() {
                    signature.process_name = Some(basename.clone());
                }
                signature.recommended_action = ResponseAction::GhostTarpit;
                signature.add_reason(format!("OTX IoC match: {}", reason));
                is_threat = true;
            }

            // Algorithm 3: Sigma Rule Matching
            if let Ok(guard) = self.sigma.read() {
                let sigma_matches = guard.check(event);
                for rule in sigma_matches {
                    warn!("Sigma Match: {}", rule.title);
                    signature.confidence = signature.confidence.max(
                        if rule.level == "critical" { 0.95 }
                        else if rule.level == "high" { 0.85 }
                        else { 0.6 }
                    );
                    signature.recommended_action = match rule.level.as_str() {
                        "critical" => ResponseAction::GhostTarpit,
                        "high" => ResponseAction::Tarpit,
                        _ => ResponseAction::Alert,
                    };
                    signature.add_reason(format!("Sigma Rule [{}]: {}", rule.title, rule.description.as_deref().unwrap_or("No description")));
                    is_threat = true;
                }
            }

            // 4. Match against Mesh-Learned Global Intelligence
            for entry in self.global_intel_rules.iter() {
                let (cve_id, rule) = entry.pair();
                if cmd_line.contains(cve_id) || basename.contains(&cve_id.to_lowercase()) {
                    warn!("Global Intelligence Match: {} violates mesh-learned rule for {}", basename, cve_id);
                    signature.confidence = signature.confidence.max(0.98);
                    signature.recommended_action = ResponseAction::Isolate;
                    signature.add_reason(format!("Gossip Sleuth: Event matches learned defense for {} (Rule: {})", cve_id, rule));
                    is_threat = true;
                }
            }
        }

        // TrafficLLM-inspired Rust adapter
        if let Some(t) = traffic_adapter::analyze(event) {
            warn!("Traffic adapter signal [{}]: {}", t.tag, t.reason);
            if !is_threat || t.confidence > signature.confidence {
                signature.confidence = t.confidence;
                signature.cve_id = Some(t.tag.clone());
                signature.recommended_action = t.action;
                signature.add_reason(format!("Traffic analysis [{}]: {}", t.tag, t.reason));
                is_threat = true;
            }
        }

        // Federated learning: down-rank if matches known false positive pattern
        if is_threat {
            if let Ok(true) = self.memory.is_false_positive_pattern(
                signature.process_name.as_deref(),
                signature.hash_blake3.as_deref(),
            ) {
                signature.confidence = (signature.confidence * 0.3).max(0.1);
                signature.add_reason("Down-ranked: matches federated false positive pattern");
            }
            Some(signature)
        } else {
            None
        }
    }

    fn match_otx_ioc(&self, event: &SysmonEvent) -> Option<String> {
        let guard = self.otx_indicators.read().ok()?;
        if guard.total_count() == 0 {
            return None;
        }

        let destination_ip = event.data.get("DestinationIp").and_then(|v| v.as_str()).unwrap_or("").to_ascii_lowercase();
        let source_ip = event.data.get("SourceIp").and_then(|v| v.as_str()).unwrap_or("").to_ascii_lowercase();
        let query_name = event.data.get("QueryName").and_then(|v| v.as_str()).unwrap_or("").to_ascii_lowercase();
        let hashes_field = event.data.get("Hashes").and_then(|v| v.as_str()).unwrap_or("").to_ascii_lowercase();
        let cmd_line = event.data.get("CommandLine").and_then(|v| v.as_str()).unwrap_or("").to_ascii_lowercase();
        let image = event.data.get("Image").and_then(|v| v.as_str()).unwrap_or("").to_ascii_lowercase();

        if !destination_ip.is_empty() && guard.ips.contains(&destination_ip) {
            return Some(format!("Destination IP {} matched OTX IoC", destination_ip));
        }
        if !source_ip.is_empty() && guard.ips.contains(&source_ip) {
            return Some(format!("Source IP {} matched OTX IoC", source_ip));
        }
        if !query_name.is_empty() {
            if guard.domains.contains(&query_name) {
                return Some(format!("Domain {} matched OTX IoC", query_name));
            }
            for domain in &guard.domains {
                if query_name.ends_with(domain) {
                    return Some(format!("Domain {} matched OTX suffix IoC {}", query_name, domain));
                }
            }
        }
        if !hashes_field.is_empty() {
            for h in &guard.hashes {
                if hashes_field.contains(h) {
                    return Some(format!("Hashes field matched OTX hash {}", h));
                }
            }
        }
        if !cmd_line.is_empty() {
            for url in &guard.urls {
                if cmd_line.contains(url) {
                    return Some(format!("Command line matched OTX URL {}", url));
                }
            }
        }
        if !image.is_empty() {
            for url in &guard.urls {
                if image.contains(url) {
                    return Some(format!("Image path matched OTX URL {}", url));
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use osoosi_types::SysmonEventId;
    use chrono::Utc;
    use std::sync::Arc;

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
        let engine = PolicyEngine::new(memory);
        let event = make_event("C:\\Windows\\System32\\whoami.exe", "whoami");
        let sig = engine.scan_event(&event);
        assert!(sig.is_some());
        let s = sig.unwrap();
        assert!(s.confidence > 0.0);
        assert!(s.reason.as_ref().map_or(false, |r| r.contains("Discovery")));
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
