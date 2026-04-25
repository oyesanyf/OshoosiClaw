use crate::engine::{ThreatVoter, VoteResult};
use osoosi_types::SysmonEvent;
use std::sync::Arc;


/// Semantic Intent Voter (Algorithm 2)
pub struct SemanticVoter {
    pub engine: crate::semantic::SemanticEngine,
}

impl ThreatVoter for SemanticVoter {
    fn name(&self) -> String { "SemanticIntent".to_string() }
    fn vote(&self, event: &SysmonEvent) -> Option<VoteResult> {
        if let Some(cmd_line) = event.data.get("CommandLine").and_then(|c| c.as_str()) {
            let drift = self.engine.verify_intent(cmd_line);
            if drift > 0.8 {
                return Some(VoteResult {
                    confidence: drift,
                    reason: format!("Semantic drift (score {:.2}): command line intent deviates from expected process behavior", drift),
                    weight: 0.7,
                });
            }
        }
        None
    }
}

/// OTX Indicator Voter (C2/Malware hashes)
pub struct OtxVoter {
    pub indicators: Arc<std::sync::RwLock<crate::feed::OtxIndicators>>,
    pub memory: Arc<osoosi_memory::MemoryStore>,
}

impl ThreatVoter for OtxVoter {
    fn name(&self) -> String { "OTX-C2".to_string() }
    fn vote(&self, event: &SysmonEvent) -> Option<VoteResult> {
        let guard = self.indicators.read().ok()?;
        let hit = crate::otx_connection::otx_match_sysmon_event(&guard, &self.memory, event);

        hit.map(|reason| VoteResult {
            confidence: crate::otx_connection::OTX_CONSENSUS_CONFIDENCE,
            reason,
            weight: crate::otx_connection::otx_consensus_weight(event),
        })
    }
}

/// Sigma Rule Voter
pub struct SigmaVoter {
    pub engine: Arc<std::sync::RwLock<crate::sigma::SigmaEngine>>,
}

impl ThreatVoter for SigmaVoter {
    fn name(&self) -> String { "Sigma".to_string() }
    fn vote(&self, event: &SysmonEvent) -> Option<VoteResult> {
        if let Ok(guard) = self.engine.read() {
            let matches = guard.check(event);
            if !matches.is_empty() {
                let rule = &matches[0];
                return Some(VoteResult {
                    confidence: if rule.level == "critical" { 0.95 } else { 0.85 },
                    reason: format!("Sigma Rule [{}]: {}", rule.title, rule.description.as_deref().unwrap_or("No description")),
                    weight: 0.8,
                });
            }
        }
        None
    }
}

/// Gemma 4 LLM Voter (The "Autonomous Cortex")
pub struct GemmaVoter {
    pub analyzer: Arc<osoosi_behavioral::Gemma4Analyzer>,
}

impl ThreatVoter for GemmaVoter {
    fn name(&self) -> String { "Gemma4-LLM".to_string() }
    fn vote(&self, event: &SysmonEvent) -> Option<VoteResult> {
        let cmd_line = event.data.get("CommandLine").and_then(|v| v.as_str()).unwrap_or("unknown");
        let image = event.data.get("Image").and_then(|v| v.as_str()).unwrap_or("unknown");
        let version = event.product_version.as_deref().unwrap_or("unknown");
        
        let summary = format!("Process Create: image={} version={} cmdline={}", image, version, cmd_line);
        
        match self.analyzer.reason_about_attack(&summary) {
            Ok(reasoning) => {
                // Heuristic: if reasoning contains "malicious", "attack", or "suspicious"
                let r_lower = reasoning.to_lowercase();
                if r_lower.contains("malicious") || r_lower.contains("attack") || r_lower.contains("suspicious") {
                    return Some(VoteResult {
                        confidence: 0.9,
                        reason: format!("Gemma 4 Reasoning: {}", reasoning),
                        weight: 0.9, // LLM reasoning has high weight for complex TTPs
                    });
                }
            }
            Err(_) => {}
        }
        None
    }
}

/// NSRL "Known Good" Veto Voter
pub struct NsrlVoter {
    pub cache: Arc<dashmap::DashMap<String, bool>>,
}

impl ThreatVoter for NsrlVoter {
    fn name(&self) -> String { "NSRL-Veto".to_string() }
    fn vote(&self, event: &SysmonEvent) -> Option<VoteResult> {
        if let Some(image) = event.data.get("Image").and_then(|v| v.as_str()) {
            if self.cache.contains_key(image) {
                return Some(VoteResult {
                    confidence: 0.0, // This is a veto
                    reason: "NSRL: Identified as a 'Known Good' system file. Vetoing block.".to_string(),
                    weight: -2.0, // Massive negative weight acts as a veto
                });
            }
        }
        None
    }
}

/// Yara-X Memory Voter (C2 Beacon Scanning)
pub struct YaraXMemoryVoter {
    pub rules: yara_x::Rules,
}

impl ThreatVoter for YaraXMemoryVoter {
    fn name(&self) -> String { "YaraX-Memory".to_string() }
    fn vote(&self, event: &SysmonEvent) -> Option<VoteResult> {
        #[cfg(target_os = "windows")]
        {
            use process_memory::{CopyAddress, TryIntoProcessHandle};
            if let Some(pid) = event.process_id() {
                if let Ok(handle) = (pid as process_memory::Pid).try_into_process_handle() {
                    // In a real implementation, we'd iterate through memory regions.
                    // Here we'll do a focused scan of the first 1MB of the image base as a placeholder.
                    let mut buffer = vec![0u8; 4096]; // Use a smaller 4KB buffer for testing
                    if let Ok(_bytes) = handle.copy_address(0x400000, &mut buffer) {
                        let mut scanner = yara_x::Scanner::new(&self.rules);
                        let results = scanner.scan(&buffer).ok()?;
                        if results.matching_rules().count() > 0 {
                            return Some(VoteResult {
                                confidence: 0.98,
                                reason: "Yara-X: Detected C2 beacon pattern in process memory".to_string(),
                                weight: 1.0,
                            });
                        }
                    }
                }
            }
        }
        None
    }
}

/// CISA KEV (Known Exploited Vulnerabilities) Voter
pub struct KevVoter {
    pub memory: std::sync::Arc<osoosi_memory::MemoryStore>,
}

impl ThreatVoter for KevVoter {
    fn name(&self) -> String { "CISA-KEV".to_string() }
    fn vote(&self, event: &SysmonEvent) -> Option<VoteResult> {
        let image = event.data.get("Image").and_then(|v| v.as_str())
            .and_then(|p| std::path::Path::new(p).file_name())
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_lowercase();
            
        let is_known_good = if let Some(path) = event.data.get("Image").and_then(|v| v.as_str()) {
            self.memory.get_file_integrity(path).map(|opt| opt.map(|(_, nsrl, _)| nsrl).unwrap_or(false)).unwrap_or(false)
        } else {
            false
        };

        if let Ok(kevs) = self.memory.get_all_kevs() {
            for kev in kevs {
                let product = kev.product.to_lowercase();
                if image.contains(&product) || product.contains(&image) {
                    // VERSION-AWARE LOGIC: 
                    // If we have a resolved product version, and it looks like a modern/patched version, 
                    // we down-rank the confidence significantly.
                    let mut confidence = if is_known_good { 0.45 } else { 0.85 };
                    
                    if let Some(ref version) = event.product_version {
                        // Heuristic: If version starts with '2.5', '3.', etc., it's likely newer than many 2025 CVEs' initial vulnerable versions.
                        // For a real production system, we would have a 'min_safe_version' in the KEV table.
                        if version.starts_with("2.5") || version.starts_with("3.") || version.starts_with("v2.5") {
                            confidence *= 0.5; // Downgrade to Alert-only range
                            return Some(VoteResult {
                                confidence,
                                reason: format!("CISA KEV [POSSIBLE FP]: {} matches product {} ({}), but running version {} appears to be patched.", image, kev.product, kev.cve_id, version),
                                weight: 0.6,
                            });
                        }
                    }

                    return Some(VoteResult {
                        confidence,
                        reason: format!("CISA KEV: process {} matches known exploited product {} ({})", image, kev.product, kev.cve_id),
                        weight: 1.0,
                    });
                }
            }
        }
        None
    }
}

