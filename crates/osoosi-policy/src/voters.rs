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
        if guard.total_count() == 0 {
            return None;
        }

        let destination_ip = event.data.get("DestinationIp").and_then(|v| v.as_str()).unwrap_or("").to_ascii_lowercase();
        let source_ip = event.data.get("SourceIp").and_then(|v| v.as_str()).unwrap_or("").to_ascii_lowercase();
        let query_name = event.data.get("QueryName").and_then(|v| v.as_str()).unwrap_or("").to_ascii_lowercase();
        let hashes_field = event.data.get("Hashes").and_then(|v| v.as_str()).unwrap_or("").to_ascii_lowercase();
        let cmd_line = event.data.get("CommandLine").and_then(|v| v.as_str()).unwrap_or("").to_ascii_lowercase();
        let image = event.data.get("Image").and_then(|v| v.as_str()).unwrap_or("").to_ascii_lowercase();

        let mut hit = None;

        if !destination_ip.is_empty() {
            if guard.ips.contains(&destination_ip) {
                hit = Some(format!("Destination IP {} matched OTX IoC (cache)", destination_ip));
            } else if let Ok(true) = self.memory.is_indicator_malicious("ipv4", &destination_ip) {
                hit = Some(format!("Destination IP {} matched OTX IoC (SQLite)", destination_ip));
            }
        } else if !source_ip.is_empty() {
            if guard.ips.contains(&source_ip) {
                hit = Some(format!("Source IP {} matched OTX IoC (cache)", source_ip));
            } else if let Ok(true) = self.memory.is_indicator_malicious("ipv4", &source_ip) {
                hit = Some(format!("Source IP {} matched OTX IoC (SQLite)", source_ip));
            }
        } else if !query_name.is_empty() {
            if guard.domains.contains(&query_name) {
                hit = Some(format!("Domain {} matched OTX IoC (cache)", query_name));
            } else if let Ok(true) = self.memory.is_indicator_malicious("domain", &query_name) {
                hit = Some(format!("Domain {} matched OTX IoC (SQLite)", query_name));
            } else {
                for domain in &guard.domains {
                    if query_name.ends_with(domain) {
                        hit = Some(format!("Domain {} matched OTX suffix IoC {}", query_name, domain));
                        break;
                    }
                }
            }
        } else if !hashes_field.is_empty() {
            for h in &guard.hashes {
                if hashes_field.contains(h) {
                    hit = Some(format!("Hashes field matched OTX hash {} (cache)", h));
                    break;
                }
            }
            if hit.is_none() {
                for hash_part in hashes_field.split(',') {
                    let val = hash_part.split('=').nth(1).unwrap_or(hash_part).trim();
                    if let Ok(true) = self.memory.is_indicator_malicious("hash", val) {
                        hit = Some(format!("Hashes field matched OTX hash {} (SQLite)", val));
                        break;
                    }
                }
            }
        } else if !cmd_line.is_empty() {
            for url in &guard.urls {
                if cmd_line.contains(url) {
                    hit = Some(format!("Command line matched OTX URL {}", url));
                    break;
                }
            }
        } else if !image.is_empty() {
            for url in &guard.urls {
                if image.contains(url) {
                    hit = Some(format!("Image path matched OTX URL {}", url));
                    break;
                }
            }
        }

        hit.map(|reason| VoteResult {
            confidence: 0.95,
            reason,
            weight: 1.0, // OTX is high weight
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
        
        let summary = format!("Process Create: image={} cmdline={}", image, cmd_line);
        
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

