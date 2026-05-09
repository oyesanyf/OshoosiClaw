use osoosi_model::{MalwareScanResult, MalwareScanner};
use async_trait::async_trait;
use osoosi_policy::engine::{ThreatVoter, VoteResult};
use osoosi_types::{HostSecurityEvent, Priority, ResourceCategory};
use std::path::Path;
use std::sync::Arc;

fn trusted_operational_path(path: &str) -> bool {
    let p = path.replace('/', "\\").to_ascii_lowercase();
    p.contains("\\windows\\system32\\")
        || p.contains("\\windows\\syswow64\\")
        || p.contains("\\program files\\")
        || p.contains("\\program files (x86)\\")
        || p.contains("\\programdata\\chocolatey\\")
        || p.contains("\\programdata\\scoop\\")
        || p.contains("\\tools\\git\\")
        || p.contains("\\oshoosiclaw\\tools\\")
        || p.contains("\\oshoosiclaw\\target\\")
}

fn event_text_field<'a>(event: &'a HostSecurityEvent, key: &str) -> Option<&'a str> {
    event
        .data
        .get(key)
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|v| !v.is_empty() && !v.eq_ignore_ascii_case("unknown"))
}

fn trusted_identity_signal(event: &HostSecurityEvent, path: &str) -> bool {
    if !trusted_operational_path(path) {
        return false;
    }

    let valid_signature = event_text_field(event, "SignatureStatus")
        .or_else(|| event_text_field(event, "Signature Status"))
        .is_some_and(|status| {
            let status = status.to_ascii_lowercase();
            status == "valid" || status.contains("trusted")
        });
    let publisher = event_text_field(event, "Signature")
        .or_else(|| event_text_field(event, "Company"))
        .unwrap_or("")
        .to_ascii_lowercase();
    let trusted_publisher = [
        "microsoft",
        "git",
        "python",
        "node.js",
        "llvm",
        "rust",
        "openai",
        "cursor",
        "anysphere",
        "patientpoint",
    ]
    .iter()
    .any(|needle| publisher.contains(needle));

    if valid_signature && trusted_publisher {
        return true;
    }

    event
        .data
        .get("ProductVersion")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .is_some_and(|v| !v.is_empty() && !v.eq_ignore_ascii_case("unknown"))
}

fn scanner_skip_path(path: &str) -> bool {
    let p = path.replace('/', "\\").to_ascii_lowercase();
    p.contains("\\.codex\\")
        || p.contains("\\.gemini\\")
        || p.contains("\\antigravity\\brain\\")
        || p.contains("\\.system_generated\\logs\\")
        || p.contains("\\oshoosiclaw\\tools\\hayabusa\\rules\\")
        || p.contains("\\oshoosiclaw\\dashboard\\")
        || p.contains("\\oshoosiclaw\\target\\")
        || p.contains("\\oshoosiclaw\\cache\\")
        || p.contains("\\oshoosiclaw\\models\\")
        || p.contains("\\oshoosiclaw\\logs\\")
        || p.contains("\\oshoosiclaw\\traps\\")
        || p.ends_with(".yml")
        || p.ends_with(".yaml")
        || p.ends_with(".json")
        || p.ends_with(".jsonl")
        || p.ends_with(".toml")
        || p.ends_with(".txt")
        || p.ends_with(".log")
        || p.ends_with(".sqlite")
        || p.ends_with(".db")
}

/// Yara-X Signature Voter (Zero-Process Replacement for ClamAV)
///
/// Yara-X is a memory-safe, pure-Rust implementation of the YARA engine.
/// It provides high-performance pattern matching without external binaries.
pub struct YaraXVoter {
    pub rules: Arc<yara_x::Rules>,
    pub adaptive: Arc<crate::adaptive::TelemetryController>,
}

#[async_trait]
impl ThreatVoter for YaraXVoter {
    fn name(&self) -> String {
        "YaraX-Signatures".to_string()
    }

    async fn vote(&self, event: &HostSecurityEvent) -> Option<VoteResult> {
        if let Some(image_path) = event.data.get("Image").and_then(|v| v.as_str()) {
            if scanner_skip_path(image_path) || trusted_identity_signal(event, image_path) {
                return None;
            }
            let path_buf = std::path::PathBuf::from(image_path);
            if !path_buf.exists() {
                return None;
            }

            // Perform scan via the native yara-x engine with adaptive concurrency
            let rules = self.rules.clone();
            let adaptive = self.adaptive.clone();
            
            let scan_result = adaptive.run_adaptive(ResourceCategory::AI, Priority::High, async move {
                if let Ok(bytes) = std::fs::read(&path_buf) {
                    let mut scanner = yara_x::Scanner::new(&rules);
                    if let Ok(results) = scanner.scan(&bytes) {
                        if let Some(primary) = results.matching_rules().next() {
                            return Some(VoteResult {
                                confidence: 1.0,
                                reason: format!("YaraX: THREAT detected - {}", primary.identifier()),
                                weight: 1.0,
                            });
                        }
                    }
                }
                None
            }).await.ok().flatten();

            return scan_result;
        }
        None
    }
}

/// Minimum `combined_score` from [`MalwareScanner::scan_file`] to cast a **malicious** vote.
/// (Below this, the voter abstains so weak signals do not drown the consensus.)  
/// `is_malware` from the scanner (same threshold as internal `0.75` gate) still yields a vote regardless.
fn malconv_vote_min_combined() -> f64 {
    std::env::var("OSOOSI_MALCONV_VOTE_MIN_SCORE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0.55_f64)
}

/// MalConv / EMBER ONNX / YARA **MalwareScanner** voter — so byte-level and PE ML participate in
/// the same `[CONSENSUS]` registry as OTX, Sigma, KEV, etc.
pub struct MalConvVoter {
    pub scanner: Arc<MalwareScanner>,
    pub adaptive: Arc<crate::adaptive::TelemetryController>,
}

#[async_trait]
impl ThreatVoter for MalConvVoter {
    fn name(&self) -> String {
        "MalConv-ML".to_string()
    }

    async fn vote(&self, event: &HostSecurityEvent) -> Option<VoteResult> {
        if std::env::var("OSOOSI_NO_AI")
            .map(|v| v == "1")
            .unwrap_or(false)
        {
            return None;
        }
        if !self.scanner.has_ml_model() {
            return None;
        }

        const MAX_BYTES: u64 = 48 * 1024 * 1024;
        let adaptive = self.adaptive.clone();
        let scanner = self.scanner.clone();
        
        // Extract paths before the async block to avoid lifetime issues
        let mut paths_to_scan = Vec::new();
        for key in ["Image", "TargetImage", "TargetFilename"] {
            if let Some(p) = event.data.get(key).and_then(|v| v.as_str()) {
                if !scanner_skip_path(p) {
                    paths_to_scan.push(p.to_string());
                }
            }
        }

        if paths_to_scan.is_empty() {
            return None;
        }

        let best_result = adaptive.run_adaptive(ResourceCategory::AI, Priority::High, async move {
            let mut best: Option<MalwareScanResult> = None;
            let mut best_path: Option<String> = None;

            for p in paths_to_scan {
                let path = Path::new(&p);
                if !path.is_file() {
                    continue;
                }
                if let Ok(m) = path.metadata() {
                    if m.len() > MAX_BYTES {
                        continue;
                    }
                }
                if let Some(res) = scanner.scan_file(path).await {
                    let replace = best
                        .as_ref()
                        .map(|b| res.combined_score > b.combined_score)
                        .unwrap_or(true);
                    if replace {
                        best_path = Some(p.clone());
                        best = Some(res);
                    }
                }
            }
            best.map(|b| (b, best_path))
        }).await.ok().flatten();

        let (res, best_path) = best_result?;
        let path_note = best_path.as_deref().unwrap_or("?");
        
        // Removed clam_detected check as it is decommissioned in the Zero-Process stack.
        let weak_signature_only = res.ml_score <= 0.0 && res.signature_score >= 1.0;
        
        if trusted_identity_signal(event, path_note) && weak_signature_only {
            return None;
        }
        let min_c = malconv_vote_min_combined();
        if !res.is_malware && res.combined_score < min_c {
            return None;
        }

        let conf = (res.combined_score.min(1.0)) as f32;
        Some(VoteResult {
            confidence: conf,
            reason: format!(
                "MalwareScanner (MalConv/ONNX+YARA): combined={:.3} ml={:.3} sig={:.3} magika={} file={}",
                res.combined_score,
                res.ml_score,
                res.signature_score,
                res.magika_label,
                path_note
            ),
            weight: 0.88,
        })
    }
}

/// Mandiant CAPA Voter
///
/// Executes CAPA (Capability Analysis) on executable binaries to identify
/// behavioral intent (persistence, C2, anti-analysis).
pub struct CapaVoter {
    pub analyzer: Arc<crate::static_analyzer::StaticAnalyzer>,
    pub adaptive: Arc<crate::adaptive::TelemetryController>,
}

#[async_trait]
impl ThreatVoter for CapaVoter {
    fn name(&self) -> String {
        "Capa-Behavior".to_string()
    }

    async fn vote(&self, event: &HostSecurityEvent) -> Option<VoteResult> {
        let is_create = matches!(
            event.event_id,
            1 | 11 // 1: ProcessCreate, 11: FileCreate
        );
        if !is_create {
            return None;
        }

        if let Some(image_path) = event.data.get("Image").and_then(|v| v.as_str()) {
            if scanner_skip_path(image_path) || trusted_identity_signal(event, image_path) {
                return None;
            }
            let path = std::path::PathBuf::from(image_path);
            let analyzer = self.analyzer.clone();
            let adaptive = self.adaptive.clone();

            let res = adaptive.run_adaptive(ResourceCategory::AI, Priority::High, async move {
                if !path.exists() {
                    return None;
                }
                analyzer.analyze_file(&path).await.ok().flatten()
            }).await.ok().flatten()?;

            // If CAPA found specific persistence/c2 capabilities, we yield a vote
            if res.confidence > 0.4 {
                return Some(VoteResult {
                    confidence: res.confidence,
                    reason: res.reason.unwrap_or_else(|| "CAPA: Detected suspicious capabilities".to_string()),
                    weight: 0.85,
                });
            }
        }
        None
    }
}

/// Composition (Nabla) Voter
///
/// Executes high-speed static heuristic analysis to identify malicious 
/// binary structures, suspicious imports, and "shadow" dependencies.
pub struct CompositionVoter {
    pub analyzer: Arc<crate::static_analyzer::StaticAnalyzer>,
    pub adaptive: Arc<crate::adaptive::TelemetryController>,
}

#[async_trait]
impl ThreatVoter for CompositionVoter {
    fn name(&self) -> String {
        "Composition-Nabla".to_string()
    }

    async fn vote(&self, event: &HostSecurityEvent) -> Option<VoteResult> {
        let is_create = matches!(
            event.event_id,
            1 | 11 // 1: ProcessCreate, 11: FileCreate
        );
        if !is_create {
            return None;
        }

        if let Some(image_path) = event.data.get("Image").and_then(|v| v.as_str()) {
            if scanner_skip_path(image_path) || trusted_identity_signal(event, image_path) {
                return None;
            }
            let path = std::path::PathBuf::from(image_path);
            let analyzer = self.analyzer.clone();
            let adaptive = self.adaptive.clone();

            let res = adaptive.run_adaptive(ResourceCategory::AI, Priority::High, async move {
                if !path.exists() {
                    return None;
                }
                analyzer.analyze_file(&path).await.ok().flatten()
            }).await.ok().flatten()?;

            // If it looks like a composition threat (ID starts with COMP-)
            if res.id.starts_with("COMP-") && res.confidence >= 0.5 {
                return Some(VoteResult {
                    confidence: res.confidence as f32,
                    reason: res.reason.unwrap_or_else(|| "Nabla: Suspicious composition detected".to_string()),
                    weight: 0.9,
                });
            }
        }
        None
    }
}

/// Behavioral YARA-X Voter
/// 
/// Replaces Hayabusa/Sigma with native YARA-X rules matching on event JSON.
#[derive(Clone)]
pub struct BehavioralYaraVoter {
    pub rules: Arc<yara_x::Rules>,
    pub adaptive: Arc<crate::adaptive::TelemetryController>,
}

#[async_trait]
impl ThreatVoter for BehavioralYaraVoter {
    fn name(&self) -> String {
        "BehavioralYara".to_string()
    }

    async fn vote(&self, event: &HostSecurityEvent) -> Option<VoteResult> {
        let json_bytes = serde_json::to_vec(event).ok()?;
        let rules = self.rules.clone();
        let adaptive = self.adaptive.clone();

        adaptive.run_adaptive(ResourceCategory::AI, Priority::High, async move {
            let mut scanner = yara_x::Scanner::new(&rules);
            if let Ok(results) = scanner.scan(&json_bytes) {
                if let Some(primary) = results.matching_rules().next() {
                    return Some(VoteResult {
                        confidence: 0.9,
                        reason: format!("BehavioralYara: DETECTED - {}", primary.identifier()),
                        weight: 0.8,
                    });
                }
            }
            None
        }).await.ok().flatten()
    }
}

/// Native .NET Forensic Voter (using dotscope)
pub struct DotscopeVoter {
    pub analyzer: Arc<crate::dotscope::DotscopeAnalyzer>,
    pub adaptive: Arc<crate::adaptive::TelemetryController>,
}

#[async_trait]
impl ThreatVoter for DotscopeVoter {
    fn name(&self) -> String {
        "Dotscope-Forensics".to_string()
    }

    async fn vote(&self, event: &HostSecurityEvent) -> Option<VoteResult> {
        if let Some(image_path) = event.data.get("Image").and_then(|v| v.as_str()) {
            if !image_path.to_lowercase().ends_with(".exe") && !image_path.to_lowercase().ends_with(".dll") {
                return None;
            }
            let path = std::path::PathBuf::from(image_path);
            let analyzer = self.analyzer.clone();
            let adaptive = self.adaptive.clone();

            adaptive.run_adaptive(ResourceCategory::AI, Priority::High, async move {
                if let Ok(results) = analyzer.analyze_file(&path).await {
                    if results.is_suspicious {
                        return Some(VoteResult {
                            confidence: 0.88,
                            reason: format!("Dotscope: Suspicious .NET CIL detected - {}", results.reason),
                            weight: 0.9,
                        });
                    }
                }
                None
            }).await.ok().flatten()
        } else {
            None
        }
    }
}

/// Native Memory Inspection Voter (using pelite)
///
/// Replaces Hollows-Hunter with in-memory PE parsing.
pub struct MemoryInspectionVoter {
    pub memory: Arc<osoosi_memory::MemoryStore>,
    pub adaptive: Arc<crate::adaptive::TelemetryController>,
}

#[async_trait]
impl ThreatVoter for MemoryInspectionVoter {
    fn name(&self) -> String {
        "MemoryInspection-Native".to_string()
    }

    async fn vote(&self, event: &HostSecurityEvent) -> Option<VoteResult> {
#[cfg(target_os = "windows")]
        {
            if let Some(pid) = event.data.get("ProcessId").and_then(|v| v.as_u64()) {
                let adaptive = self.adaptive.clone();
                adaptive.run_adaptive(ResourceCategory::IO, Priority::High, async move {
                    // Use pelite to parse the process memory and find hollowing
                    if let Ok(findings) = crate::pe_inspector::inspect_process(pid as u32) {
                        if findings.hollowing_detected {
                            return Some(VoteResult {
                                confidence: 1.0,
                                reason: format!("MemoryInspection: Process hollowing detected in PID {}", pid),
                                weight: 1.0,
                            });
                        }
                    }
                    None
                }).await.ok().flatten()
            } else {
                None
            }
        }
#[cfg(not(target_os = "windows"))]
        {
            None
        }
    }
}

/// AI Behavioral Classifier Voter
///
/// Uses the BehavioralClassifier (SecureBERT / SmolLM / LLM) to analyze
/// normalized behavioral sentences from logs.
pub struct BehavioralClassifierVoter {
    pub classifier: Arc<osoosi_behavioral::BehavioralClassifier>,
    pub adaptive: Arc<crate::adaptive::TelemetryController>,
}

#[async_trait]
impl ThreatVoter for BehavioralClassifierVoter {
    fn name(&self) -> String {
        "BehavioralAI-Cortex".to_string()
    }

    async fn vote(&self, event: &HostSecurityEvent) -> Option<VoteResult> {
        let log_event: osoosi_behavioral::LogEvent = event.into();
        let sentence = osoosi_behavioral::event_to_behavioral_sentence(&log_event);
        if sentence.is_empty() {
            return None;
        }

        let classifier = self.classifier.clone();
        let adaptive = self.adaptive.clone();

        adaptive.run_adaptive(ResourceCategory::AI, Priority::High, async move {
            let (is_suspicious, score, reason) = classifier.classify_sentence(&sentence).await;
            if is_suspicious {
                return Some(VoteResult {
                    confidence: score,
                    reason: format!("BehavioralAI: {} - {}", reason, sentence),
                    weight: 0.95,
                });
            }
            None
        }).await.ok().flatten()
    }
}
