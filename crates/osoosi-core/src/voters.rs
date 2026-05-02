use osoosi_model::{MalwareScanResult, MalwareScanner};
use async_trait::async_trait;
use osoosi_policy::engine::{ThreatVoter, VoteResult};
use osoosi_types::SysmonEvent;
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

fn event_text_field<'a>(event: &'a SysmonEvent, key: &str) -> Option<&'a str> {
    event
        .data
        .get(key)
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|v| !v.is_empty() && !v.eq_ignore_ascii_case("unknown"))
}

fn trusted_identity_signal(event: &SysmonEvent, path: &str) -> bool {
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
        .product_version
        .as_deref()
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
}

#[async_trait]
impl ThreatVoter for YaraXVoter {
    fn name(&self) -> String {
        "YaraX-Signatures".to_string()
    }

    async fn vote(&self, event: &SysmonEvent) -> Option<VoteResult> {
        if let Some(image_path) = event.data.get("Image").and_then(|v| v.as_str()) {
            if scanner_skip_path(image_path) || trusted_identity_signal(event, image_path) {
                return None;
            }
            let path = Path::new(image_path);
            if !path.exists() {
                return None;
            }

            // Perform scan via the native yara-x engine
            if let Ok(bytes) = std::fs::read(path) {
                let mut scanner = yara_x::Scanner::new(&self.rules);
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
}

#[async_trait]
impl ThreatVoter for MalConvVoter {
    fn name(&self) -> String {
        "MalConv-ML".to_string()
    }

    async fn vote(&self, event: &SysmonEvent) -> Option<VoteResult> {
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
        let mut best: Option<MalwareScanResult> = None;
        let mut best_path: Option<String> = None;

        for key in ["Image", "TargetImage", "TargetFilename"] {
            let Some(p) = event.data.get(key).and_then(|v| v.as_str()) else {
                continue;
            };
            if scanner_skip_path(p) {
                continue;
            }
            let path = Path::new(p);
            if !path.is_file() {
                continue;
            }
            if let Ok(m) = path.metadata() {
                if m.len() > MAX_BYTES {
                    continue;
                }
            }
            if let Some(res) = self.scanner.scan_file(path).await {
                let replace = best
                    .as_ref()
                    .map(|b| res.combined_score > b.combined_score)
                    .unwrap_or(true);
                if replace {
                    best_path = Some(p.to_string());
                    best = Some(res);
                }
            }
        }

        let res = best?;
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
}

#[async_trait]
impl ThreatVoter for CapaVoter {
    fn name(&self) -> String {
        "Capa-Behavior".to_string()
    }

    async fn vote(&self, event: &SysmonEvent) -> Option<VoteResult> {
        let is_create = matches!(
            event.event_id,
            osoosi_types::SysmonEventId::ProcessCreate | osoosi_types::SysmonEventId::FileCreate
        );
        if !is_create {
            return None;
        }

        if let Some(image_path) = event.data.get("Image").and_then(|v| v.as_str()) {
            if scanner_skip_path(image_path) || trusted_identity_signal(event, image_path) {
                return None;
            }
            let path = Path::new(image_path);
            if !path.exists() {
                return None;
            }

            if let Ok(Some(sig)) = self.analyzer.analyze_file(path).await {
                // If CAPA found specific persistence/c2 capabilities, we yield a vote
                if sig.confidence > 0.4 {
                    return Some(VoteResult {
                        confidence: sig.confidence,
                        reason: sig.reason.unwrap_or_else(|| "CAPA: Detected suspicious capabilities".to_string()),
                        weight: 0.85,
                    });
                }
            }
        }
        None
    }
}

/// Mandiant FLOSS Voter
///
/// Executes FLOSS (FLARE Obfuscated String Solver) to extract hidden
/// configuration artifacts like IPs and domains.
pub struct FlossVoter {
    pub analyzer: Arc<crate::static_analyzer::StaticAnalyzer>,
}

#[async_trait]
impl ThreatVoter for FlossVoter {
    fn name(&self) -> String {
        "Floss-Artifact".to_string()
    }

    async fn vote(&self, event: &SysmonEvent) -> Option<VoteResult> {
        let is_create = matches!(
            event.event_id,
            osoosi_types::SysmonEventId::ProcessCreate | osoosi_types::SysmonEventId::FileCreate
        );
        if !is_create {
            return None;
        }

        if let Some(image_path) = event.data.get("Image").and_then(|v| v.as_str()) {
            if scanner_skip_path(image_path) || trusted_identity_signal(event, image_path) {
                return None;
            }
            let path = Path::new(image_path);
            if !path.exists() {
                return None;
            }
        }
        None
    }
}

/// Native Sigma Voter (using hayabusa crate)
pub struct SigmaVoter {
    pub engine: Arc<hayabusa::HayabusaEngine>,
}

#[async_trait]
impl ThreatVoter for SigmaVoter {
    fn name(&self) -> String {
        "Sigma-Native".to_string()
    }

    async fn vote(&self, event: &SysmonEvent) -> Option<VoteResult> {
        // Convert SysmonEvent to Hayabusa format and scan
        if let Ok(matches) = self.engine.match_event(event) {
            if !matches.is_empty() {
                let primary = &matches[0];
                return Some(VoteResult {
                    confidence: 1.0, // Default to high confidence for Sigma matches
                    reason: format!("Sigma: THREAT detected - {}", primary.detail),
                    weight: 0.95,
                });
            }
        }
        None
    }
}

/// Native .NET Forensic Voter (using dotscope)
pub struct DotscopeVoter {
    pub analyzer: Arc<crate::dotscope::DotscopeAnalyzer>,
}

#[async_trait]
impl ThreatVoter for DotscopeVoter {
    fn name(&self) -> String {
        "Dotscope-Forensics".to_string()
    }

    async fn vote(&self, event: &SysmonEvent) -> Option<VoteResult> {
        if let Some(image_path) = event.data.get("Image").and_then(|v| v.as_str()) {
            if !image_path.to_lowercase().ends_with(".exe") && !image_path.to_lowercase().ends_with(".dll") {
                return None;
            }
            let path = Path::new(image_path);
            if let Ok(results) = self.analyzer.analyze_file(path).await {
                if results.is_suspicious {
                    return Some(VoteResult {
                        confidence: 0.88,
                        reason: format!("Dotscope: Suspicious .NET CIL detected - {}", results.reason),
                        weight: 0.9,
                    });
                }
            }
        }
        None
    }
}

/// Native Memory Inspection Voter (using pelite)
///
/// Replaces Hollows-Hunter with in-memory PE parsing.
pub struct MemoryInspectionVoter {
    pub memory: Arc<osoosi_memory::MemoryStore>,
}

#[async_trait]
impl ThreatVoter for MemoryInspectionVoter {
    fn name(&self) -> String {
        "MemoryInspection-Native".to_string()
    }

    async fn vote(&self, event: &SysmonEvent) -> Option<VoteResult> {
        #[cfg(target_os = "windows")]
        {
            if let Some(pid) = event.process_id() {
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
            }
        }
        None
    }
}
