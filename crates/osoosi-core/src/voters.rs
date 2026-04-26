use osoosi_model::{MalwareScanResult, MalwareScanner};
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

/// ClamAV Consensus Voter
///
/// Provides a "clean" vote if ClamAV confirms the file is not infected.
/// This acts as positive reinforcement for legitimate files that might
/// otherwise look suspicious to ML models or behavioral heuristics.
pub struct ClamVoter {
    pub scanner: Arc<MalwareScanner>,
}

impl ThreatVoter for ClamVoter {
    fn name(&self) -> String {
        "ClamAV-Consensus".to_string()
    }

    fn vote(&self, event: &SysmonEvent) -> Option<VoteResult> {
        if let Some(image_path) = event.data.get("Image").and_then(|v| v.as_str()) {
            if scanner_skip_path(image_path) || trusted_identity_signal(event, image_path) {
                return None;
            }
            let path = Path::new(image_path);
            if !path.exists() {
                return None;
            }

            // Perform scan via the shared MalwareScanner
            if let Some(result) = self.scanner.scan_file(path) {
                if result.clam_detected == Some(false) {
                    return Some(VoteResult {
                        confidence: 0.0, // This is a "clean" signal
                        reason: format!("ClamAV: File {} is clean.", image_path),
                        weight: -1.0, // Negative weight rewards clean files in consensus
                    });
                } else if result.clam_detected == Some(true) {
                    return Some(VoteResult {
                        confidence: 1.0,
                        reason: format!("ClamAV: INFECTED file detected at {}", image_path),
                        weight: 1.0, // Direct hit
                    });
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

impl ThreatVoter for MalConvVoter {
    fn name(&self) -> String {
        "MalConv-ML".to_string()
    }

    fn vote(&self, event: &SysmonEvent) -> Option<VoteResult> {
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
            if let Some(res) = self.scanner.scan_file(path) {
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
        let weak_signature_only =
            res.ml_score <= 0.0 && res.signature_score >= 1.0 && res.clam_detected != Some(true);
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
