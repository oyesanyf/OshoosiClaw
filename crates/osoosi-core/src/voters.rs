use osoosi_policy::engine::{ThreatVoter, VoteResult};
use osoosi_types::SysmonEvent;
use osoosi_model::MalwareScanner;
use std::sync::Arc;
use std::path::Path;

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
