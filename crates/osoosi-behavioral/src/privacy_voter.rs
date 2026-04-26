use osoosi_policy::engine::{ThreatVoter, VoteResult};
use osoosi_types::SysmonEvent;
use osoosi_dp::{DifferentialPrivacy, PrivacyConfig};
use osoosi_audit::MerkleAuditTree;
use std::sync::Arc;

/// A privacy-preserving voter that uses Differential Privacy and Merkle Auditing.
pub struct PrivacyVoter {
    dp: DifferentialPrivacy,
    audit: Arc<MerkleAuditTree>,
}

impl PrivacyVoter {
    pub fn new(config: PrivacyConfig, audit: Arc<MerkleAuditTree>) -> Self {
        Self {
            dp: DifferentialPrivacy::new(config),
            audit,
        }
    }
}

impl ThreatVoter for PrivacyVoter {
    fn name(&self) -> String {
        "Privacy-Enforced-Voter".to_string()
    }

    fn vote(&self, event: &SysmonEvent) -> Option<VoteResult> {
        // 1. Calculate a base "suspicion" score (placeholder logic)
        let mut base_score = 0.0;
        if let Some(cmd) = event.data.get("CommandLine").and_then(|v| v.as_str()) {
            if cmd.contains("powershell") || cmd.contains("base64") {
                base_score = 0.65;
            }
        }

        if base_score > 0.0 {
            // 2. APPLY DIFFERENTIAL PRIVACY: Add Laplacian noise to the score
            // This prevents an observer from knowing the exact local detection confidence.
            let noisy_score = (base_score + self.dp.laplace_noise()).clamp(0.0, 1.0);

            // 3. LOG TO MERKLE AUDIT TREE: Ensure the decision is tamper-proof
            let root = self.audit.log("PRIVACY_VOTE_EMITTED", serde_json::json!({
                "event_id": event.event_id,
                "noisy_score": noisy_score,
                "computer": event.computer,
            }));

            Some(VoteResult {
                confidence: noisy_score,
                reason: format!("Privacy-preserving detection (DP enabled). Merkle Root: {}", root),
                weight: 0.8,
            })
        } else {
            None
        }
    }
}
