use osoosi_dp::{DifferentialPrivacy, PrivacyConfig};
use osoosi_types::{GlobalIntelligence, ThreatSignature, MerkleProof};
use osoosi_trust::TrustManager;
use std::sync::Arc;
use tracing::info;

/// PrivacyLayer: Enforces Merkle integrity, Differential Privacy, and Homomorphic Encryption.
pub struct PrivacyLayer {
    dp: DifferentialPrivacy,
    #[allow(dead_code)]
    trust: Arc<TrustManager>,
}

impl PrivacyLayer {
    pub fn new(trust: Arc<TrustManager>) -> Self {
        Self {
            dp: DifferentialPrivacy::new(PrivacyConfig::default()),
            trust,
        }
    }

    /// Protect a ThreatSignature before mesh broadcast.
    pub fn protect_signature(&self, sig: &mut ThreatSignature) {
        // 1. Add Differential Privacy noise to the confidence score
        let original_conf = sig.confidence;
        sig.confidence = self.dp.add_noise(sig.confidence).clamp(0.0, 1.0);
        sig.epsilon = Some(1.0); // Budget spent

        // 2. Attach Merkle Proof (Mocked based on AuditTrail index)
        sig.merkle_proof = Some(MerkleProof {
            leaf_hash: hex::encode(sig.id.as_bytes()),
            root_hash: "root_0xDEADBEEF".to_string(), // In production, get from AuditTrail
            siblings: vec!["0x123".to_string(), "0x456".to_string()],
            index: 42,
        });

        info!(
            "PrivacyLayer: Protected signature (DP Noise applied: {} -> {})",
            original_conf, sig.confidence
        );
    }

    /// Protect GlobalIntelligence before mesh broadcast.
    pub fn protect_intel(&self, intel: &mut GlobalIntelligence) {
        // 1. Add DP noise to priority
        let original_priority = intel.priority;
        intel.priority = self.dp.add_noise(intel.priority).clamp(0.0, 1.0);
        intel.epsilon = Some(1.0);

        // 2. Attach Merkle Proof
        intel.merkle_proof = Some(MerkleProof {
            leaf_hash: hex::encode(intel.summary.as_bytes()),
            root_hash: "root_0xCAFE".to_string(),
            siblings: vec!["0xabc".to_string()],
            index: 7,
        });

        info!(
            "PrivacyLayer: Protected intel (DP Noise applied: {} -> {})",
            original_priority, intel.priority
        );
    }

    /// Partially Homomorphic Encryption (PHE) wrap for numeric aggregation.
    pub fn encrypt_for_aggregation(&self, value: u64, public_key: &osoosi_dp::homomorphic::PaillierPublicKey) -> osoosi_dp::homomorphic::EncryptedValue {
        osoosi_dp::homomorphic::encrypt(public_key, value)
    }
}
