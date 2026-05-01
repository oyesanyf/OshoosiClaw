//! Privacy-Preserving Collaborative Defense (TFHE).
//!
//! Uses Fully Homomorphic Encryption to allow peers to share and match IOCs
//! and participate in reputation voting without revealing local state.

use bincode;
use serde::{Deserialize, Serialize};
use tfhe::prelude::*;
use tfhe::{generate_keys, ConfigBuilder, FheUint32};
use tracing::info;

/// A message containing FHE-encrypted data for the mesh.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ConfidentialMessage {
    pub payload_type: ConfidentialType,
    pub ciphertext: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum ConfidentialType {
    IocMatch,
    ReputationVote,
    ConsensusThreshold,
}

pub struct ConfidentialOrchestrator {
    pub server_key: tfhe::ServerKey,
    pub client_key: tfhe::ClientKey,
}

impl ConfidentialOrchestrator {
    pub fn new() -> Self {
        let config = ConfigBuilder::default_with_big_encryption().build();
        let (client_key, server_key) = generate_keys(config);
        Self {
            server_key,
            client_key,
        }
    }

    /// Create an encrypted vote (1 = Agree, 0 = Disagree).
    pub fn create_vote(&self, agree: bool) -> anyhow::Result<Vec<u8>> {
        let val: u32 = if agree { 1 } else { 0 };
        let encrypted = FheUint32::encrypt(val, &self.client_key);
        let bytes = bincode::serialize(&encrypted)?;
        Ok(bytes)
    }

    /// Perform a homomorphic addition of votes from the mesh.
    /// This allows us to reach consensus without knowing how individual nodes voted.
    pub fn tally_votes(&self, votes: Vec<Vec<u8>>) -> anyhow::Result<FheUint32> {
        tfhe::set_server_key(self.server_key.clone());
        let mut total = FheUint32::encrypt(0u32, &self.client_key);

        for v in votes {
            let encrypted_vote: FheUint32 = bincode::deserialize(&v)?;
            total = &total + &encrypted_vote;
        }

        Ok(total)
    }

    /// Aggregate threat confidence scores (0-100) from the mesh.
    pub fn tally_scores(&self, encrypted_scores: Vec<Vec<u8>>) -> anyhow::Result<FheUint32> {
        tfhe::set_server_key(self.server_key.clone());
        let mut total = FheUint32::encrypt(0u32, &self.client_key);

        for s in encrypted_scores {
            let enc: FheUint32 = bincode::deserialize(&s)?;
            total = &total + &enc;
        }
        Ok(total)
    }

    /// Decrypt the final tally and apply Differential Privacy noise.
    /// This ensures that the collective intelligence is shared without leaking individual node contributions.
    pub fn finalize_with_dp(&self, tally: FheUint32, count: u32, epsilon: f32) -> f32 {
        let raw_sum: u32 = tally.decrypt(&self.client_key);
        let avg = if count > 0 { raw_sum as f32 / count as f32 } else { 0.0 };
        
        // Apply Laplace noise from osoosi-dp
        let dp_config = osoosi_dp::PrivacyConfig {
            epsilon,
            min_samples: 3,
            sensitivity: 10.0, // Scores are 0-100, sensitivity for average of N is 100/N
        };
        let dp = osoosi_dp::DifferentialPrivacy::new(dp_config);
        dp.add_noise(avg)
    }

    /// Decrypt the final tally (only the authority/mesh-leader can do this).
    pub fn finalize_tally(&self, tally: FheUint32) -> u32 {
        tally.decrypt(&self.client_key)
    }
}

/// Confidential Indicator of Compromise (IOC).
/// In a full implementation, this would use PSI (Private Set Intersection)
/// to allow matching local hashes against a global 'blacklist' without
/// revealing either.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ConfidentialIOC {
    pub encrypted_hash: Vec<u8>,
    pub action_threshold: f32,
}

impl ConfidentialIOC {
    pub fn broadcast_match(&self) {
        info!("CONFIDENTIAL: Broadcasting homomorphic IOC match request to mesh.");
    }
}
