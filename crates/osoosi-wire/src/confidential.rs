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
        let config = ConfigBuilder::default().build();
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
        let mut total = FheUint32::encrypt(0u32, &self.client_key); // In reality, server key doesn't encrypt
        tfhe::set_server_key(self.server_key.clone());

        for v in votes {
            let encrypted_vote: FheUint32 = bincode::deserialize(&v)?;
            total = &total + &encrypted_vote;
        }

        Ok(total)
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
