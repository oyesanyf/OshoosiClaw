//! TFHE-rs Fully Homomorphic Encryption (FHE) for OpenỌ̀ṣọ́ọ̀sì.
//!
//! Enables privacy-preserving arithmetic (Addition/Multiplication) on encrypted threat telemetry.

use tfhe::prelude::*;
use tfhe::{generate_keys, ConfigBuilder, ClientKey, ServerKey, FheUint16};
use serde::{Deserialize, Serialize};

pub struct OshoosiFhe {
    pub client_key: ClientKey,
    pub server_key: ServerKey,
}

impl OshoosiFhe {
    pub fn new() -> Self {
        let config = ConfigBuilder::default_with_big_encryption().build();
        let (client_key, server_key) = generate_keys(config);
        Self { client_key, server_key }
    }

    /// Encrypt a confidence score (0-100 normalized to 16-bit int)
    pub fn encrypt_score(&self, score: u16) -> FheUint16 {
        FheUint16::encrypt(score, &self.client_key)
    }

    /// Decrypt an aggregated score
    pub fn decrypt_score(&self, ciphertext: &FheUint16) -> u16 {
        ciphertext.decrypt(&self.client_key)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EncryptedTelemetry {
    pub data: Vec<u8>,
    pub source_node: String,
}

/// Utility to aggregate multiple encrypted scores homomorphically.
/// Requires the global ServerKey to be set in the task/thread context.
pub fn aggregate_scores(scores: &[FheUint16], server_key: &ServerKey) -> FheUint16 {
    tfhe::set_server_key(server_key.clone());
    let mut sum = scores[0].clone();
    for next in &scores[1..] {
        sum = sum + next;
    }
    sum
}
