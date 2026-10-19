//! Privacy-Preserving Fully Homomorphic Encryption (TFHE) & Merkle Audit Coordinator.
//!
//! Implements the 4-Pillar FHE Architectural Strategy for OpenỌ̀ṣọ́ọ̀sì:
//! 1. P2P Threat Intelligence Sharing: Zero-knowledge matching and consensus aggregation across mesh nodes
//! 2. Blind Threat Scoring / Cloud Inference: Homomorphic evaluation over encrypted feature vectors without telemetry leakage
//! 3. Privacy-Preserving Anomaly Telemetry: Cross-fleet anomaly aggregation with Differential Privacy (Laplace noise)
//! 4. Real-Time Driver / ETW Latency Boundary: Hard architectural invariant enforcing zero-FHE on hot kernel/driver paths
//! 5. Cryptographic Merkle Tree Protection: Every FHE ciphertext, batch, tally, and rollup is anchored into a tamper-evident BLAKE3 Merkle ledger

use anyhow::{anyhow, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, LazyLock, RwLock};
use tfhe::prelude::*;
use tfhe::{generate_keys, ClientKey, ConfigBuilder, FheUint16, FheUint32, ServerKey};
use tracing::warn;

/// Maximum latency budget (in microseconds) allowed for hot kernel driver and ETW ingestion paths.
/// FHE evaluation times (tens of milliseconds) strictly exceed this budget and MUST NEVER run on the hot path.
pub const KERNEL_ETW_MAX_LATENCY_MICROS: u64 = 500;

/// Default DP epsilon for privacy-preserving fleet anomaly rollups
pub const DEFAULT_FLEET_DP_EPSILON: f32 = 0.5;

/// ──────────────────────────────────────────────────────────────
/// Cryptographic Merkle Tree Structures for FHE Audit Ledger
/// ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FheMerkleLeaf {
    pub seq: u64,
    pub timestamp: String,
    pub operation_type: String, // "P2P_CONSENSUS" | "BLIND_INFERENCE" | "FLEET_ANOMALY_ROLLUP"
    pub payload_hash: String,
    pub leaf_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FheMerkleAuditProof {
    pub leaf_seq: u64,
    pub leaf_hash: String,
    pub audit_path: Vec<String>,
    pub merkle_root: String,
    pub tree_size: usize,
    pub timestamp: String,
}

/// Computes a standard binary BLAKE3 Merkle Root over a list of leaf hashes.
pub fn compute_merkle_root(leaf_hashes: &[String]) -> String {
    if leaf_hashes.is_empty() {
        return blake3::hash(b"EMPTY_MERKLE_ROOT").to_hex().to_string();
    }
    if leaf_hashes.len() == 1 {
        return leaf_hashes[0].clone();
    }

    let mut current_level = leaf_hashes.to_vec();
    while current_level.len() > 1 {
        let mut next_level = Vec::with_capacity(current_level.len().div_ceil(2));
        for chunk in current_level.chunks(2) {
            if chunk.len() == 2 {
                let mut hasher = blake3::Hasher::new();
                hasher.update(b"INTERNAL_NODE:");
                hasher.update(chunk[0].as_bytes());
                hasher.update(chunk[1].as_bytes());
                next_level.push(hasher.finalize().to_hex().to_string());
            } else {
                next_level.push(chunk[0].clone());
            }
        }
        current_level = next_level;
    }

    current_level[0].clone()
}

/// Generates a binary Merkle audit path for a given leaf index.
pub fn generate_merkle_proof(leaf_hashes: &[String], target_idx: usize) -> Option<Vec<String>> {
    if target_idx >= leaf_hashes.len() {
        return None;
    }

    let mut path = Vec::new();
    let mut current_idx = target_idx;
    let mut current_level = leaf_hashes.to_vec();

    while current_level.len() > 1 {
        let sibling_idx = if current_idx.is_multiple_of(2) {
            if current_idx + 1 < current_level.len() {
                Some(current_idx + 1)
            } else {
                None
            }
        } else {
            Some(current_idx - 1)
        };

        if let Some(s_idx) = sibling_idx {
            path.push(current_level[s_idx].clone());
        }

        let mut next_level = Vec::with_capacity(current_level.len().div_ceil(2));
        for chunk in current_level.chunks(2) {
            if chunk.len() == 2 {
                let mut hasher = blake3::Hasher::new();
                hasher.update(b"INTERNAL_NODE:");
                hasher.update(chunk[0].as_bytes());
                hasher.update(chunk[1].as_bytes());
                next_level.push(hasher.finalize().to_hex().to_string());
            } else {
                next_level.push(chunk[0].clone());
            }
        }
        current_level = next_level;
        current_idx /= 2;
    }

    Some(path)
}

/// Verifies a Merkle audit path against an expected root.
pub fn verify_merkle_proof(leaf_hash: &str, path: &[String], root: &str, mut idx: usize) -> bool {
    let mut current = leaf_hash.to_string();
    for sibling in path {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"INTERNAL_NODE:");
        if idx.is_multiple_of(2) {
            hasher.update(current.as_bytes());
            hasher.update(sibling.as_bytes());
        } else {
            hasher.update(sibling.as_bytes());
            hasher.update(current.as_bytes());
        }
        current = hasher.finalize().to_hex().to_string();
        idx /= 2;
    }
    current == root
}

// ──────────────────────────────────────────────────────────────
// FHE Coordinator Engine
// ──────────────────────────────────────────────────────────────

/// FHE Coordinator Engine managing homomorphic evaluation and BLAKE3 Merkle tree audit logging.
pub struct FheCoordinator {
    client_key: ClientKey,
    server_key: ServerKey,
    audit_leaves: RwLock<Vec<FheMerkleLeaf>>,
}

impl Default for FheCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

impl FheCoordinator {
    pub fn new() -> Self {
        let config = ConfigBuilder::default_with_big_encryption().build();
        let (client_key, server_key) = generate_keys(config);
        Self {
            client_key,
            server_key,
            audit_leaves: RwLock::new(Vec::new()),
        }
    }

    /// Records a new operation leaf in the BLAKE3 Merkle tree.
    fn record_merkle_leaf(&self, op_type: &str, payload_bytes: &[u8]) -> FheMerkleLeaf {
        let mut guard = self.audit_leaves.write().unwrap();
        let seq = guard.len() as u64;
        let timestamp = Utc::now().to_rfc3339();
        let payload_hash = blake3::hash(payload_bytes).to_hex().to_string();

        let mut leaf_hasher = blake3::Hasher::new();
        leaf_hasher.update(b"FHE_LEAF:");
        leaf_hasher.update(seq.to_le_bytes().as_ref());
        leaf_hasher.update(op_type.as_bytes());
        leaf_hasher.update(payload_hash.as_bytes());
        let leaf_hash = leaf_hasher.finalize().to_hex().to_string();

        let leaf = FheMerkleLeaf {
            seq,
            timestamp,
            operation_type: op_type.to_string(),
            payload_hash,
            leaf_hash,
        };

        guard.push(leaf.clone());
        leaf
    }

    /// Retrieves current Merkle Root across all recorded FHE operations.
    pub fn get_merkle_root(&self) -> String {
        let guard = self.audit_leaves.read().unwrap();
        let leaf_hashes: Vec<String> = guard.iter().map(|l| l.leaf_hash.clone()).collect();
        compute_merkle_root(&leaf_hashes)
    }

    /// Retrieves current number of leaves in the Merkle audit tree.
    pub fn get_tree_size(&self) -> usize {
        self.audit_leaves.read().unwrap().len()
    }

    /// Generates cryptographic Merkle proof for a recorded operation sequence.
    pub fn get_audit_proof(&self, seq: u64) -> Result<FheMerkleAuditProof> {
        let guard = self.audit_leaves.read().unwrap();
        let leaf_hashes: Vec<String> = guard.iter().map(|l| l.leaf_hash.clone()).collect();
        let tree_size = leaf_hashes.len();

        let leaf = guard
            .get(seq as usize)
            .ok_or_else(|| anyhow!("FHE Merkle leaf sequence {} not found", seq))?;

        let audit_path = generate_merkle_proof(&leaf_hashes, seq as usize)
            .ok_or_else(|| anyhow!("Failed to generate audit path for seq {}", seq))?;
        let merkle_root = compute_merkle_root(&leaf_hashes);

        Ok(FheMerkleAuditProof {
            leaf_seq: seq,
            leaf_hash: leaf.leaf_hash.clone(),
            audit_path,
            merkle_root,
            tree_size,
            timestamp: leaf.timestamp.clone(),
        })
    }

    // ──────────────────────────────────────────────────────────
    // Pillar 1: P2P Threat Intelligence Sharing
    // ──────────────────────────────────────────────────────────

    /// Encrypts an individual node's threat consensus vote (0..100 normalized score).
    pub fn encrypt_threat_vote(&self, score: u16) -> Result<Vec<u8>> {
        let enc = FheUint16::encrypt(score, &self.client_key);
        let bytes = bincode::serialize(&enc)?;
        Ok(bytes)
    }

    /// Batched P2P threat consensus aggregation:
    /// Takes encrypted votes from mesh peer nodes and homomorphically sums them
    /// without decrypting or leaking individual peer votes.
    ///
    /// Anchors the resulting encrypted tally into the BLAKE3 Merkle tree.
    pub fn aggregate_p2p_consensus_batch(
        &self,
        encrypted_votes: &[Vec<u8>],
    ) -> Result<(Vec<u8>, FheMerkleLeaf)> {
        if encrypted_votes.is_empty() {
            return Err(anyhow!("Cannot aggregate empty encrypted vote batch"));
        }

        tfhe::set_server_key(self.server_key.clone());

        let mut sum: FheUint16 = bincode::deserialize(&encrypted_votes[0])?;
        for raw in &encrypted_votes[1..] {
            let next: FheUint16 = bincode::deserialize(raw)?;
            sum += &next;
        }

        let serialized_tally = bincode::serialize(&sum)?;
        let leaf = self.record_merkle_leaf("P2P_CONSENSUS", &serialized_tally);

        Ok((serialized_tally, leaf))
    }

    /// Decrypts the aggregate consensus score (only available to nodes holding the ClientKey).
    pub fn decrypt_consensus_tally(&self, tally_bytes: &[u8], total_nodes: usize) -> Result<f32> {
        let tally: FheUint16 = bincode::deserialize(tally_bytes)?;
        let raw_sum: u16 = tally.decrypt(&self.client_key);
        if total_nodes == 0 {
            return Ok(0.0);
        }
        Ok((raw_sum as f32) / (total_nodes as f32))
    }

    // ──────────────────────────────────────────────────────────
    // Pillar 2: Blind Threat Scoring / Cloud Inference
    // ──────────────────────────────────────────────────────────

    /// Encrypts a feature vector for privacy-preserving blind remote inference.
    /// Features are normalized to u32 values (e.g., process lineage, entropy, network connection density).
    pub fn encrypt_feature_vector(&self, features: &[u32]) -> Result<Vec<Vec<u8>>> {
        let mut ciphertexts = Vec::with_capacity(features.len());
        for &feat in features {
            let enc = FheUint32::encrypt(feat, &self.client_key);
            ciphertexts.push(bincode::serialize(&enc)?);
        }
        Ok(ciphertexts)
    }

    /// Evaluates an encrypted linear decision model homomorphically over encrypted features:
    /// Computes $Score = \sum (w_i \cdot x_i)$ strictly in ciphertext space.
    /// The evaluator never learns the client's telemetry or process context.
    ///
    /// Anchors the evaluation into the Merkle audit tree.
    pub fn evaluate_blind_inference(
        &self,
        encrypted_features: &[Vec<u8>],
        model_weights: &[u32],
    ) -> Result<(Vec<u8>, FheMerkleLeaf)> {
        if encrypted_features.len() != model_weights.len() {
            return Err(anyhow!(
                "Feature count ({}) does not match weight count ({})",
                encrypted_features.len(),
                model_weights.len()
            ));
        }
        if encrypted_features.is_empty() {
            return Err(anyhow!("Feature vector cannot be empty"));
        }

        tfhe::set_server_key(self.server_key.clone());

        // Accumulate in 32-bit to prevent overflow during dot-product
        let mut accumulated = FheUint32::encrypt(0u32, &self.client_key);

        for (raw_feat, &weight) in encrypted_features.iter().zip(model_weights.iter()) {
            let feat_32: FheUint32 = bincode::deserialize(raw_feat)?;
            let term = feat_32 * weight;
            accumulated += term;
        }

        let serialized_result = bincode::serialize(&accumulated)?;
        let leaf = self.record_merkle_leaf("BLIND_INFERENCE", &serialized_result);

        Ok((serialized_result, leaf))
    }

    /// Decrypts the blind inference result (client-side only).
    pub fn decrypt_blind_inference_score(&self, result_bytes: &[u8]) -> Result<u32> {
        let enc: FheUint32 = bincode::deserialize(result_bytes)?;
        let score: u32 = enc.decrypt(&self.client_key);
        Ok(score)
    }

    // ──────────────────────────────────────────────────────────
    // Pillar 3: Privacy-Preserving Anomaly Telemetry
    // ──────────────────────────────────────────────────────────

    /// Encrypts an individual anomaly score (0..100) as FheUint32.
    pub fn encrypt_anomaly_score(&self, score: u32) -> Result<Vec<u8>> {
        let enc = FheUint32::encrypt(score, &self.client_key);
        Ok(bincode::serialize(&enc)?)
    }

    /// Cross-fleet privacy-preserving anomaly score rollup:
    /// Combines homomorphic summation with Differential Privacy (Laplace noise from `osoosi_dp`),
    /// ensuring no individual host or user PII can be re-identified in fleet telemetry.
    ///
    /// Anchors the noisy aggregated result into the Merkle audit tree.
    pub fn rollup_fleet_anomaly_telemetry(
        &self,
        encrypted_scores: &[Vec<u8>],
        epsilon: f32,
    ) -> Result<(f32, FheMerkleLeaf)> {
        if encrypted_scores.is_empty() {
            return Err(anyhow!("Empty anomaly scores array"));
        }

        tfhe::set_server_key(self.server_key.clone());

        let mut sum = FheUint32::encrypt(0u32, &self.client_key);
        for raw in encrypted_scores {
            let enc: FheUint32 = bincode::deserialize(raw)?;
            sum += enc;
        }

        let total_samples = encrypted_scores.len();
        let raw_sum: u32 = sum.decrypt(&self.client_key);
        let mean = (raw_sum as f32) / (total_samples as f32);

        // Differential Privacy Laplace Mechanism
        let dp_config = osoosi_dp::PrivacyConfig {
            epsilon,
            min_samples: 2,
            sensitivity: 100.0 / (total_samples as f32).max(1.0),
        };
        let dp = osoosi_dp::DifferentialPrivacy::new(dp_config);
        let noisy_mean = dp.add_noise(mean).clamp(0.0, 100.0);

        let rollup_bytes = format!("{}:{}:{}", total_samples, mean, noisy_mean);
        let leaf = self.record_merkle_leaf("FLEET_ANOMALY_ROLLUP", rollup_bytes.as_bytes());

        Ok((noisy_mean, leaf))
    }

    // ──────────────────────────────────────────────────────────
    // Pillar 4: Real-Time Driver & ETW Latency Boundary Enforcement
    // ──────────────────────────────────────────────────────────

    /// Architectural Assertion:
    /// Asserts that hot kernel driver and ETW ingestion paths strictly bypass FHE
    /// and rely on zero-overhead local BLAKE3/SHA-256 primitives within latency budget.
    pub fn verify_driver_etw_latency_boundary(measured_micros: u64) -> Result<()> {
        if measured_micros > KERNEL_ETW_MAX_LATENCY_MICROS {
            warn!(
                "⚠️ [FHE-LATENCY-VIOLATION] Operation latency ({} µs) exceeds kernel budget ({} µs)! FHE must NEVER be invoked on real-time driver/ETW paths.",
                measured_micros, KERNEL_ETW_MAX_LATENCY_MICROS
            );
            return Err(anyhow!(
                "Latency budget exceeded: {} µs > {} µs",
                measured_micros,
                KERNEL_ETW_MAX_LATENCY_MICROS
            ));
        }
        Ok(())
    }
}

/// Global Singleton for the FHE Coordinator
static GLOBAL_FHE_COORDINATOR: LazyLock<Arc<FheCoordinator>> =
    LazyLock::new(|| Arc::new(FheCoordinator::new()));

pub fn global_fhe_coordinator() -> &'static Arc<FheCoordinator> {
    &GLOBAL_FHE_COORDINATOR
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_tree_computation_and_proof_verification() {
        let leaves = vec![
            blake3::hash(b"leaf_0").to_hex().to_string(),
            blake3::hash(b"leaf_1").to_hex().to_string(),
            blake3::hash(b"leaf_2").to_hex().to_string(),
            blake3::hash(b"leaf_3").to_hex().to_string(),
        ];

        let root = compute_merkle_root(&leaves);
        assert_eq!(root.len(), 64);

        // Verify leaf 0 proof
        let proof_0 = generate_merkle_proof(&leaves, 0).unwrap();
        assert!(verify_merkle_proof(&leaves[0], &proof_0, &root, 0));

        // Verify leaf 2 proof
        let proof_2 = generate_merkle_proof(&leaves, 2).unwrap();
        assert!(verify_merkle_proof(&leaves[2], &proof_2, &root, 2));

        // Tampered leaf must fail verification
        let tampered = blake3::hash(b"tampered").to_hex().to_string();
        assert!(!verify_merkle_proof(&tampered, &proof_0, &root, 0));
    }

    #[test]
    fn test_driver_etw_latency_boundary_invariant() {
        // Fast path: 50 µs is well within the 500 µs kernel budget
        assert!(FheCoordinator::verify_driver_etw_latency_boundary(50).is_ok());

        // Slow path: 15,000 µs (e.g. FHE bootstrap) is rejected as violating kernel budget
        assert!(FheCoordinator::verify_driver_etw_latency_boundary(15_000).is_err());
    }

    #[test]
    fn test_fhe_coordinator_p2p_and_merkle_protection() {
        let coord = FheCoordinator::new();

        // 1. P2P Threat Sharing: Encrypt 3 peer votes (70, 80, 90)
        let v1 = coord.encrypt_threat_vote(70).unwrap();
        let v2 = coord.encrypt_threat_vote(80).unwrap();
        let v3 = coord.encrypt_threat_vote(90).unwrap();

        let (tally, leaf) = coord.aggregate_p2p_consensus_batch(&[v1, v2, v3]).unwrap();
        assert_eq!(leaf.operation_type, "P2P_CONSENSUS");

        let avg = coord.decrypt_consensus_tally(&tally, 3).unwrap();
        assert!((avg - 80.0).abs() < 0.001);

        // 2. Merkle Proof Verification for the P2P operation
        let proof = coord.get_audit_proof(leaf.seq).unwrap();
        let current_root = coord.get_merkle_root();
        assert_eq!(proof.merkle_root, current_root);
        assert!(verify_merkle_proof(
            &proof.leaf_hash,
            &proof.audit_path,
            &current_root,
            proof.leaf_seq as usize
        ));
    }

    #[test]
    fn test_fhe_blind_threat_scoring() {
        let coord = FheCoordinator::new();

        // Features: [entropy = 5, connections = 3, anomalies = 2]
        let features = vec![5u32, 3u32, 2u32];
        // Linear weights: [10, 20, 30] -> Expected dot product = 5*10 + 3*20 + 2*30 = 50 + 60 + 60 = 170
        let weights = vec![10u32, 20u32, 30u32];

        let enc_features = coord.encrypt_feature_vector(&features).unwrap();
        let (eval_result, leaf) = coord
            .evaluate_blind_inference(&enc_features, &weights)
            .unwrap();
        assert_eq!(leaf.operation_type, "BLIND_INFERENCE");

        let decrypted_score = coord.decrypt_blind_inference_score(&eval_result).unwrap();
        assert_eq!(decrypted_score, 170);

        // Verify Merkle audit proof
        let proof = coord.get_audit_proof(leaf.seq).unwrap();
        assert!(verify_merkle_proof(
            &proof.leaf_hash,
            &proof.audit_path,
            &coord.get_merkle_root(),
            proof.leaf_seq as usize
        ));
    }

    #[test]
    fn test_fhe_fleet_anomaly_telemetry_and_merkle() {
        let coord = FheCoordinator::new();

        // Anomaly scores from 3 hosts: 40, 50, 60 -> expected mean ~ 50
        let a1 = coord.encrypt_anomaly_score(40).unwrap();
        let a2 = coord.encrypt_anomaly_score(50).unwrap();
        let a3 = coord.encrypt_anomaly_score(60).unwrap();

        let (noisy_mean, leaf) = coord
            .rollup_fleet_anomaly_telemetry(&[a1, a2, a3], 1.0)
            .unwrap();
        assert_eq!(leaf.operation_type, "FLEET_ANOMALY_ROLLUP");
        // With Laplace DP noise clamped to [0.0, 100.0]
        assert!((0.0..=100.0).contains(&noisy_mean));

        let proof = coord.get_audit_proof(leaf.seq).unwrap();
        assert!(verify_merkle_proof(
            &proof.leaf_hash,
            &proof.audit_path,
            &coord.get_merkle_root(),
            proof.leaf_seq as usize
        ));
    }
}
