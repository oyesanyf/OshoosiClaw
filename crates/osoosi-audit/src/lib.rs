//! Cryptographic Audit Trail (Merkle Tree).
//!
//! Provides a tamper-evident, verifiable log of all system events and agent decisions.
//! This implementation uses a binary Merkle Tree for efficient inclusion proofs.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Mutex;

pub mod tpm;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuditEntry {
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub data: serde_json::Value,
}

pub struct MerkleAuditTree {
    entries: Mutex<Vec<AuditEntry>>,
    hashes: Mutex<Vec<String>>,
    root: Mutex<String>,
}

impl Default for MerkleAuditTree {
    fn default() -> Self {
        Self::new()
    }
}

impl MerkleAuditTree {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
            hashes: Mutex::new(Vec::new()),
            root: Mutex::new("0".repeat(64)),
        }
    }

    /// Append a new event and recalculate the Merkle Root.
    pub fn log(&self, event_type: &str, data: serde_json::Value) -> String {
        let mut entries = self.entries.lock().expect("audit entries mutex poisoned");
        let mut hashes = self.hashes.lock().expect("audit hashes mutex poisoned");
        let mut root = self.root.lock().expect("audit root mutex poisoned");

        let entry = AuditEntry {
            timestamp: Utc::now(),
            event_type: event_type.to_string(),
            data,
        };

        // 1. Calculate Leaf Hash: Hash(JSON(Entry))
        let mut hasher = Sha256::new();
        hasher.update(serde_json::to_vec(&entry).unwrap_or_default());
        let leaf_hash = hex::encode(hasher.finalize());

        entries.push(entry);
        hashes.push(leaf_hash);

        // 2. Recompute Merkle Root (Binary Tree)
        let new_root = self.compute_root(&hashes);
        *root = new_root.clone();

        // 3. Extend to hardware TPM for root-of-trust
        let _ = tpm::extend_audit_to_tpm(event_type, &new_root);

        new_root
    }

    fn compute_root(&self, leaf_hashes: &[String]) -> String {
        if leaf_hashes.is_empty() {
            return "0".repeat(64);
        }
        let mut current_level = leaf_hashes.to_vec();
        while current_level.len() > 1 {
            let mut next_level = Vec::new();
            for i in (0..current_level.len()).step_by(2) {
                let left = &current_level[i];
                let right = if i + 1 < current_level.len() {
                    &current_level[i + 1]
                } else {
                    left // Balanced tree: duplicate last node if odd
                };

                let mut hasher = Sha256::new();
                hasher.update(left.as_bytes());
                hasher.update(right.as_bytes());
                next_level.push(hex::encode(hasher.finalize()));
            }
            current_level = next_level;
        }
        current_level[0].clone()
    }

    /// Generate a Merkle Inclusion Proof for a specific entry index.
    pub fn generate_proof(&self, index: usize) -> Option<osoosi_types::MerkleProof> {
        let entries = self.entries.lock().unwrap();
        let hashes = self.hashes.lock().unwrap();
        
        if index >= entries.len() {
            return None;
        }

        let mut proof_hashes = Vec::new();
        let mut current_index = index;
        let mut current_level = hashes.clone();

        while current_level.len() > 1 {
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };

            if sibling_index < current_level.len() {
                proof_hashes.push(current_level[sibling_index].clone());
            } else {
                proof_hashes.push(current_level[current_index].clone());
            }

            // Move up to the next level
            let mut next_level = Vec::new();
            for i in (0..current_level.len()).step_by(2) {
                let left = &current_level[i];
                let right = if i + 1 < current_level.len() {
                    &current_level[i + 1]
                } else {
                    left
                };
                let mut hasher = Sha256::new();
                hasher.update(left.as_bytes());
                hasher.update(right.as_bytes());
                next_level.push(hex::encode(hasher.finalize()));
            }
            current_level = next_level;
            current_index /= 2;
        }

        Some(osoosi_types::MerkleProof {
            leaf_hash: hashes[index].clone(),
            root_hash: self.root.lock().unwrap().clone(),
            siblings: proof_hashes,
            index,
        })
    }

    pub fn root(&self) -> String {
        self.root.lock().unwrap().clone()
    }

    pub fn entries(&self) -> Vec<AuditEntry> {
        self.entries.lock().unwrap().clone()
    }
}

