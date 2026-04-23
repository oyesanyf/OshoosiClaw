//! Cryptographic Audit Trail (Merkle Chain).
//!
//! Provides a tamper-evident log of all system events and agent decisions.

use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use std::sync::Mutex;

pub mod tpm;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuditEntry {
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub data: serde_json::Value,
    pub prev_hash: String,
}

pub struct AuditTrail {
    entries: Mutex<Vec<AuditEntry>>,
    current_hash: Mutex<String>,
}

impl Default for AuditTrail {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditTrail {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
            current_hash: Mutex::new("0".repeat(64)), // Genesis hash
        }
    }

    /// Append a new event to the Merkle Chain.
    pub fn log(&self, event_type: &str, data: serde_json::Value) -> String {
        let mut entries = self.entries.lock().expect("audit entries mutex poisoned");
        let mut current_hash = self.current_hash.lock().expect("audit current_hash mutex poisoned");

        let entry = AuditEntry {
            timestamp: Utc::now(),
            event_type: event_type.to_string(),
            data,
            prev_hash: current_hash.clone(),
        };

        // Calculate new hash: Hash(Data + PrevHash)
        let mut hasher = Sha256::new();
        hasher.update(serde_json::to_vec(&entry.data).unwrap_or_default());
        hasher.update(entry.prev_hash.as_bytes());
        let new_hash = hex::encode(hasher.finalize());

        *current_hash = new_hash.clone();
        entries.push(entry);

        // Layer 3: Extend audit hash into TPM PCR (hardware attestation)
        let _attestation = tpm::extend_audit_to_tpm(event_type, &new_hash);

        new_hash
    }

    /// Verify the integrity of the entire chain.
    pub fn verify(&self) -> bool {
        let entries = self.entries.lock().unwrap();
        if entries.is_empty() {
            return true;
        }

        let mut expected_prev_hash = "0".repeat(64);
        for entry in entries.iter() {
            if entry.prev_hash != expected_prev_hash {
                return false;
            }

            let mut hasher = Sha256::new();
            hasher.update(serde_json::to_vec(&entry.data).unwrap_or_default());
            hasher.update(entry.prev_hash.as_bytes());
            expected_prev_hash = hex::encode(hasher.finalize());
        }

        true
    }

    /// Get the Merkle Root (current state hash).
    pub fn root(&self) -> String {
        self.current_hash.lock().expect("audit current_hash mutex poisoned").clone()
    }

    /// Get all entries for forensic analysis.
    pub fn entries(&self) -> Vec<AuditEntry> {
        self.entries.lock().expect("audit entries mutex poisoned").clone()
    }

    /// Get recent entries.
    pub fn get_recent_entries(&self, count: usize) -> Vec<AuditEntry> {
        let entries = self.entries.lock().expect("audit entries mutex poisoned");
        entries.iter().rev().take(count).cloned().collect()
    }

    /// Generate a Merkle Proof for a specific entry index.
    pub fn generate_proof(&self, index: usize) -> Option<osoosi_types::MerkleProof> {
        let entries = self.entries.lock().expect("audit entries mutex poisoned");
        if index >= entries.len() {
            return None;
        }

        let entry = &entries[index];
        let mut hasher = Sha256::new();
        hasher.update(serde_json::to_vec(&entry.data).unwrap_or_default());
        hasher.update(entry.prev_hash.as_bytes());
        let leaf_hash = hex::encode(hasher.finalize());

        // In a linear chain, the "siblings" are the preceding hashes.
        // For a true Merkle Tree proof, we'd need a different structure.
        // Here we provide a simplified proof for the chain.
        Some(osoosi_types::MerkleProof {
            leaf_hash,
            root_hash: self.root(),
            siblings: entries.iter().take(index).map(|e| e.prev_hash.clone()).collect(),
            index,
        })
    }
}
