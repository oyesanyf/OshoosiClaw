//! Cryptographic Audit Trail (Merkle Tree).
//!
//! Provides a tamper-evident, verifiable log of all system events and agent decisions.
//! Uses an **incremental** binary Merkle Tree — appending a leaf is O(log n), not O(n).
//!
//! Internal representation: a flat array of node hashes stored level-by-level.
//! On each `log()` call only the path from the new leaf to the root is recomputed.

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

pub const MAX_IN_MEMORY_AUDIT_ENTRIES: usize = 4096;

/// Internal state protected by a single mutex (eliminates the previous 3-lock dance).
struct Inner {
    entries: Vec<AuditEntry>,
    /// Leaf hashes (one per entry, in insertion order).
    leaves: Vec<String>,
    /// Cached internal + root node hashes.
    /// Layout: nodes[0..n] = leaves, nodes[n..] = internal nodes built bottom-up.
    /// We rebuild lazily via `incremental_root()`.
    ///
    /// For the incremental algorithm we store the "right-spine" of partial roots
    /// at each tree level.  This is O(log n) space.
    spine: Vec<String>,
    /// Current Merkle root.
    root: String,
    /// Epoch checkpoint root captured during in-memory compaction
    epoch_checkpoint_root: Option<String>,
}

pub struct MerkleAuditTree {
    inner: Mutex<Inner>,
}

impl Default for MerkleAuditTree {
    fn default() -> Self {
        Self::new()
    }
}

/// Combine two child hashes into a parent hash.
#[inline]
fn hash_pair(left: &str, right: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(left.as_bytes());
    hasher.update(right.as_bytes());
    hex::encode(hasher.finalize())
}

/// Updates the streaming right-spine with a new leaf hash at 1-based index `n`.
fn update_spine(spine: &mut Vec<String>, leaf_hash: &str, n: usize) {
    let mut carry = leaf_hash.to_string();
    let mut level_count = n;
    let mut level = 0;

    loop {
        if level >= spine.len() {
            spine.push(carry);
            break;
        }

        if level_count % 2 == 0 {
            carry = hash_pair(&spine[level], &carry);
            level_count /= 2;
            level += 1;
        } else {
            spine[level] = carry;
            break;
        }
    }
}

/// Rebuilds the spine from a sequence of leaf hashes.
fn rebuild_spine(leaves: &[String]) -> Vec<String> {
    let mut spine = Vec::new();
    for (i, leaf) in leaves.iter().enumerate() {
        update_spine(&mut spine, leaf, i + 1);
    }
    spine
}

/// Folds the active levels of the right-spine into a single root in O(log n) time.
fn fold_spine(spine: &[String], leaf_count: usize) -> String {
    if leaf_count == 0 {
        return "0".repeat(64);
    }
    let mut active_indices = Vec::new();
    for i in 0..spine.len() {
        if ((leaf_count >> i) & 1) == 1 {
            active_indices.push(i);
        }
    }
    if active_indices.is_empty() {
        return "0".repeat(64);
    }
    let mut acc = spine[active_indices[0]].clone();
    for &idx in &active_indices[1..] {
        acc = hash_pair(&spine[idx], &acc);
    }
    acc
}

impl MerkleAuditTree {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                entries: Vec::new(),
                leaves: Vec::new(),
                spine: Vec::new(),
                root: "0".repeat(64),
                epoch_checkpoint_root: None,
            }),
        }
    }

    /// Append a new event and **incrementally** update the Merkle root.
    ///
    /// Complexity: O(log n) hash operations per call.
    pub fn log(&self, event_type: &str, data: serde_json::Value) -> String {
        let mut inner = self.inner.lock().expect("audit mutex poisoned");

        let entry = AuditEntry {
            timestamp: Utc::now(),
            event_type: event_type.to_string(),
            data,
        };

        // 1. Compute leaf hash
        let mut hasher = Sha256::new();
        hasher.update(serde_json::to_vec(&entry).unwrap_or_default());
        let leaf_hash = hex::encode(hasher.finalize());

        inner.entries.push(entry);
        inner.leaves.push(leaf_hash.clone());

        // 2. Incremental Merkle root update via right-spine accumulation
        let n = inner.leaves.len();
        update_spine(&mut inner.spine, &leaf_hash, n);

        // 3. Auto-compact if in-memory entries reach 2x limit (8192) down to 4096
        if inner.entries.len() >= MAX_IN_MEMORY_AUDIT_ENTRIES * 2 {
            let evict_count = inner.entries.len() - MAX_IN_MEMORY_AUDIT_ENTRIES;
            let current_root = Self::compute_root_from_spine(
                &inner.spine,
                inner.leaves.len(),
                inner.epoch_checkpoint_root.as_deref(),
            );
            inner.epoch_checkpoint_root = Some(current_root);
            inner.entries.drain(0..evict_count);
            inner.leaves.drain(0..evict_count);
            inner.spine = rebuild_spine(&inner.leaves);
            inner.entries.shrink_to_fit();
            inner.leaves.shrink_to_fit();
            inner.spine.shrink_to_fit();
        }

        // 4. Compute final root by folding spine in O(log n) time
        let new_root = Self::compute_root_from_spine(
            &inner.spine,
            inner.leaves.len(),
            inner.epoch_checkpoint_root.as_deref(),
        );
        inner.root = new_root.clone();

        // 5. Extend to hardware TPM for root-of-trust
        let _ = tpm::extend_audit_to_tpm(event_type, &new_root);

        new_root
    }

    /// Compact in-memory audit log entries to cap RAM usage.
    /// Drains the oldest `inner.entries.len() - max_entries` entries, records the checkpoint root,
    /// rebuilds the spine for retained leaves, and returns the number of evicted entries.
    pub fn compact_memory(&self, max_entries: usize) -> usize {
        let mut inner = self.inner.lock().expect("audit mutex poisoned");
        if inner.entries.len() <= max_entries {
            return 0;
        }

        let evict_count = inner.entries.len() - max_entries;
        let checkpoint = Self::compute_root_from_spine(
            &inner.spine,
            inner.leaves.len(),
            inner.epoch_checkpoint_root.as_deref(),
        );
        inner.epoch_checkpoint_root = Some(checkpoint);

        inner.entries.drain(0..evict_count);
        inner.leaves.drain(0..evict_count);

        inner.spine = rebuild_spine(&inner.leaves);
        inner.root = Self::compute_root_from_spine(
            &inner.spine,
            inner.leaves.len(),
            inner.epoch_checkpoint_root.as_deref(),
        );

        inner.entries.shrink_to_fit();
        inner.leaves.shrink_to_fit();
        inner.spine.shrink_to_fit();

        evict_count
    }

    /// Compute the final Merkle root from the current leaf set.
    /// Used by `generate_proof()` and reference testing.
    #[allow(dead_code)]
    fn compute_root_from_leaves(leaf_hashes: &[String]) -> String {
        if leaf_hashes.is_empty() {
            return "0".repeat(64);
        }
        let mut current_level: Vec<String> = leaf_hashes.to_vec();
        while current_level.len() > 1 {
            let mut next_level = Vec::with_capacity((current_level.len() + 1) / 2);
            for i in (0..current_level.len()).step_by(2) {
                let left = &current_level[i];
                let right = if i + 1 < current_level.len() {
                    &current_level[i + 1]
                } else {
                    left // duplicate last if odd
                };
                next_level.push(hash_pair(left, right));
            }
            current_level = next_level;
        }
        current_level.into_iter().next().unwrap()
    }

    /// Derive the root from the spine in O(log n) time, folding with epoch checkpoint if set.
    fn compute_root_from_spine(
        spine: &[String],
        leaf_count: usize,
        epoch_checkpoint: Option<&str>,
    ) -> String {
        if leaf_count == 0 {
            return epoch_checkpoint
                .map(|c| c.to_string())
                .unwrap_or_else(|| "0".repeat(64));
        }
        let folded = fold_spine(spine, leaf_count);
        if let Some(cp) = epoch_checkpoint {
            hash_pair(cp, &folded)
        } else {
            folded
        }
    }

    /// Generate a Merkle Inclusion Proof for a specific entry index.
    pub fn generate_proof(&self, index: usize) -> Option<osoosi_types::MerkleProof> {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        if index >= inner.entries.len() {
            return None;
        }

        let leaf_hashes = &inner.leaves;
        let mut proof_hashes = Vec::new();
        let mut current_index = index;
        let mut current_level: Vec<String> = leaf_hashes.clone();

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
            let mut next_level = Vec::with_capacity((current_level.len() + 1) / 2);
            for i in (0..current_level.len()).step_by(2) {
                let left = &current_level[i];
                let right = if i + 1 < current_level.len() {
                    &current_level[i + 1]
                } else {
                    left
                };
                next_level.push(hash_pair(left, right));
            }
            current_level = next_level;
            current_index /= 2;
        }

        Some(osoosi_types::MerkleProof {
            leaf_hash: leaf_hashes[index].clone(),
            root_hash: inner.root.clone(),
            siblings: proof_hashes,
            index,
        })
    }

    pub fn root(&self) -> String {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).root.clone()
    }

    pub fn entries(&self) -> Vec<AuditEntry> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).entries.clone()
    }

    pub fn get_recent_entries(&self, limit: usize) -> Vec<AuditEntry> {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let start = inner.entries.len().saturating_sub(limit);
        inner.entries[start..].to_vec()
    }

    pub fn verify(&self) -> bool {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if inner.leaves.is_empty() {
            let expected_empty = inner
                .epoch_checkpoint_root
                .as_deref()
                .unwrap_or("0000000000000000000000000000000000000000000000000000000000000000");
            return inner.root == expected_empty;
        }
        let recomputed_spine = rebuild_spine(&inner.leaves);
        let computed = Self::compute_root_from_spine(
            &recomputed_spine,
            inner.leaves.len(),
            inner.epoch_checkpoint_root.as_deref(),
        );
        computed == inner.root
    }
}

/// Backward compatibility alias for the Merkle Audit Tree.
pub type AuditTrail = MerkleAuditTree;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_audit_tree_basic_lifecycle() {
        let tree = MerkleAuditTree::new();
        assert!(tree.verify());
        assert_eq!(tree.entries().len(), 0);

        let root1 = tree.log("TEST_EVENT", serde_json::json!({ "key": "val1" }));
        assert_ne!(root1, "0".repeat(64));
        assert!(tree.verify());
        assert_eq!(tree.entries().len(), 1);

        let root2 = tree.log("TEST_EVENT_2", serde_json::json!({ "key": "val2" }));
        assert_ne!(root2, root1);
        assert!(tree.verify());
        assert_eq!(tree.entries().len(), 2);
    }

    #[test]
    fn test_merkle_audit_tree_memory_compaction() {
        let tree = MerkleAuditTree::new();
        assert!(tree.verify());

        for i in 0..100 {
            tree.log("TEST_EVENT", serde_json::json!({ "index": i }));
        }
        assert_eq!(tree.entries().len(), 100);
        assert!(tree.verify());

        let evicted = tree.compact_memory(40);
        assert_eq!(evicted, 60);
        assert_eq!(tree.entries().len(), 40);
        assert!(tree.verify());

        // Logging new entries post-compaction maintains valid root and verification
        for i in 100..120 {
            tree.log("POST_COMPACT_EVENT", serde_json::json!({ "index": i }));
        }
        assert_eq!(tree.entries().len(), 60);
        assert!(tree.verify());
    }
}
