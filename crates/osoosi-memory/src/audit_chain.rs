//! Cryptographic Tamper-Evident Audit Chain for OpenỌ̀ṣọ́ọ̀sì.
//!
//! Provides mathematically verifiable, append-only cryptographic provenance for
//! system security events, isolation decisions, threat intelligence detections,
//! and administrative actions (M27).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// An immutable, cryptographically chained audit entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Zero-based monotonically increasing sequence number.
    pub seq_num: u64,
    /// Unix epoch timestamp in seconds.
    pub timestamp: i64,
    /// Classified category of the security event (e.g. "SANDBOX_ESCAPE_ATTEMPT", "REPUTATION_UPDATE").
    pub event_type: String,
    /// The originating entity, agent ID, process name, or subsystem.
    pub actor: String,
    /// JSON-encoded context payload containing threat attributes, parameters, or verdicts.
    pub details_json: String,
    /// SHA-256 hash of the immediate predecessor entry, or genesis hash for seq 0.
    pub prev_hash: String,
    /// Deterministic SHA-256 digest over the canonical serialized representation of this entry.
    pub entry_hash: String,
}

impl AuditEntry {
    /// Deterministically computes the SHA-256 digest for an audit entry.
    pub fn compute_hash(
        seq_num: u64,
        timestamp: i64,
        event_type: &str,
        actor: &str,
        details_json: &str,
        prev_hash: &str,
    ) -> String {
        let payload = format!(
            "{}:{}:{}:{}:{}:{}",
            seq_num, timestamp, event_type, actor, details_json, prev_hash
        );
        let mut hasher = Sha256::new();
        hasher.update(payload.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Validates whether the recorded `entry_hash` exactly matches its recomputed digest.
    pub fn is_self_valid(&self) -> bool {
        let expected = Self::compute_hash(
            self.seq_num,
            self.timestamp,
            &self.event_type,
            &self.actor,
            &self.details_json,
            &self.prev_hash,
        );
        self.entry_hash == expected
    }
}

/// An append-only cryptographic audit chain verifying provenance and temporal ordering.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditChain {
    genesis_seed: String,
    entries: Vec<AuditEntry>,
}

impl AuditChain {
    /// Initializes a new audit chain with an explicit genesis seed string.
    pub fn new(genesis_seed: &str) -> Self {
        Self {
            genesis_seed: genesis_seed.to_string(),
            entries: Vec::new(),
        }
    }

    /// Reconstructs a chain instance from existing entries and a genesis seed.
    pub fn from_entries(genesis_seed: &str, entries: Vec<AuditEntry>) -> Self {
        Self {
            genesis_seed: genesis_seed.to_string(),
            entries,
        }
    }

    /// Computes the deterministic genesis hash linked to sequence 0.
    pub fn genesis_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(format!("GENESIS:{}", self.genesis_seed).as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Appends a new event entry to the audit chain, automatically advancing sequence and linkage.
    pub fn append(&mut self, event_type: &str, actor: &str, details_json: &str) -> AuditEntry {
        let seq_num = self.entries.len() as u64;
        let prev_hash = self
            .entries
            .last()
            .map(|e| e.entry_hash.clone())
            .unwrap_or_else(|| self.genesis_hash());
        let timestamp = chrono::Utc::now().timestamp();
        let entry_hash = AuditEntry::compute_hash(
            seq_num,
            timestamp,
            event_type,
            actor,
            details_json,
            &prev_hash,
        );

        let entry = AuditEntry {
            seq_num,
            timestamp,
            event_type: event_type.to_string(),
            actor: actor.to_string(),
            details_json: details_json.to_string(),
            prev_hash,
            entry_hash,
        };

        self.entries.push(entry.clone());
        entry
    }

    /// Appends a pre-constructed entry after validating its sequence and cryptographic continuity.
    pub fn push_entry(&mut self, entry: AuditEntry) -> Result<(), String> {
        let expected_seq = self.entries.len() as u64;
        if entry.seq_num != expected_seq {
            return Err(format!(
                "Sequence mismatch: expected {}, got {}",
                expected_seq, entry.seq_num
            ));
        }

        let expected_prev = self
            .entries
            .last()
            .map(|e| e.entry_hash.clone())
            .unwrap_or_else(|| self.genesis_hash());

        if entry.prev_hash != expected_prev {
            return Err(format!(
                "Predecessor hash mismatch at seq {}: expected {}, got {}",
                entry.seq_num, expected_prev, entry.prev_hash
            ));
        }

        if !entry.is_self_valid() {
            return Err(format!(
                "Self-hash integrity failure for entry at seq {}",
                entry.seq_num
            ));
        }

        self.entries.push(entry);
        Ok(())
    }

    /// Validates the full cryptographic chain from genesis to head.
    ///
    /// Returns `Ok(())` if the chain is unbroken, or `Err((failed_index, failure_reason))`
    /// if any sequence violation, tampering, or hash mismatch is detected.
    pub fn verify(&self) -> Result<(), (usize, String)> {
        let genesis_h = self.genesis_hash();

        for (i, entry) in self.entries.iter().enumerate() {
            if entry.seq_num != i as u64 {
                return Err((
                    i,
                    format!("Invalid seq_num: expected {}, found {}", i, entry.seq_num),
                ));
            }

            if i == 0 {
                if entry.prev_hash != genesis_h {
                    return Err((
                        0,
                        format!(
                            "Genesis mismatch at seq 0: expected {}, got {}",
                            genesis_h, entry.prev_hash
                        ),
                    ));
                }
            } else {
                let prior = &self.entries[i - 1];
                if entry.prev_hash != prior.entry_hash {
                    return Err((
                        i,
                        format!(
                            "Hash continuity broken at seq {}: prev_hash {} != prior entry_hash {}",
                            i, entry.prev_hash, prior.entry_hash
                        ),
                    ));
                }
            }

            let computed = AuditEntry::compute_hash(
                entry.seq_num,
                entry.timestamp,
                &entry.event_type,
                &entry.actor,
                &entry.details_json,
                &entry.prev_hash,
            );
            if computed != entry.entry_hash {
                return Err((
                    i,
                    format!(
                        "Tampering detected at seq {}: recorded {} != recomputed {}",
                        i, entry.entry_hash, computed
                    ),
                ));
            }
        }

        Ok(())
    }

    /// Returns the total number of entries in the chain.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if the audit chain is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns a slice of all recorded entries.
    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }

    /// Returns the genesis seed used for this chain.
    pub fn genesis_seed(&self) -> &str {
        &self.genesis_seed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_chain_lifecycle_and_verification() {
        let mut chain = AuditChain::new("oshoosiclaw-enterprise-node-01");
        assert!(chain.is_empty());
        assert_eq!(chain.len(), 0);
        assert!(chain.verify().is_ok());

        let e0 = chain.append(
            "SYSTEM_INIT",
            "kernel_sentinel",
            r#"{"status":"bootstrapped"}"#,
        );
        assert_eq!(e0.seq_num, 0);
        assert_eq!(e0.prev_hash, chain.genesis_hash());
        assert!(e0.is_self_valid());

        let e1 = chain.append(
            "CONTAINMENT_ENGAGED",
            "appcontainer_mgr",
            r#"{"pid":4120,"ring":"L4"}"#,
        );
        assert_eq!(e1.seq_num, 1);
        assert_eq!(e1.prev_hash, e0.entry_hash);

        let e2 = chain.append(
            "THREAT_QUARANTINED",
            "clef_decider",
            r#"{"threat_id":"T-9981","verdict":"malicious"}"#,
        );
        assert_eq!(e2.seq_num, 2);
        assert_eq!(e2.prev_hash, e1.entry_hash);

        assert_eq!(chain.len(), 3);
        assert!(chain.verify().is_ok());
    }

    #[test]
    fn test_audit_chain_tamper_detection_in_payload() {
        let mut chain = AuditChain::new("test-tamper-detection");
        chain.append("EVENT_A", "agent_1", r#"{"data":1}"#);
        chain.append("EVENT_B", "agent_2", r#"{"data":2}"#);
        chain.append("EVENT_C", "agent_3", r#"{"data":3}"#);

        assert!(chain.verify().is_ok());

        // Tamper with payload of entry 1
        chain.entries[1].details_json = r#"{"data":9999}"#.to_string();
        let res = chain.verify();
        assert!(res.is_err());
        let (failed_idx, msg) = res.unwrap_err();
        assert_eq!(failed_idx, 1);
        assert!(msg.contains("Tampering detected at seq 1"));
    }

    #[test]
    fn test_audit_chain_tamper_detection_in_linkage() {
        let mut chain = AuditChain::new("test-linkage-detection");
        chain.append("EVENT_A", "agent_1", r#"{"data":1}"#);
        chain.append("EVENT_B", "agent_2", r#"{"data":2}"#);
        chain.append("EVENT_C", "agent_3", r#"{"data":3}"#);

        // Break linkage at entry 2
        chain.entries[2].prev_hash = "deadbeef000000000000000000000000".to_string();
        let res = chain.verify();
        assert!(res.is_err());
        let (failed_idx, msg) = res.unwrap_err();
        assert_eq!(failed_idx, 2);
        assert!(msg.contains("Hash continuity broken at seq 2"));
    }

    #[test]
    fn test_push_entry_validation() {
        let mut chain = AuditChain::new("test-push-entry");
        let gen_h = chain.genesis_hash();
        let t = 1700000000;
        let h0 = AuditEntry::compute_hash(0, t, "START", "admin", "{}", &gen_h);
        let entry0 = AuditEntry {
            seq_num: 0,
            timestamp: t,
            event_type: "START".to_string(),
            actor: "admin".to_string(),
            details_json: "{}".to_string(),
            prev_hash: gen_h,
            entry_hash: h0,
        };

        assert!(chain.push_entry(entry0.clone()).is_ok());

        // Attempting to push with wrong seq_num
        let mut bad_seq = entry0.clone();
        bad_seq.seq_num = 5;
        assert!(chain.push_entry(bad_seq).is_err());
    }
}
