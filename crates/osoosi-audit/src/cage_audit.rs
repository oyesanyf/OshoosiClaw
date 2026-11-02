//! CAGE Governance Audit & Trace Hash Chaining
//!
//! Provides data structures and cryptographic verification for `cage-audit/3.0`
//! and `GOVERNANCE_TRACE` records anchored into `MerkleAuditTree`.

use crate::canonical_json::{canonicalize_jcs, compute_canonical_hash, JcsError};
use serde::{Deserialize, Serialize};

/// Canonical specification schema identifier for CAGE governance audit streams.
pub const AUDIT_SCHEMA_VERSION: &str = "cage-audit/3.0";

/// Genesis block prev_hash constant (64 zeroes).
pub const GENESIS_PREV_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Event types conforming to `cage-audit/3.0`.
pub const EVENT_GOVERNANCE_DECISION: &str = "GOVERNANCE_DECISION";
pub const EVENT_GOVERNANCE_SEAL_CONSUMED: &str = "GOVERNANCE_SEAL_CONSUMED";
pub const EVENT_CBF_COMMIT: &str = "CBF_COMMIT";
pub const EVENT_CBF_ROLLBACK: &str = "CBF_ROLLBACK";
pub const EVENT_GOVERNANCE_REFUSAL: &str = "GOVERNANCE_REFUSAL";
pub const EVENT_ACTUATION_RECEIPT: &str = "ACTUATION_RECEIPT";

/// A cryptographically chained governance trace record conforming to `cage-audit/3.0`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CageTraceRecord {
    /// Unique identifier for this trace event.
    pub trace_id: String,

    /// Monotonically increasing 0-based sequence number in the governance trace stream.
    pub sequence_number: u64,

    /// 64-character lowercase hex SHA-256 digest of the previous record's leaf hash.
    /// Genesis record (sequence_number == 0) strictly binds to `0000...0000`.
    pub prev_hash: String,

    /// Name of the actuated or evaluated capability / action.
    pub action_name: String,

    /// Canonical governance verdict string (e.g. ALLOW, NARROW, REQUIRE_APPROVAL, DEFER, DENY).
    pub verdict: String,

    /// Evaluated Control Barrier Function barrier value $h(x)$, if applicable.
    pub cbf_h_value: Option<f64>,

    /// Fiscal fuel / budget units consumed or pre-reserved by this action, if applicable.
    pub fuel_consumed: Option<f64>,

    /// Active deterministic 16-character hex policy version ID.
    pub policy_version_id: String,

    /// 64-character lowercase hex SHA-256 digest of this record's canonical payload.
    pub merkle_leaf_hash: String,

    /// 64-character lowercase hex SHA-256 Merkle root at the time this record was anchored.
    pub merkle_root: String,

    /// Arbitrary structured event payload or parameter bag.
    pub payload: serde_json::Value,

    /// ISO-8601 UTC timestamp of record creation.
    pub timestamp_utc: String,
}

impl CageTraceRecord {
    /// Create a new `CageTraceRecord`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        trace_id: impl Into<String>,
        sequence_number: u64,
        prev_hash: impl Into<String>,
        action_name: impl Into<String>,
        verdict: impl Into<String>,
        cbf_h_value: Option<f64>,
        fuel_consumed: Option<f64>,
        policy_version_id: impl Into<String>,
        merkle_leaf_hash: impl Into<String>,
        merkle_root: impl Into<String>,
        payload: serde_json::Value,
        timestamp_utc: impl Into<String>,
    ) -> Self {
        Self {
            trace_id: trace_id.into(),
            sequence_number,
            prev_hash: prev_hash.into(),
            action_name: action_name.into(),
            verdict: verdict.into(),
            cbf_h_value,
            fuel_consumed,
            policy_version_id: policy_version_id.into(),
            merkle_leaf_hash: merkle_leaf_hash.into(),
            merkle_root: merkle_root.into(),
            payload,
            timestamp_utc: timestamp_utc.into(),
        }
    }

    /// Convert this record to its canonical RFC 8785 JSON representation.
    pub fn to_canonical_json(&self) -> Result<String, JcsError> {
        let val = serde_json::to_value(self).map_err(|e| JcsError::Serialization(e.to_string()))?;
        canonicalize_jcs(&val)
    }

    /// Compute the deterministic 64-hex SHA-256 canonical hash of the trace's inner content
    /// (excluding Merkle root and leaf hash to avoid circular dependency).
    pub fn compute_canonical_leaf_hash(&self) -> String {
        let v = serde_json::json!({
            "trace_id": self.trace_id,
            "sequence_number": self.sequence_number,
            "prev_hash": self.prev_hash,
            "action_name": self.action_name,
            "verdict": self.verdict,
            "cbf_h_value": self.cbf_h_value,
            "fuel_consumed": self.fuel_consumed,
            "policy_version_id": self.policy_version_id,
            "payload": self.payload,
            "timestamp_utc": self.timestamp_utc,
        });
        compute_canonical_hash(&v)
    }

    /// Compute the overall record hash across the entire canonical record.
    pub fn compute_record_hash(&self) -> String {
        let val = serde_json::to_value(self).unwrap_or_default();
        compute_canonical_hash(&val)
    }
}

/// Verifies a sequential chain of `CageTraceRecord` instances.
///
/// Asserts:
/// 1. Sequence numbers are strictly contiguous starting at 0: 0, 1, 2, ...
/// 2. Genesis record (index 0) has `prev_hash` equal to `0000...0000`.
/// 3. Every subsequent record has `prev_hash` equal to the preceding record's `merkle_leaf_hash`.
/// 4. Every record's `merkle_leaf_hash` matches its recomputed canonical payload digest.
pub fn verify_trace_chain(records: &[CageTraceRecord]) -> Result<bool, String> {
    if records.is_empty() {
        return Ok(true);
    }

    let mut expected_prev = GENESIS_PREV_HASH.to_string();

    for (i, rec) in records.iter().enumerate() {
        if rec.sequence_number != i as u64 {
            return Err(format!(
                "Sequence discontinuity at index {}: expected {}, got {}",
                i, i, rec.sequence_number
            ));
        }

        if rec.prev_hash != expected_prev {
            return Err(format!(
                "Chain break at sequence {}: expected prev_hash {}, got {}",
                rec.sequence_number, expected_prev, rec.prev_hash
            ));
        }

        let expected_leaf = rec.compute_canonical_leaf_hash();
        if rec.merkle_leaf_hash != expected_leaf {
            return Err(format!(
                "Tampered leaf hash at sequence {}: expected {}, got {}",
                rec.sequence_number, expected_leaf, rec.merkle_leaf_hash
            ));
        }

        expected_prev = rec.merkle_leaf_hash.clone();
    }

    Ok(true)
}
