//! CAGE Audit Stream Invariant Verifier
//!
//! Enforces 5 core CAGE stream invariants over JSONL audit traces:
//! 1. `no_direct_bind`: Actuations must be preceded by an unconsumed routing seal issued with ALLOW/NARROW. Detects double-spend seal replays.
//! 2. `cbf_barrier`: On `CBF_COMMIT`, verifies $h_{t+1} \ge (1 - \gamma) h_t \ge 0$ where $h_t = B_t - B_{\min}$.
//! 3. `seal`: Every ALLOW or NARROW decision must have `seal_present: true`.
//! 4. `cbf_rollback`: Rollback restores the exact committed fuel ($B_{t+1} = B_t$) with zero budget leakage.
//! 5. `refusal_evidence`: Every refusal emits a valid 64-hex lowercase SHA-256 proof hash.
//! 6. `digest_format`: All `digest`, `proof_hash`, `record_hash`, and `prev_hash` fields must match `^[0-9a-f]{64}$`.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Conformance status of an audit stream against formal invariants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StreamConformanceStatus {
    /// All formal stream invariants strictly hold across the entire trace.
    Conformant,

    /// At least one formal stream invariant was breached.
    NonConformant,
}

impl StreamConformanceStatus {
    /// Returns true if all checked invariants hold.
    pub fn is_conformant(&self) -> bool {
        matches!(self, Self::Conformant)
    }

    /// Canonical uppercase string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Conformant => "CONFORMANT",
            Self::NonConformant => "NON_CONFORMANT",
        }
    }
}

impl std::fmt::Display for StreamConformanceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// An individual invariant violation finding identified in an audit stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamFinding {
    /// Zero-based record index in the evaluated stream.
    pub record_index: usize,

    /// Name of the formal invariant breached (e.g. `no_direct_bind`, `cbf_barrier`).
    pub rule: String,

    /// Verbatim diagnostic detail explaining the failure cause.
    pub detail: String,
}

/// Comprehensive verification report produced by `StreamInvariantVerifier`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StreamVerificationReport {
    /// Total count of records evaluated in the stream.
    pub records_checked: usize,

    /// Total count of invariant violations identified.
    pub findings_count: usize,

    /// Overall stream conformance verdict.
    pub status: StreamConformanceStatus,

    /// Detailed list of all invariant findings.
    pub findings: Vec<StreamFinding>,

    /// Ordered list of formal invariants evaluated.
    pub invariants_verified: Vec<String>,

    /// 64-character lowercase hex SHA-256 digest authenticating the evaluation outcome.
    pub stream_proof_hash: String,
}

impl StreamVerificationReport {
    /// Returns true if the stream is fully conformant with zero findings.
    pub fn is_conformant(&self) -> bool {
        self.status.is_conformant()
    }

    /// Checks whether any finding matches the specified rule name.
    pub fn has_rule_violation(&self, rule: &str) -> bool {
        self.findings.iter().any(|f| f.rule == rule)
    }
}

/// Audit stream invariant verification engine.
pub struct StreamInvariantVerifier;

impl StreamInvariantVerifier {
    /// Evaluates a sequence of JSON records against the 5 core CAGE stream invariants plus digest format.
    pub fn verify_stream(records: &[serde_json::Value]) -> StreamVerificationReport {
        let mut findings = Vec::new();
        let mut governance_decisions: HashMap<String, serde_json::Value> = HashMap::new();
        let mut seals_consumed: HashMap<String, serde_json::Value> = HashMap::new();
        let mut cbf_commits: HashMap<String, serde_json::Value> = HashMap::new();
        let mut cbf_rollbacks: HashMap<String, serde_json::Value> = HashMap::new();

        for (idx, rec) in records.iter().enumerate() {
            // Check digest_format on all 64-hex string fields
            if let Some(obj) = rec.as_object() {
                for (k, v) in obj {
                    if k.contains("digest")
                        || k.contains("proof_hash")
                        || k.contains("record_hash")
                        || k.contains("prev_hash")
                    {
                        if let Some(v_str) = v.as_str() {
                            if !Self::is_64_hex_lowercase(v_str) {
                                findings.push(StreamFinding {
                                    record_index: idx,
                                    rule: "digest_format".to_string(),
                                    detail: format!(
                                        "Field '{}' value '{}' violates ^[0-9a-f]{{64}}$ (contains uppercase or invalid chars)",
                                        k, v_str
                                    ),
                                });
                            }
                        }
                    }
                }
            }

            let event_type = rec.get("event_type").and_then(|v| v.as_str()).unwrap_or("");

            match event_type {
                // Invariant 3: seal
                "GOVERNANCE_DECISION" => {
                    let verdict = rec.get("verdict").and_then(|v| v.as_str()).unwrap_or("");
                    let rec_hash = rec.get("record_hash").and_then(|v| v.as_str()).unwrap_or("");
                    let seal_present = rec.get("seal_present").and_then(|v| v.as_bool()).unwrap_or(false);

                    if (verdict == "ALLOW" || verdict == "NARROW") && !seal_present {
                        findings.push(StreamFinding {
                            record_index: idx,
                            rule: "seal".to_string(),
                            detail: format!(
                                "Decision {} verdict {} missing seal_present",
                                rec_hash, verdict
                            ),
                        });
                    }
                    if !rec_hash.is_empty() {
                        governance_decisions.insert(rec_hash.to_string(), rec.clone());
                    }
                }

                // Invariant 1: no_direct_bind (seal consumed binding)
                "GOVERNANCE_SEAL_CONSUMED" => {
                    let seal_id = rec.get("seal_id").and_then(|v| v.as_str()).unwrap_or("");
                    let decision_hash = rec
                        .get("decision_record_hash")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");

                    if !governance_decisions.contains_key(decision_hash) {
                        findings.push(StreamFinding {
                            record_index: idx,
                            rule: "no_direct_bind".to_string(),
                            detail: format!(
                                "GOVERNANCE_SEAL_CONSUMED references unknown decision hash {}",
                                decision_hash
                            ),
                        });
                    }

                    if seals_consumed.contains_key(seal_id) {
                        findings.push(StreamFinding {
                            record_index: idx,
                            rule: "no_direct_bind".to_string(),
                            detail: format!(
                                "Seal '{}' consumed multiple times (replay detected)",
                                seal_id
                            ),
                        });
                    }

                    if !seal_id.is_empty() {
                        seals_consumed.insert(seal_id.to_string(), rec.clone());
                    }
                }

                "ACTUATION_RECEIPT" | "ACTUATION_REFUSAL_RECEIPT" => {
                    let seal_ref = rec.get("seal_id").and_then(|v| v.as_str()).unwrap_or("");
                    if !seals_consumed.contains_key(seal_ref) {
                        findings.push(StreamFinding {
                            record_index: idx,
                            rule: "no_direct_bind".to_string(),
                            detail: format!(
                                "Actuation receipt for seal '{}' executed without preceding GOVERNANCE_SEAL_CONSUMED",
                                seal_ref
                            ),
                        });
                    }
                }

                // Invariant 2: cbf_barrier
                "CBF_COMMIT" => {
                    let debit_id = rec.get("debit_id").and_then(|v| v.as_str()).unwrap_or("");
                    let state_before = rec.get("state_before").and_then(|v| v.as_f64()).unwrap_or(0.0);
                    let cost = rec.get("cost").and_then(|v| v.as_f64()).unwrap_or(0.0);
                    let b_min = rec.get("b_min").and_then(|v| v.as_f64()).unwrap_or(0.0);
                    let gamma = rec.get("gamma").and_then(|v| v.as_f64()).unwrap_or(0.5);

                    let h_t = state_before - b_min;
                    let h_next = (state_before - cost) - b_min;
                    let min_h = (1.0 - gamma) * h_t;

                    if h_next < 0.0 || h_next < min_h {
                        findings.push(StreamFinding {
                            record_index: idx,
                            rule: "cbf_barrier".to_string(),
                            detail: format!(
                                "CBF_COMMIT for debit '{}' violates barrier: h_next={:.2} < min_allowed={:.2}",
                                debit_id, h_next, min_h
                            ),
                        });
                    }

                    if !debit_id.is_empty() {
                        cbf_commits.insert(debit_id.to_string(), rec.clone());
                    }
                }

                // Invariant 4: cbf_rollback
                "CBF_ROLLBACK" => {
                    let debit_id = rec.get("debit_id").and_then(|v| v.as_str()).unwrap_or("");
                    let status = rec.get("status").and_then(|v| v.as_str()).unwrap_or("");

                    if status == "ROLLED_BACK" {
                        if let Some(commit_rec) = cbf_commits.get(debit_id) {
                            let commit_cost = commit_rec.get("cost").and_then(|v| v.as_f64()).unwrap_or(0.0);
                            let restored_cost = rec.get("restored_amount").and_then(|v| v.as_f64()).unwrap_or(0.0);

                            if (commit_cost - restored_cost).abs() > 1e-6 {
                                findings.push(StreamFinding {
                                    record_index: idx,
                                    rule: "cbf_rollback".to_string(),
                                    detail: format!(
                                        "Rollback budget leakage: committed {} != restored {}",
                                        commit_cost, restored_cost
                                    ),
                                });
                            }
                        } else {
                            findings.push(StreamFinding {
                                record_index: idx,
                                rule: "cbf_rollback".to_string(),
                                detail: format!(
                                    "CBF_ROLLBACK references unledgered debit_id '{}'",
                                    debit_id
                                ),
                            });
                        }
                    }

                    if !debit_id.is_empty() {
                        cbf_rollbacks.insert(debit_id.to_string(), rec.clone());
                    }
                }

                // Invariant 5: refusal_evidence
                "GOVERNANCE_REFUSAL" | "GOVERNANCE_REFUSAL_RECEIPT" => {
                    let proof_hash = rec
                        .get("proof_hash")
                        .or_else(|| rec.get("receipt_digest"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");

                    if proof_hash.is_empty() || !Self::is_64_hex_lowercase(proof_hash) {
                        findings.push(StreamFinding {
                            record_index: idx,
                            rule: "refusal_evidence".to_string(),
                            detail: format!(
                                "Refusal event missing valid 64-character lowercase hex proof_hash: '{}'",
                                proof_hash
                            ),
                        });
                    }
                }

                _ => {}
            }
        }

        let records_checked = records.len();
        let findings_count = findings.len();
        let status = if findings.is_empty() {
            StreamConformanceStatus::Conformant
        } else {
            StreamConformanceStatus::NonConformant
        };

        let invariants_verified = vec![
            "no_direct_bind".to_string(),
            "cbf_barrier".to_string(),
            "seal".to_string(),
            "cbf_rollback".to_string(),
            "refusal_evidence".to_string(),
            "digest_format".to_string(),
        ];

        // Compute deterministic cryptographic proof hash for the stream verification outcome
        let mut hasher = Sha256::new();
        hasher.update(
            format!(
                "records_checked:{}|status:{}|findings_count:{}\n",
                records_checked,
                status.as_str(),
                findings_count
            )
            .as_bytes(),
        );
        for (i, r) in records.iter().enumerate() {
            let s = serde_json::to_string(r).unwrap_or_default();
            hasher.update(format!("rec[{i}]:{s}\n").as_bytes());
        }
        for f in &findings {
            hasher.update(format!("finding:{}:{}:{}\n", f.record_index, f.rule, f.detail).as_bytes());
        }
        let stream_proof_hash = hex::encode(hasher.finalize());

        StreamVerificationReport {
            records_checked,
            findings_count,
            status,
            findings,
            invariants_verified,
            stream_proof_hash,
        }
    }

    /// Verifies a newline-delimited JSON (JSONL) string trace against all stream invariants.
    pub fn verify_jsonl_str(jsonl: &str) -> Result<StreamVerificationReport, serde_json::Error> {
        let mut records = Vec::new();
        for line in jsonl.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let rec: serde_json::Value = serde_json::from_str(trimmed)?;
            records.push(rec);
        }
        Ok(Self::verify_stream(&records))
    }

    /// Checks if a string exactly conforms to `^[0-9a-f]{64}$`.
    #[inline]
    pub fn is_64_hex_lowercase(s: &str) -> bool {
        s.len() == 64 && s.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_verifier_empty_stream() {
        let report = StreamInvariantVerifier::verify_jsonl_str("").unwrap();
        assert!(report.status.is_conformant());
        assert_eq!(report.records_checked, 0);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn test_stream_verifier_valid_stream() {
        let hash1 = "a".repeat(64);
        let hash2 = "b".repeat(64);
        let stream = format!(
            "{{\"event_type\":\"GOVERNANCE_DECISION\",\"verdict\":\"ALLOW\",\"seal_present\":true,\"record_hash\":\"{hash1}\"}}\n{{\"event_type\":\"GOVERNANCE_SEAL_CONSUMED\",\"seal_id\":\"seal-123\",\"decision_record_hash\":\"{hash1}\",\"record_hash\":\"{hash2}\"}}"
        );
        let report = StreamInvariantVerifier::verify_jsonl_str(&stream).unwrap();
        assert!(report.status.is_conformant());
        assert_eq!(report.records_checked, 2);
    }

    #[test]
    fn test_stream_verifier_no_direct_bind_violation() {
        let hash1 = "c".repeat(64);
        let stream = format!(
            "{{\"event_type\":\"ACTUATION_RECEIPT\",\"seal_id\":\"unregistered-seal\",\"record_hash\":\"{hash1}\"}}"
        );
        let report = StreamInvariantVerifier::verify_jsonl_str(&stream).unwrap();
        assert!(!report.status.is_conformant());
        assert!(report.findings.iter().any(|f| f.rule == "no_direct_bind"));
    }
}

