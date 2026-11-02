//! Integration Test Suite for CAGE Formal BFS Model & Stream Invariant Verifier
//!
//! Validates:
//! 1. Formal 34-state BFS model proving NoDirectBind (34 gated reachable states vs 17 ungated counterexample states).
//! 2. Skipped-tier model visiting exactly 31 reachable states.
//! 3. Cryptographic receipt emission (`prove_no_direct_bind`) with 64-hex lowercase SHA-256 digest.
//! 4. Stream invariant verification across all 5 invariants + digest format:
//!    - `no_direct_bind` (unsealed actuation, double-spend replay, unknown decision binding)
//!    - `cbf_barrier` (barrier depletion breach)
//!    - `seal` (missing seal on ALLOW or NARROW)
//!    - `cbf_rollback` (unledgered debit rollback, budget leakage)
//!    - `refusal_evidence` (missing or non-64-hex lowercase receipt)
//!    - `digest_format` (uppercase or truncated non-64-hex digests)
//!    - Empty stream conformant baseline

use osoosi_policy::cage::{
    BfsPhase, FormalBfsModel, StreamConformanceStatus, StreamInvariantVerifier,
};
use serde_json::json;
use sha2::{Digest, Sha256};

fn compute_test_digest(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

// =========================================================================
// 1. Formal BFS State Model Tests (Feature 7)
// =========================================================================

#[test]
fn test_gated_bfs_model_explores_34_states_and_proves_no_direct_bind() {
    let result = FormalBfsModel::explore_gated_model();

    // Must discover exactly 34 reachable states
    assert_eq!(
        result.reachable_count, 34,
        "Gated BFS model must visit exactly 34 reachable states, got {}",
        result.reachable_count
    );
    assert_eq!(result.visited_states.len(), 34);

    // Exactly 1 terminal execution state
    assert_eq!(
        result.executed_count, 1,
        "Gated model must contain exactly 1 EXECUTED state"
    );

    // Zero NoDirectBind violations
    assert!(
        result.violations.is_empty(),
        "Gated model must have 0 violations, got {:?}",
        result.violations
    );
    assert!(result.no_direct_bind_proven);

    // Verify the single executed state strictly satisfies invariants
    let executed_states = result.executed_states();
    assert_eq!(executed_states.len(), 1);
    let exec = executed_states[0];
    assert_eq!(exec.phase, BfsPhase::Executed);
    assert_eq!(exec.label, "executed");
    assert_eq!(exec.tier, 7);
    assert!(exec.seal_present, "EXECUTED state must have seal_present == true");
    assert!(exec.resolved_allow, "EXECUTED state must have resolved_allow == true");
    assert!(exec.executed_or_narrow);

    // Verify all phases are represented
    assert!(result.visited_states.iter().any(|s| s.phase == BfsPhase::Initial));
    assert!(result.visited_states.iter().any(|s| s.phase == BfsPhase::Checking));
    assert!(result.visited_states.iter().any(|s| s.phase == BfsPhase::NarrowEval));
    assert!(result.visited_states.iter().any(|s| s.phase == BfsPhase::NarrowPassed));
    assert!(result.visited_states.iter().any(|s| s.phase == BfsPhase::SealIssued));
    assert!(result.visited_states.iter().any(|s| s.phase == BfsPhase::Executed));
    assert!(result.visited_states.iter().any(|s| s.phase == BfsPhase::Denied));
}

#[test]
fn test_ungated_counterexample_model_17_states_and_violation() {
    let result = FormalBfsModel::explore_ungated_counterexample();

    // Must reach exactly 17 states (34 vs 17 separation theorem)
    assert_eq!(
        result.reachable_count, 17,
        "Ungated model must explore exactly 17 states, got {}",
        result.reachable_count
    );
    assert_eq!(result.visited_states.len(), 17);

    // Must trigger direct-bind violation counterexample
    assert_eq!(
        result.violations.len(), 1,
        "Ungated model must trigger exactly 1 violation counterexample"
    );
    assert!(
        result.violations[0].error.contains("Direct-bind violation counterexample"),
        "Violation message must flag direct-bind counterexample: {}",
        result.violations[0].error
    );
    assert!(!result.no_direct_bind_proven);

    // Verify state separation
    let gated = FormalBfsModel::explore_gated_model();
    assert_eq!(gated.reachable_count - result.reachable_count, 17);
}

#[test]
fn test_skipped_tier_model_visits_31_states_across_all_tiers() {
    for skip_tier in 0..7 {
        let result = FormalBfsModel::explore_skipped_tier_model(skip_tier);
        assert_eq!(
            result.reachable_count, 31,
            "Skipping tier {} must visit exactly 31 reachable states, got {}",
            skip_tier, result.reachable_count
        );
        assert_eq!(result.visited_states.len(), 31);
        // Execution must be blocked when a required tier is omitted
        assert_eq!(
            result.executed_count, 0,
            "Skipped tier model must block execution (0 executed states)"
        );
        assert!(result.violations.is_empty());
    }
}

#[test]
fn test_prove_no_direct_bind_emits_valid_64_hex_receipt() {
    let proof = FormalBfsModel::prove_no_direct_bind();

    assert!(proof.proven);
    assert_eq!(proof.reachable_states, 34);
    assert_eq!(proof.executed_states, 1);
    assert_eq!(proof.violations_count, 0);

    // Proof receipt must be valid 64-hex lowercase SHA-256
    assert_eq!(proof.proof_receipt.len(), 64);
    assert!(
        StreamInvariantVerifier::is_64_hex_lowercase(&proof.proof_receipt),
        "Proof receipt must be 64 lowercase hex characters: {}",
        proof.proof_receipt
    );

    // Determinism test: second invocation must yield identical cryptographic digest
    let proof2 = FormalBfsModel::prove_no_direct_bind();
    assert_eq!(proof.proof_receipt, proof2.proof_receipt);
}

// =========================================================================
// 2. Stream Invariant Verifier Tests (Feature 8)
// =========================================================================

#[test]
fn test_stream_verifier_conformant_stream() {
    let dec_hash = compute_test_digest(b"decision_1");
    let seal_id = "seal_ok_001";
    let debit_id = "debit_ok_001";
    let ref_hash = compute_test_digest(b"refusal_reason_proof");

    let records = vec![
        json!({
            "event_type": "GOVERNANCE_DECISION",
            "verdict": "ALLOW",
            "seal_present": true,
            "record_hash": dec_hash,
        }),
        json!({
            "event_type": "GOVERNANCE_SEAL_CONSUMED",
            "seal_id": seal_id,
            "decision_record_hash": dec_hash,
            "record_hash": compute_test_digest(b"seal_consume_1"),
        }),
        json!({
            "event_type": "CBF_COMMIT",
            "debit_id": debit_id,
            "state_before": 100.0,
            "cost": 10.0,
            "b_min": 10.0,
            "gamma": 0.5,
            "record_hash": compute_test_digest(b"cbf_commit_1"),
        }),
        json!({
            "event_type": "ACTUATION_RECEIPT",
            "seal_id": seal_id,
            "record_hash": compute_test_digest(b"actuation_receipt_1"),
        }),
        json!({
            "event_type": "CBF_ROLLBACK",
            "debit_id": debit_id,
            "status": "ROLLED_BACK",
            "restored_amount": 10.0,
            "record_hash": compute_test_digest(b"cbf_rollback_1"),
        }),
        json!({
            "event_type": "GOVERNANCE_REFUSAL",
            "proof_hash": ref_hash,
            "record_hash": compute_test_digest(b"refusal_record_1"),
        }),
    ];

    let report = StreamInvariantVerifier::verify_stream(&records);
    assert_eq!(report.records_checked, 6);
    assert_eq!(report.findings_count, 0);
    assert_eq!(report.status, StreamConformanceStatus::Conformant);
    assert!(report.is_conformant());
    assert!(report.findings.is_empty());

    assert_eq!(report.stream_proof_hash.len(), 64);
    assert!(StreamInvariantVerifier::is_64_hex_lowercase(&report.stream_proof_hash));
}

#[test]
fn test_stream_verifier_no_direct_bind_unsealed_actuation() {
    let records = vec![json!({
        "event_type": "ACTUATION_RECEIPT",
        "seal_id": "unconsumed_seal_999",
        "record_hash": compute_test_digest(b"unsealed_actuation"),
    })];

    let report = StreamInvariantVerifier::verify_stream(&records);
    assert!(!report.is_conformant());
    assert_eq!(report.status, StreamConformanceStatus::NonConformant);
    assert!(report.has_rule_violation("no_direct_bind"));
    assert!(report.findings[0].detail.contains("without preceding GOVERNANCE_SEAL_CONSUMED"));
}

#[test]
fn test_stream_verifier_no_direct_bind_seal_replay() {
    let dec_hash = compute_test_digest(b"decision_replay");
    let seal_id = "replay_seal_001";

    let records = vec![
        json!({
            "event_type": "GOVERNANCE_DECISION",
            "verdict": "ALLOW",
            "seal_present": true,
            "record_hash": dec_hash,
        }),
        json!({
            "event_type": "GOVERNANCE_SEAL_CONSUMED",
            "seal_id": seal_id,
            "decision_record_hash": dec_hash,
            "record_hash": compute_test_digest(b"consume_first"),
        }),
        json!({
            "event_type": "GOVERNANCE_SEAL_CONSUMED",
            "seal_id": seal_id,
            "decision_record_hash": dec_hash,
            "record_hash": compute_test_digest(b"consume_replay"),
        }),
    ];

    let report = StreamInvariantVerifier::verify_stream(&records);
    assert!(!report.is_conformant());
    assert!(report.has_rule_violation("no_direct_bind"));
    assert!(report.findings.iter().any(|f| f.detail.contains("replay detected")));
}

#[test]
fn test_stream_verifier_no_direct_bind_unknown_decision_hash() {
    let records = vec![json!({
        "event_type": "GOVERNANCE_SEAL_CONSUMED",
        "seal_id": "seal_orphan",
        "decision_record_hash": compute_test_digest(b"non_existent_decision"),
        "record_hash": compute_test_digest(b"consume_orphan"),
    })];

    let report = StreamInvariantVerifier::verify_stream(&records);
    assert!(!report.is_conformant());
    assert!(report.has_rule_violation("no_direct_bind"));
    assert!(report.findings.iter().any(|f| f.detail.contains("unknown decision hash")));
}

#[test]
fn test_stream_verifier_cbf_barrier_breach() {
    // state_before = 100.0, b_min = 10.0, gamma = 0.5 => h_t = 90.0, min_allowed = 45.0
    // cost = 60.0 => h_next = (100 - 60) - 10 = 30.0 < 45.0 (barrier breach)
    let records = vec![json!({
        "event_type": "CBF_COMMIT",
        "debit_id": "deb_breach_001",
        "state_before": 100.0,
        "cost": 60.0,
        "b_min": 10.0,
        "gamma": 0.5,
        "record_hash": compute_test_digest(b"commit_breach"),
    })];

    let report = StreamInvariantVerifier::verify_stream(&records);
    assert!(!report.is_conformant());
    assert!(report.has_rule_violation("cbf_barrier"));
    assert!(report.findings[0].detail.contains("violates barrier"));
}

#[test]
fn test_stream_verifier_seal_missing_on_allow() {
    let records = vec![json!({
        "event_type": "GOVERNANCE_DECISION",
        "verdict": "ALLOW",
        "seal_present": false,
        "record_hash": compute_test_digest(b"dec_missing_seal"),
    })];

    let report = StreamInvariantVerifier::verify_stream(&records);
    assert!(!report.is_conformant());
    assert!(report.has_rule_violation("seal"));
    assert!(report.findings[0].detail.contains("missing seal_present"));
}

#[test]
fn test_stream_verifier_seal_missing_on_narrow() {
    let records = vec![json!({
        "event_type": "GOVERNANCE_DECISION",
        "verdict": "NARROW",
        "seal_present": false,
        "record_hash": compute_test_digest(b"dec_narrow_missing_seal"),
    })];

    let report = StreamInvariantVerifier::verify_stream(&records);
    assert!(!report.is_conformant());
    assert!(report.has_rule_violation("seal"));
}

#[test]
fn test_stream_verifier_cbf_rollback_budget_leakage() {
    let debit_id = "deb_leakage";
    let records = vec![
        json!({
            "event_type": "CBF_COMMIT",
            "debit_id": debit_id,
            "state_before": 100.0,
            "cost": 25.0,
            "b_min": 10.0,
            "gamma": 0.5,
            "record_hash": compute_test_digest(b"commit_for_leak"),
        }),
        json!({
            "event_type": "CBF_ROLLBACK",
            "debit_id": debit_id,
            "status": "ROLLED_BACK",
            "restored_amount": 20.0, // 5.0 budget leakage
            "record_hash": compute_test_digest(b"rollback_leak"),
        }),
    ];

    let report = StreamInvariantVerifier::verify_stream(&records);
    assert!(!report.is_conformant());
    assert!(report.has_rule_violation("cbf_rollback"));
    assert!(report.findings.iter().any(|f| f.detail.contains("budget leakage")));
}

#[test]
fn test_stream_verifier_cbf_rollback_unledgered_debit() {
    let records = vec![json!({
        "event_type": "CBF_ROLLBACK",
        "debit_id": "ghost_debit_999",
        "status": "ROLLED_BACK",
        "restored_amount": 10.0,
        "record_hash": compute_test_digest(b"ghost_rollback"),
    })];

    let report = StreamInvariantVerifier::verify_stream(&records);
    assert!(!report.is_conformant());
    assert!(report.has_rule_violation("cbf_rollback"));
    assert!(report.findings.iter().any(|f| f.detail.contains("unledgered debit_id")));
}

#[test]
fn test_stream_verifier_refusal_evidence_missing_or_invalid_proof_hash() {
    // Missing proof_hash
    let records1 = vec![json!({
        "event_type": "GOVERNANCE_REFUSAL",
        "record_hash": compute_test_digest(b"ref_no_hash"),
    })];
    let report1 = StreamInvariantVerifier::verify_stream(&records1);
    assert!(!report1.is_conformant());
    assert!(report1.has_rule_violation("refusal_evidence"));

    // Invalid non-64-hex proof_hash
    let records2 = vec![json!({
        "event_type": "GOVERNANCE_REFUSAL",
        "proof_hash": "not_a_valid_hex_string",
        "record_hash": compute_test_digest(b"ref_bad_hash"),
    })];
    let report2 = StreamInvariantVerifier::verify_stream(&records2);
    assert!(!report2.is_conformant());
    assert!(report2.has_rule_violation("refusal_evidence"));
}

#[test]
fn test_stream_verifier_digest_format_uppercase() {
    let uppercase_hash = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855";
    let records = vec![json!({
        "event_type": "GENERIC_TRACE",
        "record_hash": uppercase_hash,
    })];

    let report = StreamInvariantVerifier::verify_stream(&records);
    assert!(!report.is_conformant());
    assert!(report.has_rule_violation("digest_format"));
    assert!(report.findings[0].detail.contains("uppercase or invalid chars"));
}

#[test]
fn test_stream_verifier_digest_format_truncated_63_chars() {
    let truncated_hash = "a".repeat(63);
    let records = vec![json!({
        "event_type": "GENERIC_TRACE",
        "digest": truncated_hash,
    })];

    let report = StreamInvariantVerifier::verify_stream(&records);
    assert!(!report.is_conformant());
    assert!(report.has_rule_violation("digest_format"));
}

#[test]
fn test_stream_verifier_empty_stream() {
    let report = StreamInvariantVerifier::verify_stream(&[]);
    assert_eq!(report.records_checked, 0);
    assert_eq!(report.findings_count, 0);
    assert_eq!(report.status, StreamConformanceStatus::Conformant);
    assert!(report.is_conformant());
    assert!(report.findings.is_empty());
}

#[test]
fn test_stream_verifier_jsonl_str() {
    let dec_hash = compute_test_digest(b"jsonl_dec");
    let jsonl = format!(
        r#"{{"event_type":"GOVERNANCE_DECISION","verdict":"ALLOW","seal_present":true,"record_hash":"{}"}}
{{"event_type":"GOVERNANCE_SEAL_CONSUMED","seal_id":"s1","decision_record_hash":"{}","record_hash":"{}"}}
"#,
        dec_hash,
        dec_hash,
        compute_test_digest(b"jsonl_seal")
    );

    let report = StreamInvariantVerifier::verify_jsonl_str(&jsonl).expect("parse JSONL");
    assert_eq!(report.records_checked, 2);
    assert_eq!(report.findings_count, 0);
    assert!(report.is_conformant());
}
