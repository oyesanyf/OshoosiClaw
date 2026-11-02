//! crates/osoosi-policy/tests/cage_stream_adversarial_tests.rs
//!
//! Milestone 3 Adversarial Empirical Verification Suite:
//! Formal Stream Invariant Verifier (`crates/osoosi-policy/src/cage/stream_verifier.rs`)
//!
//! Author: teamwork_challenger (Challenger 2, Milestone 3)
//!
//! Empirical challenges & attack vectors:
//! 1. Multi-vector audit stream corruption:
//!    - Parallel thread seal replay attacks: Concurrent double-spend attempts on identical routing seals.
//!    - Phantom executions: Actuation receipts without preceding consumption, unledgered decision hashes, unsealed decisions.
//!    - CBF barrier violations: Decaying below $(1-\gamma)h_t$, negative floor breaches ($h_{t+1} < 0$), epsilon boundary breaches.
//!    - Budget leakage under rollback: Over-restoration ($B_t + 0.0001$), under-restoration ($B_t - 0.0001$), unledgered debits.
//!    - Refusal hash tampering & digest format: Non-hex, uppercase hex, 63-char truncated, 65-char extended, empty hashes.
//! 2. High-volume stream stress (10,000 mixed events):
//!    - 5,000 conformant events interleaved with 5,000 adversarial injection events.
//!    - Linear time complexity, zero panics, zero memory leaks, and deterministic verification receipts.
//! 3. Concurrent verification stress & JSONL stream parsing robustness.

use osoosi_policy::cage::{StreamConformanceStatus, StreamInvariantVerifier};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

// =========================================================================
// 1. Multi-Vector Stream Corruption: Replay Attacks Across Parallel Threads
// =========================================================================

#[test]
fn test_adversarial_stream_parallel_seal_replay_attack() {
    let decision_hash = sha256_hex("decision_payload_for_parallel_replay_001");
    let target_seal_id = "seal_adv_parallel_replay_target_001";

    let mut stream = vec![json!({
        "event_type": "GOVERNANCE_DECISION",
        "record_hash": decision_hash,
        "verdict": "ALLOW",
        "seal_present": true,
    })];

    // Spawn 16 parallel threads each attempting to consume the SAME routing seal
    let thread_count = 16;
    let barrier = Arc::new(std::sync::Barrier::new(thread_count));
    let collected_records = Arc::new(Mutex::new(Vec::new()));
    let mut handles = Vec::new();

    for t in 0..thread_count {
        let b = Arc::clone(&barrier);
        let records = Arc::clone(&collected_records);
        let d_hash = decision_hash.clone();
        handles.push(thread::spawn(move || {
            b.wait();
            let rec = json!({
                "event_type": "GOVERNANCE_SEAL_CONSUMED",
                "seal_id": target_seal_id,
                "decision_record_hash": d_hash,
                "thread_worker_id": t,
            });
            let mut guard = records.lock().unwrap();
            guard.push(rec);
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    let records = collected_records.lock().unwrap().clone();
    assert_eq!(records.len(), thread_count);
    stream.extend(records);

    let report = StreamInvariantVerifier::verify_stream(&stream);
    assert_eq!(report.status, StreamConformanceStatus::NonConformant);
    assert!(!report.is_conformant());
    assert!(report.has_rule_violation("no_direct_bind"));

    let replay_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|f| {
            f.rule == "no_direct_bind"
                && f.detail.contains(&format!(
                    "Seal '{}' consumed multiple times (replay detected)",
                    target_seal_id
                ))
        })
        .collect();

    assert_eq!(
        replay_findings.len(),
        thread_count - 1,
        "Expected exactly {} replay findings for {} parallel attempts on identical seal, got {}",
        thread_count - 1,
        thread_count,
        replay_findings.len()
    );
}

#[test]
fn test_adversarial_stream_multi_seal_cross_thread_contention() {
    let distinct_seals = 8;
    let attempts_per_seal = 4;
    let mut stream = Vec::new();

    // Generate valid decision records for each seal
    for s in 0..distinct_seals {
        let decision_hash = sha256_hex(&format!("decision_payload_for_contention_{s}"));
        stream.push(json!({
            "event_type": "GOVERNANCE_DECISION",
            "record_hash": decision_hash,
            "verdict": "NARROW",
            "seal_present": true,
        }));
    }

    // Concurrently fire consume requests across 32 threads (8 seals x 4 attempts)
    let total_attempts = distinct_seals * attempts_per_seal;
    let barrier = Arc::new(std::sync::Barrier::new(total_attempts));
    let collected_consumes = Arc::new(Mutex::new(Vec::new()));
    let mut handles = Vec::new();

    for s in 0..distinct_seals {
        let seal_id = format!("seal_contention_{s}");
        let decision_hash = sha256_hex(&format!("decision_payload_for_contention_{s}"));

        for attempt in 0..attempts_per_seal {
            let b = Arc::clone(&barrier);
            let out = Arc::clone(&collected_consumes);
            let s_id = seal_id.clone();
            let d_hash = decision_hash.clone();

            handles.push(thread::spawn(move || {
                b.wait();
                let rec = json!({
                    "event_type": "GOVERNANCE_SEAL_CONSUMED",
                    "seal_id": s_id,
                    "decision_record_hash": d_hash,
                    "attempt": attempt,
                });
                let mut guard = out.lock().unwrap();
                guard.push(rec);
            }));
        }
    }

    for h in handles {
        h.join().unwrap();
    }

    let consumes = collected_consumes.lock().unwrap().clone();
    assert_eq!(consumes.len(), total_attempts);
    stream.extend(consumes);

    let report = StreamInvariantVerifier::verify_stream(&stream);
    assert!(!report.is_conformant());
    assert!(report.has_rule_violation("no_direct_bind"));

    let total_replays: usize = report
        .findings
        .iter()
        .filter(|f| f.rule == "no_direct_bind" && f.detail.contains("replay detected"))
        .count();

    let expected_replays = distinct_seals * (attempts_per_seal - 1);
    assert_eq!(
        total_replays, expected_replays,
        "Expected exactly {} replay findings across {} seals, got {}",
        expected_replays, distinct_seals, total_replays
    );
}

// =========================================================================
// 2. Multi-Vector Stream Corruption: Phantom Executions & Decision Invariants
// =========================================================================

#[test]
fn test_adversarial_stream_phantom_actuation_unregistered_seal() {
    let unconsumed_seal_id = "seal_phantom_unregistered_999";

    let stream = vec![json!({
        "event_type": "ACTUATION_RECEIPT",
        "seal_id": unconsumed_seal_id,
        "action": "ExecuteSystemCommand",
        "status": "EXECUTED",
    })];

    let report = StreamInvariantVerifier::verify_stream(&stream);
    assert_eq!(report.status, StreamConformanceStatus::NonConformant);
    assert!(report.has_rule_violation("no_direct_bind"));

    let finding = report
        .findings
        .iter()
        .find(|f| f.rule == "no_direct_bind")
        .expect("Must have no_direct_bind violation");

    assert!(
        finding.detail.contains(&format!(
            "Actuation receipt for seal '{}' executed without preceding GOVERNANCE_SEAL_CONSUMED",
            unconsumed_seal_id
        )),
        "Detail mismatch: {}",
        finding.detail
    );
}

#[test]
fn test_adversarial_stream_phantom_actuation_refusal_receipt_unregistered_seal() {
    let unconsumed_seal_id = "seal_phantom_refusal_888";

    let stream = vec![json!({
        "event_type": "ACTUATION_REFUSAL_RECEIPT",
        "seal_id": unconsumed_seal_id,
        "reason": "Host capability blocked execution",
    })];

    let report = StreamInvariantVerifier::verify_stream(&stream);
    assert!(report.has_rule_violation("no_direct_bind"));

    let finding = report
        .findings
        .iter()
        .find(|f| f.rule == "no_direct_bind")
        .expect("Must flag no_direct_bind for refusal receipt");

    assert!(finding.detail.contains(unconsumed_seal_id));
}

#[test]
fn test_adversarial_stream_seal_consumed_unknown_decision_hash() {
    let ghost_decision_hash = sha256_hex("ghost_decision_never_recorded");
    let seal_id = "seal_orphan_consume_777";

    let stream = vec![json!({
        "event_type": "GOVERNANCE_SEAL_CONSUMED",
        "seal_id": seal_id,
        "decision_record_hash": ghost_decision_hash,
    })];

    let report = StreamInvariantVerifier::verify_stream(&stream);
    assert!(report.has_rule_violation("no_direct_bind"));

    let finding = report
        .findings
        .iter()
        .find(|f| f.rule == "no_direct_bind")
        .expect("Must detect unknown decision hash");

    assert!(
        finding.detail.contains(&format!(
            "references unknown decision hash {}",
            ghost_decision_hash
        )),
        "Expected unknown decision hash detail, got: {}",
        finding.detail
    );
}

#[test]
fn test_adversarial_stream_unsealed_allow_and_narrow_decisions() {
    let allow_hash = sha256_hex("allow_decision_missing_seal");
    let narrow_hash = sha256_hex("narrow_decision_missing_seal");
    let deny_hash = sha256_hex("deny_decision_properly_unsealed");

    let stream = vec![
        // Violation 1: ALLOW without seal_present
        json!({
            "event_type": "GOVERNANCE_DECISION",
            "record_hash": allow_hash,
            "verdict": "ALLOW",
            "seal_present": false,
        }),
        // Violation 2: NARROW without seal_present
        json!({
            "event_type": "GOVERNANCE_DECISION",
            "record_hash": narrow_hash,
            "verdict": "NARROW",
            "seal_present": false,
        }),
        // Negative control: DENY does NOT require seal_present
        json!({
            "event_type": "GOVERNANCE_DECISION",
            "record_hash": deny_hash,
            "verdict": "DENY",
            "seal_present": false,
        }),
    ];

    let report = StreamInvariantVerifier::verify_stream(&stream);
    assert!(!report.is_conformant());
    assert!(report.has_rule_violation("seal"));

    let seal_violations: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.rule == "seal")
        .collect();
    assert_eq!(
        seal_violations.len(),
        2,
        "ALLOW and NARROW must each flag missing seal_present; DENY must not"
    );
}

// =========================================================================
// 3. Multi-Vector Stream Corruption: CBF Barrier Violations
// =========================================================================

#[test]
fn test_adversarial_stream_cbf_barrier_decay_violation() {
    // Parameter values: state_before = 100, b_min = 20, gamma = 0.4
    // h_t = 100 - 20 = 80
    // min_allowed = (1 - 0.4) * 80 = 48.0
    // Cost = 35 -> state_after = 65 -> h_next = 65 - 20 = 45.0 < 48.0 (decay breach!)
    let debit_id = "debit_barrier_decay_breach_001";

    let stream = vec![json!({
        "event_type": "CBF_COMMIT",
        "debit_id": debit_id,
        "state_before": 100.0,
        "cost": 35.0,
        "b_min": 20.0,
        "gamma": 0.4,
    })];

    let report = StreamInvariantVerifier::verify_stream(&stream);
    assert_eq!(report.status, StreamConformanceStatus::NonConformant);
    assert!(report.has_rule_violation("cbf_barrier"));

    let finding = report
        .findings
        .iter()
        .find(|f| f.rule == "cbf_barrier")
        .expect("Must have cbf_barrier finding");

    assert!(
        finding.detail.contains("h_next=45.00 < min_allowed=48.00"),
        "Detail mismatch: {}",
        finding.detail
    );
}

#[test]
fn test_adversarial_stream_cbf_barrier_floor_breach() {
    // Parameter values: state_before = 25, b_min = 20, gamma = 0.9
    // h_t = 5, min_allowed = 0.5
    // Cost = 10 -> state_after = 15 -> h_next = 15 - 20 = -5.0 < 0.0 (non-negativity breach!)
    let debit_id = "debit_barrier_floor_breach_002";

    let stream = vec![json!({
        "event_type": "CBF_COMMIT",
        "debit_id": debit_id,
        "state_before": 25.0,
        "cost": 10.0,
        "b_min": 20.0,
        "gamma": 0.9,
    })];

    let report = StreamInvariantVerifier::verify_stream(&stream);
    assert!(report.has_rule_violation("cbf_barrier"));

    let finding = report
        .findings
        .iter()
        .find(|f| f.rule == "cbf_barrier")
        .expect("Must have cbf_barrier finding");

    assert!(
        finding.detail.contains("h_next=-5.00"),
        "Detail mismatch: {}",
        finding.detail
    );
}

#[test]
fn test_adversarial_stream_cbf_barrier_boundary_epsilon_precision() {
    // state_before = 100.0, b_min = 10.0, gamma = 0.5
    // h_t = 90.0, min_allowed = 45.0
    // Exact cost to hit boundary: cost = 45.0 -> h_next = 45.0 (conformant)
    // Cost slightly above: cost = 45.0001 -> h_next = 44.9999 < 45.0 (non-conformant)
    let conformant_stream = vec![json!({
        "event_type": "CBF_COMMIT",
        "debit_id": "debit_boundary_exact",
        "state_before": 100.0,
        "cost": 45.0,
        "b_min": 10.0,
        "gamma": 0.5,
    })];

    let rep_ok = StreamInvariantVerifier::verify_stream(&conformant_stream);
    assert!(
        !rep_ok.has_rule_violation("cbf_barrier"),
        "Exact boundary cost must be conformant"
    );

    let breach_stream = vec![json!({
        "event_type": "CBF_COMMIT",
        "debit_id": "debit_boundary_breach_epsilon",
        "state_before": 100.0,
        "cost": 45.0001,
        "b_min": 10.0,
        "gamma": 0.5,
    })];

    let rep_breach = StreamInvariantVerifier::verify_stream(&breach_stream);
    assert!(
        rep_breach.has_rule_violation("cbf_barrier"),
        "Epsilon overshoot (45.0001) must trigger cbf_barrier finding"
    );
}

// =========================================================================
// 4. Multi-Vector Stream Corruption: Fiscal Budget Leakage Under Rollback
// =========================================================================

#[test]
fn test_adversarial_stream_cbf_rollback_over_restoration_leakage() {
    let debit_id = "debit_leak_over_001";
    let committed_cost = 50.0;
    let leaked_restore = committed_cost + 0.0001; // Restoring B_t + 0.0001

    let stream = vec![
        json!({
            "event_type": "CBF_COMMIT",
            "debit_id": debit_id,
            "state_before": 100.0,
            "cost": committed_cost,
            "b_min": 10.0,
            "gamma": 0.5,
        }),
        json!({
            "event_type": "CBF_ROLLBACK",
            "debit_id": debit_id,
            "status": "ROLLED_BACK",
            "restored_amount": leaked_restore,
        }),
    ];

    let report = StreamInvariantVerifier::verify_stream(&stream);
    assert_eq!(report.status, StreamConformanceStatus::NonConformant);
    assert!(report.has_rule_violation("cbf_rollback"));

    let finding = report
        .findings
        .iter()
        .find(|f| f.rule == "cbf_rollback")
        .expect("Must have cbf_rollback violation");

    assert!(
        finding.detail.contains("committed 50 != restored 50.0001"),
        "Detail mismatch: {}",
        finding.detail
    );
}

#[test]
fn test_adversarial_stream_cbf_rollback_under_restoration_leakage() {
    let debit_id = "debit_leak_under_002";
    let committed_cost = 50.0;
    let leaked_restore = committed_cost - 0.0001; // Restoring B_t - 0.0001

    let stream = vec![
        json!({
            "event_type": "CBF_COMMIT",
            "debit_id": debit_id,
            "state_before": 100.0,
            "cost": committed_cost,
            "b_min": 10.0,
            "gamma": 0.5,
        }),
        json!({
            "event_type": "CBF_ROLLBACK",
            "debit_id": debit_id,
            "status": "ROLLED_BACK",
            "restored_amount": leaked_restore,
        }),
    ];

    let report = StreamInvariantVerifier::verify_stream(&stream);
    assert!(report.has_rule_violation("cbf_rollback"));

    let finding = report
        .findings
        .iter()
        .find(|f| f.rule == "cbf_rollback")
        .expect("Must have cbf_rollback violation");

    assert!(
        finding.detail.contains("committed 50 != restored 49.9999"),
        "Detail mismatch: {}",
        finding.detail
    );
}

#[test]
fn test_adversarial_stream_cbf_rollback_unledgered_debit_id() {
    let ghost_debit = "debit_unledgered_phantom_777";

    let stream = vec![json!({
        "event_type": "CBF_ROLLBACK",
        "debit_id": ghost_debit,
        "status": "ROLLED_BACK",
        "restored_amount": 25.0,
    })];

    let report = StreamInvariantVerifier::verify_stream(&stream);
    assert!(report.has_rule_violation("cbf_rollback"));

    let finding = report
        .findings
        .iter()
        .find(|f| f.rule == "cbf_rollback")
        .expect("Must flag unledgered rollback");

    assert!(
        finding
            .detail
            .contains(&format!("references unledgered debit_id '{}'", ghost_debit)),
        "Detail mismatch: {}",
        finding.detail
    );
}

#[test]
fn test_adversarial_stream_cbf_rollback_exact_restoration_conformant() {
    let debit_id = "debit_conformant_rollback_003";
    let cost = 42.5;

    let stream = vec![
        json!({
            "event_type": "CBF_COMMIT",
            "debit_id": debit_id,
            "state_before": 100.0,
            "cost": cost,
            "b_min": 10.0,
            "gamma": 0.5,
        }),
        json!({
            "event_type": "CBF_ROLLBACK",
            "debit_id": debit_id,
            "status": "ROLLED_BACK",
            "restored_amount": cost,
        }),
    ];

    let report = StreamInvariantVerifier::verify_stream(&stream);
    assert!(
        !report.has_rule_violation("cbf_rollback"),
        "Exact fuel restoration must have zero cbf_rollback findings"
    );
}

// =========================================================================
// 5. Multi-Vector Stream Corruption: Refusal Evidence & Digest Formatting
// =========================================================================

#[test]
fn test_adversarial_stream_refusal_proof_hash_tampering() {
    let valid_hash = sha256_hex("valid_refusal_receipt_001");

    // Case 1: Non-hex characters
    let non_hex_hash = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
    let stream_non_hex = vec![json!({
        "event_type": "GOVERNANCE_REFUSAL",
        "proof_hash": non_hex_hash,
        "reason": "FTRA threshold exceeded",
    })];
    let rep_non_hex = StreamInvariantVerifier::verify_stream(&stream_non_hex);
    assert!(
        rep_non_hex.has_rule_violation("refusal_evidence")
            || rep_non_hex.has_rule_violation("digest_format"),
        "Non-hex hash must trigger refusal_evidence or digest_format"
    );

    // Case 2: Uppercase hex characters
    let uppercase_hash = valid_hash.to_uppercase();
    let stream_upper = vec![json!({
        "event_type": "GOVERNANCE_REFUSAL",
        "proof_hash": uppercase_hash,
        "reason": "STPA hazard H-01 detected",
    })];
    let rep_upper = StreamInvariantVerifier::verify_stream(&stream_upper);
    assert!(
        rep_upper.has_rule_violation("refusal_evidence"),
        "Uppercase hex must violate lowercase refusal_evidence"
    );
    assert!(
        rep_upper.has_rule_violation("digest_format"),
        "Uppercase hex must violate digest_format ^[0-9a-f]{{64}}$"
    );

    // Case 3: Truncated 63-character hash
    let truncated_hash = &valid_hash[..63];
    let stream_trunc = vec![json!({
        "event_type": "GOVERNANCE_REFUSAL",
        "proof_hash": truncated_hash,
        "reason": "CBF barrier decay check failed",
    })];
    let rep_trunc = StreamInvariantVerifier::verify_stream(&stream_trunc);
    assert!(
        rep_trunc.has_rule_violation("refusal_evidence"),
        "Truncated 63-char hash must violate refusal_evidence"
    );
    assert!(
        rep_trunc.has_rule_violation("digest_format"),
        "Truncated 63-char hash must violate digest_format"
    );

    // Case 4: Extended 65-character hash
    let extended_hash = format!("{valid_hash}a");
    let stream_ext = vec![json!({
        "event_type": "GOVERNANCE_REFUSAL",
        "proof_hash": extended_hash,
        "reason": "Consensus veto applied",
    })];
    let rep_ext = StreamInvariantVerifier::verify_stream(&stream_ext);
    assert!(
        rep_ext.has_rule_violation("refusal_evidence")
            && rep_ext.has_rule_violation("digest_format")
    );

    // Case 5: Empty proof hash
    let stream_empty = vec![json!({
        "event_type": "GOVERNANCE_REFUSAL",
        "proof_hash": "",
        "reason": "Cedar forbid rule triggered",
    })];
    let rep_empty = StreamInvariantVerifier::verify_stream(&stream_empty);
    assert!(
        rep_empty.has_rule_violation("refusal_evidence"),
        "Empty proof hash must violate refusal_evidence"
    );

    // Case 6: Fully conformant refusal record
    let stream_ok = vec![json!({
        "event_type": "GOVERNANCE_REFUSAL",
        "proof_hash": valid_hash,
        "reason": "Legitimate denial with cryptographic proof",
    })];
    let rep_ok = StreamInvariantVerifier::verify_stream(&stream_ok);
    assert!(
        !rep_ok.has_rule_violation("refusal_evidence")
            && !rep_ok.has_rule_violation("digest_format"),
        "Conformant refusal must produce zero refusal/digest findings"
    );
}

#[test]
fn test_adversarial_stream_digest_format_on_arbitrary_metadata_fields() {
    let stream = vec![
        json!({
            "event_type": "AUDIT_RECORD",
            "record_hash": "invalid_non_64_record_hash",
        }),
        json!({
            "event_type": "AUDIT_RECORD",
            "prev_hash": "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
        }),
        json!({
            "event_type": "AUDIT_RECORD",
            "receipt_digest": "too_short_digest",
        }),
    ];

    let report = StreamInvariantVerifier::verify_stream(&stream);
    assert!(report.has_rule_violation("digest_format"));

    let digest_violations: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.rule == "digest_format")
        .collect();

    assert_eq!(
        digest_violations.len(),
        3,
        "All three malformed hash fields must be flagged by digest_format"
    );
}

// =========================================================================
// 6. High-Volume Stream Stress: 10,000 Mixed Events
// =========================================================================

#[test]
fn test_adversarial_stream_high_volume_10k_mixed_events() {
    println!("\n=== High-Volume Stream Stress: Generating 10,000 Mixed Events ===");

    let mut stream: Vec<serde_json::Value> = Vec::with_capacity(10_000);

    // 5,000 Conformant Events
    // ----------------------
    // 1,000 decisions (ALLOW + seal_present + valid 64-hex record_hash)
    for i in 0..1000 {
        let dec_hash = sha256_hex(&format!("valid_decision_event_{i}"));
        stream.push(json!({
            "event_type": "GOVERNANCE_DECISION",
            "record_hash": dec_hash,
            "verdict": "ALLOW",
            "seal_present": true,
        }));
    }

    // 1,000 seal consumptions (matching decision hashes, unique seal IDs)
    for i in 0..1000 {
        let dec_hash = sha256_hex(&format!("valid_decision_event_{i}"));
        let seal_id = format!("valid_seal_id_{i:04}");
        stream.push(json!({
            "event_type": "GOVERNANCE_SEAL_CONSUMED",
            "seal_id": seal_id,
            "decision_record_hash": dec_hash,
        }));
    }

    // 1,000 actuation receipts (referencing consumed seals)
    for i in 0..1000 {
        let seal_id = format!("valid_seal_id_{i:04}");
        stream.push(json!({
            "event_type": "ACTUATION_RECEIPT",
            "seal_id": seal_id,
            "status": "EXECUTED",
        }));
    }

    // 1,000 CBF commits (satisfying h_next >= (1-gamma)*h_t >= 0)
    for i in 0..1000 {
        let debit_id = format!("valid_debit_commit_{i:04}");
        stream.push(json!({
            "event_type": "CBF_COMMIT",
            "debit_id": debit_id,
            "state_before": 200.0,
            "cost": 20.0,
            "b_min": 10.0,
            "gamma": 0.5,
        }));
    }

    // 500 CBF rollbacks (exact restoration with zero leakage)
    for i in 0..500 {
        let debit_id = format!("valid_debit_commit_{i:04}");
        stream.push(json!({
            "event_type": "CBF_ROLLBACK",
            "debit_id": debit_id,
            "status": "ROLLED_BACK",
            "restored_amount": 20.0,
        }));
    }

    // 500 valid refusals (64-hex lowercase proof_hash)
    for i in 0..500 {
        let proof = sha256_hex(&format!("valid_refusal_proof_{i}"));
        stream.push(json!({
            "event_type": "GOVERNANCE_REFUSAL",
            "proof_hash": proof,
            "reason": "Valid policy deny",
        }));
    }

    assert_eq!(stream.len(), 5000, "Conformant stream count must be 5,000");

    // 5,000 Adversarial Injection Events
    // ----------------------------------
    // 1,000 Replay attacks: Consume the first 1,000 seals a second time
    for i in 0..1000 {
        let dec_hash = sha256_hex(&format!("valid_decision_event_{i}"));
        let seal_id = format!("valid_seal_id_{i:04}");
        stream.push(json!({
            "event_type": "GOVERNANCE_SEAL_CONSUMED",
            "seal_id": seal_id,
            "decision_record_hash": dec_hash,
            "replay_marker": true,
        }));
    }

    // 1,000 Phantom actuations (unconsumed seals)
    for i in 0..1000 {
        let phantom_seal = format!("phantom_seal_rogue_{i:04}");
        stream.push(json!({
            "event_type": "ACTUATION_RECEIPT",
            "seal_id": phantom_seal,
            "status": "EXECUTED",
        }));
    }

    // 1,000 CBF barrier breaches (cost too high: h_next < min_allowed)
    for i in 0..1000 {
        let debit_id = format!("breached_debit_commit_{i:04}");
        stream.push(json!({
            "event_type": "CBF_COMMIT",
            "debit_id": debit_id,
            "state_before": 100.0,
            "cost": 95.0,
            "b_min": 10.0,
            "gamma": 0.5,
        }));
    }

    // 1,000 CBF budget leakages (commit then restore committed + 0.0001)
    for i in 0..500 {
        let debit_id = format!("leak_debit_{i:04}");
        stream.push(json!({
            "event_type": "CBF_COMMIT",
            "debit_id": debit_id.clone(),
            "state_before": 100.0,
            "cost": 10.0,
            "b_min": 10.0,
            "gamma": 0.5,
        }));
        stream.push(json!({
            "event_type": "CBF_ROLLBACK",
            "debit_id": debit_id,
            "status": "ROLLED_BACK",
            "restored_amount": 10.0001,
        }));
    }

    // 1,000 Malformed Refusals (uppercase hex, truncated, non-hex, empty)
    for i in 0..1000 {
        let bad_hash = match i % 4 {
            0 => "A".repeat(64),
            1 => "b".repeat(63),
            2 => "z".repeat(64),
            _ => String::new(),
        };
        stream.push(json!({
            "event_type": "GOVERNANCE_REFUSAL",
            "proof_hash": bad_hash,
            "reason": "Malformed refusal hash",
        }));
    }

    assert_eq!(
        stream.len(),
        10_000,
        "Total stream count must be exactly 10,000"
    );

    // Execution & Linear Complexity Verification
    // ------------------------------------------
    let start_time = Instant::now();
    let report_a = StreamInvariantVerifier::verify_stream(&stream);
    let duration_a = start_time.elapsed();

    println!(
        " [+] Verified 10,000 mixed stream records in {:?}",
        duration_a
    );

    // Invariant 1: Zero panics & expected record count
    assert_eq!(report_a.records_checked, 10_000);
    assert_eq!(report_a.status, StreamConformanceStatus::NonConformant);
    assert!(report_a.findings_count > 0);

    // Invariant 2: Linear time complexity (10,000 records must evaluate in < 500 ms)
    assert!(
        duration_a.as_millis() < 500,
        "Stream verification of 10,000 records exceeded 500ms limit: {:?}",
        duration_a
    );

    // Invariant 3: Deterministic verification receipt
    let report_b = StreamInvariantVerifier::verify_stream(&stream);
    assert_eq!(
        report_a.stream_proof_hash, report_b.stream_proof_hash,
        "Stream proof hashes must be 100% deterministic across repeated runs"
    );
    assert_eq!(
        report_a.findings_count, report_b.findings_count,
        "Findings count must be deterministic"
    );
    assert_eq!(
        report_a.findings, report_b.findings,
        "Findings array must be deterministic"
    );
    assert_eq!(report_a.stream_proof_hash.len(), 64);
    assert!(
        StreamInvariantVerifier::is_64_hex_lowercase(&report_a.stream_proof_hash),
        "stream_proof_hash must be valid 64 lowercase hex"
    );

    // Invariant 4: Cryptographic avalanche effect (tampering with 1 byte changes proof hash)
    let mut tampered_stream = stream.clone();
    tampered_stream[9999]["reason"] = json!("Tampered character in record 9999");
    let report_tampered = StreamInvariantVerifier::verify_stream(&tampered_stream);
    assert_ne!(
        report_a.stream_proof_hash, report_tampered.stream_proof_hash,
        "Tampering with a single field in record 9,999 must alter stream_proof_hash"
    );
}

// =========================================================================
// 7. Multi-Threaded Concurrent Verification & Robustness
// =========================================================================

#[test]
fn test_adversarial_stream_concurrent_multi_verifier_threads() {
    let thread_count = 16;
    let records_per_thread = 500;
    let barrier = Arc::new(std::sync::Barrier::new(thread_count));
    let panic_count = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();

    for t in 0..thread_count {
        let b = Arc::clone(&barrier);
        let panics = Arc::clone(&panic_count);

        handles.push(thread::spawn(move || {
            let mut local_stream = Vec::with_capacity(records_per_thread);
            for i in 0..records_per_thread {
                let dec_hash = sha256_hex(&format!("t_{t}_dec_{i}"));
                local_stream.push(json!({
                    "event_type": "GOVERNANCE_DECISION",
                    "record_hash": dec_hash,
                    "verdict": "ALLOW",
                    "seal_present": true,
                }));
            }

            b.wait();
            let res =
                std::panic::catch_unwind(|| StreamInvariantVerifier::verify_stream(&local_stream));

            if let Ok(report) = res {
                assert!(report.is_conformant());
                assert_eq!(report.records_checked, records_per_thread);
            } else {
                panics.fetch_add(1, Ordering::SeqCst);
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    assert_eq!(
        panic_count.load(Ordering::SeqCst),
        0,
        "Zero panics permitted across concurrent verifier invocations"
    );
}

#[test]
fn test_adversarial_stream_jsonl_string_parser_resilience() {
    let valid_hash = sha256_hex("jsonl_test_decision");
    let valid_jsonl = format!(
        r#"
        {{"event_type": "GOVERNANCE_DECISION", "record_hash": "{valid_hash}", "verdict": "ALLOW", "seal_present": true}}

        {{"event_type": "GOVERNANCE_SEAL_CONSUMED", "seal_id": "seal_jsonl_1", "decision_record_hash": "{valid_hash}"}}

        {{"event_type": "ACTUATION_RECEIPT", "seal_id": "seal_jsonl_1", "status": "EXECUTED"}}
        "#
    );

    let report = StreamInvariantVerifier::verify_jsonl_str(&valid_jsonl)
        .expect("Valid JSONL with blank lines must parse cleanly");

    assert!(report.is_conformant());
    assert_eq!(report.records_checked, 3);
    assert_eq!(report.findings_count, 0);

    // Malformed JSON syntax must return Err
    let malformed_jsonl = "{\"event_type\": \"GOVERNANCE_DECISION\",\nNOT_VALID_JSON\n";
    assert!(
        StreamInvariantVerifier::verify_jsonl_str(malformed_jsonl).is_err(),
        "Malformed JSONL line must return Err"
    );
}
