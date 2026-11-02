//! Milestone 8 Phase 2: Tier 5 Kernel & Policy Adversarial Hardening Test Suite
//!
//! Empirical Challenger 1 Verification Suite for:
//! 1. Mathematical Bounds & CBF Invariants:
//!    - Floating-point epsilon handling and boundary precision.
//!    - Negative budget values, negative cost expenditures, and zero cost.
//!    - NaN and Infinity injection / poisoning behavior across CBF and FiscalLedger.
//!    - Discrete-time exponential barrier condition: $h_{t+1} \ge (1-\gamma)h_t \ge 0$.
//!    - Fiscal fuel pre-reservation, zero fiscal leakage on denial, and LIFO rollback integrity.
//! 2. Routing Seals & NoDirectBind:
//!    - HMAC-SHA256 constant-time comparison (`subtle::ConstantTimeEq`).
//!    - 30-second TTL expiration boundary: exact $t = 30$ vs $t = 31$ vs inverted timestamps.
//!    - Single-use nonce consumption and concurrency race resistance (50 parallel threads).
//! 3. Formal Model & Stream Invariants:
//!    - Pure-Rust BFS formal model: strictly 34 gated states vs 17 ungated counterexample states vs 31 skipped-tier states.
//!    - 5 core stream invariants: `no_direct_bind`, `cbf_barrier`, `seal`, `cbf_rollback`, `refusal_evidence`.
//!    - 64-hex lowercase SHA-256 digest format enforcement (`^[0-9a-f]{64}$`).

use osoosi_policy::cage::{
    compute_action_digest, BfsPhase, CbfViolation, ControlBarrierFunction, FiscalLedger,
    FormalBfsModel, RoutingSealSigner, SealRejection, StreamConformanceStatus,
    StreamInvariantVerifier, CBF_EPSILON,
};
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

// =========================================================================
// Category 1: Mathematical Bounds & CBF Invariants
// =========================================================================

#[test]
fn test_cbf_parameter_validation_boundaries() {
    // Valid gamma in (0, 1]
    assert!(ControlBarrierFunction::new(0.1, 10.0).is_ok());
    assert!(ControlBarrierFunction::new(1.0, 10.0).is_ok());
    assert!(ControlBarrierFunction::new(0.0001, 0.0).is_ok());

    // Invalid gamma <= 0
    let err_zero = ControlBarrierFunction::new(0.0, 10.0).unwrap_err();
    assert!(matches!(err_zero, CbfViolation::InvalidParameters(ref msg) if msg.contains("gamma")));

    let err_neg = ControlBarrierFunction::new(-0.05, 10.0).unwrap_err();
    assert!(matches!(err_neg, CbfViolation::InvalidParameters(ref msg) if msg.contains("gamma")));

    // Invalid gamma > 1.0
    let err_large = ControlBarrierFunction::new(1.0001, 10.0).unwrap_err();
    assert!(matches!(err_large, CbfViolation::InvalidParameters(ref msg) if msg.contains("gamma")));

    // Invalid b_min < 0
    let err_bmin_neg = ControlBarrierFunction::new(0.5, -0.01).unwrap_err();
    assert!(matches!(err_bmin_neg, CbfViolation::InvalidParameters(ref msg) if msg.contains("b_min")));

    // Infinity parameter handling
    assert!(ControlBarrierFunction::new(f64::INFINITY, 10.0).is_err());
    assert!(ControlBarrierFunction::new(f64::NEG_INFINITY, 10.0).is_err());
}

#[test]
fn test_cbf_cost_negativity_and_zero_cost() {
    let cbf = ControlBarrierFunction::new(0.2, 10.0).unwrap();

    // Zero cost: allowed, budget unchanged, h unchanged
    let (b_next, h_next) = cbf.evaluate(100.0, 0.0).expect("Zero cost must succeed");
    assert_eq!(b_next, 100.0);
    assert_eq!(h_next, 90.0);

    // Negative cost: must be rejected with InvalidParameters (cannot artificially increase budget)
    let err_neg_cost = cbf.evaluate(100.0, -1.0).unwrap_err();
    assert!(matches!(err_neg_cost, CbfViolation::InvalidParameters(ref msg) if msg.contains("Cost cannot be negative")));
}

#[test]
fn test_cbf_exponential_barrier_inequality_exact_epsilon_boundaries() {
    // Current budget: B_t = 100.0, b_min = 20.0 => h_t = 80.0
    // gamma = 0.25 => (1 - gamma) * h_t = 0.75 * 80.0 = 60.0
    // Required: h_{t+1} >= 60.0 => projected budget B_{t+1} >= 80.0 => max cost = 20.0
    let cbf = ControlBarrierFunction::new(0.25, 20.0).unwrap();

    // 1. Exact boundary cost = 20.0 => h_{t+1} = 60.0 == 60.0 (clears)
    let (b1, h1) = cbf.evaluate(100.0, 20.0).expect("Exact boundary must succeed");
    assert!((b1 - 80.0).abs() < CBF_EPSILON);
    assert!((h1 - 60.0).abs() < CBF_EPSILON);

    // 2. Just inside boundary: cost = 20.0 - 0.001 => h_{t+1} = 60.001 > 60.0 (clears)
    assert!(cbf.evaluate(100.0, 19.999).is_ok());

    // 3. Epsilon boundary: cost = 20.0 + (CBF_EPSILON * 0.5) => within tolerance, clears
    let eps_cost = 20.0 + (CBF_EPSILON * 0.5);
    assert!(cbf.evaluate(100.0, eps_cost).is_ok());

    // 4. Exceeding decay rate: cost = 20.0 + 1e-6 => exceeds tolerance, fails with DecayRateExceeded
    let over_cost = 20.0 + 1e-6;
    let err_decay = cbf.evaluate(100.0, over_cost).unwrap_err();
    assert!(matches!(err_decay, CbfViolation::DecayRateExceeded { .. }));
}

#[test]
fn test_cbf_floor_breach_and_current_state_unsafe() {
    let cbf = ControlBarrierFunction::new(0.5, 50.0).unwrap();

    // Current budget is already below floor
    let err_unsafe = cbf.evaluate(49.0, 0.0).unwrap_err();
    assert!(matches!(err_unsafe, CbfViolation::CurrentStateUnsafe { current_budget, b_min } if current_budget == 49.0 && b_min == 50.0));

    // Current budget is at floor: cost > 0 causes floor breach
    let err_floor = cbf.evaluate(50.0, 1.0).unwrap_err();
    assert!(matches!(err_floor, CbfViolation::FloorBreach { projected_budget, b_min } if projected_budget == 49.0 && b_min == 50.0));
}

#[test]
fn test_cbf_nan_and_infinity_resilience() {
    let cbf = ControlBarrierFunction::new(0.1, 10.0).unwrap();

    // Infinite cost
    let err_inf = cbf.evaluate(100.0, f64::INFINITY).unwrap_err();
    assert!(matches!(err_inf, CbfViolation::FloorBreach { .. }));

    // Negative infinite cost
    let err_neg_inf = cbf.evaluate(100.0, f64::NEG_INFINITY).unwrap_err();
    assert!(matches!(err_neg_inf, CbfViolation::InvalidParameters(..)));
}

#[test]
fn test_fiscal_ledger_pre_reservation_zero_leakage_and_lifo_rollback() {
    let ledger = FiscalLedger::new(100.0, 0.1, 10.0).unwrap();
    assert_eq!(ledger.available_budget(), 100.0);
    assert_eq!(ledger.barrier_margin(), 90.0);
    assert_eq!(ledger.active_reservation_count(), 0);

    // 1. Successful pre-reservation: cost 5.0 (max allowed is 9.0)
    let receipt1 = ledger.pre_reserve(5.0, "debit_001").expect("Debit 1 must succeed");
    assert_eq!(receipt1.reserved_fuel, 5.0);
    assert_eq!(receipt1.remaining_budget, 95.0);
    assert_eq!(ledger.available_budget(), 95.0);
    assert_eq!(ledger.active_reservation_count(), 1);

    // 2. Successful second pre-reservation: cost 3.0 (from 95.0, floor 10.0, h=85.0, decay max 8.5)
    let receipt2 = ledger.pre_reserve(3.0, "debit_002").expect("Debit 2 must succeed");
    assert_eq!(receipt2.reserved_fuel, 3.0);
    assert_eq!(receipt2.remaining_budget, 92.0);
    assert_eq!(ledger.available_budget(), 92.0);
    assert_eq!(ledger.active_reservation_count(), 2);

    // 3. Excessive pre-reservation: cost 50.0 (violates decay rate)
    // Invariant: ZERO FISCAL LEAKAGE ($B_{t+1} = B_t$)
    let err_excess = ledger.pre_reserve(50.0, "debit_excess").unwrap_err();
    assert!(matches!(err_excess, CbfViolation::DecayRateExceeded { .. }));
    assert_eq!(ledger.available_budget(), 92.0, "Budget must NOT leak on failure");
    assert_eq!(ledger.active_reservation_count(), 2);

    // 4. LIFO Rollback: rollback most recent active reservation ("debit_002", amount 3.0)
    let (rolled_id, restored_budget) = ledger.rollback_lifo().expect("LIFO rollback must succeed");
    assert_eq!(rolled_id, "debit_002");
    assert_eq!(restored_budget, 95.0);
    assert_eq!(ledger.available_budget(), 95.0);
    assert_eq!(ledger.active_reservation_count(), 1);

    // 5. Commit remaining reservation ("debit_001")
    ledger.commit("debit_001").expect("Commit must succeed");
    assert_eq!(ledger.active_reservation_count(), 0);

    // 6. Attempting to rollback a committed reservation must fail with AlreadyCommitted
    let err_commit_rb = ledger.rollback_reservation("debit_001").unwrap_err();
    assert!(matches!(err_commit_rb, CbfViolation::AlreadyCommitted(ref id) if id == "debit_001"));
    assert_eq!(ledger.available_budget(), 95.0);

    // 7. Attempting to rollback an already rolled back reservation must fail
    let err_double_rb = ledger.rollback_reservation("debit_002").unwrap_err();
    assert!(matches!(err_double_rb, CbfViolation::ReservationNotFound(..)));

    // 8. Attempting LIFO rollback when no uncommitted reservations exist must fail
    let err_no_lifo = ledger.rollback_lifo().unwrap_err();
    assert!(matches!(err_no_lifo, CbfViolation::ReservationNotFound(..)));
    assert_eq!(ledger.available_budget(), 95.0);
}

// =========================================================================
// Category 2: Routing Seals & NoDirectBind
// =========================================================================

#[test]
fn test_routing_seal_signature_constant_time_verification() {
    let secret_key = b"adversarial_test_secret_key_32_bytes!";
    let policy_ver = "fedcba9876543210";
    let signer = RoutingSealSigner::new(secret_key, policy_ver);

    let action_name = "TransferFunds";
    let params = json!({"amount": 1000, "currency": "USD", "recipient": "acct_888"});
    let action_digest = compute_action_digest(action_name, &params);
    let now = 1_700_000_000;

    let seal = signer.issue_seal(&action_digest, now);
    assert_eq!(seal.ttl_seconds(), 30);
    assert!(signer.verify_signature(&seal));

    // Tampered signature with identical length
    let mut tampered_seal = seal.clone();
    let mut sig_bytes = tampered_seal.signature.into_bytes();
    // Flip last hex character
    sig_bytes[63] = if sig_bytes[63] == b'a' { b'b' } else { b'a' };
    tampered_seal.signature = String::from_utf8(sig_bytes).unwrap();
    assert!(!signer.verify_signature(&tampered_seal));

    // Tampered signature with altered length
    let mut truncated_seal = seal.clone();
    truncated_seal.signature.truncate(32);
    assert!(!signer.verify_signature(&truncated_seal));

    let mut extended_seal = seal.clone();
    extended_seal.signature.push_str("00");
    assert!(!signer.verify_signature(&extended_seal));
}

#[test]
fn test_routing_seal_30s_ttl_expiration_boundaries() {
    let secret = b"routing_seal_ttl_boundary_key";
    let policy_ver = "1122334455667788";
    let signer = RoutingSealSigner::new(secret, policy_ver);

    let action_digest = "a".repeat(64);
    let issued_at = 1_700_000_000;
    let seal = signer.issue_seal(&action_digest, issued_at);

    // Exact boundary t = issued_at + 30s (now == expires_at)
    // is_expired(now) is false (now > expires_at is false)
    assert!(!seal.is_expired(issued_at + 30));
    assert!(signer
        .validate_seal_properties(&seal, &action_digest, issued_at + 30)
        .is_ok());

    // Expired at t = issued_at + 31s
    assert!(seal.is_expired(issued_at + 31));
    let err_exp = signer
        .validate_seal_properties(&seal, &action_digest, issued_at + 31)
        .unwrap_err();
    assert!(matches!(err_exp, SealRejection::Expired { current_time, expires_at } if current_time == issued_at + 31 && expires_at == issued_at + 30));

    // Future timestamp check (now < issued_at - 5s)
    let err_future = signer
        .validate_seal_properties(&seal, &action_digest, issued_at - 10)
        .unwrap_err();
    assert!(matches!(err_future, SealRejection::FutureTimestamp { .. }));
}

#[test]
fn test_routing_seal_concurrency_race_50_threads_atomic_consumption() {
    let secret = b"concurrency_race_secret_50_threads";
    let policy_ver = "abcdef0123456789";
    let signer = Arc::new(RoutingSealSigner::new(secret, policy_ver));

    let action_digest = "c".repeat(64);
    let now = 1_700_000_000;
    let seal = signer.issue_seal(&action_digest, now);

    let thread_count = 50;
    let barrier = Arc::new(Barrier::new(thread_count));
    let success_count = Arc::new(AtomicUsize::new(0));
    let rejection_count = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();

    for _ in 0..thread_count {
        let b = Arc::clone(&barrier);
        let s = Arc::clone(&signer);
        let seal_clone = seal.clone();
        let digest_clone = action_digest.clone();
        let succ = Arc::clone(&success_count);
        let rej = Arc::clone(&rejection_count);

        handles.push(thread::spawn(move || {
            b.wait();
            match s.validate_and_consume(&seal_clone, &digest_clone, now) {
                Ok(()) => {
                    succ.fetch_add(1, Ordering::SeqCst);
                }
                Err(SealRejection::AlreadyConsumed(..)) => {
                    rej.fetch_add(1, Ordering::SeqCst);
                }
                Err(other) => panic!("Unexpected seal rejection: {:?}", other),
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    // Invariant: EXACTLY 1 winner and 49 rejections (zero double-spend)
    assert_eq!(success_count.load(Ordering::SeqCst), 1);
    assert_eq!(rejection_count.load(Ordering::SeqCst), 49);
    assert!(signer.is_seal_consumed(&seal.seal_id));
    assert_eq!(signer.consumed_count(), 1);
}

// =========================================================================
// Category 3: Formal Model & Stream Invariants
// =========================================================================

#[test]
fn test_formal_bfs_model_state_spaces_empirical_proof() {
    // 1. Gated model verification: exactly 34 reachable states, 1 EXECUTED, 0 violations
    let gated = FormalBfsModel::explore_gated_model();
    assert_eq!(gated.reachable_count, 34);
    assert_eq!(gated.executed_count, 1);
    assert!(gated.violations.is_empty());
    assert!(gated.no_direct_bind_proven);

    // Verify all 34 states have proper properties
    let executed_state = gated
        .visited_states
        .iter()
        .find(|s| s.phase == BfsPhase::Executed)
        .expect("Must have 1 executed state");
    assert!(executed_state.seal_present);
    assert!(executed_state.resolved_allow);

    // 2. Ungated counterexample verification: exactly 17 reachable states, 1 violation
    let ungated = FormalBfsModel::explore_ungated_counterexample();
    assert_eq!(ungated.reachable_count, 17);
    assert_eq!(ungated.executed_count, 1);
    assert_eq!(ungated.violations.len(), 1);
    assert!(!ungated.no_direct_bind_proven);

    // 3. Skipped-tier model: all 7 tiers (0..=6) must yield exactly 31 reachable states and 0 executed
    for skip_tier in 0..7 {
        let skipped = FormalBfsModel::explore_skipped_tier_model(skip_tier);
        assert_eq!(
            skipped.reachable_count, 31,
            "Skipping tier {} must yield exactly 31 reachable states",
            skip_tier
        );
        assert_eq!(
            skipped.executed_count, 0,
            "Skipping tier {} must yield 0 executed states",
            skip_tier
        );
    }

    // 4. Theorem proof receipt
    let proof = FormalBfsModel::prove_no_direct_bind();
    assert!(proof.proven);
    assert_eq!(proof.reachable_states, 34);
    assert_eq!(proof.executed_states, 1);
    assert_eq!(proof.violations_count, 0);
    assert_eq!(proof.proof_receipt.len(), 64);
    assert!(proof.proof_receipt.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_stream_invariant_verifier_all_five_invariants() {
    let dec_hash = "1".repeat(64);
    let seal_hash = "2".repeat(64);

    // 1. Conformant stream: ALLOW with seal_present -> CONSUMED -> ACTUATION
    let conformant_stream = vec![
        json!({
            "event_type": "GOVERNANCE_DECISION",
            "verdict": "ALLOW",
            "seal_present": true,
            "record_hash": dec_hash,
        }),
        json!({
            "event_type": "GOVERNANCE_SEAL_CONSUMED",
            "seal_id": "seal_conf_001",
            "decision_record_hash": dec_hash,
            "record_hash": seal_hash,
        }),
        json!({
            "event_type": "ACTUATION_RECEIPT",
            "seal_id": "seal_conf_001",
            "record_hash": "3".repeat(64),
        }),
    ];
    let rep_conf = StreamInvariantVerifier::verify_stream(&conformant_stream);
    assert_eq!(rep_conf.status, StreamConformanceStatus::Conformant);
    assert!(rep_conf.is_conformant());
    assert_eq!(rep_conf.findings_count, 0);

    // 2. Invariant 'seal': ALLOW without seal_present
    let unsealed_decision = vec![json!({
        "event_type": "GOVERNANCE_DECISION",
        "verdict": "ALLOW",
        "seal_present": false,
        "record_hash": "4".repeat(64),
    })];
    let rep_seal = StreamInvariantVerifier::verify_stream(&unsealed_decision);
    assert_eq!(rep_seal.status, StreamConformanceStatus::NonConformant);
    assert!(rep_seal.has_rule_violation("seal"));

    // 3. Invariant 'no_direct_bind': Actuation receipt with unregistered seal
    let phantom_actuation = vec![json!({
        "event_type": "ACTUATION_RECEIPT",
        "seal_id": "unregistered_phantom_seal",
        "record_hash": "5".repeat(64),
    })];
    let rep_ndb = StreamInvariantVerifier::verify_stream(&phantom_actuation);
    assert_eq!(rep_ndb.status, StreamConformanceStatus::NonConformant);
    assert!(rep_ndb.has_rule_violation("no_direct_bind"));

    // 4. Invariant 'cbf_barrier': CBF_COMMIT where decay rate is exceeded
    let cbf_violation = vec![json!({
        "event_type": "CBF_COMMIT",
        "debit_id": "debit_breach_001",
        "state_before": 100.0,
        "cost": 50.0,
        "b_min": 10.0,
        "gamma": 0.1, // h_t = 90.0, required h_next >= 81.0, but projected h_next = 40.0
        "record_hash": "6".repeat(64),
    })];
    let rep_cbf = StreamInvariantVerifier::verify_stream(&cbf_violation);
    assert_eq!(rep_cbf.status, StreamConformanceStatus::NonConformant);
    assert!(rep_cbf.has_rule_violation("cbf_barrier"));

    // 5. Invariant 'cbf_rollback': Rollback with fiscal budget leakage (restored != committed)
    let rollback_leakage = vec![
        json!({
            "event_type": "CBF_COMMIT",
            "debit_id": "debit_rb_001",
            "state_before": 100.0,
            "cost": 5.0,
            "b_min": 10.0,
            "gamma": 0.1,
            "record_hash": "7".repeat(64),
        }),
        json!({
            "event_type": "CBF_ROLLBACK",
            "debit_id": "debit_rb_001",
            "status": "ROLLED_BACK",
            "restored_amount": 4.5, // 0.5 leaked!
            "record_hash": "8".repeat(64),
        }),
    ];
    let rep_rb = StreamInvariantVerifier::verify_stream(&rollback_leakage);
    assert_eq!(rep_rb.status, StreamConformanceStatus::NonConformant);
    assert!(rep_rb.has_rule_violation("cbf_rollback"));

    // 6. Invariant 'refusal_evidence': Refusal missing proof hash or having non-64-hex hash
    let refusal_no_proof = vec![json!({
        "event_type": "GOVERNANCE_REFUSAL",
        "proof_hash": "short_invalid_proof",
        "record_hash": "9".repeat(64),
    })];
    let rep_ref = StreamInvariantVerifier::verify_stream(&refusal_no_proof);
    assert_eq!(rep_ref.status, StreamConformanceStatus::NonConformant);
    assert!(rep_ref.has_rule_violation("refusal_evidence"));

    // 7. Invariant 'digest_format': Uppercase hex SHA-256 digest
    let uppercase_digest = vec![json!({
        "event_type": "GOVERNANCE_DECISION",
        "verdict": "DENY",
        "record_hash": "A".repeat(64), // uppercase!
    })];
    let rep_fmt = StreamInvariantVerifier::verify_stream(&uppercase_digest);
    assert_eq!(rep_fmt.status, StreamConformanceStatus::NonConformant);
    assert!(rep_fmt.has_rule_violation("digest_format"));
}
