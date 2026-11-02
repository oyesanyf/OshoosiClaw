//! crates/osoosi-policy/tests/cage_cbf_adversarial_tests.rs
//!
//! Milestone 2 Adversarial Empirical Stress Test Suite:
//! Control Barrier Functions (CBF), Fiscal Ledger Invariants, & Routing Seals
//!
//! Conducted by teamwork_challenger (Challenger 1, Milestone 2)
//!
//! Empirical challenges:
//! 1. CBF Epsilon Boundary Breaches:
//!    - Costs causing $h_{t+1}$ to fall below $(1-\gamma)h_t$ by $10^{-6}$ and $10^{-9}$.
//!    - Non-negativity floor breaches ($h_{t+1} < 0$).
//! 2. Zero Budget Leakage Under Denial Storms:
//!    - 1,000 rapid consecutive invalid/unsafe requests across all failure categories.
//!    - Exact fiscal conservation proof ($B_{t+1000} == B_t$ with 0.00000000 leakage).
//! 3. Concurrent Fuel Contention:
//!    - Multi-threaded concurrent execution against `FiscalLedger`.
//!    - Verification that no race condition causes negative balance or barrier overshoot.
//! 4. LIFO Rollback Stack Order:
//!    - Multi-action pre-reservation and selective rollback in varying orders.
//!    - Verification of exact balance restoration and anti-replay guards.

use osoosi_policy::cage::{
    CageGovernancePipeline, CbfViolation, CompiledCagePolicy, ControlBarrierFunction,
    FiscalLedger, GovernanceRequest, GovernanceVerdict, PolicyFormat, UnsafeControlAction,
    CBF_EPSILON,
};
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;

const TEST_SECRET: &[u8] = b"OSHOOSICLAW_CBF_ADVERSARIAL_CHALLENGER_SECRET_KEY";

fn make_adversarial_policy(gamma: f64, b_min: f64) -> CompiledCagePolicy {
    CompiledCagePolicy {
        policy_version_id: "cbf_adv_m2_0001".to_string(),
        format: PolicyFormat::CageStpa,
        raw_content: "cbf_adversarial_test_policy".to_string(),
        cedar_rules: vec![
            r#"forbid (principal, action == Action::"ForbiddenTerminal", resource);"#.to_string(),
            r#"forbid (principal, action, resource) when { context.path == "/etc/shadow" };"#.to_string(),
        ],
        unsafe_control_actions: vec![
            UnsafeControlAction {
                uca_id: "UCA-ADV-1".to_string(),
                hazard_ref: "H-STPA-01".to_string(),
                control_action: "ExecuteHighRiskTrade".to_string(),
                context_condition: "amount > 5000".to_string(),
                mitigation: "Limit amount to 5000".to_string(),
            },
        ],
        cbf_gamma: gamma,
        cbf_b_min: b_min,
    }
}

// =========================================================================
// 1. CBF Epsilon Boundary Breaches
// =========================================================================

#[test]
fn test_cbf_epsilon_boundary_breach_1e6() {
    let b_min = 10.0;
    let gamma = 0.5;
    let cbf = ControlBarrierFunction::new(gamma, b_min).expect("cbf new");

    let b_t = 100.0;
    let h_t = b_t - b_min; // 90.0
    let _h_min_allowed = (1.0 - gamma) * h_t; // 45.0
    let c_max = gamma * h_t; // 45.0

    // Exact boundary cost: h_{t+1} == 45.0 == h_min_allowed (MUST PASS)
    let res_exact = cbf.evaluate_step(b_t, c_max, h_t);
    assert!(res_exact.is_ok(), "Exact boundary must pass");
    assert!((res_exact.unwrap() - 45.0).abs() < 1e-12);

    // Epsilon breach by 10^-6: cost = 45.0 + 1e-6
    // h_{t+1} = 45.0 - 1e-6 = 44.999999 < 45.0 (MUST BE DENIED)
    let cost_breach_1e6 = c_max + 1e-6;
    let res_breach_1e6 = cbf.evaluate_step(b_t, cost_breach_1e6, h_t);
    assert!(
        res_breach_1e6.is_err(),
        "CBF breach by 1e-6 must be denied"
    );
    assert!(matches!(
        res_breach_1e6.unwrap_err(),
        CbfViolation::DecayRateExceeded { .. }
    ));
}

#[test]
fn test_cbf_epsilon_boundary_breach_analysis_1e9() {
    let b_min = 10.0;
    let gamma = 0.5;
    let cbf = ControlBarrierFunction::new(gamma, b_min).expect("cbf new");

    let b_t = 100.0;
    let h_t = b_t - b_min; // 90.0
    let _h_min_allowed = (1.0 - gamma) * h_t; // 45.0
    let c_max = gamma * h_t; // 45.0

    // Test breach by 2 * CBF_EPSILON (2e-9)
    let cost_breach_2e9 = c_max + 2.0 * CBF_EPSILON;
    let res_breach_2e9 = cbf.evaluate_step(b_t, cost_breach_2e9, h_t);
    assert!(
        res_breach_2e9.is_err(),
        "Cost exceeding boundary by 2e-9 must be denied"
    );
    assert!(matches!(
        res_breach_2e9.unwrap_err(),
        CbfViolation::DecayRateExceeded { .. }
    ));

    // Test breach by 1.0001 * CBF_EPSILON
    let cost_breach_1_0001e9 = c_max + 1.0001 * CBF_EPSILON;
    let res_breach_1_0001e9 = cbf.evaluate_step(b_t, cost_breach_1_0001e9, h_t);
    assert!(
        res_breach_1_0001e9.is_err(),
        "Cost exceeding boundary by 1.0001 * CBF_EPSILON must be denied"
    );

    // Analysis of exact 1e-9 tolerance band:
    // Floating point CBF_EPSILON is defined as 1e-9.
    // When cost exceeds c_max by exactly 1e-9, it sits within the float tolerance band:
    let cost_exact_1e9 = c_max + 1e-9;
    let res_exact_1e9 = cbf.evaluate_step(b_t, cost_exact_1e9, h_t);
    println!("Evaluation result at c_max + 1e-9: {:?}", res_exact_1e9);
}

#[test]
fn test_cbf_floor_breach_adversarial() {
    let b_min = 10.0;
    let gamma = 1.0;
    let cbf = ControlBarrierFunction::new(gamma, b_min).expect("cbf new");

    // Start with budget exactly at floor
    let b_t = 10.0;
    let h_t = 0.0;

    // Zero cost: budget stays at 10.0, h stays at 0.0 -> OK
    assert!(cbf.evaluate_step(b_t, 0.0, h_t).is_ok());

    // Cost 1e-6 causes floor breach: projected_budget = 9.999999 < 10.0 -> FloorBreach
    let res_floor_1e6 = cbf.evaluate_step(b_t, 1e-6, h_t);
    assert!(res_floor_1e6.is_err());
    assert!(matches!(
        res_floor_1e6.unwrap_err(),
        CbfViolation::FloorBreach { .. }
    ));

    // Cost 1e-9: projected_budget = 10.0 - 1e-9 < 10.0 -> FloorBreach
    let res_floor_1e9 = cbf.evaluate_step(b_t, 1e-9, h_t);
    assert!(res_floor_1e9.is_err());
    assert!(matches!(
        res_floor_1e9.unwrap_err(),
        CbfViolation::FloorBreach { .. }
    ));

    // Negative cost rejected unconditionally
    let res_neg = cbf.evaluate_step(b_t, -1.0, h_t);
    assert!(matches!(
        res_neg.unwrap_err(),
        CbfViolation::InvalidParameters(_)
    ));
}

// =========================================================================
// 2. Zero Budget Leakage Under Denial Storms (1,000 Requests)
// =========================================================================

#[test]
fn test_zero_budget_leakage_under_1000_denial_storm() {
    let policy = make_adversarial_policy(0.1, 10.0);
    let initial_budget = 250.0;
    let ledger = FiscalLedger::new(initial_budget, 0.1, 10.0).expect("ledger init");
    let pipeline = CageGovernancePipeline::new(policy, ledger, TEST_SECRET);

    assert_eq!(pipeline.ledger().available_budget(), initial_budget);

    let mut deny_count = 0;
    let mut defer_count = 0;
    let mut approval_count = 0;

    // Issue 1,000 diverse invalid/denied/deferred requests
    for i in 0..1000 {
        let req = match i % 8 {
            // Category 0: CBF barrier decay rate violation
            0 => GovernanceRequest {
                action_name: "InspectLogs".to_string(),
                principal: "auditor".to_string(),
                resource: "syslog".to_string(),
                parameters: json!({"iter": i}),
                caller_authority: 2,
                confidence_score: 0.99,
                consensus_score: 0.95,
                fuel_cost: 50.0, // Exceeds gamma * h_t = 0.1 * 240 = 24.0
                expected_policy_version: None,
            },
            // Category 1: CBF absolute floor breach
            1 => GovernanceRequest {
                action_name: "InspectLogs".to_string(),
                principal: "auditor".to_string(),
                resource: "syslog".to_string(),
                parameters: json!({"iter": i}),
                caller_authority: 2,
                confidence_score: 0.99,
                consensus_score: 0.95,
                fuel_cost: 300.0, // Far exceeds total budget
                expected_policy_version: None,
            },
            // Category 2: FTRA Caller Authority Violation
            2 => GovernanceRequest {
                action_name: "execute_child_process".to_string(),
                principal: "untrusted_agent".to_string(),
                resource: "/bin/sh".to_string(),
                parameters: json!({"cmd": "whoami"}),
                caller_authority: 5, // Untrusted caller, requires <= 2
                confidence_score: 0.99,
                consensus_score: 0.95,
                fuel_cost: 1.0,
                expected_policy_version: None,
            },
            // Category 3: STPA UCA Breach
            3 => GovernanceRequest {
                action_name: "ExecuteHighRiskTrade".to_string(),
                principal: "trader".to_string(),
                resource: "PORTFOLIO".to_string(),
                parameters: json!({"amount": 99999}), // > 5000 UCA limit
                caller_authority: 1,
                confidence_score: 0.99,
                consensus_score: 0.95,
                fuel_cost: 1.0,
                expected_policy_version: None,
            },
            // Category 4: Cedar Forbid Clause
            4 => GovernanceRequest {
                action_name: "ReadResource".to_string(),
                principal: "operator".to_string(),
                resource: "/etc/shadow".to_string(),
                parameters: json!({"path": "/etc/shadow"}),
                caller_authority: 2,
                confidence_score: 0.99,
                consensus_score: 0.95,
                fuel_cost: 1.0,
                expected_policy_version: None,
            },
            // Category 5: SR 26-2 Low Confidence (DEFER)
            5 => GovernanceRequest {
                action_name: "InspectLogs".to_string(),
                principal: "auditor".to_string(),
                resource: "syslog".to_string(),
                parameters: json!({"iter": i}),
                caller_authority: 2,
                confidence_score: 0.45, // < 0.70 -> DEFER
                consensus_score: 0.95,
                fuel_cost: 1.0,
                expected_policy_version: None,
            },
            // Category 6: SR 26-2 Mid Confidence (REQUIRE_APPROVAL)
            6 => GovernanceRequest {
                action_name: "InspectLogs".to_string(),
                principal: "auditor".to_string(),
                resource: "syslog".to_string(),
                parameters: json!({"iter": i}),
                caller_authority: 2,
                confidence_score: 0.85, // 0.70..0.95 -> REQUIRE_APPROVAL
                consensus_score: 0.95,
                fuel_cost: 1.0,
                expected_policy_version: None,
            },
            // Category 7: Policy Version Drift Conflict
            _ => GovernanceRequest {
                action_name: "InspectLogs".to_string(),
                principal: "auditor".to_string(),
                resource: "syslog".to_string(),
                parameters: json!({"iter": i}),
                caller_authority: 2,
                confidence_score: 0.99,
                consensus_score: 0.95,
                fuel_cost: 1.0,
                expected_policy_version: Some("stale_version_9999".to_string()),
            },
        };

        let result = pipeline.evaluate_action(&req);

        // Strict assertions on every denied/deferred/approval request:
        assert!(
            result.seal.is_none(),
            "Never issue routing seal on unapproved request at iter {}",
            i
        );
        assert!(
            result.commit_receipt.is_none(),
            "Never issue commit receipt on unapproved request at iter {}",
            i
        );

        match result.verdict {
            GovernanceVerdict::Deny { ref reason, ref proof_hash } => {
                deny_count += 1;
                assert_eq!(proof_hash.len(), 64, "Proof hash must be 64-hex SHA-256");
                assert!(!reason.is_empty());
            }
            GovernanceVerdict::Defer { backoff_ms } => {
                defer_count += 1;
                assert!(backoff_ms >= 1000);
            }
            GovernanceVerdict::RequireApproval { ref approval_token, .. } => {
                approval_count += 1;
                assert!(approval_token.starts_with("token_"));
            }
            _ => panic!("Expected non-cleared verdict at iteration {}, got {:?}", i, result.verdict),
        }

        // Check budget invariant after EACH iteration
        assert_eq!(
            pipeline.ledger().available_budget(),
            initial_budget,
            "Budget leaked at iteration {}!",
            i
        );
    }

    // FINAL STRICT INVARIANT ASSERTIONS:
    let final_budget = pipeline.ledger().available_budget();
    assert_eq!(
        final_budget, initial_budget,
        "ZERO BUDGET LEAKAGE VIOLATION: Expected {}, got {}",
        initial_budget, final_budget
    );
    assert_eq!(
        pipeline.ledger().active_reservation_count(),
        0,
        "No dangling reservations permitted"
    );

    println!(
        "1,000 Request Denial Storm Completed: {} Denied, {} Deferred, {} RequireApproval. Final Budget: {:.8}",
        deny_count, defer_count, approval_count, final_budget
    );
}

// =========================================================================
// 3. Concurrent Fuel Contention (Multi-Threaded Race Condition Harness)
// =========================================================================

#[test]
fn test_concurrent_fuel_contention_and_race_safety() {
    let initial_budget = 1000.0;
    let b_min = 100.0;
    let gamma = 1.0; // Allow using full safety margin up to floor
    let ledger = Arc::new(FiscalLedger::new(initial_budget, gamma, b_min).expect("ledger init"));

    let num_threads = 16;
    let requests_per_thread = 100;

    let successful_reservations = Arc::new(AtomicUsize::new(0));
    let denied_reservations = Arc::new(AtomicUsize::new(0));
    let committed_reservations = Arc::new(AtomicUsize::new(0));
    let rolled_back_reservations = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::new();

    for t in 0..num_threads {
        let ledger_clone = Arc::clone(&ledger);
        let succ_clone = Arc::clone(&successful_reservations);
        let den_clone = Arc::clone(&denied_reservations);
        let comm_clone = Arc::clone(&committed_reservations);
        let rb_clone = Arc::clone(&rolled_back_reservations);

        let handle = thread::spawn(move || {
            for req_idx in 0..requests_per_thread {
                let debit_id = format!("t{}_req{}", t, req_idx);
                // Costs between 5.0 and 25.0
                let cost = 5.0 + ((t * 7 + req_idx) % 20) as f64;

                match ledger_clone.pre_reserve(cost, &debit_id) {
                    Ok(receipt) => {
                        succ_clone.fetch_add(1, Ordering::Relaxed);

                        // Invariant: remaining budget must be >= b_min
                        assert!(
                            receipt.remaining_budget >= b_min - 1e-9,
                            "Receipt remaining budget violated floor: {}",
                            receipt.remaining_budget
                        );

                        // Simulate actuation: commit half, rollback half
                        if req_idx % 2 == 0 {
                            let commit_res = ledger_clone.commit(&receipt.debit_id);
                            assert!(commit_res.is_ok(), "Commit must succeed for valid reservation");
                            comm_clone.fetch_add(1, Ordering::Relaxed);
                        } else {
                            let rb_res = ledger_clone.rollback_reservation(&receipt.debit_id);
                            assert!(rb_res.is_ok(), "Rollback must succeed for valid reservation");
                            rb_clone.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    Err(violation) => {
                        den_clone.fetch_add(1, Ordering::Relaxed);
                        assert!(matches!(
                            violation,
                            CbfViolation::FloorBreach { .. } | CbfViolation::DecayRateExceeded { .. }
                        ));
                    }
                }

                // Check invariants during runtime
                let current_b = ledger_clone.available_budget();
                assert!(
                    current_b >= b_min - 1e-9,
                    "Runtime budget breached floor under concurrent contention: {}",
                    current_b
                );
            }
        });
        handles.push(handle);
    }

    for h in handles {
        h.join().expect("Worker thread panicked");
    }

    let final_budget = ledger.available_budget();
    let succ = successful_reservations.load(Ordering::SeqCst);
    let den = denied_reservations.load(Ordering::SeqCst);
    let comm = committed_reservations.load(Ordering::SeqCst);
    let rb = rolled_back_reservations.load(Ordering::SeqCst);

    println!(
        "Concurrent Contention Results: Total attempts={}, Success={}, Denied={}, Committed={}, RolledBack={}, Final Budget={:.4}",
        num_threads * requests_per_thread,
        succ,
        den,
        comm,
        rb,
        final_budget
    );

    // Invariants:
    assert_eq!(succ + den, num_threads * requests_per_thread);
    assert_eq!(comm + rb, succ);
    assert!(
        final_budget >= b_min,
        "Final budget {} breached safety floor {}",
        final_budget,
        b_min
    );
    assert!(
        final_budget <= initial_budget + 1e-9,
        "Final budget {} exceeded initial budget {}",
        final_budget,
        initial_budget
    );
    assert_eq!(ledger.active_reservation_count(), 0);
}

// =========================================================================
// 4. LIFO Rollback Stack Order & Anti-Replay Verification
// =========================================================================

#[test]
fn test_lifo_rollback_stack_strict_reversal() {
    let ledger = FiscalLedger::new(200.0, 0.5, 10.0).expect("ledger init");

    // Pre-reserve 5 sequential actions
    let amounts = [5.0, 10.0, 15.0, 20.0, 25.0];
    let names = ["action_1", "action_2", "action_3", "action_4", "action_5"];

    for (amt, name) in amounts.iter().zip(names.iter()) {
        ledger.pre_reserve(*amt, name).expect("reserve");
    }

    // Total reserved = 5 + 10 + 15 + 20 + 25 = 75.0. Budget = 200 - 75 = 125.0
    assert_eq!(ledger.available_budget(), 125.0);
    assert_eq!(ledger.active_reservation_count(), 5);

    // Pop LIFO: MUST arrive in exact reverse order: [action_5, action_4, action_3, action_2, action_1]
    let expected_order = ["action_5", "action_4", "action_3", "action_2", "action_1"];
    let mut expected_budget = 125.0;

    for (idx, expected_name) in expected_order.iter().enumerate() {
        let (popped_id, new_budget) = ledger.rollback_lifo().expect("rollback lifo");
        assert_eq!(&popped_id, expected_name, "LIFO order mismatch at pop {}", idx);
        let restored_amt = amounts[4 - idx];
        expected_budget += restored_amt;
        assert_eq!(new_budget, expected_budget);
        assert_eq!(ledger.available_budget(), expected_budget);
    }

    // Now all 5 are rolled back; budget must be exactly 200.0
    assert_eq!(ledger.available_budget(), 200.0);
    assert_eq!(ledger.active_reservation_count(), 0);

    // Popping empty stack must return ReservationNotFound
    assert!(matches!(
        ledger.rollback_lifo().unwrap_err(),
        CbfViolation::ReservationNotFound(_)
    ));
}

#[test]
fn test_selective_arbitrary_id_rollback_and_commit_guards() {
    let ledger = FiscalLedger::new(200.0, 0.5, 10.0).expect("ledger init");

    ledger.pre_reserve(10.0, "debit_A").unwrap();
    ledger.pre_reserve(20.0, "debit_B").unwrap();
    ledger.pre_reserve(30.0, "debit_C").unwrap();
    ledger.pre_reserve(40.0, "debit_D").unwrap();
    assert_eq!(ledger.available_budget(), 100.0);
    assert_eq!(ledger.active_reservation_count(), 4);

    // 1. Rollback non-top element C (30.0)
    let b_after_c = ledger.rollback_reservation("debit_C").unwrap();
    assert_eq!(b_after_c, 130.0);
    assert_eq!(ledger.active_reservation_count(), 3);

    // 2. Attempt double-rollback of C -> MUST FAIL
    assert!(matches!(
        ledger.rollback_reservation("debit_C").unwrap_err(),
        CbfViolation::ReservationNotFound(_)
    ));

    // 3. Commit B (20.0)
    assert!(ledger.commit("debit_B").is_ok());
    assert_eq!(ledger.active_reservation_count(), 2); // A and D still pending

    // 4. Attempt rollback of committed B -> MUST FAIL with AlreadyCommitted
    assert!(matches!(
        ledger.rollback_reservation("debit_B").unwrap_err(),
        CbfViolation::AlreadyCommitted(_)
    ));

    // 5. Rollback LIFO: uncommitted pending are A and D. Top is D.
    let (lifo_id, b_after_d) = ledger.rollback_lifo().unwrap();
    assert_eq!(lifo_id, "debit_D");
    assert_eq!(b_after_d, 170.0); // 130 + 40
    assert_eq!(ledger.active_reservation_count(), 1);

    // 6. Next LIFO: must skip committed B and already rolled-back C, popping A
    let (lifo_id2, b_after_a) = ledger.rollback_lifo().unwrap();
    assert_eq!(lifo_id2, "debit_A");
    assert_eq!(b_after_a, 180.0); // 170 + 10
    assert_eq!(ledger.active_reservation_count(), 0);

    // Since B was committed (20.0 deducted permanently), final budget is 200 - 20 = 180.0
    assert_eq!(ledger.available_budget(), 180.0);
}
