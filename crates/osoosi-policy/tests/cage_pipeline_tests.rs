//! Integration Test Suite for CAGE 2-Phase, 7-Tier Deterministic Governance Pipeline
//!
//! Validates:
//! 1. Phase 1 read-only verification (FTRA, STPA UCAs, Cedar/OPA, SR 26-2, Consensus)
//! 2. Phase 2 discrete-time exponential Control Barrier Function (CBF) & Fiscal Ledger
//! 3. Zero budget leakage on CBF refusal ($B_{t+1} = B_t$)
//! 4. LIFO fiscal fuel rollback on actuation failure
//! 5. 30-second TTL single-use cryptographic routing seals (HMAC-SHA256, atomic replay defense)
//! 6. Parameter clamping and NARROW verdict issuance
//! 7. Model confidence escalation (REQUIRE_APPROVAL and DEFER)
//! 8. Version pinning conflict detection (HTTP 409 Conflict)

use osoosi_policy::cage::{
    compute_action_digest, CageGovernancePipeline, CbfViolation,
    CompiledCagePolicy, ControlBarrierFunction, FiscalLedger,
    GovernanceRequest, GovernanceVerdict, PolicyFormat,
    RoutingSealSigner, SealRejection, UnsafeControlAction,
};
use serde_json::json;

fn create_test_policy(version: &str, gamma: f64, b_min: f64) -> CompiledCagePolicy {
    CompiledCagePolicy {
        policy_version_id: version.to_string(),
        format: PolicyFormat::CageStpa,
        raw_content: "system: OshoosiClaw\nversion: 1.2.0".to_string(),
        cedar_rules: vec![
            r#"forbid (principal, action == Action::"SensitiveFileAccess", resource) when { context.path == "/etc/shadow" };"#.to_string(),
            r#"forbid (principal, action == Action::"ChildProcessExec", resource) when { context.routing_seal == "" };"#.to_string(),
        ],
        unsafe_control_actions: vec![
            UnsafeControlAction {
                uca_id: "UCA-1".to_string(),
                hazard_ref: "H-1".to_string(),
                control_action: "execute_child_process".to_string(),
                context_condition: "routing_seal is_null".to_string(),
                mitigation: "Execute only with valid unconsumed routing seal".to_string(),
            },
            UnsafeControlAction {
                uca_id: "UCA-2".to_string(),
                hazard_ref: "H-FIN-01".to_string(),
                control_action: "ExecuteStockOrder".to_string(),
                context_condition: "order_value_usd > 10000".to_string(),
                mitigation: "Limit single trade value to $10,000".to_string(),
            },
        ],
        cbf_gamma: gamma,
        cbf_b_min: b_min,
    }
}

const TEST_SECRET: &[u8] = b"OSHOOSICLAW_CAGE_PIPELINE_TEST_SECRET_KEY_32";

// =========================================================================
// 1. Phase 1 Read-Only Invariant Tests
// =========================================================================

#[test]
fn test_phase1_read_only_invariant_on_ftra_authority_violation() {
    let policy = create_test_policy("c4b8e219fa8201de", 0.5, 10.0);
    let ledger = FiscalLedger::new(100.0, 0.5, 10.0).expect("ledger init");
    let pipeline = CageGovernancePipeline::new(policy, ledger, TEST_SECRET);

    let initial_budget = pipeline.ledger().available_budget();
    assert_eq!(initial_budget, 100.0);

    // Untrusted caller (level 5) attempts IrreversibleTerminal action (execute_child_process)
    let request = GovernanceRequest {
        action_name: "execute_child_process".to_string(),
        principal: "agent-untrusted-01".to_string(),
        resource: "/bin/sh".to_string(),
        parameters: json!({"cmd": "whoami"}),
        caller_authority: 5, // Untrusted (requires <= 2)
        confidence_score: 0.99,
        consensus_score: 0.95,
        fuel_cost: 10.0,
        expected_policy_version: None,
    };

    let result = pipeline.evaluate_action(&request);

    // Assert Deny at Tier 1 (FTRA)
    assert!(result.verdict.is_deny());
    if let GovernanceVerdict::Deny { reason, proof_hash } = result.verdict {
        assert!(reason.contains("FTRA_AUTHORITY_VIOLATION"));
        assert_eq!(proof_hash.len(), 64);
        assert!(proof_hash.chars().all(|c| c.is_ascii_hexdigit()));
    } else {
        panic!("Expected GovernanceVerdict::Deny");
    }

    // STRICT INVARIANT: Phase 1 failure leaves budget untouched (100.0 -> 100.0)
    assert_eq!(pipeline.ledger().available_budget(), initial_budget);
    assert_eq!(pipeline.ledger().active_reservation_count(), 0);
    assert!(result.seal.is_none());
    assert!(result.commit_receipt.is_none());
}

#[test]
fn test_phase1_read_only_invariant_on_stpa_uca_violation() {
    let policy = create_test_policy("c4b8e219fa8201de", 0.5, 10.0);
    let ledger = FiscalLedger::new(100.0, 0.5, 10.0).expect("ledger init");
    let pipeline = CageGovernancePipeline::new(policy, ledger, TEST_SECRET);

    let initial_budget = pipeline.ledger().available_budget();

    // High privilege caller (level 1) attempts stock order exceeding STPA UCA-2 limit ($10,000)
    let request = GovernanceRequest {
        action_name: "ExecuteStockOrder".to_string(),
        principal: "system-trader".to_string(),
        resource: "NASDAQ:AAPL".to_string(),
        parameters: json!({"order_value_usd": 25000.0}),
        caller_authority: 1, // High privilege passes FTRA
        confidence_score: 0.98,
        consensus_score: 0.95,
        fuel_cost: 5.0,
        expected_policy_version: None,
    };

    let result = pipeline.evaluate_action(&request);

    // Assert Deny at Tier 2 (STPA)
    assert!(result.verdict.is_deny());
    if let GovernanceVerdict::Deny { reason, proof_hash } = result.verdict {
        assert!(reason.contains("STPA_UCA_BREACH"));
        assert!(reason.contains("UCA-2"));
        assert_eq!(proof_hash.len(), 64);
    } else {
        panic!("Expected GovernanceVerdict::Deny");
    }

    // Budget untouched
    assert_eq!(pipeline.ledger().available_budget(), initial_budget);
    assert!(result.seal.is_none());
}

#[test]
fn test_phase1_read_only_invariant_on_cedar_forbid_clause() {
    let policy = create_test_policy("c4b8e219fa8201de", 0.5, 10.0);
    let ledger = FiscalLedger::new(100.0, 0.5, 10.0).expect("ledger init");
    let pipeline = CageGovernancePipeline::new(policy, ledger, TEST_SECRET);

    let initial_budget = pipeline.ledger().available_budget();

    // ReadOnly action passes FTRA and STPA, but triggers Cedar forbid on /etc/shadow
    let request = GovernanceRequest {
        action_name: "SensitiveFileAccess".to_string(),
        principal: "operator".to_string(),
        resource: "/etc/shadow".to_string(),
        parameters: json!({"path": "/etc/shadow"}),
        caller_authority: 2,
        confidence_score: 0.99,
        consensus_score: 0.95,
        fuel_cost: 5.0,
        expected_policy_version: None,
    };

    let result = pipeline.evaluate_action(&request);

    assert!(result.verdict.is_deny());
    if let GovernanceVerdict::Deny { reason, proof_hash } = result.verdict {
        assert!(reason.contains("CEDAR_FORBID_VIOLATION"));
        assert_eq!(proof_hash.len(), 64);
    } else {
        panic!("Expected GovernanceVerdict::Deny");
    }

    assert_eq!(pipeline.ledger().available_budget(), initial_budget);
    assert!(result.seal.is_none());
}

#[test]
fn test_phase1_sr_26_2_confidence_lattice_thresholds() {
    let policy = create_test_policy("c4b8e219fa8201de", 0.5, 10.0);
    let ledger = FiscalLedger::new(100.0, 0.5, 10.0).expect("ledger init");
    let pipeline = CageGovernancePipeline::new(policy, ledger, TEST_SECRET);

    // 1. Confidence >= 0.95 -> Candidate for ALLOW
    let req_high = GovernanceRequest {
        action_name: "InspectLogs".to_string(),
        principal: "auditor".to_string(),
        resource: "syslog".to_string(),
        parameters: json!({"lines": 50}),
        caller_authority: 3,
        confidence_score: 0.96,
        consensus_score: 0.90,
        fuel_cost: 2.0,
        expected_policy_version: None,
    };
    let res_high = pipeline.evaluate_action(&req_high);
    assert_eq!(res_high.verdict, GovernanceVerdict::Allow);
    assert!(res_high.seal.is_some());

    // 2. 0.70 <= Confidence < 0.95 -> REQUIRE_APPROVAL with approval token
    let req_mid = GovernanceRequest {
        action_name: "InspectLogs".to_string(),
        principal: "auditor".to_string(),
        resource: "syslog".to_string(),
        parameters: json!({"lines": 50}),
        caller_authority: 3,
        confidence_score: 0.85,
        consensus_score: 0.90,
        fuel_cost: 2.0,
        expected_policy_version: None,
    };
    let res_mid = pipeline.evaluate_action(&req_mid);
    if let GovernanceVerdict::RequireApproval { reason, approval_token } = res_mid.verdict {
        assert!(reason.contains("SR 26-2"));
        assert!(approval_token.starts_with("token_"));
        assert!(res_mid.seal.is_none());
    } else {
        panic!("Expected RequireApproval for confidence 0.85");
    }

    // 3. Confidence < 0.70 -> DEFER with exponential backoff
    let req_low = GovernanceRequest {
        action_name: "InspectLogs".to_string(),
        principal: "auditor".to_string(),
        resource: "syslog".to_string(),
        parameters: json!({"lines": 50}),
        caller_authority: 3,
        confidence_score: 0.55,
        consensus_score: 0.90,
        fuel_cost: 2.0,
        expected_policy_version: None,
    };
    let res_low = pipeline.evaluate_action(&req_low);
    if let GovernanceVerdict::Defer { backoff_ms } = res_low.verdict {
        assert!(backoff_ms >= 1000);
        assert!(res_low.seal.is_none());
    } else {
        panic!("Expected Defer for confidence 0.55");
    }
}

#[test]
fn test_phase1_bayesian_consensus_quorum_check() {
    let policy = create_test_policy("c4b8e219fa8201de", 0.5, 10.0);
    let ledger = FiscalLedger::new(100.0, 0.5, 10.0).expect("ledger init");
    let pipeline = CageGovernancePipeline::new(policy, ledger, TEST_SECRET)
        .with_consensus_threshold(0.75);

    // Consensus score 0.60 below threshold 0.75
    let req = GovernanceRequest {
        action_name: "InspectLogs".to_string(),
        principal: "auditor".to_string(),
        resource: "syslog".to_string(),
        parameters: json!({}),
        caller_authority: 3,
        confidence_score: 0.98,
        consensus_score: 0.60,
        fuel_cost: 2.0,
        expected_policy_version: None,
    };

    let res = pipeline.evaluate_action(&req);
    assert!(res.verdict.is_deny());
    if let GovernanceVerdict::Deny { reason, .. } = res.verdict {
        assert!(reason.contains("BAYESIAN_CONSENSUS_DEFICIT"));
    } else {
        panic!("Expected Deny on consensus deficit");
    }
}

// =========================================================================
// 2. Phase 2 Discrete-Time Exponential CBF & Fiscal Ledger Tests
// =========================================================================

#[test]
fn test_phase2_cbf_barrier_satisfaction_and_denial_mathematics() {
    // Formula: h_{t+1} = (B_t - c) - B_min >= (1 - gamma) * h_t >= 0
    let b_min = 10.0;
    let gamma = 0.5;
    let cbf = ControlBarrierFunction::new(gamma, b_min).expect("cbf new");

    let b_t = 100.0;
    let h_t = b_t - b_min; // 90.0
    let min_allowed = (1.0 - gamma) * h_t; // 45.0
    assert_eq!(min_allowed, 45.0);

    // 1. Satisfaction: cost = 20.0
    // h_{t+1} = (100 - 20) - 10 = 70.0 >= 45.0 >= 0 -> OK
    let res_ok = cbf.evaluate_step(b_t, 20.0, h_t);
    assert!(res_ok.is_ok());
    assert_eq!(res_ok.unwrap(), 70.0);

    // 2. Decay rate exceeded: cost = 60.0
    // h_{t+1} = (100 - 60) - 10 = 30.0 < 45.0 -> ERR
    let res_decay = cbf.evaluate_step(b_t, 60.0, h_t);
    assert!(res_decay.is_err());
    assert!(matches!(res_decay.unwrap_err(), CbfViolation::DecayRateExceeded { .. }));

    // 3. Floor breach: cost = 95.0
    // h_{t+1} = (100 - 95) - 10 = -5.0 < 0 -> ERR
    let res_floor = cbf.evaluate_step(b_t, 95.0, h_t);
    assert!(res_floor.is_err());
    assert!(matches!(res_floor.unwrap_err(), CbfViolation::FloorBreach { .. }));
}

#[test]
fn test_phase2_zero_fiscal_leakage_on_cbf_refusal() {
    let policy = create_test_policy("c4b8e219fa8201de", 0.5, 10.0);
    let ledger = FiscalLedger::new(100.0, 0.5, 10.0).expect("ledger init");
    let pipeline = CageGovernancePipeline::new(policy, ledger, TEST_SECRET);

    let initial_budget = pipeline.ledger().available_budget();
    assert_eq!(initial_budget, 100.0);

    // Submit 10 consecutive requests requesting excessive fuel cost (80.0 each)
    for i in 0..10 {
        let req = GovernanceRequest {
            action_name: "InspectLogs".to_string(),
            principal: "auditor".to_string(),
            resource: "syslog".to_string(),
            parameters: json!({"attempt": i}),
            caller_authority: 2,
            confidence_score: 0.99,
            consensus_score: 0.95,
            fuel_cost: 80.0, // Violates CBF decay bound (h_next = 10.0 < 45.0)
            expected_policy_version: None,
        };

        let res = pipeline.evaluate_action(&req);
        assert!(res.verdict.is_deny());
        assert!(res.seal.is_none());
        assert_eq!(pipeline.ledger().available_budget(), initial_budget);
    }

    // ZERO LEAKAGE: After 10 failed transactions, budget is STRICTLY 100.0
    assert_eq!(pipeline.ledger().available_budget(), 100.0);
    assert_eq!(pipeline.ledger().active_reservation_count(), 0);
}

#[test]
fn test_phase2_lifo_fiscal_fuel_rollback() {
    let ledger = FiscalLedger::new(100.0, 0.5, 10.0).expect("ledger init");

    // Pre-reserve transaction A (10.0 fuel)
    let receipt_a = ledger.pre_reserve(10.0, "debit_A").expect("reserve A");
    assert_eq!(receipt_a.remaining_budget, 90.0);
    assert_eq!(ledger.available_budget(), 90.0);

    // Pre-reserve transaction B (15.0 fuel)
    let receipt_b = ledger.pre_reserve(15.0, "debit_B").expect("reserve B");
    assert_eq!(receipt_b.remaining_budget, 75.0);
    assert_eq!(ledger.available_budget(), 75.0);

    // Downstream actuation B fails -> rollback reservation B
    let restored_b = ledger.rollback_reservation(&receipt_b.debit_id).expect("rollback B");
    assert_eq!(restored_b, 90.0);
    assert_eq!(ledger.available_budget(), 90.0);

    // Rolling back already rolled-back B fails
    assert!(ledger.rollback_reservation(&receipt_b.debit_id).is_err());

    // Actuation A succeeds -> commit reservation A
    assert!(ledger.commit(&receipt_a.debit_id).is_ok());

    // Once committed, reservation A cannot be rolled back
    assert!(ledger.rollback_reservation(&receipt_a.debit_id).is_err());
    assert_eq!(ledger.available_budget(), 90.0);
}

#[test]
fn test_phase2_lifo_stack_rollback_order() {
    let ledger = FiscalLedger::new(100.0, 0.5, 10.0).expect("ledger init");

    let _r1 = ledger.pre_reserve(5.0, "step_1").unwrap();
    let _r2 = ledger.pre_reserve(10.0, "step_2").unwrap();
    let _r3 = ledger.pre_reserve(15.0, "step_3").unwrap();
    assert_eq!(ledger.available_budget(), 70.0);

    // Rollback LIFO: should pop step_3 first
    let (debit_id, budget_after_3) = ledger.rollback_lifo().unwrap();
    assert_eq!(debit_id, "step_3");
    assert_eq!(budget_after_3, 85.0);

    // Next LIFO: should pop step_2
    let (debit_id2, budget_after_2) = ledger.rollback_lifo().unwrap();
    assert_eq!(debit_id2, "step_2");
    assert_eq!(budget_after_2, 95.0);
}

// =========================================================================
// 3. Routing Seal Generation, Signature, & Single-Use Consumption Tests
// =========================================================================

#[test]
fn test_routing_seal_signature_and_30s_ttl_enforcement() {
    let signer = RoutingSealSigner::new(TEST_SECRET, "c4b8e219fa8201de");
    let now = 1793584800_u64;

    let action_digest = compute_action_digest("InspectLogs", &json!({"lines": 50}));
    let seal = signer.issue_seal(&action_digest, now);

    // 1. Structure assertions
    assert_eq!(seal.policy_version_id, "c4b8e219fa8201de");
    assert_eq!(seal.action_digest, action_digest);
    assert_eq!(seal.issued_at, now);
    assert_eq!(seal.expires_at, now + 30);
    assert_eq!(seal.ttl_seconds(), 30);
    assert!(seal.validate_format());

    // 2. Signature verification
    assert!(signer.verify_signature(&seal));

    // 3. Tampering detection
    let mut tampered_seal = seal.clone();
    tampered_seal.action_digest = "0000000000000000000000000000000000000000000000000000000000000000".to_string();
    assert!(!signer.verify_signature(&tampered_seal));

    // 4. Expiration at t = now + 31s
    assert!(!seal.is_expired(now + 29));
    assert!(!seal.is_expired(now + 30));
    assert!(seal.is_expired(now + 31));

    let validation_expired = signer.validate_seal_properties(&seal, &action_digest, now + 31);
    assert!(matches!(validation_expired, Err(SealRejection::Expired { .. })));
}

#[test]
fn test_routing_seal_single_use_atomic_consumption() {
    let signer = RoutingSealSigner::new(TEST_SECRET, "c4b8e219fa8201de");
    let now = 1793584800_u64;

    let action_digest = compute_action_digest("InspectLogs", &json!({}));
    let seal = signer.issue_seal(&action_digest, now);

    assert_eq!(signer.consumed_count(), 0);
    assert!(!signer.is_seal_consumed(&seal.seal_id));

    // First consumption: MUST SUCCEED
    let res1 = signer.validate_and_consume(&seal, &action_digest, now + 5);
    assert!(res1.is_ok());
    assert_eq!(signer.consumed_count(), 1);
    assert!(signer.is_seal_consumed(&seal.seal_id));

    // Second consumption (REPLAY ATTACK): MUST FAIL CLOSED
    let res2 = signer.validate_and_consume(&seal, &action_digest, now + 6);
    assert!(res2.is_err());
    assert!(matches!(res2.unwrap_err(), SealRejection::AlreadyConsumed(_)));
}

// =========================================================================
// 4. Parameter Clamping & NARROW Verdict Tests
// =========================================================================

#[test]
fn test_narrow_verdict_parameter_clamping_with_routing_seal() {
    let policy = create_test_policy("c4b8e219fa8201de", 0.5, 10.0);
    let ledger = FiscalLedger::new(100.0, 0.5, 10.0).expect("ledger init");
    let pipeline = CageGovernancePipeline::new(policy, ledger, TEST_SECRET);

    // Initial request triggers UCA-2 breach ($15,000 > $10,000)
    let request = GovernanceRequest {
        action_name: "ExecuteStockOrder".to_string(),
        principal: "system-trader".to_string(),
        resource: "NASDAQ:AAPL".to_string(),
        parameters: json!({"order_value_usd": 15000.0}),
        caller_authority: 2,
        confidence_score: 0.99,
        consensus_score: 0.95,
        fuel_cost: 5.0,
        expected_policy_version: None,
    };

    // Narrower clamps order value to maximum permissible $10,000
    let narrower = |req: &GovernanceRequest| -> Option<serde_json::Value> {
        if req.action_name == "ExecuteStockOrder" {
            let mut clamped = req.parameters.clone();
            clamped["order_value_usd"] = json!(9999.0);
            Some(clamped)
        } else {
            None
        }
    };

    let result = pipeline.evaluate_with_narrowing(&request, narrower);

    // Assert NARROW verdict
    assert!(matches!(result.verdict, GovernanceVerdict::Narrow { .. }));
    if let GovernanceVerdict::Narrow { clamped_params } = &result.verdict {
        assert_eq!(clamped_params["order_value_usd"], 9999.0);
    }

    // Seal must be issued binding the CLAMPED parameters
    assert!(result.seal.is_some());
    let seal = result.seal.unwrap();
    let clamped_digest = compute_action_digest("ExecuteStockOrder", &json!({"order_value_usd": 9999.0}));
    assert_eq!(seal.action_digest, clamped_digest);
    assert!(result.commit_receipt.is_some());
}

// =========================================================================
// 5. Version Pinning Conflict (HTTP 409) Tests
// =========================================================================

#[test]
fn test_policy_version_pinning_drift_conflict() {
    let policy = create_test_policy("c4b8e219fa8201de", 0.5, 10.0);
    let ledger = FiscalLedger::new(100.0, 0.5, 10.0).expect("ledger init");
    let pipeline = CageGovernancePipeline::new(policy, ledger, TEST_SECRET);

    let req = GovernanceRequest {
        action_name: "InspectLogs".to_string(),
        principal: "operator".to_string(),
        resource: "syslog".to_string(),
        parameters: json!({}),
        caller_authority: 2,
        confidence_score: 0.99,
        consensus_score: 0.95,
        fuel_cost: 2.0,
        expected_policy_version: Some("stale_version_0000".to_string()),
    };

    let result = pipeline.evaluate_action(&req);
    assert!(result.verdict.is_deny());
    if let GovernanceVerdict::Deny { reason, .. } = result.verdict {
        assert!(reason.contains("Policy version drift detected"));
    } else {
        panic!("Expected version conflict rejection");
    }
}
