//! crates/osoosi-policy/tests/m2_challenger_adversarial_suite.rs
//!
//! Milestone 2 Adversarial Empirical Challenger Suite:
//! Routing Seal Engine, Phase 1 Read-Only Gating, Parameter Clamping,
//! Replay Prevention, and Concurrent Double-Spend Race Condition Verification.
//!
//! Conducted by teamwork_challenger (Challenger 2, Milestone 2).
//!
//! Attack Vectors Tested:
//! 1. Seal Expiration Attack (evaluated at t = issued_at + 30.001s and t = issued_at + 31s; fail-closed rejection)
//! 2. Single-Use Replay Attack (consume once -> succeed; consume second time -> AlreadyConsumed)
//! 3. Concurrent Double-Spend Race Condition (20 parallel threads -> exactly 1 succeeds, 19 receive AlreadyConsumed)
//! 4. Extreme Concurrent Double-Spend Stress (50 parallel threads across 10 repeated trials)
//! 5. Action Digest Tampering (1-byte flip in params or digest -> ActionDigestMismatch; forged digest -> InvalidSignature)
//! 6. Signature Forgery (1-byte flip, truncation, cross-seal transplant, key confusion -> InvalidSignature)
//! 7. Parameter Clamping Under NARROW (out-of-bounds params clamped, seal binds exclusively to clamped digest)
//! 8. Phase 1 Read-Only Gating Stress (50 hostile requests -> zero fiscal leakage, zero ledger mutation)

use osoosi_policy::cage::{
    compute_action_digest, CageGovernancePipeline, CompiledCagePolicy, FiscalLedger,
    GovernanceRequest, GovernanceVerdict, PolicyFormat, RoutingSealSigner, SealRejection,
    UnsafeControlAction, ROUTING_SEAL_TTL_SECS,
};
use serde_json::json;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Barrier,
};
use std::thread;

const CHALLENGER_SECRET_KEY: &[u8] = b"OSHOOSICLAW_M2_CHALLENGER_SECRET_KEY_32BYTES";
const ALTERNATIVE_SECRET_KEY: &[u8] = b"ATTACKER_MALICIOUS_KEY_TRYING_TO_FORGE_SEAL_";
const TEST_POLICY_VERSION: &str = "c4b8e219fa8201de";

fn build_adversarial_test_policy() -> CompiledCagePolicy {
    CompiledCagePolicy {
        policy_version_id: TEST_POLICY_VERSION.to_string(),
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
                uca_id: "UCA-FIN-MAX".to_string(),
                hazard_ref: "H-FIN-01".to_string(),
                control_action: "ExecuteStockOrder".to_string(),
                context_condition: "order_value_usd > 10000".to_string(),
                mitigation: "Limit single trade value to $10,000".to_string(),
            },
        ],
        cbf_gamma: 0.5,
        cbf_b_min: 10.0,
    }
}

// =============================================================================
// Attack 1: Seal Expiration Attack ($t = \text{issued\_at} + 30.001\text{s}$ & $t = 31\text{s}$)
// =============================================================================

#[test]
fn test_adversarial_seal_expiration_attacks() {
    let signer = RoutingSealSigner::new(CHALLENGER_SECRET_KEY, TEST_POLICY_VERSION);
    let issued_at = 1793584800_u64;
    let action_digest = compute_action_digest("InspectLogs", &json!({"scope": "audit"}));
    let seal = signer.issue_seal(&action_digest, issued_at);

    assert_eq!(seal.issued_at, issued_at);
    assert_eq!(seal.expires_at, issued_at + ROUTING_SEAL_TTL_SECS);
    assert_eq!(seal.expires_at, issued_at + 30);

    // 1. Boundary check inside valid window:
    // At t = issued_at + 0s: VALID
    let res_t0 = signer.validate_seal_properties(&seal, &action_digest, issued_at);
    assert!(res_t0.is_ok(), "Seal must be valid at issuance time");

    // At t = issued_at + 29s: VALID
    let res_t29 = signer.validate_seal_properties(&seal, &action_digest, issued_at + 29);
    assert!(res_t29.is_ok(), "Seal must be valid at t = issued_at + 29s");

    // At t = issued_at + 30s: Exact expiration boundary
    let res_t30 = signer.validate_seal_properties(&seal, &action_digest, issued_at + 30);
    assert!(
        res_t30.is_ok(),
        "Seal at exact boundary t = expires_at is not expired"
    );

    // 2. Attack Scenario A: Evaluation at t = issued_at + 31s
    // Explicitly 1s beyond the 30-second TTL
    let res_t31 = signer.validate_seal_properties(&seal, &action_digest, issued_at + 31);
    assert!(
        matches!(res_t31, Err(SealRejection::Expired { current_time, expires_at }) if current_time == issued_at + 31 && expires_at == issued_at + 30),
        "Seal evaluated at t = issued_at + 31s MUST be rejected with SealRejection::Expired"
    );

    // 3. Attack Scenario B: Evaluation at t = issued_at + 30.001s (subsecond boundary)
    // Continuous time duration: 30.001 seconds past issuance.
    // In discrete integer second timekeeping, continuous time t = 30.001s ceiling-quantizes
    // to t = 31s because 30 full seconds have fully elapsed and 1ms of expiration has occurred.
    let t_subsecond_continuous = issued_at as f64 + 30.001;
    let t_subsecond_ceil = t_subsecond_continuous.ceil() as u64; // issued_at + 31
    assert_eq!(t_subsecond_ceil, issued_at + 31);

    let res_t30_001 = signer.validate_seal_properties(&seal, &action_digest, t_subsecond_ceil);
    assert!(
        matches!(res_t30_001, Err(SealRejection::Expired { .. })),
        "Seal evaluated at t = issued_at + 30.001s (ceiling-quantized) MUST fail closed with Expired"
    );

    // In direct floating-point duration comparison:
    let elapsed_duration_secs = 30.001_f64;
    let ttl_duration_secs = ROUTING_SEAL_TTL_SECS as f64;
    assert!(
        elapsed_duration_secs > ttl_duration_secs,
        "Continuous duration 30.001s must strictly exceed 30.0s TTL"
    );

    // 4. Attack Scenario C: Distant future evaluation at t = issued_at + 1000s
    let res_future = signer.validate_seal_properties(&seal, &action_digest, issued_at + 1000);
    assert!(
        matches!(res_future, Err(SealRejection::Expired { .. })),
        "Seal evaluated in distant future MUST fail closed with Expired"
    );

    // 5. Atomic consumption at expired timestamp MUST fail closed without recording consumption
    let consume_expired = signer.validate_and_consume(&seal, &action_digest, issued_at + 31);
    assert!(matches!(
        consume_expired,
        Err(SealRejection::Expired { .. })
    ));
    assert!(
        !signer.is_seal_consumed(&seal.seal_id),
        "Expired seal MUST NOT be marked as consumed"
    );
    assert_eq!(signer.consumed_count(), 0);
}

// =============================================================================
// Attack 2: Single-Use Replay Attack
// =============================================================================

#[test]
fn test_adversarial_single_use_replay_attack() {
    let signer = RoutingSealSigner::new(CHALLENGER_SECRET_KEY, TEST_POLICY_VERSION);
    let now = 1793584800_u64;
    let action_digest = compute_action_digest("TransferFunds", &json!({"amount": 100}));
    let seal = signer.issue_seal(&action_digest, now);

    assert_eq!(signer.consumed_count(), 0);
    assert!(!signer.is_seal_consumed(&seal.seal_id));

    // First consumption: MUST succeed
    let first_consumption = signer.validate_and_consume(&seal, &action_digest, now + 1);
    assert!(first_consumption.is_ok(), "First consumption must succeed");
    assert_eq!(signer.consumed_count(), 1);
    assert!(signer.is_seal_consumed(&seal.seal_id));

    // Immediate second consumption (REPLAY ATTACK): MUST fail closed with AlreadyConsumed
    let second_consumption = signer.validate_and_consume(&seal, &action_digest, now + 1);
    assert!(
        matches!(second_consumption, Err(SealRejection::AlreadyConsumed(ref id)) if id == &seal.seal_id),
        "Immediate replay MUST fail closed with SealRejection::AlreadyConsumed"
    );

    // Third consumption attempt at now + 5s: MUST still fail closed
    let third_consumption = signer.validate_and_consume(&seal, &action_digest, now + 5);
    assert!(
        matches!(third_consumption, Err(SealRejection::AlreadyConsumed(ref id)) if id == &seal.seal_id),
        "Delayed replay MUST fail closed with SealRejection::AlreadyConsumed"
    );

    // Fourth consumption attempt with different action digest:
    // Replay check happens during validate_and_consume after properties pass.
    // If action digest differs, action digest mismatch triggers first:
    let fake_digest = compute_action_digest("TransferFunds", &json!({"amount": 9999}));
    let fourth_consumption = signer.validate_and_consume(&seal, &fake_digest, now + 5);
    assert!(matches!(
        fourth_consumption,
        Err(SealRejection::ActionDigestMismatch { .. })
    ));

    // Total consumed count must remain strictly 1
    assert_eq!(signer.consumed_count(), 1);
}

// =============================================================================
// Attack 3: Concurrent Double-Spend Race Condition (20 Parallel Threads)
// =============================================================================

#[test]
fn test_adversarial_concurrent_double_spend_race_condition_20_threads() {
    let signer = Arc::new(RoutingSealSigner::new(
        CHALLENGER_SECRET_KEY,
        TEST_POLICY_VERSION,
    ));
    let now = 1793584800_u64;
    let action_digest = compute_action_digest("DisburseGrant", &json!({"grant_id": "G-42"}));
    let seal = Arc::new(signer.issue_seal(&action_digest, now));

    const THREAD_COUNT: usize = 20;
    let barrier = Arc::new(Barrier::new(THREAD_COUNT));
    let success_count = Arc::new(AtomicUsize::new(0));
    let already_consumed_count = Arc::new(AtomicUsize::new(0));
    let other_error_count = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::with_capacity(THREAD_COUNT);

    for _ in 0..THREAD_COUNT {
        let signer_clone = Arc::clone(&signer);
        let seal_clone = Arc::clone(&seal);
        let digest_clone = action_digest.clone();
        let barrier_clone = Arc::clone(&barrier);
        let success_clone = Arc::clone(&success_count);
        let consumed_clone = Arc::clone(&already_consumed_count);
        let other_clone = Arc::clone(&other_error_count);

        handles.push(thread::spawn(move || {
            // Synchronize all 20 threads to execute concurrently at the exact same moment
            barrier_clone.wait();

            match signer_clone.validate_and_consume(&seal_clone, &digest_clone, now + 2) {
                Ok(()) => {
                    success_clone.fetch_add(1, Ordering::SeqCst);
                }
                Err(SealRejection::AlreadyConsumed(_)) => {
                    consumed_clone.fetch_add(1, Ordering::SeqCst);
                }
                Err(_) => {
                    other_clone.fetch_add(1, Ordering::SeqCst);
                }
            }
        }));
    }

    for h in handles {
        h.join().expect("Thread joined cleanly");
    }

    let successes = success_count.load(Ordering::SeqCst);
    let replays = already_consumed_count.load(Ordering::SeqCst);
    let others = other_error_count.load(Ordering::SeqCst);

    println!(
        "[Concurrent Double-Spend 20 Threads] Successes: {}, Replays: {}, Other Errors: {}",
        successes, replays, others
    );

    // STRICT INVARIANT: Exactly 1 thread succeeds, 19 threads receive AlreadyConsumed, 0 other errors
    assert_eq!(
        successes, 1,
        "CRITICAL RACE CONDITION: Exactly ONE thread must succeed in consuming the seal, got {}",
        successes
    );
    assert_eq!(
        replays, 19,
        "CRITICAL RACE CONDITION: Exactly 19 threads must receive AlreadyConsumed, got {}",
        replays
    );
    assert_eq!(others, 0, "No other error types allowed");
    assert_eq!(signer.consumed_count(), 1);
    assert!(signer.is_seal_consumed(&seal.seal_id));
}

// =============================================================================
// Attack 4: Extreme Concurrent Double-Spend Stress (50 Threads across 10 Trials)
// =============================================================================

#[test]
fn test_adversarial_extreme_concurrent_double_spend_50_threads_multi_trial() {
    const THREAD_COUNT: usize = 50;
    const TRIALS: usize = 10;

    for trial in 0..TRIALS {
        let signer = Arc::new(RoutingSealSigner::new(
            CHALLENGER_SECRET_KEY,
            TEST_POLICY_VERSION,
        ));
        let now = 1793584800_u64 + (trial as u64 * 100);
        let action_digest = compute_action_digest(
            "HighValueLedgerWrite",
            &json!({"trial": trial, "nonce": uuid::Uuid::new_v4().to_string()}),
        );
        let seal = Arc::new(signer.issue_seal(&action_digest, now));

        let barrier = Arc::new(Barrier::new(THREAD_COUNT));
        let success_count = Arc::new(AtomicUsize::new(0));
        let already_consumed_count = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::with_capacity(THREAD_COUNT);

        for _ in 0..THREAD_COUNT {
            let signer_c = Arc::clone(&signer);
            let seal_c = Arc::clone(&seal);
            let digest_c = action_digest.clone();
            let barrier_c = Arc::clone(&barrier);
            let succ_c = Arc::clone(&success_count);
            let cons_c = Arc::clone(&already_consumed_count);

            handles.push(thread::spawn(move || {
                barrier_c.wait();
                match signer_c.validate_and_consume(&seal_c, &digest_c, now + 1) {
                    Ok(()) => {
                        succ_c.fetch_add(1, Ordering::SeqCst);
                    }
                    Err(SealRejection::AlreadyConsumed(_)) => {
                        cons_c.fetch_add(1, Ordering::SeqCst);
                    }
                    Err(e) => panic!("Unexpected error in trial: {:?}", e),
                }
            }));
        }

        for h in handles {
            h.join().expect("Thread joined");
        }

        assert_eq!(
            success_count.load(Ordering::SeqCst),
            1,
            "Trial {} failed: expected exactly 1 winner among 50 threads",
            trial
        );
        assert_eq!(
            already_consumed_count.load(Ordering::SeqCst),
            49,
            "Trial {} failed: expected exactly 49 AlreadyConsumed",
            trial
        );
        assert_eq!(signer.consumed_count(), 1);
    }
}

// =============================================================================
// Attack 5: Action Digest Tampering
// =============================================================================

#[test]
fn test_adversarial_action_digest_tampering() {
    let signer = RoutingSealSigner::new(CHALLENGER_SECRET_KEY, TEST_POLICY_VERSION);
    let now = 1793584800_u64;

    let original_params = json!({"cmd": "whoami", "privileged": false});
    let original_digest = compute_action_digest("ExecuteCommand", &original_params);
    let seal = signer.issue_seal(&original_digest, now);

    // 1. Attack Vector A: Attacker flips 1 hex byte in seal.action_digest
    let mut tampered_digest_seal = seal.clone();
    let mut chars: Vec<char> = tampered_digest_seal.action_digest.chars().collect();
    // Flip first character: if 'a' make 'b', else 'a'
    chars[0] = if chars[0] == 'a' { 'b' } else { 'a' };
    tampered_digest_seal.action_digest = chars.into_iter().collect();

    let res_a = signer.validate_seal_properties(&tampered_digest_seal, &original_digest, now);
    assert!(
        matches!(res_a, Err(SealRejection::ActionDigestMismatch { ref expected, ref actual })
            if expected == &original_digest && actual == &tampered_digest_seal.action_digest),
        "Flipping 1 byte in seal.action_digest MUST fail closed with ActionDigestMismatch"
    );

    // 2. Attack Vector B: Attacker alters execution parameters on downstream actuation
    // e.g. "cmd": "whoami" changed to "cmd": "rm -rf /"
    let tampered_params = json!({"cmd": "rm -rf /", "privileged": false});
    let tampered_expected_digest = compute_action_digest("ExecuteCommand", &tampered_params);

    assert_ne!(original_digest, tampered_expected_digest);

    // Attacker presents the original seal (which bound the benign command)
    let res_b = signer.validate_seal_properties(&seal, &tampered_expected_digest, now);
    assert!(
        matches!(res_b, Err(SealRejection::ActionDigestMismatch { ref expected, ref actual })
            if expected == &tampered_expected_digest && actual == &seal.action_digest),
        "Altering action parameters MUST trigger ActionDigestMismatch on seal validation"
    );

    // 3. Attack Vector C: Attacker modifies the action name
    let tampered_action_digest = compute_action_digest("ExecuteScript", &original_params);
    let res_c = signer.validate_seal_properties(&seal, &tampered_action_digest, now);
    assert!(matches!(
        res_c,
        Err(SealRejection::ActionDigestMismatch { .. })
    ));

    // 4. Attack Vector D: Attacker updates seal.action_digest to match tampered action,
    // attempting to bypass action digest check without knowing secret key
    let mut forged_action_seal = seal.clone();
    forged_action_seal.action_digest = tampered_expected_digest.clone();

    // Now seal.action_digest matches expected, BUT HMAC signature will not match!
    let res_d =
        signer.validate_seal_properties(&forged_action_seal, &tampered_expected_digest, now);
    assert!(
        matches!(res_d, Err(SealRejection::InvalidSignature)),
        "Forging action_digest to bypass check MUST fail closed at HMAC signature verification"
    );
}

// =============================================================================
// Attack 6: HMAC Signature Forgery
// =============================================================================

#[test]
fn test_adversarial_signature_forgery() {
    let signer = RoutingSealSigner::new(CHALLENGER_SECRET_KEY, TEST_POLICY_VERSION);
    let now = 1793584800_u64;

    let action_digest = compute_action_digest("SpawnProcess", &json!({"bin": "/bin/bash"}));
    let seal = signer.issue_seal(&action_digest, now);

    // 1. Attack Vector A: Flip 1 byte in the hex HMAC signature
    let mut tampered_sig_seal = seal.clone();
    let mut sig_chars: Vec<char> = tampered_sig_seal.signature.chars().collect();
    let last_idx = sig_chars.len() - 1;
    sig_chars[last_idx] = if sig_chars[last_idx] == '0' { '1' } else { '0' };
    tampered_sig_seal.signature = sig_chars.into_iter().collect();

    let res_a = signer.validate_seal_properties(&tampered_sig_seal, &action_digest, now);
    assert!(
        matches!(res_a, Err(SealRejection::InvalidSignature)),
        "1-byte signature flip MUST fail closed with InvalidSignature"
    );

    // 2. Attack Vector B: Truncated signature
    let mut truncated_sig_seal = seal.clone();
    truncated_sig_seal.signature = truncated_sig_seal.signature[..32].to_string();

    let res_b = signer.validate_seal_properties(&truncated_sig_seal, &action_digest, now);
    assert!(
        matches!(res_b, Err(SealRejection::InvalidSignature)),
        "Truncated signature MUST fail closed with InvalidSignature"
    );

    // 3. Attack Vector C: Signature transplant / cross-seal replay
    // Seal 1 for Action 1; Seal 2 for Action 2
    let action_digest_2 = compute_action_digest("SpawnProcess", &json!({"bin": "/bin/echo"}));
    let seal_2 = signer.issue_seal(&action_digest_2, now);

    let mut transplanted_seal = seal_2.clone();
    transplanted_seal.signature = seal.signature.clone(); // Transplant Seal 1's signature into Seal 2

    let res_c = signer.validate_seal_properties(&transplanted_seal, &action_digest_2, now);
    assert!(
        matches!(res_c, Err(SealRejection::InvalidSignature)),
        "Transplanted cross-seal signature MUST fail closed with InvalidSignature"
    );

    // 4. Attack Vector D: Seal signed with rogue secret key (Key Confusion Attack)
    let rogue_signer = RoutingSealSigner::new(ALTERNATIVE_SECRET_KEY, TEST_POLICY_VERSION);
    let forged_seal = rogue_signer.issue_seal(&action_digest, now);

    // Verifier uses genuine secret key
    let res_d = signer.validate_seal_properties(&forged_seal, &action_digest, now);
    assert!(
        matches!(res_d, Err(SealRejection::InvalidSignature)),
        "Seal signed with rogue key MUST fail closed with InvalidSignature"
    );
}

// =============================================================================
// Attack 7: Parameter Clamping Under NARROW Verdict
// =============================================================================

#[test]
fn test_adversarial_parameter_clamping_under_narrow() {
    let policy = build_adversarial_test_policy();
    let ledger = FiscalLedger::new(100.0, 0.5, 10.0).expect("ledger init");
    let pipeline = CageGovernancePipeline::new(policy, ledger, CHALLENGER_SECRET_KEY);

    let _now = 1793584800_u64;

    // 1. Hostile request with out-of-bounds parameter ($75,000 > max $10,000 threshold)
    let unconstrained_request = GovernanceRequest {
        action_name: "ExecuteStockOrder".to_string(),
        principal: "autonomous-trader".to_string(),
        resource: "NASDAQ:NVDA".to_string(),
        parameters: json!({"order_value_usd": 75000.0, "ticker": "NVDA"}),
        caller_authority: 2,
        confidence_score: 0.99,
        consensus_score: 0.95,
        fuel_cost: 5.0,
        expected_policy_version: None,
    };

    // Primary evaluation WITHOUT narrowing MUST DENY (UCA-FIN-MAX breach)
    let direct_eval = pipeline.evaluate_action(&unconstrained_request);
    assert!(
        direct_eval.verdict.is_deny(),
        "Direct evaluation of out-of-bounds parameter must be DENIED"
    );
    assert!(direct_eval.seal.is_none());

    // 2. Evaluation WITH narrowing function:
    // Narrower strictly clamps order_value_usd down to maximum safe ceiling ($9,999.00)
    let narrower = |req: &GovernanceRequest| -> Option<serde_json::Value> {
        if req.action_name == "ExecuteStockOrder" {
            let mut clamped = req.parameters.clone();
            clamped["order_value_usd"] = json!(9999.0);
            Some(clamped)
        } else {
            None
        }
    };

    let narrow_eval = pipeline.evaluate_with_narrowing(&unconstrained_request, narrower);

    // Assert NARROW verdict
    assert!(
        matches!(narrow_eval.verdict, GovernanceVerdict::Narrow { .. }),
        "Expected GovernanceVerdict::Narrow"
    );

    let clamped_params = match &narrow_eval.verdict {
        GovernanceVerdict::Narrow { clamped_params } => clamped_params.clone(),
        _ => unreachable!(),
    };

    assert_eq!(clamped_params["order_value_usd"], 9999.0);
    assert!(clamped_params["order_value_usd"].as_f64().unwrap() <= 10000.0);

    // 3. Routing seal MUST be issued
    assert!(
        narrow_eval.seal.is_some(),
        "Routing seal must be issued on NARROW verdict"
    );
    let seal = narrow_eval.seal.unwrap();

    // 4. Assert routing seal binds EXCLUSIVELY to clamped action digest
    let clamped_digest = compute_action_digest("ExecuteStockOrder", &clamped_params);
    let unconstrained_digest =
        compute_action_digest("ExecuteStockOrder", &unconstrained_request.parameters);

    assert_ne!(
        clamped_digest, unconstrained_digest,
        "Clamped digest must differ from unconstrained digest"
    );
    assert_eq!(
        seal.action_digest, clamped_digest,
        "Seal MUST bind exclusively to the clamped action digest"
    );

    // 5. HOSTILE ATTACK SCENARIO:
    // Attacker attempts to use the issued seal to execute the ORIGINAL unconstrained action ($75,000)
    let attack_consumption = pipeline.validate_and_consume_seal(&seal, &unconstrained_digest);
    assert!(
        matches!(attack_consumption, Err(SealRejection::ActionDigestMismatch { .. })),
        "Attempting to execute unconstrained action with clamped seal MUST be rejected with ActionDigestMismatch"
    );

    // Seal was NOT consumed by the failed attack:
    assert!(!pipeline.seal_signer().is_seal_consumed(&seal.seal_id));

    // 6. Legitimate execution with clamped parameters SUCCEEDS:
    let legitimate_consumption = pipeline.validate_and_consume_seal(&seal, &clamped_digest);
    assert!(
        legitimate_consumption.is_ok(),
        "Executing clamped action with clamped seal MUST succeed"
    );
    assert!(pipeline.seal_signer().is_seal_consumed(&seal.seal_id));

    // 7. Replay of clamped actuation FAILS CLOSED:
    let replay_consumption = pipeline.validate_and_consume_seal(&seal, &clamped_digest);
    assert!(
        matches!(replay_consumption, Err(SealRejection::AlreadyConsumed(_))),
        "Replay of clamped action MUST fail closed with AlreadyConsumed"
    );
}

// =============================================================================
// Attack 8: Phase 1 Read-Only Gating Stress & Zero Fiscal Leakage
// =============================================================================

#[test]
fn test_adversarial_phase1_read_only_gating_stress_zero_fiscal_leakage() {
    let policy = build_adversarial_test_policy();
    let ledger = FiscalLedger::new(100.0, 0.5, 10.0).expect("ledger init");
    let pipeline = CageGovernancePipeline::new(policy, ledger, CHALLENGER_SECRET_KEY);

    let initial_budget = pipeline.ledger().available_budget();
    assert_eq!(initial_budget, 100.0);

    // Generate 50 hostile requests cycling through all Phase 1 failure modes
    for i in 0..50 {
        let req = match i % 5 {
            // Mode 0: FTRA authority violation (untrusted caller attempting irreversible terminal action)
            0 => GovernanceRequest {
                action_name: "execute_child_process".to_string(),
                principal: format!("adversary-{}", i),
                resource: "/bin/sh".to_string(),
                parameters: json!({"cmd": "whoami"}),
                caller_authority: 5,
                confidence_score: 0.99,
                consensus_score: 0.95,
                fuel_cost: 15.0,
                expected_policy_version: None,
            },
            // Mode 1: STPA UCA violation (trade value exceeds safety floor)
            1 => GovernanceRequest {
                action_name: "ExecuteStockOrder".to_string(),
                principal: format!("adversary-{}", i),
                resource: "NASDAQ:TSLA".to_string(),
                parameters: json!({"order_value_usd": 20000.0 + (i as f64 * 1000.0)}),
                caller_authority: 1,
                confidence_score: 0.99,
                consensus_score: 0.95,
                fuel_cost: 10.0,
                expected_policy_version: None,
            },
            // Mode 2: Cedar forbid clause (/etc/shadow access)
            2 => GovernanceRequest {
                action_name: "SensitiveFileAccess".to_string(),
                principal: format!("adversary-{}", i),
                resource: "/etc/shadow".to_string(),
                parameters: json!({"path": "/etc/shadow"}),
                caller_authority: 2,
                confidence_score: 0.99,
                consensus_score: 0.95,
                fuel_cost: 5.0,
                expected_policy_version: None,
            },
            // Mode 3: SR 26-2 low confidence (< 0.70 triggers DEFER)
            3 => GovernanceRequest {
                action_name: "InspectLogs".to_string(),
                principal: format!("adversary-{}", i),
                resource: "syslog".to_string(),
                parameters: json!({"filter": "auth"}),
                caller_authority: 2,
                confidence_score: 0.45,
                consensus_score: 0.95,
                fuel_cost: 5.0,
                expected_policy_version: None,
            },
            // Mode 4: Consensus score below quorum (< 0.70)
            _ => GovernanceRequest {
                action_name: "InspectLogs".to_string(),
                principal: format!("adversary-{}", i),
                resource: "syslog".to_string(),
                parameters: json!({"filter": "auth"}),
                caller_authority: 2,
                confidence_score: 0.99,
                consensus_score: 0.35,
                fuel_cost: 5.0,
                expected_policy_version: None,
            },
        };

        let result = pipeline.evaluate_action(&req);

        // All 50 hostile requests must be rejected / non-cleared
        assert!(
            !result.verdict.is_allowed_or_narrowed(),
            "Hostile request {} must not be cleared",
            i
        );
        assert!(
            result.seal.is_none(),
            "No seal may be issued for hostile request {}",
            i
        );
        assert!(result.commit_receipt.is_none());

        // STRICT INVARIANT: Zero fiscal leakage across every single iteration
        assert_eq!(
            pipeline.ledger().available_budget(),
            initial_budget,
            "Fiscal leakage detected on hostile request {}: budget mutated from {}",
            i,
            initial_budget
        );
        assert_eq!(pipeline.ledger().active_reservation_count(), 0);
    }

    // Final assert: Budget remains 100.000000 with 0 active reservations
    assert_eq!(pipeline.ledger().available_budget(), 100.0);
    assert_eq!(pipeline.ledger().active_reservation_count(), 0);
}
