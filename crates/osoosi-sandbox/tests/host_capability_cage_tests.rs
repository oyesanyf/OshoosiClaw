//! Integration Tests for Host Capability Gate Routing Seal Enforcement (`NoDirectBind`)
//!
//! Validates:
//! 1. Authentic routing seal validation and atomic consumption.
//! 2. Single-use replay blocking (idempotency / double-spend prevention).
//! 3. Strict TTL window expiration (>30s) rejection.
//! 4. Tampered / mismatched action parameter rejection.
//! 5. Forged / invalid cryptographic HMAC-SHA256 signature rejection.
//! 6. Configurable substrate secrets via builder `with_substrate_secret`.
//! 7. Unsealed execution rejection failing closed on `NoDirectBind` violation.
//! 8. 20-thread concurrent double-spend race condition (exactly 1 success, 19 failures).
//! 9. RFC 8785 JCS canonical formatting and action digest determinism.
//! 10. Empty / missing seal ID rejection.

use osoosi_sandbox::host_capability_gate::{
    compute_action_digest, sign_routing_seal, GateError, HostCapabilityGate,
    DEFAULT_CAGE_SUBSTRATE_SECRET,
};
use osoosi_types::cage::RoutingSeal;
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

/// Helper function to construct a valid signed routing seal.
fn make_test_seal(
    secret: &[u8],
    seal_id: &str,
    action_name: &str,
    params: &serde_json::Value,
    policy_version_id: &str,
    issued_at: u64,
    ttl_seconds: u64,
) -> RoutingSeal {
    let action_digest = compute_action_digest(action_name, params);
    let signature = sign_routing_seal(
        secret,
        seal_id,
        &action_digest,
        policy_version_id,
        issued_at,
    );
    RoutingSeal {
        seal_id: seal_id.to_string(),
        policy_version_id: policy_version_id.to_string(),
        action_digest,
        issued_at,
        expires_at: issued_at + ttl_seconds,
        signature,
    }
}

#[test]
fn test_valid_seal_consumed_successfully() {
    let gate = HostCapabilityGate::default();
    let params = json!({"path": "/etc/config.json", "mode": "read"});
    let seal = make_test_seal(
        DEFAULT_CAGE_SUBSTRATE_SECRET,
        "seal_001_valid",
        "ReadFile",
        &params,
        "a1b2c3d4e5f67890",
        1_000_000,
        30,
    );

    let receipt = gate
        .validate_and_consume_seal(&seal, "ReadFile", &params, Some(1_000_010))
        .expect("Valid routing seal must be consumed successfully");

    assert_eq!(receipt.status, "CONSUMED");
    assert_eq!(receipt.seal_id, "seal_001_valid");
    assert_eq!(receipt.action_name, "ReadFile");
    assert_eq!(receipt.consumed_at_utc, 1_000_010);
    assert_eq!(receipt.ttl_remaining_seconds, 20);

    assert!(gate.is_seal_consumed("seal_001_valid"));
    assert_eq!(gate.consumed_seals_count(), 1);
}

#[test]
fn test_replay_attempt_with_already_consumed_seal_rejected() {
    let gate = HostCapabilityGate::default();
    let params = json!({"endpoint": "https://api.github.com/repos"});
    let seal = make_test_seal(
        DEFAULT_CAGE_SUBSTRATE_SECRET,
        "seal_002_replay",
        "FetchRepo",
        &params,
        "1234567890abcdef",
        2_000_000,
        30,
    );

    // First consumption succeeds
    let first = gate.validate_and_consume_seal(&seal, "FetchRepo", &params, Some(2_000_005));
    assert!(first.is_ok());

    // Second consumption attempt with exact same seal MUST fail with replay detection
    let second = gate.validate_and_consume_seal(&seal, "FetchRepo", &params, Some(2_000_010));
    match second {
        Err(GateError::SealRejection(err_msg)) => {
            assert!(
                err_msg.contains("Replay detected"),
                "Error message should mention replay detected, got: {}",
                err_msg
            );
            assert!(
                err_msg.contains("seal_002_replay"),
                "Error message should mention seal ID, got: {}",
                err_msg
            );
        }
        other => panic!(
            "Expected GateError::SealRejection for replay, got: {:?}",
            other
        ),
    }

    assert_eq!(gate.consumed_seals_count(), 1);
}

#[test]
fn test_expired_seal_rejected() {
    let gate = HostCapabilityGate::default();
    let params = json!({"volume": "storage_01"});
    let seal = make_test_seal(
        DEFAULT_CAGE_SUBSTRATE_SECRET,
        "seal_003_expired",
        "MountVolume",
        &params,
        "fedcba0987654321",
        1_000_000,
        30,
    );

    // Attempt consumption at issued_at + 35 seconds (expires at issued_at + 30)
    let res = gate.validate_and_consume_seal(&seal, "MountVolume", &params, Some(1_000_035));
    match res {
        Err(GateError::SealRejection(err_msg)) => {
            assert!(
                err_msg.to_lowercase().contains("expired"),
                "Error should mention expiration, got: {}",
                err_msg
            );
            assert!(
                err_msg.contains("1000035") && err_msg.contains("1000030"),
                "Error should include timestamps, got: {}",
                err_msg
            );
        }
        other => panic!(
            "Expected GateError::SealRejection for expired seal, got: {:?}",
            other
        ),
    }

    // Unconsumed expired seal must not be recorded in consumed set
    assert!(!gate.is_seal_consumed("seal_003_expired"));
    assert_eq!(gate.consumed_seals_count(), 0);
}

#[test]
fn test_tampered_action_parameters_rejected() {
    let gate = HostCapabilityGate::default();
    let original_params = json!({"amount": 100, "currency": "USD"});
    let seal = make_test_seal(
        DEFAULT_CAGE_SUBSTRATE_SECRET,
        "seal_004_tampered",
        "TransferFunds",
        &original_params,
        "bbbbccccddddeeee",
        1_500_000,
        30,
    );

    // Attacker attempts to swap parameters to transfer 50000 instead of 100
    let tampered_params = json!({"amount": 50000, "currency": "USD"});
    let res =
        gate.validate_and_consume_seal(&seal, "TransferFunds", &tampered_params, Some(1_500_005));

    match res {
        Err(GateError::SealRejection(err_msg)) => {
            assert!(
                err_msg.contains("Action digest mismatch"),
                "Error should identify action digest mismatch, got: {}",
                err_msg
            );
        }
        other => panic!(
            "Expected GateError::SealRejection for tampered params, got: {:?}",
            other
        ),
    }

    // Also test swapped action name
    let wrong_action_res =
        gate.validate_and_consume_seal(&seal, "WithdrawFunds", &original_params, Some(1_500_005));
    match wrong_action_res {
        Err(GateError::SealRejection(err_msg)) => {
            assert!(err_msg.contains("Action digest mismatch"));
        }
        other => panic!(
            "Expected GateError::SealRejection for swapped action name, got: {:?}",
            other
        ),
    }

    assert!(!gate.is_seal_consumed("seal_004_tampered"));
}

#[test]
fn test_forged_hmac_signature_rejected() {
    let gate = HostCapabilityGate::default();
    let params = json!({"target": "host"});
    let mut seal = make_test_seal(
        DEFAULT_CAGE_SUBSTRATE_SECRET,
        "seal_005_forged",
        "Reboot",
        &params,
        "0011223344556677",
        1_000_000,
        30,
    );

    // Attacker attempts forged signature
    seal.signature = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string();

    let res = gate.validate_and_consume_seal(&seal, "Reboot", &params, Some(1_000_002));
    match res {
        Err(GateError::SealRejection(err_msg)) => {
            assert!(
                err_msg.contains("Cryptographic HMAC signature invalid"),
                "Error should detect invalid HMAC, got: {}",
                err_msg
            );
        }
        other => panic!(
            "Expected GateError::SealRejection for forged signature, got: {:?}",
            other
        ),
    }

    assert!(!gate.is_seal_consumed("seal_005_forged"));
}

#[test]
fn test_custom_substrate_secret_configuration() {
    let custom_secret = b"my_super_secure_production_substrate_secret_key_2026!";
    let gate = HostCapabilityGate::default().with_substrate_secret(custom_secret);
    let params = json!({"cluster": "us-east-1"});

    let seal = make_test_seal(
        custom_secret,
        "seal_006_custom_secret",
        "DeployCluster",
        &params,
        "9988776655443322",
        1_200_000,
        30,
    );

    // Succeeded with matching custom secret
    let res = gate.validate_and_consume_seal(&seal, "DeployCluster", &params, Some(1_200_005));
    assert!(res.is_ok());

    // A seal signed with default secret MUST be rejected by this custom-secret gate
    let default_signed_seal = make_test_seal(
        DEFAULT_CAGE_SUBSTRATE_SECRET,
        "seal_006_default_secret",
        "DeployCluster",
        &params,
        "9988776655443322",
        1_200_000,
        30,
    );
    let res_mismatch = gate.validate_and_consume_seal(
        &default_signed_seal,
        "DeployCluster",
        &params,
        Some(1_200_005),
    );
    assert!(matches!(res_mismatch, Err(GateError::SealRejection(_))));
}

#[tokio::test]
async fn test_unsealed_actuation_attempt_fails_closed_no_direct_bind() {
    let gate = HostCapabilityGate::default();
    let params = json!({"query": "breakout"});

    // Attempt dispatch with seal = None
    let res = gate
        .dispatch_request_with_seal(
            "GET",
            "https://export.arxiv.org/api/query?search_query=all:breakout",
            &[],
            None,
            None,
            "QueryArxiv",
            &params,
        )
        .await;

    match res {
        Err(GateError::SealRequired(err_msg)) => {
            assert!(
                err_msg.contains("NoDirectBind violation: unsealed execution rejected"),
                "Error should enforce NoDirectBind violation, got: {}",
                err_msg
            );
        }
        other => panic!(
            "Expected GateError::SealRequired for unsealed actuation, got: {:?}",
            other
        ),
    }
}

#[test]
fn test_concurrent_double_spend_race_condition() {
    // 20 concurrent threads racing to consume the exact same seal instance
    const NUM_THREADS: usize = 20;
    let gate = Arc::new(HostCapabilityGate::default());
    let params = json!({"resource": "financial_ledger_write", "amount": 10000});

    let seal = Arc::new(make_test_seal(
        DEFAULT_CAGE_SUBSTRATE_SECRET,
        "seal_race_double_spend_001",
        "WriteLedger",
        &params,
        "7766554433221100",
        1_000_000,
        30,
    ));

    let barrier = Arc::new(Barrier::new(NUM_THREADS));
    let success_count = Arc::new(AtomicUsize::new(0));
    let reject_count = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::with_capacity(NUM_THREADS);
    for _ in 0..NUM_THREADS {
        let gate_clone = Arc::clone(&gate);
        let seal_clone = Arc::clone(&seal);
        let barrier_clone = Arc::clone(&barrier);
        let params_clone = params.clone();
        let success_clone = Arc::clone(&success_count);
        let reject_clone = Arc::clone(&reject_count);

        handles.push(thread::spawn(move || {
            // Wait for all threads to be ready before firing simultaneously
            barrier_clone.wait();

            let outcome = gate_clone.validate_and_consume_seal(
                &seal_clone,
                "WriteLedger",
                &params_clone,
                Some(1_000_005),
            );

            match outcome {
                Ok(_) => {
                    success_clone.fetch_add(1, Ordering::SeqCst);
                }
                Err(GateError::SealRejection(msg)) => {
                    if msg.contains("Replay detected") {
                        reject_clone.fetch_add(1, Ordering::SeqCst);
                    }
                }
                Err(_) => {}
            }
        }));
    }

    for h in handles {
        h.join().expect("Thread must join cleanly");
    }

    // Invariant: Exactly 1 thread succeeds in consuming the seal; all 19 other threads are rejected
    assert_eq!(
        success_count.load(Ordering::SeqCst),
        1,
        "Exactly 1 thread MUST succeed in consuming the single-use seal"
    );
    assert_eq!(
        reject_count.load(Ordering::SeqCst),
        NUM_THREADS - 1,
        "All other 19 threads MUST be rejected with replay detection"
    );
    assert!(gate.is_seal_consumed("seal_race_double_spend_001"));
    assert_eq!(gate.consumed_seals_count(), 1);
}

#[test]
fn test_rfc8785_jcs_canonical_action_digest_key_ordering() {
    // Keys in different order must yield identical action digests
    let params_order_a = json!({"z": 100, "b": "test", "a": true});
    let params_order_b = json!({"a": true, "z": 100, "b": "test"});
    let params_order_c = json!({"b": "test", "a": true, "z": 100});

    let digest_a = compute_action_digest("OrderTest", &params_order_a);
    let digest_b = compute_action_digest("OrderTest", &params_order_b);
    let digest_c = compute_action_digest("OrderTest", &params_order_c);

    assert_eq!(digest_a, digest_b);
    assert_eq!(digest_b, digest_c);
    assert_eq!(digest_a.len(), 64);
    assert!(digest_a.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_missing_seal_id_rejected() {
    let gate = HostCapabilityGate::default();
    let params = json!({});
    let mut seal = make_test_seal(
        DEFAULT_CAGE_SUBSTRATE_SECRET,
        "placeholder",
        "TestEmpty",
        &params,
        "1111222233334444",
        1_000_000,
        30,
    );
    seal.seal_id = "".to_string();

    let res = gate.validate_and_consume_seal(&seal, "TestEmpty", &params, Some(1_000_005));
    match res {
        Err(GateError::SealRejection(msg)) => {
            assert!(msg.contains("Missing seal_id"));
        }
        other => panic!(
            "Expected GateError::SealRejection for empty seal_id, got: {:?}",
            other
        ),
    }
}
