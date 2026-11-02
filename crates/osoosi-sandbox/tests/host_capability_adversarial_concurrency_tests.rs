//! Empirical Adversarial Concurrency & Replay Protection Test Suite
//! Target: `HostCapabilityGate` (`crates/osoosi-sandbox/src/host_capability_gate.rs`)
//!
//! Adversarial Verification Objectives:
//! 1. Extreme concurrent double-spend race condition:
//!    - 10 consecutive trials of 50 concurrent threads racing to consume the same valid routing seal.
//!    - Assert across all 500 thread executions that exactly 1 succeeds per trial and 49 receive
//!      `GateError::SealRejection` with "Replay detected".
//! 2. Multi-seal cross-thread contention:
//!    - 30 threads consuming a pool of 10 distinct valid seals concurrently.
//!    - Assert exactly 10 successes and 20 rejections (1 success and 2 rejections per seal).
//! 3. Adversarial mixed-payload concurrency under stampede:
//!    - 50 concurrent threads racing with tampered params, forged HMAC signatures, and valid tokens.
//!    - Ensure malformed tokens fail fail-closed without corrupting the atomic nonce set.
//! 4. Expired seal concurrency race:
//!    - 40 threads racing on expired tokens; assert zero double-spend and zero consumed seals.
//! 5. High-throughput saturation stress test:
//!    - 100 threads competing across 20 distinct seals (5 threads/seal); assert exactly 20 successes and 80 rejections.

use osoosi_sandbox::host_capability_gate::{
    compute_action_digest, sign_routing_seal, GateError, HostCapabilityGate,
    DEFAULT_CAGE_SUBSTRATE_SECRET,
};
use osoosi_types::cage::RoutingSeal;
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

/// Helper function to construct an authentic, cryptographically signed CAGE routing seal.
fn make_adversarial_seal(
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

/// Adversarial Challenge 1: Extreme concurrent double-spend race condition.
///
/// Executes 10 consecutive trials of 50 concurrent threads racing to consume
/// the same valid routing seal via `validate_and_consume_seal`.
///
/// Invariant: Across all 500 thread executions (10 trials * 50 threads),
/// exactly 1 thread succeeds per trial (10 total successes) and exactly 49 threads
/// receive `GateError::SealRejection` with "Replay detected" per trial (490 total rejections).
#[test]
fn test_extreme_concurrent_double_spend_race_condition_10_trials_50_threads() {
    const NUM_TRIALS: usize = 10;
    const THREADS_PER_TRIAL: usize = 50;
    const EXPECTED_TOTAL_EXECUTIONS: usize = NUM_TRIALS * THREADS_PER_TRIAL; // 500

    let gate = Arc::new(HostCapabilityGate::default());
    let mut total_successes = 0;
    let mut total_rejections = 0;

    for trial in 0..NUM_TRIALS {
        let seal_id = format!("adversarial_race_seal_trial_{:02}", trial);
        let action_name = "HostActuation::EmergencyPowerCycle";
        let params = json!({
            "subsystem": "avionics_sensor_bus",
            "trial_index": trial,
            "force": true,
            "nonce": format!("trial_nonce_{:04}", trial)
        });
        let policy_version = "f0e1d2c3b4a59687";
        let issued_at = 1_700_000_000 + (trial as u64) * 100;
        let test_now = issued_at + 5; // Valid within 30s TTL window

        let seal = Arc::new(make_adversarial_seal(
            DEFAULT_CAGE_SUBSTRATE_SECRET,
            &seal_id,
            action_name,
            &params,
            policy_version,
            issued_at,
            30,
        ));

        let barrier = Arc::new(Barrier::new(THREADS_PER_TRIAL));
        let trial_success_count = Arc::new(AtomicUsize::new(0));
        let trial_replay_reject_count = Arc::new(AtomicUsize::new(0));
        let trial_unexpected_error_count = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::with_capacity(THREADS_PER_TRIAL);

        for _ in 0..THREADS_PER_TRIAL {
            let gate_clone = Arc::clone(&gate);
            let seal_clone = Arc::clone(&seal);
            let barrier_clone = Arc::clone(&barrier);
            let params_clone = params.clone();
            let success_count = Arc::clone(&trial_success_count);
            let replay_reject_count = Arc::clone(&trial_replay_reject_count);
            let unexpected_error_count = Arc::clone(&trial_unexpected_error_count);
            let expected_seal_id = seal_id.clone();

            handles.push(thread::spawn(move || {
                // Synchronize all 50 threads so they storm the gate concurrently
                barrier_clone.wait();

                let outcome = gate_clone.validate_and_consume_seal(
                    &seal_clone,
                    action_name,
                    &params_clone,
                    Some(test_now),
                );

                match outcome {
                    Ok(receipt) => {
                        assert_eq!(receipt.status, "CONSUMED");
                        assert_eq!(receipt.seal_id, expected_seal_id);
                        assert_eq!(receipt.action_name, action_name);
                        assert_eq!(receipt.consumed_at_utc, test_now);
                        success_count.fetch_add(1, Ordering::SeqCst);
                    }
                    Err(GateError::SealRejection(err_msg)) => {
                        if err_msg.contains("Replay detected") && err_msg.contains(&expected_seal_id) {
                            replay_reject_count.fetch_add(1, Ordering::SeqCst);
                        } else {
                            eprintln!("Unexpected SealRejection message: {}", err_msg);
                            unexpected_error_count.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                    Err(other_err) => {
                        eprintln!("Unexpected GateError: {:?}", other_err);
                        unexpected_error_count.fetch_add(1, Ordering::SeqCst);
                    }
                }
            }));
        }

        for h in handles {
            h.join().expect("Trial thread joined cleanly");
        }

        let trial_successes = trial_success_count.load(Ordering::SeqCst);
        let trial_replays = trial_replay_reject_count.load(Ordering::SeqCst);
        let trial_errors = trial_unexpected_error_count.load(Ordering::SeqCst);

        assert_eq!(
            trial_successes, 1,
            "Trial {}: EXACTLY 1 thread must succeed in consuming the routing seal, found {}",
            trial, trial_successes
        );
        assert_eq!(
            trial_replays,
            THREADS_PER_TRIAL - 1,
            "Trial {}: EXACTLY 49 threads must receive 'Replay detected', found {}",
            trial, trial_replays
        );
        assert_eq!(
            trial_errors, 0,
            "Trial {}: Zero unexpected errors permitted, found {}",
            trial, trial_errors
        );
        assert!(
            gate.is_seal_consumed(&seal_id),
            "Trial {}: Seal '{}' must be permanently marked consumed",
            trial, seal_id
        );

        total_successes += trial_successes;
        total_rejections += trial_replays;
    }

    // Cumulative assertions across all 10 trials (500 total executions)
    assert_eq!(
        total_successes, NUM_TRIALS,
        "Total successes across 10 trials must be exactly 10, found {}",
        total_successes
    );
    assert_eq!(
        total_rejections,
        EXPECTED_TOTAL_EXECUTIONS - NUM_TRIALS,
        "Total rejections across 10 trials must be exactly 490, found {}",
        total_rejections
    );
    assert_eq!(
        gate.consumed_seals_count(),
        NUM_TRIALS,
        "Gate must report exactly 10 consumed seals in total"
    );
}

/// Adversarial Challenge 2: Multi-seal cross-thread contention.
///
/// Spawns 30 threads consuming a pool of 10 distinct valid seals concurrently
/// (3 threads racing for each of the 10 distinct seals).
///
/// Invariant: Across all 30 thread executions, exactly 10 succeed (1 per seal)
/// and exactly 20 are rejected with `GateError::SealRejection` ("Replay detected").
#[test]
fn test_multi_seal_cross_thread_contention_30_threads_10_seals() {
    const NUM_SEALS: usize = 10;
    const NUM_THREADS: usize = 30;
    const THREADS_PER_SEAL: usize = NUM_THREADS / NUM_SEALS; // 3 threads per seal

    let gate = Arc::new(HostCapabilityGate::default());

    // Generate pool of 10 distinct valid seals
    let mut seals = Vec::with_capacity(NUM_SEALS);
    let mut param_payloads = Vec::with_capacity(NUM_SEALS);
    let mut action_names = Vec::with_capacity(NUM_SEALS);
    let base_time = 1_700_500_000u64;

    for i in 0..NUM_SEALS {
        let seal_id = format!("multi_pool_seal_{:02}", i);
        let action_name = format!("HostActuation::Step_{:02}", i);
        let params = json!({
            "target_id": format!("resource_partition_{}", i),
            "quota_bytes": (i + 1) * 1024 * 1024,
            "seal_index": i
        });

        let seal = make_adversarial_seal(
            DEFAULT_CAGE_SUBSTRATE_SECRET,
            &seal_id,
            &action_name,
            &params,
            "c0ffee1122334455",
            base_time + (i as u64) * 10,
            30,
        );

        seals.push(seal);
        param_payloads.push(params);
        action_names.push(action_name);
    }

    let seals = Arc::new(seals);
    let param_payloads = Arc::new(param_payloads);
    let action_names = Arc::new(action_names);

    let barrier = Arc::new(Barrier::new(NUM_THREADS));
    let total_success_count = Arc::new(AtomicUsize::new(0));
    let total_reject_count = Arc::new(AtomicUsize::new(0));
    let total_unexpected_count = Arc::new(AtomicUsize::new(0));

    // Per-seal outcome tracking
    let per_seal_success: Arc<Vec<AtomicUsize>> =
        Arc::new((0..NUM_SEALS).map(|_| AtomicUsize::new(0)).collect());
    let per_seal_reject: Arc<Vec<AtomicUsize>> =
        Arc::new((0..NUM_SEALS).map(|_| AtomicUsize::new(0)).collect());

    let mut handles = Vec::with_capacity(NUM_THREADS);

    for thread_idx in 0..NUM_THREADS {
        let gate_clone = Arc::clone(&gate);
        let seals_clone = Arc::clone(&seals);
        let params_clone = Arc::clone(&param_payloads);
        let actions_clone = Arc::clone(&action_names);
        let barrier_clone = Arc::clone(&barrier);
        let success_counter = Arc::clone(&total_success_count);
        let reject_counter = Arc::clone(&total_reject_count);
        let unexpected_counter = Arc::clone(&total_unexpected_count);
        let per_seal_success_clone = Arc::clone(&per_seal_success);
        let per_seal_reject_clone = Arc::clone(&per_seal_reject);

        // Map thread_idx to a seal in the pool: thread i targets seal (i % 10)
        let seal_idx = thread_idx % NUM_SEALS;

        handles.push(thread::spawn(move || {
            let target_seal = &seals_clone[seal_idx];
            let target_action = &actions_clone[seal_idx];
            let target_params = &params_clone[seal_idx];
            let expected_seal_id = &target_seal.seal_id;
            let check_time = target_seal.issued_at + 10;

            // Wait until all 30 threads are primed
            barrier_clone.wait();

            let outcome = gate_clone.validate_and_consume_seal(
                target_seal,
                target_action,
                target_params,
                Some(check_time),
            );

            match outcome {
                Ok(receipt) => {
                    assert_eq!(receipt.status, "CONSUMED");
                    assert_eq!(&receipt.seal_id, expected_seal_id);
                    success_counter.fetch_add(1, Ordering::SeqCst);
                    per_seal_success_clone[seal_idx].fetch_add(1, Ordering::SeqCst);
                }
                Err(GateError::SealRejection(err_msg)) => {
                    if err_msg.contains("Replay detected") && err_msg.contains(expected_seal_id) {
                        reject_counter.fetch_add(1, Ordering::SeqCst);
                        per_seal_reject_clone[seal_idx].fetch_add(1, Ordering::SeqCst);
                    } else {
                        eprintln!(
                            "Thread {} failed with unexpected rejection: {}",
                            thread_idx, err_msg
                        );
                        unexpected_counter.fetch_add(1, Ordering::SeqCst);
                    }
                }
                Err(err) => {
                    eprintln!("Thread {} failed with unexpected error: {:?}", thread_idx, err);
                    unexpected_counter.fetch_add(1, Ordering::SeqCst);
                }
            }
        }));
    }

    for h in handles {
        h.join().expect("Worker thread joined cleanly");
    }

    let final_successes = total_success_count.load(Ordering::SeqCst);
    let final_rejections = total_reject_count.load(Ordering::SeqCst);
    let final_unexpected = total_unexpected_count.load(Ordering::SeqCst);

    // Global assertions
    assert_eq!(
        final_successes, NUM_SEALS,
        "Exactly 10 successes expected (1 per distinct seal), got {}",
        final_successes
    );
    assert_eq!(
        final_rejections,
        NUM_THREADS - NUM_SEALS,
        "Exactly 20 rejections expected (2 per distinct seal), got {}",
        final_rejections
    );
    assert_eq!(
        final_unexpected, 0,
        "Zero unexpected errors permitted, got {}",
        final_unexpected
    );
    assert_eq!(
        gate.consumed_seals_count(),
        NUM_SEALS,
        "Gate must report exactly 10 consumed seals in total"
    );

    // Granular per-seal assertions
    for i in 0..NUM_SEALS {
        let seal_s = per_seal_success[i].load(Ordering::SeqCst);
        let seal_r = per_seal_reject[i].load(Ordering::SeqCst);
        assert_eq!(
            seal_s, 1,
            "Seal {}: Exactly 1 thread must succeed, got {}",
            i, seal_s
        );
        assert_eq!(
            seal_r,
            THREADS_PER_SEAL - 1,
            "Seal {}: Exactly 2 threads must be rejected with replay detection, got {}",
            i, seal_r
        );
        assert!(
            gate.is_seal_consumed(&seals[i].seal_id),
            "Seal {}: Must be marked consumed in gate",
            i
        );
    }
}

/// Adversarial Challenge 3: Mixed valid, tampered, and forged tokens under high concurrency.
///
/// Spawns 50 concurrent threads targeting the same seal ID:
/// - 10 threads present valid signed seals with authentic parameters.
/// - 20 threads present tampered action parameters (triggering action digest mismatch).
/// - 20 threads present forged HMAC signatures (triggering cryptographic signature rejection).
///
/// Invariant:
/// - Tampered parameters and forged signatures fail closed BEFORE mutating state.
/// - Exactly 1 valid thread consumes the seal.
/// - Remaining 9 valid threads receive "Replay detected".
/// - Total: 1 success, 49 rejections (9 replay, 20 digest mismatch, 20 signature rejection).
#[test]
fn test_mixed_valid_and_tampered_seals_concurrent_race() {
    const NUM_THREADS: usize = 50;
    let gate = Arc::new(HostCapabilityGate::default());

    let seal_id = "adversarial_mixed_stampede_01";
    let action_name = "HostActuation::MutateKernelQuota";
    let authentic_params = json!({"quota_mb": 512, "tenant": "sec_auditor"});
    let tampered_params = json!({"quota_mb": 1048576, "tenant": "root_attacker"}); // Privilege escalation attempt
    let policy_version = "abcd1234efgh5678";
    let issued_at = 1_700_900_000u64;

    let authentic_seal = Arc::new(make_adversarial_seal(
        DEFAULT_CAGE_SUBSTRATE_SECRET,
        seal_id,
        action_name,
        &authentic_params,
        policy_version,
        issued_at,
        30,
    ));

    // Forged seal: legitimate payload but signed with wrong key
    let forged_seal = Arc::new(make_adversarial_seal(
        b"attacker_rogue_secret_key_1234567890",
        seal_id,
        action_name,
        &authentic_params,
        policy_version,
        issued_at,
        30,
    ));

    let barrier = Arc::new(Barrier::new(NUM_THREADS));
    let valid_success = Arc::new(AtomicUsize::new(0));
    let replay_reject = Arc::new(AtomicUsize::new(0));
    let digest_mismatch = Arc::new(AtomicUsize::new(0));
    let sig_reject = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::with_capacity(NUM_THREADS);

    for i in 0..NUM_THREADS {
        let gate_clone = Arc::clone(&gate);
        let authentic_seal_clone = Arc::clone(&authentic_seal);
        let forged_seal_clone = Arc::clone(&forged_seal);
        let authentic_params_clone = authentic_params.clone();
        let tampered_params_clone = tampered_params.clone();
        let barrier_clone = Arc::clone(&barrier);
        let s_count = Arc::clone(&valid_success);
        let r_count = Arc::clone(&replay_reject);
        let d_count = Arc::clone(&digest_mismatch);
        let f_count = Arc::clone(&sig_reject);

        handles.push(thread::spawn(move || {
            barrier_clone.wait();

            if i < 10 {
                // Legitimate race contender
                let outcome = gate_clone.validate_and_consume_seal(
                    &authentic_seal_clone,
                    action_name,
                    &authentic_params_clone,
                    Some(issued_at + 10),
                );
                match outcome {
                    Ok(_) => {
                        s_count.fetch_add(1, Ordering::SeqCst);
                    }
                    Err(GateError::SealRejection(msg)) if msg.contains("Replay detected") => {
                        r_count.fetch_add(1, Ordering::SeqCst);
                    }
                    Err(other) => panic!("Unexpected error on legitimate thread: {:?}", other),
                }
            } else if i < 30 {
                // Tampered parameter attacker
                let outcome = gate_clone.validate_and_consume_seal(
                    &authentic_seal_clone,
                    action_name,
                    &tampered_params_clone,
                    Some(issued_at + 10),
                );
                match outcome {
                    Ok(_) => panic!("Tampered parameters MUST NEVER be accepted!"),
                    Err(GateError::SealRejection(msg)) => {
                        if msg.contains("Action digest mismatch") {
                            d_count.fetch_add(1, Ordering::SeqCst);
                        } else if msg.contains("Replay detected") {
                            // If a valid thread already consumed before this thread checked replay,
                            // preliminary replay check 1 triggers: that's also fail-closed!
                            r_count.fetch_add(1, Ordering::SeqCst);
                        } else {
                            panic!("Unexpected rejection for tampered params: {}", msg);
                        }
                    }
                    Err(other) => panic!("Unexpected error for tampered params: {:?}", other),
                }
            } else {
                // Forged cryptographic signature attacker
                let outcome = gate_clone.validate_and_consume_seal(
                    &forged_seal_clone,
                    action_name,
                    &authentic_params_clone,
                    Some(issued_at + 10),
                );
                match outcome {
                    Ok(_) => panic!("Forged HMAC signature MUST NEVER be accepted!"),
                    Err(GateError::SealRejection(msg)) => {
                        if msg.contains("Cryptographic HMAC signature invalid") {
                            f_count.fetch_add(1, Ordering::SeqCst);
                        } else if msg.contains("Replay detected") {
                            // Preliminary check can fire if already consumed
                            r_count.fetch_add(1, Ordering::SeqCst);
                        } else {
                            panic!("Unexpected rejection for forged sig: {}", msg);
                        }
                    }
                    Err(other) => panic!("Unexpected error for forged sig: {:?}", other),
                }
            }
        }));
    }

    for h in handles {
        h.join().expect("Mixed thread joined cleanly");
    }

    assert_eq!(
        valid_success.load(Ordering::SeqCst),
        1,
        "Exactly 1 legitimate thread must succeed"
    );
    let total_rejections = replay_reject.load(Ordering::SeqCst)
        + digest_mismatch.load(Ordering::SeqCst)
        + sig_reject.load(Ordering::SeqCst);
    assert_eq!(
        total_rejections,
        NUM_THREADS - 1,
        "All other 49 attempts must be rejected"
    );
    assert!(gate.is_seal_consumed(seal_id));
    assert_eq!(gate.consumed_seals_count(), 1);
}

/// Adversarial Challenge 4: Concurrency race on expired routing seals.
///
/// 40 concurrent threads storm the gate with an expired routing seal.
///
/// Invariant:
/// - Exactly 0 successes.
/// - All 40 threads receive `GateError::SealRejection` with "Routing seal expired".
/// - Gate consumed count remains 0.
#[test]
fn test_expired_seal_concurrency_race_zero_success() {
    const NUM_THREADS: usize = 40;
    let gate = Arc::new(HostCapabilityGate::default());

    let seal_id = "adversarial_expired_concurrency_01";
    let action_name = "HostActuation::UnmountDisk";
    let params = json!({"mount_point": "/mnt/secure_vault"});
    let policy_version = "0123456789abcdef";
    let issued_at = 1_700_000_000u64;

    let seal = Arc::new(make_adversarial_seal(
        DEFAULT_CAGE_SUBSTRATE_SECRET,
        seal_id,
        action_name,
        &params,
        policy_version,
        issued_at,
        30,
    ));

    let barrier = Arc::new(Barrier::new(NUM_THREADS));
    let success_count = Arc::new(AtomicUsize::new(0));
    let expired_reject_count = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::with_capacity(NUM_THREADS);

    for _ in 0..NUM_THREADS {
        let gate_clone = Arc::clone(&gate);
        let seal_clone = Arc::clone(&seal);
        let barrier_clone = Arc::clone(&barrier);
        let params_clone = params.clone();
        let s_count = Arc::clone(&success_count);
        let e_count = Arc::clone(&expired_reject_count);

        handles.push(thread::spawn(move || {
            barrier_clone.wait();

            // Attempt to consume at issued_at + 31s (> 30s TTL)
            let outcome = gate_clone.validate_and_consume_seal(
                &seal_clone,
                action_name,
                &params_clone,
                Some(issued_at + 31),
            );

            match outcome {
                Ok(_) => {
                    s_count.fetch_add(1, Ordering::SeqCst);
                }
                Err(GateError::SealRejection(msg)) if msg.contains("Routing seal expired") => {
                    e_count.fetch_add(1, Ordering::SeqCst);
                }
                Err(other) => panic!("Unexpected error on expired seal: {:?}", other),
            }
        }));
    }

    for h in handles {
        h.join().expect("Expired thread joined cleanly");
    }

    assert_eq!(
        success_count.load(Ordering::SeqCst),
        0,
        "Expired seal MUST NEVER be consumed under any concurrency condition"
    );
    assert_eq!(
        expired_reject_count.load(Ordering::SeqCst),
        NUM_THREADS,
        "All 40 threads must receive expired seal rejection"
    );
    assert!(
        !gate.is_seal_consumed(seal_id),
        "Expired seal must not be entered into the consumed set"
    );
    assert_eq!(gate.consumed_seals_count(), 0);
}

/// Adversarial Challenge 5: High-throughput saturation stress test.
///
/// 100 concurrent threads competing across 20 distinct seals (5 threads per seal).
///
/// Invariant:
/// - Exactly 20 successes (1 per distinct seal).
/// - Exactly 80 rejections with "Replay detected" (4 per distinct seal).
/// - Total consumed count equals 20.
#[test]
fn test_stress_saturation_100_threads_20_distinct_seals() {
    const NUM_SEALS: usize = 20;
    const NUM_THREADS: usize = 100;
    const THREADS_PER_SEAL: usize = NUM_THREADS / NUM_SEALS; // 5 threads per seal

    let gate = Arc::new(HostCapabilityGate::default());
    let base_time = 1_701_000_000u64;

    let mut seals = Vec::with_capacity(NUM_SEALS);
    let mut param_payloads = Vec::with_capacity(NUM_SEALS);
    let mut action_names = Vec::with_capacity(NUM_SEALS);

    for i in 0..NUM_SEALS {
        let seal_id = format!("saturation_seal_{:03}", i);
        let action_name = format!("HostActuation::ProcessJob_{:03}", i);
        let params = json!({"job_id": i, "priority": "high"});

        let seal = make_adversarial_seal(
            DEFAULT_CAGE_SUBSTRATE_SECRET,
            &seal_id,
            &action_name,
            &params,
            "beefdead01020304",
            base_time + (i as u64) * 5,
            30,
        );

        seals.push(seal);
        param_payloads.push(params);
        action_names.push(action_name);
    }

    let seals = Arc::new(seals);
    let param_payloads = Arc::new(param_payloads);
    let action_names = Arc::new(action_names);

    let barrier = Arc::new(Barrier::new(NUM_THREADS));
    let success_count = Arc::new(AtomicUsize::new(0));
    let replay_count = Arc::new(AtomicUsize::new(0));
    let per_seal_success: Arc<Vec<AtomicUsize>> =
        Arc::new((0..NUM_SEALS).map(|_| AtomicUsize::new(0)).collect());
    let per_seal_reject: Arc<Vec<AtomicUsize>> =
        Arc::new((0..NUM_SEALS).map(|_| AtomicUsize::new(0)).collect());

    let mut handles = Vec::with_capacity(NUM_THREADS);

    for thread_idx in 0..NUM_THREADS {
        let gate_clone = Arc::clone(&gate);
        let seals_clone = Arc::clone(&seals);
        let params_clone = Arc::clone(&param_payloads);
        let actions_clone = Arc::clone(&action_names);
        let barrier_clone = Arc::clone(&barrier);
        let s_count = Arc::clone(&success_count);
        let r_count = Arc::clone(&replay_count);
        let per_seal_s = Arc::clone(&per_seal_success);
        let per_seal_r = Arc::clone(&per_seal_reject);

        let seal_idx = thread_idx % NUM_SEALS;

        handles.push(thread::spawn(move || {
            let target_seal = &seals_clone[seal_idx];
            let target_action = &actions_clone[seal_idx];
            let target_params = &params_clone[seal_idx];
            let expected_seal_id = &target_seal.seal_id;
            let check_time = target_seal.issued_at + 5;

            barrier_clone.wait();

            let outcome = gate_clone.validate_and_consume_seal(
                target_seal,
                target_action,
                target_params,
                Some(check_time),
            );

            match outcome {
                Ok(_) => {
                    s_count.fetch_add(1, Ordering::SeqCst);
                    per_seal_s[seal_idx].fetch_add(1, Ordering::SeqCst);
                }
                Err(GateError::SealRejection(msg)) if msg.contains("Replay detected") => {
                    assert!(msg.contains(expected_seal_id));
                    r_count.fetch_add(1, Ordering::SeqCst);
                    per_seal_r[seal_idx].fetch_add(1, Ordering::SeqCst);
                }
                Err(other) => panic!("Unexpected error in saturation test: {:?}", other),
            }
        }));
    }

    for h in handles {
        h.join().expect("Saturation thread joined cleanly");
    }

    assert_eq!(
        success_count.load(Ordering::SeqCst),
        NUM_SEALS,
        "Exactly 20 successes expected across 100 threads, got {}",
        success_count.load(Ordering::SeqCst)
    );
    assert_eq!(
        replay_count.load(Ordering::SeqCst),
        NUM_THREADS - NUM_SEALS,
        "Exactly 80 rejections expected across 100 threads, got {}",
        replay_count.load(Ordering::SeqCst)
    );
    assert_eq!(
        gate.consumed_seals_count(),
        NUM_SEALS,
        "Gate must register exactly 20 consumed seals"
    );

    for i in 0..NUM_SEALS {
        assert_eq!(
            per_seal_success[i].load(Ordering::SeqCst),
            1,
            "Seal {}: Exactly 1 success required",
            i
        );
        assert_eq!(
            per_seal_reject[i].load(Ordering::SeqCst),
            THREADS_PER_SEAL - 1,
            "Seal {}: Exactly {} replay rejections required",
            i,
            THREADS_PER_SEAL - 1
        );
        assert!(gate.is_seal_consumed(&seals[i].seal_id));
    }
}
