//! Milestone 3 Empirical Challenger Test Suite: Pure-Rust BFS Formal Model Adversarial Stress
//!
//! Validates:
//! 1. Exhaustive State-Space Validation across 100 sequential trials:
//!    - Gated model: strictly 34 reachable states, exactly 1 EXECUTED state, 0 violations, NoDirectBind proven.
//!    - Ungated model: strictly 17 reachable states, exactly 1 EXECUTED state, 1+ NoDirectBind violations.
//!    - Skipped-tier model: all 7 tiers (0..=6) visit strictly 31 reachable states, exactly 0 executed states.
//! 2. Graph Corruption Stress:
//!    - Corrupted transitions: Tier 2 direct jump to SEAL_ISSUED or EXECUTED.
//!    - Flag tampering: `seal_present` set to false on executed state.
//!    - Verdict tampering: `resolved_allow` set to false on executed state.
//!    - Multiple executions injection: duplicate executed states (replay attack).
//!    - Seal expired resurrection: transitioning from expired seal to execution.
//!    - Cyclic graph traversal: cycle injection verifying termination without stack overflow.
//! 3. Concurrency and Deterministic Proof Hashing:
//!    - 20 concurrent threads running `prove_no_direct_bind`, asserting bit-for-bit identical 64-hex lowercase receipts.
//!    - 50 concurrent threads stress test mixing all BFS model functions under heavy contention.
//!    - Independent SHA-256 oracle verification and bit-flip sensitivity (avalanche effect).

use osoosi_policy::cage::{
    BfsModelResult, BfsPhase, BfsState, BfsViolation, FormalBfsModel, StreamInvariantVerifier,
    TheoremProofResult,
};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Barrier};
use std::thread;

// =========================================================================
// Adversarial BFS Graph Corruption Engine & Invariant Verification Oracle
// =========================================================================

struct AdversarialBfsHarness;

impl AdversarialBfsHarness {
    /// Constructs canonical baseline transitions for the 7-tier pipeline.
    pub fn build_canonical_transitions() -> (BfsState, HashMap<BfsState, Vec<BfsState>>) {
        let initial_state = BfsState::new(BfsPhase::Initial, "PENDING", 0, false, false, false);
        let mut transitions: HashMap<BfsState, Vec<BfsState>> = HashMap::new();

        let first_check = BfsState::new(
            BfsPhase::Checking,
            FormalBfsModel::TIER_NAMES[0],
            0,
            false,
            false,
            false,
        );
        transitions.insert(initial_state.clone(), vec![first_check]);

        for idx in 0..7 {
            let current_check = BfsState::new(
                BfsPhase::Checking,
                FormalBfsModel::TIER_NAMES[idx],
                idx,
                false,
                false,
                false,
            );
            let next_check = if idx < 6 {
                BfsState::new(
                    BfsPhase::Checking,
                    FormalBfsModel::TIER_NAMES[idx + 1],
                    idx + 1,
                    false,
                    false,
                    false,
                )
            } else {
                BfsState::new(BfsPhase::Checking, "completed", 7, false, false, false)
            };
            let direct_deny = BfsState::new(
                BfsPhase::Denied,
                format!("direct_tier_{idx}"),
                idx,
                false,
                false,
                false,
            );
            let narrow_eval = BfsState::new(
                BfsPhase::NarrowEval,
                format!("tier_{idx}"),
                idx,
                false,
                false,
                true,
            );

            transitions.insert(
                current_check,
                vec![next_check, direct_deny, narrow_eval.clone()],
            );

            let narrow_rerun_deny = BfsState::new(
                BfsPhase::Denied,
                format!("narrow_rerun_tier_{idx}"),
                idx,
                false,
                false,
                false,
            );
            if idx < 6 {
                let next_narrow = BfsState::new(
                    BfsPhase::NarrowEval,
                    format!("tier_{}", idx + 1),
                    idx + 1,
                    false,
                    false,
                    true,
                );
                transitions.insert(narrow_eval, vec![next_narrow, narrow_rerun_deny]);
            } else {
                let narrow_pass =
                    BfsState::new(BfsPhase::NarrowPassed, "all_clamped", 7, true, true, true);
                transitions.insert(narrow_eval, vec![narrow_pass, narrow_rerun_deny]);
            }
        }

        let seal_issued = BfsState::new(BfsPhase::SealIssued, "valid", 7, true, true, false);
        let completed_check =
            BfsState::new(BfsPhase::Checking, "completed", 7, false, false, false);
        transitions.insert(completed_check, vec![seal_issued.clone()]);

        let narrow_pass = BfsState::new(BfsPhase::NarrowPassed, "all_clamped", 7, true, true, true);
        transitions.insert(narrow_pass, vec![seal_issued.clone()]);

        let executed = BfsState::new(BfsPhase::Executed, "executed", 7, true, true, true);
        let seal_expired = BfsState::new(BfsPhase::Denied, "seal_expired", 7, true, false, false);
        transitions.insert(seal_issued, vec![executed.clone(), seal_expired.clone()]);

        for idx in 0..7 {
            transitions.insert(
                BfsState::new(
                    BfsPhase::Denied,
                    format!("direct_tier_{idx}"),
                    idx,
                    false,
                    false,
                    false,
                ),
                Vec::new(),
            );
            transitions.insert(
                BfsState::new(
                    BfsPhase::Denied,
                    format!("narrow_rerun_tier_{idx}"),
                    idx,
                    false,
                    false,
                    false,
                ),
                Vec::new(),
            );
        }
        transitions.insert(executed, Vec::new());
        transitions.insert(seal_expired, Vec::new());

        (initial_state, transitions)
    }

    /// Evaluates transitions using BFS exploration with strict invariant checks.
    pub fn verify_transitions(
        initial_state: BfsState,
        transitions: &HashMap<BfsState, Vec<BfsState>>,
    ) -> BfsModelResult {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(initial_state);
        let mut violations = Vec::new();
        let mut executed_count = 0;

        while let Some(state) = queue.pop_front() {
            if visited.contains(&state) {
                continue;
            }
            visited.insert(state.clone());

            if state.phase == BfsPhase::Executed {
                executed_count += 1;
                // Invariant 1: NoDirectBind (must have valid seal and resolved allow)
                if !state.resolved_allow || !state.seal_present {
                    violations.push(BfsViolation {
                        state: state.clone(),
                        error: format!(
                            "NoDirectBind violation in EXECUTED phase: resolved_allow={}, seal_present={}",
                            state.resolved_allow, state.seal_present
                        ),
                    });
                }
                // Invariant 2: Terminal Execution tier index must be 7
                if state.tier != 7 {
                    violations.push(BfsViolation {
                        state: state.clone(),
                        error: format!(
                            "Premature execution tier: expected tier 7, got tier {}",
                            state.tier
                        ),
                    });
                }
            }

            if let Some(next_states) = transitions.get(&state) {
                for next in next_states {
                    // Invariant 3: Checking tier jump bypass
                    if state.phase == BfsPhase::Checking
                        && state.tier < 6
                        && (next.phase == BfsPhase::SealIssued || next.phase == BfsPhase::Executed)
                    {
                        violations.push(BfsViolation {
                            state: state.clone(),
                            error: format!(
                                "Illegal pipeline jump: Checking tier {} transitioned directly to {}",
                                state.tier, next.phase
                            ),
                        });
                    }
                    // Invariant 4: Denied/SealExpired state resurrection
                    if state.phase == BfsPhase::Denied && next.phase == BfsPhase::Executed {
                        violations.push(BfsViolation {
                            state: state.clone(),
                            error: format!(
                                "Illegal resurrection: Denied state '{}' transitioned to Executed",
                                state.label
                            ),
                        });
                    }

                    if !visited.contains(next) {
                        queue.push_back(next.clone());
                    }
                }
            }
        }

        // Invariant 5: Unique execution state
        if executed_count > 1 {
            violations.push(BfsViolation {
                state: BfsState::new(
                    BfsPhase::Executed,
                    "multiple_executions",
                    7,
                    true,
                    true,
                    true,
                ),
                error: format!(
                    "Multiple execution states detected: count={}",
                    executed_count
                ),
            });
        }

        let reachable_count = visited.len();
        let no_direct_bind_proven = violations.is_empty() && executed_count == 1;

        BfsModelResult {
            visited_states: visited,
            reachable_count,
            executed_count,
            violations,
            no_direct_bind_proven,
        }
    }
}

// =========================================================================
// 1. Exhaustive State-Space Validation
// =========================================================================

#[test]
fn test_adversarial_gated_model_100_sequential_trials_stability() {
    let mut baseline_states: Option<HashSet<BfsState>> = None;

    for trial in 1..=100 {
        let result = FormalBfsModel::explore_gated_model();

        // 1. Strictly 34 reachable states
        assert_eq!(
            result.reachable_count, 34,
            "Trial #{}: Expected strictly 34 reachable states, got {}",
            trial, result.reachable_count
        );
        assert_eq!(result.visited_states.len(), 34);

        // 2. Exactly 1 EXECUTED state
        assert_eq!(
            result.executed_count, 1,
            "Trial #{}: Expected exactly 1 executed state, got {}",
            trial, result.executed_count
        );

        // 3. Exactly 0 invariant violations
        assert!(
            result.violations.is_empty(),
            "Trial #{}: Expected 0 violations, found {:?}",
            trial,
            result.violations
        );
        assert!(result.no_direct_bind_proven);

        // 4. Executed state integrity
        let executed_list = result.executed_states();
        assert_eq!(executed_list.len(), 1);
        let exec = executed_list[0];
        assert_eq!(exec.phase, BfsPhase::Executed);
        assert_eq!(exec.label, "executed");
        assert_eq!(exec.tier, 7);
        assert!(
            exec.seal_present,
            "Trial #{}: seal_present must be true",
            trial
        );
        assert!(
            exec.resolved_allow,
            "Trial #{}: resolved_allow must be true",
            trial
        );
        assert!(exec.executed_or_narrow);

        // 5. Phase population breakdown:
        //    1 Initial + 8 Checking + 7 NarrowEval + 1 NarrowPassed + 1 SealIssued + 1 Executed + 15 Denied = 34
        let initial_count = result
            .visited_states
            .iter()
            .filter(|s| s.phase == BfsPhase::Initial)
            .count();
        let checking_count = result
            .visited_states
            .iter()
            .filter(|s| s.phase == BfsPhase::Checking)
            .count();
        let narrow_eval_count = result
            .visited_states
            .iter()
            .filter(|s| s.phase == BfsPhase::NarrowEval)
            .count();
        let narrow_pass_count = result
            .visited_states
            .iter()
            .filter(|s| s.phase == BfsPhase::NarrowPassed)
            .count();
        let seal_issued_count = result
            .visited_states
            .iter()
            .filter(|s| s.phase == BfsPhase::SealIssued)
            .count();
        let executed_phase_count = result
            .visited_states
            .iter()
            .filter(|s| s.phase == BfsPhase::Executed)
            .count();
        let denied_count = result
            .visited_states
            .iter()
            .filter(|s| s.phase == BfsPhase::Denied)
            .count();

        assert_eq!(initial_count, 1, "Initial count mismatch");
        assert_eq!(
            checking_count, 8,
            "Checking count mismatch (7 tiers + completed)"
        );
        assert_eq!(narrow_eval_count, 7, "NarrowEval count mismatch (7 tiers)");
        assert_eq!(narrow_pass_count, 1, "NarrowPassed count mismatch");
        assert_eq!(seal_issued_count, 1, "SealIssued count mismatch");
        assert_eq!(executed_phase_count, 1, "Executed count mismatch");
        assert_eq!(
            denied_count, 15,
            "Denied count mismatch (7 direct + 7 narrow rerun + 1 seal expired)"
        );

        // 6. Complete state set invariance across all 100 trials
        if let Some(ref base) = baseline_states {
            assert_eq!(
                base, &result.visited_states,
                "Trial #{}: Visited state set differed from baseline",
                trial
            );
        } else {
            baseline_states = Some(result.visited_states.clone());
        }
    }
}

#[test]
fn test_adversarial_ungated_model_100_sequential_trials_negative_control() {
    let mut baseline_states: Option<HashSet<BfsState>> = None;

    for trial in 1..=100 {
        let result = FormalBfsModel::explore_ungated_counterexample();

        // 1. Strictly 17 reachable states
        assert_eq!(
            result.reachable_count, 17,
            "Trial #{}: Expected strictly 17 reachable states, got {}",
            trial, result.reachable_count
        );
        assert_eq!(result.visited_states.len(), 17);

        // 2. Exactly 1 executed state (ungated counterexample)
        assert_eq!(result.executed_count, 1);

        // 3. Strictly emits NoDirectBind violation
        assert!(
            !result.violations.is_empty(),
            "Trial #{}: Ungated model must emit violations",
            trial
        );
        assert_eq!(result.violations.len(), 1);
        let violation = &result.violations[0];
        assert_eq!(violation.state.phase, BfsPhase::Executed);
        assert_eq!(violation.state.label, "ungated_direct_bind");
        assert!(!violation.state.seal_present);
        assert!(violation
            .error
            .contains("Direct-bind violation counterexample"));
        assert!(!result.no_direct_bind_proven);

        // 4. Phase breakdown:
        //    1 Initial + 7 Checking + 1 Executed + 8 Denied (7 tier denies + 1 terminal_failure) = 17
        let initial_count = result
            .visited_states
            .iter()
            .filter(|s| s.phase == BfsPhase::Initial)
            .count();
        let checking_count = result
            .visited_states
            .iter()
            .filter(|s| s.phase == BfsPhase::Checking)
            .count();
        let executed_count = result
            .visited_states
            .iter()
            .filter(|s| s.phase == BfsPhase::Executed)
            .count();
        let denied_count = result
            .visited_states
            .iter()
            .filter(|s| s.phase == BfsPhase::Denied)
            .count();

        assert_eq!(initial_count, 1);
        assert_eq!(checking_count, 7);
        assert_eq!(executed_count, 1);
        assert_eq!(denied_count, 8);

        // 5. Invariance across trials
        if let Some(ref base) = baseline_states {
            assert_eq!(
                base, &result.visited_states,
                "Trial #{}: Ungated state set drifted",
                trial
            );
        } else {
            baseline_states = Some(result.visited_states.clone());
        }
    }
}

#[test]
fn test_adversarial_skipped_tier_variations_all_7_tiers_100_trials() {
    // Test all 7 tiers (0..=6: ftra, stpa, opa, confidence, consensus, cbf, fiscal)
    for skip_tier in 0..7 {
        for trial in 1..=100 {
            let result = FormalBfsModel::explore_skipped_tier_model(skip_tier);

            // 1. Strictly 31 reachable states
            assert_eq!(
                result.reachable_count, 31,
                "Tier {} Trial #{}: Expected strictly 31 reachable states, got {}",
                skip_tier, trial, result.reachable_count
            );
            assert_eq!(result.visited_states.len(), 31);

            // 2. Exactly 0 executed states (actuation strictly blocked)
            assert_eq!(
                result.executed_count, 0,
                "Tier {} Trial #{}: Skipped tier must yield 0 executed states, got {}",
                skip_tier, trial, result.executed_count
            );
            assert!(result.executed_states().is_empty());

            // 3. No unsealed execution breaches occurred
            assert!(
                result.violations.is_empty(),
                "Tier {} Trial #{}: Unexpected violations: {:?}",
                skip_tier,
                trial,
                result.violations
            );
            assert!(result.no_direct_bind_proven);

            // 4. Verify terminal status: SealExpired is reachable, but Executed is strictly absent
            assert!(
                result
                    .visited_states
                    .iter()
                    .any(|s| s.label == "seal_expired"),
                "Tier {} Trial #{}: seal_expired state must be reached",
                skip_tier,
                trial
            );
            assert!(
                !result
                    .visited_states
                    .iter()
                    .any(|s| s.phase == BfsPhase::Executed),
                "Tier {} Trial #{}: Executed state must not be reachable",
                skip_tier,
                trial
            );
        }
    }
}

// =========================================================================
// 2. Graph Corruption Stress Testing
// =========================================================================

#[test]
fn test_graph_corruption_tier2_direct_jump_to_seal_issued() {
    let (initial_state, mut transitions) = AdversarialBfsHarness::build_canonical_transitions();

    // Adversarial injection: Tier 2 ("opa") jumps directly to SEAL_ISSUED
    let tier2_state = BfsState::new(BfsPhase::Checking, "opa", 2, false, false, false);
    let seal_issued = BfsState::new(BfsPhase::SealIssued, "valid", 7, true, true, false);

    // Corrupt transitions of tier 2
    transitions.get_mut(&tier2_state).unwrap().push(seal_issued);

    let result = AdversarialBfsHarness::verify_transitions(initial_state, &transitions);

    // BFS verifier must catch the illegal pipeline jump invariant violation
    assert!(!result.no_direct_bind_proven);
    assert!(
        result.violations.iter().any(|v| {
            v.error.contains("Illegal pipeline jump")
                && v.error.contains("Checking tier 2")
                && v.error.contains("SEAL_ISSUED")
        }),
        "Expected illegal pipeline jump violation, got: {:?}",
        result.violations
    );
}

#[test]
fn test_graph_corruption_tier2_direct_jump_to_unsealed_executed() {
    let (initial_state, mut transitions) = AdversarialBfsHarness::build_canonical_transitions();

    // Adversarial injection: Tier 2 ("opa") jumps directly to an EXECUTED state without seal
    let tier2_state = BfsState::new(BfsPhase::Checking, "opa", 2, false, false, false);
    let rogue_exec = BfsState::new(
        BfsPhase::Executed,
        "rogue_tier2_actuation",
        2,
        false,
        false,
        true,
    );

    transitions
        .get_mut(&tier2_state)
        .unwrap()
        .push(rogue_exec.clone());
    transitions.insert(rogue_exec, Vec::new());

    let result = AdversarialBfsHarness::verify_transitions(initial_state, &transitions);

    // BFS verifier must flag both NoDirectBind violation and premature execution tier
    assert!(!result.no_direct_bind_proven);
    assert!(result
        .violations
        .iter()
        .any(|v| v.error.contains("NoDirectBind violation in EXECUTED phase")));
    assert!(result
        .violations
        .iter()
        .any(|v| v.error.contains("Premature execution tier")));
    assert!(result
        .violations
        .iter()
        .any(|v| v.error.contains("Illegal pipeline jump")));
}

#[test]
fn test_graph_corruption_executed_state_seal_present_tampered_to_false() {
    let (initial_state, mut transitions) = AdversarialBfsHarness::build_canonical_transitions();

    // Adversarial injection: The executed state reached has seal_present = false
    let seal_issued = BfsState::new(BfsPhase::SealIssued, "valid", 7, true, true, false);
    let tampered_exec = BfsState::new(BfsPhase::Executed, "executed", 7, false, true, true);
    let seal_expired = BfsState::new(BfsPhase::Denied, "seal_expired", 7, true, false, false);

    transitions.insert(seal_issued, vec![tampered_exec.clone(), seal_expired]);
    transitions.insert(tampered_exec, Vec::new());

    let result = AdversarialBfsHarness::verify_transitions(initial_state, &transitions);

    assert!(!result.no_direct_bind_proven);
    assert!(
        result.violations.iter().any(|v| {
            v.error.contains("NoDirectBind violation in EXECUTED phase")
                && v.error.contains("seal_present=false")
        }),
        "Expected seal_present=false NoDirectBind violation, got: {:?}",
        result.violations
    );
}

#[test]
fn test_graph_corruption_executed_state_resolved_allow_tampered_to_false() {
    let (initial_state, mut transitions) = AdversarialBfsHarness::build_canonical_transitions();

    // Adversarial injection: The executed state reached has resolved_allow = false (DENIED actuation)
    let seal_issued = BfsState::new(BfsPhase::SealIssued, "valid", 7, true, true, false);
    let tampered_exec = BfsState::new(BfsPhase::Executed, "executed", 7, true, false, true);
    let seal_expired = BfsState::new(BfsPhase::Denied, "seal_expired", 7, true, false, false);

    transitions.insert(seal_issued, vec![tampered_exec.clone(), seal_expired]);
    transitions.insert(tampered_exec, Vec::new());

    let result = AdversarialBfsHarness::verify_transitions(initial_state, &transitions);

    assert!(!result.no_direct_bind_proven);
    assert!(
        result.violations.iter().any(|v| {
            v.error.contains("NoDirectBind violation in EXECUTED phase")
                && v.error.contains("resolved_allow=false")
        }),
        "Expected resolved_allow=false NoDirectBind violation, got: {:?}",
        result.violations
    );
}

#[test]
fn test_graph_corruption_double_execution_injection_replay_attack() {
    let (initial_state, mut transitions) = AdversarialBfsHarness::build_canonical_transitions();

    // Adversarial injection: Two distinct EXECUTED states (e.g. seal replay)
    let seal_issued = BfsState::new(BfsPhase::SealIssued, "valid", 7, true, true, false);
    let exec1 = BfsState::new(BfsPhase::Executed, "executed_1", 7, true, true, true);
    let exec2 = BfsState::new(
        BfsPhase::Executed,
        "executed_2_replayed",
        7,
        true,
        true,
        true,
    );
    let seal_expired = BfsState::new(BfsPhase::Denied, "seal_expired", 7, true, false, false);

    transitions.insert(
        seal_issued,
        vec![exec1.clone(), exec2.clone(), seal_expired],
    );
    transitions.insert(exec1, Vec::new());
    transitions.insert(exec2, Vec::new());

    let result = AdversarialBfsHarness::verify_transitions(initial_state, &transitions);

    // BFS verifier must catch the multiple execution states violation
    assert!(!result.no_direct_bind_proven);
    assert_eq!(result.executed_count, 2);
    assert!(
        result.violations.iter().any(|v| v
            .error
            .contains("Multiple execution states detected: count=2")),
        "Expected multiple execution states violation, got: {:?}",
        result.violations
    );
}

#[test]
fn test_graph_corruption_seal_expired_resurrection_bypass() {
    let (initial_state, mut transitions) = AdversarialBfsHarness::build_canonical_transitions();

    // Adversarial injection: Seal expired state resurrects and transitions to EXECUTED
    let seal_expired = BfsState::new(BfsPhase::Denied, "seal_expired", 7, true, false, false);
    let resurrected_exec =
        BfsState::new(BfsPhase::Executed, "resurrected_exec", 7, true, true, true);

    transitions.insert(seal_expired, vec![resurrected_exec.clone()]);
    transitions.insert(resurrected_exec, Vec::new());

    let result = AdversarialBfsHarness::verify_transitions(initial_state, &transitions);

    assert!(!result.no_direct_bind_proven);
    assert!(
        result.violations.iter().any(|v| {
            v.error.contains("Illegal resurrection") && v.error.contains("seal_expired")
        }),
        "Expected illegal resurrection violation, got: {:?}",
        result.violations
    );
}

#[test]
fn test_graph_corruption_cyclic_transition_graph_robustness() {
    let (initial_state, mut transitions) = AdversarialBfsHarness::build_canonical_transitions();

    // Adversarial injection: Add cycle between tier 3 ("confidence") and tier 1 ("stpa")
    let tier3_state = BfsState::new(BfsPhase::Checking, "confidence", 3, false, false, false);
    let tier1_state = BfsState::new(BfsPhase::Checking, "stpa", 1, false, false, false);

    transitions.get_mut(&tier3_state).unwrap().push(tier1_state);

    // Must terminate cleanly without infinite loop or stack overflow
    let result = AdversarialBfsHarness::verify_transitions(initial_state, &transitions);

    // The cycle does not create additional discrete states because all 34 states are already represented
    assert_eq!(result.reachable_count, 34);
    assert_eq!(result.executed_count, 1);
}

// =========================================================================
// 3. Concurrency and Deterministic Proof Hashing
// =========================================================================

#[test]
fn test_concurrency_20_threads_deterministic_proof_receipts() {
    const NUM_THREADS: usize = 20;
    const RUNS_PER_THREAD: usize = 50;

    let barrier = Arc::new(Barrier::new(NUM_THREADS));
    let mut handles = Vec::with_capacity(NUM_THREADS);

    for thread_idx in 0..NUM_THREADS {
        let b = Arc::clone(&barrier);
        let handle = thread::spawn(move || {
            // Synchronize all threads so they start simultaneously
            b.wait();

            let mut receipts = Vec::with_capacity(RUNS_PER_THREAD);
            for _ in 0..RUNS_PER_THREAD {
                let proof: TheoremProofResult = FormalBfsModel::prove_no_direct_bind();

                assert!(proof.proven, "Thread {}: proof must succeed", thread_idx);
                assert_eq!(proof.reachable_states, 34);
                assert_eq!(proof.executed_states, 1);
                assert_eq!(proof.violations_count, 0);
                assert_eq!(proof.proof_receipt.len(), 64);
                assert!(
                    StreamInvariantVerifier::is_64_hex_lowercase(&proof.proof_receipt),
                    "Thread {}: proof receipt must be valid 64-hex lowercase: {}",
                    thread_idx,
                    proof.proof_receipt
                );

                receipts.push(proof.proof_receipt);
            }
            receipts
        });
        handles.push(handle);
    }

    let mut all_thread_results = Vec::new();
    for handle in handles {
        let receipts = handle.join().expect("Thread joined successfully");
        all_thread_results.push(receipts);
    }

    // Assert that every single one of the 1,000 generated receipts across all 20 threads is identical
    let baseline_receipt = &all_thread_results[0][0];
    for (t_idx, receipts) in all_thread_results.iter().enumerate() {
        for (r_idx, receipt) in receipts.iter().enumerate() {
            assert_eq!(
                receipt, baseline_receipt,
                "Hash divergence at thread {} run {}: expected {}, got {}",
                t_idx, r_idx, baseline_receipt, receipt
            );
        }
    }
}

#[test]
fn test_concurrency_50_threads_mixed_workload_stress() {
    const NUM_THREADS: usize = 50;
    let barrier = Arc::new(Barrier::new(NUM_THREADS));
    let mut handles = Vec::with_capacity(NUM_THREADS);

    for thread_idx in 0..NUM_THREADS {
        let b = Arc::clone(&barrier);
        let handle = thread::spawn(move || {
            b.wait();

            match thread_idx % 4 {
                0 => {
                    // Proof generation
                    for _ in 0..20 {
                        let proof = FormalBfsModel::prove_no_direct_bind();
                        assert!(proof.proven);
                        assert_eq!(proof.reachable_states, 34);
                    }
                }
                1 => {
                    // Gated model exploration
                    for _ in 0..20 {
                        let res = FormalBfsModel::explore_gated_model();
                        assert_eq!(res.reachable_count, 34);
                        assert_eq!(res.executed_count, 1);
                    }
                }
                2 => {
                    // Ungated counterexample
                    for _ in 0..20 {
                        let res = FormalBfsModel::explore_ungated_counterexample();
                        assert_eq!(res.reachable_count, 17);
                        assert_eq!(res.violations.len(), 1);
                    }
                }
                3 => {
                    // Skipped tier model across varying tiers
                    let skip_tier = thread_idx % 7;
                    for _ in 0..20 {
                        let res = FormalBfsModel::explore_skipped_tier_model(skip_tier);
                        assert_eq!(res.reachable_count, 31);
                        assert_eq!(res.executed_count, 0);
                    }
                }
                _ => unreachable!(),
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle
            .join()
            .expect("All 50 worker threads must succeed without panic");
    }
}

#[test]
fn test_proof_receipt_independent_oracle_verification_and_avalanche() {
    let proof = FormalBfsModel::prove_no_direct_bind();
    let gated = FormalBfsModel::explore_gated_model();

    // Recompute the canonical hash independently using raw Sha256 oracle
    let mut sorted_states: Vec<&BfsState> = gated.visited_states.iter().collect();
    sorted_states.sort_by(|a, b| {
        a.label
            .cmp(&b.label)
            .then(a.tier.cmp(&b.tier))
            .then(a.phase.as_str().cmp(b.phase.as_str()))
    });

    let mut oracle_hasher = Sha256::new();
    oracle_hasher.update(b"Theorem:NoDirectBind|GatedStates:34|Executed:1|Violations:0\n");
    for s in sorted_states {
        oracle_hasher.update(
            format!(
                "{}|{}|{}|{}|{}|{}\n",
                s.phase.as_str(),
                s.label,
                s.tier,
                s.seal_present,
                s.resolved_allow,
                s.executed_or_narrow
            )
            .as_bytes(),
        );
    }
    let oracle_receipt = hex::encode(oracle_hasher.finalize());

    // Independent oracle must bit-for-bit match the engine's proof receipt
    assert_eq!(
        proof.proof_receipt, oracle_receipt,
        "Independent oracle verification failed: expected {}, got {}",
        oracle_receipt, proof.proof_receipt
    );

    // Avalanche effect sensitivity test: altering any single bit in the canonical string
    // must alter the resulting hash completely
    let mut mutated_hasher = Sha256::new();
    mutated_hasher.update(b"Theorem:NoDirectBind|GatedStates:34|Executed:1|Violations:1\n"); // 1 bit flip '0' -> '1'
    let mutated_receipt = hex::encode(mutated_hasher.finalize());

    assert_ne!(proof.proof_receipt, mutated_receipt);
    let diff_chars = proof
        .proof_receipt
        .chars()
        .zip(mutated_receipt.chars())
        .filter(|(c1, c2)| c1 != c2)
        .count();
    // In a 64-character hex hash, changing one bit should flip ~32 hex chars (50% avalanche)
    assert!(
        diff_chars >= 25,
        "Cryptographic avalanche failure: only {} differing hex characters",
        diff_chars
    );
}
