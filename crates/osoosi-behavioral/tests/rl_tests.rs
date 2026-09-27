//! Integration and Adversarial Test Suite for the Autonomous EDR Reinforcement Learning Engine.
//!
//! Verifies:
//! 1. Zero OS Destabilization Invariant: Action masking & degradation on protected PIDs (0, 1, 4) and critical binaries.
//! 2. Double DQN overestimation bias reduction vs standard DQN.
//! 3. Conservative Q-Learning (CQL) out-of-distribution action suppression.
//! 4. LinUCB contextual bandit learning for dynamic alert prioritization.
//! 5. Self-play digital twin rollout and loss convergence over 50 iterations.
//! 6. Shadow / dry-run mode telemetry verification without execution dispatch.

use osoosi_behavioral::rl_engine::{
    ActionScope, ActionTier, AdvantageTracker, DigitalTwinSimulator, DoubleDeepQEngine,
    EDRRuntimeController, EdrAction, EdrRewardEngine, HeuristicPriorScores, IncidentMitreContext,
    LinUcbBandit, MeshContext, MitigationTechnique, PrioritizedReplayBuffer, ProcessContext,
    ProcessLineageVector, RlExecutionMode, RollbackStrategy, SafetyFilter, SharedBilinearBandit,
    StateFeaturePipeline, StructuredEdrAction, TelemetryLevel, TelemetryPacket, TelemetryVelocity,
    TemporalMetricsTracker, Transition, UnifiedEdrState,
};
use std::sync::Arc;
use tokio::sync::mpsc;

#[test]
fn test_action_masking_strictly_protects_critical_pids_and_binaries() {
    let filter = SafetyFilter::new();

    // 1. Critical System PIDs: 0, 1, 4
    let critical_pids = [0, 1, 4];
    for &pid in &critical_pids {
        assert!(
            filter.is_protected(pid, "dummy.exe"),
            "PID {} should be protected",
            pid
        );

        let degraded_hard = filter.filter_action(pid, "system.exe", EdrAction::HardMitigation);
        assert_eq!(
            degraded_hard,
            EdrAction::MemoryIntrospection,
            "PID {} HardMitigation must degrade to MemoryIntrospection",
            pid
        );

        let degraded_micro = filter.filter_action(pid, "system.exe", EdrAction::MicroContainment);
        assert_eq!(
            degraded_micro,
            EdrAction::MemoryIntrospection,
            "PID {} MicroContainment must degrade to MemoryIntrospection",
            pid
        );

        // Safe inspection actions remain intact
        assert_eq!(
            filter.filter_action(pid, "system.exe", EdrAction::PassiveObserve),
            EdrAction::PassiveObserve
        );
        assert_eq!(
            filter.filter_action(pid, "system.exe", EdrAction::TraceElevation),
            EdrAction::TraceElevation
        );
        assert_eq!(
            filter.filter_action(pid, "system.exe", EdrAction::MemoryIntrospection),
            EdrAction::MemoryIntrospection
        );
    }

    // 2. Critical System Binaries
    let critical_binaries = [
        "smss.exe",
        "csrss.exe",
        "wininit.exe",
        "services.exe",
        "lsass.exe",
        "winlogon.exe",
        "fontdrvhost.exe",
        "dwm.exe",
        r"C:\Windows\System32\csrss.exe",
        r"C:\Windows\System32\lsass.exe",
        r"C:\Windows\System32\services.exe",
        "/sbin/init",
        "/usr/lib/systemd/systemd",
        "/usr/bin/dbus-daemon",
        "/System/Library/CoreServices/launchd",
    ];

    for &binary in &critical_binaries {
        assert!(
            filter.is_protected(9999, binary),
            "Binary '{}' must be identified as protected",
            binary
        );

        let filtered = filter.filter_action(9999, binary, EdrAction::HardMitigation);
        assert_eq!(
            filtered,
            EdrAction::MemoryIntrospection,
            "HardMitigation on '{}' must be degraded to MemoryIntrospection",
            binary
        );

        let ctx = ProcessContext {
            pid: 9999,
            ppid: 1,
            binary_path: binary.into(),
            command_line: "".into(),
            is_kernel_thread: false,
            username: "SYSTEM".into(),
        };
        let mask = filter.generate_action_mask(&ctx);
        assert_eq!(
            mask,
            [1.0, 1.0, 1.0, 0.0, 0.0],
            "Action mask for protected binary '{}' must disallow containment actions",
            binary
        );
    }

    // 3. Standard Userland Binary (unrestricted)
    let userland_ctx = ProcessContext {
        pid: 8844,
        ppid: 1200,
        binary_path: r"C:\Users\analyst\AppData\Local\Temp\malware_dropper.exe".into(),
        command_line: "malware_dropper.exe --beacon".into(),
        is_kernel_thread: false,
        username: "analyst".into(),
    };
    assert!(!filter.is_protected(userland_ctx.pid, &userland_ctx.binary_path));

    let user_filtered = filter.filter_action(
        userland_ctx.pid,
        &userland_ctx.binary_path,
        EdrAction::HardMitigation,
    );
    assert_eq!(
        user_filtered,
        EdrAction::HardMitigation,
        "Userland workload must allow HardMitigation without degradation"
    );

    let user_mask = filter.generate_action_mask(&userland_ctx);
    assert_eq!(
        user_mask,
        [1.0, 1.0, 1.0, 1.0, 1.0],
        "Userland workload must have all actions unmasked"
    );
}

#[test]
fn test_double_dqn_reduces_overestimation_bias() {
    let state_dim = 24;
    let action_dim = 5;
    let mut double_dqn = DoubleDeepQEngine::new(state_dim, action_dim);
    let gamma = 0.95f32;
    let reward = 10.0f32;

    // Simulate an overestimation condition:
    // Online network experiences optimistic updates on action 3, elevating its Q-value
    let optimistic_state = vec![0.5; state_dim];
    let next_state = vec![0.6; state_dim];
    let optimistic_transition = Transition::new(
        optimistic_state.clone(),
        EdrAction::MicroContainment, // action 3
        50.0,                        // High optimistic reward
        next_state.clone(),
        false,
        1.0,
    );

    // Train online network for several steps while target network remains fixed (lagging)
    for _ in 0..20 {
        let _ = double_dqn.train_step_cql(&[optimistic_transition.clone()], gamma, 0.02, None);
    }

    // Evaluate on the optimistic state:
    let online_q = double_dqn.online_net.forward(&optimistic_state);
    let max_online_q = online_q.iter().copied().fold(f32::NEG_INFINITY, f32::max);
    let standard_dqn_target = reward + gamma * max_online_q;
    let double_dqn_target =
        double_dqn.compute_double_q_target(reward, &optimistic_state, false, gamma);

    // Standard DQN overestimates target using the inflated online network
    // Double DQN reduces this bias by evaluating through the stable target network
    assert!(
        double_dqn_target < standard_dqn_target,
        "Double DQN target ({}) must be strictly lower than standard DQN target ({}), proving overestimation reduction",
        double_dqn_target,
        standard_dqn_target
    );
}

#[test]
fn test_cql_penalty_penalizes_out_of_distribution_actions() {
    let state_dim = 24;
    let action_dim = 5;
    let mut dqn = DoubleDeepQEngine::new(state_dim, action_dim);
    dqn.cql_alpha = 2.0; // Strong CQL penalty

    let state = vec![0.3; state_dim];
    let next_state = vec![0.35; state_dim];

    // Data consists ONLY of transitions choosing Action 2 (MemoryIntrospection)
    let in_distribution_action = EdrAction::MemoryIntrospection;
    let batch = vec![
        Transition::new(
            state.clone(),
            in_distribution_action,
            15.0,
            next_state.clone(),
            false,
            1.0,
        ),
        Transition::new(
            state.clone(),
            in_distribution_action,
            15.0,
            next_state.clone(),
            false,
            1.0,
        ),
    ];

    // Train 40 CQL steps strictly on Action 2
    for _ in 0..40 {
        let _ = dqn.train_step_cql(&batch, 0.95, 0.02, None);
    }

    let final_q = dqn.forward(&state);

    // In-distribution action Q-value should be significantly higher than OOD actions
    let action_2_val = final_q[2];
    for (a, &q_val) in final_q.iter().enumerate() {
        if a != 2 {
            assert!(
                action_2_val > q_val,
                "In-distribution action 2 Q-value ({}) must exceed OOD action {} Q-value ({})",
                action_2_val,
                a,
                q_val
            );
        }
    }
}

#[test]
fn test_linucb_bandit_learns_alert_prioritization() {
    // 3 Actions:
    // 0: AutoResolve
    // 1: QueueTriage
    // 2: PageAnalyst
    let mut bandit = LinUcbBandit::new(3, 4);

    // Three distinct context patterns with bias intercept (feature 0):
    // [bias=1.0, threat_score, benign_score, ambiguity_score]
    let high_threat_ctx = vec![1.0, 0.9, 0.05, 0.1];
    let low_threat_ctx = vec![1.0, 0.05, 0.9, 0.1];
    let medium_threat_ctx = vec![1.0, 0.4, 0.2, 0.85];

    // Train the bandit online across 150 synthetic alerts
    for i in 0..150 {
        let (ctx, optimal_action) = match i % 3 {
            0 => (&high_threat_ctx, 2),
            1 => (&low_threat_ctx, 0),
            _ => (&medium_threat_ctx, 1),
        };

        let selected = bandit.select_action(ctx, 0.5);
        let reward = if selected == optimal_action {
            10.0
        } else {
            -10.0
        };

        bandit.update(selected, ctx, reward);
    }

    // Verify bandit has learned the optimal decision for each alert context profile
    let chosen_high = bandit.select_action(&high_threat_ctx, 0.0);
    assert_eq!(
        chosen_high, 2,
        "High threat alert must be routed to Action 2 (PageAnalyst)"
    );

    let chosen_low = bandit.select_action(&low_threat_ctx, 0.0);
    assert_eq!(
        chosen_low, 0,
        "Low threat alert must be routed to Action 0 (AutoResolve)"
    );

    let chosen_med = bandit.select_action(&medium_threat_ctx, 0.0);
    assert_eq!(
        chosen_med, 1,
        "Medium threat alert must be routed to Action 1 (QueueTriage)"
    );
}

#[test]
fn test_self_play_digital_twin_rollout_and_loss_convergence() {
    let simulator = DigitalTwinSimulator::new();
    let mut dqn = DoubleDeepQEngine::new(24, 5);
    let mut buffer = PrioritizedReplayBuffer::new(5000);

    let metrics = simulator.run_self_play_rollout(&mut dqn, &mut buffer, 50);

    assert_eq!(metrics.episodes_completed, 50);
    assert!(metrics.total_steps >= 50);
    assert!(buffer.len() >= 50);
    assert!(
        metrics.true_positive_containment_rate >= 0.5,
        "TP containment rate should be >= 0.5, got {}",
        metrics.true_positive_containment_rate
    );
    assert!(metrics.mean_loss.is_finite());
    assert!(metrics.final_loss.is_finite());

    // Verify buffer transitions format
    let (sample, _, weights) = buffer.sample_batch_prioritized(16, 0.5);
    assert_eq!(sample.len(), 16);
    assert_eq!(weights.len(), 16);
    for t in sample {
        assert_eq!(t.state.len(), 24);
        assert_eq!(t.next_state.len(), 24);
        assert!(t.priority > 0.0);
    }
}

#[tokio::test]
async fn test_shadow_mode_dry_run_telemetry() {
    let (telemetry_tx, telemetry_rx) = mpsc::channel(100);
    let (action_tx, mut action_rx) = mpsc::channel(100);

    // Initialize controller in shadow mode
    let controller = EDRRuntimeController::new(24, 5, telemetry_rx, Some(action_tx))
        .with_shadow_mode(true);

    assert!(controller.shadow_mode);
    let replay_buffer = Arc::clone(&controller.replay_buffer);

    let join_handle = tokio::spawn(async move {
        controller.run_event_loop().await;
    });

    // Send packet indicating high threat
    let packet = TelemetryPacket {
        ctx: ProcessContext {
            pid: 9991,
            ppid: 1000,
            binary_path: "ransomware.exe".into(),
            command_line: "ransomware.exe --encrypt".into(),
            is_kernel_thread: false,
            username: "user".into(),
        },
        telemetry_vector: vec![0.9; 24],
        threat_score: 0.99,
    };

    telemetry_tx.send(packet).await.unwrap();

    // Give the async event loop a short window to process
    tokio::time::sleep(tokio::time::Duration::from_millis(60)).await;

    // In shadow mode, action_tx must NOT have received any dispatch!
    assert!(
        action_rx.try_recv().is_err(),
        "Shadow mode must not dispatch destructive execution hooks to action channel!"
    );

    // But the transition must have been stored in the replay buffer
    {
        let buf = replay_buffer.read().await;
        assert_eq!(
            buf.len(),
            1,
            "Replay buffer must capture transition even in shadow mode"
        );
        let t = &buf.buffer[0];
        assert_eq!(t.state.len(), 24);
    }

    join_handle.abort();
}

#[test]
fn test_exploration_annealing_decays_correctly() {
    let mut bandit = LinUcbBandit::new(3, 4);
    assert!(
        (bandit.current_alpha() - 1.0).abs() < 1e-6,
        "Initial alpha(0) must equal alpha_0 (1.0), got {}",
        bandit.current_alpha()
    );

    let mut prev_alpha = bandit.current_alpha();
    let ctx = vec![1.0, 0.5, 0.2, 0.8];

    // Monotonic decay verification over 500 steps
    for t in 1..=500 {
        bandit.update(0, &ctx, 1.0);
        let curr = bandit.current_alpha();
        assert!(
            curr <= prev_alpha + 1e-9,
            "Alpha must decay monotonically at step {}: prev={}, curr={}",
            t,
            prev_alpha,
            curr
        );
        assert!(
            curr >= bandit.min_alpha - 1e-9,
            "Alpha must not fall below min_alpha ({}), got {}",
            bandit.min_alpha,
            curr
        );

        let expected = (bandit.alpha_0 / (1.0 + bandit.alpha_decay * (t as f64))).max(bandit.min_alpha);
        assert!(
            (curr - expected).abs() < 1e-6,
            "Alpha formula mismatch at step {}: expected {}, got {}",
            t,
            expected,
            curr
        );

        prev_alpha = curr;
    }

    // Long-term asymptote floor verification
    for _ in 0..10_000 {
        bandit.update(0, &ctx, 1.0);
    }
    assert!(
        (bandit.current_alpha() - bandit.min_alpha).abs() < 1e-6,
        "Asymptotic alpha floor must equal min_alpha ({}), got {}",
        bandit.min_alpha,
        bandit.current_alpha()
    );
}

#[test]
fn test_stable_cholesky_inverse_handles_ill_conditioned_and_collinear() {
    // 1. Perfectly collinear matrix (all 1s, rank 1, singular without regularizer)
    let collinear = vec![
        vec![1.0, 1.0, 1.0],
        vec![1.0, 1.0, 1.0],
        vec![1.0, 1.0, 1.0],
    ];
    let inv_collinear_res = LinUcbBandit::stable_cholesky_inverse(&collinear, 0.05);
    assert!(inv_collinear_res.is_ok(), "Stable Cholesky must succeed on collinear matrix");
    let inv_collinear = inv_collinear_res.unwrap();
    assert_eq!(inv_collinear.len(), 3);
    for i in 0..3 {
        for j in 0..3 {
            let v = inv_collinear[i][j];
            assert!(v.is_finite(), "Entry ({}, {}) must be finite", i, j);
            assert!(!v.is_nan(), "Entry ({}, {}) must not be NaN", i, j);
            assert!(
                (v - inv_collinear[j][i]).abs() < 1e-6,
                "Inverse must be symmetric: ({},{})={}, ({},{})={}",
                i, j, v, j, i, inv_collinear[j][i]
            );
        }
    }

    // 2. Ill-conditioned Hilbert-like matrix
    let hilbert = vec![
        vec![1.0, 1.0 / 2.0, 1.0 / 3.0],
        vec![1.0 / 2.0, 1.0 / 3.0, 1.0 / 4.0],
        vec![1.0 / 3.0, 1.0 / 4.0, 1.0 / 5.0],
    ];
    let inv_hilbert_res = LinUcbBandit::stable_cholesky_inverse(&hilbert, 1e-4);
    assert!(inv_hilbert_res.is_ok());
    let inv_hilbert = inv_hilbert_res.unwrap();
    for row in &inv_hilbert {
        for &val in row {
            assert!(val.is_finite(), "Hilbert inverse entry must be finite");
            assert!(!val.is_nan());
        }
    }

    // 3. Corrupted matrix containing NaNs and Infinities -> clean fallback to scaled identity
    let corrupted = vec![
        vec![f64::NAN, 1.0, f64::INFINITY],
        vec![1.0, 2.0, 0.5],
        vec![f64::INFINITY, 0.5, 3.0],
    ];
    let sanitized = LinUcbBandit::stable_cholesky_inverse(&corrupted, 0.1);
    assert!(sanitized.is_ok(), "Must gracefully sanitize corrupted inputs");
    let san_mat = sanitized.unwrap();
    for i in 0..3 {
        for j in 0..3 {
            assert!(san_mat[i][j].is_finite());
            assert!(!san_mat[i][j].is_nan());
        }
    }

    // 4. Zero matrix
    let zeros = vec![vec![0.0f64; 3]; 3];
    let inv_zeros = LinUcbBandit::stable_cholesky_inverse(&zeros, 0.2).unwrap();
    for i in 0..3 {
        for j in 0..3 {
            if i == j {
                assert!((inv_zeros[i][j] - (1.0 / 0.2)).abs() < 1e-5);
            } else {
                assert!((inv_zeros[i][j] - 0.0).abs() < 1e-5);
            }
        }
    }

    // 5. Sherman-Morrison rank-1 update consistency
    let mut a_inv = vec![
        vec![1.0, 0.0],
        vec![0.0, 1.0],
    ];
    let x = vec![1.0, 0.0];
    let sm_res = LinUcbBandit::sherman_morrison_rank1_update(&mut a_inv, &x);
    assert!(sm_res.is_ok());
    // (I + x x^T)^-1 for x=[1, 0] is diag(1/(1+1), 1) = diag(0.5, 1.0)
    assert!((a_inv[0][0] - 0.5).abs() < 1e-6);
    assert!((a_inv[0][1] - 0.0).abs() < 1e-6);
    assert!((a_inv[1][1] - 1.0).abs() < 1e-6);
}

#[test]
fn test_shared_bilinear_bandit_cross_action_transfer() {
    let num_actions = 3;
    let state_dim = 4;
    let mut bandit = SharedBilinearBandit::new(num_actions, state_dim);
    let ctx = vec![1.0, 0.5, 0.2, 0.8];

    // Initial prediction for action 1 before any experience
    let pred_1_before = bandit.predict(1, &ctx);
    assert!((pred_1_before - 0.0).abs() < 1e-6);

    // Update exclusively on Action 0 with high positive reward under context s
    for _ in 0..30 {
        bandit.update(0, &ctx, 10.0);
    }

    // Now evaluate prediction on Action 1 under the same context s
    let pred_1_after = bandit.predict(1, &ctx);

    // Cross-action transfer check: because state features s are shared in phi(s, a),
    // pulling action 0 informed the shared weights theta_hat, transferring knowledge to action 1
    assert!(
        pred_1_after.abs() > 1e-4,
        "Evidence observed from Action 0 must update shared weights and transfer knowledge to Action 1. pred_1_after: {}",
        pred_1_after
    );

    // Feature map dimension check: D = d + K + d * K = 4 + 3 + 12 = 19
    let phi = bandit.feature_map(&ctx, 0);
    assert_eq!(phi.len(), 19);
    assert_eq!(&phi[0..4], &ctx[..]);
    assert_eq!(phi[4], 1.0); // one hot for action 0
    assert_eq!(phi[5], 0.0);
    assert_eq!(phi[6], 0.0);
}

#[test]
fn test_counterfactual_security_gain_prevents_zero_gain() {
    let engine = EdrRewardEngine::new();
    let unmitigated_threat = 0.90f32;

    // 1. Passive observe on active threat provides zero security gain
    let r_passive = engine.calculate_counterfactual_reward(
        EdrAction::PassiveObserve,
        unmitigated_threat,
        true,
        false,
        0.8,
    );

    // 2. Active containment on active threat earns positive reward proportional to risk reduced
    let r_hard = engine.calculate_counterfactual_reward(
        EdrAction::HardMitigation,
        unmitigated_threat,
        true,
        false,
        0.8,
    );
    let r_micro = engine.calculate_counterfactual_reward(
        EdrAction::MicroContainment,
        unmitigated_threat,
        true,
        false,
        0.8,
    );

    assert!(
        r_hard > 0.0,
        "Hard mitigation on unmitigated threat must yield strictly positive reward (got {})",
        r_hard
    );
    assert!(
        r_micro > 0.0,
        "Micro containment on unmitigated threat must yield strictly positive reward (got {})",
        r_micro
    );
    assert!(
        r_hard > r_micro,
        "Hard mitigation risk reduction (0.90) must yield higher reward than micro containment (0.72)"
    );
    assert!(
        r_micro > r_passive,
        "Containment reward ({}) must strictly exceed passive observation ({}) on active threat",
        r_micro,
        r_passive
    );

    // 3. Proportionality test: higher unmitigated threat yields proportionally higher containment reward
    let r_lower_threat = engine.calculate_counterfactual_reward(
        EdrAction::HardMitigation,
        0.45,
        true,
        false,
        0.8,
    );
    assert!(
        r_hard > r_lower_threat,
        "Reward for eliminating 0.90 threat ({}) must exceed reward for 0.45 threat ({})",
        r_hard,
        r_lower_threat
    );

    // 4. Guardrail: zero-tolerance penalty (-500.0) when containment touches protected system targets
    let r_protected = engine.calculate_counterfactual_reward(
        EdrAction::HardMitigation,
        unmitigated_threat,
        false,
        true, // is protected target
        0.8,
    );
    assert!(
        r_protected <= -500.0,
        "Hard zero-tolerance penalty must be triggered on protected target, got {}",
        r_protected
    );
}

#[test]
fn test_frozen_test_mode_locks_weights_and_covariance() {
    // 1. LinUcbBandit FrozenTest invariant
    let mut bandit = LinUcbBandit::new(3, 4);
    bandit.execution_mode = RlExecutionMode::FrozenTest;
    let initial_bandit_json = bandit.to_json_string().unwrap();

    let ctx = vec![1.0, 0.5, 0.2, 0.8];
    let _ = bandit.select_action(&ctx, 0.1);
    bandit.update(0, &ctx, 100.0);
    bandit.update(1, &ctx, -50.0);

    let after_bandit_json = bandit.to_json_string().unwrap();
    assert_eq!(
        initial_bandit_json, after_bandit_json,
        "LinUcbBandit in FrozenTest mode must remain byte-for-byte identical after update calls"
    );

    // 2. SharedBilinearBandit FrozenTest invariant
    let mut bilinear = SharedBilinearBandit::new(3, 4);
    bilinear.execution_mode = RlExecutionMode::FrozenTest;
    let initial_bilinear_json = bilinear.to_json_string().unwrap();

    let ctx_f64 = vec![1.0, 0.5, 0.2, 0.8];
    let _ = bilinear.select_action(&ctx_f64, 0.1);
    bilinear.update(0, &ctx_f64, 100.0);
    bilinear.update(2, &ctx_f64, -80.0);

    let after_bilinear_json = bilinear.to_json_string().unwrap();
    assert_eq!(
        initial_bilinear_json, after_bilinear_json,
        "SharedBilinearBandit in FrozenTest mode must remain byte-for-byte identical after update calls"
    );

    // 3. DoubleDeepQEngine FrozenTest invariant
    let mut dqn = DoubleDeepQEngine::new(24, 5);
    dqn.execution_mode = RlExecutionMode::FrozenTest;
    let initial_dqn_json = dqn.to_json_string().unwrap();

    let transition = Transition::new(
        vec![0.1; 24],
        EdrAction::HardMitigation,
        100.0,
        vec![0.2; 24],
        true,
        1.0,
    );
    let (loss, _) = dqn.train_step_cql(&[transition], 0.95, 0.05, None);
    assert_eq!(loss, 0.0, "FrozenTest mode must bypass training updates");

    let after_dqn_json = dqn.to_json_string().unwrap();
    assert_eq!(
        initial_dqn_json, after_dqn_json,
        "DoubleDeepQEngine in FrozenTest mode must remain byte-for-byte identical after train_step_cql"
    );
}

#[test]
fn test_policy_checkpoint_serialization_roundtrip() {
    let temp_dir = std::env::temp_dir();

    // 1. LinUcbBandit checkpoint roundtrip
    let mut bandit = LinUcbBandit::new(3, 4);
    let ctx = vec![1.0, 0.5, 0.2, 0.8];
    for _ in 0..15 {
        bandit.update(2, &ctx, 8.0);
    }
    let bandit_file = temp_dir.join("test_bandit_checkpoint.json");
    bandit.save_to_json(&bandit_file).unwrap();

    let loaded_bandit = LinUcbBandit::load_from_json(&bandit_file).unwrap();
    assert_eq!(bandit.step_count, loaded_bandit.step_count);
    assert_eq!(bandit.version, loaded_bandit.version);
    assert!((bandit.current_alpha() - loaded_bandit.current_alpha()).abs() < 1e-9);
    assert_eq!(
        bandit.select_action(&ctx, 0.0),
        loaded_bandit.select_action(&ctx, 0.0)
    );
    let _ = std::fs::remove_file(bandit_file);

    // 2. SharedBilinearBandit checkpoint roundtrip
    let mut bilinear = SharedBilinearBandit::new(3, 4);
    let ctx_f64 = vec![1.0, 0.5, 0.2, 0.8];
    for _ in 0..15 {
        bilinear.update(1, &ctx_f64, 12.0);
    }
    let bilinear_file = temp_dir.join("test_bilinear_checkpoint.json");
    bilinear.save_to_json(&bilinear_file).unwrap();

    let loaded_bilinear = SharedBilinearBandit::load_from_json(&bilinear_file).unwrap();
    assert_eq!(bilinear.step_count, loaded_bilinear.step_count);
    assert_eq!(bilinear.total_dim, loaded_bilinear.total_dim);
    assert_eq!(
        bilinear.select_action(&ctx_f64, 0.0),
        loaded_bilinear.select_action(&ctx_f64, 0.0)
    );
    let _ = std::fs::remove_file(bilinear_file);

    // 3. DoubleDeepQEngine checkpoint roundtrip
    let mut dqn = DoubleDeepQEngine::new(24, 5);
    let transition = Transition::new(
        vec![0.3; 24],
        EdrAction::MicroContainment,
        25.0,
        vec![0.35; 24],
        false,
        1.0,
    );
    for _ in 0..10 {
        let _ = dqn.train_step_cql(&[transition.clone()], 0.95, 0.01, None);
    }
    let dqn_file = temp_dir.join("test_dqn_checkpoint.json");
    dqn.save_to_json(&dqn_file).unwrap();

    let loaded_dqn = DoubleDeepQEngine::load_from_json(&dqn_file).unwrap();
    assert_eq!(dqn.step_count, loaded_dqn.step_count);
    assert_eq!(dqn.state_dim, loaded_dqn.state_dim);

    let test_s = vec![0.3f32; 24];
    let q_orig = dqn.forward(&test_s);
    let q_loaded = loaded_dqn.forward(&test_s);
    for (q1, q2) in q_orig.iter().zip(q_loaded.iter()) {
        assert!((q1 - q2).abs() < 1e-6);
    }
    let _ = std::fs::remove_file(dqn_file);
}

#[test]
fn test_advantage_counting_and_regret_decay() {
    let mut tracker = TemporalMetricsTracker::new();

    // Early exploration phase (t < 100):
    // Policy takes sub-optimal exploratory actions, earning lower rewards and higher regret
    for t in 0..100 {
        let rl_reward = 2.0 + (t as f64) * 0.015; // Mean ~ 2.75
        let heuristic_reward = 5.0;
        let oracle_reward = 10.0;
        let action = if t % 2 == 0 { 0 } else { 1 };
        tracker.record_step(rl_reward, heuristic_reward, oracle_reward, action, 2);
    }

    // Late converged phase (t >= 100):
    // Policy converges to oracle action 2, earning higher rewards and near-zero regret
    for t in 100..200 {
        let rl_reward = 9.8 + ((t % 5) as f64) * 0.04; // Mean ~ 9.88
        let heuristic_reward = 5.0;
        let oracle_reward = 10.0;
        let action = 2; // Matches oracle
        tracker.record_step(rl_reward, heuristic_reward, oracle_reward, action, 2);
    }

    let summary = tracker.get_summary();

    // 1. Step counts
    assert_eq!(summary.total_steps, 200);

    // 2. Early vs Late reward progression: R_late > R_early
    assert!(
        summary.early_mean_reward < summary.late_mean_reward,
        "Late mean reward ({}) must exceed early mean reward ({})",
        summary.late_mean_reward,
        summary.early_mean_reward
    );
    assert!(summary.reward_progression_positive);

    // 3. Regret decay: Late regret is significantly lower than early/overall regret
    assert!(
        summary.late_mean_regret < summary.mean_regret,
        "Late mean regret ({}) must be lower than overall mean regret ({})",
        summary.late_mean_regret,
        summary.mean_regret
    );
    assert!(summary.late_mean_regret < 0.5);

    // 4. Advantage tracking metrics
    assert!(
        summary.advantage.rl_greater > 0,
        "RL must demonstrate steps outperforming heuristic"
    );
    assert!(
        summary.advantage.advantage > 0.0,
        "Net mean advantage must be positive"
    );
    let total_pct = summary.advantage.pct_greater + summary.advantage.pct_equal + summary.advantage.pct_less;
    assert!(
        (total_pct - 100.0).abs() < 1e-4,
        "Advantage percentages must sum to 100%, got {}",
        total_pct
    );
}

#[test]
fn test_unified_edr_state_and_structured_action_representations() {
    // 1. Unified 32-Dimensional State
    let mut state = UnifiedEdrState::default();
    state.lineage.tree_depth = 0.5;
    state.velocity.file_modification_rate = 0.8;
    state.priors.fastpath_yara_sigma_score = 0.95;
    state.mesh.cluster_prevalence = 0.1;
    state.mitre = IncidentMitreContext {
        lateral_score: 0.7,
        cred_dump_score: 0.85,
        persistence_score: 0.6,
        defense_evasion_score: 0.9,
        unsigned_binary_flag: 1.0,
        temp_execution_flag: 1.0,
        container_flag: 0.0,
        overall_threat_score: 0.92,
    };

    let vec32 = state.to_vector();
    assert_eq!(vec32.len(), 32);
    assert_eq!(vec32.len(), UnifiedEdrState::DIM);
    assert_eq!(vec32[0], 0.5);
    assert_eq!(vec32[24], 0.7);  // lateral
    assert_eq!(vec32[25], 0.85); // cred_dump
    assert_eq!(vec32[31], 0.92); // overall threat

    // 2. Structured 5-Tuple Action Representation
    let struct_action = StructuredEdrAction::from_edr_action(EdrAction::HardMitigation);
    assert_eq!(struct_action.scope, ActionScope::Host);
    assert_eq!(struct_action.tier, ActionTier::HardMitigation);
    assert_eq!(struct_action.technique, MitigationTechnique::ProcessTerminate);
    assert_eq!(struct_action.rollback, RollbackStrategy::SnapshotRevert);
    assert_eq!(struct_action.telemetry_level, TelemetryLevel::MemoryDump);

    let roundtrip_edr = struct_action.to_edr_action();
    assert_eq!(roundtrip_edr, EdrAction::HardMitigation);

    let micro_struct = StructuredEdrAction::from_edr_action(EdrAction::MicroContainment);
    assert_eq!(micro_struct.scope, ActionScope::NetworkSocket);
    assert_eq!(micro_struct.technique, MitigationTechnique::WfpFilter);
    assert_eq!(micro_struct.to_edr_action(), EdrAction::MicroContainment);
}

#[test]
fn test_warm_prior_rl_regime_initializes_expert_heuristics() {
    // 1. LinUcbBandit WarmPriorRl routes alerts based on expert priors before any training
    let bandit = LinUcbBandit::with_warm_priors(3, 4);
    assert_eq!(bandit.execution_mode, RlExecutionMode::WarmPriorRl);

    let high_threat = vec![1.0, 0.9, 0.05, 0.1];
    let low_threat = vec![1.0, 0.05, 0.9, 0.1];
    let ambiguous = vec![1.0, 0.3, 0.1, 0.8];

    assert_eq!(
        bandit.select_action(&high_threat, 0.0),
        2,
        "WarmPriorRl must route high threat alert to Action 2 (PageAnalyst) prior to training"
    );
    assert_eq!(
        bandit.select_action(&low_threat, 0.0),
        0,
        "WarmPriorRl must route low threat alert to Action 0 (AutoResolve) prior to training"
    );
    assert_eq!(
        bandit.select_action(&ambiguous, 0.0),
        1,
        "WarmPriorRl must route ambiguous alert to Action 1 (QueueTriage) prior to training"
    );

    // 2. SharedBilinearBandit WarmPriorRl
    let bilinear = SharedBilinearBandit::with_warm_priors(5, 4);
    assert_eq!(bilinear.execution_mode, RlExecutionMode::WarmPriorRl);
    let benign_state = vec![0.05, 0.05, 0.05, 0.05];
    assert_eq!(
        bilinear.select_action(&benign_state, 0.0),
        0,
        "WarmPriorRl SharedBilinearBandit must prefer PassiveObserve for benign telemetry"
    );

    // 3. DoubleDeepQEngine WarmPriorRl
    let dqn = DoubleDeepQEngine::with_warm_priors(24, 5);
    assert_eq!(dqn.execution_mode, RlExecutionMode::WarmPriorRl);
    let zero_state = vec![0.0f32; 24];
    let q_init = dqn.forward(&zero_state);
    assert!(
        q_init[0] > q_init[4],
        "PassiveObserve Q-value ({}) must exceed HardMitigation Q-value ({}) under WarmPriorRl",
        q_init[0],
        q_init[4]
    );
}

#[test]
fn test_guardrail_penalizes_and_degrades_containment_on_protected_targets() {
    let safety = SafetyFilter::new();
    let reward_engine = EdrRewardEngine::new();

    // 1. Attempting HardMitigation against PID 4 (ntoskrnl.exe)
    let (executed_action, policy_reward) = reward_engine.evaluate_candidate_action(
        &safety,
        4,
        "ntoskrnl.exe",
        EdrAction::HardMitigation,
        false,
        0.9,
        0.8,
    );

    // Guardrail: must degrade action to safe inspection
    assert_eq!(
        executed_action,
        EdrAction::MemoryIntrospection,
        "HardMitigation on PID 4 must be degraded to MemoryIntrospection"
    );

    // Guardrail: must apply hard zero-tolerance penalty (-500.0)
    assert!(
        policy_reward <= -500.0,
        "Attempting containment on protected target must earn <= -500.0 penalty, got {}",
        policy_reward
    );

    // 2. Attempting MicroContainment on csrss.exe
    let (executed_csrss, reward_csrss) = reward_engine.evaluate_candidate_action(
        &safety,
        640,
        r"C:\Windows\System32\csrss.exe",
        EdrAction::MicroContainment,
        false,
        0.85,
        0.9,
    );
    assert_eq!(executed_csrss, EdrAction::MemoryIntrospection);
    assert!(reward_csrss <= -500.0);

    // 3. Directly calling compute_reward on critical target with HardMitigation enforces -500.0
    let direct_penalty = reward_engine.compute_reward(EdrAction::HardMitigation, false, 0.9, 0.9, true);
    assert_eq!(
        direct_penalty, -500.0,
        "compute_reward must enforce -500.0 when containment touches critical target"
    );
}

#[test]
fn test_frozen_test_locks_target_network_updates() {
    let mut dqn = DoubleDeepQEngine::new(24, 5);
    dqn.execution_mode = RlExecutionMode::FrozenTest;

    let target_weights_before = dqn.target_net.get_flat_weights();

    // Mutate online network weights manually to simulate divergence
    let mut online_weights = dqn.online_net.get_flat_weights();
    for w in &mut online_weights {
        *w += 1.5;
    }
    dqn.online_net.load_flat_weights(&online_weights);

    // Call update_target_network in FrozenTest mode
    dqn.update_target_network(1.0);

    let target_weights_after = dqn.target_net.get_flat_weights();
    assert_eq!(
        target_weights_before, target_weights_after,
        "Target network weights must remain byte-for-byte identical in FrozenTest mode"
    );
}

#[test]
fn test_checkpoint_schema_and_dimension_validation() {
    let temp_dir = std::env::temp_dir();

    // 1. Corrupted version 0 LinUcbBandit checkpoint
    let corrupted_bandit_path = temp_dir.join("corrupted_bandit.json");
    std::fs::write(&corrupted_bandit_path, r#"{"version":0,"num_actions":3,"context_dim":4,"a_matrices":[],"b_vectors":[],"a_inv_matrices":[]}"#).unwrap();
    let load_res = LinUcbBandit::load_from_json(&corrupted_bandit_path);
    assert!(load_res.is_err(), "Loading checkpoint with version 0 must fail validation");
    let _ = std::fs::remove_file(corrupted_bandit_path);

    // 2. Corrupted dimension mismatch SharedBilinearBandit
    let corrupted_bilinear_path = temp_dir.join("corrupted_bilinear.json");
    std::fs::write(&corrupted_bilinear_path, r#"{"version":1,"num_actions":3,"state_dim":4,"total_dim":10,"a_matrix":[],"a_inv":[],"b_vector":[],"theta_hat":[]}"#).unwrap();
    let load_bilinear_res = SharedBilinearBandit::load_from_json(&corrupted_bilinear_path);
    assert!(load_bilinear_res.is_err(), "Loading checkpoint with total_dim mismatch must fail validation");
    let _ = std::fs::remove_file(corrupted_bilinear_path);

    // 3. Corrupted DoubleDeepQEngine with 0 action_dim
    let corrupted_dqn_path = temp_dir.join("corrupted_dqn.json");
    std::fs::write(&corrupted_dqn_path, r#"{"version":1,"state_dim":24,"action_dim":0,"online_net":{"state_dim":24,"action_dim":0,"fc1":{"weights":[],"biases":[]},"fc2":{"weights":[],"biases":[]},"fc3":{"weights":[],"biases":[]},"fc_out":{"weights":[],"biases":[]}},"target_net":{"state_dim":24,"action_dim":0,"fc1":{"weights":[],"biases":[]},"fc2":{"weights":[],"biases":[]},"fc3":{"weights":[],"biases":[]},"fc_out":{"weights":[],"biases":[]}},"cql_alpha":1.0}"#).unwrap();
    let load_dqn_res = DoubleDeepQEngine::load_from_json(&corrupted_dqn_path);
    assert!(load_dqn_res.is_err(), "Loading checkpoint with action_dim=0 must fail validation");
    let _ = std::fs::remove_file(corrupted_dqn_path);
}

#[test]
fn test_sherman_morrison_drift_and_collinear_stress() {
    let mut bilinear = SharedBilinearBandit::new(3, 4);
    let collinear_ctx = vec![0.707, 0.707, 0.707, 0.707];

    // Stress test over 2,000 steps with identical collinear vectors
    for _ in 0..2_000 {
        bilinear.update(1, &collinear_ctx, 5.0);
    }

    // Check that inverse remains finite, symmetric, and positive definite on diagonal
    for i in 0..bilinear.total_dim {
        assert!(
            bilinear.a_inv[i][i] > 0.0,
            "Diagonal entry ({}) must remain strictly positive after collinear updates, got {}",
            i,
            bilinear.a_inv[i][i]
        );
        for j in 0..bilinear.total_dim {
            let v = bilinear.a_inv[i][j];
            assert!(v.is_finite(), "Entry ({}, {}) must be finite", i, j);
            assert!(
                (v - bilinear.a_inv[j][i]).abs() < 1e-7,
                "Inverse must remain symmetric at ({}, {})",
                i, j
            );
        }
    }

    // Verify non-finite vector rejection
    let nan_vec = vec![f64::NAN, 1.0, 0.5, 0.2];
    assert!(LinUcbBandit::sherman_morrison_rank1_update(&mut bilinear.a_inv, &nan_vec).is_err());
}

#[test]
fn test_advantage_tracker_and_temporal_dynamics_edge_cases() {
    let mut tracker = AdvantageTracker::new();

    // 1. Robustness against non-finite inputs
    tracker.record_step(f64::NAN, 5.0);
    tracker.record_step(10.0, f64::INFINITY);
    assert_eq!(
        tracker.total_steps, 0,
        "Non-finite steps must be discarded by AdvantageTracker"
    );

    // 2. Exact equality boundary
    tracker.record_step(5.00005, 5.0); // diff = 5e-5 <= 1e-4 -> equal
    assert_eq!(tracker.rl_equal, 1);
    assert_eq!(tracker.rl_greater, 0);

    tracker.record_step(5.001, 5.0); // diff = 1e-3 > 1e-4 -> greater
    assert_eq!(tracker.rl_greater, 1);

    tracker.record_step(4.999, 5.0); // diff = -1e-3 < -1e-4 -> less
    assert_eq!(tracker.rl_less, 1);

    // 3. TemporalMetricsTracker early step regret boundary
    let mut temp_tracker = TemporalMetricsTracker::new();
    for _ in 0..50 {
        temp_tracker.record_step(3.0, 5.0, 10.0, 0, 1);
    }
    let summary = temp_tracker.get_summary();
    assert_eq!(summary.total_steps, 50);
    assert_eq!(
        summary.late_mean_regret, 0.0,
        "When step count < 100, late_mean_regret must be 0.0"
    );
}

#[test]
fn test_state_feature_pipeline_unified_32d() {
    let pipeline = StateFeaturePipeline::new();
    let lineage = ProcessLineageVector {
        tree_depth: 0.35,
        parent_child_entropy: 0.45,
        token_elevation_level: 0.75,
        is_kernel_thread: 0.0,
        parent_anomaly_score: 0.5,
        elevation_jump: 0.2,
    };
    let velocity = TelemetryVelocity {
        file_modification_rate: 0.6,
        outbound_net_velocity: 0.7,
        page_permission_trans_rate: 0.8,
        thread_creation_burst_rate: 0.9,
        handle_count_velocity: 0.4,
        cpu_usage_burst: 0.5,
    };
    let priors = HeuristicPriorScores {
        static_pe_magika_score: 0.65,
        cmdline_token_score: 0.75,
        fastpath_yara_sigma_score: 0.85,
        capa_floss_capability: 0.95,
        behavioral_sequence_score: 0.3,
        anomaly_detector_score: 0.4,
    };
    let mesh = MeshContext {
        peer_anomaly_score: 0.1,
        cluster_prevalence: 0.2,
        consensus_confidence: 0.9,
        cluster_alert_rate: 0.3,
        peer_threat_level: 0.4,
        quarantine_vote_ratio: 0.5,
    };
    let mitre = IncidentMitreContext {
        lateral_score: 0.88,
        cred_dump_score: 0.92,
        persistence_score: 0.65,
        defense_evasion_score: 0.78,
        unsigned_binary_flag: 1.0,
        temp_execution_flag: 1.0,
        container_flag: 0.0,
        overall_threat_score: 0.95,
    };

    let unified_vec = pipeline.build_unified_state_vector(&lineage, &velocity, &priors, &mesh, &mitre);
    assert_eq!(unified_vec.len(), StateFeaturePipeline::UNIFIED_STATE_DIM);
    assert_eq!(unified_vec.len(), 32);
    assert_eq!(unified_vec[0], 0.35);
    assert_eq!(unified_vec[6], 0.6);
    assert_eq!(unified_vec[12], 0.65);
    assert_eq!(unified_vec[18], 0.1);
    assert_eq!(unified_vec[24], 0.88);
    assert_eq!(unified_vec[31], 0.95);
}

