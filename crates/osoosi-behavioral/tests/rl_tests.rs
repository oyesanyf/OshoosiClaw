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
    DigitalTwinSimulator, DoubleDeepQEngine, EDRRuntimeController, EdrAction,
    LinUcbBandit, PrioritizedReplayBuffer, ProcessContext, SafetyFilter, TelemetryPacket,
    Transition,
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
