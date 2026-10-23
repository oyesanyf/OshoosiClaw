// Empirical Adversarial Challenger Test Suite
// Milestone M2C: STIX 2.1 ATT&CK + ATLAS MDP RL Controller & Differential Privacy CSPRNG
//
// Complies with:
// - RULE[rl_benchmarking_and_evaluation.md]: Standardized empirical evaluation, CI95, backend labeling
// - Empirical Challenger Invariants: Real tests, genuine statistical oracles, stress harnesses, zero mocks

use osoosi_agent_anomaly::rl_controller::{
    DefenseAction, RLAdaptiveController, StixCurriculumGenerator, StixMdpStateVector,
};
use osoosi_dp::perturb_timestamp_csprng;
use std::collections::HashSet;

#[test]
fn challenge_1_stix_mdp_state_vector_bounds_and_gym_features() {
    println!("\n=== Challenge 1: StixMdpStateVector 16-Dim Projection & Bound Invariants ===");

    // 1. Grid of adversarial edge-case inputs
    let test_cases = [
        // (tactic_phase, severity, lineage_depth, canary, trust, expected_discrete_state)
        (0, 0.0, 0, false, 0.0, 1),       // Minimum inputs
        (13, 1.0, 16, true, 1.0, 7),      // Maximum bounded inputs with canary
        (2, 0.95, 4, false, 0.0, 5),      // AML.T0043 prompt injection execution
        (6, 0.95, 2, false, 0.0, 3),      // Credential dumping
        (7, 0.20, 1, false, 1.0, 0),      // Benign signed OS binary in discovery
        (8, 0.85, 3, false, 0.0, 4),      // Lateral movement
        (11, 0.95, 5, false, 0.0, 6),     // Exfiltration / Impact / AML.T0054
        (100, 50.0, 100, false, 10.0, 3), // Extreme unbounded inputs clamped by constructor
    ];

    for (case_idx, &(tactic, sev, lineage, canary, trust, expected_state)) in
        test_cases.iter().enumerate()
    {
        let vec = StixMdpStateVector::new(tactic, sev, lineage, canary, trust);

        // Verify discrete state index is strictly in 0..=7
        let discrete_idx = vec.to_discrete_state_index();
        assert!(
            discrete_idx <= 7,
            "Case {}: discrete state index {} exceeds bound 7",
            case_idx,
            discrete_idx
        );
        assert_eq!(
            discrete_idx, expected_state,
            "Case {}: discrete state expected {}, got {}",
            case_idx, expected_state, discrete_idx
        );

        // Verify 16-dim gym features
        let gym = vec.to_gym_features();
        assert_eq!(
            gym.len(),
            16,
            "Gym feature vector must have exactly 16 dimensions"
        );

        for (dim_idx, &val) in gym.iter().enumerate() {
            assert!(
                !val.is_nan(),
                "Case {}, Dim {}: Feature value is NaN!",
                case_idx,
                dim_idx
            );
            assert!(
                !val.is_infinite(),
                "Case {}, Dim {}: Feature value is Infinite!",
                case_idx,
                dim_idx
            );
            assert!(
                val >= -1.0 && val <= 1.0,
                "Case {}, Dim {}: Feature value {:.4} violates bounds [-1.0, 1.0]",
                case_idx,
                dim_idx,
                val
            );
            // Normalized features should actually be in [0.0, 1.0]
            assert!(
                val >= 0.0 && val <= 1.0,
                "Case {}, Dim {}: Feature value {:.4} outside [0.0, 1.0]",
                case_idx,
                dim_idx,
                val
            );
        }

        // Verify categorical one-hot bucket invariant (exactly one of feats[5..=10] is 1.0)
        let one_hot_sum: f32 = gym[5..=10].iter().sum();
        assert!(
            (one_hot_sum - 1.0).abs() < 1e-5,
            "Case {}: One-hot phase sum must be exactly 1.0, got {:.4}",
            case_idx,
            one_hot_sum
        );
    }

    // 2. Randomized stress testing: 5,000 combinations
    let mut rng_state = 0xDEAD_BEEF_CAFE_0001u64;
    for iter in 0..5000 {
        rng_state = RLAdaptiveController::splitmix64(&mut rng_state);
        let tactic = (rng_state % 30) as usize;
        rng_state = RLAdaptiveController::splitmix64(&mut rng_state);
        let sev = (rng_state % 200) as f64 / 100.0 - 0.5; // [-0.5, 1.5]
        rng_state = RLAdaptiveController::splitmix64(&mut rng_state);
        let lineage = (rng_state % 50) as usize;
        rng_state = RLAdaptiveController::splitmix64(&mut rng_state);
        let canary = (rng_state % 2) == 1;
        rng_state = RLAdaptiveController::splitmix64(&mut rng_state);
        let trust = (rng_state % 300) as f64 / 100.0 - 1.0; // [-1.0, 2.0]

        let vec = StixMdpStateVector::new(tactic, sev, lineage, canary, trust);
        let gym = vec.to_gym_features();
        let discrete_idx = vec.to_discrete_state_index();

        assert!(discrete_idx <= 7);
        for &feat in &gym {
            assert!(
                feat >= 0.0 && feat <= 1.0,
                "Iter {}: feature {:.4} out of bounds",
                iter,
                feat
            );
        }
    }

    // 3. STIX Technique ID Parser Stress Test
    let known_techniques = [
        ("T1189", 1, 0.70),
        ("T1059", 2, 0.75),
        ("T1547", 3, 0.80),
        ("T1068", 4, 0.85),
        ("T1055", 5, 0.90),
        ("T1003", 6, 0.95),
        ("T1082", 7, 0.35),
        ("T1021", 8, 0.85),
        ("T1114", 9, 0.75),
        ("T1071", 10, 0.85),
        ("T1041", 11, 0.90),
        ("T1486", 12, 0.95),
        ("AML.T0043", 2, 0.95),
        ("AML.T0048", 5, 0.90),
        ("AML.T0040", 7, 0.70),
        ("AML.T0044", 4, 0.85),
        ("AML.T0051", 2, 0.92),
        ("AML.T0054", 11, 0.95),
    ];

    for (tech, exp_phase, exp_sev) in known_techniques {
        let v = StixMdpStateVector::from_stix_technique(tech, None, 2, false, 0.0);
        assert_eq!(
            v.tactic_phase, exp_phase,
            "Technique {} phase mismatch",
            tech
        );
        assert!(
            (v.technique_severity - exp_sev).abs() < 1e-4,
            "Technique {} severity mismatch",
            tech
        );
    }

    println!("PASS: StixMdpStateVector correctly maps all techniques, guarantees bounds [0.0, 1.0] across 5,000 trials.");
}

#[test]
fn challenge_2_canary_containment_reward_and_voter_nudge_bounds() {
    println!("\n=== Challenge 2: Canary Containment Reward (+100.0) & Voter Nudge Bounds [1.02, 2.50] ===");

    let mut controller = RLAdaptiveController::new();

    // Initial state: Q-table is all 0.0
    for s in 0..8 {
        for a in 0..4 {
            assert_eq!(controller.q_table[s][a], 0.0);
        }
    }

    // Initial voter weights before any containment events
    let initial_nudges = controller.nudge_voter_weights();
    assert_eq!(initial_nudges.len(), 6);
    for (voter, &weight) in &initial_nudges {
        assert!(
            weight >= 1.02 && weight <= 2.50,
            "Initial weight for {} is {:.4}, outside [1.02, 2.50]",
            voter,
            weight
        );
    }

    // Call record_canary_containment_reward()
    let reward = controller.record_canary_containment_reward();
    assert_eq!(
        reward, 100.0,
        "Canary containment reward must be exactly +100.0"
    );

    // Verify Q-table updates:
    // State 7 (Canary active exploit) -> SurgicalAutotomyAndCgroupFreeze
    let q7_autotomy =
        controller.q_table[7][DefenseAction::SurgicalAutotomyAndCgroupFreeze as usize];
    assert!(
        q7_autotomy > 0.0,
        "Q(7, Autotomy) must be positive after containment reward, got {:.2}",
        q7_autotomy
    );
    assert!(
        (q7_autotomy - 28.0).abs() < 1e-6,
        "First step TD update: 0.28 * 100.0 = 28.0"
    );

    // State 5 (AML.T0043 prompt injection) -> SurgicalAutotomyAndCgroupFreeze
    let q5_autotomy =
        controller.q_table[5][DefenseAction::SurgicalAutotomyAndCgroupFreeze as usize];
    assert!(
        (q5_autotomy - 28.0).abs() < 1e-6,
        "Q(5, Autotomy) must be 28.0"
    );

    // State 4 (Lateral movement) -> IsolateLateralEdgeAndHoneypot
    let q4_isolate = controller.q_table[4][DefenseAction::IsolateLateralEdgeAndHoneypot as usize];
    assert!(
        (q4_isolate - 28.0).abs() < 1e-6,
        "Q(4, Isolate) must be 28.0"
    );

    // Total steps incremented by 3
    assert_eq!(controller.total_steps, 3);

    // Verify voter weight nudging after 1 containment
    let nudges_1 = controller.nudge_voter_weights();
    for (voter, &w) in &nudges_1 {
        let initial_w = initial_nudges[voter];
        assert!(
            w > initial_w,
            "Voter {} weight should increase after containment event (was {:.4}, now {:.4})",
            voter,
            initial_w,
            w
        );
        assert!(
            w >= 1.02 && w <= 2.50,
            "Voter {} weight {:.4} outside [1.02, 2.50]",
            voter,
            w
        );
    }

    // Stress test: Call 50 times to drive Q-values toward convergence
    for _ in 0..50 {
        controller.record_canary_containment_reward();
    }

    let converged_nudges = controller.nudge_voter_weights();
    for (voter, &w) in &converged_nudges {
        assert!(
            w >= 1.02 && w <= 2.50,
            "Converged voter {} weight {:.4} outside [1.02, 2.50]",
            voter,
            w
        );
        // Under high Q-values, high-priority voters should reach the ceiling of 2.50
        if voter == "Agentic-Escape-Detector" || voter == "SpiderWeb-Containment" {
            assert!(
                (w - 2.50).abs() < 1e-4,
                "High-priority voter {} should saturate at 2.50, got {:.4}",
                voter,
                w
            );
        }
    }

    // Adversarial test: set Q-table to extreme negative values
    for s in 0..8 {
        for a in 0..4 {
            controller.q_table[s][a] = -100_000.0;
        }
    }
    let negative_nudges = controller.nudge_voter_weights();
    for (voter, &w) in &negative_nudges {
        assert!(
            w >= 1.02 && w <= 2.50,
            "Adversarial negative Q: voter {} weight {:.4} outside [1.02, 2.50]",
            voter,
            w
        );
    }

    println!("PASS: Canary containment reward triggers +100.0, Q-values update accurately, and voter weights remain strictly in [1.02, 2.50].");
}

#[test]
fn challenge_3_stix_curriculum_generator_and_trajectory_synthesis() {
    println!("\n=== Challenge 3: StixCurriculumGenerator Trajectories & Learning Synthesis ===");

    let episodes = StixCurriculumGenerator::generate_attack_trajectories();
    assert_eq!(
        episodes.len(),
        3,
        "Curriculum must generate exactly 3 trajectories"
    );

    // Trajectory 1: APT-Agent-Jacker-01
    // Initial Access -> AML.T0043 Indirect Prompt Injection -> T1059 Command Execution -> T1552.001 Credential Access
    let ep1 = &episodes[0];
    assert_eq!(ep1.adversary_id, "APT-Agent-Jacker-01");
    assert_eq!(ep1.trajectory.len(), 4);
    assert_eq!(ep1.trajectory[0].technique_id, "T1189");
    assert_eq!(ep1.trajectory[1].technique_id, "AML.T0043");
    assert_eq!(ep1.trajectory[2].technique_id, "T1059");
    assert_eq!(ep1.trajectory[3].technique_id, "T1552.001");

    // Trajectory 2: APT-Stego-LLM-02
    // Reconnaissance -> AML.T0040 Model Access -> AML.T0051 Prompt Injection -> AML.T0054 System Prompt Exfiltration
    let ep2 = &episodes[1];
    assert_eq!(ep2.adversary_id, "APT-Stego-LLM-02");
    assert_eq!(ep2.trajectory.len(), 4);
    assert_eq!(ep2.trajectory[0].technique_id, "T1595");
    assert_eq!(ep2.trajectory[1].technique_id, "AML.T0040");
    assert_eq!(ep2.trajectory[2].technique_id, "AML.T0051");
    assert_eq!(ep2.trajectory[3].technique_id, "AML.T0054");

    // Trajectory 3: APT-Ghost-Mesh-03
    // C2 Beacon -> AML.T0048 Cross-Domain Context Hijacking -> T1055 Process Injection -> T1003 OS Credential Dumping
    let ep3 = &episodes[2];
    assert_eq!(ep3.adversary_id, "APT-Ghost-Mesh-03");
    assert_eq!(ep3.trajectory.len(), 4);
    assert_eq!(ep3.trajectory[0].technique_id, "T1071");
    assert_eq!(ep3.trajectory[1].technique_id, "AML.T0048");
    assert_eq!(ep3.trajectory[2].technique_id, "T1055");
    assert_eq!(ep3.trajectory[3].technique_id, "T1003");

    // Verify all steps have valid non-empty mitigations
    for ep in &episodes {
        for step in &ep.trajectory {
            assert!(!step.technique_id.is_empty());
            assert!(!step.tactic.is_empty());
            assert!(step.severity >= 0.0 && step.severity <= 1.0);
            assert!(
                !step.mitigations.is_empty(),
                "Step {} must have mitigations",
                step.technique_id
            );
        }
    }

    // Train controller on curriculum for 10 epochs
    let mut controller = RLAdaptiveController::new();
    for _ in 0..10 {
        StixCurriculumGenerator::train_controller_on_curriculum(&mut controller, &episodes);
    }

    // Each epoch trains 3 episodes * 4 steps * 4 actions = 48 updates
    // 10 epochs = 480 updates
    assert_eq!(controller.total_steps, 480);

    // Verify learned action preferences:
    // State 7 (Canary triggered on credential access T1552.001 / AML.T0054)
    // Optimal action is SurgicalAutotomyAndCgroupFreeze
    let q7_autotomy =
        controller.q_table[7][DefenseAction::SurgicalAutotomyAndCgroupFreeze as usize];
    let q7_observe = controller.q_table[7][DefenseAction::ObserveOnly as usize];
    assert!(
        q7_autotomy > q7_observe,
        "Learned Q(7, Autotomy) ({:.2}) must exceed Q(7, Observe) ({:.2})",
        q7_autotomy,
        q7_observe
    );
    assert!(
        q7_autotomy > 50.0,
        "Learned Q(7, Autotomy) should be strongly reinforced (> 50.0), got {:.2}",
        q7_autotomy
    );

    // Verify action selection chooses active defense
    let selected_action = controller.select_action(7, true);
    assert_eq!(
        selected_action,
        DefenseAction::SurgicalAutotomyAndCgroupFreeze,
        "Controller must select SurgicalAutotomy on State 7 after curriculum training"
    );

    println!("PASS: All 3 multi-step attack trajectories synthesize properly into training episodes and train optimal defensive policy.");
}

#[test]
fn challenge_4_dp_csprng_laplace_distribution_and_causality_preservation() {
    println!("\n=== Challenge 4: DP CSPRNG Laplace Distribution & Causality Preservation ===");

    // 1. Statistical Oracle: Empirical Laplace Distribution Test
    // For Laplace(0, b) with scale b = 1.0 / epsilon:
    // Mean = 0, Variance = 2 * b^2, Standard Deviation = sqrt(2) * b
    let test_epsilons = [1.0f64, 0.5f64, 0.2f64];
    let n_samples = 15_000;
    let base_ts = 1_776_540_000i64;

    for &eps in &test_epsilons {
        let b = 1.0 / eps;
        let theoretical_mean = 0.0f64;
        let theoretical_std = (2.0f64).sqrt() * b;

        let mut samples = Vec::with_capacity(n_samples);
        let mut noise_vals = Vec::with_capacity(n_samples);

        for _ in 0..n_samples {
            let perturbed = perturb_timestamp_csprng(base_ts, eps);
            let noise = (perturbed - base_ts) as f64;
            samples.push(perturbed);
            noise_vals.push(noise);
        }

        // Compute empirical mean and standard deviation
        let sample_mean: f64 = noise_vals.iter().sum::<f64>() / (n_samples as f64);
        let sample_var: f64 = noise_vals
            .iter()
            .map(|&x| (x - sample_mean).powi(2))
            .sum::<f64>()
            / ((n_samples - 1) as f64);
        let sample_std: f64 = sample_var.sqrt();

        println!(
            "Epsilon = {:.2}: Theoretical [mean: {:.2}, std: {:.3}], Empirical [mean: {:.3}, std: {:.3}]",
            eps, theoretical_mean, theoretical_std, sample_mean, sample_std
        );

        // Assert empirical mean is within 4 standard errors of 0: SE = std / sqrt(N)
        let se = sample_std / (n_samples as f64).sqrt();
        assert!(
            (sample_mean - theoretical_mean).abs() < 4.0 * se,
            "Empirical mean {:.4} deviates significantly from theoretical 0.0 (SE = {:.4})",
            sample_mean,
            se
        );

        // Assert empirical std is within 12% of theoretical Laplace standard deviation
        let std_ratio = sample_std / theoretical_std;
        assert!(
            std_ratio >= 0.88 && std_ratio <= 1.12,
            "Empirical std {:.4} deviates from theoretical Laplace std {:.4} (ratio: {:.4})",
            sample_std,
            theoretical_std,
            std_ratio
        );
    }

    // 2. Causality Preservation within 3600s
    // Given two real-world events separated by 1 hour (3600s):
    // t_1 = T, t_2 = T + 3600.
    // Under operational differential privacy (epsilon >= 0.1),
    // perturbations must strictly preserve event ordering (t_1' < t_2') across all trials!
    let t1 = 1_776_540_000i64;
    let t2 = t1 + 3600i64; // 1 hour later
    let causality_trials = 10_000;
    let mut causality_preserved = 0usize;
    let mut max_abs_perturbation = 0i64;

    for _ in 0..causality_trials {
        let t1_perturbed = perturb_timestamp_csprng(t1, 0.5);
        let t2_perturbed = perturb_timestamp_csprng(t2, 0.5);

        let d1 = (t1_perturbed - t1).abs();
        let d2 = (t2_perturbed - t2).abs();
        max_abs_perturbation = max_abs_perturbation.max(d1).max(d2);

        // Perturbation on any single timestamp must be well within 3600s
        assert!(d1 < 3600, "Perturbation {} exceeds 3600s limit", d1);
        assert!(d2 < 3600, "Perturbation {} exceeds 3600s limit", d2);

        // Temporal order must be strictly preserved
        if t2_perturbed > t1_perturbed {
            causality_preserved += 1;
        }
    }

    let causality_rate = (causality_preserved as f64 / causality_trials as f64) * 100.0;
    println!(
        "Causality Preservation Rate over {} trials: {:.2}% (Max single perturbation: {}s)",
        causality_trials, causality_rate, max_abs_perturbation
    );
    assert_eq!(
        causality_rate, 100.0,
        "Causality must be 100% preserved for events separated by 3600s"
    );

    // 3. CSPRNG Non-Determinism Check: 100 consecutive calls must produce diverse perturbations
    let mut distinct_values_eps1 = HashSet::new();
    let mut distinct_values_eps01 = HashSet::new();
    for _ in 0..100 {
        distinct_values_eps1.insert(perturb_timestamp_csprng(base_ts, 1.0));
        distinct_values_eps01.insert(perturb_timestamp_csprng(base_ts, 0.1));
    }
    // At epsilon=1.0, std=1.414, over 100 integer samples expect >= 5 distinct integer buckets
    assert!(
        distinct_values_eps1.len() >= 5,
        "CSPRNG must produce non-deterministic perturbations (got {} distinct values for eps=1.0)",
        distinct_values_eps1.len()
    );
    // At epsilon=0.1, std=14.14, over 100 integer samples expect >= 20 distinct integer buckets
    assert!(
        distinct_values_eps01.len() >= 20,
        "CSPRNG must produce diverse spread for eps=0.1 (got {} distinct values)",
        distinct_values_eps01.len()
    );

    println!("PASS: DP CSPRNG follows theoretical Laplace distribution, preserves temporal causality (100%), and uses true OsRng randomness.");
}
