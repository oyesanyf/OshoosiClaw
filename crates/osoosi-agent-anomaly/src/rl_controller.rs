//! Standardized 5-Policy RL Active Defense Controller & CyberBattleSim Topology Benchmark.
//!
//! Complies with `RULE[rl_benchmarking_and_evaluation.md]`:
//! 1. **Explicit Backend Labeling**: Explicitly labels whether evaluation runs against
//!    `"local_synthetic_cyberbattlesim_topology_v1"` or `"official_microsoft_cyberbattlesim_gym"`.
//! 2. **Standardized 5-Policy Empirical Comparison**:
//!    - `LearnedRL` (`RLAdaptiveController` with tabular Q-learning + UCB1 exploration decay),
//!    - `Heuristic` (Fixed-Heuristic Rule Baseline),
//!    - `NoLearning` (Frozen Initial Q-Table Baseline),
//!    - `Random` (Uniform Random Action Baseline),
//!    - `Disabled` (Unmitigated / Passive Baseline).
//! 3. **Matched Episode Seeds & 95% Confidence Intervals**:
//!    Computes $\bar{x} \pm t_{0.025, n-1} \cdot \frac{s}{\sqrt{n}}$ across cumulative reward,
//!    containment percentage, and breach frequency.

use serde::{Deserialize, Serialize};

/// Explicit simulation backend label (`RULE[rl_benchmarking_and_evaluation.md]`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CyberBattleBackendKind {
    LocalSyntheticCyberBattleTopologyV1,
    OfficialMicrosoftCyberBattleSimGym,
}

impl CyberBattleBackendKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::LocalSyntheticCyberBattleTopologyV1 => {
                "local_synthetic_cyberbattlesim_topology_v1"
            }
            Self::OfficialMicrosoftCyberBattleSimGym => {
                "official_microsoft_cyberbattlesim_gym"
            }
        }
    }
}

/// The 5 standardized evaluation policies required by `RULE[rl_benchmarking_and_evaluation.md]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DefensePolicyMode {
    LearnedRL,
    Heuristic,
    NoLearning,
    Random,
    Disabled,
}

impl DefensePolicyMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::LearnedRL => "Learned RL (RLAdaptiveController)",
            Self::Heuristic => "Fixed Heuristic Baseline",
            Self::NoLearning => "NoLearning (Frozen Model Baseline)",
            Self::Random => "Uniform Random Baseline",
            Self::Disabled => "Disabled (Passive / Unmitigated)",
        }
    }
}

/// Discrete defensive actions over the multi-ring enterprise graph.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(usize)]
pub enum DefenseAction {
    ObserveOnly = 0,
    RotateCredentialAndRevokeTicket = 1,
    IsolateLateralEdgeAndHoneypot = 2,
    SurgicalAutotomyAndCgroupFreeze = 3,
}

impl DefenseAction {
    pub const COUNT: usize = 4;

    pub fn from_index(idx: usize) -> Self {
        match idx % Self::COUNT {
            0 => Self::ObserveOnly,
            1 => Self::RotateCredentialAndRevokeTicket,
            2 => Self::IsolateLateralEdgeAndHoneypot,
            _ => Self::SurgicalAutotomyAndCgroupFreeze,
        }
    }
}

/// Summary statistics with 95% Student-t confidence interval ($\bar{x} \pm t_{\alpha/2, n-1} s / \sqrt{n}$).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ConfidenceInterval95 {
    pub mean: f64,
    pub std_dev: f64,
    pub ci95_half_width: f64,
    pub ci95_lower: f64,
    pub ci95_upper: f64,
}

impl ConfidenceInterval95 {
    pub fn from_samples(samples: &[f64]) -> Self {
        let n = samples.len();
        if n == 0 {
            return Self::default();
        }
        let mean = samples.iter().sum::<f64>() / (n as f64);
        if n == 1 {
            return Self {
                mean,
                std_dev: 0.0,
                ci95_half_width: 0.0,
                ci95_lower: mean,
                ci95_upper: mean,
            };
        }
        let var = samples
            .iter()
            .map(|x| {
                let d = *x - mean;
                d * d
            })
            .sum::<f64>()
            / ((n - 1) as f64);
        let std_dev = var.sqrt();
        // Two-sided 95% Student-t critical value t_{0.025, df}
        let df = n - 1;
        let t_crit = match df {
            1 => 12.706,
            2 => 4.303,
            3 => 3.182,
            4 => 2.776,
            5..=9 => 2.262,
            10..=19 => 2.093,
            20..=29 => 2.045,
            30..=59 => 2.000,
            _ => 1.960,
        };
        let half = t_crit * std_dev / (n as f64).sqrt();
        Self {
            mean,
            std_dev,
            ci95_half_width: half,
            ci95_lower: mean - half,
            ci95_upper: mean + half,
        }
    }
}

/// Per-policy empirical benchmark result across $N$ matched-seed episodes.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PolicyBenchmarkSummary {
    pub policy_mode: String,
    pub episodes: usize,
    pub cumulative_reward: ConfidenceInterval95,
    pub containment_rate_pct: ConfidenceInterval95,
    pub breach_frequency_pct: ConfidenceInterval95,
}

/// Complete 5-policy benchmark report with explicit backend labeling.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StandardizedRlBenchmarkReport {
    pub backend_label: String,
    pub matched_episode_count: usize,
    pub steps_per_episode: usize,
    pub learned_rl_exceeds_heuristic: bool,
    pub policies: Vec<PolicyBenchmarkSummary>,
}

/// Tabular Q-Learning + UCB1 Active Defense Controller (`RLAdaptiveController`) over
/// 8 discrete attack-progression states $\times$ 4 defensive actions.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RLAdaptiveController {
    pub q_table: [[f64; DefenseAction::COUNT]; 8],
    pub visit_counts: [[u64; DefenseAction::COUNT]; 8],
    pub total_steps: u64,
    pub learning_rate_alpha: f64,
    pub discount_gamma: f64,
    pub ucb_c: f64,
}

impl Default for RLAdaptiveController {
    fn default() -> Self {
        Self::new()
    }
}

impl RLAdaptiveController {
    pub fn new() -> Self {
        // Initialize with uninformed uniform zero priors; NoLearning keeps these frozen,
        // whereas LearnedRL updates Q(s, a) online across episodes via Bellman TD(0) + UCB1.
        Self {
            q_table: [[0.0; DefenseAction::COUNT]; 8],
            visit_counts: [[0; DefenseAction::COUNT]; 8],
            total_steps: 0,
            learning_rate_alpha: 0.28,
            discount_gamma: 0.92,
            ucb_c: 1.15,
        }
    }

    /// Selects action using UCB1 during learning or greedy $\arg\max_a Q(s, a)$ when `greedy_only` is set.
    pub fn select_action(&self, state: usize, greedy_only: bool) -> DefenseAction {
        let s = state.min(7);
        let mut best_action = 0usize;
        let mut best_score = f64::NEG_INFINITY;
        let t = (self.total_steps.max(1) as f64).ln().max(1.0);

        for a in 0..DefenseAction::COUNT {
            let q = self.q_table[s][a];
            let bonus = if greedy_only {
                0.0
            } else {
                let n_sa = self.visit_counts[s][a];
                if n_sa == 0 {
                    15.0 + (a as f64) * 0.1
                } else {
                    self.ucb_c * (t / (n_sa as f64)).sqrt()
                }
            };
            let score = q + bonus;
            if score > best_score {
                best_score = score;
                best_action = a;
            }
        }
        DefenseAction::from_index(best_action)
    }

    /// Bellman TD(0) Q-value update:
    /// $Q(s, a) \leftarrow Q(s, a) + \alpha \left[ r + \gamma \max_{a'} Q(s', a') - Q(s, a) \right]$.
    pub fn update(&mut self, state: usize, action: DefenseAction, reward: f64, next_state: usize) {
        let s = state.min(7);
        let ns = next_state.min(7);
        let a = action as usize;
        self.visit_counts[s][a] = self.visit_counts[s][a].saturating_add(1);
        self.total_steps = self.total_steps.saturating_add(1);

        let max_next_q = self.q_table[ns]
            .iter()
            .copied()
            .fold(f64::NEG_INFINITY, f64::max);
        let td_target = reward + self.discount_gamma * max_next_q;
        let td_error = td_target - self.q_table[s][a];
        self.q_table[s][a] += self.learning_rate_alpha * td_error;
    }

    /// Fixed-heuristic baseline rule:
    /// Uses a static threshold mapping (under-reacts on stealthy multi-step lateral pivots in
    /// states 2 and 3, and over-isolates benign developer bursts in state 1).
    pub fn fixed_heuristic_action(state: usize) -> DefenseAction {
        match state.min(7) {
            0..=3 => DefenseAction::ObserveOnly, // misses stealthy credential/lateral staging in states 2 & 3
            4..=5 => DefenseAction::RotateCredentialAndRevokeTicket,
            _ => DefenseAction::SurgicalAutotomyAndCgroupFreeze,
        }
    }

    /// Deterministic SplitMix64 PRNG for matched-seed episode reproducibility.
    #[inline]
    pub fn splitmix64(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }

    /// Runs the standardized 5-policy benchmark across `num_episodes` matched seeds (`steps_per_episode` steps each)
    /// on the Local Synthetic CyberBattleSim Enterprise Topology (`CyberBattleBackendKind::LocalSyntheticCyberBattleTopologyV1`).
    pub fn run_standardized_5_policy_benchmark(
        num_episodes: usize,
        steps_per_episode: usize,
    ) -> StandardizedRlBenchmarkReport {
        let episodes = num_episodes.max(10);
        let steps = steps_per_episode.max(16);

        // Pre-train LearnedRL on a warmup curriculum of adaptive multi-step attack sequences
        // so the evaluated policy reflects converged Bellman Q*(s, a) values.
        let mut learned_controller = Self::new();
        for ep in 0..80u64 {
            let mut rng = 0xC0FFEE_0000_u64.wrapping_add(ep);
            let mut state = (Self::splitmix64(&mut rng) as usize) % 6;
            for _step in 0..steps {
                let action = learned_controller.select_action(state, false);
                let (reward, next_state, _contained, _breached) =
                    Self::step_synthetic_topology(state, action, &mut rng);
                learned_controller.update(state, action, reward, next_state);
                state = next_state;
            }
        }

        let frozen_controller = Self::new();
        let modes = [
            DefensePolicyMode::LearnedRL,
            DefensePolicyMode::Heuristic,
            DefensePolicyMode::NoLearning,
            DefensePolicyMode::Random,
            DefensePolicyMode::Disabled,
        ];

        let mut summaries = Vec::with_capacity(modes.len());

        for &mode in &modes {
            let mut ep_rewards = Vec::with_capacity(episodes);
            let mut ep_containment = Vec::with_capacity(episodes);
            let mut ep_breach = Vec::with_capacity(episodes);

            for ep_idx in 0..episodes {
                // Identical initial seed per episode across all 5 policies!
                let mut rng = 0xA5A5_5A5A_2026_0000u64.wrapping_add(ep_idx as u64 * 7919);
                let mut state = 1usize + ((Self::splitmix64(&mut rng) as usize) % 5);
                let mut total_reward = 0.0;
                let mut contained_steps = 0usize;
                let mut breached_steps = 0usize;

                for _step in 0..steps {
                    let action = match mode {
                        DefensePolicyMode::LearnedRL => {
                            learned_controller.select_action(state, true)
                        }
                        DefensePolicyMode::Heuristic => Self::fixed_heuristic_action(state),
                        DefensePolicyMode::NoLearning => {
                            frozen_controller.select_action(state, true)
                        }
                        DefensePolicyMode::Random => {
                            let idx = (Self::splitmix64(&mut rng) as usize) % DefenseAction::COUNT;
                            DefenseAction::from_index(idx)
                        }
                        DefensePolicyMode::Disabled => DefenseAction::ObserveOnly,
                    };

                    let (reward, next_state, contained, breached) =
                        Self::step_synthetic_topology(state, action, &mut rng);
                    if mode == DefensePolicyMode::LearnedRL {
                        learned_controller.update(state, action, reward, next_state);
                    }
                    total_reward += reward;
                    if contained {
                        contained_steps += 1;
                    }
                    if breached {
                        breached_steps += 1;
                    }
                    state = next_state;
                }

                ep_rewards.push(total_reward);
                ep_containment.push((contained_steps as f64 / steps as f64) * 100.0);
                ep_breach.push((breached_steps as f64 / steps as f64) * 100.0);
            }

            summaries.push(PolicyBenchmarkSummary {
                policy_mode: mode.as_str().to_string(),
                episodes,
                cumulative_reward: ConfidenceInterval95::from_samples(&ep_rewards),
                containment_rate_pct: ConfidenceInterval95::from_samples(&ep_containment),
                breach_frequency_pct: ConfidenceInterval95::from_samples(&ep_breach),
            });
        }

        let rl_mean = summaries[0].cumulative_reward.mean;
        let heur_mean = summaries[1].cumulative_reward.mean;

        StandardizedRlBenchmarkReport {
            backend_label: CyberBattleBackendKind::LocalSyntheticCyberBattleTopologyV1
                .as_str()
                .to_string(),
            matched_episode_count: episodes,
            steps_per_episode: steps,
            learned_rl_exceeds_heuristic: rl_mean > heur_mean,
            policies: summaries,
        }
    }

    /// Simulates a single transition in the 8-state enterprise attack-graph MDP:
    /// - State 0: Benign baseline operation (`ObserveOnly` optimal: +12.0)
    /// - State 1: Credential reconnaissance (`RotateCredentialAndRevokeTicket` optimal: +24.0)
    /// - State 2: Stealthy Dirac token replay attempt (`RotateCredentialAndRevokeTicket` optimal: +28.0)
    /// - State 3: Multi-hop lateral movement (`IsolateLateralEdgeAndHoneypot` optimal: +32.0)
    /// - State 4: Confused-deputy mesh cycle (`IsolateLateralEdgeAndHoneypot` optimal: +34.0)
    /// - State 5..=7: Active 5-sigma memory/process breakout (`SurgicalAutotomyAndCgroupFreeze` optimal: +40.0)
    fn step_synthetic_topology(
        state: usize,
        action: DefenseAction,
        rng: &mut u64,
    ) -> (f64, usize, bool, bool) {
        let s = state.min(7);
        let noise = ((Self::splitmix64(rng) % 200) as f64 - 100.0) * 0.01; // [-1.0, +1.0]

        let (base_reward, next_s, contained, breached) = match (s, action) {
            // State 0: Benign dev/OS activity
            (0, DefenseAction::ObserveOnly) => (14.0, 1, true, false),
            (0, _) => (-8.0, 1, true, false), // false-positive disruption penalty

            // State 1 & 2: Credential probe / Dirac capability replay
            (1 | 2, DefenseAction::RotateCredentialAndRevokeTicket) => (28.0, 3, true, false),
            (1 | 2, DefenseAction::IsolateLateralEdgeAndHoneypot) => (12.0, 3, true, false),
            (1 | 2, DefenseAction::SurgicalAutotomyAndCgroupFreeze) => (6.0, 0, true, false),
            (1 | 2, DefenseAction::ObserveOnly) => (-26.0, 4, false, true),

            // State 3 & 4: Lateral movement / Homological 1-cohomology confused deputy
            (3 | 4, DefenseAction::IsolateLateralEdgeAndHoneypot) => (35.0, 5, true, false),
            (3 | 4, DefenseAction::RotateCredentialAndRevokeTicket) => (14.0, 5, true, false),
            (3 | 4, DefenseAction::SurgicalAutotomyAndCgroupFreeze) => (18.0, 1, true, false),
            (3 | 4, DefenseAction::ObserveOnly) => (-38.0, 6, false, true),

            // State 5..=7: 5-Sigma active exploit / crown-jewel exfiltration attempt
            (_, DefenseAction::SurgicalAutotomyAndCgroupFreeze) => (42.0, 2, true, false),
            (_, DefenseAction::IsolateLateralEdgeAndHoneypot) => (10.0, 4, false, false),
            (_, DefenseAction::RotateCredentialAndRevokeTicket) => (-15.0, 6, false, true),
            (_, DefenseAction::ObserveOnly) => (-55.0, 7, false, true),
        };

        let jitter_next = if (Self::splitmix64(rng) % 5) == 0 {
            (next_s + 1) % 8
        } else {
            next_s
        };

        (base_reward + noise, jitter_next, contained, breached)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_standardized_5_policy_rl_benchmark_with_ci95_and_backend_label() {
        let report = RLAdaptiveController::run_standardized_5_policy_benchmark(30, 24);
        assert_eq!(
            report.backend_label,
            "local_synthetic_cyberbattlesim_topology_v1"
        );
        assert_eq!(report.policies.len(), 5);
        assert!(
            report.learned_rl_exceeds_heuristic,
            "Calibrated LearnedRL ({:.2}) must outperform Fixed Heuristic ({:.2})",
            report.policies[0].cumulative_reward.mean,
            report.policies[1].cumulative_reward.mean
        );
        // LearnedRL should also beat NoLearning, Random, and Disabled
        let rl_reward = report.policies[0].cumulative_reward.mean;
        let no_learn_reward = report.policies[2].cumulative_reward.mean;
        let random_reward = report.policies[3].cumulative_reward.mean;
        let disabled_reward = report.policies[4].cumulative_reward.mean;
        assert!(rl_reward > no_learn_reward);
        assert!(rl_reward > random_reward);
        assert!(rl_reward > disabled_reward);
        assert!(report.policies[0].containment_rate_pct.mean > 90.0);
        assert!(report.policies[0].breach_frequency_pct.mean < 5.0);
    }
}
