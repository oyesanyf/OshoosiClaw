//! Advanced Autonomous EDR Reinforcement Learning Engine and Self-Improvement System.
//!
//! Provides:
//! 1. Ordinal Discrete Progressive Action Space (EdrAction) with backward-compatible MitigationAction
//! 2. Deterministic Safety Filter & Action Masking (SafetyFilter & SafetyGuardrail) enforcing Zero OS Destabilization Invariant
//! 3. Structured State Space Feature Vector (Lineage, Velocity, Priors, Mesh) & StateFeaturePipeline
//! 4. Reward Engineering Engine (EdrRewardEngine)
//! 5. Double Deep Q-Network (DoubleDeepQEngine) with Target Network (theta^-) & Conservative Q-Learning (CQL)
//! 6. Contextual Bandit Engine (LinUcbBandit) for dynamic alert throttling
//! 7. Shadow / Dry-Run Mode & Non-Blocking Controller (EDRRuntimeController)
//! 8. Self-Improvement Loop & Digital Twin Simulator (DigitalTwinSimulator)
//! 9. Prioritized Experience Replay Buffer (PrioritizedReplayBuffer) with importance sampling
//! 10. Byzantine-Robust Parameter Aggregator (ByzantineRobustAggregator)

use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{info, warn};

/// Ordinal Discrete Progressive Action Space ($A_t$) for autonomous EDR mitigation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum EdrAction {
    /// Level 0: Default telemetry logging, passive monitoring.
    PassiveObserve = 0,
    /// Level 1: Verbose API tracing (OpenProcess, VirtualAllocEx, handle tracking).
    TraceElevation = 1,
    /// Level 2: Immediate in-memory scan via YARA-L, minidump, thread stack inspection.
    MemoryIntrospection = 2,
    /// Level 3: Drop outbound network sockets, suspend suspicious threads while analysis runs.
    MicroContainment = 3,
    /// Level 4: Terminate process tree, isolate host from mesh, quarantine file.
    HardMitigation = 4,
}

impl EdrAction {
    // Backward-compatible associated constants for legacy MitigationAction callers
    #[allow(non_upper_case_globals)]
    pub const Allow: EdrAction = EdrAction::PassiveObserve;
    #[allow(non_upper_case_globals)]
    pub const Throttle: EdrAction = EdrAction::TraceElevation;
    #[allow(non_upper_case_globals)]
    pub const Suspend: EdrAction = EdrAction::MicroContainment;
    #[allow(non_upper_case_globals)]
    pub const TerminateAndIsolate: EdrAction = EdrAction::HardMitigation;

    pub fn from_index(idx: usize) -> Self {
        match idx {
            0 => Self::PassiveObserve,
            1 => Self::TraceElevation,
            2 => Self::MemoryIntrospection,
            3 => Self::MicroContainment,
            4 => Self::HardMitigation,
            _ => Self::PassiveObserve,
        }
    }

    pub fn to_index(self) -> usize {
        self as usize
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::PassiveObserve => "PassiveObserve",
            Self::TraceElevation => "TraceElevation",
            Self::MemoryIntrospection => "MemoryIntrospection",
            Self::MicroContainment => "MicroContainment",
            Self::HardMitigation => "HardMitigation",
        }
    }

    pub fn is_containment(self) -> bool {
        matches!(self, Self::MicroContainment | Self::HardMitigation)
    }

    pub fn is_inspection(self) -> bool {
        matches!(self, Self::TraceElevation | Self::MemoryIntrospection)
    }
}

/// Backward-compatible type alias so existing callers continue compiling seamlessly.
pub type MitigationAction = EdrAction;

/// Metadata context of an executing process under RL evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessContext {
    pub pid: u32,
    pub ppid: u32,
    pub binary_path: String,
    pub command_line: String,
    pub is_kernel_thread: bool,
    pub username: String,
}

/// Deterministic Safety Filter & Action Masking.
/// Enforces the Zero OS Destabilization Invariant: Critical OS kernel and system
/// daemons can NEVER be mutated, suspended, isolated, or terminated.
#[derive(Debug, Clone)]
pub struct SafetyFilter {
    pub protected_pids: HashSet<u32>,
    pub protected_binaries: HashSet<String>,
}

impl Default for SafetyFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl SafetyFilter {
    pub fn new() -> Self {
        let mut protected_pids = HashSet::new();
        // Core protected PIDs
        protected_pids.insert(0); // System Idle (Windows/Linux)
        protected_pids.insert(1); // init / systemd / launchd
        protected_pids.insert(4); // NT Kernel & System (Windows)

        let mut protected_binaries = HashSet::new();
        // Windows Core Protected Binaries
        protected_binaries.insert("smss.exe".to_lowercase());
        protected_binaries.insert("csrss.exe".to_lowercase());
        protected_binaries.insert("wininit.exe".to_lowercase());
        protected_binaries.insert("services.exe".to_lowercase());
        protected_binaries.insert("lsass.exe".to_lowercase());
        protected_binaries.insert("winlogon.exe".to_lowercase());
        protected_binaries.insert("fontdrvhost.exe".to_lowercase());
        protected_binaries.insert("dwm.exe".to_lowercase());

        // Linux / Unix / macOS Core Protected Binaries
        protected_binaries.insert("/sbin/init".to_lowercase());
        protected_binaries.insert("/usr/lib/systemd/systemd".to_lowercase());
        protected_binaries.insert("/usr/bin/dbus-daemon".to_lowercase());
        protected_binaries.insert("/System/Library/CoreServices/launchd".to_lowercase());
        protected_binaries.insert("systemd".to_lowercase());
        protected_binaries.insert("dbus-daemon".to_lowercase());
        protected_binaries.insert("launchd".to_lowercase());
        protected_binaries.insert("init".to_lowercase());

        Self {
            protected_pids,
            protected_binaries,
        }
    }

    /// Checks if a PID or binary name corresponds to a protected system target.
    pub fn is_protected(&self, target_pid: u32, target_name: &str) -> bool {
        if self.protected_pids.contains(&target_pid) {
            return true;
        }
        let name_lower = target_name.to_lowercase();
        let filename = std::path::Path::new(&name_lower)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(&name_lower);

        self.protected_binaries.contains(filename) || self.protected_binaries.contains(&name_lower)
    }

    /// Filters a candidate action: if target is critical/protected and candidate is
    /// HardMitigation or MicroContainment, degrades to safe MemoryIntrospection (Level 2).
    pub fn filter_action(
        &self,
        target_pid: u32,
        target_name: &str,
        candidate_action: EdrAction,
    ) -> EdrAction {
        if self.is_protected(target_pid, target_name) {
            if candidate_action == EdrAction::HardMitigation
                || candidate_action == EdrAction::MicroContainment
            {
                warn!(
                    "Action {:?} masked for critical target {}. Degraded to safe inspection",
                    candidate_action, target_name
                );
                return EdrAction::MemoryIntrospection;
            }
        }
        candidate_action
    }

    /// Generates a 5-action float mask: [PassiveObserve, TraceElevation, MemoryIntrospection, MicroContainment, HardMitigation]
    /// 1.0 = Action Permitted, 0.0 = Action Strictly Masked
    pub fn generate_action_mask(&self, ctx: &ProcessContext) -> [f32; 5] {
        if ctx.is_kernel_thread || self.is_protected(ctx.pid, &ctx.binary_path) {
            // Level 0, 1, 2 permitted; destructive levels 3, 4 prohibited
            [1.0, 1.0, 1.0, 0.0, 0.0]
        } else {
            // Standard userland targets permit full mitigation spectrum
            [1.0, 1.0, 1.0, 1.0, 1.0]
        }
    }
}

/// Backward-compatible wrapper for existing SafetyGuardrail callers.
#[derive(Debug, Clone, Default)]
pub struct SafetyGuardrail {
    pub filter: SafetyFilter,
}

impl SafetyGuardrail {
    pub fn new() -> Self {
        Self {
            filter: SafetyFilter::new(),
        }
    }

    pub fn is_protected(&self, target_pid: u32, target_name: &str) -> bool {
        self.filter.is_protected(target_pid, target_name)
    }

    pub fn filter_action(
        &self,
        target_pid: u32,
        target_name: &str,
        candidate_action: EdrAction,
    ) -> EdrAction {
        self.filter
            .filter_action(target_pid, target_name, candidate_action)
    }

    /// Legacy 4-action mask [Allow, Throttle, Suspend, Terminate] for backward compatibility.
    pub fn generate_action_mask(&self, ctx: &ProcessContext) -> [f32; 4] {
        if ctx.is_kernel_thread || self.filter.is_protected(ctx.pid, &ctx.binary_path) {
            [1.0, 0.0, 0.0, 0.0]
        } else {
            [1.0, 1.0, 1.0, 1.0]
        }
    }

    /// 5-action mask for modern progressive EDR RL engine.
    pub fn generate_action_mask_5(&self, ctx: &ProcessContext) -> [f32; 5] {
        self.filter.generate_action_mask(ctx)
    }
}

/// Structured Process Lineage component of the RL state vector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessLineageVector {
    /// Normalized process tree depth [0.0, 1.0]
    pub tree_depth: f32,
    /// Parent-child execution entropy / transition anomaly score [0.0, 1.0]
    pub parent_child_entropy: f32,
    /// Token elevation level (Untrusted=0.0, Low=0.25, Medium=0.5, High=0.75, System=1.0)
    pub token_elevation_level: f32,
    /// Kernel thread flag (0.0 or 1.0)
    pub is_kernel_thread: f32,
    /// Parent anomaly indicator score [0.0, 1.0]
    pub parent_anomaly_score: f32,
    /// Sudden privilege escalation indicator [0.0, 1.0]
    pub elevation_jump: f32,
}

impl Default for ProcessLineageVector {
    fn default() -> Self {
        Self {
            tree_depth: 0.1,
            parent_child_entropy: 0.1,
            token_elevation_level: 0.5,
            is_kernel_thread: 0.0,
            parent_anomaly_score: 0.0,
            elevation_jump: 0.0,
        }
    }
}

/// Telemetry Velocity metrics ($df/dt, dn/dt$).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryVelocity {
    /// File modification rate / sec ($df/dt$, normalized)
    pub file_modification_rate: f32,
    /// Outbound network connection velocity ($dn/dt$, normalized)
    pub outbound_net_velocity: f32,
    /// Memory page permission transition rate (PAGE_READWRITE -> PAGE_EXECUTE_READWRITE)
    pub page_permission_trans_rate: f32,
    /// Thread creation burst rate
    pub thread_creation_burst_rate: f32,
    /// Handle count duplication/manipulation velocity
    pub handle_count_velocity: f32,
    /// CPU burst rate
    pub cpu_usage_burst: f32,
}

impl Default for TelemetryVelocity {
    fn default() -> Self {
        Self {
            file_modification_rate: 0.0,
            outbound_net_velocity: 0.0,
            page_permission_trans_rate: 0.0,
            thread_creation_burst_rate: 0.0,
            handle_count_velocity: 0.0,
            cpu_usage_burst: 0.0,
        }
    }
}

/// Heuristic and static capability prior scores.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeuristicPriorScores {
    /// Static PE / Magika classification score [0.0, 1.0]
    pub static_pe_magika_score: f32,
    /// Command-line token classification score [0.0, 1.0]
    pub cmdline_token_score: f32,
    /// Fast-path YARA/Sigma rule match score [0.0, 1.0]
    pub fastpath_yara_sigma_score: f32,
    /// CAPA/FLOSS capability indicator [0.0, 1.0]
    pub capa_floss_capability: f32,
    /// Behavioral sequence model score [0.0, 1.0]
    pub behavioral_sequence_score: f32,
    /// Anomaly detector / isolation forest score [0.0, 1.0]
    pub anomaly_detector_score: f32,
}

impl Default for HeuristicPriorScores {
    fn default() -> Self {
        Self {
            static_pe_magika_score: 0.0,
            cmdline_token_score: 0.0,
            fastpath_yara_sigma_score: 0.0,
            capa_floss_capability: 0.0,
            behavioral_sequence_score: 0.0,
            anomaly_detector_score: 0.0,
        }
    }
}

/// Mesh peer context and consensus indicators.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshContext {
    /// Peer anomaly score across mesh nodes [0.0, 1.0]
    pub peer_anomaly_score: f32,
    /// Cluster-wide prevalence (seen across peer nodes in last 10 minutes) [0.0, 1.0]
    pub cluster_prevalence: f32,
    /// Consensus confidence score [0.0, 1.0]
    pub consensus_confidence: f32,
    /// Cluster alert rate velocity
    pub cluster_alert_rate: f32,
    /// Peer threat level
    pub peer_threat_level: f32,
    /// Quarantine vote ratio across mesh
    pub quarantine_vote_ratio: f32,
}

impl Default for MeshContext {
    fn default() -> Self {
        Self {
            peer_anomaly_score: 0.0,
            cluster_prevalence: 0.5,
            consensus_confidence: 0.8,
            cluster_alert_rate: 0.0,
            peer_threat_level: 0.0,
            quarantine_vote_ratio: 0.0,
        }
    }
}

/// State Feature Pipeline normalizing and concatenating sub-vectors into a 24-dimensional continuous observation vector $S_t$.
#[derive(Debug, Clone, Default)]
pub struct StateFeaturePipeline;

impl StateFeaturePipeline {
    pub const STATE_DIM: usize = 24;

    pub fn new() -> Self {
        Self
    }

    pub fn build_state_vector(
        &self,
        lineage: &ProcessLineageVector,
        velocity: &TelemetryVelocity,
        priors: &HeuristicPriorScores,
        mesh: &MeshContext,
    ) -> [f32; Self::STATE_DIM] {
        [
            // Lineage (6)
            lineage.tree_depth.clamp(0.0, 1.0),
            lineage.parent_child_entropy.clamp(0.0, 1.0),
            lineage.token_elevation_level.clamp(0.0, 1.0),
            lineage.is_kernel_thread.clamp(0.0, 1.0),
            lineage.parent_anomaly_score.clamp(0.0, 1.0),
            lineage.elevation_jump.clamp(0.0, 1.0),
            // Velocity (6)
            velocity.file_modification_rate.clamp(0.0, 1.0),
            velocity.outbound_net_velocity.clamp(0.0, 1.0),
            velocity.page_permission_trans_rate.clamp(0.0, 1.0),
            velocity.thread_creation_burst_rate.clamp(0.0, 1.0),
            velocity.handle_count_velocity.clamp(0.0, 1.0),
            velocity.cpu_usage_burst.clamp(0.0, 1.0),
            // Priors (6)
            priors.static_pe_magika_score.clamp(0.0, 1.0),
            priors.cmdline_token_score.clamp(0.0, 1.0),
            priors.fastpath_yara_sigma_score.clamp(0.0, 1.0),
            priors.capa_floss_capability.clamp(0.0, 1.0),
            priors.behavioral_sequence_score.clamp(0.0, 1.0),
            priors.anomaly_detector_score.clamp(0.0, 1.0),
            // Mesh (6)
            mesh.peer_anomaly_score.clamp(0.0, 1.0),
            mesh.cluster_prevalence.clamp(0.0, 1.0),
            mesh.consensus_confidence.clamp(0.0, 1.0),
            mesh.cluster_alert_rate.clamp(0.0, 1.0),
            mesh.peer_threat_level.clamp(0.0, 1.0),
            mesh.quarantine_vote_ratio.clamp(0.0, 1.0),
        ]
    }

    pub fn to_vec(
        &self,
        lineage: &ProcessLineageVector,
        velocity: &TelemetryVelocity,
        priors: &HeuristicPriorScores,
        mesh: &MeshContext,
    ) -> Vec<f32> {
        self.build_state_vector(lineage, velocity, priors, mesh)
            .to_vec()
    }
}

/// Reward Engineering Engine:
/// Formula: $R_t = R_{\text{security}} - R_{\text{disruption}} - R_{\text{cost}}$
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdrRewardEngine {
    pub tp_containment_reward: f32,     // +100.0
    pub early_elevation_reward: f32,    // +15.0
    pub fp_disruption_penalty: f32,     // -200.0
    pub fp_micro_penalty: f32,          // -50.0
    pub dwell_penalty_per_step: f32,    // -0.5
    pub telemetry_overhead_penalty: f32,// -0.1
}

impl Default for EdrRewardEngine {
    fn default() -> Self {
        Self {
            tp_containment_reward: 100.0,
            early_elevation_reward: 15.0,
            fp_disruption_penalty: 200.0,
            fp_micro_penalty: 50.0,
            dwell_penalty_per_step: 0.5,
            telemetry_overhead_penalty: 0.1,
        }
    }
}

impl EdrRewardEngine {
    pub fn new() -> Self {
        Self::default()
    }

    /// Computes $R_t = R_{\text{security}} - R_{\text{disruption}} - R_{\text{cost}}$
    pub fn compute_reward(
        &self,
        action: EdrAction,
        is_malicious: bool,
        threat_score: f32,
        prev_threat_score: f32,
        is_critical_target: bool,
    ) -> f32 {
        let mut r_security = 0.0f32;
        let mut r_disruption = 0.0f32;
        let mut r_cost = 0.0f32;

        if is_malicious {
            match action {
                EdrAction::HardMitigation | EdrAction::MicroContainment => {
                    r_security = self.tp_containment_reward;
                }
                EdrAction::TraceElevation | EdrAction::MemoryIntrospection => {
                    r_security = self.early_elevation_reward;
                }
                EdrAction::PassiveObserve => {
                    if threat_score >= prev_threat_score || threat_score > 0.4 {
                        r_cost = self.dwell_penalty_per_step * (1.0 + threat_score);
                    }
                }
            }
        } else {
            // Benign workload or critical system daemon
            match action {
                EdrAction::HardMitigation => {
                    r_disruption = if is_critical_target {
                        self.fp_disruption_penalty * 1.5
                    } else {
                        self.fp_disruption_penalty
                    };
                }
                EdrAction::MicroContainment => {
                    r_disruption = if is_critical_target {
                        self.fp_micro_penalty * 1.5
                    } else {
                        self.fp_micro_penalty
                    };
                }
                EdrAction::TraceElevation | EdrAction::MemoryIntrospection => {
                    r_cost = self.telemetry_overhead_penalty;
                }
                EdrAction::PassiveObserve => {
                    r_security = 1.0;
                }
            }
        }

        r_security - r_disruption - r_cost
    }
}

/// Feed-forward Linear Layer for Deep Q-Network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DenseLayer {
    pub weights: Vec<Vec<f32>>, // [in_dim, out_dim]
    pub biases: Vec<f32>,       // [out_dim]
}

impl DenseLayer {
    pub fn new(in_dim: usize, out_dim: usize) -> Self {
        let mut rng = rand::thread_rng();
        let bound = (6.0 / (in_dim + out_dim) as f32).sqrt(); // Glorot uniform
        let weights = (0..in_dim)
            .map(|_| {
                (0..out_dim)
                    .map(|_| rng.gen_range(-bound..bound))
                    .collect()
            })
            .collect();
        let biases = vec![0.0; out_dim];
        Self { weights, biases }
    }

    pub fn forward(&self, input: &[f32], relu: bool) -> Vec<f32> {
        let out_dim = self.biases.len();
        let in_dim = input.len();
        let mut output = self.biases.clone();

        for i in 0..in_dim {
            let x = input[i];
            for j in 0..out_dim {
                output[j] += x * self.weights[i][j];
            }
        }

        if relu {
            for v in output.iter_mut() {
                *v = v.max(0.0);
            }
        }
        output
    }

    pub fn flatten_parameters(&self) -> Vec<f32> {
        let mut flat = Vec::new();
        for row in &self.weights {
            flat.extend_from_slice(row);
        }
        flat.extend_from_slice(&self.biases);
        flat
    }

    pub fn load_parameters(&mut self, flat: &[f32]) -> usize {
        let in_dim = self.weights.len();
        let out_dim = self.biases.len();
        let mut offset = 0;

        for i in 0..in_dim {
            for j in 0..out_dim {
                if offset < flat.len() {
                    self.weights[i][j] = flat[offset];
                    offset += 1;
                }
            }
        }
        for j in 0..out_dim {
            if offset < flat.len() {
                self.biases[j] = flat[offset];
                offset += 1;
            }
        }
        offset
    }

    pub fn backward(&mut self, input: &[f32], grad_output: &[f32], lr: f32) -> Vec<f32> {
        let in_dim = input.len();
        let out_dim = self.biases.len();
        let mut grad_input = vec![0.0; in_dim];

        for i in 0..in_dim {
            for j in 0..out_dim {
                grad_input[i] += grad_output[j] * self.weights[i][j];
                let delta = lr * input[i] * grad_output[j];
                self.weights[i][j] -= delta.clamp(-0.2, 0.2);
            }
        }
        for j in 0..out_dim {
            let delta = lr * grad_output[j];
            self.biases[j] -= delta.clamp(-0.2, 0.2);
        }
        grad_input
    }
}

/// Deep Q-Network Policy Engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeepQEngine {
    pub state_dim: usize,
    pub action_dim: usize,
    pub fc1: DenseLayer,
    pub fc2: DenseLayer,
    pub fc3: DenseLayer,
    pub fc_out: DenseLayer,
}

impl DeepQEngine {
    pub fn new(state_dim: usize, action_dim: usize) -> Self {
        Self {
            state_dim,
            action_dim,
            fc1: DenseLayer::new(state_dim, 128),
            fc2: DenseLayer::new(128, 128),
            fc3: DenseLayer::new(128, 64),
            fc_out: DenseLayer::new(64, action_dim),
        }
    }

    pub fn forward(&self, state: &[f32]) -> Vec<f32> {
        let h1 = self.fc1.forward(state, true);
        let h2 = self.fc2.forward(&h1, true);
        let h3 = self.fc3.forward(&h2, true);
        self.fc_out.forward(&h3, false)
    }

    /// Legacy 4-action guarded selection for backward compatibility.
    pub fn select_guarded_action(
        &self,
        state_features: &[f32],
        mask: &[f32; 4],
        epsilon: f32,
    ) -> MitigationAction {
        let mut rng = rand::thread_rng();

        if rng.gen::<f32>() < epsilon {
            let valid_indices: Vec<usize> = mask
                .iter()
                .enumerate()
                .filter_map(|(i, &m)| if m > 0.0 { Some(i) } else { None })
                .collect();

            if !valid_indices.is_empty() {
                let chosen = valid_indices[rng.gen_range(0..valid_indices.len())];
                return MitigationAction::from_index(chosen);
            }
            return MitigationAction::Allow;
        }

        let raw_q = self.forward(state_features);
        let mut best_idx = 0;
        let mut max_q = f32::NEG_INFINITY;

        for i in 0..self.action_dim.min(4) {
            if mask[i] > 0.0 {
                let q = raw_q.get(i).copied().unwrap_or(0.0);
                if q > max_q {
                    max_q = q;
                    best_idx = i;
                }
            }
        }

        MitigationAction::from_index(best_idx)
    }

    /// 5-action guarded selection. Prohibited actions (mask[i] <= 0.0) are set to -infinity.
    pub fn select_guarded_action_5(
        &self,
        state_features: &[f32],
        mask: &[f32; 5],
        epsilon: f32,
    ) -> EdrAction {
        let mut rng = rand::thread_rng();

        if rng.gen::<f32>() < epsilon {
            let valid_indices: Vec<usize> = mask
                .iter()
                .enumerate()
                .filter_map(|(i, &m)| {
                    if m > 0.0 && i < self.action_dim {
                        Some(i)
                    } else {
                        None
                    }
                })
                .collect();

            if !valid_indices.is_empty() {
                let chosen = valid_indices[rng.gen_range(0..valid_indices.len())];
                return EdrAction::from_index(chosen);
            }
            return EdrAction::PassiveObserve;
        }

        let raw_q = self.forward(state_features);
        let mut best_idx = 0;
        let mut max_q = f32::NEG_INFINITY;

        for i in 0..self.action_dim.min(5) {
            if mask[i] > 0.0 {
                let q = raw_q.get(i).copied().unwrap_or(0.0);
                if q > max_q {
                    max_q = q;
                    best_idx = i;
                }
            }
        }

        EdrAction::from_index(best_idx)
    }

    pub fn get_flat_weights(&self) -> Vec<f32> {
        let mut params = Vec::new();
        params.extend(self.fc1.flatten_parameters());
        params.extend(self.fc2.flatten_parameters());
        params.extend(self.fc3.flatten_parameters());
        params.extend(self.fc_out.flatten_parameters());
        params
    }

    pub fn load_flat_weights(&mut self, flat: &[f32]) {
        let mut offset = 0;
        offset += self.fc1.load_parameters(&flat[offset..]);
        offset += self.fc2.load_parameters(&flat[offset..]);
        offset += self.fc3.load_parameters(&flat[offset..]);
        let _ = self.fc_out.load_parameters(&flat[offset..]);
    }

    /// Backpropagates gradient through network layers with ReLU gating.
    pub fn backward_step(&mut self, state: &[f32], grad_out: &[f32], lr: f32) {
        let h1 = self.fc1.forward(state, true);
        let h2 = self.fc2.forward(&h1, true);
        let h3 = self.fc3.forward(&h2, true);

        let grad_h3 = self.fc_out.backward(&h3, grad_out, lr);

        let mut grad_z3 = grad_h3;
        for (k, val) in grad_z3.iter_mut().enumerate() {
            if h3.get(k).copied().unwrap_or(0.0) <= 0.0 {
                *val = 0.0;
            }
        }

        let grad_h2 = self.fc3.backward(&h2, &grad_z3, lr);
        let mut grad_z2 = grad_h2;
        for (k, val) in grad_z2.iter_mut().enumerate() {
            if h2.get(k).copied().unwrap_or(0.0) <= 0.0 {
                *val = 0.0;
            }
        }

        let grad_h1 = self.fc2.backward(&h1, &grad_z2, lr);
        let mut grad_z1 = grad_h1;
        for (k, val) in grad_z1.iter_mut().enumerate() {
            if h1.get(k).copied().unwrap_or(0.0) <= 0.0 {
                *val = 0.0;
            }
        }

        let _ = self.fc1.backward(state, &grad_z1, lr);
    }

    /// Standard single-network training pass for backward compatibility.
    pub fn train_batch(&mut self, batch: &[Transition], gamma: f32, lr: f32) -> f32 {
        if batch.is_empty() {
            return 0.0;
        }

        let mut total_loss = 0.0;

        for transition in batch {
            let q_pred = self.forward(&transition.state);

            let target = if transition.done {
                transition.reward
            } else {
                let next_q = self.forward(&transition.next_state);
                let max_next_q = next_q
                    .into_iter()
                    .fold(f32::NEG_INFINITY, f32::max);
                let max_q = if max_next_q.is_finite() { max_next_q } else { 0.0 };
                transition.reward + gamma * max_q
            };

            let action_idx = transition.get_action_index();
            let current_q = q_pred.get(action_idx).copied().unwrap_or(0.0);
            let td_error = current_q - target;
            total_loss += td_error * td_error;

            let mut grad_out = vec![0.0; self.action_dim];
            if action_idx < self.action_dim {
                grad_out[action_idx] = td_error;
            }

            self.backward_step(&transition.state, &grad_out, lr);
        }

        total_loss / (batch.len() as f32)
    }
}

/// Double Deep Q-Network (Double DQN) with Target Network ($\theta^-$) & Conservative Q-Learning (CQL).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoubleDeepQEngine {
    pub state_dim: usize,
    pub action_dim: usize,
    pub online_net: DeepQEngine,
    pub target_net: DeepQEngine,
    pub cql_alpha: f32,
}

impl DoubleDeepQEngine {
    pub fn new(state_dim: usize, action_dim: usize) -> Self {
        let online_net = DeepQEngine::new(state_dim, action_dim);
        let mut target_net = DeepQEngine::new(state_dim, action_dim);
        target_net.load_flat_weights(&online_net.get_flat_weights());
        Self {
            state_dim,
            action_dim,
            online_net,
            target_net,
            cql_alpha: 1.0,
        }
    }

    /// Forward pass through the primary online network.
    pub fn forward(&self, state: &[f32]) -> Vec<f32> {
        self.online_net.forward(state)
    }

    /// Action selection with strict deterministic action masking.
    /// Actions with mask[i] <= 0.0 are masked to f32::NEG_INFINITY.
    pub fn select_guarded_action(
        &self,
        state: &[f32],
        mask: &[f32; 5],
        epsilon: f32,
    ) -> EdrAction {
        let mut rng = rand::thread_rng();

        if rng.gen::<f32>() < epsilon {
            let valid: Vec<usize> = mask
                .iter()
                .enumerate()
                .filter_map(|(i, &m)| {
                    if m > 0.0 && i < self.action_dim {
                        Some(i)
                    } else {
                        None
                    }
                })
                .collect();
            if !valid.is_empty() {
                let chosen = valid[rng.gen_range(0..valid.len())];
                return EdrAction::from_index(chosen);
            }
            return EdrAction::PassiveObserve;
        }

        let q_values = self.online_net.forward(state);
        let mut best_action = 0;
        let mut max_q = f32::NEG_INFINITY;

        for i in 0..self.action_dim.min(5) {
            if mask[i] > 0.0 {
                let q = q_values.get(i).copied().unwrap_or(0.0);
                if q > max_q {
                    max_q = q;
                    best_action = i;
                }
            }
        }

        EdrAction::from_index(best_action)
    }

    /// Double Q target calculation:
    /// Target action: $a^* = \text{argmax}_{a'} Q(s', a'; \theta_{\text{online}})$
    /// Target value: $y = r + \gamma Q(s', a^*; \theta_{\text{target}})$ (or $r$ if done).
    pub fn compute_double_q_target(
        &self,
        reward: f32,
        next_state: &[f32],
        done: bool,
        gamma: f32,
    ) -> f32 {
        if done {
            return reward;
        }
        let next_q_online = self.online_net.forward(next_state);
        let mut best_a = 0;
        let mut best_q = f32::NEG_INFINITY;
        for (a, &q) in next_q_online.iter().enumerate() {
            if q > best_q {
                best_q = q;
                best_a = a;
            }
        }
        let next_q_target = self.target_net.forward(next_state);
        let target_q = next_q_target.get(best_a).copied().unwrap_or(0.0);
        reward + gamma * target_q
    }

    /// Polyak soft target network update: $\theta^- \leftarrow \tau \theta + (1-\tau)\theta^-$
    pub fn update_target_network(&mut self, tau: f32) {
        let online_w = self.online_net.get_flat_weights();
        let mut target_w = self.target_net.get_flat_weights();
        for (t, o) in target_w.iter_mut().zip(online_w.iter()) {
            *t = tau * o + (1.0 - tau) * *t;
        }
        self.target_net.load_flat_weights(&target_w);
    }

    /// Performs one gradient descent optimization pass over a batch using Double DQN targets
    /// and Conservative Q-Learning (CQL) regularization loss:
    /// $\mathcal{L}_{\text{CQL}} = \mathcal{L}_{\text{TD}} + \alpha_{\text{CQL}} \left( \log \sum_{a} \exp(Q(s, a)) - Q(s, a_{\text{data}}) \right)$
    /// Returns (mean_loss, td_errors) for PER priority updates.
    pub fn train_step_cql(
        &mut self,
        batch: &[Transition],
        gamma: f32,
        lr: f32,
        is_weights: Option<&[f32]>,
    ) -> (f32, Vec<f32>) {
        if batch.is_empty() {
            return (0.0, Vec::new());
        }

        let mut total_loss = 0.0;
        let mut td_errors = Vec::with_capacity(batch.len());

        for (idx, transition) in batch.iter().enumerate() {
            let weight = is_weights
                .map(|w| w.get(idx).copied().unwrap_or(1.0))
                .unwrap_or(1.0);

            // 1. Current Q-values
            let q_pred = self.online_net.forward(&transition.state);
            let action_idx = transition.get_action_index();
            let current_q = q_pred.get(action_idx).copied().unwrap_or(0.0);

            // 2. Double Q Target
            let target = self.compute_double_q_target(
                transition.reward,
                &transition.next_state,
                transition.done,
                gamma,
            );

            let td_error = current_q - target;
            let td_error_safe = if td_error.is_finite() { td_error } else { 0.0 };
            td_errors.push(td_error_safe);

            // 3. CQL Regularization: L_CQL = alpha * (logsumexp(Q) - Q(s, a_data))
            let max_q = q_pred.iter().copied().fold(f32::NEG_INFINITY, f32::max);
            let max_q_safe = if max_q.is_finite() { max_q } else { 0.0 };
            let sum_exp: f32 = q_pred.iter().map(|&q| (q - max_q_safe).exp()).sum();
            let logsumexp = max_q_safe + sum_exp.max(1e-8).ln();
            let cql_penalty = self.cql_alpha * (logsumexp - current_q);

            let td_clipped = td_error_safe.clamp(-5.0, 5.0);
            let td_loss = td_clipped * td_clipped;
            let sample_loss = td_loss + cql_penalty;
            if sample_loss.is_finite() {
                total_loss += sample_loss * weight;
            }

            // 4. Output Gradients:
            // d/dQ(s,a) = alpha * softmax(Q)_a + (if a == a_data { td_error - alpha } else { 0 })
            let mut grad_out = vec![0.0; self.action_dim];
            for a in 0..self.action_dim {
                let softmax_p = if sum_exp > 0.0 {
                    (q_pred.get(a).copied().unwrap_or(0.0) - max_q_safe).exp() / sum_exp
                } else {
                    1.0 / (self.action_dim as f32)
                };
                grad_out[a] = (self.cql_alpha * softmax_p * weight).clamp(-2.0, 2.0);
            }

            if action_idx < self.action_dim {
                grad_out[action_idx] += (td_clipped - self.cql_alpha) * weight;
                grad_out[action_idx] = grad_out[action_idx].clamp(-5.0, 5.0);
            }

            // Backpropagate through online network
            self.online_net.backward_step(&transition.state, &grad_out, lr);
        }

        let mean_loss = total_loss / (batch.len() as f32);
        (mean_loss, td_errors)
    }
}

/// Linear solver using Gauss-Jordan elimination with partial pivoting for LinUCB.
fn solve_linear_system(a: &[Vec<f32>], b: &[f32]) -> Option<Vec<f32>> {
    let n = b.len();
    if a.len() != n {
        return None;
    }
    let mut aug: Vec<Vec<f32>> = Vec::with_capacity(n);
    for i in 0..n {
        if a[i].len() != n {
            return None;
        }
        let mut row = a[i].clone();
        row.push(b[i]);
        aug.push(row);
    }

    for k in 0..n {
        let mut max_row = k;
        let mut max_val = aug[k][k].abs();
        for i in (k + 1)..n {
            let val = aug[i][k].abs();
            if val > max_val {
                max_val = val;
                max_row = i;
            }
        }

        if max_val < 1e-12 {
            return None;
        }

        if max_row != k {
            aug.swap(k, max_row);
        }

        let pivot = aug[k][k];
        for j in k..=n {
            aug[k][j] /= pivot;
        }

        for i in 0..n {
            if i != k {
                let factor = aug[i][k];
                for j in k..=n {
                    let sub = factor * aug[k][j];
                    aug[i][j] -= sub;
                }
            }
        }
    }

    let mut x = vec![0.0; n];
    for i in 0..n {
        x[i] = aug[i][n];
    }
    Some(x)
}

/// Contextual Bandit Engine (LinUCB with Disjoint Linear Models).
/// For single-step dynamic alert throttling & priority scoring:
/// Action 0: AutoResolve, Action 1: QueueTriage, Action 2: PageAnalyst.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinUcbBandit {
    pub num_actions: usize,
    pub context_dim: usize,
    pub a_matrices: Vec<Vec<Vec<f32>>>, // [action][d][d]
    pub b_vectors: Vec<Vec<f32>>,       // [action][d]
}

impl LinUcbBandit {
    pub fn new(num_actions: usize, context_dim: usize) -> Self {
        let mut a_matrices = Vec::with_capacity(num_actions);
        let mut b_vectors = Vec::with_capacity(num_actions);

        for _ in 0..num_actions {
            let mut a = vec![vec![0.0; context_dim]; context_dim];
            for i in 0..context_dim {
                a[i][i] = 1.0; // Ridge regularizer I_d
            }
            a_matrices.push(a);
            b_vectors.push(vec![0.0; context_dim]);
        }

        Self {
            num_actions,
            context_dim,
            a_matrices,
            b_vectors,
        }
    }

    /// Selects action maximizing Upper Confidence Bound:
    /// $\text{score}_a = x^T \hat{\theta}_a + \alpha \sqrt{x^T A_a^{-1} x}$
    pub fn select_action(&self, context: &[f32], alpha: f32) -> usize {
        let mut best_action = 0;
        let mut highest_score = f32::NEG_INFINITY;

        for a in 0..self.num_actions {
            let theta = solve_linear_system(&self.a_matrices[a], &self.b_vectors[a])
                .unwrap_or_else(|| vec![0.0; self.context_dim]);
            let inv_x = solve_linear_system(&self.a_matrices[a], context)
                .unwrap_or_else(|| vec![0.0; self.context_dim]);

            let mean: f32 = context
                .iter()
                .zip(theta.iter())
                .map(|(&x, &t)| x * t)
                .sum();
            let var: f32 = context
                .iter()
                .zip(inv_x.iter())
                .map(|(&x, &z)| x * z)
                .sum();

            let score = mean + alpha * var.max(0.0).sqrt();

            if score > highest_score {
                highest_score = score;
                best_action = a;
            }
        }

        best_action
    }

    /// Updates covariance matrix $A_a \leftarrow A_a + x x^T$ and response vector $b_a \leftarrow b_a + r x$.
    pub fn update(&mut self, action: usize, context: &[f32], reward: f32) {
        if action >= self.num_actions || context.len() != self.context_dim {
            return;
        }

        for i in 0..self.context_dim {
            self.b_vectors[action][i] += reward * context[i];
            for j in 0..self.context_dim {
                self.a_matrices[action][i][j] += context[i] * context[j];
            }
        }
    }
}

/// Transition experience tuple stored in replay memory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transition {
    pub state: Vec<f32>,
    pub action: EdrAction,
    pub reward: f32,
    pub next_state: Vec<f32>,
    pub done: bool,
    pub priority: f32,
    #[serde(default)]
    pub action_index: Option<usize>,
}

impl Transition {
    pub fn new(
        state: Vec<f32>,
        action: EdrAction,
        reward: f32,
        next_state: Vec<f32>,
        done: bool,
        priority: f32,
    ) -> Self {
        let action_index = Some(action.to_index());
        Self {
            state,
            action,
            reward,
            next_state,
            done,
            priority,
            action_index,
        }
    }

    pub fn new_with_index(
        state: Vec<f32>,
        action_index: usize,
        reward: f32,
        next_state: Vec<f32>,
        done: bool,
        priority: f32,
    ) -> Self {
        let action = EdrAction::from_index(action_index);
        Self {
            state,
            action,
            reward,
            next_state,
            done,
            priority,
            action_index: Some(action_index),
        }
    }

    pub fn get_action_index(&self) -> usize {
        self.action_index.unwrap_or_else(|| self.action.to_index())
    }
}

/// Prioritized Experience Replay (PER) Buffer with proportional sampling and importance sampling weights.
#[derive(Debug, Clone)]
pub struct PrioritizedReplayBuffer {
    pub capacity: usize,
    pub buffer: Vec<Transition>,
    pub alpha: f32,
    pub epsilon_p: f32,
}

impl PrioritizedReplayBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            buffer: Vec::with_capacity(capacity),
            alpha: 0.6,
            epsilon_p: 0.01,
        }
    }

    pub fn push(&mut self, transition: Transition) {
        if self.buffer.len() >= self.capacity {
            self.buffer.remove(0);
        }
        self.buffer.push(transition);
    }

    /// Uniform random sample batch for backward compatibility.
    pub fn sample_batch(&self, batch_size: usize) -> Vec<Transition> {
        if self.buffer.is_empty() {
            return Vec::new();
        }
        let mut rng = rand::thread_rng();
        let k = batch_size.min(self.buffer.len());
        (0..k)
            .map(|_| self.buffer[rng.gen_range(0..self.buffer.len())].clone())
            .collect()
    }

    /// Proportional prioritized sampling: $P(i) = \frac{p_i^\alpha}{\sum_k p_k^\alpha}$
    /// with importance sampling weights $w_i = (N \cdot P(i))^{-\beta} / \max_j w_j$.
    /// Returns (transitions, sampled_indices, is_weights).
    pub fn sample_batch_prioritized(
        &self,
        batch_size: usize,
        beta: f32,
    ) -> (Vec<Transition>, Vec<usize>, Vec<f32>) {
        if self.buffer.is_empty() {
            return (Vec::new(), Vec::new(), Vec::new());
        }

        let k = batch_size.min(self.buffer.len());
        let n = self.buffer.len() as f32;

        let priorities: Vec<f32> = self
            .buffer
            .iter()
            .map(|t| (t.priority.abs() + self.epsilon_p).powf(self.alpha))
            .collect();

        let total_p: f32 = priorities.iter().sum();
        let probs: Vec<f32> = if total_p > 0.0 {
            priorities.iter().map(|p| p / total_p).collect()
        } else {
            vec![1.0 / n; self.buffer.len()]
        };

        // Proportional sampling
        let mut rng = rand::thread_rng();
        let mut sampled_indices = Vec::with_capacity(k);
        for _ in 0..k {
            let r: f32 = rng.gen_range(0.0..1.0);
            let mut cum = 0.0;
            let mut picked = self.buffer.len() - 1;
            for (idx, &p) in probs.iter().enumerate() {
                cum += p;
                if r <= cum {
                    picked = idx;
                    break;
                }
            }
            sampled_indices.push(picked);
        }

        // Importance sampling weights
        let mut raw_weights = Vec::with_capacity(k);
        let mut max_w = 0.0f32;
        for &idx in &sampled_indices {
            let p = probs[idx].max(1e-8);
            let w = (1.0 / (n * p)).powf(beta);
            if w > max_w {
                max_w = w;
            }
            raw_weights.push(w);
        }

        let is_weights = if max_w > 0.0 {
            raw_weights.into_iter().map(|w| w / max_w).collect()
        } else {
            vec![1.0; k]
        };

        let transitions = sampled_indices
            .iter()
            .map(|&idx| self.buffer[idx].clone())
            .collect();

        (transitions, sampled_indices, is_weights)
    }

    /// Updates priority $p_i = |\delta_i| + 0.01$ for sampled transitions.
    pub fn update_priorities(&mut self, indices: &[usize], td_errors: &[f32]) {
        for (&idx, &td) in indices.iter().zip(td_errors.iter()) {
            if idx < self.buffer.len() {
                self.buffer[idx].priority = td.abs() + self.epsilon_p;
            }
        }
    }

    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }
}

/// Byzantine-Robust Parameter Aggregator for P2P Mesh Topologies.
/// Uses Coordinate-Wise Trimmed Mean ($\beta = 0.15$) with L2-Norm Gradient Clipping.
#[derive(Debug, Clone)]
pub struct ByzantineRobustAggregator {
    pub trim_ratio: f32,
    pub max_l2_norm: f32,
}

impl Default for ByzantineRobustAggregator {
    fn default() -> Self {
        Self::new(0.15, 10.0)
    }
}

impl ByzantineRobustAggregator {
    pub fn new(trim_ratio: f32, max_l2_norm: f32) -> Self {
        Self {
            trim_ratio,
            max_l2_norm,
        }
    }

    pub fn clip_weights(&self, mut weights: Vec<f32>) -> Vec<f32> {
        let norm_sq: f32 = weights.iter().map(|w| w * w).sum();
        let norm = norm_sq.sqrt();

        if norm > self.max_l2_norm && norm > 0.0 {
            let scale = self.max_l2_norm / norm;
            for w in &mut weights {
                *w *= scale;
            }
        }
        weights
    }

    pub fn aggregate(&self, mut peer_updates: Vec<Vec<f32>>) -> Result<Vec<f32>, &'static str> {
        if peer_updates.is_empty() {
            return Err("Zero updates provided");
        }

        let num_nodes = peer_updates.len();
        let param_dim = peer_updates[0].len();
        let trim_k = (num_nodes as f32 * self.trim_ratio).floor() as usize;

        if 2 * trim_k >= num_nodes {
            let mut avg = vec![0.0; param_dim];
            for u in &peer_updates {
                let clipped = self.clip_weights(u.clone());
                for (i, v) in clipped.iter().enumerate() {
                    avg[i] += v;
                }
            }
            for v in &mut avg {
                *v /= num_nodes as f32;
            }
            return Ok(avg);
        }

        for update in &mut peer_updates {
            *update = self.clip_weights(update.clone());
        }

        let mut aggregated = vec![0.0; param_dim];

        for i in 0..param_dim {
            let mut col_vals: Vec<f32> = peer_updates.iter().map(|u| u[i]).collect();
            col_vals.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

            let retained = &col_vals[trim_k..(num_nodes - trim_k)];
            let sum: f32 = retained.iter().sum();
            aggregated[i] = sum / retained.len() as f32;
        }

        Ok(aggregated)
    }
}

/// Incoming Telemetry Packet to be evaluated by the RL Response Engine.
#[derive(Debug, Clone)]
pub struct TelemetryPacket {
    pub ctx: ProcessContext,
    pub telemetry_vector: Vec<f32>,
    pub threat_score: f32,
}

/// Non-blocking Actor Controller running the real-time event evaluation loop.
/// Supports Shadow / Dry-Run Mode.
pub struct EDRRuntimeController {
    pub safety: Arc<SafetyFilter>,
    pub dqn: Arc<tokio::sync::RwLock<DeepQEngine>>,
    pub double_dqn: Arc<tokio::sync::RwLock<DoubleDeepQEngine>>,
    pub reward_engine: Arc<EdrRewardEngine>,
    pub replay_buffer: Arc<tokio::sync::RwLock<PrioritizedReplayBuffer>>,
    pub aggregator: Arc<ByzantineRobustAggregator>,
    pub telemetry_rx: mpsc::Receiver<TelemetryPacket>,
    pub action_tx: Option<mpsc::Sender<(ProcessContext, EdrAction)>>,
    pub shadow_mode: bool,
}

impl EDRRuntimeController {
    pub fn new(
        state_dim: usize,
        action_dim: usize,
        telemetry_rx: mpsc::Receiver<TelemetryPacket>,
        action_tx: Option<mpsc::Sender<(ProcessContext, EdrAction)>>,
    ) -> Self {
        let double_dqn = DoubleDeepQEngine::new(state_dim, action_dim);
        let legacy_dqn = double_dqn.online_net.clone();

        Self {
            safety: Arc::new(SafetyFilter::new()),
            dqn: Arc::new(tokio::sync::RwLock::new(legacy_dqn)),
            double_dqn: Arc::new(tokio::sync::RwLock::new(double_dqn)),
            reward_engine: Arc::new(EdrRewardEngine::new()),
            replay_buffer: Arc::new(tokio::sync::RwLock::new(PrioritizedReplayBuffer::new(50000))),
            aggregator: Arc::new(ByzantineRobustAggregator::default()),
            telemetry_rx,
            action_tx,
            shadow_mode: false,
        }
    }

    pub fn with_shadow_mode(mut self, shadow: bool) -> Self {
        self.shadow_mode = shadow;
        self
    }

    /// Asynchronous non-blocking event loop processing real-time telemetry.
    pub async fn run_event_loop(mut self) {
        info!(
            "[RL-ENGINE] Autonomous Reinforcement Learning Response Actor loop initialized. (Shadow Mode: {})",
            self.shadow_mode
        );

        while let Some(packet) = self.telemetry_rx.recv().await {
            // 1. Generate Deterministic Action Mask
            let mask = self.safety.generate_action_mask(&packet.ctx);

            // 2. Select Guarded Action via Double DQN Masked Argmax
            let candidate_action = {
                let dqn_guard = self.double_dqn.read().await;
                dqn_guard.select_guarded_action(&packet.telemetry_vector, &mask, 0.05)
            };

            // 3. Filter candidate action through SafetyFilter invariant
            let action = self.safety.filter_action(
                packet.ctx.pid,
                &packet.ctx.binary_path,
                candidate_action,
            );

            // 4. Dispatch or Dry-Run Execution
            if self.shadow_mode {
                info!(
                    "[RL-ENGINE][SHADOW-MODE] Recommended action {:?} on PID {} ({}) [Threat Score: {:.2}] - Dry run, execution hook withheld",
                    action, packet.ctx.pid, packet.ctx.binary_path, packet.threat_score
                );
            } else if action != EdrAction::PassiveObserve {
                warn!(
                    "[RL-ENGINE] Guarded Action Dispatched: {:?} on PID {} ({}) [Threat Score: {:.2}]",
                    action, packet.ctx.pid, packet.ctx.binary_path, packet.threat_score
                );

                if let Some(ref tx) = self.action_tx {
                    let _ = tx.send((packet.ctx.clone(), action)).await;
                }
            }

            // 5. Calculate Reward and Store Transition
            let is_malicious = packet.threat_score > 0.65;
            let is_critical = self.safety.is_protected(packet.ctx.pid, &packet.ctx.binary_path);
            let reward = self.reward_engine.compute_reward(
                action,
                is_malicious,
                packet.threat_score,
                0.5,
                is_critical,
            );

            let transition = Transition {
                state: packet.telemetry_vector.clone(),
                action,
                reward,
                next_state: packet.telemetry_vector,
                done: action == EdrAction::HardMitigation,
                priority: reward.abs() + 0.01,
                action_index: Some(action.to_index()),
            };

            {
                let mut buffer_guard = self.replay_buffer.write().await;
                buffer_guard.push(transition);
            }
        }
    }
}

/// Self-Improvement & Rollout Performance Metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RolloutMetrics {
    pub episodes_completed: usize,
    pub total_steps: usize,
    pub mean_loss: f32,
    pub initial_loss: f32,
    pub final_loss: f32,
    pub true_positive_containment_rate: f32,
    pub false_positive_disruption_rate: f32,
    pub average_dwell_time: f32,
    pub mean_reward: f32,
}

/// Digital Twin Simulator & Self-Improvement Loop.
/// Simulates multi-stage synthetic attack scenarios:
/// (1) Initial Access / Spearphishing -> (2) Defense Evasion / Masquerading ->
/// (3) Credential Access / LSASS -> (4) Lateral Movement -> (5) Ransomware Encryption / Exfiltration
/// along with Benign developer/system background workloads.
#[derive(Debug, Clone)]
pub struct DigitalTwinSimulator {
    pub pipeline: StateFeaturePipeline,
    pub safety: SafetyFilter,
    pub reward_engine: EdrRewardEngine,
}

impl Default for DigitalTwinSimulator {
    fn default() -> Self {
        Self::new()
    }
}

impl DigitalTwinSimulator {
    pub fn new() -> Self {
        Self {
            pipeline: StateFeaturePipeline::new(),
            safety: SafetyFilter::new(),
            reward_engine: EdrRewardEngine::new(),
        }
    }

    /// Generates synthetic state vector for a specified attack stage (1..=5) or benign workload (stage 0).
    pub fn generate_synthetic_features(&self, stage: usize, is_attack: bool) -> [f32; 24] {
        if !is_attack || stage == 0 {
            // Benign normal activity
            let lineage = ProcessLineageVector {
                tree_depth: 0.15,
                parent_child_entropy: 0.05,
                token_elevation_level: 0.5,
                is_kernel_thread: 0.0,
                parent_anomaly_score: 0.02,
                elevation_jump: 0.0,
            };
            let velocity = TelemetryVelocity {
                file_modification_rate: 0.05,
                outbound_net_velocity: 0.05,
                page_permission_trans_rate: 0.0,
                thread_creation_burst_rate: 0.02,
                handle_count_velocity: 0.05,
                cpu_usage_burst: 0.1,
            };
            let priors = HeuristicPriorScores {
                static_pe_magika_score: 0.05,
                cmdline_token_score: 0.05,
                fastpath_yara_sigma_score: 0.0,
                capa_floss_capability: 0.02,
                behavioral_sequence_score: 0.05,
                anomaly_detector_score: 0.05,
            };
            let mesh = MeshContext {
                peer_anomaly_score: 0.05,
                cluster_prevalence: 0.9,
                consensus_confidence: 0.95,
                cluster_alert_rate: 0.02,
                peer_threat_level: 0.05,
                quarantine_vote_ratio: 0.0,
            };
            return self.pipeline.build_state_vector(&lineage, &velocity, &priors, &mesh);
        }

        match stage {
            1 => {
                // Stage 1: Initial Access / Spearphishing
                let lineage = ProcessLineageVector {
                    tree_depth: 0.3,
                    parent_child_entropy: 0.6,
                    token_elevation_level: 0.5,
                    is_kernel_thread: 0.0,
                    parent_anomaly_score: 0.7,
                    elevation_jump: 0.1,
                };
                let velocity = TelemetryVelocity {
                    file_modification_rate: 0.1,
                    outbound_net_velocity: 0.25,
                    page_permission_trans_rate: 0.1,
                    thread_creation_burst_rate: 0.2,
                    handle_count_velocity: 0.2,
                    cpu_usage_burst: 0.3,
                };
                let priors = HeuristicPriorScores {
                    static_pe_magika_score: 0.65,
                    cmdline_token_score: 0.7,
                    fastpath_yara_sigma_score: 0.4,
                    capa_floss_capability: 0.35,
                    behavioral_sequence_score: 0.6,
                    anomaly_detector_score: 0.55,
                };
                let mesh = MeshContext {
                    peer_anomaly_score: 0.3,
                    cluster_prevalence: 0.1,
                    consensus_confidence: 0.5,
                    cluster_alert_rate: 0.2,
                    peer_threat_level: 0.3,
                    quarantine_vote_ratio: 0.1,
                };
                self.pipeline.build_state_vector(&lineage, &velocity, &priors, &mesh)
            }
            2 => {
                // Stage 2: Defense Evasion / Masquerading
                let lineage = ProcessLineageVector {
                    tree_depth: 0.4,
                    parent_child_entropy: 0.75,
                    token_elevation_level: 0.5,
                    is_kernel_thread: 0.0,
                    parent_anomaly_score: 0.8,
                    elevation_jump: 0.2,
                };
                let velocity = TelemetryVelocity {
                    file_modification_rate: 0.2,
                    outbound_net_velocity: 0.35,
                    page_permission_trans_rate: 0.8, // PAGE_RW -> PAGE_RX/RWX
                    thread_creation_burst_rate: 0.4,
                    handle_count_velocity: 0.5,
                    cpu_usage_burst: 0.4,
                };
                let priors = HeuristicPriorScores {
                    static_pe_magika_score: 0.8,
                    cmdline_token_score: 0.85,
                    fastpath_yara_sigma_score: 0.7,
                    capa_floss_capability: 0.65,
                    behavioral_sequence_score: 0.75,
                    anomaly_detector_score: 0.7,
                };
                let mesh = MeshContext {
                    peer_anomaly_score: 0.5,
                    cluster_prevalence: 0.05,
                    consensus_confidence: 0.65,
                    cluster_alert_rate: 0.4,
                    peer_threat_level: 0.5,
                    quarantine_vote_ratio: 0.25,
                };
                self.pipeline.build_state_vector(&lineage, &velocity, &priors, &mesh)
            }
            3 => {
                // Stage 3: Credential Access / LSASS
                let lineage = ProcessLineageVector {
                    tree_depth: 0.5,
                    parent_child_entropy: 0.85,
                    token_elevation_level: 0.75,
                    is_kernel_thread: 0.0,
                    parent_anomaly_score: 0.85,
                    elevation_jump: 0.8,
                };
                let velocity = TelemetryVelocity {
                    file_modification_rate: 0.3,
                    outbound_net_velocity: 0.4,
                    page_permission_trans_rate: 0.9,
                    thread_creation_burst_rate: 0.7,
                    handle_count_velocity: 0.95, // LSASS handle duplication
                    cpu_usage_burst: 0.5,
                };
                let priors = HeuristicPriorScores {
                    static_pe_magika_score: 0.9,
                    cmdline_token_score: 0.9,
                    fastpath_yara_sigma_score: 0.9,
                    capa_floss_capability: 0.85,
                    behavioral_sequence_score: 0.85,
                    anomaly_detector_score: 0.85,
                };
                let mesh = MeshContext {
                    peer_anomaly_score: 0.75,
                    cluster_prevalence: 0.02,
                    consensus_confidence: 0.8,
                    cluster_alert_rate: 0.65,
                    peer_threat_level: 0.75,
                    quarantine_vote_ratio: 0.5,
                };
                self.pipeline.build_state_vector(&lineage, &velocity, &priors, &mesh)
            }
            4 => {
                // Stage 4: Lateral Movement
                let lineage = ProcessLineageVector {
                    tree_depth: 0.6,
                    parent_child_entropy: 0.9,
                    token_elevation_level: 0.75,
                    is_kernel_thread: 0.0,
                    parent_anomaly_score: 0.9,
                    elevation_jump: 0.8,
                };
                let velocity = TelemetryVelocity {
                    file_modification_rate: 0.4,
                    outbound_net_velocity: 0.95, // High network blast velocity
                    page_permission_trans_rate: 0.9,
                    thread_creation_burst_rate: 0.7,
                    handle_count_velocity: 0.8,
                    cpu_usage_burst: 0.6,
                };
                let priors = HeuristicPriorScores {
                    static_pe_magika_score: 0.92,
                    cmdline_token_score: 0.92,
                    fastpath_yara_sigma_score: 0.92,
                    capa_floss_capability: 0.9,
                    behavioral_sequence_score: 0.9,
                    anomaly_detector_score: 0.9,
                };
                let mesh = MeshContext {
                    peer_anomaly_score: 0.85,
                    cluster_prevalence: 0.4,
                    consensus_confidence: 0.88,
                    cluster_alert_rate: 0.85,
                    peer_threat_level: 0.85,
                    quarantine_vote_ratio: 0.7,
                };
                self.pipeline.build_state_vector(&lineage, &velocity, &priors, &mesh)
            }
            _ => {
                // Stage 5: Ransomware Encryption / Exfiltration
                let lineage = ProcessLineageVector {
                    tree_depth: 0.7,
                    parent_child_entropy: 0.95,
                    token_elevation_level: 1.0,
                    is_kernel_thread: 0.0,
                    parent_anomaly_score: 0.95,
                    elevation_jump: 0.9,
                };
                let velocity = TelemetryVelocity {
                    file_modification_rate: 0.99, // Extreme encryption velocity df/dt
                    outbound_net_velocity: 0.95,
                    page_permission_trans_rate: 0.95,
                    thread_creation_burst_rate: 0.95,
                    handle_count_velocity: 0.9,
                    cpu_usage_burst: 0.95,
                };
                let priors = HeuristicPriorScores {
                    static_pe_magika_score: 0.98,
                    cmdline_token_score: 0.98,
                    fastpath_yara_sigma_score: 0.98,
                    capa_floss_capability: 0.98,
                    behavioral_sequence_score: 0.98,
                    anomaly_detector_score: 0.98,
                };
                let mesh = MeshContext {
                    peer_anomaly_score: 0.95,
                    cluster_prevalence: 0.01,
                    consensus_confidence: 0.95,
                    cluster_alert_rate: 0.95,
                    peer_threat_level: 0.95,
                    quarantine_vote_ratio: 0.95,
                };
                self.pipeline.build_state_vector(&lineage, &velocity, &priors, &mesh)
            }
        }
    }

    /// Runs multi-episode self-play rollout across synthetic attack scenarios,
    /// populates the prioritized replay buffer, optimizes the Double DQN policy with CQL loss,
    /// and reports convergence and self-improvement metrics.
    pub fn run_self_play_rollout(
        &self,
        dqn: &mut DoubleDeepQEngine,
        replay_buffer: &mut PrioritizedReplayBuffer,
        episodes: usize,
    ) -> RolloutMetrics {
        let mut total_steps = 0;
        let mut initial_loss = 0.0f32;
        let mut final_loss = 0.0f32;
        let mut loss_records = Vec::new();
        let mut true_positive_containments = 0;
        let mut total_attack_episodes = 0;
        let mut false_positive_disruptions = 0;
        let mut total_benign_episodes = 0;
        let mut total_dwell_steps = 0;
        let mut total_rewards = 0.0f32;

        for ep in 0..episodes {
            // 70% attack scenarios, 30% benign workloads
            let is_attack = (ep % 10) < 7;
            let is_protected_target = !is_attack && (ep % 4 == 0);

            let (pid, binary_name) = if is_protected_target {
                (4, "ntoskrnl.exe")
            } else if is_attack {
                (8420 + (ep as u32), "powershell_payload.exe")
            } else {
                (3100 + (ep as u32), "code_editor.exe")
            };

            let ctx = ProcessContext {
                pid,
                ppid: 1000,
                binary_path: binary_name.into(),
                command_line: format!("{} --exec", binary_name),
                is_kernel_thread: is_protected_target && pid == 4,
                username: if is_protected_target {
                    "SYSTEM".into()
                } else {
                    "analyst".into()
                },
            };

            let mask = self.safety.generate_action_mask(&ctx);
            let mut current_stage = if is_attack { 1 } else { 0 };
            let mut dwell = 0;

            for step in 0..6 {
                total_steps += 1;
                let s_vec = self
                    .generate_synthetic_features(current_stage, is_attack)
                    .to_vec();

                let threat_score = if is_attack {
                    0.4 + (current_stage as f32) * 0.12
                } else {
                    0.05
                };
                let prev_threat_score = (threat_score - 0.1).max(0.0);

                let epsilon = (0.2 * (1.0 - (ep as f32 / episodes as f32))).max(0.02);
                let candidate_action = dqn.select_guarded_action(&s_vec, &mask, epsilon);
                let guarded_action =
                    self.safety.filter_action(ctx.pid, &ctx.binary_path, candidate_action);

                let reward = self.reward_engine.compute_reward(
                    guarded_action,
                    is_attack,
                    threat_score,
                    prev_threat_score,
                    is_protected_target,
                );
                total_rewards += reward;

                let mut done = false;

                if is_attack {
                    if guarded_action.is_containment() {
                        true_positive_containments += 1;
                        done = true;
                    } else if guarded_action.is_inspection() {
                        // Inspection discovers more indicators
                        current_stage = (current_stage + 1).min(5);
                    } else {
                        // Passive observe increases dwell time
                        dwell += 1;
                        current_stage = (current_stage + 1).min(5);
                        if current_stage >= 5 && step >= 4 {
                            done = true; // Final impact reached
                        }
                    }
                } else {
                    // Benign scenario
                    if guarded_action.is_containment() {
                        false_positive_disruptions += 1;
                        done = true;
                    }
                }

                if step >= 5 {
                    done = true;
                }

                let next_s_vec = self
                    .generate_synthetic_features(current_stage, is_attack)
                    .to_vec();

                let transition = Transition {
                    state: s_vec,
                    action: guarded_action,
                    reward,
                    next_state: next_s_vec,
                    done,
                    priority: reward.abs() + 0.01,
                    action_index: Some(guarded_action.to_index()),
                };

                replay_buffer.push(transition);

                // Periodic batch training with Double DQN + CQL
                if replay_buffer.len() >= 16 {
                    let batch_size = 16.min(replay_buffer.len());
                    let beta = 0.4 + 0.6 * (ep as f32 / episodes as f32);
                    let (batch, indices, is_weights) =
                        replay_buffer.sample_batch_prioritized(batch_size, beta);

                    let (loss, td_errors) =
                        dqn.train_step_cql(&batch, 0.95, 0.002, Some(&is_weights));

                    replay_buffer.update_priorities(&indices, &td_errors);

                    // Polyak soft target update
                    dqn.update_target_network(0.05);

                    if loss.is_finite() && loss > 0.0 {
                        if initial_loss == 0.0f32 {
                            initial_loss = loss;
                        }
                        loss_records.push(loss);
                        final_loss = loss;
                    }
                }

                if done {
                    break;
                }
            }

            if is_attack {
                total_attack_episodes += 1;
                total_dwell_steps += dwell;
            } else {
                total_benign_episodes += 1;
            }
        }

        let mean_loss = if !loss_records.is_empty() {
            let finite_records: Vec<f32> = loss_records
                .iter()
                .copied()
                .filter(|l| l.is_finite())
                .collect();
            if !finite_records.is_empty() {
                finite_records.iter().sum::<f32>() / (finite_records.len() as f32)
            } else {
                0.0
            }
        } else {
            0.0
        };

        let tp_rate = if total_attack_episodes > 0 {
            true_positive_containments as f32 / total_attack_episodes as f32
        } else {
            1.0
        };

        let fp_rate = if total_benign_episodes > 0 {
            false_positive_disruptions as f32 / total_benign_episodes as f32
        } else {
            0.0
        };

        let avg_dwell = if total_attack_episodes > 0 {
            total_dwell_steps as f32 / total_attack_episodes as f32
        } else {
            0.0
        };

        let mean_reward = if total_steps > 0 {
            total_rewards / total_steps as f32
        } else {
            0.0
        };

        RolloutMetrics {
            episodes_completed: episodes,
            total_steps,
            mean_loss,
            initial_loss,
            final_loss,
            true_positive_containment_rate: tp_rate,
            false_positive_disruption_rate: fp_rate,
            average_dwell_time: avg_dwell,
            mean_reward,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safety_filter_degrades_containment_on_protected_targets() {
        let filter = SafetyFilter::new();

        // PID 4 (NT Kernel)
        let filtered = filter.filter_action(4, "ntoskrnl.exe", EdrAction::HardMitigation);
        assert_eq!(filtered, EdrAction::MemoryIntrospection);

        let filtered_micro = filter.filter_action(4, "ntoskrnl.exe", EdrAction::MicroContainment);
        assert_eq!(filtered_micro, EdrAction::MemoryIntrospection);

        // PID 0 (System Idle)
        let filtered_idle = filter.filter_action(0, "System Idle Process", EdrAction::HardMitigation);
        assert_eq!(filtered_idle, EdrAction::MemoryIntrospection);

        // csrss.exe
        let filtered_csrss = filter.filter_action(640, r"C:\Windows\System32\csrss.exe", EdrAction::HardMitigation);
        assert_eq!(filtered_csrss, EdrAction::MemoryIntrospection);

        // Standard userland process remains unmasked
        let user_act = filter.filter_action(8812, "malware.exe", EdrAction::HardMitigation);
        assert_eq!(user_act, EdrAction::HardMitigation);
    }

    #[test]
    fn test_action_masking_invariant() {
        let filter = SafetyFilter::new();

        let ctx_kernel = ProcessContext {
            pid: 4,
            ppid: 0,
            binary_path: "ntoskrnl.exe".into(),
            command_line: "".into(),
            is_kernel_thread: true,
            username: "SYSTEM".into(),
        };
        let mask = filter.generate_action_mask(&ctx_kernel);
        assert_eq!(mask, [1.0, 1.0, 1.0, 0.0, 0.0]);

        let ctx_user = ProcessContext {
            pid: 5120,
            ppid: 1000,
            binary_path: r"C:\Users\test\sample.exe".into(),
            command_line: "sample.exe".into(),
            is_kernel_thread: false,
            username: "test".into(),
        };
        let user_mask = filter.generate_action_mask(&ctx_user);
        assert_eq!(user_mask, [1.0, 1.0, 1.0, 1.0, 1.0]);
    }

    #[test]
    fn test_reward_engine_rewards_and_penalties() {
        let engine = EdrRewardEngine::new();

        // TP containment on threat
        let r_tp = engine.compute_reward(EdrAction::HardMitigation, true, 0.9, 0.8, false);
        assert_eq!(r_tp, 100.0);

        // Early elevation
        let r_elev = engine.compute_reward(EdrAction::TraceElevation, true, 0.5, 0.4, false);
        assert_eq!(r_elev, 15.0);

        // FP hard mitigation on benign
        let r_fp = engine.compute_reward(EdrAction::HardMitigation, false, 0.05, 0.05, false);
        assert_eq!(r_fp, -200.0);

        // FP micro containment on benign
        let r_fp_micro = engine.compute_reward(EdrAction::MicroContainment, false, 0.05, 0.05, false);
        assert_eq!(r_fp_micro, -50.0);
    }

    #[test]
    fn test_linucb_bandit_converges_to_best_action() {
        let mut bandit = LinUcbBandit::new(3, 4);
        let ctx = vec![1.0, 0.5, 0.2, 0.8];

        // Action 2 gives reward +1.0, Action 0 gives -1.0, Action 1 gives 0.0
        for _ in 0..40 {
            bandit.update(2, &ctx, 1.0);
            bandit.update(0, &ctx, -1.0);
            bandit.update(1, &ctx, 0.0);
        }

        let selected = bandit.select_action(&ctx, 0.1);
        assert_eq!(selected, 2);
    }
}
