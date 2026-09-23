//! Deep Reinforcement Learning (DQN) Autonomous Response & Byzantine-Resilient Federated Mesh Engine.
//!
//! Provides:
//! 1. Deterministic Action Masking & Safety Guardrails (Zero OS Destabilization Invariant)
//! 2. Deep Q-Network Policy with Masked Argmax
//! 3. Prioritized Experience Replay Buffer
//! 4. Byzantine-Robust Gradient Aggregator (Coordinate-Wise Trimmed Mean with L2 Norm Clipping)
//! 5. Non-Blocking Real-Time Actor Loop for Host & Mesh Telemetry

use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{info, warn};

/// Discrete Autonomous Mitigation Actions available to the RL policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum MitigationAction {
    /// Action 0: Normal Execution Allowed (No Mitigation)
    Allow = 0,
    /// Action 1: CPU Throttling / I/O Rate-Limiting
    Throttle = 1,
    /// Action 2: Process Execution Suspended (Freeze Thread Group for Triage)
    Suspend = 2,
    /// Action 3: Process Termination & Network Tarpit Isolation
    TerminateAndIsolate = 3,
}

impl MitigationAction {
    pub fn from_index(idx: usize) -> Self {
        match idx {
            1 => Self::Throttle,
            2 => Self::Suspend,
            3 => Self::TerminateAndIsolate,
            _ => Self::Allow,
        }
    }

    pub fn to_index(self) -> usize {
        self as usize
    }
}

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

/// Strict Invariant Engine: Guarantees that critical kernel and system daemons
/// can NEVER be mutated, suspended, or killed regardless of RL policy predictions.
#[derive(Debug, Clone)]
pub struct SafetyGuardrail {
    protected_pids: HashSet<u32>,
    protected_binaries: HashSet<String>,
}

impl Default for SafetyGuardrail {
    fn default() -> Self {
        Self::new()
    }
}

impl SafetyGuardrail {
    pub fn new() -> Self {
        let mut protected_pids = HashSet::new();
        // Core OS Kernel / Init PIDs
        protected_pids.insert(0); // System Idle (Windows/Linux)
        protected_pids.insert(1); // init / systemd / launchd
        protected_pids.insert(4); // NT Kernel & System (Windows)

        let mut protected_binaries = HashSet::new();
        // Linux / Unix Critical System Binaries
        protected_binaries.insert("/sbin/init".to_lowercase());
        protected_binaries.insert("/usr/lib/systemd/systemd".to_lowercase());
        protected_binaries.insert("/System/Library/CoreServices/launchd".to_lowercase());
        protected_binaries.insert("/usr/bin/dbus-daemon".to_lowercase());

        // Windows Critical System Binaries
        protected_binaries.insert("smss.exe".to_lowercase());
        protected_binaries.insert("csrss.exe".to_lowercase());
        protected_binaries.insert("wininit.exe".to_lowercase());
        protected_binaries.insert("services.exe".to_lowercase());
        protected_binaries.insert("lsass.exe".to_lowercase());
        protected_binaries.insert("winlogon.exe".to_lowercase());
        protected_binaries.insert("fontdrvhost.exe".to_lowercase());

        Self {
            protected_pids,
            protected_binaries,
        }
    }

    /// Generates a binary mask: [Allow, Throttle, Suspend, Terminate]
    /// 1.0 = Action Permitted, 0.0 = Action Strictly Prohibited
    pub fn generate_action_mask(&self, ctx: &ProcessContext) -> [f32; 4] {
        let path_lower = ctx.binary_path.to_lowercase();
        let filename = std::path::Path::new(&path_lower)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(&path_lower);

        let is_protected_pid = self.protected_pids.contains(&ctx.pid);
        let is_protected_bin = self.protected_binaries.contains(filename)
            || self.protected_binaries.contains(&path_lower);

        if ctx.is_kernel_thread || is_protected_pid || is_protected_bin {
            // Full Invariant Guarantee: Only "Allow" is permitted
            return [1.0, 0.0, 0.0, 0.0];
        }

        // Standard userland workloads permit full mitigation spectrum
        [1.0, 1.0, 1.0, 1.0]
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
                self.weights[i][j] -= lr * input[i] * grad_output[j];
            }
        }
        for j in 0..out_dim {
            self.biases[j] -= lr * grad_output[j];
        }
        grad_input
    }
}

/// Deep Q-Network (DQN) Policy Engine with Masked Argmax.
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

    /// Forward pass through the network layers.
    pub fn forward(&self, state: &[f32]) -> Vec<f32> {
        let h1 = self.fc1.forward(state, true);
        let h2 = self.fc2.forward(&h1, true);
        let h3 = self.fc3.forward(&h2, true);
        self.fc_out.forward(&h3, false)
    }

    /// Select an optimal mitigation action subject to hard deterministic bounds.
    /// Actions prohibited by the mask are assigned -infinity, ensuring mathematical impossibility of selection.
    pub fn select_guarded_action(
        &self,
        state_features: &[f32],
        mask: &[f32; 4],
        epsilon: f32,
    ) -> MitigationAction {
        let mut rng = rand::thread_rng();

        // Epsilon-greedy exploration over strictly permitted actions
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

        // Forward inference
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

    /// Flattens all network weights and biases into a continuous parameter vector for mesh sharing.
    pub fn get_flat_weights(&self) -> Vec<f32> {
        let mut params = Vec::new();
        params.extend(self.fc1.flatten_parameters());
        params.extend(self.fc2.flatten_parameters());
        params.extend(self.fc3.flatten_parameters());
        params.extend(self.fc_out.flatten_parameters());
        params
    }

    /// Loads aggregated parameter weights into the network layers.
    pub fn load_flat_weights(&mut self, flat: &[f32]) {
        let mut offset = 0;
        offset += self.fc1.load_parameters(&flat[offset..]);
        offset += self.fc2.load_parameters(&flat[offset..]);
        offset += self.fc3.load_parameters(&flat[offset..]);
        let _ = self.fc_out.load_parameters(&flat[offset..]);
    }

    /// Performs one gradient descent optimization pass over a batch of experience replay transitions.
    /// Computes the Temporal Difference (TD) loss via the Bellman optimality equation:
    /// y_i = r + \gamma \max_{a'} Q(s', a') (or r if terminal).
    /// Caches intermediate activations and backpropagates through layers with ReLU gradient gating.
    pub fn train_batch(&mut self, batch: &[Transition], gamma: f32, lr: f32) -> f32 {
        if batch.is_empty() {
            return 0.0;
        }

        let mut total_loss = 0.0;

        for transition in batch {
            // 1. Forward pass caching intermediate activations
            let h1 = self.fc1.forward(&transition.state, true);
            let h2 = self.fc2.forward(&h1, true);
            let h3 = self.fc3.forward(&h2, true);
            let q_pred = self.fc_out.forward(&h3, false);

            // 2. Bellman target calculation
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

            // 3. Output gradient for chosen action
            let mut grad_out = vec![0.0; self.action_dim];
            if action_idx < self.action_dim {
                grad_out[action_idx] = td_error;
            }

            // 4. Backprop through fc_out
            let grad_h3 = self.fc_out.backward(&h3, &grad_out, lr);

            // Backprop through fc3 with ReLU gradient gating (h_k > 0.0)
            let mut grad_z3 = grad_h3;
            for (k, val) in grad_z3.iter_mut().enumerate() {
                if h3.get(k).copied().unwrap_or(0.0) <= 0.0 {
                    *val = 0.0;
                }
            }

            // Backprop through fc2 with ReLU gradient gating
            let grad_h2 = self.fc3.backward(&h2, &grad_z3, lr);
            let mut grad_z2 = grad_h2;
            for (k, val) in grad_z2.iter_mut().enumerate() {
                if h2.get(k).copied().unwrap_or(0.0) <= 0.0 {
                    *val = 0.0;
                }
            }

            // Backprop through fc1 with ReLU gradient gating
            let grad_h1 = self.fc2.backward(&h1, &grad_z2, lr);
            let mut grad_z1 = grad_h1;
            for (k, val) in grad_z1.iter_mut().enumerate() {
                if h1.get(k).copied().unwrap_or(0.0) <= 0.0 {
                    *val = 0.0;
                }
            }

            let _ = self.fc1.backward(&transition.state, &grad_z1, lr);
        }

        total_loss / (batch.len() as f32)
    }
}

/// Transition experience tuple stored in replay memory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transition {
    pub state: Vec<f32>,
    pub action: MitigationAction,
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
        action: MitigationAction,
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
        let action = MitigationAction::from_index(action_index);
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

/// Prioritized Experience Replay Buffer for continual policy optimization.
#[derive(Debug, Clone)]
pub struct PrioritizedReplayBuffer {
    pub capacity: usize,
    pub buffer: Vec<Transition>,
}

impl PrioritizedReplayBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            buffer: Vec::with_capacity(capacity),
        }
    }

    pub fn push(&mut self, transition: Transition) {
        if self.buffer.len() >= self.capacity {
            self.buffer.remove(0);
        }
        self.buffer.push(transition);
    }

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

    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }
}

/// Byzantine-Robust Parameter Aggregator for P2P Mesh Topologies.
/// Uses Coordinate-Wise Trimmed Mean ($\beta = 0.15$) with L2-Norm Gradient Clipping
/// to neutralize model poisoning attacks from compromised peer hosts.
#[derive(Debug, Clone)]
pub struct ByzantineRobustAggregator {
    pub trim_ratio: f32, // Fraction of top/bottom outliers to strip (e.g. 0.15)
    pub max_l2_norm: f32, // Max permitted gradient L2 norm
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

    /// Enforces L2-norm clipping on inbound peer parameter updates.
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

    /// Aggregates parameter updates from N peers using Coordinate-Wise Trimmed Mean.
    pub fn aggregate(&self, mut peer_updates: Vec<Vec<f32>>) -> Result<Vec<f32>, &'static str> {
        if peer_updates.is_empty() {
            return Err("Zero updates provided");
        }

        let num_nodes = peer_updates.len();
        let param_dim = peer_updates[0].len();
        let trim_k = (num_nodes as f32 * self.trim_ratio).floor() as usize;

        // If fewer than required nodes to trim, average with clipping
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

        // Clip all inbound peer updates
        for update in &mut peer_updates {
            *update = self.clip_weights(update.clone());
        }

        let mut aggregated = vec![0.0; param_dim];

        for i in 0..param_dim {
            let mut col_vals: Vec<f32> = peer_updates.iter().map(|u| u[i]).collect();
            col_vals.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

            // Slice out top-k and bottom-k outliers
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
pub struct EDRRuntimeController {
    pub safety: Arc<SafetyGuardrail>,
    pub dqn: Arc<tokio::sync::RwLock<DeepQEngine>>,
    pub replay_buffer: Arc<tokio::sync::RwLock<PrioritizedReplayBuffer>>,
    pub aggregator: Arc<ByzantineRobustAggregator>,
    pub telemetry_rx: mpsc::Receiver<TelemetryPacket>,
    pub action_tx: Option<mpsc::Sender<(ProcessContext, MitigationAction)>>,
}

impl EDRRuntimeController {
    pub fn new(
        state_dim: usize,
        action_dim: usize,
        telemetry_rx: mpsc::Receiver<TelemetryPacket>,
        action_tx: Option<mpsc::Sender<(ProcessContext, MitigationAction)>>,
    ) -> Self {
        Self {
            safety: Arc::new(SafetyGuardrail::new()),
            dqn: Arc::new(tokio::sync::RwLock::new(DeepQEngine::new(state_dim, action_dim))),
            replay_buffer: Arc::new(tokio::sync::RwLock::new(PrioritizedReplayBuffer::new(50000))),
            aggregator: Arc::new(ByzantineRobustAggregator::default()),
            telemetry_rx,
            action_tx,
        }
    }

    /// Asynchronous non-blocking event loop processing real-time telemetry.
    pub async fn run_event_loop(mut self) {
        info!("[RL-ENGINE] Autonomous Reinforcement Learning Response Actor loop initialized.");

        while let Some(packet) = self.telemetry_rx.recv().await {
            // 1. Generate Deterministic Action Mask
            let mask = self.safety.generate_action_mask(&packet.ctx);

            // 2. Select Guarded Action via Masked Argmax
            let action = {
                let dqn_guard = self.dqn.read().await;
                dqn_guard.select_guarded_action(&packet.telemetry_vector, &mask, 0.05)
            };

            // 3. Dispatch mitigation to OS subsystem if action is active
            if action != MitigationAction::Allow {
                warn!(
                    "[RL-ENGINE] Guarded Mitigation Selected: {:?} on PID {} ({}) [Threat Score: {:.2}]",
                    action, packet.ctx.pid, packet.ctx.binary_path, packet.threat_score
                );

                if let Some(ref tx) = self.action_tx {
                    let _ = tx.send((packet.ctx.clone(), action)).await;
                }
            }

            // 4. Calculate Reward and Store in Replay Buffer
            // Reward Formulation: High penalty for false positives, positive reward for timely threat mitigation
            let reward = if packet.threat_score > 0.70 {
                match action {
                    MitigationAction::TerminateAndIsolate => 1.0,
                    MitigationAction::Suspend => 0.7,
                    MitigationAction::Throttle => 0.3,
                    MitigationAction::Allow => -1.0, // Missed threat penalty
                }
            } else {
                match action {
                    MitigationAction::Allow => 0.5,
                    _ => -2.0, // False positive mitigation penalty
                }
            };

            let transition = Transition {
                state: packet.telemetry_vector.clone(),
                action,
                reward,
                next_state: packet.telemetry_vector,
                done: action == MitigationAction::TerminateAndIsolate,
                priority: (reward.abs() + 0.01),
                action_index: Some(action.to_index()),
            };

            {
                let mut buffer_guard = self.replay_buffer.write().await;
                buffer_guard.push(transition);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safety_guardrails_protects_critical_pids() {
        let guard = SafetyGuardrail::new();

        // PID 0 (System Idle)
        let ctx_idle = ProcessContext {
            pid: 0,
            ppid: 0,
            binary_path: "System Idle Process".into(),
            command_line: "".into(),
            is_kernel_thread: true,
            username: "SYSTEM".into(),
        };
        assert_eq!(guard.generate_action_mask(&ctx_idle), [1.0, 0.0, 0.0, 0.0]);

        // PID 4 (Windows NT Kernel)
        let ctx_kernel = ProcessContext {
            pid: 4,
            ppid: 0,
            binary_path: "ntoskrnl.exe".into(),
            command_line: "".into(),
            is_kernel_thread: true,
            username: "SYSTEM".into(),
        };
        assert_eq!(guard.generate_action_mask(&ctx_kernel), [1.0, 0.0, 0.0, 0.0]);

        // csrss.exe
        let ctx_csrss = ProcessContext {
            pid: 640,
            ppid: 4,
            binary_path: r"C:\Windows\System32\csrss.exe".into(),
            command_line: "".into(),
            is_kernel_thread: false,
            username: "SYSTEM".into(),
        };
        assert_eq!(guard.generate_action_mask(&ctx_csrss), [1.0, 0.0, 0.0, 0.0]);

        // Standard userland workload (permits full mitigation)
        let ctx_user = ProcessContext {
            pid: 8912,
            ppid: 4000,
            binary_path: r"C:\Users\user\AppData\Local\Temp\malicious.exe".into(),
            command_line: "malicious.exe --beacon".into(),
            is_kernel_thread: false,
            username: "user".into(),
        };
        assert_eq!(guard.generate_action_mask(&ctx_user), [1.0, 1.0, 1.0, 1.0]);
    }

    #[test]
    fn test_dqn_masked_argmax_never_picks_prohibited_actions() {
        let dqn = DeepQEngine::new(16, 4);
        let dummy_state = vec![0.5; 16];

        // Mask allowing ONLY Action 0 (Allow)
        let strict_mask = [1.0, 0.0, 0.0, 0.0];
        for _ in 0..50 {
            let action = dqn.select_guarded_action(&dummy_state, &strict_mask, 0.0);
            assert_eq!(action, MitigationAction::Allow);
        }
    }

    #[test]
    fn test_byzantine_trimmed_mean_rejects_poisoned_gradients() {
        let aggregator = ByzantineRobustAggregator::new(0.20, 10.0);

        // 5 peer updates: 4 honest around 1.0, 1 malicious poisoned node sending 1000.0
        let honest_update_1 = vec![1.0, 1.0, 1.0];
        let honest_update_2 = vec![1.1, 0.9, 1.0];
        let honest_update_3 = vec![0.9, 1.1, 1.0];
        let honest_update_4 = vec![1.0, 1.0, 0.9];
        let poisoned_update = vec![1000.0, -1000.0, 500.0]; // Poison attack

        let peer_updates = vec![
            honest_update_1,
            honest_update_2,
            honest_update_3,
            honest_update_4,
            poisoned_update,
        ];

        let agg = aggregator.aggregate(peer_updates).expect("Aggregation succeeded");

        // Outlier 1000.0 was trimmed out; result must remain close to 1.0
        for val in agg {
            assert!(val >= 0.8 && val <= 1.2, "Byzantine outlier was not trimmed: {}", val);
        }
    }

    #[test]
    fn test_dense_layer_backward() {
        let mut layer = DenseLayer::new(4, 2);
        let input = vec![1.0, 0.5, -0.5, 2.0];
        let grad_output = vec![0.1, -0.2];
        let lr = 0.01;

        let grad_input = layer.backward(&input, &grad_output, lr);
        assert_eq!(grad_input.len(), 4);
    }

    #[test]
    fn test_dqn_train_batch_reduces_loss() {
        let mut dqn = DeepQEngine::new(8, 4);
        let s = vec![0.2, 0.4, 0.1, 0.9, 0.0, 0.5, 0.3, 0.7];
        let next_s = vec![0.1, 0.3, 0.0, 0.8, 0.0, 0.4, 0.2, 0.6];

        let batch = vec![
            Transition::new_with_index(s.clone(), 3, 1.0, next_s.clone(), true, 1.0),
            Transition::new_with_index(s.clone(), 0, -1.0, next_s.clone(), false, 1.0),
        ];

        let initial_loss = dqn.train_batch(&batch, 0.95, 0.05);
        assert!(initial_loss.is_finite());

        let mut final_loss = initial_loss;
        for _ in 0..50 {
            final_loss = dqn.train_batch(&batch, 0.95, 0.05);
        }

        assert!(
            final_loss < initial_loss,
            "Loss should decrease: initial={}, final={}",
            initial_loss,
            final_loss
        );
    }
}

