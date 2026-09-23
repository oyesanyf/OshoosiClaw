//! SkyRL EDR Self-Improvement Loop & Security Gymnasium Environment.
//!
//! Provides:
//! 1. `SkyAction`: 9-action discrete policy space covering read inquiries & autonomous containment.
//! 2. `StepResult`: Verifiable step feedback including normalized observation, reward, and thought traces.
//! 3. `OshoosiSecurityGym`: Multi-turn investigation environment enforcing verifiable rewards
//!    and the Zero OS Destabilization Invariant via `SafetyGuardrail`.

use crate::rl_engine::{ProcessContext, SafetyGuardrail};
use serde::{Deserialize, Serialize};

/// 9-Action Discrete Policy Space for SkyRL EDR Agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum SkyAction {
    /// Action 0: Permit execution without mitigation (Normal execution)
    Allow = 0,
    /// Action 1: Query process hierarchy, parent-child lineages, and ancestry
    QueryProcessTree = 1,
    /// Action 2: Inspect active sockets, remote endpoints, and beaconing
    QueryNetworkConnections = 2,
    /// Action 3: Scan virtual memory pages for injected shellcode / RWX regions
    QueryMemorySignatures = 3,
    /// Action 4: Rate-limit CPU and I/O consumption
    Throttle = 4,
    /// Action 5: Freeze threads in process for triage
    Suspend = 5,
    /// Action 6: Terminate process execution tree
    Terminate = 6,
    /// Action 7: Sever host/process network interfaces
    IsolateNetwork = 7,
    /// Action 8: Roll back system state to pre-incident snapshot
    RollbackRestorePoint = 8,
}

impl SkyAction {
    pub fn from_index(idx: usize) -> Self {
        match idx {
            1 => Self::QueryProcessTree,
            2 => Self::QueryNetworkConnections,
            3 => Self::QueryMemorySignatures,
            4 => Self::Throttle,
            5 => Self::Suspend,
            6 => Self::Terminate,
            7 => Self::IsolateNetwork,
            8 => Self::RollbackRestorePoint,
            _ => Self::Allow,
        }
    }

    pub fn to_index(self) -> usize {
        self as usize
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "Allow",
            Self::QueryProcessTree => "QueryProcessTree",
            Self::QueryNetworkConnections => "QueryNetworkConnections",
            Self::QueryMemorySignatures => "QueryMemorySignatures",
            Self::Throttle => "Throttle",
            Self::Suspend => "Suspend",
            Self::Terminate => "Terminate",
            Self::IsolateNetwork => "IsolateNetwork",
            Self::RollbackRestorePoint => "RollbackRestorePoint",
        }
    }

    pub fn from_str_name(name: &str) -> Option<Self> {
        match name.trim().to_lowercase().as_str() {
            "allow" => Some(Self::Allow),
            "queryprocesstree" | "query_process_tree" | "queryprocess" => {
                Some(Self::QueryProcessTree)
            }
            "querynetworkconnections" | "query_network_connections" | "querynetwork" => {
                Some(Self::QueryNetworkConnections)
            }
            "querymemorysignatures" | "query_memory_signatures" | "querymemory" => {
                Some(Self::QueryMemorySignatures)
            }
            "throttle" => Some(Self::Throttle),
            "suspend" => Some(Self::Suspend),
            "terminate" => Some(Self::Terminate),
            "isolatenetwork" | "isolate_network" | "isolate" => Some(Self::IsolateNetwork),
            "rollbackrestorepoint" | "rollback_restore_point" | "rollback" => {
                Some(Self::RollbackRestorePoint)
            }
            _ => None,
        }
    }

    /// Returns true if the action is a read-only telemetry investigation query.
    pub fn is_query(self) -> bool {
        matches!(
            self,
            Self::QueryProcessTree | Self::QueryNetworkConnections | Self::QueryMemorySignatures
        )
    }

    /// Returns true if the action performs stateful containment or process mitigation.
    pub fn is_containment(self) -> bool {
        matches!(
            self,
            Self::Throttle
                | Self::Suspend
                | Self::Terminate
                | Self::IsolateNetwork
                | Self::RollbackRestorePoint
        )
    }
}

/// Verifiable Step Result returned by the EDR Gym Environment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepResult {
    /// 16-feature normalized observation vector
    pub observation: Vec<f32>,
    /// Verifiable scalar reward signal
    pub reward: f32,
    /// Terminal flag indicating episode completion
    pub done: bool,
    /// Structured reasoning thought trace formatted as `<thought>...</thought><action>...</action>`
    pub thought_trace: String,
    /// Operational description of step execution
    pub explanation: String,
}

/// Oshoosi Security Gymnasium Environment.
///
/// Implements a multi-turn investigation environment where an agent inspects
/// host telemetry, gathers evidence, and mitigates threats subject to
/// strict safety guardrails and verifiable reward calculations.
#[derive(Debug, Clone)]
pub struct OshoosiSecurityGym {
    /// Context of process under triage
    pub target_process: ProcessContext,
    /// Ground-truth label of the process workload
    pub is_malicious: bool,
    /// 16-feature normalized observation vector
    pub observation: Vec<f32>,
    /// Multi-turn investigation counter
    pub current_step: usize,
    /// Maximum permitted turns per investigation episode (default 8)
    pub max_steps: usize,
    /// Invariant safety guardrail ensuring protected daemons cannot be targeted
    pub safety: SafetyGuardrail,
    /// History of actions taken and rewards received in current episode
    pub history: Vec<(SkyAction, f32)>,
    /// Textual record of forensic facts gathered during queries
    pub evidence_gathered: Vec<String>,
}

impl OshoosiSecurityGym {
    /// Creates a new Gymnasium instance for a given target process.
    pub fn new(target_process: ProcessContext, is_malicious: bool) -> Self {
        let safety = SafetyGuardrail::new();
        let observation = Self::initialize_observation(&target_process, is_malicious, &safety);

        Self {
            target_process,
            is_malicious,
            observation,
            current_step: 0,
            max_steps: 8,
            safety,
            history: Vec::new(),
            evidence_gathered: Vec::new(),
        }
    }

    /// Generates initial 16-feature normalized observation vector.
    ///
    /// Indices:
    /// 0: parent_anomaly_score
    /// 1: unsigned_binary_flag
    /// 2: temp_path_execution_flag
    /// 3: cmdline_entropy
    /// 4: network_beacon_frequency
    /// 5: lateral_movement_score
    /// 6: memory_injection_score
    /// 7: privilege_escalation_score
    /// 8: persistence_score
    /// 9: defense_evasion_score
    /// 10: credential_access_score
    /// 11: discovery_activity_score
    /// 12: process_tree_depth
    /// 13: connection_count
    /// 14: thread_count
    /// 15: threat_score
    fn initialize_observation(
        ctx: &ProcessContext,
        is_malicious: bool,
        safety: &SafetyGuardrail,
    ) -> Vec<f32> {
        let mask = safety.generate_action_mask(ctx);
        let is_protected = mask == [1.0, 0.0, 0.0, 0.0];

        let mut obs = vec![0.0; 16];
        if is_protected {
            obs[12] = 0.1; // Kernel / core root depth
            obs[14] = 0.8; // High thread count for system daemons
            obs[15] = 0.01; // Negligible threat score
            return obs;
        }

        if is_malicious {
            obs[0] = 0.65; // Parent anomaly
            obs[1] = 0.90; // Unsigned binary
            obs[2] = if ctx.binary_path.to_lowercase().contains("temp") {
                1.0
            } else {
                0.5
            };
            obs[3] = 0.75; // Obfuscated / high-entropy cmdline
            obs[4] = 0.40; // Initial beacon hint
            obs[5] = 0.20;
            obs[6] = 0.50; // Suspicious memory footprint
            obs[7] = 0.30;
            obs[8] = 0.40;
            obs[9] = 0.60;
            obs[10] = 0.25;
            obs[11] = 0.35;
            obs[12] = 0.45;
            obs[13] = 0.30;
            obs[14] = 0.40;
            obs[15] = 0.82; // Threat score
        } else {
            obs[0] = 0.05;
            obs[1] = 0.00;
            obs[2] = 0.00;
            obs[3] = 0.15;
            obs[4] = 0.00;
            obs[5] = 0.00;
            obs[6] = 0.00;
            obs[7] = 0.00;
            obs[8] = 0.00;
            obs[9] = 0.05;
            obs[10] = 0.00;
            obs[11] = 0.05;
            obs[12] = 0.20;
            obs[13] = 0.10;
            obs[14] = 0.25;
            obs[15] = 0.04;
        }

        obs
    }

    /// Resets the environment for another episode.
    pub fn reset(&mut self) -> Vec<f32> {
        self.current_step = 0;
        self.history.clear();
        self.evidence_gathered.clear();
        self.observation =
            Self::initialize_observation(&self.target_process, self.is_malicious, &self.safety);
        self.observation.clone()
    }

    /// Evaluates one step in the gymnasium environment according to the verifiable reward formula:
    /// R = R_correctness - lambda * (latency / steps) - mu * (false containment) - nu * (invariant violation)
    pub fn step(&mut self, action: SkyAction) -> StepResult {
        let mask = self.safety.generate_action_mask(&self.target_process);
        let is_protected = mask == [1.0, 0.0, 0.0, 0.0];

        // 1. SafetyGuardrail Invariant Check:
        // Core system PIDs and protected binaries can NEVER be targeted for containment.
        if is_protected && action.is_containment() {
            let reward = -100.0;
            let done = true;
            let thought_trace = format!(
                "<thought>Step {}: Invariant violation intercepted by SafetyGuardrail! Attempted action {:?} against protected system process PID {} ({}). Absolute zero OS destabilization invariant triggered. R = -100.0.</thought><action>{:?}</action>",
                self.current_step, action, self.target_process.pid, self.target_process.binary_path, action
            );
            let explanation = format!(
                "SafetyGuardrail invariant violation: Protected process PID {} ({}) cannot be targeted for containment.",
                self.target_process.pid, self.target_process.binary_path
            );
            self.history.push((action, reward));
            return StepResult {
                observation: self.observation.clone(),
                reward,
                done,
                thought_trace,
                explanation,
            };
        }

        // 2. Multi-turn Inquiry Actions (Exploration):
        if action.is_query() {
            let reward = -0.05; // Exploration step latency cost
            self.current_step += 1;
            let done = self.current_step >= self.max_steps;

            let forensic_evidence = match action {
                SkyAction::QueryProcessTree => {
                    if self.is_malicious {
                        self.observation[0] = (self.observation[0] + 0.25).min(1.0);
                        self.observation[12] = (self.observation[12] + 0.30).min(1.0);
                        "Anomalous parent lineage: spawned by masqueraded cmd.exe"
                    } else {
                        self.observation[0] = 0.02;
                        "Legitimate service ancestry verified"
                    }
                }
                SkyAction::QueryNetworkConnections => {
                    if self.is_malicious {
                        self.observation[4] = (self.observation[4] + 0.40).min(1.0);
                        self.observation[13] = (self.observation[13] + 0.35).min(1.0);
                        "Active beaconing socket connected to suspicious external endpoint"
                    } else {
                        self.observation[4] = 0.0;
                        "Local loopback IPC telemetry only"
                    }
                }
                SkyAction::QueryMemorySignatures => {
                    if self.is_malicious {
                        self.observation[6] = (self.observation[6] + 0.45).min(1.0);
                        self.observation[9] = (self.observation[9] + 0.25).min(1.0);
                        "RWX unmapped executable pages with reflective payload headers detected"
                    } else {
                        self.observation[6] = 0.0;
                        "Clean memory space; all executable segments mapped to signed binaries"
                    }
                }
                _ => "Forensic scan complete",
            };

            self.evidence_gathered.push(forensic_evidence.to_string());
            self.history.push((action, reward));

            let thought_trace = format!(
                "<thought>Step {}: Executed exploratory inquiry {:?} on PID {}. Forensic discovery: {}. Step exploration penalty: -0.05. Threat score: {:.2}.</thought><action>{:?}</action>",
                self.current_step, action, self.target_process.pid, forensic_evidence, self.observation[15], action
            );
            let explanation = format!("Forensic inquiry {:?} executed: {}.", action, forensic_evidence);

            return StepResult {
                observation: self.observation.clone(),
                reward,
                done,
                thought_trace,
                explanation,
            };
        }

        // 3. Terminal Containment / Mitigation / Allow Actions:
        let step_cost = 0.05 * (self.current_step as f32);
        let done = true;

        let (reward, thought_trace, explanation) = if self.is_malicious {
            match action {
                SkyAction::Terminate | SkyAction::Suspend | SkyAction::IsolateNetwork => {
                    let r = 1.0 - step_cost;
                    (
                        r,
                        format!(
                            "<thought>Step {}: Target PID {} confirmed malicious. Containment action {:?} deployed. Verified timely threat mitigation. Reward: {:.2}.</thought><action>{:?}</action>",
                            self.current_step + 1, self.target_process.pid, action, r, action
                        ),
                        format!("Malicious process successfully neutralized via {:?}.", action),
                    )
                }
                SkyAction::Throttle | SkyAction::RollbackRestorePoint => {
                    let r = 0.8 - step_cost;
                    (
                        r,
                        format!(
                            "<thought>Step {}: Target PID {} confirmed malicious. Partial containment action {:?} deployed. Reward: {:.2}.</thought><action>{:?}</action>",
                            self.current_step + 1, self.target_process.pid, action, r, action
                        ),
                        format!("Containment action {:?} applied to malicious process.", action),
                    )
                }
                SkyAction::Allow => (
                    -1.5,
                    format!(
                        "<thought>Step {}: False negative containment error! Malicious workload PID {} was allowed without mitigation. Severe penalty: -1.5.</thought><action>Allow</action>",
                        self.current_step + 1, self.target_process.pid
                    ),
                    "Missed threat: Malicious process permitted execution without mitigation.".to_string(),
                ),
                _ => (0.0, "<thought>Unrecognized terminal action</thought><action>Allow</action>".into(), "Unrecognized action".into()),
            }
        } else {
            // Benign Target Process
            match action {
                SkyAction::Allow => {
                    let r = 0.8 - step_cost;
                    (
                        r,
                        format!(
                            "<thought>Step {}: Benign target PID {} correctly identified and allowed normal execution. Zero operational disruption. Reward: {:.2}.</thought><action>Allow</action>",
                            self.current_step + 1, self.target_process.pid, r
                        ),
                        "Legitimate workload verified and allowed normal execution.".to_string(),
                    )
                }
                _ => (
                    -1.0,
                    format!(
                        "<thought>Step {}: False positive containment error! Benign process PID {} subjected to unjustified {:?}. Penalty: -1.0.</thought><action>{:?}</action>",
                        self.current_step + 1, self.target_process.pid, action, action
                    ),
                    format!("False containment penalty: Benign workload disrupted by {:?}.", action),
                ),
            }
        };

        self.current_step += 1;
        self.history.push((action, reward));

        StepResult {
            observation: self.observation.clone(),
            reward,
            done,
            thought_trace,
            explanation,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gym_safety_guardrail_invariant() {
        // NT Kernel & System process (PID 4) must NEVER be terminated or mutated
        let kernel_ctx = ProcessContext {
            pid: 4,
            ppid: 0,
            binary_path: "ntoskrnl.exe".into(),
            command_line: "".into(),
            is_kernel_thread: true,
            username: "SYSTEM".into(),
        };

        let mut gym = OshoosiSecurityGym::new(kernel_ctx, false);
        let result = gym.step(SkyAction::Terminate);

        assert_eq!(result.reward, -100.0);
        assert!(result.done);
        assert!(result.thought_trace.contains("Invariant violation"));
    }

    #[test]
    fn test_gym_multi_turn_investigation_and_containment() {
        let malicious_ctx = ProcessContext {
            pid: 7812,
            ppid: 3400,
            binary_path: r"C:\Windows\Temp\payload.exe".into(),
            command_line: "payload.exe --beacon 185.220.101.5".into(),
            is_kernel_thread: false,
            username: "Administrator".into(),
        };

        let mut gym = OshoosiSecurityGym::new(malicious_ctx, true);

        // Turn 1: Query process tree (-0.05 step cost)
        let r1 = gym.step(SkyAction::QueryProcessTree);
        assert_eq!(r1.reward, -0.05);
        assert!(!r1.done);

        // Turn 2: Query network sockets (-0.05 step cost)
        let r2 = gym.step(SkyAction::QueryNetworkConnections);
        assert_eq!(r2.reward, -0.05);
        assert!(!r2.done);

        // Turn 3: Terminate malicious process (1.0 - 0.05 * 2 = 0.90)
        let r3 = gym.step(SkyAction::Terminate);
        assert_eq!(r3.reward, 0.90);
        assert!(r3.done);

        // Cumulative reward must remain distinctly positive (+0.80)
        let total_reward: f32 = gym.history.iter().map(|(_, r)| *r).sum();
        assert!(
            total_reward > 0.0,
            "Multi-turn investigation should yield positive cumulative reward: {}",
            total_reward
        );
        assert!((total_reward - 0.80).abs() < 1e-4);
    }

    #[test]
    fn test_gym_false_positive_benign_allow() {
        let benign_ctx = ProcessContext {
            pid: 4120,
            ppid: 800,
            binary_path: r"C:\Program Files\Notepad++\notepad++.exe".into(),
            command_line: "notepad++.exe notes.txt".into(),
            is_kernel_thread: false,
            username: "user".into(),
        };

        let mut gym = OshoosiSecurityGym::new(benign_ctx, false);
        let result = gym.step(SkyAction::Allow);

        assert_eq!(result.reward, 0.8);
        assert!(result.done);
        assert!(result.thought_trace.contains("<action>Allow</action>"));
    }
}
