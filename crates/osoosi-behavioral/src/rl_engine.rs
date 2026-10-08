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
use std::collections::{HashSet, VecDeque};
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

/// Scope of autonomous EDR mitigation actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ActionScope {
    Process,
    Thread,
    NetworkSocket,
    Host,
}

/// Friction/impact tier of autonomous EDR mitigation actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ActionTier {
    PassiveObserve,
    LowFrictionTriage,
    HighFrictionContainment,
    HardMitigation,
}

/// System-level mitigation technique used to enforce the action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MitigationTechnique {
    WfpFilter,
    JobObjectLimit,
    ThreadSuspend,
    ProcessTerminate,
}

/// Rollback mechanism for reversible containment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RollbackStrategy {
    None,
    SnapshotRevert,
    RegistryRollback,
}

/// Telemetry depth dispatched for verification and forensic capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TelemetryLevel {
    Standard,
    VerboseEtw,
    MemoryDump,
}

/// Structured 5-Tuple Action Representation for autonomous EDR RL controller.
/// Dissects mitigation along orthogonal operational dimensions:
/// (scope, tier, technique, rollback, telemetry_level).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StructuredEdrAction {
    pub scope: ActionScope,
    pub tier: ActionTier,
    pub technique: MitigationTechnique,
    pub rollback: RollbackStrategy,
    pub telemetry_level: TelemetryLevel,
}

impl StructuredEdrAction {
    pub fn new(
        scope: ActionScope,
        tier: ActionTier,
        technique: MitigationTechnique,
        rollback: RollbackStrategy,
        telemetry_level: TelemetryLevel,
    ) -> Self {
        Self {
            scope,
            tier,
            technique,
            rollback,
            telemetry_level,
        }
    }

    pub fn from_edr_action(action: EdrAction) -> Self {
        match action {
            EdrAction::PassiveObserve => Self {
                scope: ActionScope::Process,
                tier: ActionTier::PassiveObserve,
                technique: MitigationTechnique::JobObjectLimit,
                rollback: RollbackStrategy::None,
                telemetry_level: TelemetryLevel::Standard,
            },
            EdrAction::TraceElevation => Self {
                scope: ActionScope::Process,
                tier: ActionTier::LowFrictionTriage,
                technique: MitigationTechnique::JobObjectLimit,
                rollback: RollbackStrategy::None,
                telemetry_level: TelemetryLevel::VerboseEtw,
            },
            EdrAction::MemoryIntrospection => Self {
                scope: ActionScope::Thread,
                tier: ActionTier::LowFrictionTriage,
                technique: MitigationTechnique::ThreadSuspend,
                rollback: RollbackStrategy::None,
                telemetry_level: TelemetryLevel::MemoryDump,
            },
            EdrAction::MicroContainment => Self {
                scope: ActionScope::NetworkSocket,
                tier: ActionTier::HighFrictionContainment,
                technique: MitigationTechnique::WfpFilter,
                rollback: RollbackStrategy::RegistryRollback,
                telemetry_level: TelemetryLevel::VerboseEtw,
            },
            EdrAction::HardMitigation => Self {
                scope: ActionScope::Host,
                tier: ActionTier::HardMitigation,
                technique: MitigationTechnique::ProcessTerminate,
                rollback: RollbackStrategy::SnapshotRevert,
                telemetry_level: TelemetryLevel::MemoryDump,
            },
        }
    }

    pub fn to_edr_action(&self) -> EdrAction {
        match self.tier {
            ActionTier::PassiveObserve => EdrAction::PassiveObserve,
            ActionTier::LowFrictionTriage => {
                if self.telemetry_level == TelemetryLevel::MemoryDump
                    || self.technique == MitigationTechnique::ThreadSuspend
                {
                    EdrAction::MemoryIntrospection
                } else {
                    EdrAction::TraceElevation
                }
            }
            ActionTier::HighFrictionContainment => EdrAction::MicroContainment,
            ActionTier::HardMitigation => EdrAction::HardMitigation,
        }
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

    pub const UNIFIED_STATE_DIM: usize = 32;

    pub fn build_unified_state_vector(
        &self,
        lineage: &ProcessLineageVector,
        velocity: &TelemetryVelocity,
        priors: &HeuristicPriorScores,
        mesh: &MeshContext,
        mitre: &IncidentMitreContext,
    ) -> [f32; Self::UNIFIED_STATE_DIM] {
        let base = self.build_state_vector(lineage, velocity, priors, mesh);
        let mut unified = [0.0f32; Self::UNIFIED_STATE_DIM];
        unified[..24].copy_from_slice(&base);
        unified[24] = mitre.lateral_score.clamp(0.0, 1.0);
        unified[25] = mitre.cred_dump_score.clamp(0.0, 1.0);
        unified[26] = mitre.persistence_score.clamp(0.0, 1.0);
        unified[27] = mitre.defense_evasion_score.clamp(0.0, 1.0);
        unified[28] = mitre.unsigned_binary_flag.clamp(0.0, 1.0);
        unified[29] = mitre.temp_execution_flag.clamp(0.0, 1.0);
        unified[30] = mitre.container_flag.clamp(0.0, 1.0);
        unified[31] = mitre.overall_threat_score.clamp(0.0, 1.0);
        unified
    }

    pub fn to_unified_vec(
        &self,
        lineage: &ProcessLineageVector,
        velocity: &TelemetryVelocity,
        priors: &HeuristicPriorScores,
        mesh: &MeshContext,
        mitre: &IncidentMitreContext,
    ) -> Vec<f32> {
        self.build_unified_state_vector(lineage, velocity, priors, mesh, mitre)
            .to_vec()
    }
}

/// Incident and MITRE ATT&CK Behavioral Context (features 24..31).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentMitreContext {
    pub lateral_score: f32,
    pub cred_dump_score: f32,
    pub persistence_score: f32,
    pub defense_evasion_score: f32,
    pub unsigned_binary_flag: f32, // 0.0 or 1.0
    pub temp_execution_flag: f32,  // 0.0 or 1.0
    pub container_flag: f32,       // 0.0 or 1.0
    pub overall_threat_score: f32, // [0.0, 1.0]
}

impl Default for IncidentMitreContext {
    fn default() -> Self {
        Self {
            lateral_score: 0.0,
            cred_dump_score: 0.0,
            persistence_score: 0.0,
            defense_evasion_score: 0.0,
            unsigned_binary_flag: 0.0,
            temp_execution_flag: 0.0,
            container_flag: 0.0,
            overall_threat_score: 0.0,
        }
    }
}

/// Unified 32-Dimensional Continuous State Observation Vector ($S_t$).
/// Aggregates:
/// - Process Lineage (0..5)
/// - Telemetry Velocity (6..11)
/// - Detection Priors (12..17)
/// - Wire Mesh & Consensus (18..23)
/// - Incident & MITRE Context (24..31)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UnifiedEdrState {
    pub lineage: ProcessLineageVector,
    pub velocity: TelemetryVelocity,
    pub priors: HeuristicPriorScores,
    pub mesh: MeshContext,
    pub mitre: IncidentMitreContext,
}

impl UnifiedEdrState {
    pub const DIM: usize = 32;

    pub fn to_vector(&self) -> [f32; Self::DIM] {
        [
            // Lineage (0..5)
            self.lineage.tree_depth.clamp(0.0, 1.0),
            self.lineage.parent_child_entropy.clamp(0.0, 1.0),
            self.lineage.token_elevation_level.clamp(0.0, 1.0),
            self.lineage.is_kernel_thread.clamp(0.0, 1.0),
            self.lineage.parent_anomaly_score.clamp(0.0, 1.0),
            self.lineage.elevation_jump.clamp(0.0, 1.0),
            // Velocity (6..11)
            self.velocity.file_modification_rate.clamp(0.0, 1.0),
            self.velocity.outbound_net_velocity.clamp(0.0, 1.0),
            self.velocity.page_permission_trans_rate.clamp(0.0, 1.0),
            self.velocity.thread_creation_burst_rate.clamp(0.0, 1.0),
            self.velocity.handle_count_velocity.clamp(0.0, 1.0),
            self.velocity.cpu_usage_burst.clamp(0.0, 1.0),
            // Priors (12..17)
            self.priors.static_pe_magika_score.clamp(0.0, 1.0),
            self.priors.cmdline_token_score.clamp(0.0, 1.0),
            self.priors.fastpath_yara_sigma_score.clamp(0.0, 1.0),
            self.priors.capa_floss_capability.clamp(0.0, 1.0),
            self.priors.behavioral_sequence_score.clamp(0.0, 1.0),
            self.priors.anomaly_detector_score.clamp(0.0, 1.0),
            // Wire Mesh & Consensus (18..23)
            self.mesh.peer_anomaly_score.clamp(0.0, 1.0),
            self.mesh.cluster_prevalence.clamp(0.0, 1.0),
            self.mesh.consensus_confidence.clamp(0.0, 1.0),
            self.mesh.cluster_alert_rate.clamp(0.0, 1.0),
            self.mesh.peer_threat_level.clamp(0.0, 1.0),
            self.mesh.quarantine_vote_ratio.clamp(0.0, 1.0),
            // Incident & MITRE Context (24..31)
            self.mitre.lateral_score.clamp(0.0, 1.0),
            self.mitre.cred_dump_score.clamp(0.0, 1.0),
            self.mitre.persistence_score.clamp(0.0, 1.0),
            self.mitre.defense_evasion_score.clamp(0.0, 1.0),
            self.mitre.unsigned_binary_flag.clamp(0.0, 1.0),
            self.mitre.temp_execution_flag.clamp(0.0, 1.0),
            self.mitre.container_flag.clamp(0.0, 1.0),
            self.mitre.overall_threat_score.clamp(0.0, 1.0),
        ]
    }

    pub fn to_vec(&self) -> Vec<f32> {
        self.to_vector().to_vec()
    }
}

/// Multi-signal inputs for multi-objective reward calculation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiObjectiveSignals {
    pub s_acc: f32,
    pub s_disrupt: f32,
    pub s_dwell: f32,
    pub s_cost: f32,
    pub s_consensus: f32,
    pub s_violation: f32,
}

/// Weights for multi-objective reward function:
/// $R = w_{acc} S_{acc} - w_{disrupt} S_{disrupt} + w_{dwell} S_{dwell} - w_{cost} S_{cost} + w_{consensus} S_{consensus} - w_{invar} S_{violation}$
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiObjectiveWeights {
    pub w_acc: f32,
    pub w_disrupt: f32,
    pub w_dwell: f32,
    pub w_cost: f32,
    pub w_consensus: f32,
    pub w_invar: f32,
}

impl Default for MultiObjectiveWeights {
    fn default() -> Self {
        Self {
            w_acc: 100.0,
            w_disrupt: 150.0,
            w_dwell: 10.0,
            w_cost: 5.0,
            w_consensus: 20.0,
            w_invar: 500.0,
        }
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
    #[serde(default)]
    pub multi_weights: MultiObjectiveWeights,
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
            multi_weights: MultiObjectiveWeights::default(),
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
                    if is_critical_target {
                        return -500.0;
                    }
                    r_disruption = self.fp_disruption_penalty;
                }
                EdrAction::MicroContainment => {
                    if is_critical_target {
                        return -500.0;
                    }
                    r_disruption = self.fp_micro_penalty;
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

    /// Enhanced Multi-Objective Reward:
    /// R = w_acc * S_acc - w_disrupt * S_disrupt + w_dwell * S_dwell - w_cost * S_cost + w_consensus * S_consensus - w_invar * S_violation
    /// Guardrail: Zero-tolerance penalty (-500.0) if invariant is violated.
    pub fn calculate_multi_objective_reward(&self, signals: &MultiObjectiveSignals) -> f32 {
        let r = self.multi_weights.w_acc * signals.s_acc
            - self.multi_weights.w_disrupt * signals.s_disrupt
            + self.multi_weights.w_dwell * signals.s_dwell
            - self.multi_weights.w_cost * signals.s_cost
            + self.multi_weights.w_consensus * signals.s_consensus
            - self.multi_weights.w_invar * signals.s_violation;

        if signals.s_violation > 0.0 {
            r.min(-500.0)
        } else {
            r
        }
    }

    /// Evaluates reward against unmitigated baseline threat severity to prevent the Counterfactual Zero-Gain Bug.
    /// Delta_security = max(0.0, S_unmitigated - S_mitigated(a))
    pub fn calculate_counterfactual_reward(
        &self,
        action: EdrAction,
        unmitigated_threat: f32,
        is_malicious: bool,
        is_protected_target: bool,
        consensus_score: f32,
    ) -> f32 {
        let s_violation = if is_protected_target && action.is_containment() {
            1.0
        } else {
            0.0
        };

        let s_mitigated = match action {
            EdrAction::HardMitigation => 0.0,
            EdrAction::MicroContainment => 0.2 * unmitigated_threat,
            EdrAction::MemoryIntrospection => 0.6 * unmitigated_threat,
            EdrAction::TraceElevation => 0.75 * unmitigated_threat,
            EdrAction::PassiveObserve => unmitigated_threat,
        };

        let delta_security = (unmitigated_threat - s_mitigated).max(0.0);

        let s_acc = if is_malicious { delta_security } else { 0.0 };
        let s_disrupt = if !is_malicious {
            match action {
                EdrAction::HardMitigation => 1.0,
                EdrAction::MicroContainment => 0.5,
                _ => 0.0,
            }
        } else {
            0.0
        };

        let s_dwell = if is_malicious && action.is_containment() { 1.0 } else { 0.0 };
        let s_cost = match action {
            EdrAction::MemoryIntrospection => 0.2,
            EdrAction::TraceElevation => 0.1,
            _ => 0.0,
        };

        let signals = MultiObjectiveSignals {
            s_acc,
            s_disrupt,
            s_dwell,
            s_cost,
            s_consensus: consensus_score,
            s_violation,
        };

        self.calculate_multi_objective_reward(&signals)
    }

    /// Evaluates candidate action against safety guardrails:
    /// Returns (executed_action, policy_reward) with hard -500.0 penalty and safe degradation.
    pub fn evaluate_candidate_action(
        &self,
        safety: &SafetyFilter,
        target_pid: u32,
        target_name: &str,
        candidate_action: EdrAction,
        is_malicious: bool,
        unmitigated_threat: f32,
        consensus_score: f32,
    ) -> (EdrAction, f32) {
        let is_protected = safety.is_protected(target_pid, target_name);
        let executed_action = safety.filter_action(target_pid, target_name, candidate_action);
        let reward = self.calculate_counterfactual_reward(
            candidate_action,
            unmitigated_threat,
            is_malicious,
            is_protected,
            consensus_score,
        );
        (executed_action, reward)
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

/// Execution regimes for RL controllers (Pillar 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RlExecutionMode {
    /// Policy trains online from scratch.
    ColdRl,
    /// Policy initialized with expert heuristic priors.
    WarmPriorRl,
    /// Strictly read-only evaluation mode: weights and covariance matrices locked.
    FrozenTest,
}

impl Default for RlExecutionMode {
    fn default() -> Self {
        Self::ColdRl
    }
}

fn default_version() -> usize {
    1
}

/// Double Deep Q-Network (Double DQN) with Target Network ($\theta^-$) & Conservative Q-Learning (CQL).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoubleDeepQEngine {
    #[serde(default = "default_version")]
    pub version: usize,
    pub state_dim: usize,
    pub action_dim: usize,
    pub online_net: DeepQEngine,
    pub target_net: DeepQEngine,
    pub cql_alpha: f32,
    #[serde(default)]
    pub execution_mode: RlExecutionMode,
    #[serde(default)]
    pub step_count: usize,
}

impl DoubleDeepQEngine {
    pub fn new(state_dim: usize, action_dim: usize) -> Self {
        let online_net = DeepQEngine::new(state_dim, action_dim);
        let mut target_net = DeepQEngine::new(state_dim, action_dim);
        target_net.load_flat_weights(&online_net.get_flat_weights());
        Self {
            version: 1,
            state_dim,
            action_dim,
            online_net,
            target_net,
            cql_alpha: 1.0,
            execution_mode: RlExecutionMode::ColdRl,
            step_count: 0,
        }
    }

    /// Initializes DoubleDeepQEngine with domain expert heuristic priors (Pillar 4 WarmPriorRl).
    pub fn with_warm_priors(state_dim: usize, action_dim: usize) -> Self {
        let mut engine = Self::new(state_dim, action_dim);
        engine.execution_mode = RlExecutionMode::WarmPriorRl;
        engine.initialize_heuristic_priors();
        engine
    }

    /// Injects domain expert heuristic priors into output layer biases:
    /// Action 0 (PassiveObserve): +1.0 base bias
    /// Action 1 (TraceElevation): +0.5 base bias
    /// Action 2 (MemoryIntrospection): +0.2 base bias
    /// Action 3 (MicroContainment): -0.5 base bias
    /// Action 4 (HardMitigation): -1.0 base bias
    pub fn initialize_heuristic_priors(&mut self) {
        let biases = [1.0f32, 0.5, 0.2, -0.5, -1.0];
        for (i, &b) in biases.iter().enumerate().take(self.action_dim) {
            if i < self.online_net.fc_out.biases.len() {
                self.online_net.fc_out.biases[i] = b;
            }
        }
        self.target_net.load_flat_weights(&self.online_net.get_flat_weights());
    }

    /// Validates internal neural network dimension consistency against declared state/action dimensions.
    pub fn validate(&self) -> Result<(), String> {
        if self.version == 0 {
            return Err("Invalid version 0".into());
        }
        if self.state_dim == 0 || self.action_dim == 0 {
            return Err("state_dim and action_dim must be non-zero".into());
        }
        if self.online_net.state_dim != self.state_dim || self.online_net.action_dim != self.action_dim {
            return Err("online_net dimensions mismatch".into());
        }
        if self.target_net.state_dim != self.state_dim || self.target_net.action_dim != self.action_dim {
            return Err("target_net dimensions mismatch".into());
        }
        Ok(())
    }

    pub fn to_json_string(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    pub fn from_json_string(s: &str) -> Result<Self, serde_json::Error> {
        let engine: Self = serde_json::from_str(s)?;
        if let Err(msg) = engine.validate() {
            return Err(serde::de::Error::custom(msg));
        }
        Ok(engine)
    }

    pub fn save_to_json(&self, path: impl AsRef<std::path::Path>) -> Result<(), std::io::Error> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        std::fs::write(path, json)
    }

    pub fn load_from_json(path: impl AsRef<std::path::Path>) -> Result<Self, std::io::Error> {
        let contents = std::fs::read_to_string(path)?;
        let engine: Self = serde_json::from_str(&contents)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        engine.validate()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(engine)
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
        if self.execution_mode == RlExecutionMode::FrozenTest {
            return;
        }
        let online_w = self.online_net.get_flat_weights();
        let mut target_w = self.target_net.get_flat_weights();
        for (t, o) in target_w.iter_mut().zip(online_w.iter()) {
            *t = tau * o + (1.0 - tau) * *t;
        }
        self.target_net.load_flat_weights(&target_w);
    }

    /// Strict Contextual Episode Boundary: alert triage operates with zero temporal credit leakage ($\gamma = 0.0$).
    pub const CONTEXTUAL_BANDIT_GAMMA: f32 = 0.0;

    /// Single-event contextual alert triage training step with strict gamma = 0.0.
    pub fn train_step_contextual_bandit(
        &mut self,
        batch: &[Transition],
        lr: f32,
        is_weights: Option<&[f32]>,
    ) -> (f32, Vec<f32>) {
        self.train_step_cql(batch, Self::CONTEXTUAL_BANDIT_GAMMA, lr, is_weights)
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
        if self.execution_mode == RlExecutionMode::FrozenTest {
            return (0.0, vec![0.0; batch.len()]);
        }
        if batch.is_empty() {
            return (0.0, Vec::new());
        }

        self.step_count += 1;
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

/// Risk sensitivity profiles for action evaluation (Conditional Value-at-Risk / CVaR).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum RiskProfile {
    RiskNeutral,
    RiskAverse { alpha: f32 },
    RiskSeeking { alpha: f32 },
}

impl Default for RiskProfile {
    fn default() -> Self {
        Self::RiskNeutral
    }
}

impl RiskProfile {
    pub fn evaluate_distribution(&self, quantiles: &[f32]) -> f32 {
        if quantiles.is_empty() {
            return 0.0;
        }
        match self {
            Self::RiskNeutral => {
                quantiles.iter().sum::<f32>() / (quantiles.len() as f32)
            }
            Self::RiskAverse { alpha } => {
                let mut sorted = quantiles.to_vec();
                sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
                let alpha_clamped = alpha.clamp(0.0, 1.0);
                let k = (((alpha_clamped * (sorted.len() as f32)).floor() as usize).max(1)).min(sorted.len());
                sorted[..k].iter().sum::<f32>() / (k as f32)
            }
            Self::RiskSeeking { alpha } => {
                let mut sorted = quantiles.to_vec();
                sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
                let alpha_clamped = alpha.clamp(0.0, 1.0);
                let k = (((alpha_clamped * (sorted.len() as f32)).floor() as usize).max(1)).min(sorted.len());
                let start = sorted.len() - k;
                sorted[start..].iter().sum::<f32>() / (k as f32)
            }
        }
    }
}

/// Dueling Quantile Network Architecture (Wang et al. 2016 / Dopamine Rainbow/QR-DQN).
/// Decouples value stream $V(s) \in \mathbb{R}^N$ and advantage stream $A(s, a) \in \mathbb{R}^{K \times N}$
/// with identifiability constraint: $\theta_i(s, a) = V_i(s) + (A_i(s, a) - \frac{1}{|A|}\sum_{a'} A_i(s, a'))$.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuelingQuantileNetwork {
    pub state_dim: usize,
    pub action_dim: usize,
    pub num_quantiles: usize,
    pub fc1: DenseLayer,
    pub fc2: DenseLayer,
    pub fc_val: DenseLayer,
    pub fc_adv: DenseLayer,
}

impl DuelingQuantileNetwork {
    pub fn new(state_dim: usize, action_dim: usize, num_quantiles: usize) -> Self {
        Self {
            state_dim,
            action_dim,
            num_quantiles,
            fc1: DenseLayer::new(state_dim, 128),
            fc2: DenseLayer::new(128, 128),
            fc_val: DenseLayer::new(128, num_quantiles),
            fc_adv: DenseLayer::new(128, action_dim * num_quantiles),
        }
    }

    pub fn forward_quantiles(&self, state: &[f32]) -> Vec<Vec<f32>> {
        let h1 = self.fc1.forward(state, true);
        let h2 = self.fc2.forward(&h1, true);
        let v = self.fc_val.forward(&h2, false);
        let adv_flat = self.fc_adv.forward(&h2, false);

        let mut mean_adv = vec![0.0f32; self.num_quantiles];
        let num_actions = self.action_dim;

        for a in 0..num_actions {
            let offset = a * self.num_quantiles;
            for i in 0..self.num_quantiles {
                mean_adv[i] += adv_flat[offset + i];
            }
        }
        for i in 0..self.num_quantiles {
            mean_adv[i] /= num_actions as f32;
        }

        let mut theta = vec![vec![0.0f32; self.num_quantiles]; num_actions];
        for a in 0..num_actions {
            let offset = a * self.num_quantiles;
            for i in 0..self.num_quantiles {
                theta[a][i] = v[i] + adv_flat[offset + i] - mean_adv[i];
            }
        }

        theta
    }

    pub fn backward_quantiles(
        &mut self,
        state: &[f32],
        grad_quantiles: &[Vec<f32>],
        lr: f32,
    ) {
        let h1 = self.fc1.forward(state, true);
        let h2 = self.fc2.forward(&h1, true);

        let mut grad_v = vec![0.0f32; self.num_quantiles];
        let mut grad_adv_flat = vec![0.0f32; self.action_dim * self.num_quantiles];

        let mut sum_grad_quantile = vec![0.0f32; self.num_quantiles];
        for a in 0..self.action_dim {
            if a < grad_quantiles.len() {
                for i in 0..self.num_quantiles {
                    if i < grad_quantiles[a].len() {
                        sum_grad_quantile[i] += grad_quantiles[a][i];
                    }
                }
            }
        }

        for i in 0..self.num_quantiles {
            grad_v[i] = sum_grad_quantile[i];
        }

        let inv_a = 1.0 / (self.action_dim as f32);
        for a in 0..self.action_dim {
            let offset = a * self.num_quantiles;
            for i in 0..self.num_quantiles {
                let g = if a < grad_quantiles.len() && i < grad_quantiles[a].len() {
                    grad_quantiles[a][i]
                } else {
                    0.0
                };
                grad_adv_flat[offset + i] = g - inv_a * sum_grad_quantile[i];
            }
        }

        let grad_h2_val = self.fc_val.backward(&h2, &grad_v, lr);
        let grad_h2_adv = self.fc_adv.backward(&h2, &grad_adv_flat, lr);

        let mut grad_z2 = vec![0.0f32; h2.len()];
        for k in 0..h2.len() {
            let g = grad_h2_val.get(k).copied().unwrap_or(0.0)
                + grad_h2_adv.get(k).copied().unwrap_or(0.0);
            grad_z2[k] = if h2.get(k).copied().unwrap_or(0.0) > 0.0 {
                g
            } else {
                0.0
            };
        }

        let grad_h1 = self.fc2.backward(&h1, &grad_z2, lr);
        let mut grad_z1 = vec![0.0f32; h1.len()];
        for k in 0..h1.len() {
            let g = grad_h1.get(k).copied().unwrap_or(0.0);
            grad_z1[k] = if h1.get(k).copied().unwrap_or(0.0) > 0.0 {
                g
            } else {
                0.0
            };
        }

        let _ = self.fc1.backward(state, &grad_z1, lr);
    }

    pub fn flatten_parameters(&self) -> Vec<f32> {
        let mut params = Vec::new();
        params.extend(self.fc1.flatten_parameters());
        params.extend(self.fc2.flatten_parameters());
        params.extend(self.fc_val.flatten_parameters());
        params.extend(self.fc_adv.flatten_parameters());
        params
    }

    pub fn load_parameters(&mut self, flat: &[f32]) {
        let mut offset = 0;
        offset += self.fc1.load_parameters(&flat[offset..]);
        offset += self.fc2.load_parameters(&flat[offset..]);
        offset += self.fc_val.load_parameters(&flat[offset..]);
        let _ = self.fc_adv.load_parameters(&flat[offset..]);
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.state_dim == 0 || self.action_dim == 0 || self.num_quantiles == 0 {
            return Err("dimensions must be non-zero".into());
        }
        if self.fc1.weights.len() != self.state_dim || self.fc1.biases.len() != 128 {
            return Err("fc1 dimension mismatch".into());
        }
        if self.fc2.weights.len() != 128 || self.fc2.biases.len() != 128 {
            return Err("fc2 dimension mismatch".into());
        }
        if self.fc_val.weights.len() != 128 || self.fc_val.biases.len() != self.num_quantiles {
            return Err("fc_val dimension mismatch".into());
        }
        if self.fc_adv.weights.len() != 128 || self.fc_adv.biases.len() != self.action_dim * self.num_quantiles {
            return Err("fc_adv dimension mismatch".into());
        }
        Ok(())
    }
}

/// Quantile Regression Deep Q-Network (QR-DQN, Dabney et al. 2018 / Google Dopamine).
/// Models the full return distribution via $N=32$ quantile locations $\theta_i(s, a)$
/// minimizing Quantile Huber Loss with Double DQN target projection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantileRegressionDqnEngine {
    #[serde(default = "default_version")]
    pub version: usize,
    pub state_dim: usize,
    pub action_dim: usize,
    pub num_quantiles: usize,
    pub online_net: DuelingQuantileNetwork,
    pub target_net: DuelingQuantileNetwork,
    pub kappa: f32,
    pub tau: Vec<f32>,
    #[serde(default)]
    pub execution_mode: RlExecutionMode,
    #[serde(default)]
    pub step_count: usize,
}

impl QuantileRegressionDqnEngine {
    pub fn new(state_dim: usize, action_dim: usize) -> Self {
        let num_quantiles = 32;
        let online_net = DuelingQuantileNetwork::new(state_dim, action_dim, num_quantiles);
        let mut target_net = DuelingQuantileNetwork::new(state_dim, action_dim, num_quantiles);
        target_net.load_parameters(&online_net.flatten_parameters());
        let tau: Vec<f32> = (0..num_quantiles)
            .map(|i| (i as f32 + 0.5) / (num_quantiles as f32))
            .collect();
        Self {
            version: 1,
            state_dim,
            action_dim,
            num_quantiles,
            online_net,
            target_net,
            kappa: 1.0,
            tau,
            execution_mode: RlExecutionMode::ColdRl,
            step_count: 0,
        }
    }

    pub fn with_warm_priors(state_dim: usize, action_dim: usize) -> Self {
        let mut engine = Self::new(state_dim, action_dim);
        engine.execution_mode = RlExecutionMode::WarmPriorRl;
        engine.initialize_heuristic_priors();
        engine
    }

    pub fn initialize_heuristic_priors(&mut self) {
        let biases = [1.0f32, 0.5, 0.2, -0.5, -1.0];
        for (a, &b) in biases.iter().enumerate().take(self.action_dim) {
            for q in 0..self.num_quantiles {
                let idx = a * self.num_quantiles + q;
                if idx < self.online_net.fc_adv.biases.len() {
                    self.online_net.fc_adv.biases[idx] = b;
                }
            }
        }
        self.target_net.load_parameters(&self.online_net.flatten_parameters());
    }

    pub fn forward_all_quantiles(&self, state: &[f32]) -> Vec<Vec<f32>> {
        self.online_net.forward_quantiles(state)
    }

    pub fn forward_q_values(&self, state: &[f32]) -> Vec<f32> {
        self.evaluate_risk_action_values(state, RiskProfile::RiskNeutral)
    }

    pub fn evaluate_risk_action_values(&self, state: &[f32], risk_profile: RiskProfile) -> Vec<f32> {
        let quantiles = self.online_net.forward_quantiles(state);
        quantiles
            .iter()
            .map(|dist| risk_profile.evaluate_distribution(dist))
            .collect()
    }

    pub fn select_guarded_action(
        &self,
        state: &[f32],
        mask: &[f32; 5],
        risk_profile: RiskProfile,
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

        let action_values = self.evaluate_risk_action_values(state, risk_profile);
        let mut best_action = 0;
        let mut max_val = f32::NEG_INFINITY;

        for i in 0..self.action_dim.min(5) {
            if mask[i] > 0.0 {
                let val = action_values.get(i).copied().unwrap_or(f32::NEG_INFINITY);
                if val > max_val {
                    max_val = val;
                    best_action = i;
                }
            }
        }

        EdrAction::from_index(best_action)
    }

    pub fn train_step_qr_dqn(&mut self, batch: &[Transition], gamma: f32, lr: f32) -> f32 {
        if self.execution_mode == RlExecutionMode::FrozenTest {
            return 0.0;
        }
        if batch.is_empty() {
            return 0.0;
        }

        self.step_count += 1;
        let mut total_loss = 0.0;
        let n_quantiles = self.num_quantiles;

        for transition in batch {
            // Double DQN target selection:
            // a* = argmax_a mean_i(online_net(s')[a][i])
            let next_online_quantiles = self.online_net.forward_quantiles(&transition.next_state);
            let mut best_a = 0;
            let mut best_mean = f32::NEG_INFINITY;
            for (a, dist) in next_online_quantiles.iter().enumerate() {
                let mean_val = if dist.is_empty() {
                    0.0
                } else {
                    dist.iter().sum::<f32>() / (dist.len() as f32)
                };
                if mean_val > best_mean {
                    best_mean = mean_val;
                    best_a = a;
                }
            }

            // Target quantiles from target network:
            // T theta_j = r + gamma * target_net(s')[a*][j] (if not done, else r)
            let next_target_quantiles = self.target_net.forward_quantiles(&transition.next_state);
            let mut target_quantiles = vec![transition.reward; n_quantiles];
            if !transition.done {
                if let Some(target_dist) = next_target_quantiles.get(best_a) {
                    for j in 0..n_quantiles {
                        let q_target = target_dist.get(j).copied().unwrap_or(0.0);
                        target_quantiles[j] = transition.reward + gamma * q_target;
                    }
                }
            }

            // Online prediction for (s, a)
            let current_quantiles = self.online_net.forward_quantiles(&transition.state);
            let action_idx = transition.get_action_index();
            let current_dist = current_quantiles
                .get(action_idx)
                .cloned()
                .unwrap_or_else(|| vec![0.0; n_quantiles]);

            let mut grad_theta = vec![vec![0.0f32; n_quantiles]; self.action_dim];
            let mut transition_loss = 0.0f32;

            for i in 0..n_quantiles {
                let theta_i = current_dist.get(i).copied().unwrap_or(0.0);
                let tau_i = self.tau.get(i).copied().unwrap_or((i as f32 + 0.5) / (n_quantiles as f32));

                let mut grad_i_sum = 0.0f32;
                for j in 0..n_quantiles {
                    let t_theta_j = target_quantiles[j];
                    let u = t_theta_j - theta_i;

                    let abs_u = u.abs();
                    let huber = if abs_u <= self.kappa {
                        0.5 * u * u
                    } else {
                        self.kappa * (abs_u - 0.5 * self.kappa)
                    };

                    let indicator = if u < 0.0 { 1.0 } else { 0.0 };
                    let weight = (tau_i - indicator).abs();
                    let loss_ij = weight * (huber / self.kappa);
                    transition_loss += loss_ij;

                    let huber_grad = ((theta_i - t_theta_j) / self.kappa).clamp(-1.0, 1.0);
                    grad_i_sum += weight * huber_grad;
                }

                if action_idx < self.action_dim {
                    grad_theta[action_idx][i] = grad_i_sum / (n_quantiles as f32);
                }
            }

            total_loss += transition_loss / ((n_quantiles * n_quantiles) as f32);

            self.online_net.backward_quantiles(&transition.state, &grad_theta, lr);
        }

        total_loss / (batch.len() as f32)
    }

    pub fn update_target_network(&mut self, polyak_tau: f32) {
        if self.execution_mode == RlExecutionMode::FrozenTest {
            return;
        }
        let online_w = self.online_net.flatten_parameters();
        let mut target_w = self.target_net.flatten_parameters();
        if polyak_tau >= 1.0 {
            target_w.copy_from_slice(&online_w);
        } else {
            for (t, o) in target_w.iter_mut().zip(online_w.iter()) {
                *t = (1.0 - polyak_tau) * *t + polyak_tau * o;
            }
        }
        self.target_net.load_parameters(&target_w);
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.version == 0 {
            return Err("Invalid version 0".into());
        }
        if self.state_dim == 0 || self.action_dim == 0 || self.num_quantiles == 0 {
            return Err("state_dim, action_dim, and num_quantiles must be non-zero".into());
        }
        if self.online_net.state_dim != self.state_dim
            || self.online_net.action_dim != self.action_dim
            || self.online_net.num_quantiles != self.num_quantiles
        {
            return Err("online_net dimensions mismatch".into());
        }
        if self.target_net.state_dim != self.state_dim
            || self.target_net.action_dim != self.action_dim
            || self.target_net.num_quantiles != self.num_quantiles
        {
            return Err("target_net dimensions mismatch".into());
        }
        if self.tau.len() != self.num_quantiles {
            return Err("tau length does not match num_quantiles".into());
        }
        self.online_net.validate()?;
        self.target_net.validate()?;
        Ok(())
    }

    pub fn to_json_string(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    pub fn from_json_string(s: &str) -> Result<Self, serde_json::Error> {
        let engine: Self = serde_json::from_str(s)?;
        if let Err(msg) = engine.validate() {
            return Err(serde::de::Error::custom(msg));
        }
        Ok(engine)
    }

    pub fn save_to_json(&self, path: impl AsRef<std::path::Path>) -> Result<(), std::io::Error> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        std::fs::write(path, json)
    }

    pub fn load_from_json(path: impl AsRef<std::path::Path>) -> Result<Self, std::io::Error> {
        let contents = std::fs::read_to_string(path)?;
        let engine: Self = serde_json::from_str(&contents)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        engine.validate()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(engine)
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

fn default_alpha_0() -> f64 {
    1.0
}

fn default_alpha_decay() -> f64 {
    0.005
}

fn default_min_alpha() -> f64 {
    0.05
}

/// Contextual Bandit Engine (LinUCB with Disjoint Linear Models & Exploration Annealing).
/// For single-step dynamic alert throttling & priority scoring:
/// Action 0: AutoResolve, Action 1: QueueTriage, Action 2: PageAnalyst.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinUcbBandit {
    #[serde(default = "default_version")]
    pub version: usize,
    pub num_actions: usize,
    pub context_dim: usize,
    pub a_matrices: Vec<Vec<Vec<f32>>>, // [action][d][d]
    pub b_vectors: Vec<Vec<f32>>,       // [action][d]
    #[serde(default)]
    pub a_inv_matrices: Vec<Vec<Vec<f64>>>, // [action][d][d] Sherman-Morrison streaming inverse
    #[serde(default = "default_alpha_0")]
    pub alpha: f64,
    #[serde(default = "default_alpha_0")]
    pub alpha_0: f64,
    #[serde(default = "default_alpha_decay")]
    pub alpha_decay: f64,
    #[serde(default = "default_min_alpha")]
    pub min_alpha: f64,
    #[serde(default)]
    pub step_count: usize,
    #[serde(default)]
    pub execution_mode: RlExecutionMode,
}

impl LinUcbBandit {
    /// Strict Contextual Episode Boundary: alert triage operates with zero temporal credit leakage ($\gamma = 0.0$).
    pub const BANDIT_GAMMA: f32 = 0.0;

    pub fn gamma(&self) -> f32 {
        Self::BANDIT_GAMMA
    }

    pub fn new(num_actions: usize, context_dim: usize) -> Self {
        Self::with_exploration(num_actions, context_dim, 1.0, 0.005, 0.05)
    }

    pub fn with_exploration(
        num_actions: usize,
        context_dim: usize,
        alpha_0: f64,
        alpha_decay: f64,
        min_alpha: f64,
    ) -> Self {
        let mut a_matrices = Vec::with_capacity(num_actions);
        let mut b_vectors = Vec::with_capacity(num_actions);
        let mut a_inv_matrices = Vec::with_capacity(num_actions);

        for _ in 0..num_actions {
            let mut a = vec![vec![0.0f32; context_dim]; context_dim];
            let mut a_inv = vec![vec![0.0f64; context_dim]; context_dim];
            for i in 0..context_dim {
                a[i][i] = 1.0; // Ridge regularizer I_d
                a_inv[i][i] = 1.0;
            }
            a_matrices.push(a);
            b_vectors.push(vec![0.0f32; context_dim]);
            a_inv_matrices.push(a_inv);
        }

        Self {
            version: 1,
            num_actions,
            context_dim,
            a_matrices,
            b_vectors,
            a_inv_matrices,
            alpha: alpha_0,
            alpha_0,
            alpha_decay,
            min_alpha,
            step_count: 0,
            execution_mode: RlExecutionMode::ColdRl,
        }
    }

    /// Initializes LinUcbBandit with domain expert heuristic priors (Pillar 4 WarmPriorRl).
    pub fn with_warm_priors(num_actions: usize, context_dim: usize) -> Self {
        let mut bandit = Self::new(num_actions, context_dim);
        bandit.execution_mode = RlExecutionMode::WarmPriorRl;
        bandit.initialize_heuristic_priors();
        bandit
    }

    /// Injects domain expert heuristic priors into response vectors b_vectors:
    /// Action 0 (AutoResolve): favors low threat / high benign score
    /// Action 1 (QueueTriage): favors intermediate / ambiguous alerts
    /// Action 2 (PageAnalyst): favors high threat score
    pub fn initialize_heuristic_priors(&mut self) {
        if self.context_dim >= 4 {
            if self.num_actions > 0 {
                // Action 0: AutoResolve: [bias=1.0, threat=-5.0, benign=+5.0, ambiguity=0.0]
                self.b_vectors[0][0] = 1.0;
                self.b_vectors[0][1] = -5.0;
                self.b_vectors[0][2] = 5.0;
            }
            if self.num_actions > 1 {
                // Action 1: QueueTriage: [bias=0.5, threat=1.0, benign=0.0, ambiguity=+4.0]
                self.b_vectors[1][0] = 0.5;
                self.b_vectors[1][1] = 1.0;
                self.b_vectors[1][3] = 4.0;
            }
            if self.num_actions > 2 {
                // Action 2: PageAnalyst: [bias=-1.0, threat=+8.0, benign=-5.0, ambiguity=0.0]
                self.b_vectors[2][0] = -1.0;
                self.b_vectors[2][1] = 8.0;
                self.b_vectors[2][2] = -5.0;
            }
        } else if self.context_dim > 0 {
            for a in 0..self.num_actions {
                let bias_val = match a {
                    0 => 1.0,
                    1 => 0.5,
                    _ => -0.5,
                };
                self.b_vectors[a][0] = bias_val;
            }
        }
    }

    /// Validates matrix dimensions and version consistency for safe deserialization.
    pub fn validate(&self) -> Result<(), String> {
        if self.version == 0 {
            return Err("Invalid version 0".into());
        }
        if self.num_actions == 0 || self.context_dim == 0 {
            return Err("num_actions and context_dim must be non-zero".into());
        }
        if self.a_matrices.len() != self.num_actions {
            return Err(format!(
                "a_matrices length {} != num_actions {}",
                self.a_matrices.len(),
                self.num_actions
            ));
        }
        for (a, m) in self.a_matrices.iter().enumerate() {
            if m.len() != self.context_dim {
                return Err(format!("a_matrices[{}] row count != context_dim", a));
            }
            for (r, row) in m.iter().enumerate() {
                if row.len() != self.context_dim {
                    return Err(format!("a_matrices[{}][{}] col count != context_dim", a, r));
                }
            }
        }
        if self.b_vectors.len() != self.num_actions {
            return Err("b_vectors length != num_actions".into());
        }
        for (a, v) in self.b_vectors.iter().enumerate() {
            if v.len() != self.context_dim {
                return Err(format!("b_vectors[{}] length != context_dim", a));
            }
        }
        if self.a_inv_matrices.len() != self.num_actions {
            return Err("a_inv_matrices length != num_actions".into());
        }
        for (a, m) in self.a_inv_matrices.iter().enumerate() {
            if m.len() != self.context_dim {
                return Err(format!("a_inv_matrices[{}] row count != context_dim", a));
            }
            for (r, row) in m.iter().enumerate() {
                if row.len() != self.context_dim {
                    return Err(format!("a_inv_matrices[{}][{}] col count != context_dim", a, r));
                }
            }
        }
        Ok(())
    }

    /// Computes current annealed exploration parameter:
    /// $\alpha(t) = \max\left(\text{min\_alpha}, \frac{\alpha_0}{1.0 + \alpha_{\text{decay}} \cdot t}\right)$
    pub fn current_alpha(&self) -> f64 {
        let decayed = self.alpha_0 / (1.0 + self.alpha_decay * (self.step_count as f64));
        decayed.max(self.min_alpha)
    }

    /// Numerically stable Cholesky decomposition inversion with Tikhonov regularization ($\lambda I$).
    /// Symmetrizes input, adds $\lambda I$ to diagonal (ensuring strictly positive definite),
    /// solves $A = L L^T$, inverts $L$ via forward substitution, and forms $A^{-1} = (L^{-1})^T L^{-1}$.
    /// Sanitizes any NaNs or Infs, cleanly falling back to scaled identity.
    pub fn stable_cholesky_inverse(
        matrix: &[Vec<f64>],
        tikhonov_lambda: f64,
    ) -> Result<Vec<Vec<f64>>, String> {
        let n = matrix.len();
        if n == 0 {
            return Ok(Vec::new());
        }
        for row in matrix {
            if row.len() != n {
                return Err("Matrix must be square".into());
            }
        }

        let lambda = tikhonov_lambda.max(1e-9);
        let fallback_scale = 1.0 / lambda;
        let make_fallback = || {
            let mut id = vec![vec![0.0f64; n]; n];
            for i in 0..n {
                id[i][i] = fallback_scale;
            }
            id
        };

        // Check for non-finite values in input
        for i in 0..n {
            for j in 0..n {
                if !matrix[i][j].is_finite() {
                    return Ok(make_fallback());
                }
            }
        }

        // 1. Symmetrize and add Tikhonov diagonal regularization: M = 0.5*(A + A^T) + lambda*I
        let mut m = vec![vec![0.0f64; n]; n];
        for i in 0..n {
            for j in 0..n {
                m[i][j] = 0.5 * (matrix[i][j] + matrix[j][i]);
            }
            m[i][i] += lambda;
        }

        // 2. Cholesky decomposition M = L L^T
        let mut l = vec![vec![0.0f64; n]; n];
        for i in 0..n {
            for j in 0..=i {
                let mut sum = 0.0f64;
                for k in 0..j {
                    sum += l[i][k] * l[j][k];
                }

                if i == j {
                    let diag = m[i][i] - sum;
                    if !diag.is_finite() || diag <= 1e-12 {
                        return Ok(make_fallback());
                    }
                    l[i][j] = diag.sqrt();
                } else {
                    let lj = l[j][j];
                    if lj.abs() < 1e-12 {
                        return Ok(make_fallback());
                    }
                    let val = (m[i][j] - sum) / lj;
                    if !val.is_finite() {
                        return Ok(make_fallback());
                    }
                    l[i][j] = val;
                }
            }
        }

        // 3. Invert lower triangular L via forward substitution: L * L^-1 = I
        let mut l_inv = vec![vec![0.0f64; n]; n];
        for i in 0..n {
            l_inv[i][i] = 1.0 / l[i][i];
            for j in 0..i {
                let mut sum = 0.0f64;
                for k in j..i {
                    sum += l[i][k] * l_inv[k][j];
                }
                l_inv[i][j] = -sum / l[i][i];
            }
        }

        // 4. Form A^-1 = (L^-1)^T * L^-1
        let mut a_inv = vec![vec![0.0f64; n]; n];
        for i in 0..n {
            for j in 0..n {
                let mut sum = 0.0f64;
                let start_k = i.max(j);
                for k in start_k..n {
                    sum += l_inv[k][i] * l_inv[k][j];
                }
                if !sum.is_finite() {
                    return Ok(make_fallback());
                }
                a_inv[i][j] = sum;
            }
        }

        Ok(a_inv)
    }

    /// Rank-1 Sherman-Morrison streaming update:
    /// $A_{t+1}^{-1} = A_t^{-1} - \frac{A_t^{-1} x x^T A_t^{-1}}{1 + x^T A_t^{-1} x}$
    /// Computes $O(d^2)$ step updates without full matrix inversion.
    pub fn sherman_morrison_rank1_update(a_inv: &mut [Vec<f64>], x: &[f64]) -> Result<(), String> {
        let d = a_inv.len();
        if x.len() != d {
            return Err(format!(
                "Vector dimension {} does not match matrix dimension {}",
                x.len(),
                d
            ));
        }
        for (idx, &val) in x.iter().enumerate() {
            if !val.is_finite() {
                return Err(format!("Input vector element {} is non-finite", idx));
            }
        }

        // 1. v = A^-1 x
        let mut v = vec![0.0f64; d];
        for i in 0..d {
            let mut sum = 0.0f64;
            for j in 0..d {
                sum += a_inv[i][j] * x[j];
            }
            v[i] = sum;
        }

        // 2. denom = 1.0 + x^T v
        let mut x_dot_v = 0.0f64;
        for i in 0..d {
            x_dot_v += x[i] * v[i];
        }
        let denom = 1.0 + x_dot_v;
        if !denom.is_finite() || denom <= 1e-12 {
            return Err("Sherman-Morrison denominator is near-zero, non-finite, or non-positive".into());
        }

        // 3. Compute update into temporary buffer to ensure transactional safety
        let mut updated = vec![vec![0.0f64; d]; d];
        for i in 0..d {
            for j in i..d {
                let delta = (v[i] * v[j]) / denom;
                let val = 0.5 * ((a_inv[i][j] - delta) + (a_inv[j][i] - delta));
                if !val.is_finite() {
                    return Err("Sherman-Morrison update produced non-finite entry".into());
                }
                updated[i][j] = val;
                updated[j][i] = val;
            }
        }

        // 4. Verify positive-definiteness on diagonal before mutating in-place
        for i in 0..d {
            if updated[i][i] <= 1e-12 {
                return Err("Sherman-Morrison update lost positive-definiteness on diagonal".into());
            }
        }

        for i in 0..d {
            a_inv[i].copy_from_slice(&updated[i]);
        }

        Ok(())
    }

    /// Selects action maximizing Upper Confidence Bound:
    /// $\text{score}_a = x^T \hat{\theta}_a + \alpha \sqrt{x^T A_a^{-1} x}$
    /// If alpha < 0.0, uses current annealed alpha(t).
    pub fn select_action(&self, context: &[f32], alpha: f32) -> usize {
        let eff_alpha = if alpha < 0.0 {
            self.current_alpha()
        } else {
            alpha as f64
        };
        self.select_action_internal(context, eff_alpha)
    }

    /// Selects action with current annealed exploration parameter.
    pub fn select_action_annealed(&self, context: &[f32]) -> usize {
        self.select_action_internal(context, self.current_alpha())
    }

    fn select_action_internal(&self, context: &[f32], alpha: f64) -> usize {
        let mut best_action = 0;
        let mut highest_score = f64::NEG_INFINITY;
        let ctx_f64: Vec<f64> = context.iter().map(|&x| x as f64).collect();

        for a in 0..self.num_actions {
            let (mean, var) = if a < self.a_inv_matrices.len()
                && self.a_inv_matrices[a].len() == self.context_dim
            {
                let a_inv = &self.a_inv_matrices[a];
                // theta = A^-1 b
                let mut theta = vec![0.0f64; self.context_dim];
                for i in 0..self.context_dim {
                    let mut sum = 0.0f64;
                    for j in 0..self.context_dim {
                        sum += a_inv[i][j] * (self.b_vectors[a][j] as f64);
                    }
                    theta[i] = sum;
                }
                // mean = x^T theta
                let mut m = 0.0f64;
                for i in 0..self.context_dim {
                    m += ctx_f64[i] * theta[i];
                }
                // var = x^T A^-1 x
                let mut v = 0.0f64;
                for i in 0..self.context_dim {
                    let mut a_inv_x_i = 0.0f64;
                    for j in 0..self.context_dim {
                        a_inv_x_i += a_inv[i][j] * ctx_f64[j];
                    }
                    v += ctx_f64[i] * a_inv_x_i;
                }
                (m, v)
            } else {
                let theta = solve_linear_system(&self.a_matrices[a], &self.b_vectors[a])
                    .unwrap_or_else(|| vec![0.0; self.context_dim]);
                let inv_x = solve_linear_system(&self.a_matrices[a], context)
                    .unwrap_or_else(|| vec![0.0; self.context_dim]);

                let m: f32 = context
                    .iter()
                    .zip(theta.iter())
                    .map(|(&x, &t)| x * t)
                    .sum();
                let v: f32 = context
                    .iter()
                    .zip(inv_x.iter())
                    .map(|(&x, &z)| x * z)
                    .sum();
                (m as f64, v as f64)
            };

            let score = mean + alpha * var.max(0.0).sqrt();

            if score > highest_score {
                highest_score = score;
                best_action = a;
            }
        }

        best_action
    }

    /// Updates covariance matrix $A_a \leftarrow A_a + x x^T$ and response vector $b_a \leftarrow b_a + r x$.
    /// Uses Sherman-Morrison rank-1 streaming update for $A_a^{-1}$ in $O(d^2)$.
    /// In FrozenTest mode, learning is locked (no-op).
    pub fn update(&mut self, action: usize, context: &[f32], reward: f32) {
        if self.execution_mode == RlExecutionMode::FrozenTest {
            return;
        }
        if action >= self.num_actions || context.len() != self.context_dim {
            return;
        }

        self.step_count += 1;
        self.alpha = self.current_alpha();

        for i in 0..self.context_dim {
            self.b_vectors[action][i] += reward * context[i];
            for j in 0..self.context_dim {
                self.a_matrices[action][i][j] += context[i] * context[j];
            }
        }

        // Streaming Sherman-Morrison update on A^-1
        if action < self.a_inv_matrices.len() {
            let ctx_f64: Vec<f64> = context.iter().map(|&x| x as f64).collect();
            let sm_failed = Self::sherman_morrison_rank1_update(&mut self.a_inv_matrices[action], &ctx_f64).is_err();
            // Recover or periodically re-synchronize (every 500 steps) to prevent cumulative floating point drift
            if sm_failed || (self.step_count % 500 == 0) {
                let a_f64: Vec<Vec<f64>> = self.a_matrices[action]
                    .iter()
                    .map(|r| r.iter().map(|&v| v as f64).collect())
                    .collect();
                if let Ok(recovered) = Self::stable_cholesky_inverse(&a_f64, 1e-3) {
                    self.a_inv_matrices[action] = recovered;
                }
            }
        }
    }

    pub fn to_json_string(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    pub fn from_json_string(s: &str) -> Result<Self, serde_json::Error> {
        let bandit: Self = serde_json::from_str(s)?;
        if let Err(msg) = bandit.validate() {
            return Err(serde::de::Error::custom(msg));
        }
        Ok(bandit)
    }

    pub fn save_to_json(&self, path: impl AsRef<std::path::Path>) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        std::fs::write(path, json)
    }

    pub fn load_from_json(path: impl AsRef<std::path::Path>) -> std::io::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let bandit: Self = serde_json::from_str(&contents)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        bandit.validate()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(bandit)
    }
}

/// Shared Bilinear Action-Conditioned Bayesian Bandit Model (Pillar 2).
/// Implements joint state-action feature mapping $\phi(s, a)$:
/// - State vector $s \in \mathbb{R}^d$
/// - One-hot action vector $e_a \in \mathbb{R}^K$
/// - Bilinear outer product interaction terms $s \otimes e_a \in \mathbb{R}^{d \cdot K}$
/// Total dimension $D = d + K + d \cdot K$.
/// Maintains a single shared covariance matrix $A_{\text{shared}} \in \mathbb{R}^{D \times D}$,
/// streaming inverse $A^{-1}$, and response vector $b_{\text{shared}} \in \mathbb{R}^D$.
/// Enables transfer learning across actions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedBilinearBandit {
    #[serde(default = "default_version")]
    pub version: usize,
    pub num_actions: usize,
    pub state_dim: usize,
    pub total_dim: usize,
    pub a_matrix: Vec<Vec<f64>>,
    pub a_inv: Vec<Vec<f64>>,
    pub b_vector: Vec<f64>,
    pub theta_hat: Vec<f64>,
    #[serde(default = "default_alpha_0")]
    pub alpha: f64,
    #[serde(default = "default_alpha_0")]
    pub alpha_0: f64,
    #[serde(default = "default_alpha_decay")]
    pub alpha_decay: f64,
    #[serde(default = "default_min_alpha")]
    pub min_alpha: f64,
    #[serde(default)]
    pub step_count: usize,
    #[serde(default)]
    pub execution_mode: RlExecutionMode,
}

impl SharedBilinearBandit {
    /// Strict Contextual Episode Boundary: alert triage operates with zero temporal credit leakage ($\gamma = 0.0$).
    pub const BANDIT_GAMMA: f32 = 0.0;

    pub fn gamma(&self) -> f32 {
        Self::BANDIT_GAMMA
    }

    pub fn new(num_actions: usize, state_dim: usize) -> Self {
        Self::with_exploration(num_actions, state_dim, 1.0, 0.005, 0.05)
    }

    pub fn with_exploration(
        num_actions: usize,
        state_dim: usize,
        alpha_0: f64,
        alpha_decay: f64,
        min_alpha: f64,
    ) -> Self {
        let total_dim = state_dim + num_actions + state_dim * num_actions;
        let mut a_matrix = vec![vec![0.0f64; total_dim]; total_dim];
        let mut a_inv = vec![vec![0.0f64; total_dim]; total_dim];
        for i in 0..total_dim {
            a_matrix[i][i] = 1.0; // Ridge regularizer I_D
            a_inv[i][i] = 1.0;
        }
        let b_vector = vec![0.0f64; total_dim];
        let theta_hat = vec![0.0f64; total_dim];

        Self {
            version: 1,
            num_actions,
            state_dim,
            total_dim,
            a_matrix,
            a_inv,
            b_vector,
            theta_hat,
            alpha: alpha_0,
            alpha_0,
            alpha_decay,
            min_alpha,
            step_count: 0,
            execution_mode: RlExecutionMode::ColdRl,
        }
    }

    /// Initializes SharedBilinearBandit with domain expert heuristic priors (Pillar 4 WarmPriorRl).
    pub fn with_warm_priors(num_actions: usize, state_dim: usize) -> Self {
        let mut bandit = Self::new(num_actions, state_dim);
        bandit.execution_mode = RlExecutionMode::WarmPriorRl;
        bandit.initialize_heuristic_priors();
        bandit
    }

    /// Injects domain expert heuristic priors into shared weights theta_hat and response vector b_vector:
    /// Action 0 (PassiveObserve): positive weight on benign features
    /// Containment actions: positive weights on threat velocity and MITRE features
    pub fn initialize_heuristic_priors(&mut self) {
        let d = self.state_dim;
        let k = self.num_actions;

        // Baseline action preference
        for a in 0..k {
            let offset = d + a;
            let action_bias = match a {
                0 => 2.0,  // PassiveObserve
                1 => 1.0,  // LowFrictionTriage
                2 => 0.5,  // MemoryIntrospection
                3 => -1.0, // MicroContainment
                _ => -2.0, // HardMitigation
            };
            self.theta_hat[offset] = action_bias;
        }

        // Align b_vector = A * theta_hat (since A_0 = I, b_0 = theta_hat)
        for i in 0..self.total_dim {
            let mut sum = 0.0f64;
            for j in 0..self.total_dim {
                sum += self.a_matrix[i][j] * self.theta_hat[j];
            }
            self.b_vector[i] = sum;
        }
    }

    /// Validates matrix dimensions and version consistency for safe deserialization.
    pub fn validate(&self) -> Result<(), String> {
        if self.version == 0 {
            return Err("Invalid version 0".into());
        }
        let expected_total = self.state_dim + self.num_actions + self.state_dim * self.num_actions;
        if self.total_dim != expected_total {
            return Err(format!(
                "total_dim {} does not match expected {}",
                self.total_dim, expected_total
            ));
        }
        if self.a_matrix.len() != self.total_dim {
            return Err("a_matrix row count != total_dim".into());
        }
        for (r, row) in self.a_matrix.iter().enumerate() {
            if row.len() != self.total_dim {
                return Err(format!("a_matrix[{}] col count != total_dim", r));
            }
        }
        if self.a_inv.len() != self.total_dim {
            return Err("a_inv row count != total_dim".into());
        }
        for (r, row) in self.a_inv.iter().enumerate() {
            if row.len() != self.total_dim {
                return Err(format!("a_inv[{}] col count != total_dim", r));
            }
        }
        if self.b_vector.len() != self.total_dim {
            return Err("b_vector length != total_dim".into());
        }
        if self.theta_hat.len() != self.total_dim {
            return Err("theta_hat length != total_dim".into());
        }
        Ok(())
    }

    pub fn current_alpha(&self) -> f64 {
        let decayed = self.alpha_0 / (1.0 + self.alpha_decay * (self.step_count as f64));
        decayed.max(self.min_alpha)
    }

    /// Joint state-action feature mapping $\phi(s, a) \in \mathbb{R}^D$:
    /// $[s_0..s_{d-1}, e_0..e_{K-1}, (s \otimes e_a)_0..(s \otimes e_a)_{d \cdot K - 1}]$.
    pub fn feature_map(&self, state: &[f64], action: usize) -> Vec<f64> {
        let mut phi = vec![0.0f64; self.total_dim];
        let d = self.state_dim;
        let k = self.num_actions;

        // 1. Shared state vector s
        for i in 0..d.min(state.len()) {
            phi[i] = state[i];
        }

        // 2. One-hot action vector e_a
        if action < k {
            phi[d + action] = 1.0;
        }

        // 3. Bilinear outer product interaction terms: s \otimes e_a
        if action < k {
            let offset = d + k + action * d;
            for i in 0..d.min(state.len()) {
                phi[offset + i] = state[i];
            }
        }

        phi
    }

    /// Evaluates expected reward prediction for candidate action: $\hat{r}(s, a) = \phi(s, a)^T \hat{\theta}$.
    pub fn predict(&self, action: usize, state: &[f64]) -> f64 {
        let phi = self.feature_map(state, action);
        phi.iter().zip(self.theta_hat.iter()).map(|(&p, &t)| p * t).sum()
    }

    /// Selects action maximizing Upper Confidence Bound under shared representation:
    /// $\text{score}_a = \phi(s, a)^T \hat{\theta} + \alpha \sqrt{\phi(s, a)^T A_{\text{shared}}^{-1} \phi(s, a)}$
    pub fn select_action(&self, state: &[f64], alpha: f64) -> usize {
        let eff_alpha = if alpha < 0.0 {
            self.current_alpha()
        } else {
            alpha
        };
        self.select_action_internal(state, eff_alpha)
    }

    pub fn select_action_annealed(&self, state: &[f64]) -> usize {
        self.select_action_internal(state, self.current_alpha())
    }

    fn select_action_internal(&self, state: &[f64], alpha: f64) -> usize {
        let mut best_action = 0;
        let mut highest_score = f64::NEG_INFINITY;

        for a in 0..self.num_actions {
            let phi = self.feature_map(state, a);

            // mean = phi^T theta_hat
            let mean: f64 = phi.iter().zip(self.theta_hat.iter()).map(|(&p, &t)| p * t).sum();

            // var = phi^T A^-1 phi
            let mut var = 0.0f64;
            for i in 0..self.total_dim {
                let mut a_inv_phi_i = 0.0f64;
                for j in 0..self.total_dim {
                    a_inv_phi_i += self.a_inv[i][j] * phi[j];
                }
                var += phi[i] * a_inv_phi_i;
            }

            let score = mean + alpha * var.max(0.0).sqrt();
            if score > highest_score {
                highest_score = score;
                best_action = a;
            }
        }

        best_action
    }

    /// Updates shared covariance matrix $A \leftarrow A + \phi \phi^T$ and response vector $b \leftarrow b + r \phi$.
    /// Uses Sherman-Morrison rank-1 update to update $A^{-1}$ in $O(D^2)$, then updates $\hat{\theta} = A^{-1} b$.
    /// In FrozenTest mode, learning is locked (no-op).
    pub fn update(&mut self, action: usize, state: &[f64], reward: f64) {
        if self.execution_mode == RlExecutionMode::FrozenTest {
            return;
        }
        if action >= self.num_actions || state.len() != self.state_dim {
            return;
        }

        self.step_count += 1;
        self.alpha = self.current_alpha();

        let phi = self.feature_map(state, action);

        // 1. Update response vector b and covariance A
        for i in 0..self.total_dim {
            self.b_vector[i] += reward * phi[i];
            for j in 0..self.total_dim {
                self.a_matrix[i][j] += phi[i] * phi[j];
            }
        }

        // 2. Sherman-Morrison streaming update on A^-1
        let sm_failed = LinUcbBandit::sherman_morrison_rank1_update(&mut self.a_inv, &phi).is_err();
        if sm_failed || (self.step_count % 500 == 0) {
            if let Ok(recovered) = LinUcbBandit::stable_cholesky_inverse(&self.a_matrix, 1e-3) {
                self.a_inv = recovered;
            }
        }

        // 3. Update theta_hat = A^-1 b
        for i in 0..self.total_dim {
            let mut sum = 0.0f64;
            for j in 0..self.total_dim {
                sum += self.a_inv[i][j] * self.b_vector[j];
            }
            self.theta_hat[i] = sum;
        }
    }

    pub fn to_json_string(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    pub fn from_json_string(s: &str) -> Result<Self, serde_json::Error> {
        let bandit: Self = serde_json::from_str(s)?;
        if let Err(msg) = bandit.validate() {
            return Err(serde::de::Error::custom(msg));
        }
        Ok(bandit)
    }

    pub fn save_to_json(&self, path: impl AsRef<std::path::Path>) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        std::fs::write(path, json)
    }

    pub fn load_from_json(path: impl AsRef<std::path::Path>) -> std::io::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let bandit: Self = serde_json::from_str(&contents)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        bandit.validate()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(bandit)
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

/// Multi-Step Return Transition Buffer (n-step learning, n=3).
/// Maintains a rolling window of $n$ transitions accumulating discounted returns:
/// $R_t = \sum_{k=0}^{m-1} \gamma^k r_{t+k}$ before emitting to experience replay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NStepTransitionBuffer {
    pub n_steps: usize,
    pub gamma: f32,
    pub buffer: VecDeque<Transition>,
}

impl NStepTransitionBuffer {
    pub fn new(n_steps: usize, gamma: f32) -> Self {
        Self {
            n_steps: n_steps.max(1),
            gamma,
            buffer: VecDeque::new(),
        }
    }

    pub fn push(&mut self, transition: Transition) -> Option<Transition> {
        let is_done = transition.done;
        self.buffer.push_back(transition);

        if self.buffer.len() >= self.n_steps {
            Some(self.pop_n_step_transition())
        } else if is_done && !self.buffer.is_empty() {
            Some(self.pop_n_step_transition())
        } else {
            None
        }
    }

    fn pop_n_step_transition(&mut self) -> Transition {
        let first = self.buffer.pop_front().expect("buffer must not be empty");
        let mut r = first.reward;
        let mut discount = self.gamma;
        let mut next_state = first.next_state.clone();
        let mut done = first.done;

        let lookahead = (self.n_steps - 1).min(self.buffer.len());
        for k in 0..lookahead {
            r += discount * self.buffer[k].reward;
            discount *= self.gamma;
            next_state = self.buffer[k].next_state.clone();
            done = self.buffer[k].done;
            if done {
                break;
            }
        }

        Transition {
            state: first.state,
            action: first.action,
            reward: r,
            next_state,
            done,
            priority: r.abs() + 0.01,
            action_index: first.action_index,
        }
    }

    pub fn flush(&mut self) -> Vec<Transition> {
        let mut out = Vec::new();
        while !self.buffer.is_empty() {
            out.push(self.pop_n_step_transition());
        }
        out
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
            let reward = if is_critical && candidate_action.is_containment() {
                -500.0f32
            } else {
                self.reward_engine.compute_reward(
                    action,
                    is_malicious,
                    packet.threat_score,
                    0.5,
                    is_critical,
                )
            };

            let transition = Transition {
                state: packet.telemetry_vector.clone(),
                action: candidate_action,
                reward,
                next_state: packet.telemetry_vector,
                done: action == EdrAction::HardMitigation,
                priority: reward.abs() + 0.01,
                action_index: Some(candidate_action.to_index()),
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

                let reward = if is_protected_target && candidate_action.is_containment() {
                    -500.0f32
                } else {
                    self.reward_engine.compute_reward(
                        guarded_action,
                        is_attack,
                        threat_score,
                        prev_threat_score,
                        is_protected_target,
                    )
                };
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
                    action: candidate_action,
                    reward,
                    next_state: next_s_vec,
                    done,
                    priority: reward.abs() + 0.01,
                    action_index: Some(candidate_action.to_index()),
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

/// Advantage Tracker (Pillars 5 & 6).
/// Compares RL verdict against the deterministic heuristic baseline:
/// - rl_greater: Count and percentage where R_RL > R_heuristic + 1e-4
/// - rl_equal: Count and percentage where |R_RL - R_heuristic| <= 1e-4
/// - rl_less: Count and percentage where R_RL < R_heuristic - 1e-4
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AdvantageTracker {
    pub rl_greater: usize,
    pub rl_equal: usize,
    pub rl_less: usize,
    pub total_steps: usize,
    pub cumulative_rl_reward: f64,
    pub cumulative_heuristic_reward: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvantageSummary {
    pub total_steps: usize,
    pub rl_greater: usize,
    pub rl_equal: usize,
    pub rl_less: usize,
    pub pct_greater: f64,
    pub pct_equal: f64,
    pub pct_less: f64,
    pub mean_rl_reward: f64,
    pub mean_heuristic_reward: f64,
    pub advantage: f64,
}

impl AdvantageTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_step(&mut self, rl_reward: f64, heuristic_reward: f64) {
        if !rl_reward.is_finite() || !heuristic_reward.is_finite() {
            return;
        }
        self.total_steps += 1;
        self.cumulative_rl_reward += rl_reward;
        self.cumulative_heuristic_reward += heuristic_reward;

        let diff = rl_reward - heuristic_reward;
        if diff > 1e-4 {
            self.rl_greater += 1;
        } else if diff < -1e-4 {
            self.rl_less += 1;
        } else {
            self.rl_equal += 1;
        }
    }

    pub fn get_summary(&self) -> AdvantageSummary {
        let total = self.total_steps as f64;
        let (pct_greater, pct_equal, pct_less) = if total > 0.0 {
            (
                (self.rl_greater as f64 / total) * 100.0,
                (self.rl_equal as f64 / total) * 100.0,
                (self.rl_less as f64 / total) * 100.0,
            )
        } else {
            (0.0, 0.0, 0.0)
        };

        let mean_rl = if total > 0.0 {
            self.cumulative_rl_reward / total
        } else {
            0.0
        };
        let mean_heur = if total > 0.0 {
            self.cumulative_heuristic_reward / total
        } else {
            0.0
        };

        AdvantageSummary {
            total_steps: self.total_steps,
            rl_greater: self.rl_greater,
            rl_equal: self.rl_equal,
            rl_less: self.rl_less,
            pct_greater,
            pct_equal,
            pct_less,
            mean_rl_reward: mean_rl,
            mean_heuristic_reward: mean_heur,
            advantage: mean_rl - mean_heur,
        }
    }
}

/// Oracle Regret & Temporal Learning Dynamics Tracker (Pillars 5 & 6).
/// - Instantaneous Regret_t = max(0.0, R* - R(a_t)) where R* is the oracle best action reward.
/// - Early mean reward (t < 100) vs Late mean reward (t >= 100).
/// - Tracks regret decay over time: lim_{t -> infty} Regret_t -> 0.
/// - Tracks false positive rollback drops.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TemporalMetricsTracker {
    pub step_count: usize,
    pub early_rewards: Vec<f64>,
    pub late_rewards: Vec<f64>,
    pub instantaneous_regrets: Vec<f64>,
    pub cumulative_regret: f64,
    pub oracle_matches: usize,
    pub fp_rollback_drops: usize,
    pub advantage_tracker: AdvantageTracker,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalMetricsSummary {
    pub total_steps: usize,
    pub early_mean_reward: f64,
    pub late_mean_reward: f64,
    pub reward_progression_positive: bool,
    pub mean_regret: f64,
    pub late_mean_regret: f64,
    pub cumulative_regret: f64,
    pub oracle_match_rate: f64,
    pub fp_rollback_drops: usize,
    pub advantage: AdvantageSummary,
}

impl TemporalMetricsTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_step(
        &mut self,
        rl_reward: f64,
        heuristic_reward: f64,
        oracle_reward: f64,
        action_selected: usize,
        oracle_action: usize,
    ) {
        let safe_rl = if rl_reward.is_finite() { rl_reward } else { 0.0 };
        let safe_heur = if heuristic_reward.is_finite() { heuristic_reward } else { 0.0 };
        let safe_oracle = if oracle_reward.is_finite() { oracle_reward } else { 0.0 };

        let t = self.step_count;
        self.step_count += 1;

        if t < 100 {
            self.early_rewards.push(safe_rl);
        } else {
            self.late_rewards.push(safe_rl);
        }

        let regret = (safe_oracle - safe_rl).max(0.0);
        self.instantaneous_regrets.push(regret);
        self.cumulative_regret += regret;

        if action_selected == oracle_action {
            self.oracle_matches += 1;
        }

        self.advantage_tracker.record_step(safe_rl, safe_heur);
    }

    pub fn record_rollback_drop(&mut self, is_fp: bool) {
        if is_fp {
            self.fp_rollback_drops += 1;
        }
    }

    pub fn get_summary(&self) -> TemporalMetricsSummary {
        let early_mean = if !self.early_rewards.is_empty() {
            self.early_rewards.iter().sum::<f64>() / (self.early_rewards.len() as f64)
        } else {
            0.0
        };

        let late_mean = if !self.late_rewards.is_empty() {
            self.late_rewards.iter().sum::<f64>() / (self.late_rewards.len() as f64)
        } else {
            0.0
        };

        let total = self.step_count as f64;
        let mean_regret = if total > 0.0 {
            self.cumulative_regret / total
        } else {
            0.0
        };

        let late_mean_regret = if self.step_count >= 100 && !self.late_rewards.is_empty() {
            let late_regrets = &self.instantaneous_regrets[100..];
            if !late_regrets.is_empty() {
                late_regrets.iter().sum::<f64>() / (late_regrets.len() as f64)
            } else {
                0.0
            }
        } else {
            0.0
        };

        let match_rate = if total > 0.0 {
            self.oracle_matches as f64 / total
        } else {
            0.0
        };

        TemporalMetricsSummary {
            total_steps: self.step_count,
            early_mean_reward: early_mean,
            late_mean_reward: late_mean,
            reward_progression_positive: late_mean > early_mean,
            mean_regret,
            late_mean_regret,
            cumulative_regret: self.cumulative_regret,
            oracle_match_rate: match_rate,
            fp_rollback_drops: self.fp_rollback_drops,
            advantage: self.advantage_tracker.get_summary(),
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
