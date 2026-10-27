//! OpenỌ̀ṣọ́ọ̀sì Agentic EDR Orchestrator (The "Core").
//!
//! Connects Telemetry, Policy, Wire (P2P), and Runtime.

#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::collapsible_match)]
#![allow(clippy::unnecessary_sort_by)]
#![allow(clippy::redundant_pattern_matching)]
#![allow(clippy::if_same_then_else)]
#![allow(clippy::manual_strip)]
#![allow(clippy::useless_borrows_in_formatting)]
#![allow(clippy::needless_borrow)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::unnecessary_to_owned)]
#![allow(clippy::redundant_closure)]
#![allow(clippy::match_like_matches_macro)]
#![allow(clippy::manual_flatten)]
#![allow(
    clippy::manual_is_multiple_of,
    clippy::await_holding_lock,
    clippy::assertions_on_constants
)]
#![allow(ambiguous_glob_reexports)]

pub use osoosi_audit;
pub use parking_lot;

pub mod adaptive;
pub mod adversarial_gauntlet;
pub mod agent_egress;
pub mod ai_feeds;
pub mod attack_graph;
pub mod backup;
pub mod baseline;
pub mod blocking_manager;
pub mod browser_guard;
pub mod byzantine;
pub mod canary;
pub mod causal_ai;
pub mod causal_graph;
pub mod config_integrity;
pub mod console_defense;
pub use console_defense::{
    compute_hardened_console_mode, detach_console, flush_console_input, harden_windows_console,
    is_console_mode_hardened, CommandConsoleExt, ConsoleProcessContext, ConsoleSecurityAlert,
    ElevatedConsoleHijackDetector,
};
pub mod correlator;
pub mod disk_cleanup;
pub mod dlp_lineage;
pub mod dotscope;
pub mod edr_bench;
pub mod fhe_coordinator;
pub mod firewall;
pub mod forensics;
pub mod fprime_flight;
pub mod geo_mesh;
pub mod gossip;
pub mod hardened;
pub mod hybrid_runtime;
pub mod killchain;
pub mod landlock;
pub mod log_retention;
pub mod memory_watchdog;
pub mod military;
pub mod mitre;
pub mod network;
pub mod nostr_mesh;
pub mod openshell;
pub mod orchestrator;
pub mod otx_tarpit;
pub mod pe_inspector;
pub mod pii;
pub mod privacy;
pub mod privilege;
pub mod quarantine;
pub mod rate_limit_backoff;
pub mod rea;
pub mod relativistic;
pub mod remediation;
pub mod safe_browsing;
pub mod secured_executor;
pub mod self_healing;
pub mod shield;
pub mod software_replacement;
pub mod static_analyzer;
pub mod supervisor;
pub mod system_check;
pub mod tool_paths;
pub mod triage;
pub mod version_utils;
pub mod voters;
pub mod watchdog;
pub mod wfp;
pub mod win_trust;
pub mod yara;
pub mod yara_gen;

pub const CONSENSUS_LOG_TARGET: &str = "osoosi_core::consensus";

pub use causal_graph::{
    AdversarialRegressionCase, AuthorityLevel, CausalEdgeType, CausalEventRecord,
    CausalSecurityGraph, CausalVerdict, ConfusedDeputyBrokerRouter, DeclassificationResult,
    FileClassification, OsEffectType, ProcessInstanceIdentity, ServiceIdentityKeyStore,
    TransitiveTaintReport, WorkflowSequenceMatch,
};
pub use disk_cleanup::{
    evaluate_disk_pressure, get_current_cleanup_job, get_disk_cleanup_policy,
    get_disk_cleanup_status_snapshot, run_autonomous_disk_cleanup_sweep, set_current_cleanup_job,
    spawn_autonomous_disk_cleanup_watchdog, update_current_cleanup_job, update_disk_cleanup_policy,
    DiskCleanupJobProgress, DiskCleanupJobResponse, DiskCleanupPolicy, DiskCleanupStatusSnapshot,
    DiskCleanupSweepReport, DiskCleanupTierResult, DiskPressureLevel,
};
pub use dlp_lineage::{
    compare_ssdeep, compute_sha256_hex, compute_ssdeep, ArtifactKey, ArtifactTaintRecord,
    ClassificationLattice, DlpBaggage, DlpLineageTracker, EgressDecision, FileWriteTaintDecision,
    PolicyLattice, ProcessInstanceKey, ProcessTaintRecord,
};
pub use edr_bench::{
    resolve_fixture_path, BenchmarkReport, BenignBaselineAssertion, EdrBenchHarness, EdrBenchTask,
    ExpectedVerdict, HarnessBounds, TargetArch, TelemetryContext, ThreatAssertion,
};
pub use fprime_flight::{
    create_port_pair, ArenaBinKind, ArenaSlotHandle, BftMeshConsensusComponent,
    BftQuorumPromotionProof, ComponentHealthVerdict, ContainmentDirective,
    EbpfPmuTelemetryComponent, FPrimeComponent, FPrimeError, FPrimeFlightRuntime,
    FPrimeOperatingMode, FPrimeTelemetrySnapshot, FPrimeTopology, InputPort, IsolationAck,
    OutputPort, PingToken, PongToken, PortConnectionDescriptor, PortEnvelope, PortQosLane,
    ReaInspectionVerdict, ReaMagikaInspectorComponent, RecoilAssessment,
    RecoilLikelihoodScorerComponent, SafeModeExecutionReport, SafeModePlaybook, SequencerOp,
    StaticArenaPool, SvcCmdSequencer, SvcHealthMonitor, TelemetryFrame, WatchdogStrokeReceipt,
    WfpNetworkIsolatorComponent,
};
pub use hybrid_runtime::{
    init_hybrid_concurrency, max_blocking_threads, rayon_thread_count, run_on_rayon, spawn_rayon,
    spawn_smart, tokio_worker_threads,
};
pub use memory_watchdog::{
    evaluate_memory_pressure, get_available_memory_mb, spawn_memory_watchdog, MemoryPressureLevel,
    MemoryWatchdogDebouncer,
};
pub use orchestrator::*;
pub use rate_limit_backoff::*;
pub use rea::*;
