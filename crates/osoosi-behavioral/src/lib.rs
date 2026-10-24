//! Behavioral detection from system and application logs.
//!
//! First detection layer: streams Windows Event Log (System, Application, Security),
//! Linux journald/syslog, and macOS unified log into behavioral sentences for
//! SecureBERT-style classification. Supports continual training via labeled feedback.

#![allow(clippy::needless_range_loop)]
#![allow(clippy::doc_lazy_continuation)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::manual_memcpy)]
#![allow(clippy::large_enum_variant)]
#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::manual_range_contains)]

pub mod agentic_arbitrator;
mod analyzer;
mod classifier;
mod colog;
pub mod consensus;
pub mod deception;
pub mod decision_model;
pub mod detectors;
pub mod ebpf_monitor;
pub mod embedding_gemma;
pub mod feedback;
pub mod forensics;
pub mod hardware_selection;
pub mod llm_engine;
mod log_reader;
mod process_tree;
pub mod reasoning;
pub mod rl_engine;
mod sentence;
pub mod skyrl;
pub mod spider_eyes;
pub mod yara_analyzer;

pub use decision_model::{ClefDecisionEngine, LocalDecisionEngine, SecurityIncidentDecision};
pub use hardware_selection::{
    detect_live_resources, get_system_resources, query_installed_ollama_models,
    query_installed_ollama_models_sync, query_system_resources, DiskResourceInfo, HardwareTier,
    OptimalModelSelection, SystemResourceSummary,
};

pub use agentic_arbitrator::{
    AgentTrajectoryTracker, AgenticArbitrator, AgenticToolValidator, AgenticVerdict, DefenseAction,
    Layer2Critic, TrajectoryEvent, VassilevMutator,
};
pub use analyzer::{AnalysisMode, BehavioralAnalyzer, InvestigativePrompt};
pub use classifier::{BehavioralClassifier, BehavioralResult};
pub use detectors::{ConsoleProcessContext, ConsoleSecurityAlert, ElevatedConsoleHijackDetector};
pub use ebpf_monitor::EbpfMonitor;
pub use embedding_gemma::{EmbeddingGemma2Engine, MatryoshkaDim};
pub use feedback::{FeedbackStore, LabeledSample};
pub use forensics::{PacketForensics, TriageResult};
pub use llm_engine::{FoundationSecAnalyzer, Gemma4Analyzer, SmolLMAnalyzer};
pub use log_reader::{BehavioralLogReader, LogEvent};
pub use process_tree::{ProcessRelationship, ProcessTreeEmbedder};
pub use rl_engine::{
    ActionScope, ActionTier, AdvantageSummary, AdvantageTracker, ByzantineRobustAggregator,
    DeepQEngine, DigitalTwinSimulator, DoubleDeepQEngine, DuelingQuantileNetwork,
    EDRRuntimeController, EdrAction, EdrRewardEngine, HeuristicPriorScores, IncidentMitreContext,
    LinUcbBandit, MeshContext, MitigationAction, MitigationTechnique, MultiObjectiveSignals,
    MultiObjectiveWeights, NStepTransitionBuffer, PrioritizedReplayBuffer, ProcessContext,
    ProcessLineageVector, QuantileRegressionDqnEngine, RiskProfile, RlExecutionMode,
    RollbackStrategy, RolloutMetrics, SafetyFilter, SafetyGuardrail, SharedBilinearBandit,
    StateFeaturePipeline, StructuredEdrAction, TelemetryLevel, TelemetryPacket, TelemetryVelocity,
    TemporalMetricsSummary, TemporalMetricsTracker, Transition, UnifiedEdrState,
};
pub use sentence::{
    event_to_behavioral_sentence, extract_event_pid, extract_sentence_image, extract_sentence_pid,
    generate_behavioral_sentence,
};
pub use skyrl::{OshoosiSecurityGym, SkyAction, StepResult};
pub use spider_eyes::{GemmaSupervisor, SpiderEyes};
pub use yara_analyzer::YaraAnalyzer;
