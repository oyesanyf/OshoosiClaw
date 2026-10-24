//! OpenỌ̀ṣọ́ọ̀sì Agentic EDR Orchestrator (The "Core").
//! Connects Telemetry, Policy, Wire (P2P), and Runtime.

#![allow(unused_imports)]

use anyhow::{anyhow, Result};
use chrono::Utc;
use osoosi_audit::AuditTrail;
use osoosi_model::{MalwareScanner, ModelConfig, ThreatModel};
use osoosi_policy::{PolicyEngine, ThreatFeedFetcher};
use osoosi_repair::PatchEngine;
use osoosi_runtime::DeceptionManager;
use osoosi_trust::TrustManager;
use osoosi_types::{
    load_runtime_config, resolve_nvd_api_key, resolve_otx_api_key, HostSecurityEvent, Priority,
    ResourceCategory, SecuredExecutor, TelemetryMode,
};
use osoosi_wire::{JoinGate, MeshCommand, MeshNode};
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Once};
use std::time::{Duration, Instant};
use tracing::{debug, error, info, warn};

pub use osoosi_memory::MemoryStore;

// Re-export crate modules for convenient unqualified access across orchestrator submodules
pub use crate::ai_feeds;
pub use crate::attack_graph;
pub use crate::backup;
pub use crate::baseline;
pub use crate::blocking_manager;
pub use crate::browser_guard;
pub use crate::byzantine;
pub use crate::canary;
pub use crate::causal_ai;
pub use crate::causal_graph;
pub use crate::config_integrity;
pub use crate::console_defense;
pub use crate::correlator;
pub use crate::disk_cleanup;
pub use crate::dotscope;
pub use crate::fhe_coordinator;
pub use crate::firewall;
pub use crate::forensics;
pub use crate::geo_mesh;
pub use crate::gossip;
pub use crate::hardened;
pub use crate::hybrid_runtime;
pub use crate::killchain;
pub use crate::landlock;
pub use crate::log_retention;
pub use crate::memory_watchdog;
pub use crate::military;
pub use crate::mitre;
pub use crate::network;
pub use crate::nostr_mesh;
pub use crate::openshell;
pub use crate::otx_tarpit;
pub use crate::pe_inspector;
pub use crate::pii;
pub use crate::privacy;
pub use crate::privilege;
pub use crate::quarantine;
pub use crate::rea;
pub use crate::relativistic;
pub use crate::remediation as rem_mod;
pub use crate::secured_executor;
pub use crate::self_healing;
pub use crate::shield;
pub use crate::software_replacement;
pub use crate::static_analyzer;
pub use crate::supervisor;
pub use crate::system_check;
pub use crate::tool_paths;
pub use crate::triage;
pub use crate::version_utils;
pub use crate::voters;
pub use crate::watchdog;
pub use crate::wfp;
pub use crate::win_trust;
pub use crate::yara;
pub use crate::yara_gen;

pub mod event_pipeline;
pub mod gossip_feed;
pub mod init;
pub mod maintenance;
pub mod mesh;
pub mod monitors;
pub mod query;
pub mod remediation;
pub mod siquery;
pub mod types;

#[cfg(test)]
mod tests;

pub use event_pipeline::*;
pub use gossip_feed::*;
pub use init::*;
pub use maintenance::*;
pub use mesh::*;
pub use monitors::*;
pub use query::*;
pub use remediation::*;
pub use siquery::*;
pub use types::*;

#[derive(Clone)]
pub struct EdrOrchestrator {
    /// Memory: Local persistence
    pub memory: Arc<MemoryStore>,
    /// Mesh peer count (updated when peers are approved)
    pub(crate) mesh_peer_count: Arc<AtomicU32>,
    /// Start time for uptime calculation
    pub(crate) start_time: Instant,
    /// Policy: Reasoning with NVD/KEV intelligence
    pub(crate) policy: Arc<PolicyEngine>,
    /// Wire: P2P Gossip intelligence sharing (used for broadcast when mesh is running)
    pub(crate) mesh: Arc<tokio::sync::Mutex<Option<MeshNode>>>,
    /// Channel to send commands to the mesh task (broadcast, approve peer)
    pub(crate) mesh_command_tx:
        Arc<tokio::sync::Mutex<Option<tokio::sync::mpsc::Sender<MeshCommand>>>>,
    /// Runtime: Active Response (Ghost/Tarpit)
    pub(crate) response: Arc<DeceptionManager>,
    /// Audit: Tamper-evident Merkle Logchain
    pub audit: Arc<AuditTrail>,
    /// Trust: Identity and Attestation
    pub trust: Arc<TrustManager>,
    pub(crate) watcher: Arc<tokio::sync::Mutex<osoosi_telemetry::FileWatcher>>,
    /// Receiver for file system events. Taken by the monitor loop.
    pub(crate) file_event_rx: Arc<
        tokio::sync::Mutex<
            Option<tokio::sync::mpsc::Receiver<anyhow::Result<osoosi_telemetry::FileChangeEvent>>>,
        >,
    >,
    /// Repair Engine: Patch discovery and application
    pub(crate) patch_engine: Arc<PatchEngine>,
    /// Privacy: Differential Privacy + Merkle Proofs + Homomorphic Encryption
    pub(crate) privacy: Arc<privacy::PrivacyLayer>,
    /// Military: Tactical detection for asymmetric warfare
    pub(crate) military: Arc<military::MilitaryGuard>,
    /// Local model trained on self + peer data (stored in models/)
    pub(crate) threat_model: Arc<tokio::sync::RwLock<ThreatModel>>,
    /// Malware scanner (PE features + ML + signatures)
    pub(crate) malware_scanner: Arc<MalwareScanner>,
    /// LLM triage: high-confidence threats awaiting agent decision
    pub(crate) triage_store: crate::triage::TriageStore,
    /// Behavioral baseline for anomaly detection
    pub(crate) baseline: Arc<crate::baseline::BehavioralBaseline>,
    /// Policy Consensus tracking (Mesh-validated patches) — DashMap: lock-free concurrent access
    pub(crate) policy_consensus:
        Arc<dashmap::DashMap<String, Vec<osoosi_types::PolicyConsensusMessage>>>,
    /// Approval Queue for high-stakes autonomous actions
    pub(crate) approval_queue: Arc<tokio::sync::Mutex<Vec<osoosi_sandbox::ApprovalRequest>>>,
    /// Sandbox Executor for isolated tool execution
    pub(crate) sandbox: Arc<osoosi_sandbox::SandboxExecutor>,
    /// Shield Layer for Taint/SSRF/Policy protection
    pub(crate) shield: Arc<crate::shield::ShieldLayer>,
    /// Holographic Deception Sharding (HDS) Engine
    pub holograph: Arc<osoosi_wire::holograph::HolographEngine>,
    /// Relativistic Guard (Einstein Engine)
    pub(crate) relativistic: Arc<crate::relativistic::RelativisticGuard>,
    /// Behavioral Classifier (SecureBERT + Rules + Feedback)
    pub(crate) behavioral_classifier: Arc<osoosi_behavioral::BehavioralClassifier>,
    /// Behavioral AI Analyzer (OpenAI/Azure adapted from AIEventAnalyzer)
    pub(crate) behavioral_analyzer: Arc<osoosi_behavioral::BehavioralAnalyzer>,
    /// Native Candle SmolLM (optional — agent runs if files missing or load fails).
    #[allow(dead_code)]
    pub(crate) behavioral_engine: Option<Arc<osoosi_behavioral::SmolLMAnalyzer>>,
    #[allow(dead_code)]
    pub(crate) gemma_cortex: Option<Arc<osoosi_behavioral::Gemma4Analyzer>>,
    pub blocking_manager: Arc<crate::blocking_manager::BlockingManager>,
    pub yara_manager: Arc<crate::yara::YaraManager>,
    /// PII Classifier (Presidio + Tika + Magika fallback)
    #[allow(dead_code)]
    pub(crate) pii_classifier: Arc<crate::pii::PiiClassifier>,
    /// Browser security auditor (extensions, search hijacking)
    #[allow(dead_code)]
    pub(crate) browser_guard: Arc<crate::browser_guard::BrowserGuard>,
    /// NSRL "Known Good" Cache (SHA1 -> IsValid) to avoid SQLite hits for every process spawn.
    #[allow(dead_code)]
    pub(crate) nsrl_cache: Arc<dashmap::DashMap<String, bool>>,
    /// Remediation: Autonomous response actions (Isolate/Kill)
    #[allow(dead_code)]
    pub(crate) remediation: Arc<crate::remediation::RemediationController>,
    /// Adaptive Telemetry: Scaling fidelity based on CPU/Detections
    #[allow(dead_code)]
    pub(crate) adaptive: Arc<crate::adaptive::TelemetryController>,
    /// Forensic Storyteller: AI-driven attack narratives
    #[allow(dead_code)]
    pub(crate) storyteller: Arc<crate::forensics::ForensicStoryteller>,
    /// Causal AI: Process lineage and predictive analysis
    #[allow(dead_code)]
    pub(crate) causal_ai: Arc<crate::causal_ai::CausalEngine>,
    /// Self-Healing: Automatic rollback of malicious changes
    #[allow(dead_code)]
    pub(crate) self_healing: Arc<crate::self_healing::SelfHealingEngine>,
    /// Ghost Node: Active deception manager
    pub ghost_nodes: Arc<osoosi_wire::GhostNodeManager>,
    /// Ghost Trap Canary System
    pub canary: Arc<crate::canary::CanaryManager>,
    /// Host execution layer (Always Direct for maintenance)
    pub(crate) host_executor: Arc<dyn SecuredExecutor>,
    /// Task execution layer (Direct or OpenShell for analysis)
    pub(crate) task_executor: Arc<dyn SecuredExecutor>,
    /// Debouncer for behavioral alerts (reason -> last_log_time)
    pub(crate) behavioral_debouncer: Arc<dashmap::DashMap<String, Instant>>,
    /// Event Correlator: Multi-engine intelligence fusion
    pub(crate) correlator: Arc<crate::correlator::EventCorrelator>,
    /// Static Analyzer: CAPA + FLOSS + LLM reasoning
    pub(crate) static_analyzer: Arc<crate::static_analyzer::StaticAnalyzer>,
    /// Morphic Hyper-Web: Entanglement and Probabilistic Deception
    pub(crate) deception_engine:
        Arc<tokio::sync::RwLock<osoosi_behavioral::deception::EntanglementEngine>>,
    /// Spider Eyes: Binary Analyzer (LLM Cortex + Capstone)
    pub(crate) spider_eyes: Arc<osoosi_behavioral::SpiderEyes>,
    /// Runtime config (db paths, sandboxes, etc.)
    pub(crate) runtime_config: osoosi_types::config::RuntimeConfig,
    /// Alert suppression cache (Hash -> Last Alert Time)
    pub(crate) alert_suppression_cache: Arc<dashmap::DashMap<String, Instant>>,
    /// Nostr Mesh: Decentralized relay-based threat broadcasting (BitChat style)
    pub(crate) nostr_mesh: Arc<crate::nostr_mesh::NostrMeshOrchestrator>,
    /// Total telemetry events ingested (for dashboard metrics)
    pub(crate) telemetry_total_count: Arc<std::sync::atomic::AtomicU64>,
    /// Last time a TELEMETRY_SUMMARY was logged
    pub(crate) last_telemetry_summary: Arc<tokio::sync::Mutex<Instant>>,
    /// Last total count when summary was logged
    pub(crate) last_telemetry_summary_count: Arc<std::sync::atomic::AtomicU64>,
    /// Total Gossip messages received from peers
    pub(crate) mesh_gossip_count_atomic: Arc<AtomicU32>,
    /// Live Gossip Mesh Feed buffer (recent inbound and outbound peer intelligence)
    pub(crate) mesh_gossip_feed:
        Arc<std::sync::RwLock<std::collections::VecDeque<osoosi_types::GossipFeedItem>>>,
    /// Set of threat / gossip feed IDs explicitly dismissed or remediated
    pub dismissed_gossip_ids: Arc<dashmap::DashSet<String>>,
    /// Set of process basenames autonomously adjudicated clean by REA
    pub rea_adjudicated_clean_procs: Arc<dashmap::DashSet<String>>,
    /// Timestamp (unix seconds) of the last autonomous REA threat adjudication sweep
    pub(crate) last_rea_adjudication_ts: Arc<std::sync::atomic::AtomicI64>,
    /// Debouncer for mesh threat broadcasts (key -> last_broadcast_time)
    pub(crate) mesh_broadcast_debouncer: Arc<dashmap::DashMap<String, Instant>>,
    /// Synthetic Canary Correlator: Tracking probe health and anti-blinding
    pub canary_correlator: Arc<tokio::sync::Mutex<osoosi_telemetry::canary::CanaryCorrelator>>,
    /// Process Hollowing Interception Detector
    pub hollowing_detector: Arc<osoosi_telemetry::hollowing::ProcessHollowingDetector>,
    /// Immutable baseline of pre-existing accounts captured at startup to prevent Confused Deputy rollback attacks.
    pub preexisting_accounts: Arc<std::collections::HashSet<String>>,
    /// Cognitive Fusion Supervisor Agent (Dempster-Shafer multi-sensor watchdog)
    pub supervisor: Arc<supervisor::CognitiveFusionSupervisor>,
    /// Hardware-enforced Ring-0 Windows Driver client for pre-operation process blocking.
    pub kernel_driver:
        Arc<parking_lot::RwLock<Option<osoosi_runtime::kernel_driver::KernelDriverClient>>>,
    /// Embedded Velociraptor Forensic Extraction Service client.
    pub forensics: Arc<osoosi_forensics::VelociraptorClient>,
    /// Non-autoregressive Clef Decision Model engine.
    pub decision_engine: Arc<osoosi_behavioral::decision_model::ClefDecisionEngine>,
    /// Native Rust Agent Anomaly Detection (AAD) engine (OWASP Agentic Top 10)
    pub agent_anomaly_detector: Arc<osoosi_agent_anomaly::AgentAnomalyDetector>,
    /// Native in-process relational SQL engine for host discovery & telemetry audits (siquery-rs parity)
    pub siquery_engine: Arc<osoosi_agent_anomaly::SiqueryEngine>,
    /// Cached latest siquery EDR multi-table audit sweep telemetry
    pub siquery_last_telemetry: Arc<parking_lot::RwLock<Option<serde_json::Value>>>,
    /// Autonomous MITRE ATT&CK + MITRE ATLAS™ STIX 2.1 Refresh Synchronizer
    pub mitre_synchronizer: Arc<mitre::AutonomousMitreSynchronizer>,
    /// Autonomous AI Threat Feed Ingestion & FeedPoisoningSanitizer Collector
    pub ai_feed_collector: Arc<ai_feeds::AutonomousAiFeedCollector>,
    /// RL Adaptive Controller (SkyRL-aligned multi-technique containment & voter weight optimization)
    pub rl_controller: Arc<parking_lot::RwLock<osoosi_agent_anomaly::RLAdaptiveController>>,
}
