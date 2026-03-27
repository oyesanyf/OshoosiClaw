//! OpenỌ̀ṣọ́ọ̀sì Agentic EDR Orchestrator (The "Core").
//!
//! Connects Telemetry, Policy, Wire (P2P), and Runtime.

pub mod attack_graph;
pub mod backup;
pub mod baseline;
pub mod firewall;
pub mod software_replacement;
pub mod forensics;
pub mod privilege;
pub mod quarantine;
pub mod triage;
pub mod yara_gen;
pub mod shield;
pub mod relativistic;
pub mod gossip;
pub mod system_check;
pub mod pii;
pub mod openshell;
pub mod config_integrity;
pub mod hardened;
pub mod landlock;
pub mod watchdog;
pub mod canary;
pub mod browser_guard;
pub mod capa_analyzer;

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use osoosi_memory::MemoryStore;
use osoosi_telemetry::SysmonParser;
use osoosi_policy::{PolicyEngine, ThreatFeedFetcher};
use osoosi_wire::{MeshNode, MeshCommand, JoinGate};
use osoosi_runtime::{DeceptionManager, TarpitManager};
use osoosi_types::{SysmonEvent, load_runtime_config};
use osoosi_audit::AuditTrail;
use osoosi_repair::PatchEngine;
use osoosi_trust::TrustManager;
use osoosi_model::{ThreatModel, ModelConfig, MalwareScanner};
use crate::forensics::ForensicStoryteller;
use tracing::{debug, info, warn, error};

/// Repair status tuple: (last_cve, last_state, last_sig, last_at, pending_count, last_error).
pub type RepairStatus = (Option<String>, Option<String>, Option<String>, Option<String>, u32, Option<String>);

#[derive(Clone)]
pub struct EdrOrchestrator {
    /// Memory: Local persistence
    memory: Arc<MemoryStore>,
    /// Mesh peer count (updated when peers are approved)
    mesh_peer_count: Arc<AtomicU32>,
    /// Start time for uptime calculation
    start_time: Instant,
    /// Telemetry: Parse Sysmon logs (reserved for future use)
    #[allow(dead_code)]
    telemetry: Arc<SysmonParser>,
    /// Policy: Reasoning with NVD/KEV intelligence
    policy: Arc<PolicyEngine>,
    /// Wire: P2P Gossip intelligence sharing (used for broadcast when mesh is running)
    mesh: Arc<tokio::sync::Mutex<Option<MeshNode>>>,
    /// Channel to send commands to the mesh task (broadcast, approve peer)
    mesh_command_tx: Arc<tokio::sync::Mutex<Option<tokio::sync::mpsc::Sender<MeshCommand>>>>,
    /// Runtime: Active Response (Ghost/Tarpit)
    response: Arc<DeceptionManager>,
    /// Audit: Tamper-evident Merkle Logchain
    audit: Arc<AuditTrail>,
    /// Trust: Identity and Attestation
    trust: Arc<TrustManager>,
    /// Telemetry: File System Watcher
    watcher: Arc<tokio::sync::Mutex<osoosi_telemetry::FileWatcher>>,
    /// Repair Engine: Patch discovery and application
    patch_engine: Arc<PatchEngine>,
    /// Local model trained on self + peer data (stored in models/)
    threat_model: Arc<tokio::sync::RwLock<ThreatModel>>,
    /// Malware scanner (PE features + ML + signatures)
    malware_scanner: Arc<MalwareScanner>,
    /// LLM triage: high-confidence threats awaiting agent decision
    triage_store: crate::triage::TriageStore,
    /// Behavioral baseline for anomaly detection
    baseline: Arc<crate::baseline::BehavioralBaseline>,
    /// Policy Consensus tracking (Mesh-validated patches)
    policy_consensus: Arc<tokio::sync::Mutex<HashMap<String, Vec<osoosi_types::PolicyConsensusMessage>>>>,
    /// Approval Queue for high-stakes autonomous actions
    approval_queue: Arc<tokio::sync::Mutex<Vec<osoosi_sandbox::ApprovalRequest>>>,
    /// Sandbox Executor for isolated tool execution
    sandbox: Arc<osoosi_sandbox::SandboxExecutor>,
    /// Shield Layer for Taint/SSRF/Policy protection
    shield: Arc<crate::shield::ShieldLayer>,
    /// Holographic Deception Sharding (HDS) Engine
    holograph: Arc<osoosi_wire::holograph::HolographEngine>,
    /// Relativistic Guard (Einstein Engine)
    relativistic: Arc<crate::relativistic::RelativisticGuard>,
    /// Behavioral Classifier (SecureBERT + Rules + Feedback)
    behavioral_classifier: Arc<osoosi_behavioral::BehavioralClassifier>,
    /// Behavioral AI Analyzer (OpenAI/Azure adapted from AIEventAnalyzer)
    behavioral_analyzer: Arc<osoosi_behavioral::BehavioralAnalyzer>,
    /// PII Classifier (Presidio + Tika + Magika fallback)
    #[allow(dead_code)]
    pii_classifier: Arc<crate::pii::PiiClassifier>,
    /// Browser security auditor (extensions, search hijacking)
    browser_guard: Arc<crate::browser_guard::BrowserGuard>,
    /// CAPA: Deep capability analysis for unknown files
    capa_analyzer: Arc<crate::capa_analyzer::CapaAnalyzer>,
    /// NSRL "Known Good" Cache (SHA1 -> IsValid) to avoid SQLite hits for every process spawn.
    nsrl_cache: Arc<dashmap::DashMap<String, bool>>,
    /// Runtime paths (db_path, traps_path) from config
    runtime_config: osoosi_types::RuntimeConfig,
}
impl EdrOrchestrator {
    pub fn behavioral_classifier(&self) -> Arc<osoosi_behavioral::BehavioralClassifier> {
        self.behavioral_classifier.clone()
    }

    pub fn memory(&self) -> Arc<MemoryStore> {
        self.memory.clone()
    }

    /// Add feedback to the behavioral model (Continuous Learning)
    pub fn learn_behavior(&self, sentence: &str, is_suspicious: bool) {
        self.behavioral_classifier.learn(sentence, is_suspicious);
    }

    pub fn analyzer(&self) -> Arc<osoosi_behavioral::BehavioralAnalyzer> {
        self.behavioral_analyzer.clone()
    }

    /// Explicitly trigger a patch discovery cycle.
    pub fn trigger_patch_discovery(&self) {
        let engine = self.patch_engine.clone();
        tokio::spawn(async move {
            let _ = engine.run_discovery().await;
        });
    }

    fn dns_domain_candidates(query_name: &str) -> Vec<String> {
        let normalized = query_name
            .trim()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        let labels: Vec<&str> = normalized.split('.').filter(|s| !s.is_empty()).collect();
        if labels.len() < 2 {
            return Vec::new();
        }
        let mut out = Vec::new();
        for i in 0..(labels.len() - 1) {
            let candidate = labels[i..].join(".");
            out.push(candidate);
        }
        out
    }

    async fn lookup_domain_age_days(&self, query_name: &str) -> anyhow::Result<Option<i64>> {
        if std::env::var("OSOOSI_OFFLINE_MODE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
        {
            return Ok(None);
        }
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(4))
            .build()?;

        for domain in Self::dns_domain_candidates(query_name) {
            let url = format!("https://rdap.org/domain/{}", domain);
            let resp = client.get(&url).send().await;
            let Ok(resp) = resp else {
                continue;
            };
            if !resp.status().is_success() {
                continue;
            }
            let val: serde_json::Value = resp.json().await?;
            let created_at = val
                .get("events")
                .and_then(|v| v.as_array())
                .and_then(|events| {
                    events.iter().find_map(|ev| {
                        let action = ev
                            .get("eventAction")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default()
                            .to_ascii_lowercase();
                        if action.contains("registration") || action.contains("created") {
                            ev.get("eventDate")
                                .and_then(|v| v.as_str())
                                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                                .map(|dt| dt.with_timezone(&chrono::Utc))
                        } else {
                            None
                        }
                    })
                });
            if let Some(created) = created_at {
                let age_days = (chrono::Utc::now() - created).num_days().max(0);
                return Ok(Some(age_days));
            }
        }
        Ok(None)
    }

    async fn lookup_otx_domain_hits(&self, query_name: &str) -> anyhow::Result<u64> {
        if std::env::var("OSOOSI_OFFLINE_MODE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
        {
            return Ok(0);
        }
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(4))
            .build()?;
        let api_key = std::env::var("OTX_API_KEY").ok();
        let mut max_hits = 0u64;

        for domain in Self::dns_domain_candidates(query_name) {
            let url = format!("https://otx.alienvault.com/api/v1/indicators/domain/{}/general", domain);
            let mut req = client.get(&url);
            if let Some(ref k) = api_key {
                let key = k.trim();
                if !key.is_empty() {
                    req = req.header("X-OTX-API-KEY", key);
                }
            }
            let resp = req.send().await;
            let Ok(resp) = resp else {
                continue;
            };
            if !resp.status().is_success() {
                continue;
            }
            let val: serde_json::Value = resp.json().await?;
            let hits = val
                .get("pulse_info")
                .and_then(|p| p.get("count"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            max_hits = max_hits.max(hits);
        }

        Ok(max_hits)
    }

    async fn analyze_dns_query_risk(&self, event: &SysmonEvent) -> Option<osoosi_types::ThreatSignature> {
        let query_name = event
            .data
            .get("QueryName")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())?;

        let max_age_days: i64 = std::env::var("OSOOSI_NEW_DOMAIN_MAX_AGE_DAYS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(30);

        let age_days = match self.lookup_domain_age_days(query_name).await {
            Ok(Some(days)) => days,
            Ok(None) => {
                debug!("DNS enrichment: no RDAP registration date for {}", query_name);
                return None;
            }
            Err(e) => {
                debug!("DNS enrichment: domain age lookup failed for {}: {}", query_name, e);
                return None;
            }
        };

        if age_days > max_age_days {
            return None;
        }

        let otx_hits = self.lookup_otx_domain_hits(query_name).await.unwrap_or(0);
        let mut sig = osoosi_types::ThreatSignature::new(event.computer.clone());
        sig.process_name = event
            .data
            .get("Image")
            .and_then(|i| i.as_str())
            .and_then(|p| std::path::Path::new(p).file_name())
            .and_then(|n| n.to_str())
            .map(String::from);
        sig.cve_id = Some(format!("DNS-NEW-DOMAIN:{}", query_name.to_ascii_lowercase()));

        if otx_hits > 0 {
            sig.confidence = 0.92;
            sig.recommended_action = osoosi_types::ResponseAction::GhostTarpit;
            warn!(
                "DNS risk: newly registered domain '{}' (age={}d) has OTX hits={} (suspicious)",
                query_name, age_days, otx_hits
            );
        } else {
            sig.confidence = 0.70;
            sig.recommended_action = osoosi_types::ResponseAction::Alert;
            warn!(
                "DNS risk: newly registered domain '{}' (age={}d) without current OTX hits (watchlist)",
                query_name, age_days
            );
        }

        Some(sig)
    }

    pub async fn new() -> anyhow::Result<Self> {
        let runtime_config = load_runtime_config();
        let memory = Arc::new(MemoryStore::new(&runtime_config.db_path)?);
        let telemetry = Arc::new(SysmonParser::new());
        let policy = Arc::new(PolicyEngine::new(memory.clone()));
        let sigma_dir = std::env::var("OSOOSI_SIGMA_DIR").unwrap_or_else(|_| "sigma".to_string());
        policy.load_sigma_rules(std::path::Path::new(&sigma_dir));
        let mesh = Arc::new(tokio::sync::Mutex::new(Some(MeshNode::new().await?)));
        let mesh_command_tx = Arc::new(tokio::sync::Mutex::new(None));
        let response = Arc::new(DeceptionManager::new());
        let audit = Arc::new(AuditTrail::new());
        let trust = Arc::new(TrustManager::new()?);
        let exclude_paths = osoosi_types::load_exclude_paths_from_config();
        let watcher = Arc::new(tokio::sync::Mutex::new(
            osoosi_telemetry::FileWatcher::new(Some(memory.clone()), exclude_paths)?
        ));
        let mesh_peer_count = Arc::new(AtomicU32::new(0));
        let repair_config = osoosi_types::load_repair_config();
        let patch_engine = Arc::new(PatchEngine::new(audit.clone(), repair_config));
        let model_config = ModelConfig {
            models_dir: std::env::var("OSOOSI_MODELS_DIR").unwrap_or_else(|_| "models".to_string()),
            min_samples: std::env::var("OSOOSI_MODEL_MIN_SAMPLES").ok().and_then(|s| s.parse().ok()).unwrap_or(10),
            ..Default::default()
        };
        let threat_model = Arc::new(tokio::sync::RwLock::new(ThreatModel::new(model_config)));

        let malware_model_path = std::path::PathBuf::from(
            std::env::var("OSOOSI_MODELS_DIR").unwrap_or_else(|_| "models".to_string())
        ).join("malware").join("malware_model.json");
        let malware_scanner = Arc::new(MalwareScanner::new(&malware_model_path));
        let triage_store = crate::triage::new_triage_store();
        let baseline = Arc::new(crate::baseline::BehavioralBaseline::new());
        let sandbox = Arc::new(osoosi_sandbox::SandboxExecutor::new(audit.clone(), memory.clone(), malware_scanner.clone())?);
        let approval_queue = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let shield = Arc::new(crate::shield::ShieldLayer::new());
        let node_id = trust.did().to_string();
        let holograph = Arc::new(osoosi_wire::holograph::HolographEngine::new(node_id));
        let relativistic = Arc::new(crate::relativistic::RelativisticGuard::new());
        let behavioral_classifier = Arc::new(osoosi_behavioral::BehavioralClassifier::new().await);
        let behavioral_analyzer = Arc::new(osoosi_behavioral::BehavioralAnalyzer::new());
        let pii_classifier = Arc::new(crate::pii::PiiClassifier::new());
        let browser_guard = Arc::new(crate::browser_guard::BrowserGuard::new(memory.clone(), audit.clone()));
        let capa_analyzer = Arc::new(crate::capa_analyzer::CapaAnalyzer::new(memory.clone()));
        let nsrl_cache = Arc::new(dashmap::DashMap::new());

        Ok(Self {
            memory,
            mesh_peer_count,
            start_time: Instant::now(),
            telemetry,
            policy,
            mesh,
            mesh_command_tx,
            response,
            audit,
            trust,
            watcher,
            patch_engine,
            threat_model,
            malware_scanner,
            triage_store,
            baseline,
            policy_consensus: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            approval_queue,
            sandbox,
            shield,
            holograph,
            relativistic,
            behavioral_classifier,
            behavioral_analyzer,
            pii_classifier,
            browser_guard,
            capa_analyzer,
            nsrl_cache,
            runtime_config,
        })
    }

    /// Start the P2P Mesh event loop.
    pub async fn start_p2p_loop(&self) {
        let _mesh_mutex = self.mesh.clone();
        let _orchestrator = self.clone();

        // Placeholder: mesh lifecycle would be managed here.
        // In a real implementation, MeshNode would run in its own task.
    }

    /// Start background maintenance loop for rule updates and health checks.
    pub fn start_maintenance_loop(&self) {
        let orchestrator = self.clone();
        tokio::spawn(async move {
            info!("Starting Rule Maintenance Loop (YARA, Sigma, ClamAV)...");
            
            // 1. YARA Update (Core Forge + Agentic Discovery) - offload to blocking pool
            tokio::task::spawn_blocking(|| {
                osoosi_model::malware::MalwareScanner::update_yara_rules_on_startup();
            });

            let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600 * 4)); // Every 4 hours
            loop {
                interval.tick().await;
                info!("Running periodic rule maintenance...");

                // 2. Sigma Rule Refresh - offload to blocking pool
                let sigma_dir = std::env::var("OSOOSI_SIGMA_DIR").unwrap_or_else(|_| "sigma".to_string());
                let orch_clone = orchestrator.clone();
                tokio::task::spawn_blocking(move || {
                    orch_clone.policy.load_sigma_rules(std::path::Path::new(&sigma_dir));
                });

                // 3. ClamAV Health Check / Update
                #[cfg(target_os = "windows")]
                {
                    tokio::task::spawn_blocking(|| {
                        let _ = std::process::Command::new("freshclam").status();
                    });
                }
                
                #[cfg(not(target_os = "windows"))]
                {
                    tokio::task::spawn_blocking(|| {
                         let _ = std::process::Command::new("freshclam").status();
                    });
                }
            }
        });
    }

    /// CEREBUS port: CyberShield Real-Time Monitor
    /// Tracks processes for high resource usage and suspicious behavior.
    pub fn start_cybershield_monitor(&self) {
        let orchestrator = self.clone();
        tokio::spawn(async move {
            use sysinfo::*;
            let mut sys = System::new_all();
            info!("CyberShield Real-Time Monitor active (CEREBUS-AI port).");

            // Auto-start browser auditor alongside cybershield
            orchestrator.start_browser_auditor();
            
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            loop {
                interval.tick().await;
                sys.refresh_all();
                
                let total_memory = sys.total_memory();
                let memory_threshold = total_memory / 2; // 50%
                let my_pid = Pid::from(std::process::id() as usize);
                
                for (pid, process) in sys.processes() {
                    if *pid == my_pid {
                        continue; // NEVER scan self
                    }

                    let cpu_usage = process.cpu_usage();
                    let memory_usage = process.memory();
                    
                    // Higher thresholds for alerting (3.0 cores CPU, 50% RAM)
                    if cpu_usage > 300.0 || memory_usage > memory_threshold {
                        let process_name = process.name();
                        let exe_path = process.exe();
                        
                        warn!(
                            "CyberShield Insight: Process {} (PID {}) exceeds resource thresholds (CPU: {:.1}%, Mem: {}KB).",
                            process_name, pid, cpu_usage, memory_usage / 1024
                        );
                        
                        // Analyze the image path immediately using the CEREBUS-enhanced MalwareScanner
                        if let Some(path) = exe_path {
                            if let Some(result) = orchestrator.malware_scanner.scan_file(path) {
                                if result.clam_detected == Some(false) {
                                    orchestrator.audit.log("CLAMAV_CLEAN", serde_json::json!({
                                        "file_path": result.file_path,
                                        "context": "CyberShield",
                                        "process_name": process_name,
                                        "action": "allowed",
                                    }));
                                    continue; // ClamAV says clean — let it go
                                }
                                if result.is_malware {
                                    warn!("CyberShield INTERCEPTION: High-resource process {} is MALICIOUS. Triggering active response.", process_name);
                                    
                                    // NEW: Holographic Deception Sharding (HDS) activation
                                    // Calculate "fake" attacker IP (prototype uses local loopback for testing)
                                    let _ = orchestrator.activate_mesh_hologram("127.0.0.1").await;

                                    // Tarpit the suspicious process
                                    let pid_str = pid.to_string();
                                    #[cfg(target_os = "windows")]
                                    let _ = std::process::Command::new("powershell")
                                        .args(["-NoProfile", "-Command", &format!("Suspend-Process -Id {}", pid_str)])
                                        .status();
                                }
                            }
                        }
                    }
                }
            }
        });
    }

    /// Start behavioral detector: streams System/Application logs (Windows, Linux, macOS)
    /// into SecureBERT-style classification. First detection layer before file/malware scan.
    pub fn start_behavioral_detector(&self) {
        let orchestrator = self.clone();
        tokio::spawn(async move {
            let reader = osoosi_behavioral::BehavioralLogReader::new();
            let classifier = orchestrator.behavioral_classifier.clone();
            let analyzer = &orchestrator.behavioral_analyzer;
            let interval_secs: u64 = std::env::var("OSOOSI_BEHAVIORAL_INTERVAL")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(10);
            info!("Behavioral detector active (System/App logs, interval: {}s)", interval_secs);
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
            loop {
                interval.tick().await;
                match reader.poll_events() {
                    Ok(events) => {
                        for event in events {
                            // Tier 1: CoLog Autonomous Sequence Check
                            let colog_score = analyzer.autonomous_check(&event);
                            if colog_score > 0.7 {
                                warn!("COLOG ANOMALY: Sequence deviation detected (score={:.2}) for source {}", colog_score, event.source);
                                orchestrator.audit.log("COLOG_ANOMALY", serde_json::json!({
                                    "source": event.source,
                                    "score": colog_score,
                                    "event_id": event.event_id,
                                    "data": event.data.get("Message"),
                                }));
                            }

                            // Layer 2: SecureBERT / Rule-based Classification
                            let result = classifier.classify(&event).await;
                            if result.is_suspicious {
                                warn!(
                                    "BEHAVIORAL ALERT: {} (score={:.2}, reason={})",
                                    result.sentence.chars().take(80).collect::<String>(),
                                    result.score,
                                    result.reason
                                );
                                orchestrator.audit.log("BEHAVIORAL_ALERT", serde_json::json!({
                                    "sentence": result.sentence,
                                    "score": result.score,
                                    "reason": result.reason,
                                    "event_id": result.event_id,
                                    "source": result.source,
                                }));
                            }
                        }
                    }
                    Err(e) => {
                        tracing::debug!("Behavioral log poll failed: {}", e);
                    }
                }
            }
        });
    }

    /// Start watching directories for changes. Call once with all paths.
    pub async fn start_file_watcher(&self, path: &str) -> anyhow::Result<()> {
        self.start_file_watcher_paths(&[path]).await
    }

    /// Start watching multiple directories. Active real-time monitoring.
    pub async fn start_file_watcher_paths(&self, paths: &[&str]) -> anyhow::Result<()> {
        {
            let mut watcher: tokio::sync::MutexGuard<osoosi_telemetry::FileWatcher> = self.watcher.lock().await;
            for path in paths {
                if let Err(e) = watcher.watch(path) {
                    tracing::warn!("Could not watch {}: {}", path, e);
                }
            }
        }
        
        // Start background OS file baseline hash on startup
        let baseline_memory = self.memory.clone();
        let baseline_paths: Vec<String> = paths.iter().map(|&s| s.to_string()).collect();
        let baseline_excludes = osoosi_types::load_exclude_paths_from_config();
        tokio::spawn(async move {
            osoosi_telemetry::build_os_file_hash_baseline(baseline_paths, baseline_memory, baseline_excludes).await;
        });

        let orchestrator = self.clone();
        tokio::spawn(async move {
            let mut watcher: tokio::sync::MutexGuard<osoosi_telemetry::FileWatcher> = orchestrator.watcher.lock().await;
            while let Some(res) = watcher.next_event().await {
                if let Ok(event) = res {
                    info!("File change detected: {} (Hash: {})", event.path, event.hash);
                    let _ = orchestrator.memory.update_file_hash(&event.path, &event.hash);

                    // Magika pre-filter: only executable/scannable files go to the full scanner
                    let path = std::path::Path::new(&event.path);
                    if let Some(result) = orchestrator.malware_scanner.scan_file(path) {
                        // ClamAV says clean → let it go (trust ClamAV over ML/signatures)
                        if result.clam_detected == Some(false) {
                            info!("ClamAV clean: {} — allowing (no action)", result.file_path);
                            orchestrator.audit.log("CLAMAV_CLEAN", serde_json::json!({
                                "file_path": result.file_path,
                                "magika_label": result.magika_label,
                                "combined_score": result.combined_score,
                                "action": "allowed",
                            }));
                            continue;
                        }
                        if result.is_malware {
                            warn!(
                                "MALWARE DETECTED: {} (magika={}, type={}, ml={:.2}, sig={:.2}, combined={:.2})",
                                result.file_path, result.magika_label, result.malware_type,
                                result.ml_score, result.signature_score, result.combined_score
                            );
                            // Broadcast to mesh for distributed EMBER training (PE samples with features)
                            if let Some(ref features) = result.features {
                                let autonomy = osoosi_types::load_autonomy_config();
                                if result.combined_score >= autonomy.quarantine_confidence_threshold as f64 {
                                    let sample = osoosi_types::MalwareSample {
                                        source_node: orchestrator.trust.did().to_string(),
                                        file_hash: result.file_hash.clone(),
                                        label: 0, // malware
                                        features: features.clone(),
                                        feature_version: "legacy".to_string(),
                                        timestamp: chrono::Utc::now(),
                                    };
                                    if let Some(ref tx) = *orchestrator.mesh_command_tx.lock().await {
                                        let _ = tx.try_send(osoosi_wire::MeshCommand::BroadcastMalwareSample(sample));
                                    }
                                }
                            }
                            orchestrator.audit.log("MALWARE_DETECTED", serde_json::json!({
                                "file_path": result.file_path,
                                "file_hash": result.file_hash,
                                "magika_label": result.magika_label,
                                "malware_type": result.malware_type,
                                "ml_score": result.ml_score,
                                "signature_score": result.signature_score,
                                "combined_score": result.combined_score,
                                "evasion": result.evasion_indicators,
                            }));

                            // Autonomous: try search-and-replace first, then quarantine
                            let autonomy = osoosi_types::load_autonomy_config();
                            let path_excluded = autonomy.quarantine_exclude_paths.iter()
                                .any(|p| result.file_path.contains(p));
                            let should_quarantine = !path_excluded
                                && autonomy.auto_quarantine_malware
                                && (result.combined_score >= autonomy.quarantine_confidence_threshold as f64
                                    || result.clam_detected == Some(true)
                                    || result.malware_type.contains("EICAR"));
                            if path_excluded && result.is_malware {
                                info!("Malware in excluded path (cloud sync temp?): {} — alert only, no quarantine", result.file_path);
                            } else if autonomy.auto_replace_malware_binaries && should_quarantine {
                                // Search for vuln-free version and replace (no hardcoded URLs)
                                if let Some(download_url) = crate::software_replacement::resolve_replacement_url(&result.file_path).await {
                                    match orchestrator.patch_engine.remediate_file(&result.file_path, &download_url).await {
                                        Ok(backup) => {
                                            info!("Replaced compromised binary {} with clean version from {} (backup: {:?})", result.file_path, download_url, backup);
                                            orchestrator.audit.log("MALWARE_REPLACED", serde_json::json!({
                                                "file_path": result.file_path,
                                                "download_url": download_url,
                                                "backup": backup.to_string_lossy(),
                                            }));
                                        }
                                        Err(e) => {
                                            warn!("Search-and-replace failed for {}: {}. Falling back to quarantine.", result.file_path, e);
                                            if let Err(qe) = crate::quarantine::quarantine_file(&result.file_path, &autonomy.quarantine_path) {
                                                error!("Failed to quarantine malware file {}: {}", result.file_path, qe);
                                            } else {
                                                info!("Quarantined malware: {} -> {} (conf={:.2})", result.file_path, autonomy.quarantine_path, result.combined_score);
                                            }
                                        }
                                    }
                                } else if let Err(e) = crate::quarantine::quarantine_file(&result.file_path, &autonomy.quarantine_path) {
                                    error!("Failed to quarantine malware file {}: {}", result.file_path, e);
                                } else {
                                    info!("Quarantined malware: {} -> {} (conf={:.2})", result.file_path, autonomy.quarantine_path, result.combined_score);
                                }
                            } else if should_quarantine {
                                if let Err(e) = crate::quarantine::quarantine_file(&result.file_path, &autonomy.quarantine_path) {
                                    error!("Failed to quarantine malware file {}: {}", result.file_path, e);
                                } else {
                                    info!("Quarantined malware: {} -> {} (conf={:.2})", result.file_path, autonomy.quarantine_path, result.combined_score);
                                }
                            } else if autonomy.auto_quarantine_malware && result.is_malware {
                                info!("Malware detected but below quarantine threshold (conf={:.2} < {:.2}): alert only", result.combined_score, autonomy.quarantine_confidence_threshold);
                            }
                        }
                    }
                }
            }
        });
        Ok(())
    }

    /// Start polling host security event logs (Windows Event Log, Linux auditd, macOS audit).
    /// Events are fed into the policy engine for protection.
    pub async fn start_host_event_loop(&self, event_channel_or_path: &str, poll_interval_secs: u64) {
        let channel = if event_channel_or_path.is_empty() {
            #[cfg(target_os = "windows")]
            { "Microsoft-Windows-Sysmon/Operational".to_string() }
            #[cfg(target_os = "linux")]
            { "default".to_string() }
            #[cfg(target_os = "macos")]
            { "default".to_string() }
            #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
            { "default".to_string() }
        } else {
            event_channel_or_path.to_string()
        };

        match osoosi_telemetry::create_host_event_reader(&channel) {
            Ok(mut reader) => {
                let resolved_source = reader.source_name();
                let orchestrator = self.clone();
                let interval = poll_interval_secs;
                tokio::spawn(async move {
                    info!(
                        "Host security event loop started (requested: {}, resolved: {})",
                        channel, resolved_source
                    );
                    let mut last_access_denied_log: Option<std::time::Instant> = None;
                    let mut last_channel_missing_log: Option<std::time::Instant> = None;
                    loop {
                        match reader.poll_events() {
                            Ok(events) => {
                                for ev in events {
                                    let sysmon = ev.to_sysmon_event();
                                    if let Err(e) = orchestrator.process_telemetry(sysmon).await {
                                        error!("Failed to process host event: {}", e);
                                    }
                                }
                            }
                            Err(e) => {
                                let is_access_denied = e.to_string().contains("access denied");
                                let is_channel_missing = e.to_string().contains("channel")
                                    && e.to_string().contains("not found");
                                if is_access_denied {
                                    let should_log = last_access_denied_log
                                        .map(|t| t.elapsed().as_secs() >= 300)
                                        .unwrap_or(true);
                                    if should_log {
                                        error!("Host event poll failed: {}. Run scripts/grant-sysmon-read.ps1 as Admin to fix.", e);
                                        last_access_denied_log = Some(std::time::Instant::now());
                                    }
                                } else if is_channel_missing {
                                    let should_log = last_channel_missing_log
                                        .map(|t| t.elapsed().as_secs() >= 300)
                                        .unwrap_or(true);
                                    if should_log {
                                        error!("Host event poll failed: {}.", e);
                                        last_channel_missing_log = Some(std::time::Instant::now());
                                    }
                                } else {
                                    error!("Host event poll failed: {}", e);
                                }
                            }
                        }
                        tokio::time::sleep(tokio::time::Duration::from_secs(interval)).await;
                    }
                });
            }
            Err(e) => {
                error!("Could not create host event reader: {}. Host logs will not be monitored.", e);
            }
        }
    }

    /// Background task for Repair Engine: discover patches, optionally apply.
    pub async fn start_repair_loop(&self, interval_secs: u64, auto_apply: bool) {
        let engine = self.patch_engine.clone();
        let memory = self.memory.clone();
        let mesh_tx = self.mesh_command_tx.clone();
        let trust = self.trust.clone();
        tokio::spawn(async move {
            info!("Repair Engine started (interval: {}s, auto_apply: {})", interval_secs, auto_apply);
            loop {
                match engine.run_discovery().await {
                    Ok(patches) => {
                        let count = patches.len();
                        if count > 0 {
                            info!("Repair Engine: discovered {} missing patches", count);
                            let _ = memory.set_repair_status("pending_count", &count.to_string());
                            if auto_apply {
                                let mut applied_count: usize = 0;
                                for patch in patches {
                                    match engine.apply_patch(patch).await {
                                        Ok(tx) => {
                                            if matches!(tx.state, osoosi_types::PatchState::Committed) {
                                                applied_count += 1;
                                                // Broadcast successful local repair to the mesh
                                                let vote = osoosi_types::PolicyConsensusMessage::Vote(osoosi_types::PolicyHealthVote {
                                                    policy_id: tx.patch.cve_id.clone(),
                                                    voter_id: trust.did().id.clone(),
                                                    status: osoosi_types::PolicyHealthStatus::Optimal,
                                                    uptime_seconds: 0, // Placeholder
                                                    timestamp: chrono::Utc::now(),
                                                });
                                                let tx_guard = mesh_tx.lock().await;
                                                if let Some(ref tx_chan) = *tx_guard {
                                                    let _ = tx_chan.send(MeshCommand::BroadcastConsensus(vote)).await;
                                                }
                                            }
                                            let _ = memory.set_repair_status("last_cve", &tx.patch.cve_id);
                                            let _ = memory.set_repair_status("last_state", &format!("{:?}", tx.state));
                                            let _ = memory.set_repair_status("last_component", &tx.patch.component);
                                            if let Some(ref sid) = tx.snapshot_id {
                                                let _ = memory.set_repair_status("last_snapshot_id", sid);
                                            }
                                            let sig_short = if tx.transaction_id.len() >= 12 {
                                                format!("0x{}...{}", &tx.transaction_id[..6], &tx.transaction_id[tx.transaction_id.len()-4..])
                                            } else {
                                                tx.transaction_id.clone()
                                            };
                                            let _ = memory.set_repair_status("last_sig", &sig_short);
                                            let _ = memory.set_repair_status("last_at", &tx.started_at.to_rfc3339());
                                            let _ = memory.set_repair_status("last_error", "");
                                        }
                                        Err(e) => {
                                            error!("Repair Engine apply failed: {}", e);
                                            let _ = memory.set_repair_status("last_state", "ApplyFailed");
                                            let _ = memory.set_repair_status("last_error", &e.to_string());
                                        }
                                    }
                                }
                                let remaining = count.saturating_sub(applied_count);
                                let _ = memory.set_repair_status("pending_count", &remaining.to_string());
                            }
                        } else {
                            let _ = memory.set_repair_status("pending_count", "0");
                        }
                    }
                    Err(e) => error!("Repair Engine discovery failed: {}", e),
                }
                tokio::time::sleep(tokio::time::Duration::from_secs(interval_secs)).await;
            }
        });
    }



    /// Trigger one repair cycle (discovery + apply). Used by LLM agent.
    pub async fn trigger_repair_cycle(&self, auto_apply: bool) -> anyhow::Result<serde_json::Value> {
        let patches = self.patch_engine.run_discovery().await?;
        let count = patches.len();
        let _ = self.memory.set_repair_status("pending_count", &count.to_string());
        let mut applied = 0usize;
        if auto_apply && count > 0 {
            for patch in patches {
                match self.patch_engine.apply_patch(patch).await {
                    Ok(tx) => {
                        if matches!(tx.state, osoosi_types::PatchState::Committed) {
                            applied += 1;
                            // Broadcast success to mesh
                            let vote = osoosi_types::PolicyConsensusMessage::Vote(osoosi_types::PolicyHealthVote {
                                policy_id: tx.patch.cve_id.clone(),
                                voter_id: self.trust.did().id.clone(),
                                status: osoosi_types::PolicyHealthStatus::Optimal,
                                uptime_seconds: 0,
                                timestamp: chrono::Utc::now(),
                            });
                            let tx_guard = self.mesh_command_tx.lock().await;
                            if let Some(ref tx_chan) = *tx_guard {
                                let _ = tx_chan.send(MeshCommand::BroadcastConsensus(vote)).await;
                            }
                        }
                        let _ = self.memory.set_repair_status("last_cve", &tx.patch.cve_id);
                        let _ = self.memory.set_repair_status("last_state", &format!("{:?}", tx.state));
                        let _ = self.memory.set_repair_status("last_component", &tx.patch.component);
                        if let Some(ref sid) = tx.snapshot_id {
                            let _ = self.memory.set_repair_status("last_snapshot_id", sid);
                        }
                        let _ = self.memory.set_repair_status("last_error", "");
                    }
                    Err(e) => {
                        let _ = self.memory.set_repair_status("last_state", "ApplyFailed");
                        let _ = self.memory.set_repair_status("last_error", &e.to_string());
                    }
                }
            }
        }
        Ok(serde_json::json!({
            "discovered": count,
            "applied": applied,
            "auto_apply": auto_apply,
        }))
    }

    /// Background task to fetch latest threat feeds (KEV, NVD).
    pub async fn start_fetcher_loop(&self) {
        let fetcher = ThreatFeedFetcher::new();
        loop {
            info!("Fetching latest threat intelligence feeds...");
            match fetcher.fetch_kev().await {
                Ok(kevs) => {
                    info!("Successfully loaded {} known exploited vulnerabilities.", kevs.len());
                    if let Err(e) = self.memory.insert_kevs_batch(&kevs) {
                        error!("Failed to persist KEV batch: {} (will retry next cycle)", e);
                    } else {
                        info!("KEV batch persisted successfully.");
                    }
                },
                Err(e) => error!("Failed to fetch CISA KEV feed: {}", e),
            }

            // Optional OTX feed (enabled when OTX_API_KEY is provided).
            if let Ok(api_key) = std::env::var("OTX_API_KEY") {
                let key = api_key.trim();
                if !key.is_empty() {
                    match fetcher.fetch_otx_indicators(key).await {
                        Ok(indicators) => {
                            let total = indicators.total_count();
                            self.policy.update_otx_indicators(indicators);
                            info!("Successfully loaded {} OTX indicators.", total);
                        }
                        Err(e) => error!("Failed to fetch OTX indicators: {}", e),
                    }
                }
            }
            // Update cycle: Every 24 hours.
            tokio::time::sleep(tokio::time::Duration::from_secs(86400)).await;
        }
    }

    /// List all pending approval requests from autonomous agents.
    pub async fn list_pending_approvals(&self) -> Vec<osoosi_sandbox::ApprovalRequest> {
        let queue = self.approval_queue.lock().await;
        queue.clone()
    }

    /// Approve or deny a pending request.
    pub async fn process_approval(&self, id: &str, approved: bool) -> anyhow::Result<()> {
        let mut queue = self.approval_queue.lock().await;
        if let Some(pos) = queue.iter().position(|r| r.id == id) {
            let req = queue.remove(pos);
            info!("Approval processed: {} (action: {}, approved: {})", id, req.action, approved);
            self.audit.log("APPROVAL_PROCESSED", serde_json::json!({
                "id": id,
                "action": req.action,
                "approved": approved,
                "timestamp": chrono::Utc::now(),
            }));
        } else {
            return Err(anyhow::anyhow!("Approval request not found: {}", id));
        }
        Ok(())
    }

    /// Run an autonomous remediation script in the WASM sandbox.
    /// Performs yara-scanning of all generated files in the workspace.
    pub async fn run_isolated_action(
        &self, 
        wasm_bytes: &[u8], 
        config: osoosi_sandbox::SandboxConfig,
        taint_labels: std::collections::HashSet<osoosi_types::TaintLabel>,
    ) -> anyhow::Result<osoosi_sandbox::SandboxResult> {
        info!("Running isolated action in WASM sandbox: max_fuel={}", config.max_fuel);
        
        let result = self.sandbox.run_script(wasm_bytes, config.clone(), taint_labels).await?;
        
        // Register pending approvals in the global queue
        if !result.pending_approvals.is_empty() {
            let mut queue = self.approval_queue.lock().await;
            queue.extend(result.pending_approvals.clone());
        }

        // Post-execution: scan the workspace for malicious payloads generated by the script
        for entry in walkdir::WalkDir::new(&config.workspace_dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            if let Some(scan) = self.malware_scanner.scan_file(entry.path()) {
                if scan.clam_detected == Some(false) {
                    self.audit.log("CLAMAV_CLEAN", serde_json::json!({
                        "file_path": entry.path().to_string_lossy(),
                        "context": "Sandbox",
                        "action": "allowed",
                    }));
                    continue; // ClamAV says clean — let it go
                }
                if scan.is_malware {
                    warn!("MALWARE GENERATED IN SANDBOX: {} (type={})", entry.path().display(), scan.malware_type);
                    self.audit.log("SANDBOX_MALWARE_DETECTED", serde_json::json!({
                        "file_path": entry.path().to_string_lossy(),
                        "malware_type": scan.malware_type,
                        "confidence": scan.combined_score,
                    }));
                }
            }
        }

        Ok(result)
    }

    pub async fn process_telemetry(&self, event: SysmonEvent) -> anyhow::Result<()> {
        use osoosi_types::{ResponseAction, SysmonEventId};

        // Log telemetry entry to Merkle Audit Chain
        self.audit.log("TELEMETRY_INGESTED", serde_json::to_value(&event)?);

        info!("Processing Sysmon telemetry: {:?}", event.event_id);

        // Einstein Engine: Check for "Dilation of Truth" (temporal anomalies)
        let temporal_score = self.relativistic.check_temporal_dilation(&event);
        
        // 1. NSRL "Known Good" Fast-Path: Skip deep analysis for trusted binaries.
        // We use a three-tier check: In-Memory L1 -> Persistent L2 -> Authoritative DB L3.
        if let Some(sha1) = event.data.get("Hashes").and_then(|h| h.as_str())
            .and_then(|hashes| hashes.split(',').find(|s| s.starts_with("SHA1=")))
            .map(|s| &s[5..]) {
            
            // Tier 1: In-memory session cache (Extremely fast)
            if let Some(is_good) = self.nsrl_cache.get(sha1) {
                if *is_good {
                    debug!("NSRL Bypass (Memory Cache): Trusted hash {}", sha1);
                    return Ok(());
                }
            }

            // Tier 2: Persistent integrity cache (Checks if hash for this path has been validated before)
            if let Some(path) = event.data.get("Image").and_then(|v| v.as_str()) {
                if let Ok(Some((last_sha1, is_nsrl))) = self.memory.get_file_integrity(path) {
                    if last_sha1 == sha1 && is_nsrl {
                        self.nsrl_cache.insert(sha1.to_string(), true);
                        debug!("NSRL Bypass (Persistent Cache): Trusted path {}", path);
                        return Ok(());
                    }
                }
            }

            // Tier 3: Authoritative NSRL database lookup
            if self.memory.is_nsrl_known_good(sha1).unwrap_or(false) {
                self.nsrl_cache.insert(sha1.to_string(), true);
                if let Some(path) = event.data.get("Image").and_then(|v| v.as_str()) {
                    let _ = self.memory.upsert_file_integrity(path, sha1, true);
                }
                debug!("NSRL Bypass (DB Verified): {} -> Known Good.", 
                    event.data.get("Image").and_then(|i| i.as_str()).unwrap_or("Unknown"));
                return Ok(());
            }
        }

        let mut signature = self.policy.scan_event(&event);
        
        if temporal_score > 0.6 {
            warn!("Einstein Alert: Significant temporal dilation ({}) for event from {}.", temporal_score, event.computer);
            if let Some(ref mut sig) = signature {
                sig.confidence = sig.confidence.max(temporal_score);
                sig.add_reason(format!("Einstein Engine: Critical temporal anomaly detected (score: {:.2})", temporal_score));
            } else {
                let mut sig = osoosi_types::ThreatSignature::new(event.computer.clone());
                sig.confidence = temporal_score;
                sig.add_reason("Einstein Engine: Event rejected/flagged due to temporal paradox.");
                signature = Some(sig);
            }
        }
        // Behavioral baselining: record and detect first-connection anomalies
        let baseline_anomaly = match event.event_id {
            SysmonEventId::NetworkConnect => {
                let proc = event.data.get("Image").and_then(|i| i.as_str())
                    .and_then(|p| std::path::Path::new(p).file_name())
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown");
                let dest = event.data.get("DestinationIp").and_then(|v| v.as_str()).unwrap_or("");
                self.baseline.record_network(&event.computer, proc, dest)
            }
            SysmonEventId::DnsQuery => {
                let proc = event.data.get("Image").and_then(|i| i.as_str())
                    .and_then(|p| std::path::Path::new(p).file_name())
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown");
                let query = event.data.get("QueryName").and_then(|v| v.as_str()).unwrap_or("");
                self.baseline.record_dns(&event.computer, proc, query)
            }
            _ => false,
        };

        if matches!(event.event_id, SysmonEventId::DnsQuery) {
            if let Some(dns_sig) = self.analyze_dns_query_risk(&event).await {
                let take_dns_sig = signature
                    .as_ref()
                    .map(|s| dns_sig.confidence > s.confidence)
                    .unwrap_or(true);
                if take_dns_sig {
                    signature = Some(dns_sig);
                }
            }
        }
        // Baseline anomaly: first outbound connection from process
        if baseline_anomaly {
            if let Some(ref mut sig) = signature {
                sig.add_reason("Behavioral baseline: first outbound connection/query from this process on this host");
                sig.confidence = sig.confidence.max(0.4);
            } else {
                let mut sig = osoosi_types::ThreatSignature::new(event.computer.clone());
                sig.confidence = 0.4;
                sig.process_name = event.data.get("Image").and_then(|i| i.as_str())
                    .and_then(|p| std::path::Path::new(p).file_name())
                    .and_then(|n| n.to_str())
                    .map(String::from);
                sig.add_reason("Behavioral baseline: first outbound connection/query from this process on this host");
                signature = Some(sig);
            }
        }

        if signature.is_none() {
            let proc = event.data.get("Image").and_then(|i| i.as_str())
                .and_then(|p| std::path::Path::new(p).file_name())
                .and_then(|n| n.to_str())
                .map(String::from);
            let cve = event.data.get("CveId").and_then(|c| c.as_str()).map(String::from);
            let model = self.threat_model.read().await;
            let score = model.infer(proc.as_deref(), cve.as_deref());
            if score >= 0.5 {
                let mut sig = osoosi_types::ThreatSignature::new(event.computer.clone());
                sig.confidence = score;
                sig.process_name = proc.clone();
                sig.cve_id = cve.clone();
                sig.add_reason(format!("ML threat model: process {:?} / CVE {:?} scored {:.2}", proc, cve, score));
                if let Some(ref p) = proc {
                    if p.to_lowercase().contains("mimikatz") || p.to_lowercase().contains("lsass") {
                        sig.set_predicted_next("Credential dumping or LSASS access may lead to lateral movement");
                    }
                }
                signature = Some(sig);
            }
        }

        // --- SECOND-TIER: CAPA Analysis for Unknown Files ---
        if signature.is_none() {
             if let Some(image_path) = event.data.get("Image").and_then(|v| v.as_str()) {
                 let path = std::path::Path::new(image_path);
                 // Only run CAPA if NSRL/Cache doesn't know the file
                 let is_known = self.nsrl_cache.contains_key(image_path);
                 
                 if !is_known {
                     match self.capa_analyzer.analyze_file(path).await {
                         Ok(Some(capa_sig)) => {
                             signature = Some(capa_sig);
                             warn!("CAPA Intelligence: Identified critical capabilities in unknown file: {:?}", path);
                         },
                         Ok(None) => debug!("CAPA: No suspicious capabilities found for {:?}", path),
                         Err(e) => error!("CAPA analysis error for {:?}: {}", path, e),
                     }
                 }
             }
        }

        // --- THIRD-TIER: HollowsHunter Memory Forensics (Reactive to Sysmon ETW) ---
        // Trigger conditions:
        //   1. ProcessAccess (Event ID 10) targeting lsass.exe → credential dumping attempt
        //   2. CreateRemoteThread (Event ID 8) → code injection / process hollowing
        // This is the "Pro Shortcut": we use Sysmon's signed kernel driver as our eyes,
        // and HollowsHunter as our hands to scan the suspect process's memory.
        #[cfg(target_os = "windows")]
        {
            let should_memory_scan = match event.event_id {
                SysmonEventId::ProcessAccess => {
                    // Check if target is lsass.exe (credential dumping)
                    let target = event.data.get("TargetImage")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    target.to_lowercase().contains("lsass.exe")
                }
                SysmonEventId::CreateRemoteThread => {
                    // Any remote thread creation is suspicious — scan both source and target
                    true
                }
                _ => false,
            };

            if should_memory_scan {
                let hh_path = osoosi_types::resolve_tool_path("hollows_hunter", "hollows_hunter.exe");
                if hh_path.exists() {
                    // Get the target PID for focused scanning
                    let target_pid = event.data.get("TargetProcessId")
                        .or_else(|| event.data.get("SourceProcessId"))
                        .and_then(|v| v.as_str())
                        .or_else(|| event.data.get("ProcessId").and_then(|v| v.as_str()));

                    if let Some(pid) = target_pid {
                        warn!("MEMORY FORENSICS: Sysmon {:?} triggered HollowsHunter scan on PID {}",
                            event.event_id, pid);
                        
                        let hh_path_clone = hh_path.clone();
                        let pid_str = pid.to_string();
                        let pid_display = pid_str.clone();
                        let computer = event.computer.clone();
                        
                        // Run HollowsHunter in a blocking task to avoid blocking the async loop
                        let hh_result = tokio::task::spawn_blocking(move || {
                            std::process::Command::new(&hh_path_clone)
                                .args(["/pid", &pid_str, "/json", "/quiet", "/shellc", "/iat"])
                                .output()
                        }).await;

                        match hh_result {
                            Ok(Ok(output)) if output.status.success() => {
                                let stdout = String::from_utf8_lossy(&output.stdout);
                                // Parse HollowsHunter JSON output
                                if let Ok(hh_json) = serde_json::from_str::<serde_json::Value>(&stdout) {
                                    let total_suspicious = hh_json.get("summary")
                                        .and_then(|s| s.get("replaced"))
                                        .and_then(|v| v.as_u64())
                                        .unwrap_or(0)
                                        + hh_json.get("summary")
                                            .and_then(|s| s.get("implanted"))
                                            .and_then(|v| v.as_u64())
                                            .unwrap_or(0)
                                        + hh_json.get("summary")
                                            .and_then(|s| s.get("hooks"))
                                            .and_then(|v| v.as_u64())
                                            .unwrap_or(0);

                                    if total_suspicious > 0 {
                                        warn!("MEMORY FORENSICS ALERT: HollowsHunter found {} suspicious implants in PID {}",
                                            total_suspicious, pid_display);
                                        
                                        let mut mem_sig = osoosi_types::ThreatSignature::new(computer);
                                        mem_sig.confidence = 0.95;
                                        mem_sig.process_name = event.data.get("TargetImage")
                                            .or_else(|| event.data.get("SourceImage"))
                                            .and_then(|v| v.as_str())
                                            .and_then(|p| std::path::Path::new(p).file_name())
                                            .and_then(|n| n.to_str())
                                            .map(String::from);
                                        mem_sig.recommended_action = osoosi_types::ResponseAction::Isolate;
                                        mem_sig.add_reason(format!(
                                            "HollowsHunter: {} in-memory implants detected (replaced/injected PEs, shellcode, hooks)",
                                            total_suspicious
                                        ));

                                        // Extract specific findings
                                        if let Some(scanned) = hh_json.get("scanned").and_then(|s| s.as_array()) {
                                            for proc_info in scanned.iter().take(5) {
                                                if let Some(name) = proc_info.get("name").and_then(|v| v.as_str()) {
                                                    let replaced = proc_info.get("replaced").and_then(|v| v.as_u64()).unwrap_or(0);
                                                    let implanted = proc_info.get("implanted").and_then(|v| v.as_u64()).unwrap_or(0);
                                                    if replaced > 0 || implanted > 0 {
                                                        mem_sig.add_reason(format!(
                                                            "Process '{}': {} replaced modules, {} implanted",
                                                            name, replaced, implanted
                                                        ));
                                                    }
                                                }
                                            }
                                        }

                                        // Override any existing signature with memory forensics finding
                                        signature = Some(mem_sig);
                                    } else {
                                        debug!("HollowsHunter: PID {} clean — no in-memory implants found.", pid_display);
                                    }
                                }
                            }
                            Ok(Ok(output)) => {
                                debug!("HollowsHunter exited with status {} for PID {}", output.status, pid_display);
                            }
                            Ok(Err(e)) => {
                                debug!("HollowsHunter execution failed for PID {}: {}", pid_display, e);
                            }
                            Err(e) => {
                                debug!("HollowsHunter task join failed: {}", e);
                            }
                        }
                    }
                }
            }
        }

        if let Some(signature) = signature {
            warn!("ALARM: Threat identified on node {}: {:?}", event.computer, signature);

            // Log detection to Audit Trail (include image_path for dashboard display)
            let mut audit_data = serde_json::to_value(&signature)?.as_object().cloned().unwrap_or_default();
            if let Some(img) = event.data.get("Image").and_then(|v| v.as_str()) {
                audit_data.insert("image_path".to_string(), serde_json::json!(img));
            }
            self.audit.log("THREAT_DETECTED", serde_json::Value::Object(audit_data));
            let _ = self.memory.log_threat(&signature);

            if matches!(event.event_id, SysmonEventId::DnsQuery)
                && crate::firewall::dns_autoblock_enabled()
                && signature.confidence >= crate::firewall::dns_autoblock_min_confidence()
            {
                let query_name = event.data.get("QueryName").and_then(|v| v.as_str());
                let query_results = event.data.get("QueryResults").and_then(|v| v.as_str());
                match crate::firewall::block_dns_destinations(query_name, query_results) {
                    Ok(msg) => {
                        warn!("Firewall DNS auto-block applied: {}", msg);
                        self.audit.log("RESPONSE_ACTION", serde_json::json!({
                            "type": "FirewallDnsBlock",
                            "query_name": query_name,
                            "message": msg
                        }));
                    }
                    Err(e) => {
                        warn!("Firewall DNS auto-block skipped/failed: {}", e);
                    }
                }
            }

            // 1. Broadcast to P2P Mesh immediately (Herd Immunity).
            {
                let tx_guard = self.mesh_command_tx.lock().await;
                if let Some(ref tx) = *tx_guard {
                    // Military-Grade Hardening: Differential Privacy (DP) Broadcast
                    // Adds Laplacian noise to confidence scores to prevent peer fingerprinting.
                    let dp_config = osoosi_dp::PrivacyConfig {
                        epsilon: 0.8, // Privacy budget (smaller = more privacy)
                        min_samples: 3,
                        sensitivity: 1.0,
                    };
                    let _ = tx.send(MeshCommand::BroadcastNoisyThreat(signature.clone(), dp_config)).await;

                    // Phase 3: Shadow Chain (Distributed Audit Ledger)
                    // Broadcast a signed proof of this detection to ensure audit log immutability.
                    let proof = self.audit.root();
                    let _ = tx.try_send(MeshCommand::BroadcastAuditProof(proof));
                }
            }

            // Auto-generated YARA from high-confidence detections
            if signature.confidence >= 0.8 {
                let _ = crate::yara_gen::generate_yara_from_threat(&signature);
            }
            
            // 2. Dispatch Active Response based on Decision Matrix (sensible: only when confidence high)
            let autonomy = osoosi_types::load_autonomy_config();
            let mut effective_action = if signature.confidence >= autonomy.action_confidence_threshold {
                signature.recommended_action
            } else {
                info!("Threat confidence {:.2} below action threshold {:.2}: downgrading to Alert", signature.confidence, autonomy.action_confidence_threshold);
                ResponseAction::Alert
            };

            // Platform-specific safety check: Validate Windows system files with SFC before isolation.
            #[cfg(target_os = "windows")]
            {
                if effective_action != ResponseAction::Alert {
                    if let Some(file_path) = event.data.get("Image").and_then(|i| i.as_str()) {
                        if crate::system_check::validate_windows_file_integrity(file_path).await {
                             warn!("SFC SAFETY OVERRIDE: File {} verified as clean by Windows SFC. Downgrading action to Alert to prevent system destabilization.", file_path);
                             effective_action = ResponseAction::Alert;
                             // We don't modify the signature's confidence here, just the current decision's action.
                        }
                    }
                }
            }

            // Shield Layer: Verify action safety against Taint/SSRF policies
            let sink = match effective_action {
                ResponseAction::Tarpit => Some(osoosi_types::TaintSink::process_injection()),
                ResponseAction::GhostTarpit | ResponseAction::Deception => Some(osoosi_types::TaintSink::deception()),
                ResponseAction::Isolate => Some(osoosi_types::TaintSink::mesh_join()), 
                _ => None,
            };

            if let Some(sink) = sink {
                if !self.shield.verify_taint_flow(&event, &sink) {
                    warn!("SHIELD BLOCK: Autonomous action {:?} blocked by taint policy for event provenance", effective_action);
                    self.audit.log("SHIELD_BLOCKED", serde_json::json!({
                        "action": format!("{:?}", effective_action),
                        "reason": "Taint violation detected in Shield Layer"
                    }));
                    return Ok(());
                }
            }

            match effective_action {
                ResponseAction::Deception => {
                    let traps_path = &self.runtime_config.traps_path;
                    warn!("Action: Spawning Ghost Files (Deception Traps) in response to discovery behavior.");
                    self.response.spawn_ghost_files(traps_path).await?;
                    self.audit.log("RESPONSE_ACTION", serde_json::json!({"type": "GhostFiles", "path": traps_path}));
                }
                ResponseAction::Tarpit => {
                    warn!("Action: Applying Resource Tarpit to PID (confidence {:.2})", signature.confidence);
                    if let Some(pid) = event.data.get("ProcessId").and_then(|p| p.as_u64()) {
                        let tarpit = TarpitManager::new();
                        tarpit.apply_tarpit(pid as u32, 60).await;
                        self.audit.log("RESPONSE_ACTION", serde_json::json!({"type": "Tarpit", "pid": pid}));
                    }
                }
                ResponseAction::GhostTarpit => {
                    let traps_path = &self.runtime_config.traps_path;
                    warn!("Action: Multi-tier Response (Ghost + Tarpit) active (confidence {:.2})", signature.confidence);
                    self.response.spawn_ghost_files(traps_path).await?;
                    if let Some(pid) = event.data.get("ProcessId").and_then(|p| p.as_u64()) {
                        let tarpit = TarpitManager::new();
                        tarpit.apply_tarpit(pid as u32, 120).await;
                        self.audit.log("RESPONSE_ACTION", serde_json::json!({"type": "GhostTarpit", "pid": pid, "ghost_path": traps_path}));
                    }
                    if crate::firewall::autoblock_enabled() {
                        let pid = event.data.get("ProcessId").and_then(|p| p.as_u64()).map(|v| v as u32);
                        let image = event.data.get("Image").and_then(|i| i.as_str());
                        match crate::firewall::block_process_network(pid, image) {
                            Ok(msg) => {
                                warn!("Firewall auto-block applied: {}", msg);
                                self.audit.log("RESPONSE_ACTION", serde_json::json!({
                                    "type": "FirewallBlock",
                                    "pid": pid,
                                    "image": image,
                                    "message": msg
                                }));
                            }
                            Err(e) => warn!("Firewall auto-block failed: {}", e),
                        }
                    }
                }
                ResponseAction::Alert => {
                    info!("Action: Logged and Alerted.");
                    self.audit.log("RESPONSE_ACTION", serde_json::json!({"type": "Alert"}));
                }
                ResponseAction::Isolate => {
                    warn!("Action: Targeted Process Block (confidence {:.2}) — blocking process network; full host isolation skipped for safety", signature.confidence);
                    self.audit.log("RESPONSE_ACTION", serde_json::json!({"type": "TargetedProcessBlock", "confidence": signature.confidence}));
                    
                    // Instead of full isolation, we block only the offending process network
                    if let Some(pid) = event.data.get("ProcessId").and_then(|p| p.as_u64()).map(|v| v as u32) {
                        let image = event.data.get("Image").and_then(|i| i.as_str());
                        match crate::firewall::block_process_network(Some(pid), image) {
                            Ok(msg) => {
                                warn!("Targeted firewall block applied: {}", msg);
                                self.audit.log("RESPONSE_ACTION", serde_json::json!({
                                    "type": "FirewallBlock",
                                    "pid": pid,
                                    "image": image,
                                    "message": msg
                                }));
                            }
                            Err(e) => warn!("Targeted firewall block failed: {}", e),
                        }
                    }
                }
            }

            // LLM triage: add high-confidence threats for agent decision
            if crate::triage::triage_enabled()
                && signature.confidence >= crate::triage::triage_confidence_threshold()
            {
                crate::triage::add_pending(
                    &self.triage_store,
                    &signature.id,
                    signature.clone(),
                    &event,
                    effective_action,
                );
                crate::triage::remove_expired(&self.triage_store, 300);
            }
        }

        Ok(())
    }

    /// Generate an attack narrative from the audit log.
    pub fn generate_story(&self) -> String {
        let storyteller = ForensicStoryteller::new();
        storyteller.summarize(&self.audit)
    }

    /// Access the trust manager to bootstrap mesh identity.
    pub fn trust(&self) -> Arc<TrustManager> {
        self.trust.clone()
    }


    /// Access the audit trail for dashboard queries.
    pub fn audit(&self) -> Arc<AuditTrail> {
        self.audit.clone()
    }

    /// Access the malware scanner for dashboard queries.
    pub fn malware_scanner(&self) -> Arc<MalwareScanner> {
        self.malware_scanner.clone()
    }

    /// Pending triage entries (high-confidence threats awaiting LLM decision).
    pub fn pending_triage(&self) -> Vec<serde_json::Value> {
        crate::triage::list_pending(&self.triage_store, 300)
    }

    /// Natural language-style query over audit and threat store.
    /// Keywords: threats, malware, process, host, response, dns, network.
    pub fn query_natural(&self, q: &str) -> serde_json::Value {
        let q_lower = q.to_lowercase();
        let limit = 50;
        let mut results: Vec<serde_json::Value> = Vec::new();

        let wants_threats = q_lower.contains("threat") || q_lower.contains("detect") || q_lower.contains("alarm");
        let wants_malware = q_lower.contains("malware") || q_lower.contains("virus") || q_lower.contains("infected");
        let wants_response = q_lower.contains("response") || q_lower.contains("action") || q_lower.contains("block");
        let wants_traffic = q_lower.contains("dns") || q_lower.contains("network") || q_lower.contains("connect");
        let wants_all = !wants_threats && !wants_malware && !wants_response && !wants_traffic;

        let entries = self.audit.entries();
        for entry in entries.iter().rev().take(limit * 2) {
            let include = wants_all
                || (wants_threats && entry.event_type == "THREAT_DETECTED")
                || (wants_malware && entry.event_type == "MALWARE_DETECTED")
                || (wants_response && entry.event_type == "RESPONSE_ACTION")
                || (wants_traffic && entry.event_type == "TELEMETRY_INGESTED"
                    && (entry.data.get("data").and_then(|d| d.get("DestinationIp")).is_some()
                        || entry.data.get("data").and_then(|d| d.get("QueryName")).is_some()));
            if include {
                let summary = match entry.event_type.as_str() {
                    "THREAT_DETECTED" => {
                        let proc = entry.data.get("process_name").and_then(|v| v.as_str()).unwrap_or("?");
                        let conf = entry.data.get("confidence").and_then(|v| v.as_f64()).unwrap_or(0.0);
                        format!("Threat: {} (conf: {:.0}%)", proc, conf * 100.0)
                    }
                    "MALWARE_DETECTED" => {
                        let fp = entry.data.get("file_path").and_then(|v| v.as_str()).unwrap_or("?");
                        format!("Malware: {}", fp.rsplit(['\\', '/']).next().unwrap_or(fp))
                    }
                    "RESPONSE_ACTION" => {
                        let t = entry.data.get("type").and_then(|v| v.as_str()).unwrap_or("?");
                        format!("Response: {}", t)
                    }
                    "TELEMETRY_INGESTED" => {
                        let ev = entry.data.get("event_id").and_then(|v| v.as_i64()).unwrap_or(0);
                        format!("Event {} ingested", ev)
                    }
                    _ => entry.event_type.clone(),
                };
                results.push(serde_json::json!({
                    "type": entry.event_type,
                    "summary": summary,
                    "timestamp": entry.timestamp.to_rfc3339(),
                    "data": entry.data,
                }));
                if results.len() >= limit {
                    break;
                }
            }
        }

        serde_json::json!({
            "query": q,
            "count": results.len(),
            "results": results,
        })
    }

    /// Apply LLM triage decision: override action for a pending threat.
    /// If agent chooses a more severe action (e.g. Isolate when we did Alert), applies it.
    pub async fn triage_decide(&self, threat_id: &str, action: osoosi_types::ResponseAction) -> anyhow::Result<bool> {
        let Some((_, entry)) = self.triage_store.remove(threat_id) else {
            return Ok(false);
        };
        self.audit.log("TRIAGE_DECISION", serde_json::json!({
            "threat_id": threat_id,
            "agent_action": format!("{:?}", action),
            "previously_applied": format!("{:?}", entry.applied_action),
        }));
        use osoosi_types::ResponseAction as RA;
        let needs_escalation = matches!(
            (entry.applied_action, action),
            (RA::Alert, RA::Isolate | RA::GhostTarpit | RA::Tarpit | RA::Deception)
            | (RA::Deception, RA::Isolate | RA::GhostTarpit | RA::Tarpit)
            | (RA::Tarpit, RA::Isolate | RA::GhostTarpit)
            | (RA::GhostTarpit, RA::Isolate)
        );
        if needs_escalation {
            if let Ok(event) = serde_json::from_value::<SysmonEvent>(entry.event.clone()) {
                if crate::firewall::autoblock_enabled() {
                    let pid = event.data.get("ProcessId").and_then(|p| p.as_u64()).map(|v| v as u32);
                    let image = event.data.get("Image").and_then(|i| i.as_str());
                    if let Ok(msg) = crate::firewall::block_process_network(pid, image) {
                        self.audit.log("RESPONSE_ACTION", serde_json::json!({
                            "type": "TriageEscalation",
                            "threat_id": threat_id,
                            "action": format!("{:?}", action),
                            "message": msg,
                        }));
                    }
                }
            }
        }
        Ok(true)
    }

    /// Analyze TrafficLLM-style prompt input using Rust traffic adapter.
    pub fn analyze_traffic_prompt(&self, human_instruction: &str, traffic_data: &str) -> serde_json::Value {
        let result = osoosi_policy::analyze_prompt(human_instruction, traffic_data);
        serde_json::json!({
            "status": "success",
            "task_response": result.task_response,
            "final_response": result.final_response,
            "confidence": result.confidence,
            "recommended_action": format!("{:?}", result.action),
            "tag": result.tag,
            "reason": result.reason,
        })
    }

    /// Count recent traffic events (NetworkConnect/DnsQuery) in audit. Lightweight.
    pub fn recent_traffic_events_count(&self, limit: usize) -> u32 {
        use osoosi_types::SysmonEventId;
        let limit = limit.clamp(1, 500);
        let entries = self.audit.entries();
        let mut n = 0u32;
        for entry in entries.iter().rev() {
            if entry.event_type != "TELEMETRY_INGESTED" {
                continue;
            }
            let Ok(event) = serde_json::from_value::<SysmonEvent>(entry.data.clone()) else {
                continue;
            };
            if matches!(event.event_id, SysmonEventId::NetworkConnect | SysmonEventId::DnsQuery) {
                n += 1;
                if n >= limit as u32 {
                    break;
                }
            }
        }
        n
    }

    /// Analyze traffic captured by this codebase (Sysmon NetworkConnect/DnsQuery from audit).
    /// No pasting required — reads from TELEMETRY_INGESTED entries.
    pub fn analyze_captured_traffic(&self, limit: usize) -> serde_json::Value {
        use osoosi_types::SysmonEventId;

        let limit = limit.clamp(1, 100);
        let entries = self.audit.entries();
        let mut events_analyzed = 0u32;
        let mut findings: Vec<serde_json::Value> = Vec::new();

        for entry in entries.iter().rev() {
            if entry.event_type != "TELEMETRY_INGESTED" {
                continue;
            }
            let Ok(event) = serde_json::from_value::<SysmonEvent>(entry.data.clone()) else {
                continue;
            };
            let is_traffic = matches!(event.event_id, SysmonEventId::NetworkConnect | SysmonEventId::DnsQuery);
            if !is_traffic {
                continue;
            }
            events_analyzed += 1;
            if events_analyzed > limit as u32 {
                break;
            }
            if let Some(threat) = osoosi_policy::traffic_adapter::analyze(&event) {
                findings.push(serde_json::json!({
                    "event_id": format!("{:?}", event.event_id),
                    "timestamp": event.timestamp.to_rfc3339(),
                    "computer": event.computer,
                    "confidence": threat.confidence,
                    "tag": threat.tag,
                    "reason": threat.reason,
                    "action": format!("{:?}", threat.action),
                }));
            }
        }

        serde_json::json!({
            "status": "success",
            "events_analyzed": events_analyzed,
            "findings_count": findings.len(),
            "findings": findings,
        })
    }

    /// Build attack graph from audit trail and policy graph for visualization.
    pub fn attack_graph(&self, limit: usize) -> serde_json::Value {
        let rels = self.policy.graph_relationships();
        crate::attack_graph::build_attack_graph(self.audit.as_ref(), &rels, limit)
    }

    /// Current mesh peer count (approved peers).
    pub fn mesh_peer_count(&self) -> u32 {
        self.mesh_peer_count.load(Ordering::Relaxed)
    }

    /// Uptime since orchestrator creation.
    pub fn uptime(&self) -> std::time::Duration {
        self.start_time.elapsed()
    }

    /// Backup status for dashboard.
    pub fn backup_status(&self) -> (Option<String>, Option<String>, Option<String>, Option<String>) {
        let memory = self.memory();
        let status = memory.get_backup_status("status").ok().flatten();
        let message = memory.get_backup_status("message").ok().flatten();
        let last_at = memory.get_backup_status("last_at").ok().flatten();
        let target = memory.get_backup_status("target").ok().flatten();
        (status, message, last_at, target)
    }

    /// Model training status for dashboard.
    pub fn model_training_status(&self) -> (Option<String>, Option<String>, Option<String>, u32, u32, Option<String>) {
        let memory = self.memory();
        let status = memory.get_model_training_status("status").ok().flatten();
        let last_attempt = memory.get_model_training_status("last_attempt").ok().flatten();
        let last_success = memory.get_model_training_status("last_success").ok().flatten();
        let sample_count = memory.get_model_training_status("sample_count").ok().flatten()
            .and_then(|s| s.parse().ok()).unwrap_or(0);
        let feature_count = memory.get_model_training_status("feature_count").ok().flatten()
            .and_then(|s| s.parse().ok()).unwrap_or(0);
        let last_error = memory.get_model_training_status("last_error").ok().flatten();
        (status, last_attempt, last_success, sample_count, feature_count, last_error)
    }

    /// Repair Engine status for dashboard (last patch, pending count, last error).
    pub fn repair_status(&self) -> RepairStatus {
        let memory = self.memory();
        let last_cve = memory.get_repair_status("last_cve").ok().flatten();
        let last_state = memory.get_repair_status("last_state").ok().flatten();
        let last_sig = memory.get_repair_status("last_sig").ok().flatten();
        let last_at = memory.get_repair_status("last_at").ok().flatten();
        let pending: u32 = memory.get_repair_status("pending_count").ok().flatten()
            .and_then(|s| s.parse().ok()).unwrap_or(0);
        let last_error = memory.get_repair_status("last_error").ok().flatten()
            .filter(|s| !s.is_empty());
        (last_cve, last_state, last_sig, last_at, pending, last_error)
    }

    /// Rollback a previously applied patch. Use --last to rollback the most recent patch, or --patch <id> to specify.
    pub async fn rollback_patch(
        &self,
        patch_id: Option<&str>,
        use_last: bool,
    ) -> anyhow::Result<()> {
        let memory = self.memory();
        let (id, snapshot_id, component) = if use_last {
            let last_cve = memory.get_repair_status("last_cve").ok().flatten();
            let last_snap = memory.get_repair_status("last_snapshot_id").ok().flatten();
            let last_comp = memory.get_repair_status("last_component").ok().flatten();
            match (last_cve, last_snap, last_comp) {
                (Some(cve), snap, comp) => (cve, snap, comp),
                (None, _, _) => {
                    return Err(anyhow::anyhow!(
                        "No last patch to rollback. Apply a patch first, or use --patch <id> to specify."
                    ));
                }
            }
        } else if let Some(id) = patch_id {
            (id.to_string(), None, None)
        } else {
            return Err(anyhow::anyhow!(
                "Specify --last to rollback the most recent patch, or --patch <id> (e.g. KB1234567 or package-name)"
            ));
        };

        self.patch_engine
            .rollback_patch(&id, snapshot_id.as_deref(), component.as_deref())
            .await
    }

    /// Broadcast intelligence across the mesh network.
    pub async fn broadcast_intelligence(&self, summary: String) -> anyhow::Result<()> {
        let intel = osoosi_types::GlobalIntelligence {
            source_url: "user_dashboard".to_string(),
            summary: summary.clone(),
            defense: None,
            timestamp: chrono::Utc::now(),
            source_node: self.trust.did().to_string(),
        };
        
        info!("Broadcasting intelligence: {}", summary);
        self.audit.log("INTEL_BROADCAST", serde_json::json!({
            "summary": summary,
            "source": "dashboard",
        }));

        if let Some(ref tx) = *self.mesh_command_tx.lock().await {
            tx.send(osoosi_wire::MeshCommand::BroadcastGlobalIntel(intel)).await
                .map_err(|e| anyhow::anyhow!("Mesh channel closed: {}", e))
        } else {
            Err(anyhow::anyhow!("Mesh not active"))
        }
    }

    pub async fn start_mesh_with_join_gate(&self) -> anyhow::Result<Arc<JoinGate>> {
        let autonomy = osoosi_types::load_autonomy_config();
        let peer_rules = osoosi_types::load_peer_rules_config();
        let master_node_pk = osoosi_types::load_mesh_listen_config_extended().master_node_public_key;
        let (command_tx, command_rx) = tokio::sync::mpsc::channel(32);
        let (peer_threat_tx, mut peer_threat_rx) = tokio::sync::mpsc::channel::<osoosi_types::ThreatSignature>(64);
        let join_gate = Arc::new(JoinGate::new(
            self.memory.clone(),
            command_tx.clone(),
            autonomy.auto_approve_reputation_threshold,
            peer_rules.clone(),
            master_node_pk,
        ));

        {
            let mut tx_guard = self.mesh_command_tx.lock().await;
            *tx_guard = Some(command_tx.clone());
        }

        let mesh = {
            let mut guard = self.mesh.lock().await;
            guard.take().ok_or_else(|| anyhow::anyhow!("Mesh already started or taken"))?
        };

        let (peer_consensus_tx, mut peer_consensus_rx) = tokio::sync::mpsc::channel::<osoosi_types::PolicyConsensusMessage>(64);
        let (ghost_shard_tx, mut ghost_shard_rx) = tokio::sync::mpsc::channel::<osoosi_types::GhostShardData>(64);
        let (peer_intel_tx, mut peer_intel_rx) = tokio::sync::mpsc::channel::<osoosi_types::GlobalIntelligence>(64);
        let (malware_sample_tx, mut malware_sample_rx) = tokio::sync::mpsc::channel::<osoosi_types::MalwareSample>(256);

        let join_gate_clone = join_gate.clone();
        let peer_count = self.mesh_peer_count.clone();
        let peer_tx = peer_threat_tx.clone();
        let cons_tx = peer_consensus_tx.clone();
        let ghost_tx = ghost_shard_tx.clone();
        let intel_tx = peer_intel_tx.clone();
        let sample_tx = malware_sample_tx.clone();
        // Box the future to avoid stack overflow: libp2p Swarm + run_loop is large.
        let mesh_future = Box::pin(async move {
            mesh.run_loop(
                join_gate_clone,
                command_rx,
                Some(peer_count),
                peer_rules,
                move |sig| { let _ = peer_tx.try_send(sig); },
                move |m| { let _ = cons_tx.try_send(m); },
                move |s| { let _ = ghost_tx.try_send(s); },
                move |i| { let _ = intel_tx.try_send(i); },
                move |s| { let _ = sample_tx.try_send(s); },
            )
            .await;
        });
        // Process backlog of pending joins that now meet auto-approval criteria
        let _ = join_gate.auto_approve_backlog();

        tokio::spawn(mesh_future);

        // 6. Periodic Peer Announce (Status broadcast for join rules & Master Node verification)
        let orch_for_announce = self.clone();
        let announce_tx = command_tx.clone();
        tokio::spawn(async move {
            loop {
                match orch_for_announce.get_status_for_announce().await {
                    Ok(status) => {
                        let _ = announce_tx.send(MeshCommand::PublishPeerAnnounce(status)).await;
                    }
                    Err(e) => {
                        tracing::warn!("Failed to generate peer status for announcement: {}", e);
                    }
                }
                tokio::time::sleep(tokio::time::Duration::from_secs(300)).await;
            }
        });

        // Process Ghost Shards: HDS Algorithm Activation
        let holograph_orch = self.holograph.clone();
        tokio::spawn(async move {
             while let Some(shard) = ghost_shard_rx.recv().await {
                 holograph_orch.add_shard(shard);
             }
        });

        // Process Global Intelligence: Gossip Sleuth Defense Learning
        let policy_orch = self.policy.clone();
        tokio::spawn(async move {
            while let Some(intel) = peer_intel_rx.recv().await {
                info!("Gossip: Received intelligence from peer {}: {}", intel.source_node, intel.summary);
                if let Some(defense) = intel.defense {
                    info!("Gossip Learning: Automatically registering new defense rule for {}.", defense.cve_id);
                    // In a real implementation, we would parse defense.learned_rule and add to PolicyEngine
                    policy_orch.register_temporary_rule(&defense.cve_id, &defense.learned_rule, defense.severity);
                }
            }
        });

        // Start local Gossip Sleuth: scouting for new threats to share
        let sleuth = Arc::new(crate::gossip::GossipSleuth::new(
            command_tx.clone(),
            self.trust.did().to_string(),
        ));
        tokio::spawn(sleuth.start_sleuthing_loop());

        // Process peer consensus: validate mesh-driven policy health
        let history = self.policy_consensus.clone();
        tokio::spawn(async move {
            while let Some(msg) = peer_consensus_rx.recv().await {
                let policy_id = match &msg {
                    osoosi_types::PolicyConsensusMessage::Announcement(a) => a.policy_id.clone(),
                    osoosi_types::PolicyConsensusMessage::Vote(v) => v.policy_id.clone(),
                };
                let mut guard = history.lock().await;
                let entry = guard.entry(policy_id.clone()).or_insert_with(Vec::new);
                entry.push(msg.clone());
                
                // Heuristic: If we have 3 independent nodes vouching for a policy, mark as Mesh-Validated.
                let votes = entry.iter().filter_map(|m| {
                    if let osoosi_types::PolicyConsensusMessage::Vote(v) = m {
                        if v.status == osoosi_types::PolicyHealthStatus::Optimal { Some(v.voter_id.clone()) } else { None }
                    } else { None }
                }).collect::<HashSet<String>>();
                
                if votes.len() >= 3 {
                    info!("Policy/Patch {} has reached mesh CONSENSUS. Marked as Stable/Mesh-Validated.", policy_id);
                }
            }
        });

        // Process peer threats: store in memory, add to model
        let memory_peer = self.memory.clone();
        let model_peer = self.threat_model.clone();
        tokio::spawn(async move {
            while let Some(sig) = peer_threat_rx.recv().await {
                if let Err(e) = memory_peer.log_threat(&sig) {
                    error!("Failed to store peer threat: {}", e);
                }
                let mut model = model_peer.write().await;
                model.add_training_sample(&sig);
                if sig.confidence >= 0.8 {
                    let _ = crate::yara_gen::generate_yara_from_threat(&sig);
                }
            }
        });

        // Process malware samples from mesh: store for distributed EMBER training
        let memory_malware = self.memory.clone();
        tokio::spawn(async move {
            while let Some(sample) = malware_sample_rx.recv().await {
                if let Err(e) = memory_malware.insert_malware_sample(&sample) {
                    error!("Failed to store mesh malware sample: {}", e);
                } else {
                    debug!("Stored malware sample from {} (hash={}, label={})", sample.source_node, &sample.file_hash[..sample.file_hash.len().min(12)], sample.label);
                }
            }
        });

        Ok(join_gate)
    }

    /// Start model training loop: aggregate self + peer data, train, save to models/.
    pub async fn start_model_training_loop(&self, interval_secs: u64) {
        let memory = self.memory.clone();
        let threat_model = self.threat_model.clone();
        tokio::spawn(async move {
            info!("Model training loop started (interval: {}s, models in ./models/)", interval_secs);
            let _ = memory.set_model_training_status("status", "running");
            loop {
                let _ = memory.set_model_training_status("last_attempt", &chrono::Utc::now().to_rfc3339());
                match memory.get_threats_for_training(500) {
                    Ok(samples) => {
                        let _ = memory.set_model_training_status("sample_count", &samples.len().to_string());
                        if samples.is_empty() {
                            let _ = memory.set_model_training_status("status", "waiting_for_samples");
                            let _ = memory.set_model_training_status("last_error", "");
                        } else {
                            let mut model = threat_model.write().await;
                            if let Err(e) = model.train(&samples) {
                                error!("Model training failed: {}", e);
                                let _ = memory.set_model_training_status("status", "failed");
                                let _ = memory.set_model_training_status("last_error", &e.to_string());
                            } else {
                                let w = model.weights();
                                let _ = memory.set_model_training_status("status", "running");
                                let _ = memory.set_model_training_status("feature_count", &w.features.len().to_string());
                                if let Some(ref trained_at) = w.trained_at {
                                    let _ = memory.set_model_training_status("last_success", trained_at);
                                }
                                let _ = memory.set_model_training_status("last_error", "");
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to get threats for training: {}", e);
                        let _ = memory.set_model_training_status("status", "failed");
                        let _ = memory.set_model_training_status("last_error", &e.to_string());
                    },
                }
                tokio::time::sleep(tokio::time::Duration::from_secs(interval_secs)).await;
            }
        });
    }

    /// Policy Consensus status for all policies tracked in the mesh.
    pub async fn policy_consensus_status(&self) -> HashMap<String, Vec<osoosi_types::PolicyConsensusMessage>> {
        self.policy_consensus.lock().await.clone()
    }

    /// Access the threat model for inference (used by policy engine).
    pub fn threat_model(&self) -> Arc<tokio::sync::RwLock<ThreatModel>> {
        self.threat_model.clone()
    }

    /// COORDINATOR: Activate Holographic Deception Sharding across the mesh.
    /// Spawns distributed ghost shards to trap an identified attacker.
    pub async fn activate_mesh_hologram(&self, attacker_ip: &str) -> anyhow::Result<()> {
        use std::sync::atomic::Ordering;
        let peer_count = self.mesh_peer_count.load(Ordering::Relaxed);
        if peer_count == 0 {
             warn!("HDS: Cannot activate sharding without mesh peers.");
             return Ok(());
        }

        let mesh_members = vec![self.trust.did().to_string()]; // Simplified for prototype
        
        let ports = vec![22, 80, 443, 3306, 5432];
        let tx_guard = self.mesh_command_tx.lock().await;
        if let Some(ref tx) = *tx_guard {
            for port in ports {
                let owner = osoosi_wire::holograph::HolographEngine::calculate_shard_assignment(
                    attacker_ip, port, &mesh_members
                );
                
                let shard = osoosi_types::GhostShardData {
                    attacker_ip: attacker_ip.to_string(),
                    virtual_port: port,
                    deception_type: match port {
                        22 => osoosi_types::DeceptionType::SshDelay,
                        80 | 443 => osoosi_types::DeceptionType::HttpLabyrinth,
                        _ => osoosi_types::DeceptionType::DbSimulation,
                    },
                    shard_owner: owner,
                };
                
                let _ = tx.try_send(osoosi_wire::MeshCommand::BroadcastGhostShard(shard));
            }
        }
        
        info!("HDS: Holographic Lattice deployed for attacker {}.", attacker_ip);
        Ok(())
    }

    /// Run AI Behavioral Analysis (Adapted from AIEventAnalyzer)
    /// This is a multi-platform (Win/Mac/Linux) investigative tool.
    pub async fn run_behavioral_analysis(&self, mode: osoosi_behavioral::AnalysisMode, event_count: usize) -> anyhow::Result<Vec<osoosi_behavioral::InvestigativePrompt>> {
        let reader = osoosi_behavioral::BehavioralLogReader::new();
        let events = reader.poll_events()?; // Get latest logs across all sources
        let count = event_count.clamp(1, 50);
        let sample = if events.len() > count {
            &events[events.len() - count..]
        } else {
            &events
        };
        
        self.behavioral_analyzer.generate_investigative_prompts(mode, sample).await
    }

    /// Perform deep AI analysis on a specific behavioral lead.
    pub async fn run_behavioral_deep_dive(&self, prompt: &str, event_count: usize) -> anyhow::Result<String> {
        let reader = osoosi_behavioral::BehavioralLogReader::new();
        let events = reader.poll_events()?;
        let count = event_count.clamp(1, 50);
        let sample = if events.len() > count {
            &events[events.len() - count..]
        } else {
            &events
        };

        self.behavioral_analyzer.perform_deep_analysis(prompt, sample).await
    }

    pub async fn get_status_for_announce(&self) -> anyhow::Result<osoosi_types::PeerAnnounce> {
        use osoosi_types::PeerAnnounce;
        let repair_status = self.repair_status();
        let is_patched = repair_status.4 == 0; // pending_count == 0
        let (os_name, os_version, os_supported) = crate::system_check::get_os_info();
        
        let mesh_config = osoosi_types::load_mesh_listen_config_extended();
        
        Ok(PeerAnnounce {
            source_node: self.trust.did().id.clone(),
            is_patched,
            os_name,
            os_version,
            os_supported,
            timestamp: chrono::Utc::now(),
            membership_proof: mesh_config.membership_proof,
        })
    }

    /// Start the autonomous browser security auditor loop (default 1 hour).
    pub fn start_browser_auditor(&self) {
        let guard = self.browser_guard.clone();
        let interval_env = std::env::var("OSOOSI_BROWSER_SCAN_INTERVAL");
        let interval: u64 = interval_env.ok().and_then(|s| s.parse().ok()).unwrap_or(3600);
        
        let mesh_tx = self.mesh_command_tx.clone();
        let memory = self.memory.clone();
        
        tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(std::time::Duration::from_secs(interval));
            loop {
                interval_timer.tick().await;
                info!("BrowserGuard: Periodic sweep running...");
                let threats = guard.run_sweep().await;
                for threat in threats {
                    // 1. Log locally to MemoryStore and AuditTrail
                    let _ = memory.log_threat(&threat);
                    warn!("ALARM: Browser Security Threat Identified: {:?}", threat);
                    
                    // 2. Broadcast to mesh if high confidence
                    if threat.confidence > 0.8 {
                         if let Some(ref tx) = *mesh_tx.lock().await {
                             let _ = tx.send(osoosi_wire::MeshCommand::Broadcast(threat)).await;
                         }
                    }
                }
            }
        });
    }

    /// Perform a manual browser security sweep.
    pub async fn run_browser_sweep(&self) -> Vec<osoosi_types::ThreatSignature> {
        self.browser_guard.run_sweep().await
    }
}
