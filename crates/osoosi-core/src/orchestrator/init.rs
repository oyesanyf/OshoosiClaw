#![allow(unused_imports)]

use super::types::*;
use super::*;
use crate::causal_graph::*;
use crate::console_defense::*;
use crate::disk_cleanup::*;
use crate::hybrid_runtime::*;
use crate::killchain::*;
use crate::memory_watchdog::*;
use crate::rea::*;
use crate::voters::*;

impl EdrOrchestrator {
    pub(crate) fn dns_domain_candidates(query_name: &str) -> Vec<String> {
        let normalized = query_name.trim().trim_end_matches('.').to_ascii_lowercase();
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

    pub(crate) async fn lookup_domain_age_days(
        &self,
        query_name: &str,
    ) -> anyhow::Result<Option<i64>> {
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

    pub(crate) async fn lookup_otx_domain_hits(&self, query_name: &str) -> anyhow::Result<u64> {
        if std::env::var("OSOOSI_OFFLINE_MODE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
        {
            return Ok(0);
        }
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(4))
            .build()?;
        let api_key = resolve_otx_api_key();
        let mut max_hits = 0u64;

        for domain in Self::dns_domain_candidates(query_name) {
            let url = format!(
                "https://otx.alienvault.com/api/v1/indicators/domain/{}/general",
                domain
            );
            let mut req = client.get(&url);
            if let Some(ref k) = api_key {
                req = req.header("X-OTX-API-KEY", k);
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

    pub(crate) async fn analyze_dns_query_risk(
        &self,
        event: &HostSecurityEvent,
    ) -> Option<osoosi_types::ThreatSignature> {
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
                debug!(
                    "DNS enrichment: no RDAP registration date for {}",
                    query_name
                );
                return None;
            }
            Err(e) => {
                debug!(
                    "DNS enrichment: domain age lookup failed for {}: {}",
                    query_name, e
                );
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
        sig.cve_id = Some(format!(
            "DNS-NEW-DOMAIN:{}",
            query_name.to_ascii_lowercase()
        ));

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

    /// Evaluates and enforces the Human Escalation Gate.
    /// When `human_escalation_required` is true, autonomous destructive action is strictly
    /// downgraded to Alert, queued as ActionState::Pending, and require_approval is set to true.
    pub fn apply_human_escalation_gate(
        signature: &mut osoosi_types::ThreatSignature,
        effective_action: &mut osoosi_types::ResponseAction,
        human_escalation_required: bool,
    ) {
        if human_escalation_required {
            *effective_action = osoosi_types::ResponseAction::Alert;
            signature.recommended_action = osoosi_types::ResponseAction::Alert;
            signature.action_state = osoosi_types::ActionState::Pending;
            signature.require_approval = true;
        }
    }

    /// Evaluates and enforces the Multi-Signal Corroboration Gate.
    /// Caps uncorroborated single-detector destructive actions (Isolate/Tarpit/GhostTarpit)
    /// to require human approval unless deterministic cryptographic, YARA, or multi-detector proof exists.
    pub fn apply_corroboration_gate(
        signature: &mut osoosi_types::ThreatSignature,
        effective_action: osoosi_types::ResponseAction,
        is_destructive: bool,
        action_confidence_threshold: f32,
    ) {
        let has_deterministic_guard = signature
            .reason
            .as_deref()
            .map(|r| {
                r.contains("[CredentialGuard-Memory]")
                    || r.contains("[ProcessInjection-Memory]")
                    || r.contains("HollowsHunter")
                    || r.contains("YaraX")
                    || r.contains("ASI10")
                    || r.contains("T1003")
                    || r.contains("T1555")
                    || r.contains("[Sigma-Engine]")
                    || r.contains("Sigma Match:")
            })
            .unwrap_or(false);

        if has_deterministic_guard && signature.confidence >= 0.85 {
            return;
        }

        if matches!(
            effective_action,
            osoosi_types::ResponseAction::Isolate
                | osoosi_types::ResponseAction::Tarpit
                | osoosi_types::ResponseAction::GhostTarpit
        ) && signature.detector_count < 2
            && signature.cve_id.is_none()
            && !is_destructive
            && signature.signature.is_none()
            && signature.merkle_proof.is_none()
            && (action_confidence_threshold > 0.40 || signature.confidence < 0.90)
        {
            tracing::info!(
                "Corroboration Gate: Single detector (count={}) without multi-signal deterministic corroboration. Requiring operator approval before {:?}.",
                signature.detector_count, effective_action
            );
            signature.require_approval = true;
        }
    }

    pub async fn new() -> anyhow::Result<Self> {
        // Drastic Performance Optimization: Lower process priority so we don't freeze the UI
        #[cfg(windows)]
        {
            use windows::Win32::System::Threading::{
                GetCurrentProcess, SetPriorityClass, BELOW_NORMAL_PRIORITY_CLASS,
            };
            unsafe {
                let _ = SetPriorityClass(GetCurrentProcess(), BELOW_NORMAL_PRIORITY_CLASS);
            }
            info!("Performance: Agent process priority set to BELOW_NORMAL.");
        }

        // Ensures hybrid Tokio+Rayon is wired even when the agent is not started via `osoosi` CLI (tests, embedders).
        crate::init_hybrid_concurrency();
        info!("EdrOrchestrator: Loading runtime configuration...");
        let runtime_config = load_runtime_config();

        info!("EdrOrchestrator: Initializing executors...");
        let host_executor: Arc<dyn SecuredExecutor> =
            Arc::new(crate::secured_executor::DirectExecutor::new());
        let task_executor: Arc<dyn SecuredExecutor> =
            if runtime_config.secure_runtime.as_deref() == Some("openshell") {
                info!(
                    "Initializing OpenShell sandboxed task executor (Sandbox: {})...",
                    runtime_config.openshell_sandbox
                );
                Arc::new(crate::secured_executor::OpenShellExecutor::new(
                    &runtime_config.openshell_sandbox,
                    runtime_config.openshell_policy.as_deref(),
                ))
            } else {
                Arc::new(crate::secured_executor::DirectExecutor::new())
            };

        info!(
            "EdrOrchestrator: Initializing memory store at {}...",
            runtime_config.db_path
        );
        let memory = match MemoryStore::new(&runtime_config.db_path) {
            Ok(store) => Arc::new(store),
            Err(primary_err) => {
                let fallback_db = dirs::data_local_dir()
                    .unwrap_or_else(std::env::temp_dir)
                    .join("OshoosiClaw")
                    .join("database")
                    .join("osoosi.db");
                if let Some(parent) = fallback_db.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let fallback_str = fallback_db.to_string_lossy().to_string();
                warn!(
                    "EdrOrchestrator: Primary database path '{}' unavailable ({}). Falling back to user-writable path '{}'...",
                    runtime_config.db_path, primary_err, fallback_str
                );
                Arc::new(MemoryStore::new(&fallback_str)?)
            }
        };
        info!("EdrOrchestrator: Registering internal assets...");
        register_internal_assets(&memory);
        if let Ok(Some(posture)) = memory.load_zone_posture("zone-alpha-mesh") {
            info!("EdrOrchestrator: Restoring persisted security posture from database...");
            if posture["tpm_remediated"].as_bool().unwrap_or(false) {
                crate::hardened::TPM_REMEDIATED.store(true, std::sync::atomic::Ordering::SeqCst);
            }
            if posture["memory_shield_remediated"]
                .as_bool()
                .unwrap_or(false)
            {
                crate::hardened::MEMORY_SHIELD_REMEDIATED
                    .store(true, std::sync::atomic::Ordering::SeqCst);
            }
            if posture["egress_remediated"].as_bool().unwrap_or(false) {
                crate::hardened::SOFTWARE_EGRESS_REMEDIATED
                    .store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
        let policy_config = osoosi_types::load_policy_config();
        info!("EdrOrchestrator: Initializing policy engine...");
        let mut policy = Arc::new(PolicyEngine::new(memory.clone(), policy_config));

        info!("EdrOrchestrator: Initializing mesh network...");
        let mesh_config = osoosi_types::load_mesh_listen_config();
        let mesh_node_opt = match MeshNode::new(memory.clone()).await {
            Ok(node) => {
                info!("EdrOrchestrator: Mesh network initialized.");
                Some(node)
            }
            Err(e) => {
                warn!(
                    "EdrOrchestrator: Mesh network initialization failed (continuing in standalone mode): {}",
                    e
                );
                None
            }
        };
        let mesh = Arc::new(tokio::sync::Mutex::new(mesh_node_opt));

        // --- 2. NOSTR GLOBAL INTELLIGENCE (BitChat Style) ---
        // Uses decentralized relays for cross-organization threat sharing with Differential Privacy.
        // Always initialize the orchestrator non-blockingly and perform geo-relay HTTP bootstrap
        // and WebSocket connection in a background task so port 3030 binds immediately on startup.
        let initial_nostr_relays = mesh_config.nostr_relays.clone();
        let allow_public_nostr = mesh_config.allow_public_relays;
        let nostr_orch = Arc::new(crate::nostr_mesh::NostrMeshOrchestrator::new(None, 1.0).await?);
        let connect_orch = nostr_orch.clone();
        tokio::spawn(async move {
            let mut nostr_relays = initial_nostr_relays;
            if nostr_relays.is_empty()
                || (nostr_relays.len() == 1
                    && (nostr_relays[0].contains("localhost")
                        || nostr_relays[0].contains("127.0.0.1")))
            {
                if allow_public_nostr {
                    info!("Nostr Mesh: No public relays configured or only localhost found. Bootstrapping global public relays in background...");
                    let geo_dir = crate::geo_mesh::GeoRelayDirectory::new();
                    let geo_csv_url = "https://raw.githubusercontent.com/permissionlesstech/georelays/refs/heads/main/nostr_relays.csv";

                    if let Ok(client) = reqwest::Client::builder()
                        .timeout(Duration::from_secs(5))
                        .build()
                    {
                        if let Ok(resp) = client.get(geo_csv_url).send().await {
                            if let Ok(csv) = resp.text().await {
                                geo_dir.load_csv(&csv).await;
                                nostr_relays = geo_dir.auto_bootstrap().await;
                            }
                        }
                    }
                    if nostr_relays.is_empty() {
                        info!("Nostr Mesh: Geo-bootstrap skipped/empty. P2P libp2p swarm active.");
                    }
                } else {
                    info!("Nostr Mesh: Public Nostr relays disabled by configuration. Running in pure P2P libp2p mesh mode.");
                }
            }

            if nostr_relays.len() > 1 {
                nostr_relays.retain(|r| !r.contains("localhost") && !r.contains("127.0.0.1"));
            }

            if !nostr_relays.is_empty() {
                info!(
                    "Initializing Nostr Mesh with {} relays...",
                    nostr_relays.len()
                );
                for relay in nostr_relays {
                    let _ = connect_orch.add_relay(&relay).await;
                }
                connect_orch.connect().await;
                info!("Nostr Mesh: Connection task completed.");
            }
        });
        let nostr_mesh = nostr_orch;

        let mesh_command_tx = Arc::new(tokio::sync::Mutex::new(None));
        let response = Arc::new(DeceptionManager::new());
        let audit = Arc::new(AuditTrail::new());

        // 2. Initialize Trust Manager
        let trust = Arc::new(TrustManager::new(host_executor.clone())?);
        let exclude_paths = osoosi_types::load_exclude_paths_from_config();

        let adaptive = Arc::new(crate::adaptive::TelemetryController::new());

        // Inject adaptive controller into policy engine for heavy voter skipping
        if let Some(p) = Arc::get_mut(&mut policy) {
            p.telemetry_controller = Some(adaptive.clone());
        }
        let (watcher_obj, file_rx) = osoosi_telemetry::FileWatcher::new(
            Some(memory.clone()),
            exclude_paths,
            adaptive.clone(),
        )?;
        let watcher = Arc::new(tokio::sync::Mutex::new(watcher_obj));
        let file_event_rx = Arc::new(tokio::sync::Mutex::new(Some(file_rx)));
        let mesh_peer_count = Arc::new(AtomicU32::new(0));
        let repair_config = osoosi_types::load_repair_config();
        let patch_engine = Arc::new(PatchEngine::new(audit.clone(), repair_config));
        let min_train = std::env::var("OSOOSI_MODEL_MIN_SAMPLES")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(3); // 3 samples = enough for initial baseline; override with OSOOSI_MODEL_MIN_SAMPLES=N
        let model_config = ModelConfig {
            models_dir: osoosi_types::resolve_models_dir()
                .to_string_lossy()
                .to_string(),
            min_samples: min_train,
            ..Default::default()
        };
        info!(
            "Federated threat-model training will run when at least {} labeled samples are available (set OSOOSI_MODEL_MIN_SAMPLES to change).",
            min_train
        );
        let threat_model = Arc::new(tokio::sync::RwLock::new(ThreatModel::new(model_config)));

        let yara_manager = Arc::new(crate::yara::YaraManager::new());
        let _yara_rules = yara_manager.active_rules();
        let models_dir = osoosi_types::resolve_models_dir();
        let malware_dir = models_dir.join("malware");
        let model_path = malware_dir.join("sorel.onnx");
        let malware_scanner = Arc::new(MalwareScanner::new(&model_path));

        let behavioral_yara_voter = try_build_behavioral_yara_voter(adaptive.clone()).map(Arc::new);
        let dotscope_analyzer = Arc::new(dotscope::DotscopeAnalyzer::new());
        let triage_store = crate::triage::new_triage_store();
        let baseline = Arc::new(crate::baseline::BehavioralBaseline::new());
        let sandbox = Arc::new(osoosi_sandbox::SandboxExecutor::new(
            audit.clone(),
            memory.clone(),
            malware_scanner.clone(),
        )?);
        let approval_queue = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let shield = Arc::new(crate::shield::ShieldLayer::with_manager(
            memory.clone(),
            yara_manager.clone(),
        ));
        let node_id = trust.did().to_string();
        let holograph = Arc::new(osoosi_wire::holograph::HolographEngine::new(
            node_id.clone(),
        ));
        let relativistic = Arc::new(crate::relativistic::RelativisticGuard::new());
        let behavioral_classifier = Arc::new(osoosi_behavioral::BehavioralClassifier::new().await);
        let behavioral_analyzer = Arc::new(osoosi_behavioral::BehavioralAnalyzer::new());
        let pii_classifier = Arc::new(crate::pii::PiiClassifier::new());
        let browser_guard = Arc::new(crate::browser_guard::BrowserGuard::new(
            memory.clone(),
            audit.clone(),
        ));
        let static_analyzer = Arc::new(crate::static_analyzer::StaticAnalyzer::with_manager(
            memory.clone(),
            task_executor.clone(),
            malware_scanner.clone(),
            yara_manager.clone(),
            adaptive.clone(),
        ));
        let correlator = Arc::new(crate::correlator::EventCorrelator::new());
        let ghost_nodes = Arc::new(osoosi_wire::GhostNodeManager::new(
            node_id.clone(),
            mesh_command_tx.clone(),
        ));
        let canary = Arc::new(crate::canary::CanaryManager::new());
        let nsrl_cache = Arc::new(dashmap::DashMap::new());
        let remediation = Arc::new(crate::remediation::RemediationController::new());
        let causal_ai = Arc::new(crate::causal_ai::CausalEngine::new());
        let self_healing = Arc::new(crate::self_healing::SelfHealingEngine::new(
            audit.clone(),
            memory.clone(),
        ));
        let models_dir = osoosi_types::resolve_models_dir();
        let smollm_dir = std::env::var("OSOOSI_SMOLLM_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| {
                let hf_dir = models_dir
                    .join("models--HuggingFaceTB--SmolLM2-135M-Instruct")
                    .join("snapshots");
                if let Ok(mut entries) = std::fs::read_dir(&hf_dir) {
                    if let Some(Ok(entry)) = entries.next() {
                        return entry.path();
                    }
                }
                models_dir.join("smollm")
            });

        let behavioral_debouncer = Arc::new(dashmap::DashMap::new());

        let has_smollm = smollm_dir.join("config.json").exists()
            && smollm_dir.join("model.safetensors").exists()
            && smollm_dir.join("tokenizer.json").exists();
        let enable_smollm = std::env::var("OSOOSI_ENABLE_SMOLLM")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let behavioral_engine = if enable_smollm && has_smollm {
            match osoosi_behavioral::SmolLMAnalyzer::new(&smollm_dir) {
                Ok(a) => {
                    info!("Native SmolLM analyzer loaded from {:?}.", smollm_dir);
                    Some(Arc::new(a))
                }
                Err(e) => {
                    warn!(
                    "Native SmolLM analyzer unavailable: {}. Expect tokenizer.json, model.safetensors, and config.json under {:?} (Candle/LLaMA format). The agent continues with rules and optional ONNX path in BehavioralClassifier.",
                    e, smollm_dir
                );
                    None
                }
            }
        } else {
            None
        };

        let gemma_dir = std::env::var("OSOOSI_GEMMA_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| {
                let standard_dir = models_dir.join("gemma4-e4b");
                if standard_dir.exists() && standard_dir.join("tokenizer.json").exists() {
                    return standard_dir;
                }

                let hf_base = models_dir.join("models--onnx-community--gemma-4-E4B-it-ONNX");
                let hf_dir = hf_base.join("snapshots");
                if let Ok(entries) = std::fs::read_dir(&hf_dir) {
                    for entry in entries.flatten() {
                        let p = entry.path();
                        if p.join("tokenizer.json").exists() {
                            return p;
                        }
                    }
                }
                standard_dir
            });

        let spider_eyes = Arc::new(osoosi_behavioral::SpiderEyes::new(
            &gemma_dir.to_string_lossy(),
        ));
        let gemma_cortex = if gemma_dir.exists() || osoosi_types::config::load_ai_config().enabled {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                osoosi_behavioral::Gemma4Analyzer::new(&gemma_dir)
            })) {
                Ok(Ok(analyzer)) => Some(Arc::new(analyzer)),
                Ok(Err(e)) => {
                    if osoosi_types::is_model_provisioning() {
                        info!("LLM Cortex waiting for model provisioning: {}. Using baseline heuristics.", e);
                    } else {
                        warn!(
                            "LLM ONNX cortex failed to load: {}. Check model.onnx, tokenizer.json, and ONNX Runtime (ort.dll) version vs `ort` crate.",
                            e
                        );
                    }
                    None
                }
                Err(_) => {
                    warn!(
                        "LLM ONNX init panicked (often ONNX Runtime native library mismatch). Install a matching ORT or remove {:?} to skip.",
                        gemma_dir
                    );
                    None
                }
            }
        } else {
            None
        };

        let foundation_sec_dir = std::env::var("OSOOSI_FOUNDATION_SEC_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| models_dir.join("foundation-sec"));

        let foundation_sec_cortex = if foundation_sec_dir.exists()
            || std::env::var("OSOOSI_FOUNDATION_SEC_ENABLED").unwrap_or_default() == "1"
            || osoosi_types::config::load_ai_config().foundation_sec_enabled
        {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                osoosi_behavioral::FoundationSecAnalyzer::new(&foundation_sec_dir)
            })) {
                Ok(Ok(analyzer)) => Some(Arc::new(analyzer)),
                Ok(Err(e)) => {
                    warn!("FoundationSec cortex failed to load: {}.", e);
                    None
                }
                Err(_) => {
                    warn!("FoundationSec init panicked.");
                    None
                }
            }
        } else {
            None
        };

        let storyteller = Arc::new(crate::forensics::ForensicStoryteller::new(
            gemma_cortex.clone(),
            foundation_sec_cortex.clone(),
        ));

        let provisioner = Arc::new(osoosi_telemetry::AgentProvisioner::new(
            host_executor.clone(),
        ));
        let blocking_manager = Arc::new(crate::blocking_manager::BlockingManager::new(provisioner));
        // Register Voters into Policy Engine for Multi-Detector Consensus
        policy
            .add_voter(Box::new(osoosi_policy::voters::SemanticVoter {
                engine: osoosi_policy::semantic::SemanticEngine::new(),
            }))
            .await;

        policy
            .add_voter(Box::new(osoosi_policy::voters::TrustedVendorVoter))
            .await;
        policy
            .add_voter(Box::new(osoosi_policy::voters::GitNoiseVoter))
            .await;

        policy
            .add_voter(Box::new(osoosi_policy::voters::NsrlVoter {
                cache: nsrl_cache.clone(),
                memory: memory.clone(),
            }))
            .await;

        policy
            .add_voter(Box::new(osoosi_policy::voters::OtxVoter {
                indicators: policy.otx_indicators_ref().clone(),
                memory: memory.clone(),
            }))
            .await;

        if let Some(ref gemma) = gemma_cortex {
            policy
                .add_voter(Box::new(osoosi_policy::voters::GemmaVoter::new(
                    gemma.clone(),
                )))
                .await;
        }

        if let Some(ref foundation_sec) = foundation_sec_cortex {
            policy
                .add_voter(Box::new(osoosi_policy::voters::FoundationSecVoter::new(
                    foundation_sec.clone(),
                )))
                .await;
        }

        policy
            .add_voter(Box::new(osoosi_policy::voters::KevVoter {
                memory: memory.clone(),
                config: policy.config.clone(),
            }))
            .await;

        policy
            .add_voter(Box::new(osoosi_policy::voters::CveLookupVoter {
                fetcher: policy.fetcher.clone(),
                memory: memory.clone(),
                cve_cache: policy.cve_cache.clone(),
                broadcaster: policy.intel_broadcaster.clone(),
                node_id: node_id.clone(),
            }))
            .await;

        // Behavioral Threat Model Voter: Uses the bulk-trained CVE/Lineage model
        policy
            .add_voter(Box::new(osoosi_policy::voters::BehavioralThreatVoter {
                model: threat_model.clone(),
            }))
            .await;

        // Decompile Voter: SpiderEyes binary analysis (LLM + Capstone)
        policy
            .add_voter(Box::new(osoosi_policy::voters::DecompileVoter {
                spider: spider_eyes.clone(),
            }))
            .await;

        // Agentic Escape Detection Voter (Process Reward & State Trajectory Scoring)
        policy
            .add_voter(Box::new(
                osoosi_policy::agentic_voter::AgenticPolicyVoter::new(),
            ))
            .await;

        // Default-Deny Agent Network Egress & Covert Side-Channel Isolation Voter
        policy
            .add_voter(Box::new(
                osoosi_policy::agent_egress::AgentEgressVoter::new(),
            ))
            .await;

        // Cloudflare AI Security Audit Voter (Tool-Argument Injection, Memory Poisoning & Memory Safety)
        policy
            .add_voter(Box::new(
                osoosi_policy::ai_audit_voter::AiSecurityAuditVoter::new(),
            ))
            .await;

        // Nonlinear Phase-Lock Attractor & Physics-of-Zero Invariant Voter (Linux & Windows)
        policy
            .add_voter(Box::new(
                osoosi_policy::voters::PhaseLockAttractorVoter::new(),
            ))
            .await;

        policy
            .add_voter(Box::new(osoosi_policy::voters::ZeroDayVoter::new()))
            .await;
        policy
            .add_voter(Box::new(osoosi_policy::voters::SandboxSurfaceVoter))
            .await;

        // Enhanced Detection Engines (Adapted from Rustinel)
        let mut sigma_engine = osoosi_policy::sigma::SigmaEngine::new();
        let sigma_dir = osoosi_types::config::resolve_sigma_rules_dir();
        let sigma_dir = if sigma_dir.is_dir() {
            sigma_dir
        } else {
            std::path::PathBuf::from("config/sigma")
        };
        sigma_engine.load_rules_from_dir(&sigma_dir);
        let sigma_engine = Arc::new(sigma_engine);
        policy
            .add_voter(Box::new(osoosi_policy::voters::SigmaVoter {
                engine: sigma_engine,
            }))
            .await;

        let mut ioc_engine = osoosi_policy::ioc::IocEngine::new();
        ioc_engine.load_from_files(std::path::Path::new("config/ioc"));
        let ioc_engine = Arc::new(ioc_engine);
        policy
            .add_voter(Box::new(osoosi_policy::voters::IocVoter {
                engine: ioc_engine,
            }))
            .await;

        policy
            .add_voter(Box::new(crate::voters::YaraXVoter {
                yara_manager: yara_manager.clone(),
                adaptive: adaptive.clone(),
                total_detections: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            }))
            .await;
        if let Some(ref voter) = behavioral_yara_voter {
            policy.add_voter(Box::new((**voter).clone())).await;
        }
        policy
            .add_voter(Box::new(crate::voters::DotscopeVoter {
                analyzer: dotscope_analyzer.clone(),
                adaptive: adaptive.clone(),
            }))
            .await;
        policy
            .add_voter(Box::new(crate::voters::MemoryInspectionVoter {
                memory: memory.clone(),
                adaptive: adaptive.clone(),
            }))
            .await;

        // MalConv / ONNX malware model + YARA — same [`MalwareScanner`] as Clam; separate vote for ML path
        policy
            .add_voter(Box::new(crate::voters::MalConvVoter {
                scanner: malware_scanner.clone(),
                adaptive: adaptive.clone(),
            }))
            .await;

        // Mandiant Trio Voters (Capa + Floss)
        policy
            .add_voter(Box::new(crate::voters::CapaVoter {
                analyzer: static_analyzer.clone(),
                adaptive: adaptive.clone(),
            }))
            .await;

        policy
            .add_voter(Box::new(crate::voters::CompositionVoter {
                analyzer: static_analyzer.clone(),
                adaptive: adaptive.clone(),
            }))
            .await;

        // Privacy-Enforced Voter: DP + Merkle Audit
        let privacy_config = osoosi_dp::PrivacyConfig::default();
        policy
            .add_voter(Box::new(osoosi_policy::voters::PrivacyVoter::new(
                privacy_config,
                audit.clone(),
            )))
            .await;

        // Native Instrumentation Voter: Ported from OpenEDR
        policy
            .add_voter(Box::new(osoosi_policy::voters::NativeVoter {
                memory: memory.clone(),
            }))
            .await;

        // Injection Telemetry Voter: Processes inner-process hook events (BitBlt, CreateProcessW, send, ptrace, etc.)
        policy
            .add_voter(Box::new(osoosi_policy::voters::InjectionTelemetryVoter))
            .await;

        // DNS Shield Voter: Evaluates DNS query telemetry (DGA, tunneling, blocklist, darknet)
        policy
            .add_voter(Box::new(osoosi_policy::voters::DnsShieldVoter))
            .await;

        // Sysmon DNS Voter (Event ID 22): Process-attributed DNS analysis with LLM context
        let dns_blocklist = Arc::new(osoosi_dns::DnsBlocklist::new());
        policy
            .add_voter(Box::new(osoosi_policy::voters::SysmonDnsVoter {
                blocklist: dns_blocklist,
            }))
            .await;

        // --- 4. BEHAVIORAL AI CONSENSUS ---
        // Connect the SecureBERT/SmolLM/Gemma classifier to the voting engine.
        policy
            .add_voter(Box::new(crate::voters::BehavioralClassifierVoter {
                classifier: behavioral_classifier.clone(),
                adaptive: adaptive.clone(),
            }))
            .await;

        // Start background threat intel sync (NVD Local Cache, etc.)
        policy.start_background_tasks();

        let deception_engine = Arc::new(tokio::sync::RwLock::new(
            osoosi_behavioral::deception::EntanglementEngine::new(),
        ));

        let privacy = Arc::new(privacy::PrivacyLayer::new(trust.clone()));
        let military = Arc::new(military::MilitaryGuard::new());

        let mesh_gossip_count_atomic = Arc::new(AtomicU32::new(0));

        let preexisting_accounts = Arc::new(query_system_accounts());
        info!(
            "Account Security Guardrail: Baselined {} pre-existing/protected accounts.",
            preexisting_accounts.len()
        );

        let supervisor = Arc::new(supervisor::CognitiveFusionSupervisor::new());
        let active_tarpit = osoosi_runtime::tarpit::ActiveProcessTarpit::new();
        supervisor.clone().start(memory.clone(), active_tarpit);

        let kernel_driver_client = osoosi_runtime::kernel_driver::KernelDriverClient::open();
        if let Some(ref client) = kernel_driver_client {
            info!("[KERNEL_DRIVER] Ring-0 Pre-Operation Driver attached! Hardware-enforced process blocking active before Sysmon Event 1.");
            let autonomy_cfg = osoosi_types::load_autonomy_config();
            let mode = match autonomy_cfg.current_mode() {
                osoosi_types::AutonomyMode::Audit => {
                    osoosi_runtime::kernel_driver::DriverAutonomyMode::Audit
                }
                osoosi_types::AutonomyMode::Lockdown => {
                    osoosi_runtime::kernel_driver::DriverAutonomyMode::Lockdown
                }
                _ => osoosi_runtime::kernel_driver::DriverAutonomyMode::Active,
            };
            let _ = client.set_mode(mode);
        } else {
            info!("[KERNEL_DRIVER] Ring-0 driver not detected. Operating with user-mode WFP packet filter + active thread tarpit.");
        }
        let kernel_driver = Arc::new(parking_lot::RwLock::new(kernel_driver_client));

        // Background task: drain driver interception events and feed into memory and audit trail
        {
            let kd_bg = kernel_driver.clone();
            let memory_bg = memory.clone();
            let audit_bg = audit.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_millis(500));
                loop {
                    interval.tick().await;
                    let events_opt = {
                        let lock = kd_bg.read();
                        if let Some(ref kd) = *lock {
                            kd.poll_interceptions().ok()
                        } else {
                            None
                        }
                    };
                    if let Some(events) = events_opt {
                        for ev in events {
                            warn!(
                                "[KERNEL_DRIVER] Intercepted process spawn PID: {} Image: {} (Blocked: {})",
                                ev.pid, ev.image_path, ev.blocked
                            );
                            let _ = memory_bg.log_threat_event(
                                "KERNEL_DRIVER_PRE_EXEC_BLOCK",
                                ev.pid,
                                ev.parent_pid,
                            );
                            audit_bg.log(
                                "KERNEL_DRIVER_INTERCEPTION",
                                serde_json::json!({
                                    "pid": ev.pid,
                                    "parent_pid": ev.parent_pid,
                                    "image_path": ev.image_path,
                                    "command_line": ev.command_line,
                                    "blocked": ev.blocked,
                                    "timestamp": ev.timestamp,
                                }),
                            );
                        }
                    }
                }
            });
        }

        let forensics_cfg = osoosi_types::config::load_forensics_config();
        let forensics = Arc::new(osoosi_forensics::VelociraptorClient::new(forensics_cfg));
        info!(
            "[FORENSICS] Embedded Velociraptor extraction service initialized (available: {})",
            forensics.is_available()
        );

        let decision_cfg = osoosi_types::config::load_decision_model_config();
        let decision_engine = Arc::new(osoosi_behavioral::decision_model::ClefDecisionEngine::new(
            decision_cfg.clone(),
        ));
        supervisor.set_decision_engine(decision_engine.clone());
        info!(
            "[DECISION] Non-autoregressive Clef Decision Model initialized (provider: {}, model: {}, enabled: {})",
            decision_cfg.provider, decision_cfg.model, decision_cfg.enabled
        );

        let agent_anomaly_detector = Arc::new(osoosi_agent_anomaly::AgentAnomalyDetector::new(
            50, 200, None,
        ));
        info!("[AAD] Native Rust Agent Anomaly Detection (OWASP Top 10) initialized.");

        let siquery_engine = Arc::new(osoosi_agent_anomaly::SiqueryEngine::new());
        let siquery_last_telemetry = Arc::new(parking_lot::RwLock::new(None));
        info!("[SIQUERY] Native in-process relational SQL engine initialized (41 tables).");

        let mitre_synchronizer = Arc::new(mitre::AutonomousMitreSynchronizer::new(
            mesh_command_tx.clone(),
        ));
        mitre::AutonomousMitreSynchronizer::start_background_refresh_loop(
            mitre_synchronizer.clone(),
        );
        info!("[MITRE-STIX] Autonomous MITRE ATT&CK + ATLAS STIX 2.1 refresh loop started.");

        let ai_feed_collector = Arc::new(ai_feeds::AutonomousAiFeedCollector::new(
            mesh_command_tx.clone(),
        ));
        crate::ai_feeds::init_global_ai_feed_collector(ai_feed_collector.clone());
        ai_feeds::AutonomousAiFeedCollector::start_background_loop(ai_feed_collector.clone());
        info!("[AI-FEEDS] Autonomous AI Threat Feed Ingestion loop started (60m interval).");

        let rl_controller = Arc::new(parking_lot::RwLock::new(
            osoosi_agent_anomaly::RLAdaptiveController::new(),
        ));
        info!("[RL-CONTROLLER] RL Adaptive Controller initialized (SkyRL MDP & Action Masking).");

        let orch = Self {
            memory,
            mesh_peer_count,
            start_time: Instant::now(),
            policy,
            mesh,
            mesh_command_tx,
            response,
            audit,
            trust,
            watcher,
            file_event_rx,
            patch_engine,
            privacy,
            military,
            threat_model,
            malware_scanner,
            triage_store,
            baseline,
            policy_consensus: Arc::new(dashmap::DashMap::new()),
            approval_queue,
            sandbox,
            shield,
            holograph,
            relativistic,
            behavioral_classifier,
            behavioral_analyzer,
            pii_classifier,
            browser_guard,
            static_analyzer,
            deception_engine,
            correlator,
            nsrl_cache,
            remediation,
            adaptive,
            storyteller,
            causal_ai,
            self_healing,
            ghost_nodes,
            canary,
            behavioral_engine,
            gemma_cortex,
            blocking_manager,
            yara_manager,
            runtime_config,
            host_executor,
            task_executor,
            behavioral_debouncer,
            spider_eyes,
            alert_suppression_cache: Arc::new(dashmap::DashMap::new()),
            mesh_gossip_feed: Arc::new(std::sync::RwLock::new(
                std::collections::VecDeque::with_capacity(200),
            )),
            dismissed_gossip_ids: Arc::new(dashmap::DashSet::new()),
            rea_adjudicated_clean_procs: Arc::new(dashmap::DashSet::new()),
            last_rea_adjudication_ts: Arc::new(std::sync::atomic::AtomicI64::new(0)),
            mesh_broadcast_debouncer: Arc::new(dashmap::DashMap::new()),
            nostr_mesh,
            mesh_gossip_count_atomic,
            telemetry_total_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            last_telemetry_summary: Arc::new(tokio::sync::Mutex::new(Instant::now())),
            last_telemetry_summary_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            canary_correlator: {
                let (canary_alert_tx, _canary_alert_rx) = tokio::sync::mpsc::channel(100);
                Arc::new(tokio::sync::Mutex::new(
                    osoosi_telemetry::canary::CanaryCorrelator::new(canary_alert_tx, 3),
                ))
            },
            hollowing_detector: Arc::new(
                osoosi_telemetry::hollowing::ProcessHollowingDetector::new(),
            ),
            preexisting_accounts,
            supervisor,
            kernel_driver,
            forensics,
            decision_engine,
            agent_anomaly_detector,
            siquery_engine,
            siquery_last_telemetry,
            mitre_synchronizer,
            ai_feed_collector,
            rl_controller,
        };

        // Start background log retention loop (hourly rotation and pruning)
        let log_dir = osoosi_types::resolve_log_directory();
        let log_cfg = osoosi_types::load_log_retention_config();
        tokio::spawn(
            crate::log_retention::LogRetentionManager::start_retention_loop(log_dir, log_cfg),
        );

        osoosi_model::malware::trim_working_set_after_init();

        orch.run_autonomous_rea_threat_adjudication();

        Ok(orch)
    }

    /// Register voters that require an Arc reference to the orchestrator (post-initialization).
    pub async fn post_init_voters(self: &Arc<Self>) {
        self.policy
            .add_voter(Box::new(osoosi_policy::voters::CredentialGuardVoter))
            .await;
        self.policy
            .add_voter(Box::new(osoosi_policy::voters::ProcessInjectionVoter))
            .await;
        self.policy
            .add_voter(Box::new(osoosi_policy::voters::HarTrafficVoter))
            .await;
        self.policy
            .add_voter(Box::new(osoosi_policy::voters::MercuryFluidVoter))
            .await;
        self.policy
            .add_voter(Box::new(osoosi_policy::voters::SpiderWebPhysicsVoter))
            .await;
        self.policy
            .add_voter(Box::new(
                osoosi_policy::voters::PhaseLockAttractorVoter::new(),
            ))
            .await;
        self.policy
            .add_voter(Box::new(
                osoosi_policy::voters::DualChannelDiscriminationVoter::new(),
            ))
            .await;
        self.policy
            .add_voter(Box::new(crate::rea::ReaVoter::new()))
            .await;
        self.policy
            .add_voter(Box::new(crate::rea::OpenJevVoter::new()))
            .await;
        self.policy
            .add_voter(Box::new(crate::voters::BehavioralProcessLineageVoter::new(
                self.behavioral_analyzer.clone(),
                self.agent_anomaly_detector.classifier.clone(),
                crate::causal_graph::global_causal_security_graph(),
                self.adaptive.clone(),
            )))
            .await;
        self.policy
            .add_voter(Box::new(crate::voters::ClefDecisionVoter::new(
                self.decision_engine.clone(),
                self.adaptive.clone(),
            )))
            .await;
        info!(
            target: crate::CONSENSUS_LOG_TARGET,
            "[CONSENSUS] native voters registered and operational (CredentialGuard + ProcessInjection + HarTrafficVoter + MercuryFluidVoter + SpiderWebPhysicsVoter + PhaseLockAttractorVoter + DualChannelDiscriminationVoter + REA-Voter + OpenJEV-Voter + Behavioral-Process-Lineage + Clef-Decision-Model)"
        );
    }

    pub async fn boot(&self) -> anyhow::Result<()> {
        info!(
            "OpenỌ̀ṣọ́ọ̀sì Agent Booting (Target: {})",
            std::env::consts::OS
        );

        // 0. Proactive Out-Of-Memory Watchdog
        crate::spawn_memory_watchdog();

        // 1. Adaptive Runtime & Maintenance
        self.start_maintenance_loop();

        // 1a. Dashboard Metrics & Hydration
        let hyd_orch = self.clone();
        tokio::spawn(async move {
            // Initial Welcome Event (Hydration)
            hyd_orch.audit.log("ACTIVITY_BOOT", serde_json::json!({
                "message": "OpenỌ̀ṣọ́ọ̀sì Agent Intelligence active. Monitoring host security events.",
                "status": "Healthy"
            }));

            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                if let Ok(mut last) = hyd_orch.last_telemetry_summary.try_lock() {
                    if last.elapsed() > Duration::from_secs(55) {
                        let total = hyd_orch.telemetry_total_count.load(Ordering::Relaxed);
                        let prev_count = hyd_orch
                            .last_telemetry_summary_count
                            .swap(total, Ordering::Relaxed);
                        let diff = total.saturating_sub(prev_count);
                        if diff > 0 {
                            hyd_orch.audit.log(
                                "TELEMETRY_SUMMARY",
                                serde_json::json!({
                                    "count": diff,
                                    "total_ingested": total,
                                    "computer": hyd_orch.trust.did().to_string(),
                                }),
                            );
                        }
                        *last = Instant::now();
                    }
                }
            }
        });

        self.clone().adaptive().start_adaptive_loop();

        // 2. Behavioral & Resource Monitors
        self.start_cybershield_monitor();
        self.start_behavioral_detector();

        // 3. File Monitoring (Hooking the FileWatcher)
        let watch_paths = osoosi_types::load_watch_paths_from_config()
            .unwrap_or_else(osoosi_types::all_physical_drive_paths);
        let paths_refs: Vec<&str> = watch_paths.iter().map(String::as_str).collect();
        if let Err(e) = self.start_file_watcher_paths(&paths_refs).await {
            warn!(
                "FileWatcher failed to start: {}. Real-time file monitoring disabled.",
                e
            );
        } else {
            info!("FileWatcher activated for {} paths.", paths_refs.len());
        }

        // 4. Host Security Events (Sysmon/Journald)
        let event_source = if cfg!(windows) {
            "".to_string() // Triggers NativeETWReader (Zero-Process Stack)
        } else {
            "default".to_string()
        };
        self.start_host_event_loop(&event_source, 2).await;

        // 5. Intelligent Sourcing & Self-Healing
        self.start_repair_loop(3600, true).await;
        self.start_fetcher_loop().await;
        // Model training every 30 minutes: training involves SQLite reads, Rayon ML work,
        // and mesh delta broadcasts — doing it every 60s was a significant background CPU load.
        self.start_model_training_loop(1800).await;

        // 6. Ghost Node Deception Services + Canary Deployment
        let ghost_enabled = std::env::var("OSOOSI_GHOST_ENABLED")
            .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
            .unwrap_or(true);
        if ghost_enabled {
            info!("Starting Ghost Node deception services (honeypot listeners)...");
            self.ghost_nodes.start_all_deceptions().await;

            // Deploy Ghost Canary files on disk
            let canary_system = crate::canary::CanaryManager::new();
            let deployed = canary_system.deploy_canaries();
            if !deployed.is_empty() {
                info!(
                    "Deployed {} Ghost Canary traps across the filesystem.",
                    deployed.len()
                );
            }

            // Deploy ghost trap files (high-value bait)
            let traps_path = &self.runtime_config.traps_path;
            if let Err(e) = self.response.spawn_ghost_files(traps_path).await {
                warn!("Ghost trap file deployment failed: {} (non-fatal)", e);
            } else {
                info!("Ghost trap files deployed to {:?}", traps_path);
            }
        } else {
            info!("Ghost Node deception disabled via OSOOSI_GHOST_ENABLED=0.");
        }

        info!("All security subsystems are ACTIVE.");

        // 7. NOSTR HEARTBEAT (BitChat style)
        let orch_heart = self.clone();
        tokio::spawn(async move {
            let node_id = orch_heart.trust.did().to_string();
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                if let Err(e) = orch_heart.nostr_mesh.send_heartbeat(&node_id).await {
                    debug!("Nostr heartbeat failed: {} (relays may be offline)", e);
                }
            }
        });

        // 8a. Osquery relational discovery loop for AI agents (every 30s)
        let osquery_orch = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
            loop {
                interval.tick().await;
                let records = osquery_orch
                    .agent_anomaly_detector
                    .classifier
                    .run_osquery_host_scan();
                if !records.is_empty() {
                    debug!(
                        "Osquery relational scan identified {} active AI agent candidates",
                        records.len()
                    );
                }
            }
        });

        // 8b. Agent Anomaly Detection (AAD) findings listener & P2P Mesh Watch-Out Broadcast
        let aad_orch = self.clone();
        let mut aad_rx = self.agent_anomaly_detector.subscribe_findings();
        tokio::spawn(async move {
            info!("Agent Anomaly Detection (AAD) findings listener active.");
            while let Ok(finding) = aad_rx.recv().await {
                if finding.severity == osoosi_agent_anomaly::AlertSeverity::Critical
                    || finding.severity == osoosi_agent_anomaly::AlertSeverity::High
                {
                    warn!(
                        "Agent Anomaly Threat [{}]: {} (Agent: {}, Session: {})",
                        finding.risk_category.as_code(),
                        finding.rationale,
                        finding.agent_id,
                        finding.session_id
                    );
                    aad_orch.audit.log(
                        "AGENT_ANOMALY_THREAT",
                        serde_json::json!({
                            "id": finding.id,
                            "agent_id": finding.agent_id,
                            "session_id": finding.session_id,
                            "risk_category": finding.risk_category.as_code(),
                            "risk_name": finding.risk_category.as_name(),
                            "severity": finding.severity.as_str(),
                            "confidence": finding.confidence_score,
                            "rationale": finding.rationale,
                            "mitigation": finding.recommended_mitigation,
                            "evidence": finding.evidence,
                        }),
                    );

                    let threat_sig = osoosi_types::ThreatSignature {
                        id: format!("aad-{}", finding.id),
                        cve_id: None,
                        hash_blake3: None,
                        process_name: Some(finding.agent_id.clone()),
                        parent_process: None,
                        version: None,
                        confidence: finding.confidence_score,
                        detector_count: 1,
                        detected_at: chrono::Utc::now(),
                        source_node: aad_orch.trust.did().to_string(),
                        signature: None,
                        public_key: None,
                        merkle_proof: None,
                        recommended_action: osoosi_types::ResponseAction::Isolate,
                        reason: Some(format!(
                            "[AAD Consensus] {}: {}",
                            finding.risk_category.as_code(),
                            finding.rationale
                        )),
                        predicted_next: Some(
                            "Autonomous containment engaged to sever breakout limb.".to_string(),
                        ),
                        epsilon: None,
                        require_approval: false,
                        action_state: osoosi_types::ActionState::Executed,
                        is_signed: false,
                        mitre_tactic: Some("TA0002".to_string()),
                        mitre_technique: Some("AML.T0043".to_string()),
                        mitre_technique_name: Some("Adversarial AI / Agentic Breakout".to_string()),
                    };

                    let Some(threat_sig) = aad_orch
                        .adjudicate_threat_signature_with_rea_and_voters(None, threat_sig, None)
                        .await
                    else {
                        continue;
                    };

                    // Execute autotomy severance after multi-voter consensus confirms threat
                    aad_orch
                        .agent_anomaly_detector
                        .containment_ring
                        .sever_rogue_agent_branch(&finding.agent_id, &finding.rationale, None)
                        .await;

                    let _ = aad_orch.memory.log_threat(&threat_sig);
                    aad_orch.record_gossip_threat(&threat_sig, "AGENT_BREAKOUT_ISOLATED");

                    // Broadcast over libp2p GossipSub wire mesh
                    let tx_guard = aad_orch.mesh_command_tx.lock().await;
                    if let Some(ref tx) = *tx_guard {
                        let _ = tx
                            .send(osoosi_wire::MeshCommand::Broadcast(threat_sig.clone()))
                            .await;
                    }

                    // Publish over decentralized Nostr BitChat mesh
                    let nostr = aad_orch.nostr_mesh.clone();
                    let sig_nostr = threat_sig.clone();
                    tokio::spawn(async move {
                        if let Err(e) = nostr.broadcast_threat(sig_nostr).await {
                            debug!("Failed to broadcast AAD threat via Nostr relay: {}", e);
                        }
                    });
                }
            }
        });

        // 8c. Continuous Siquery EDR Relational Multi-Table Audit Sweep (every 45s)
        let siquery_orch = self.clone();
        tokio::spawn(async move {
            info!("Siquery EDR Relational Multi-Table Audit Engine activated.");
            // Initial sweep immediately on boot
            let _ = siquery_orch.run_siquery_edr_audit_sweep().await;
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(45));
            loop {
                interval.tick().await;
                let _ = siquery_orch.run_siquery_edr_audit_sweep().await;
            }
        });

        Ok(())
    }
}
