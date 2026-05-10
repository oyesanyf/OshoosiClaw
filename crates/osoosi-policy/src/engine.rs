//! Threat Engine (The "Brain").
//!
//! Correlates telemetry events with threat signatures.

use crate::feed::OtxIndicators;
use crate::graph::{GraphCorrelationEngine, Relationship};
use crate::semantic::SemanticEngine;
use dashmap::DashMap;
use osoosi_types::{HostSecurityEvent, ThreatSignature};
use osoosi_memory::MemoryStore;
use std::sync::Arc;
use std::sync::RwLock;
use tracing::{debug, info, warn};

/// `tracing` target for grep-friendly consensus / voting lines (`RUST_LOG=consensus=debug`).
pub const CONSENSUS_LOG_TARGET: &str = "consensus";

#[derive(Debug, Clone)]
pub struct VoteResult {
    pub confidence: f32,
    pub reason: String,
    pub weight: f32,
}

use async_trait::async_trait;

#[async_trait]
pub trait ThreatVoter: Send + Sync {
    fn name(&self) -> String;
    async fn vote(&self, event: &HostSecurityEvent) -> Option<VoteResult>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum EvidenceClass {
    LiveNetwork,
    Behavior,
    Memory,
    StaticArtifact,
    ThreatIntel,
    Reputation,
}

#[derive(Debug, Clone)]
struct EvidenceVote {
    result: VoteResult,
    class: EvidenceClass,
    reliability: f32,
    strong_action: bool,
}

#[derive(Debug)]
struct EvidenceDecision {
    confidence: f32,
    action: osoosi_types::ResponseAction,
    require_approval: bool,
    summary: String,
}

fn process_name_from_event(event: &HostSecurityEvent) -> Option<String> {
    event
        .data
        .get("Image")
        .and_then(|v| v.as_str())
        .and_then(|p| std::path::Path::new(p).file_name())
        .and_then(|n| n.to_str())
        .map(ToOwned::to_owned)
}

fn preferred_hash_from_event(event: &HostSecurityEvent) -> Option<String> {
    let hashes = event.data.get("Hashes")?.as_str()?;
    for prefix in ["SHA256=", "SHA256:", "SHA1=", "SHA1:", "MD5=", "MD5:"] {
        if let Some(value) = hashes
            .split(',')
            .map(str::trim)
            .find_map(|part| part.strip_prefix(prefix))
        {
            let value = value.trim();
            if !value.is_empty() {
                return Some(value.to_ascii_lowercase());
            }
        }
    }
    None
}

fn event_image_path(event: &HostSecurityEvent) -> Option<&str> {
    event.data.get("Image").and_then(|v| v.as_str())
}

fn event_stem(event: &HostSecurityEvent) -> String {
    event_image_path(event)
        .and_then(|p| std::path::Path::new(p).file_stem())
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
}

fn is_trusted_operational_tool(event: &HostSecurityEvent, config: &osoosi_types::PolicyConfig) -> bool {
    let image_path = event.data.get("Image").and_then(|v| v.as_str()).unwrap_or("");
    if image_path.is_empty() {
        return false;
    }
    let path_lc = image_path.to_lowercase();
    
    // 1. Check dynamic whitelists from config
    let is_trusted_path = config.trusted_paths.iter().any(|p| path_lc.contains(&p.to_lowercase()));
    let is_trusted_stem = config.trusted_stems.iter().any(|s| {
        let s_lc = s.to_lowercase();
        path_lc.ends_with(&s_lc) || path_lc.contains(&format!("\\{}\\", s_lc)) || path_lc.ends_with(&format!("\\{}", s_lc))
    });

    if is_trusted_path || is_trusted_stem {
        // 2. Obtain signature from the file on disk (Authenticode)
        if let Some(metadata) = osoosi_types::get_pe_metadata(std::path::Path::new(image_path)) {
            if metadata.is_signed {
                return true;
            }
        }

        // 3. Fallback to Sysmon's own signature check
        let sig_status = event.data.get("SignatureStatus")
            .or_else(|| event.data.get("Signature Status"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_lowercase();
        
        if sig_status == "valid" || sig_status.contains("trusted") {
            return true;
        }
        
        // 4. Last resort: If it's in a critical System32 path, we trust it to avoid OS breakage
        if path_lc.contains("\\windows\\system32") || path_lc.contains("\\windows\\syswow64") {
            return true;
        }
    }

    false
}

fn classify_vote(
    voter: &str,
    result: &VoteResult,
    event: &HostSecurityEvent,
) -> (EvidenceClass, f32, bool) {
    let reason_lc = result.reason.to_ascii_lowercase();
    match voter {
        "OTX-C2" => {
            let live = matches!(
                event.event_id,
                3 | 22 // 3: NetworkConnect, 22: DnsQuery
            );
            if live {
                (EvidenceClass::LiveNetwork, 1.0, true)
            } else {
                (EvidenceClass::ThreatIntel, 0.72, false)
            }
        }
        "CISA-KEV" => (EvidenceClass::ThreatIntel, 0.58, false),
        "NVD-CVE-Lookup" => (EvidenceClass::ThreatIntel, 1.0, true), // High reliability, triggers strong action
        "BehavioralYara" => (EvidenceClass::Behavior, 0.88, true),
        "YaraX-Signatures" | "YaraX-Memory" | "HollowsHunter-Memory" | "MemoryInspection-Native" => {
            (EvidenceClass::Memory, 1.0, true)
        }
        "SemanticIntent" | "LLM-Reasoning" => (EvidenceClass::Behavior, 0.78, true),
        "Decompile" => (EvidenceClass::Behavior, 0.96, true),
        "Capa-Behavior" => (EvidenceClass::Behavior, 0.92, true),
        "Floss-Artifact" => (EvidenceClass::StaticArtifact, 0.82, false),
        "Dotscope-Forensics" => (EvidenceClass::StaticArtifact, 0.85, true),
        name if name.contains("NexusShield") => (EvidenceClass::StaticArtifact, 0.95, true),
        "ZeroDayTracker" => (EvidenceClass::ThreatIntel, 1.0, true),
        "SandboxSurfaceAnalysis" => (EvidenceClass::Behavior, 0.85, true),
        name if name.contains("MalConv") || name.contains("ML") => {
            let weak_pe_signature =
                reason_lc.contains("ml=0.000") && reason_lc.contains("sig=1.000");
            if weak_pe_signature {
                (EvidenceClass::StaticArtifact, 0.42, false)
            } else {
                (EvidenceClass::StaticArtifact, 0.78, true)
            }
        }
        _ => (EvidenceClass::Reputation, 0.65, false),
    }
}

fn orchestrate_evidence(votes: &[EvidenceVote], event: &HostSecurityEvent, config: &osoosi_types::PolicyConfig) -> EvidenceDecision {
    use osoosi_types::ResponseAction;

    let mut classes = std::collections::HashSet::new();
    let mut support = 0.0f32;
    let mut mass = 0.0f32;
    let mut max_single = 0.0f32;
    let mut strong_action = false;
    let mut threat_intel_only = true;

    for vote in votes {
        classes.insert(vote.class);
        let weighted =
            vote.result.confidence.clamp(0.0, 1.0) * vote.result.weight.max(0.0) * vote.reliability;
        support += weighted;
        mass += vote.result.weight.max(0.0) * vote.reliability;
        max_single = max_single.max(weighted);
        strong_action |= vote.strong_action;
        threat_intel_only &= vote.class == EvidenceClass::ThreatIntel;
    }

    let independent = classes.len();
    let base = if mass > 0.0 { support / mass } else { 0.0 };
    let corroboration = match independent {
        0 => 0.0,
        1 => 0.52,
        2 => 0.82,
        _ => 1.0,
    };
    let mut confidence = (base * corroboration + max_single.min(1.0) * 0.12).min(1.0);

    let has_live_network = classes.contains(&EvidenceClass::LiveNetwork);
    let has_behavior = classes.contains(&EvidenceClass::Behavior);
    let has_memory = classes.contains(&EvidenceClass::Memory);
    let has_static = classes.contains(&EvidenceClass::StaticArtifact);
    let lifecycle_only = matches!(
        event.event_id,
        1 | 5 // 1: ProcessCreate, 5: ProcessTerminate
    );
    let trusted_operational_tool = is_trusted_operational_tool(event, config);

    if threat_intel_only {
        confidence = confidence.min(0.49);
    }
    if lifecycle_only && !has_behavior && !has_memory && !has_live_network {
        confidence = confidence.min(0.62);
    }
    if has_static && !has_behavior && !has_memory && !has_live_network && independent < 3 {
        confidence = confidence.min(0.68);
    }
    if trusted_operational_tool && !has_live_network && !has_behavior && !has_memory {
        confidence = confidence.min(0.18);
    } else if trusted_operational_tool && !strong_action {
        confidence = confidence.min(0.45);
    }

    // NVD-Negative Suppression: if the CVE lookup explicitly found NO CVEs, and we only have static/intel evidence,
    // lower the score to ensure we wait for behavioral evidence.
    let nvd_negative = votes.iter().any(|v| v.result.reason.contains("No matching CVEs found") && v.result.weight < 0.0);
    if nvd_negative && !has_behavior && !has_memory && !has_live_network {
        confidence = confidence.min(0.35);
    }

    let require_approval = confidence >= 0.70 && independent < 2;
    let action = if confidence >= 0.94 && independent >= 3 && strong_action {
        ResponseAction::Isolate
    } else if confidence >= 0.82 && has_live_network && (has_behavior || has_static || has_memory) {
        ResponseAction::GhostTarpit
    } else if confidence >= 0.74 && has_live_network {
        ResponseAction::Tarpit
    } else if confidence >= 0.72 && strong_action && independent >= 2 {
        ResponseAction::Deception
    } else {
        ResponseAction::Alert
    };

    EvidenceDecision {
        confidence,
        action,
        require_approval,
        summary: format!(
            "EvidenceOrchestrator: classes={} independent={} strong_action={} base={:.2} confidence={:.2}",
            classes
                .iter()
                .map(|c| format!("{:?}", c))
                .collect::<Vec<_>>()
                .join("+"),
            independent,
            strong_action,
            base,
            confidence
        ),
    }
}

pub struct PolicyEngine {
    /// Local persistence store
    memory: Arc<MemoryStore>,
    /// Semantic Intent Filter
    _semantic: SemanticEngine,
    /// Relationship Graph
    graph: GraphCorrelationEngine,
    /// Custom threat signatures (Hash -> Signature)
    #[allow(dead_code)]
    signatures: Arc<DashMap<String, ThreatSignature>>,
    /// OTX indicators cached in-memory from feed fetch loop.
    otx_indicators: Arc<RwLock<OtxIndicators>>,

    /// Learned Zero-Day defenses from the mesh (CVE -> Learned Rule)
    global_intel_rules: Arc<DashMap<String, String>>,
    /// Consensus cache to prevent duplicate notifications (Key: EventID+Path+Hash -> (Signature, Time))
    consensus_cache: Arc<DashMap<String, (ThreatSignature, std::time::Instant)>>,
    /// Multi-tool consensus voters
    voters: Arc<tokio::sync::RwLock<Vec<Box<dyn ThreatVoter + Send + Sync>>>>,
    /// Global policy config (noise suppression, trusted paths)
    pub config: osoosi_types::PolicyConfig,
    /// Shared threat feed fetcher
    pub fetcher: Arc<crate::feed::ThreatFeedFetcher>,
    /// Optional callback to broadcast discoveries to the mesh
    pub intel_broadcaster: Arc<tokio::sync::RwLock<Option<Arc<dyn Fn(osoosi_types::GlobalIntelligence) + Send + Sync>>>>,
    /// Local SQLite cache for NVD CVEs
    pub cve_cache: Option<Arc<tokio::sync::Mutex<crate::cve_cache::CveCache>>>,
}

impl PolicyEngine {
    pub fn new(memory: Arc<MemoryStore>, config: osoosi_types::PolicyConfig) -> Self {
        Self {
            memory,
            _semantic: SemanticEngine::new(),
            graph: GraphCorrelationEngine::new(),
            signatures: Arc::new(DashMap::new()),
            otx_indicators: Arc::new(RwLock::new(OtxIndicators::default())),
            global_intel_rules: Arc::new(DashMap::new()),
            consensus_cache: Arc::new(DashMap::new()),
            voters: Arc::new(tokio::sync::RwLock::new(Vec::new())),
            config,
            fetcher: Arc::new(crate::feed::ThreatFeedFetcher::new()),
            intel_broadcaster: Arc::new(tokio::sync::RwLock::new(None)),
            cve_cache: {
                let db_path = std::path::Path::new("C:\\ProgramData\\OshoosiClaw\\nvd_cache.db");
                if let Some(parent) = db_path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                match crate::cve_cache::CveCache::new(db_path) {
                    Ok(cache) => Some(Arc::new(tokio::sync::Mutex::new(cache))),
                    Err(e) => {
                        warn!("Failed to initialize NVD SQLite cache: {}", e);
                        None
                    }
                }
            },
        }
    }

    pub async fn set_intel_broadcaster(&self, broadcaster: Arc<dyn Fn(osoosi_types::GlobalIntelligence) + Send + Sync>) {
        let mut guard = self.intel_broadcaster.write().await;
        *guard = Some(broadcaster);
    }

    pub async fn add_voter(&self, voter: Box<dyn ThreatVoter + Send + Sync>) {
        let mut guard = self.voters.write().await;
        let name = voter.name();
        guard.push(voter);
        info!(
            target: CONSENSUS_LOG_TARGET,
            voter = %name,
            total = guard.len(),
            "[CONSENSUS] registered threat voter"
        );
    }

    /// Spawns long-running background tasks for threat intelligence synchronization.
    pub fn start_background_tasks(&self) {
        let fetcher = self.fetcher.clone();
        let cache = self.cve_cache.clone();

        tokio::spawn(async move {
            info!("[PolicyEngine] NVD Background Sync Task started (Cycle: 24h).");
            loop {
                if let Some(ref cache_ref) = cache {
                    let api_key = osoosi_types::resolve_nvd_api_key();
                    info!("[PolicyEngine] Running scheduled NVD bulk synchronization...");
                    match fetcher.fetch_nvd_cves(api_key.as_deref()).await {
                        Ok(kevs) => {
                            let cache_guard = cache_ref.lock().await;
                            if let Err(e) = cache_guard.bulk_import(&kevs) {
                                warn!("[PolicyEngine] Failed to import NVD CVEs into local cache: {}", e);
                            } else {
                                info!("[PolicyEngine] NVD Local Cache updated with {} new records.", kevs.len());
                            }
                        }
                        Err(e) => {
                            warn!("[PolicyEngine] NVD Background Sync failed: {}", e);
                        }
                    }
                }
                // Sleep for 24 hours
                tokio::time::sleep(std::time::Duration::from_secs(86400)).await;
            }
        });
    }



    pub fn otx_indicators_ref(&self) -> &Arc<RwLock<OtxIndicators>> {
        &self.otx_indicators
    }

    /// Return all graph relationships for attack graph construction.
    pub fn graph_relationships(&self) -> Vec<Relationship> {
        self.graph.relationships()
    }

    pub fn update_otx_indicators(&self, indicators: OtxIndicators) {
        if let Ok(mut guard) = self.otx_indicators.write() {
            *guard = indicators;
        }
    }

    /// Returns a match reason if this Sysmon event hits an OTX IoC.
    ///
    /// IOCs are populated by the background `ThreatFeedFetcher::fetch_otx_indicators` (which uses
    /// **TAXII 1.1** when `OTX_USE_TAXII` is left at default) and persisted in SQLite. This is a
    /// **local lookup** — not a live TAXII poll per connection.
    pub fn otx_ioc_match_for_event(&self, event: &HostSecurityEvent) -> Option<String> {
        let otx = self.otx_indicators.read().ok()?;
        crate::otx_connection::otx_match_sysmon_event_normalized(&otx, &self.memory, event)
    }

    /// Check a single outbound (or inbound) IP from a connection against OTX state (memory + SQLite).
    pub fn otx_ioc_match_for_ip(&self, ip: &str) -> Option<String> {
        let otx = self.otx_indicators.read().ok()?;
        crate::otx_connection::otx_match_destination_ip(&otx, &self.memory, ip)
    }



    /// Register a temporary learned defense (Zero-Day defense from mesh gossip).
    pub fn register_temporary_rule(&self, cve_id: &str, rule: &str, _severity: f32) {
        info!(
            "PolicyEngine: Learning new defense for {} from mesh gossip.",
            cve_id
        );
        self.global_intel_rules
            .insert(cve_id.to_string(), rule.to_string());
    }

    /// Process a Sysmon event and check for threats.
    ///
    /// OTX / TAXII (or REST) **IoCs participate in the same weighted vote** as all other
    /// [`ThreatVoter`]s, typically through [`crate::voters::OtxVoter`]. If that voter is not
    /// registered, a matching [`Self::otx_ioc_match_for_event`] is merged in so TAXII-backed IOCs
    /// still affect consensus.
    pub async fn scan_event(&self, event: &HostSecurityEvent) -> Option<ThreatSignature> {
        use osoosi_types::ResponseAction;

        let image_path = event_image_path(event).unwrap_or("unknown");
        let hash = preferred_hash_from_event(event).unwrap_or_else(|| "no-hash".to_string());

        // 0. Global Exclusions: Skip all voting if path is in consensus_exclude_paths
        let path_lc = image_path.to_lowercase();
        if self.config.consensus_exclude_paths.iter().any(|ex| path_lc.contains(&ex.to_lowercase())) {
            debug!(
                target: CONSENSUS_LOG_TARGET,
                path = %image_path,
                "[CONSENSUS] round skipped (path in consensus_exclude_paths)"
            );
            return None;
        }

        // NEW: Known-Good Bypass (NSRL + Analyst False Positives)
        // If the binary is in the NSRL (National Software Reference Library) or has been manually 
        // marked as a false positive, we bypass the consensus engine entirely to save CPU and stop log spam.
        if let Some(h) = preferred_hash_from_event(event) {
            let is_nsrl = self.memory.is_nsrl_known_good(&h).unwrap_or(false);
            let proc_name = process_name_from_event(event);
            let is_fp = self.memory.is_false_positive_pattern(proc_name.as_deref(), Some(&h)).unwrap_or(false);
            
            if is_nsrl || is_fp {
                debug!(
                    target: CONSENSUS_LOG_TARGET,
                    path = %image_path,
                    hash = %h,
                    is_nsrl,
                    is_fp,
                    "[CONSENSUS] round bypassed (Known-Good match)"
                );
                return None;
            }
        }

        // 0.1 Trusted Paths & Noisy Stems: Reduce sensitivity for known noise
        let stem = event_stem(event);
        let is_noisy = self.config.consensus_noisy_stems.iter().any(|s| s.eq_ignore_ascii_case(&stem))
            || self.config.consensus_trusted_paths.iter().any(|p| path_lc.contains(&p.to_lowercase()));

        let cache_key = format!("{:?}:{:?}:{}", event.event_id, image_path, hash);

        // Deduplication: Avoid re-running consensus for the same event in a short window (30s)
        if let Some(cached) = self.consensus_cache.get(&cache_key) {
            let (sig, timestamp) = cached.value();
            if timestamp.elapsed() < std::time::Duration::from_secs(30) {
                return Some(sig.clone());
            }
        }

        let voters_len = self.voters.read().await.len();
        debug!(
            target: CONSENSUS_LOG_TARGET,
            event_id = ?event.event_id,
            voters = voters_len,
            path = %image_path,
            "[CONSENSUS] round start"
        );

        let mut signature = ThreatSignature::new(event.computer.clone());
        let mut total_score: f32 = 0.0;
        let mut vote_count: u32 = 0;
        let mut is_threat = false;
        let mut vetoed = false;
        let mut otx_voted = false;
        let mut evidence_votes: Vec<EvidenceVote> = Vec::new();
        const OTX_VOTER: &str = "OTX-C2";

        // ADAPTIVE THREADING: Run all voters concurrently with per-voter timeouts.
        // Each voter gets a strict 5-second SLA. If a voter hangs (LLM inference,
        // memory inspection, decompile), it's treated as an abstention — never
        // blocking the consensus pipeline for other, faster voters.
        // We use join_all (all run concurrently) with individual timeout wrappers
        // so a stalled voter only wastes its own 5s budget, not the group's.
        const VOTER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
        let results = {
            let voters_guard = self.voters.read().await;
            let mut timeout_futs = Vec::with_capacity(voters_guard.len());
            let mut names = Vec::with_capacity(voters_guard.len());
            for voter in voters_guard.iter() {
                let name = voter.name();
                let vote_fut = voter.vote(event);
                // Wrap each voter future in an individual timeout
                timeout_futs.push(tokio::time::timeout(VOTER_TIMEOUT, vote_fut));
                names.push(name);
            }
            let raw_results = futures::future::join_all(timeout_futs).await;
            drop(voters_guard); // Release read lock immediately

            names.into_iter().zip(raw_results.into_iter()).map(|(name, res)| {
                match res {
                    Ok(vote_opt) => (name, vote_opt),
                    Err(_elapsed) => {
                        warn!(
                            target: CONSENSUS_LOG_TARGET,
                            voter = %name,
                            timeout_ms = VOTER_TIMEOUT.as_millis() as u64,
                            "[CONSENSUS] voter TIMEOUT — treating as abstain"
                        );
                        (name, None)
                    }
                }
            }).collect::<Vec<_>>()
        };

        for (vname, res_opt) in results {
            if let Some(res) = res_opt {
                if res.weight < 0.0 {
                    debug!(
                        target: CONSENSUS_LOG_TARGET,
                        voter = %vname,
                        reason = %res.reason,
                        "[CONSENSUS] veto — detection blocked"
                    );
                    vetoed = true;
                    signature.add_reason(format!("Veto [{}]: {}", vname, res.reason));
                    // We don't break immediately here because we already ran them all, 
                    // but we mark as vetoed.
                }

                let contribution = res.confidence * res.weight;
                debug!(
                    target: CONSENSUS_LOG_TARGET,
                    voter = %vname,
                    conf = res.confidence,
                    weight = res.weight,
                    contribution,
                    reason = %res.reason,
                    "[CONSENSUS] voter YIELD"
                );
                total_score += contribution;
                vote_count += 1;
                signature.add_reason(format!("[{}]: {}", vname, res.reason));
                is_threat = true;
                if vname == OTX_VOTER {
                    otx_voted = true;
                }
                let (class, reliability, strong_action) = classify_vote(&vname, &res, event);
                evidence_votes.push(EvidenceVote {
                    result: res,
                    class,
                    reliability,
                    strong_action,
                });
            } else {
                debug!(
                    target: CONSENSUS_LOG_TARGET,
                    voter = %vname,
                    event_id = ?event.event_id,
                    "[CONSENSUS] voter abstain (no match)"
                );
            }
        }

        if vetoed {
            debug!(target: CONSENSUS_LOG_TARGET, "[CONSENSUS] round aborted (veto)");
            return None;
        }

        // Safety net: TAXII/REST IoCs must count toward voting even if OtxVoter was not registered.
        if !otx_voted {
            if let Some(otx_reason) = self.otx_ioc_match_for_event(event) {
                let w = crate::otx_connection::otx_consensus_weight(event);
                let c = crate::otx_connection::OTX_CONSENSUS_CONFIDENCE;
                info!(
                    target: CONSENSUS_LOG_TARGET,
                    voter = OTX_VOTER,
                    conf = c,
                    weight = w,
                    contribution = c * w,
                    reason = %otx_reason,
                    "[CONSENSUS] OTX safety-net YIELD"
                );
                total_score += c * w;
                vote_count += 1;
                signature.add_reason(format!("[{}]: {}", OTX_VOTER, otx_reason));
                is_threat = true;
                let res = VoteResult {
                    confidence: c,
                    reason: otx_reason,
                    weight: w,
                };
                let (class, reliability, strong_action) = classify_vote(OTX_VOTER, &res, event);
                evidence_votes.push(EvidenceVote {
                    result: res,
                    class,
                    reliability,
                    strong_action,
                });
            }
        }

        if !is_threat {
            debug!(
                target: CONSENSUS_LOG_TARGET,
                path = %image_path,
                "[CONSENSUS] clean (all voters abstained)"
            );
            return None;
        }

        signature.detector_count = vote_count;
        signature.process_name = process_name_from_event(event);
        signature.hash_blake3 = preferred_hash_from_event(event);
        signature.parent_process = event.data.get("ParentImage")
            .and_then(|v| v.as_str())
            .and_then(|p| std::path::Path::new(p).file_name())
            .and_then(|n| n.to_str())
            .map(|s| s.to_string());
        signature.version = event
            .data
            .get("ProductVersion")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);

        let decision = orchestrate_evidence(&evidence_votes, event, &self.config);
        signature.confidence = decision.confidence;
        
        // Apply suppression for noisy/trusted paths by capping confidence
        if is_noisy {
            signature.confidence = signature.confidence.min(0.15);
            signature.add_reason("Suppressed: Matches consensus_noisy_stems or consensus_trusted_paths".to_string());
        }

        signature.recommended_action = decision.action;
        signature.require_approval = decision.require_approval;
        signature.add_reason(decision.summary);

        if signature.confidence < 0.20 && is_trusted_operational_tool(event, &self.config) {
            info!(
                target: CONSENSUS_LOG_TARGET,
                event_id = ?event.event_id,
                process = ?signature.process_name,
                confidence = signature.confidence,
                "[CONSENSUS] trusted operational tool observed; no threat emitted without independent malicious behavior"
            );
            return None;
        }

        // Federated learning: adjust confidence based on known true/false positive patterns
        if is_threat {
            let proc_owned = signature.process_name.clone();
            let hash_owned = signature.hash_blake3.clone();
            let proc = proc_owned.as_deref();
            let hash = hash_owned.as_deref();

            // 1. If it's a confirmed TRUE positive, boost to 1.0
            if let Ok(true) = self.memory.is_true_positive_pattern(proc, hash) {
                signature.confidence = 1.0;
                signature.add_reason("Reinforced: matches confirmed federated threat pattern");
                // Ensure action is at least GhostTarpit
                if signature.recommended_action == ResponseAction::Alert
                    || signature.recommended_action == ResponseAction::Tarpit
                {
                    signature.recommended_action = ResponseAction::GhostTarpit;
                }
            }
            // 2. If it's a known FALSE positive, suppress
            else if let Ok(true) = self.memory.is_false_positive_pattern(proc, hash) {
                signature.confidence = (signature.confidence * 0.05).max(0.0);
                signature.add_reason("Suppressed: matches federated false positive pattern");
                // If confidence is now very low, drop the finding completely.
                if signature.confidence < 0.2 {
                    info!(
                        target: CONSENSUS_LOG_TARGET,
                        event_id = ?event.event_id,
                        process = ?proc,
                        hash = ?hash,
                        "[CONSENSUS] suppressed false-positive pattern"
                    );
                    return None;
                }
            }
        }

        info!(
            target: CONSENSUS_LOG_TARGET,
            event_id = ?event.event_id,
            votes = vote_count,
            weighted_score = total_score,
            confidence = signature.confidence,
            action = ?signature.recommended_action,
            "[CONSENSUS] round COMPLETE — threat signature emitted"
        );

        self.consensus_cache.insert(cache_key, (signature.clone(), std::time::Instant::now()));
        Some(signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feed::OtxIndicators;
    use crate::voters::{OtxVoter, SemanticVoter};
    use chrono::Utc;
    use osoosi_types::HostSecurityEvent;
    use serde_json::json;
    use std::sync::Arc;

    fn make_event(image: &str, cmd_line: &str) -> osoosi_types::HostSecurityEvent {
        osoosi_types::HostSecurityEvent {
            source: osoosi_types::HostEventSource::WindowsEventLog,
            event_id: 1, // ProcessCreate
            timestamp: Utc::now(),
            computer: "test-host".to_string(),
            data: serde_json::json!({
                "Image": image,
                "CommandLine": cmd_line,
                "ProcessId": 1234,
            }),
            causal_parent: None,
        }
    }

    #[test]
    fn test_scan_event_discovery_ttp() {
        let memory = Arc::new(MemoryStore::new(":memory:").expect("in-memory db"));
        let config = osoosi_types::PolicyConfig::default();
        let engine = PolicyEngine::new(memory, config);

        // Add a basic semantic voter for testing
        let semantic_voter = Box::new(SemanticVoter {
            engine: crate::semantic::SemanticEngine::new(),
        });
        
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            engine.add_voter(semantic_voter).await;
            let event = make_event("C:\\Windows\\System32\\whoami.exe", "whoami");
            let sig = engine.scan_event(&event).await;
            // Note: semantic drift might not hit on 'whoami' without training,
            // but this confirms the loop runs.
            let _ = sig;
        });
    }

    #[test]
    fn test_scan_event_benign() {
        let memory = Arc::new(MemoryStore::new(":memory:").expect("in-memory db"));
        let config = osoosi_types::PolicyConfig::default();
        let engine = PolicyEngine::new(memory, config);
        let event = make_event("C:\\Program Files\\notepad.exe", "notepad");
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let sig = engine.scan_event(&event).await;
            let _ = sig; // just ensure it doesn't panic
        });
    }

    /// OTX IoCs merge into voting via safety-net when `OtxVoter` is not registered.
    #[test]
    fn test_otx_ioc_safety_net_participates_in_consensus() {
        let memory = Arc::new(MemoryStore::new(":memory:").expect("in-memory"));
        let config = osoosi_types::PolicyConfig::default();
        let engine = PolicyEngine::new(memory, config);
        let mut otx = OtxIndicators::default();
        otx.ips.insert("198.51.100.2".to_string());
        engine.update_otx_indicators(otx);

        let event = HostSecurityEvent {
            source: osoosi_types::HostEventSource::WindowsEventLog,
            event_id: 3, // NetworkConnect
            timestamp: Utc::now(),
            computer: "h".to_string(),
            data: json!({
                "Image": "C:\\\\Windows\\\\System32\\\\curl.exe",
                "DestinationIp": "198.51.100.2",
                "DestinationPort": 443,
                "ProcessId": 1,
            }),
            causal_parent: None,
        };

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let sig = engine
                .scan_event(&event)
                .await
                .expect("OTX should vote via safety-net");
            let reason = sig.reason.as_deref().unwrap();
            assert!(reason.contains("OTX-C2"), "reason was: {}", reason);
            assert_eq!(sig.detector_count, 1);
        });
    }

    /// When `OtxVoter` is present, the same OTX reason must not be applied twice.
    #[test]
    fn test_otx_voter_no_double_votes() {
        let memory = Arc::new(MemoryStore::new(":memory:").expect("in-memory"));
        let config = osoosi_types::PolicyConfig::default();
        let engine = PolicyEngine::new(memory.clone(), config);
        let mut otx = OtxIndicators::default();
        otx.ips.insert("198.51.100.3".to_string());
        engine.update_otx_indicators(otx);

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            engine.add_voter(Box::new(OtxVoter {
                indicators: engine.otx_indicators_ref().clone(),
                memory: memory.clone(),
            })).await;

            let event = HostSecurityEvent {
                source: osoosi_types::HostEventSource::WindowsEventLog,
                event_id: 3, // NetworkConnect
                timestamp: Utc::now(),
                computer: "h".to_string(),
                data: json!({
                    "Image": "C:\\\\Windows\\\\System32\\\\curl.exe",
                    "DestinationIp": "198.51.100.3",
                    "ProcessId": 1,
                }),
                causal_parent: None,
            };

            let sig = engine.scan_event(&event).await.expect("OtxVoter + OTX");
            let reason = sig.reason.as_deref().unwrap();
            assert_eq!(
                reason.matches("OTX-C2").count(),
                1,
                "expected single OTX block in reasons: {}",
                reason
            );
            assert_eq!(sig.detector_count, 1);
        });
    }

    #[test]
    fn evidence_orchestrator_caps_kev_plus_weak_static_noise() {
        let event = make_event("C:\\tools\\git\\cmd\\git.exe", "git status");
        let config = osoosi_types::PolicyConfig::default();
        let votes = vec![
            EvidenceVote {
                result: VoteResult {
                    confidence: 0.85,
                    reason: "CISA KEV: git.exe matches product Git".to_string(),
                    weight: 1.0,
                },
                class: EvidenceClass::ThreatIntel,
                reliability: 0.58,
                strong_action: false,
            },
            EvidenceVote {
                result: VoteResult {
                    confidence: 1.0,
                    reason: "MalwareScanner: combined=1.000 ml=0.000 sig=1.000 magika=pebin"
                        .to_string(),
                    weight: 0.88,
                },
                class: EvidenceClass::StaticArtifact,
                reliability: 0.42,
                strong_action: false,
            },
        ];

        let decision = orchestrate_evidence(&votes, &event, &config);
        assert!(decision.confidence <= 0.68, "decision={decision:?}");
        assert_eq!(decision.action, osoosi_types::ResponseAction::Alert);
    }

    #[test]
    fn evidence_orchestrator_tarpits_correlated_live_network_findings() {
        let mut event = make_event("C:\\Temp\\payload.exe", "payload.exe");
        let config = osoosi_types::PolicyConfig::default();
        event.event_id = 3; // NetworkConnect
        event.data = json!({
            "Image": "C:\\Temp\\payload.exe",
            "CommandLine": "payload.exe",
            "DestinationIp": "203.0.113.50",
            "ProcessId": 4321
        });
        let votes = vec![
            EvidenceVote {
                result: VoteResult {
                    confidence: 0.93,
                    reason: "OTX: destination IP matched pulse".to_string(),
                    weight: 1.0,
                },
                class: EvidenceClass::LiveNetwork,
                reliability: 1.0,
                strong_action: true,
            },
            EvidenceVote {
                result: VoteResult {
                    confidence: 0.86,
                    reason: "BehavioralYara: suspicious outbound connection".to_string(),
                    weight: 0.8,
                },
                class: EvidenceClass::Behavior,
                reliability: 0.88,
                strong_action: true,
            },
        ];

        let decision = orchestrate_evidence(&votes, &event, &config);
        assert!(decision.confidence >= 0.74, "decision={decision:?}");
        assert!(matches!(
            decision.action,
            osoosi_types::ResponseAction::Tarpit | osoosi_types::ResponseAction::GhostTarpit
        ));
    }
}
