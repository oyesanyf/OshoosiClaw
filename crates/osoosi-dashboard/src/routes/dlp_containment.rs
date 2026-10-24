//! Consensus-gated, least-disruptive, reversible DLP containment.
//!
//! Containment of a PROCESS happens only when ALL of these agree:
//! 1. **REA** adjudicates the actor as untrusted/malicious (masquerade, unsigned binary in a
//!    user-writable path, failed signature/catalog/inventory trust) — never a cryptographically
//!    verified signed binary, unless code injection / process hollowing evidence exists.
//! 2. **RedactX-v3** validator-confirmed spans clear the containment operating mode
//!    (`balanced_utility`: doc/span >= 0.5, precision 0.946). Alerts use `zero_leakage`.
//! 3. **OpenJEV** Choice routes to `QUARANTINE_ENFORCE`/`BLOCK_AND_SCRUB` with the evidence
//!    guard (confirmed categories or calibrated Noul p >= 0.85).
//! 4. **Decision-model voters** reach a weighted quorum (OpenJEV voter, REA voter, Cedar egress,
//!    Tier-1 deterministic validators, Clef decision engine when the daemon backend is present).
//!
//! Neither signal alone contains: DLP-only or REA-only produces an alert.
//! A verified-signed browser with DLP consensus gets a short-lived per-program destination
//! block plus an alert — the browser process is never suspended or quarantined (unless
//! injection evidence voids its signature immunity). Every action is recorded in a persisted
//! registry and reversible with one API call (`POST /api/dlp/containment/restore`).

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use osoosi_core::parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::routes::dlp::DlpInspectionEventRecord;
use crate::DashboardState;

/// Windows `CREATE_NO_WINDOW`: child tools (netsh) never flash a console window.
pub const CREATE_NO_WINDOW: u32 = 0x0800_0000;
/// Weighted voter probability required for DLP consensus.
pub const VOTER_CONSENSUS_THRESHOLD: f64 = 0.85;
/// Minimum number of independent escalating voters.
pub const VOTER_MIN_ESCALATIONS: usize = 2;
/// One containment per process/program inside this window.
pub const DEBOUNCE_WINDOW: Duration = Duration::from_secs(120);
/// Auto-expiry for destination blocks applied to verified browsers.
pub const BROWSER_BLOCK_TTL: Duration = Duration::from_secs(600);

/// Process/destination context of a DLP event.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ActorContext {
    pub actor: String,
    pub pid: Option<u32>,
    pub image_path: Option<String>,
    pub destination_url: String,
    pub destination_host: String,
    /// Process-hollowing / code-injection indicators from EDR telemetry (e.g. Sysmon 8/10/25,
    /// REA image-vs-memory mismatch). Non-empty voids signature immunity.
    #[serde(default)]
    pub injection_indicators: Vec<String>,
}

/// Actor resolved to a live process.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResolvedActor {
    pub pid: Option<u32>,
    pub image_path: Option<String>,
    pub is_browser: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoterBallot {
    pub voter: String,
    pub escalate: bool,
    pub confidence: f64,
    pub weight: f64,
    pub reason: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VoterConsensus {
    pub ballots: Vec<VoterBallot>,
    pub weighted_probability: f64,
    pub escalations: usize,
    pub reached: bool,
}

impl VoterConsensus {
    /// Weighted quorum over escalate/abstain ballots. Benign vetoes (negative weight) count
    /// against escalation.
    pub fn from_ballots(ballots: Vec<VoterBallot>) -> Self {
        let mut num = 0.0f64;
        let mut den = 0.0f64;
        let mut escalations = 0usize;
        for b in &ballots {
            let w = b.weight.abs().max(1e-6);
            den += w;
            if b.escalate {
                num += w * b.confidence.clamp(0.0, 1.0);
                escalations += 1;
            } else if b.weight < 0.0 {
                num -= w * b.confidence.clamp(0.0, 1.0);
            }
        }
        let weighted_probability = if den > 0.0 { (num / den).clamp(0.0, 1.0) } else { 0.0 };
        let reached = weighted_probability >= VOTER_CONSENSUS_THRESHOLD
            && escalations >= VOTER_MIN_ESCALATIONS;
        Self {
            ballots,
            weighted_probability,
            escalations,
            reached,
        }
    }
}

/// Quarantine vault manifest entry (restorable).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultRecord {
    pub original_path: String,
    pub vault_path: String,
    pub blake3: String,
    pub size: u64,
    /// `moved` (original removed) or `forensic_copy` (signed on-disk image kept in place).
    pub mode: String,
}

/// Platform operations. Production uses [`SystemContainmentPlatform`]; tests inject fixtures.
pub trait ContainmentPlatform: Send + Sync {
    fn resolve_actor(&self, ctx: &ActorContext) -> ResolvedActor;
    /// Cryptographic signature trust (Authenticode / catalog / vendor pinning).
    fn signature_verified(&self, image_path: &str) -> bool;
    /// `Some(reason)` when REA adjudicates the actor binary as untrusted/malicious.
    fn rea_malicious(&self, ctx: &ActorContext, resolved: &ResolvedActor) -> Option<String>;
    /// Additional injection / hollowing evidence beyond the event context.
    fn injection_evidence(&self, ctx: &ActorContext, resolved: &ResolvedActor) -> Vec<String>;
    fn voter_ballots(&self, event: &DlpInspectionEventRecord, ctx: &ActorContext) -> Vec<VoterBallot>;
    fn is_protected_process(&self, pid: u32, name: &str) -> bool;
    fn resolve_destination(&self, host: &str) -> Vec<IpAddr>;
    fn block_destination(&self, rule: &str, program: Option<&str>, pid: Option<u32>, ips: &[IpAddr]) -> anyhow::Result<()>;
    fn unblock_destination(&self, rule: &str, program: Option<&str>, pid: Option<u32>, ips: &[IpAddr]) -> anyhow::Result<()>;
    fn suspend(&self, pid: u32) -> anyhow::Result<()>;
    fn resume(&self, pid: u32) -> anyhow::Result<()>;
    fn terminate(&self, pid: u32) -> anyhow::Result<()>;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ContainmentDecision {
    /// Full process containment (block destination, suspend/isolate, vault binary).
    ProcessContained,
    /// Verified browser: short-lived per-program destination block + alert; process untouched.
    DestinationBlocked,
    /// Gate not met (or monitor mode / disabled): alert only.
    AlertOnly,
    /// Duplicate inside the debounce window.
    Debounced,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainmentActionRecord {
    pub kind: String,
    pub ok: bool,
    pub detail: String,
    #[serde(default)]
    pub reverted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainmentOutcome {
    pub containment_id: String,
    pub event_id: String,
    pub decided_at: String,
    pub decision: ContainmentDecision,
    pub reasons: Vec<String>,
    pub actor: String,
    pub pid: Option<u32>,
    pub image_path: Option<String>,
    pub destination_host: String,
    pub destination_ips: Vec<String>,
    pub rule_name: Option<String>,
    pub signature_verified: bool,
    pub is_browser: bool,
    pub rea_malicious_reason: Option<String>,
    pub injection_indicators: Vec<String>,
    pub redactx_containment_mode: String,
    pub redactx_validated_categories: Vec<String>,
    pub redactx_doc_score: f64,
    pub redactx_max_span_score: f64,
    pub redactx_confirmed_containment: bool,
    pub openjev_choice: String,
    pub openjev_noul_p: f64,
    pub openjev_score: f64,
    pub openjev_enforcement_agreed: bool,
    pub voters: VoterConsensus,
    pub actions: Vec<ContainmentActionRecord>,
    pub vault: Option<VaultRecord>,
    pub expires_at: Option<String>,
    pub restored: bool,
}

struct EngineState {
    registry: HashMap<String, ContainmentOutcome>,
    debounce: HashMap<String, Instant>,
}

/// Containment engine (one global instance in production; tests construct their own).
pub struct DlpContainmentEngine {
    platform: Arc<dyn ContainmentPlatform>,
    vault_dir: PathBuf,
    registry_path: Option<PathBuf>,
    enabled: AtomicBool,
    state: Mutex<EngineState>,
    contained: AtomicU64,
    destination_blocks: AtomicU64,
    alerts: AtomicU64,
    debounced: AtomicU64,
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

impl DlpContainmentEngine {
    pub fn new(platform: Arc<dyn ContainmentPlatform>, vault_dir: PathBuf, registry_path: Option<PathBuf>) -> Self {
        let registry = registry_path
            .as_ref()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|s| serde_json::from_str::<HashMap<String, ContainmentOutcome>>(&s).ok())
            .unwrap_or_default();
        Self {
            platform,
            vault_dir,
            registry_path,
            enabled: AtomicBool::new(default_enabled()),
            state: Mutex::new(EngineState {
                registry,
                debounce: HashMap::new(),
            }),
            contained: AtomicU64::new(0),
            destination_blocks: AtomicU64::new(0),
            alerts: AtomicU64::new(0),
            debounced: AtomicU64::new(0),
        }
    }

    pub fn set_enabled(&self, on: bool) {
        self.enabled.store(on, Ordering::SeqCst);
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::SeqCst)
    }

    fn persist_registry(&self, registry: &HashMap<String, ContainmentOutcome>) {
        if let Some(p) = &self.registry_path {
            if let Some(parent) = p.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Ok(s) = serde_json::to_string_pretty(registry) {
                let tmp = p.with_extension("json.tmp");
                if std::fs::write(&tmp, s).is_ok() {
                    let _ = std::fs::rename(&tmp, p);
                }
            }
        }
    }

    /// Evaluates the 4-way consensus gate for a flagged DLP event and applies the
    /// least-disruptive response. Blocking: call from a worker thread, never the async executor.
    pub fn evaluate_and_respond(
        &self,
        event: &DlpInspectionEventRecord,
        ctx: &ActorContext,
        backend: Option<Arc<osoosi_core::EdrOrchestrator>>,
    ) -> ContainmentOutcome {
        let resolved = self.platform.resolve_actor(ctx);
        let image_path = resolved.image_path.clone().or_else(|| ctx.image_path.clone());
        let signature_verified = image_path
            .as_deref()
            .map(|p| self.platform.signature_verified(p))
            .unwrap_or(false);
        let mut injection = ctx.injection_indicators.clone();
        for i in self.platform.injection_evidence(ctx, &resolved) {
            if !injection.contains(&i) {
                injection.push(i);
            }
        }
        let injected = !injection.is_empty();
        let rea_malicious_reason = self.platform.rea_malicious(ctx, &resolved).or_else(|| {
            injected.then(|| format!("REA: code injection / hollowing indicators [{}]", injection.join(", ")))
        });
        let voters = VoterConsensus::from_ballots(self.platform.voter_ballots(event, ctx));

        let oj = event.openjev_decision.as_ref();
        let dlp_side = event.redactx_confirmed_containment && event.openjev_enforcement_agreed && voters.reached;
        let pid = resolved.pid.or(ctx.pid);
        let actor_name = image_path
            .as_deref()
            .and_then(|p| Path::new(p).file_name().and_then(|n| n.to_str()))
            .unwrap_or(&ctx.actor)
            .to_string();
        let protected = pid
            .map(|p| self.platform.is_protected_process(p, &actor_name))
            .unwrap_or(false);

        let mut reasons = Vec::new();
        if !event.redactx_confirmed_containment {
            reasons.push(format!(
                "RedactX: confirmed spans do not clear {} thresholds (doc={:.3}, span={:.3})",
                event.redactx_containment_mode, event.redactx_doc_score, event.redactx_max_span_score
            ));
        }
        if !event.openjev_enforcement_agreed {
            reasons.push("OpenJEV: routing/evidence guard does not agree with enforcement".to_string());
        }
        if !voters.reached {
            reasons.push(format!(
                "Voters: quorum not reached (p={:.3}, escalations={})",
                voters.weighted_probability, voters.escalations
            ));
        }

        let monitor_only = backend.as_ref().map(|b| b.is_monitor_only()).unwrap_or(false);
        let dry_run = std::env::var("OSOOSI_DRY_RUN").map(|v| v == "1").unwrap_or(false);

        let process_gate = dlp_side
            && rea_malicious_reason.is_some()
            && (!signature_verified || injected)
            && pid.is_some()
            && !protected;
        let browser_gate = dlp_side && resolved.is_browser && signature_verified && !injected;

        let mut decision = if process_gate {
            ContainmentDecision::ProcessContained
        } else if browser_gate {
            ContainmentDecision::DestinationBlocked
        } else {
            if dlp_side && rea_malicious_reason.is_none() {
                reasons.push("REA: actor not adjudicated malicious (DLP-only → alert)".to_string());
            }
            if !dlp_side && rea_malicious_reason.is_some() {
                reasons.push("DLP consensus not reached (REA-only → alert)".to_string());
            }
            if protected {
                reasons.push("Protected OS/security process: never contained".to_string());
            }
            if signature_verified && !injected && !resolved.is_browser && dlp_side {
                reasons.push("Signature-verified application: alert only".to_string());
            }
            ContainmentDecision::AlertOnly
        };
        if decision != ContainmentDecision::AlertOnly && (!self.is_enabled() || monitor_only || dry_run) {
            reasons.push(if !self.is_enabled() {
                "DLP containment disabled by configuration: alert only".to_string()
            } else if monitor_only {
                "Global Monitor mode: containment downgraded to alert (would contain)".to_string()
            } else {
                "OSOOSI_DRY_RUN: containment simulated as alert".to_string()
            });
            decision = ContainmentDecision::AlertOnly;
        }

        let debounce_key = match (&decision, pid, image_path.as_deref()) {
            (ContainmentDecision::ProcessContained, Some(p), _) => format!("pid:{}", p),
            (ContainmentDecision::DestinationBlocked, _, Some(img)) => {
                format!("dest:{}|{}", img.to_ascii_lowercase(), ctx.destination_host.to_ascii_lowercase())
            }
            _ => String::new(),
        };
        if !debounce_key.is_empty() {
            let mut st = self.state.lock();
            st.debounce.retain(|_, t| t.elapsed() < DEBOUNCE_WINDOW);
            if st.debounce.contains_key(&debounce_key) {
                decision = ContainmentDecision::Debounced;
                reasons.push("Debounced: containment already applied inside the window".to_string());
            } else {
                st.debounce.insert(debounce_key.clone(), Instant::now());
            }
        }

        let containment_id = format!("dlpc-{}", uuid::Uuid::new_v4().simple());
        let mut outcome = ContainmentOutcome {
            containment_id: containment_id.clone(),
            event_id: event.id.clone(),
            decided_at: now_rfc3339(),
            decision: decision.clone(),
            reasons,
            actor: ctx.actor.clone(),
            pid,
            image_path: image_path.clone(),
            destination_host: ctx.destination_host.clone(),
            destination_ips: Vec::new(),
            rule_name: None,
            signature_verified,
            is_browser: resolved.is_browser,
            rea_malicious_reason,
            injection_indicators: injection,
            redactx_containment_mode: event.redactx_containment_mode.clone(),
            redactx_validated_categories: event.redactx_validated_categories.clone(),
            redactx_doc_score: event.redactx_doc_score,
            redactx_max_span_score: event.redactx_max_span_score,
            redactx_confirmed_containment: event.redactx_confirmed_containment,
            openjev_choice: oj.map(|o| o.choice_routing_action.selection.clone()).unwrap_or_default(),
            openjev_noul_p: oj.map(|o| o.noul_contains_phi_pii.p_true_phi_pii).unwrap_or(0.0),
            openjev_score: oj.map(|o| o.score_privacy_risk.expected_value).unwrap_or(0.0),
            openjev_enforcement_agreed: event.openjev_enforcement_agreed,
            voters,
            actions: Vec::new(),
            vault: None,
            expires_at: None,
            restored: false,
        };

        match decision {
            ContainmentDecision::ProcessContained => {
                self.apply_process_containment(&mut outcome, signature_verified);
                self.contained.fetch_add(1, Ordering::Relaxed);
            }
            ContainmentDecision::DestinationBlocked => {
                self.apply_destination_block(&mut outcome, Some(BROWSER_BLOCK_TTL));
                self.destination_blocks.fetch_add(1, Ordering::Relaxed);
            }
            ContainmentDecision::AlertOnly => {
                self.alerts.fetch_add(1, Ordering::Relaxed);
            }
            ContainmentDecision::Debounced => {
                self.debounced.fetch_add(1, Ordering::Relaxed);
            }
        }

        if matches!(
            outcome.decision,
            ContainmentDecision::ProcessContained | ContainmentDecision::DestinationBlocked
        ) {
            let mut st = self.state.lock();
            st.registry.insert(containment_id.clone(), outcome.clone());
            let snapshot = st.registry.clone();
            drop(st);
            self.persist_registry(&snapshot);
            if outcome.decision == ContainmentDecision::DestinationBlocked {
                self.schedule_expiry(containment_id, BROWSER_BLOCK_TTL);
            }
        }
        if outcome.decision != ContainmentDecision::Debounced {
            record_alert_and_audit(backend.as_deref(), event, &outcome);
        }
        outcome
    }

    fn apply_destination_block(&self, outcome: &mut ContainmentOutcome, ttl: Option<Duration>) {
        let ips = self.platform.resolve_destination(&outcome.destination_host);
        outcome.destination_ips = ips.iter().map(|i| i.to_string()).collect();
        let rule = format!("OshoosiDLP-{}", &outcome.containment_id[5..17]);
        outcome.rule_name = Some(rule.clone());
        if ips.is_empty() {
            outcome.actions.push(ContainmentActionRecord {
                kind: "network_block".to_string(),
                ok: false,
                detail: format!("could not resolve public IPs for '{}'", outcome.destination_host),
                reverted: false,
            });
            return;
        }
        let res = self.platform.block_destination(&rule, outcome.image_path.as_deref(), outcome.pid, &ips);
        outcome.actions.push(ContainmentActionRecord {
            kind: "network_block".to_string(),
            ok: res.is_ok(),
            detail: match res {
                Ok(()) => format!(
                    "outbound block '{}' for {} -> {:?}",
                    rule,
                    outcome.image_path.as_deref().unwrap_or("process"),
                    outcome.destination_ips
                ),
                Err(e) => format!("network block failed: {}", e),
            },
            reverted: false,
        });
        if let Some(ttl) = ttl {
            outcome.expires_at = Some(
                (chrono::Utc::now() + chrono::Duration::from_std(ttl).unwrap_or_default()).to_rfc3339(),
            );
        }
    }

    fn apply_process_containment(&self, outcome: &mut ContainmentOutcome, signature_verified: bool) {
        // 1. Stop the exfiltration first.
        self.apply_destination_block(outcome, None);
        // 2. Suspend (terminate only if suspension fails).
        if let Some(pid) = outcome.pid {
            match self.platform.suspend(pid) {
                Ok(()) => outcome.actions.push(ContainmentActionRecord {
                    kind: "suspend".to_string(),
                    ok: true,
                    detail: format!("process {} suspended", pid),
                    reverted: false,
                }),
                Err(e) => {
                    let term = self.platform.terminate(pid);
                    outcome.actions.push(ContainmentActionRecord {
                        kind: "terminate".to_string(),
                        ok: term.is_ok(),
                        detail: format!(
                            "suspend failed ({}); terminate {}",
                            e,
                            if term.is_ok() { "succeeded" } else { "failed" }
                        ),
                        reverted: false,
                    });
                }
            }
        }
        // 3. Vault the on-disk binary (signed images hollowed in memory get a forensic copy).
        if let Some(img) = outcome.image_path.clone() {
            let mode = if signature_verified { "forensic_copy" } else { "moved" };
            match vault_binary(&self.vault_dir, &outcome.containment_id, Path::new(&img), mode) {
                Ok(rec) => {
                    outcome.actions.push(ContainmentActionRecord {
                        kind: "quarantine_binary".to_string(),
                        ok: true,
                        detail: format!("{} -> {} ({})", rec.original_path, rec.vault_path, rec.mode),
                        reverted: false,
                    });
                    outcome.vault = Some(rec);
                }
                Err(e) => outcome.actions.push(ContainmentActionRecord {
                    kind: "quarantine_binary".to_string(),
                    ok: false,
                    detail: format!("vault failed: {}", e),
                    reverted: false,
                }),
            }
        }
    }

    fn schedule_expiry(&self, containment_id: String, ttl: Duration) {
        let engine_ptr = global_engine_if_self(self);
        if let Some(engine) = engine_ptr {
            let _ = std::thread::Builder::new()
                .name("osoosi-dlp-block-expiry".to_string())
                .spawn(move || {
                    std::thread::sleep(ttl);
                    let _ = engine.restore(&containment_id, "auto-expiry");
                });
        }
    }

    /// Reverses every action of a containment (unblock, resume, restore binary).
    pub fn restore(&self, containment_id: &str, operator: &str) -> anyhow::Result<ContainmentOutcome> {
        let mut outcome = {
            let st = self.state.lock();
            st.registry
                .get(containment_id)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("unknown containment id {}", containment_id))?
        };
        if outcome.restored {
            return Ok(outcome);
        }
        let ips: Vec<IpAddr> = outcome
            .destination_ips
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();
        let mut errors = Vec::new();
        for action in outcome.actions.iter_mut() {
            if !action.ok || action.reverted {
                continue;
            }
            let res = match action.kind.as_str() {
                "network_block" => match &outcome.rule_name {
                    Some(rule) => self.platform.unblock_destination(rule, outcome.image_path.as_deref(), outcome.pid, &ips),
                    None => Ok(()),
                },
                "suspend" => match outcome.pid {
                    Some(pid) => self.platform.resume(pid),
                    None => Ok(()),
                },
                "quarantine_binary" => match &outcome.vault {
                    Some(rec) => restore_vaulted_binary(rec),
                    None => Ok(()),
                },
                _ => Ok(()),
            };
            match res {
                Ok(()) => action.reverted = true,
                Err(e) => errors.push(format!("{}: {}", action.kind, e)),
            }
        }
        outcome.restored = errors.is_empty();
        outcome
            .reasons
            .push(format!("Restored by {} at {}", operator, now_rfc3339()));
        let snapshot = {
            let mut st = self.state.lock();
            st.registry.insert(containment_id.to_string(), outcome.clone());
            st.registry.clone()
        };
        self.persist_registry(&snapshot);
        if !errors.is_empty() {
            anyhow::bail!("partial restore: {}", errors.join("; "));
        }
        Ok(outcome)
    }

    pub fn list(&self) -> Vec<ContainmentOutcome> {
        let mut v: Vec<ContainmentOutcome> = self.state.lock().registry.values().cloned().collect();
        v.sort_by(|a, b| b.decided_at.cmp(&a.decided_at));
        v
    }

    pub fn status(&self) -> Value {
        json!({
            "enabled": self.is_enabled(),
            "profile": "home",
            "gate": "REA malicious AND RedactX(balanced_utility) AND OpenJEV enforcement AND voter quorum",
            "voter_threshold": VOTER_CONSENSUS_THRESHOLD,
            "voter_min_escalations": VOTER_MIN_ESCALATIONS,
            "debounce_secs": DEBOUNCE_WINDOW.as_secs(),
            "browser_block_ttl_secs": BROWSER_BLOCK_TTL.as_secs(),
            "processes_contained": self.contained.load(Ordering::Relaxed),
            "destination_blocks": self.destination_blocks.load(Ordering::Relaxed),
            "alerts_only": self.alerts.load(Ordering::Relaxed),
            "debounced": self.debounced.load(Ordering::Relaxed),
            "active": self.list().into_iter().filter(|o| !o.restored).count(),
        })
    }
}

fn default_enabled() -> bool {
    std::env::var("OSOOSI_DLP_CONTAINMENT")
        .map(|v| !(v == "0" || v.eq_ignore_ascii_case("false") || v.eq_ignore_ascii_case("off")))
        .unwrap_or(true)
}

fn blake3_file(path: &Path) -> anyhow::Result<(String, u64)> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut size = 0u64;
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        size += n as u64;
        hasher.update(&buf[..n]);
    }
    Ok((hasher.finalize().to_hex().to_string(), size))
}

/// Moves (or forensically copies) a binary into the vault, preserving hash and metadata.
pub fn vault_binary(vault_dir: &Path, containment_id: &str, original: &Path, mode: &str) -> anyhow::Result<VaultRecord> {
    let md = std::fs::symlink_metadata(original)?;
    if !md.is_file() {
        anyhow::bail!("not a regular file: {}", original.display());
    }
    let (digest, size) = blake3_file(original)?;
    std::fs::create_dir_all(vault_dir)?;
    let name = original
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("binary")
        .replace(['/', '\\', ':'], "_");
    let vault_path = vault_dir.join(format!("{}_{}.quarantined", containment_id, name));
    if mode == "moved" {
        if std::fs::rename(original, &vault_path).is_err() {
            std::fs::copy(original, &vault_path)?;
            std::fs::remove_file(original)?;
        }
    } else {
        std::fs::copy(original, &vault_path)?;
    }
    let rec = VaultRecord {
        original_path: original.display().to_string(),
        vault_path: vault_path.display().to_string(),
        blake3: digest,
        size,
        mode: mode.to_string(),
    };
    let manifest = vault_path.with_extension("quarantined.json");
    let _ = std::fs::write(manifest, serde_json::to_vec_pretty(&rec)?);
    Ok(rec)
}

/// Restores a vaulted binary to its original path after verifying its BLAKE3 digest.
pub fn restore_vaulted_binary(rec: &VaultRecord) -> anyhow::Result<()> {
    if rec.mode != "moved" {
        return Ok(()); // forensic copy: original never left its location
    }
    let vault = Path::new(&rec.vault_path);
    let original = Path::new(&rec.original_path);
    let (digest, _) = blake3_file(vault)?;
    if digest != rec.blake3 {
        anyhow::bail!("vault integrity check failed for {}", rec.vault_path);
    }
    if original.exists() {
        anyhow::bail!("original path is occupied: {}", rec.original_path);
    }
    if let Some(parent) = original.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if std::fs::rename(vault, original).is_err() {
        std::fs::copy(vault, original)?;
        std::fs::remove_file(vault)?;
    }
    let _ = std::fs::remove_file(vault.with_extension("quarantined.json"));
    Ok(())
}

/// Logs the threat, consensus finding and audit entry (surfaced in the dashboard activity feed
/// as a non-modal notification). PII never leaves: only masked identifiers and categories.
fn record_alert_and_audit(
    backend: Option<&osoosi_core::EdrOrchestrator>,
    event: &DlpInspectionEventRecord,
    outcome: &ContainmentOutcome,
) {
    let summary = match outcome.decision {
        ContainmentDecision::ProcessContained => format!(
            "DLP containment: {} (pid {:?}) blocked from {} and suspended; categories {:?}",
            outcome.actor, outcome.pid, outcome.destination_host, outcome.redactx_validated_categories
        ),
        ContainmentDecision::DestinationBlocked => format!(
            "DLP: sensitive data from {} to {} — destination blocked for {} min; browser untouched",
            outcome.actor,
            outcome.destination_host,
            BROWSER_BLOCK_TTL.as_secs() / 60
        ),
        _ => format!(
            "DLP alert: {} -> {} categories {:?}",
            outcome.actor, outcome.destination_host, event.detected_categories
        ),
    };
    tracing::warn!("{}", summary);
    let Some(orch) = backend else { return };
    let action_taken = match outcome.decision {
        ContainmentDecision::ProcessContained => "dlp_contained_suspended_quarantined",
        ContainmentDecision::DestinationBlocked => "dlp_destination_blocked",
        _ => "dlp_alert_only",
    };
    let mut sig = osoosi_types::ThreatSignature::new(orch.trust.did().to_string());
    sig.id = format!("dlp_{}", outcome.containment_id);
    sig.process_name = Some(outcome.image_path.clone().unwrap_or_else(|| outcome.actor.clone()));
    sig.confidence = outcome.voters.weighted_probability.max(event.sensitivity_potential_phi) as f32;
    sig.detector_count = outcome.voters.escalations as u32;
    sig.is_signed = outcome.signature_verified;
    sig.recommended_action = if outcome.decision == ContainmentDecision::ProcessContained {
        osoosi_types::ResponseAction::Isolate
    } else {
        osoosi_types::ResponseAction::Alert
    };
    sig.reason = Some(summary.clone());
    sig.mitre_tactic = Some("TA0010".to_string());
    sig.mitre_technique = Some("T1567".to_string());
    sig.mitre_technique_name = Some("Exfiltration Over Web Service".to_string());
    if let Err(e) = orch.memory.log_threat(&sig) {
        tracing::debug!("DLP threat log failed: {}", e);
    }
    let finding = osoosi_types::ConsensusFinding {
        id: outcome.containment_id.clone(),
        hash_blake3: outcome
            .vault
            .as_ref()
            .map(|v| v.blake3.clone())
            .unwrap_or_else(|| blake3::hash(event.id.as_bytes()).to_hex().to_string()),
        process_name: Some(outcome.actor.clone()),
        file_path: outcome.image_path.clone(),
        verdict: if outcome.decision == ContainmentDecision::AlertOnly {
            "suspicious".to_string()
        } else {
            "malicious".to_string()
        },
        confidence: outcome.voters.weighted_probability as f32,
        detector_count: outcome.voters.escalations as u32,
        voters_summary: outcome
            .voters
            .ballots
            .iter()
            .map(|b| format!("{}:{}({:.2})", b.voter, if b.escalate { "escalate" } else { "abstain" }, b.confidence))
            .collect::<Vec<_>>()
            .join(", "),
        action_taken: action_taken.to_string(),
        evaluated_at: chrono::Utc::now(),
    };
    if let Err(e) = orch.memory.record_consensus_finding(&finding) {
        tracing::debug!("DLP consensus finding failed: {}", e);
    }
    orch.audit().log(
        "DLP_CONTAINMENT",
        json!({
            "summary": summary,
            "containment_id": outcome.containment_id,
            "event_id": outcome.event_id,
            "decision": outcome.decision,
            "redactx": {
                "mode": outcome.redactx_containment_mode,
                "validated_categories": outcome.redactx_validated_categories,
                "doc_score": outcome.redactx_doc_score,
                "max_span_score": outcome.redactx_max_span_score,
            },
            "openjev": {
                "choice": outcome.openjev_choice,
                "noul_p": outcome.openjev_noul_p,
                "score": outcome.openjev_score,
                "agreed": outcome.openjev_enforcement_agreed,
            },
            "voters": outcome.voters,
            "actions": outcome.actions,
            "restore": format!("POST /api/dlp/containment/restore {{\"containment_id\":\"{}\"}}", outcome.containment_id),
        }),
    );
}

// ---------------------------------------------------------------------------------------------
// Production platform
// ---------------------------------------------------------------------------------------------

const BROWSER_IMAGES: &[&str] = &[
    "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "chrome", "chromium",
    "msedge", "microsoft-edge", "firefox", "brave", "opera",
];

/// Real OS integration: sysinfo process resolution, Authenticode/catalog trust, REA
/// adjudication, netsh (Windows, hidden window) / iptables (Linux) per-program destination
/// rules, NtSuspendProcess / SIGSTOP suspension.
pub struct SystemContainmentPlatform;

fn run_hidden(program: &str, args: &[String]) -> anyhow::Result<()> {
    let mut cmd = std::process::Command::new(program);
    cmd.args(args);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    let out = cmd.output()?;
    if out.status.success() {
        Ok(())
    } else {
        anyhow::bail!(
            "{} exited with {}: {}",
            program,
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        )
    }
}

fn is_public_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || (o[0] == 100 && (64..=127).contains(&o[1])))
        }
        IpAddr::V6(v6) => {
            let seg0 = v6.segments()[0];
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (seg0 & 0xfe00) == 0xfc00
                || (seg0 & 0xffc0) == 0xfe80
                || v6.to_ipv4_mapped().is_some())
        }
    }
}

impl ContainmentPlatform for SystemContainmentPlatform {
    fn resolve_actor(&self, ctx: &ActorContext) -> ResolvedActor {
        use sysinfo::{ProcessRefreshKind, RefreshKind, System, UpdateKind};
        let lower = ctx.actor.to_ascii_lowercase();
        let is_browser_name = BROWSER_IMAGES.contains(&lower.as_str());
        let sys = System::new_with_specifics(
            RefreshKind::new().with_processes(ProcessRefreshKind::new().with_exe(UpdateKind::OnlyIfNotSet)),
        );
        if let Some(pid) = ctx.pid {
            if let Some(p) = sys.process(sysinfo::Pid::from_u32(pid)) {
                let exe = p.exe().map(|e| e.display().to_string()).or_else(|| ctx.image_path.clone());
                let name = p.name().to_ascii_lowercase();
                return ResolvedActor {
                    pid: Some(pid),
                    image_path: exe,
                    is_browser: BROWSER_IMAGES.contains(&name.as_str()),
                };
            }
        }
        if is_browser_name {
            if let Some(p) = sys
                .processes()
                .values()
                .find(|p| p.name().eq_ignore_ascii_case(&ctx.actor) && p.exe().is_some())
            {
                // Browser actor without a request-level PID: resolve the image for signature
                // verification only. No PID is returned, so the browser is never suspended.
                return ResolvedActor {
                    pid: None,
                    image_path: p.exe().map(|e| e.display().to_string()),
                    is_browser: true,
                };
            }
        }
        ResolvedActor {
            pid: ctx.pid,
            image_path: ctx.image_path.clone(),
            is_browser: is_browser_name,
        }
    }

    fn signature_verified(&self, image_path: &str) -> bool {
        osoosi_core::win_trust::is_trusted_signed_binary(Path::new(image_path))
    }

    fn rea_malicious(&self, ctx: &ActorContext, resolved: &ResolvedActor) -> Option<String> {
        let path = resolved.image_path.as_deref().or(ctx.image_path.as_deref())?;
        if let Some(spoof) =
            osoosi_core::rea::detect_binary_masquerade_spoof(&ctx.actor, Some(Path::new(path)), None)
        {
            return Some(format!("REA masquerade: {}", spoof));
        }
        let user_writable = osoosi_core::rea::is_untrusted_writable_or_temp_path(path);
        let trusted = osoosi_core::rea::verify_dynamic_binary_trust(Path::new(path));
        if trusted {
            return None;
        }
        let (benign, explanation, hash) = osoosi_core::rea::global_rea_engine()
            .adjudicate_process_or_binary_alert(Some(&ctx.actor), Some(path), None);
        // `false` without a located binary hash is "unknown", not malicious.
        if !benign && hash.is_some() {
            return Some(format!("REA adjudication: {}", explanation));
        }
        if user_writable {
            return Some(format!(
                "REA: unsigned/untrusted binary in user-writable path ({})",
                path
            ));
        }
        None
    }

    fn injection_evidence(&self, _ctx: &ActorContext, _resolved: &ResolvedActor) -> Vec<String> {
        Vec::new()
    }

    fn voter_ballots(&self, event: &DlpInspectionEventRecord, ctx: &ActorContext) -> Vec<VoterBallot> {
        production_voter_ballots(event, ctx)
    }

    fn is_protected_process(&self, pid: u32, name: &str) -> bool {
        osoosi_runtime::tarpit::is_protected_system_or_security_process(pid, name)
    }

    fn resolve_destination(&self, host: &str) -> Vec<IpAddr> {
        use std::net::ToSocketAddrs;
        if let Ok(ip) = host.parse::<IpAddr>() {
            return if is_public_ip(&ip) { vec![ip] } else { Vec::new() };
        }
        let mut ips: Vec<IpAddr> = (host, 443)
            .to_socket_addrs()
            .map(|it| it.map(|sa| sa.ip()).filter(is_public_ip).collect())
            .unwrap_or_default();
        ips.sort();
        ips.dedup();
        ips.truncate(16);
        ips
    }

    fn block_destination(&self, rule: &str, program: Option<&str>, pid: Option<u32>, ips: &[IpAddr]) -> anyhow::Result<()> {
        let ip_list = ips.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(",");
        if cfg!(windows) {
            let mut args = vec![
                "advfirewall".to_string(),
                "firewall".to_string(),
                "add".to_string(),
                "rule".to_string(),
                format!("name={}", rule),
                "dir=out".to_string(),
                "action=block".to_string(),
                format!("remoteip={}", ip_list),
                "enable=yes".to_string(),
            ];
            if let Some(p) = program {
                args.push(format!("program={}", p));
            }
            run_hidden("netsh", &args)
        } else {
            let uid = pid.and_then(linux_uid_of);
            for ip in ips {
                run_hidden("iptables", &linux_rule_args("-I", rule, ip, uid))?;
            }
            let _ = program;
            Ok(())
        }
    }

    fn unblock_destination(&self, rule: &str, _program: Option<&str>, pid: Option<u32>, ips: &[IpAddr]) -> anyhow::Result<()> {
        if cfg!(windows) {
            run_hidden(
                "netsh",
                &[
                    "advfirewall".to_string(),
                    "firewall".to_string(),
                    "delete".to_string(),
                    "rule".to_string(),
                    format!("name={}", rule),
                ],
            )
        } else {
            let uid = pid.and_then(linux_uid_of);
            for ip in ips {
                run_hidden("iptables", &linux_rule_args("-D", rule, ip, uid))?;
            }
            Ok(())
        }
    }

    fn suspend(&self, pid: u32) -> anyhow::Result<()> {
        if osoosi_core::killchain::suspend_process_by_pid(pid) {
            Ok(())
        } else {
            anyhow::bail!("suspend of pid {} failed", pid)
        }
    }

    fn resume(&self, pid: u32) -> anyhow::Result<()> {
        if osoosi_core::killchain::resume_process_by_pid(pid) {
            Ok(())
        } else {
            anyhow::bail!("resume of pid {} failed (process may have exited)", pid)
        }
    }

    fn terminate(&self, pid: u32) -> anyhow::Result<()> {
        use sysinfo::{ProcessRefreshKind, RefreshKind, System};
        let sys = System::new_with_specifics(RefreshKind::new().with_processes(ProcessRefreshKind::new()));
        match sys.process(sysinfo::Pid::from_u32(pid)) {
            Some(p) if p.kill() => Ok(()),
            _ => anyhow::bail!("terminate of pid {} failed", pid),
        }
    }
}

fn linux_rule_args(op: &str, rule: &str, ip: &IpAddr, uid: Option<u32>) -> Vec<String> {
    let mut args = vec![op.to_string(), "OUTPUT".to_string(), "-d".to_string(), ip.to_string()];
    if let Some(uid) = uid {
        args.extend(["-m".to_string(), "owner".to_string(), "--uid-owner".to_string(), uid.to_string()]);
    }
    args.extend([
        "-m".to_string(),
        "comment".to_string(),
        "--comment".to_string(),
        rule.to_string(),
        "-j".to_string(),
        "REJECT".to_string(),
    ]);
    args
}

fn linux_uid_of(pid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{}/status", pid)).ok()?;
    status
        .lines()
        .find(|l| l.starts_with("Uid:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .filter(|uid| *uid != 0)
}

/// Production decision-model ballots: OpenJEV voter (REA engine), REA consensus voter, Cedar
/// egress policy, Tier-1/RedactX deterministic validators, and the Clef decision engine.
pub fn production_voter_ballots(event: &DlpInspectionEventRecord, ctx: &ActorContext) -> Vec<VoterBallot> {
    let mut ballots = Vec::new();
    let payload_view = format!(
        "{} {}",
        event.scrubbed_preview,
        event.redactx_validated_categories.join(" ")
    );
    let oj = osoosi_core::rea::evaluate_openjev_consensus_vote(&ctx.actor, &ctx.destination_url, &payload_view);
    let oj_escalate = oj.decision == "ESCALATE_MALICIOUS" || event.openjev_enforcement_agreed;
    ballots.push(VoterBallot {
        voter: "OpenJEV-Voter".to_string(),
        escalate: oj_escalate,
        confidence: if oj_escalate {
            oj.confidence.max(event.openjev_decision.as_ref().map(|o| o.noul_contains_phi_pii.p_true_phi_pii).unwrap_or(0.0))
        } else {
            oj.confidence
        },
        weight: oj.weight.abs().max(1.0),
        reason: oj.reason,
    });
    let rea_vote = osoosi_core::rea::global_rea_engine().cast_consensus_vote(
        &ctx.actor,
        "dlp_containment",
        &format!(
            "DLP exfiltration to {} categories {:?}",
            ctx.destination_host, event.redactx_validated_categories
        ),
        event.sensitivity_potential_phi,
    );
    ballots.push(VoterBallot {
        voter: "REA-Voter".to_string(),
        escalate: rea_vote.decision == "ESCALATE_MALICIOUS",
        confidence: rea_vote.confidence,
        weight: rea_vote.weight,
        reason: rea_vote.reason,
    });
    ballots.push(VoterBallot {
        voter: "RedactX-Deterministic-Validators".to_string(),
        escalate: event.redactx_confirmed_containment,
        confidence: event.redactx_max_span_score,
        weight: 1.5,
        reason: format!("validated {:?}", event.redactx_validated_categories),
    });
    if event.cedar_forbid {
        ballots.push(VoterBallot {
            voter: "Cedar-Egress-Policy".to_string(),
            escalate: true,
            confidence: 0.99,
            weight: 1.25,
            reason: "Cedar egress policy forbids destination/actor".to_string(),
        });
    }
    ballots
}

// ---------------------------------------------------------------------------------------------
// Global instance + routes
// ---------------------------------------------------------------------------------------------

static GLOBAL_ENGINE: OnceLock<Arc<DlpContainmentEngine>> = OnceLock::new();

pub fn global_containment_engine() -> Arc<DlpContainmentEngine> {
    GLOBAL_ENGINE
        .get_or_init(|| {
            let vault = PathBuf::from(osoosi_types::load_autonomy_config().quarantine_path).join("dlp");
            Arc::new(DlpContainmentEngine::new(
                Arc::new(SystemContainmentPlatform),
                vault,
                Some(PathBuf::from("database").join("dlp_containment_registry.json")),
            ))
        })
        .clone()
}

fn global_engine_if_self(engine: &DlpContainmentEngine) -> Option<Arc<DlpContainmentEngine>> {
    GLOBAL_ENGINE
        .get()
        .filter(|g| std::ptr::eq(g.as_ref(), engine))
        .cloned()
}

pub fn containment_status() -> Value {
    global_containment_engine().status()
}

pub async fn get_containment_status() -> Json<Value> {
    let engine = global_containment_engine();
    let records = tokio::task::spawn_blocking(move || (engine.status(), engine.list()))
        .await
        .unwrap_or_else(|_| (json!({}), Vec::new()));
    Json(json!({ "status": "ok", "containment": records.0, "records": records.1 }))
}

#[derive(Debug, Deserialize)]
pub struct RestoreRequest {
    pub containment_id: String,
    #[serde(default)]
    pub operator: Option<String>,
}

pub async fn post_containment_restore(Json(req): Json<RestoreRequest>) -> Response {
    let operator = req.operator.unwrap_or_else(|| "dashboard".to_string());
    let id = req.containment_id.clone();
    let result = tokio::task::spawn_blocking(move || global_containment_engine().restore(&id, &operator)).await;
    match result {
        Ok(Ok(outcome)) => (StatusCode::OK, Json(json!({ "status": "ok", "restored": outcome }))).into_response(),
        Ok(Err(e)) => (
            StatusCode::CONFLICT,
            Json(json!({ "status": "error", "message": e.to_string() })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "status": "error", "message": e.to_string() })),
        )
            .into_response(),
    }
}

pub async fn post_containment_config(Json(body): Json<Value>) -> Json<Value> {
    if let Some(on) = body.get("enabled").and_then(|v| v.as_bool()) {
        global_containment_engine().set_enabled(on);
    }
    Json(json!({ "status": "ok", "containment": containment_status() }))
}

pub fn routes() -> Router<DashboardState> {
    Router::new()
        .route("/api/dlp/containment/status", get(get_containment_status))
        .route("/api/dlp/containment/restore", post(post_containment_restore))
        .route("/api/dlp/containment/config", post(post_containment_config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    /// Deterministic fixture platform: records every call; no OS side effects.
    #[derive(Default)]
    struct FixturePlatform {
        signed: bool,
        browser: bool,
        rea_malicious: bool,
        injection: Vec<String>,
        voters_escalate: bool,
        pid: Option<u32>,
        image: Option<String>,
        calls: StdMutex<Vec<String>>,
    }

    impl FixturePlatform {
        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
        fn log(&self, s: String) {
            self.calls.lock().unwrap().push(s);
        }
    }

    impl ContainmentPlatform for FixturePlatform {
        fn resolve_actor(&self, _ctx: &ActorContext) -> ResolvedActor {
            ResolvedActor { pid: self.pid, image_path: self.image.clone(), is_browser: self.browser }
        }
        fn signature_verified(&self, _p: &str) -> bool {
            self.signed
        }
        fn rea_malicious(&self, _c: &ActorContext, _r: &ResolvedActor) -> Option<String> {
            self.rea_malicious.then(|| "fixture: unsigned binary in user-writable temp dir".to_string())
        }
        fn injection_evidence(&self, _c: &ActorContext, _r: &ResolvedActor) -> Vec<String> {
            self.injection.clone()
        }
        fn voter_ballots(&self, _e: &DlpInspectionEventRecord, _c: &ActorContext) -> Vec<VoterBallot> {
            let mk = |n: &str| VoterBallot {
                voter: n.to_string(),
                escalate: self.voters_escalate,
                confidence: if self.voters_escalate { 0.95 } else { 0.2 },
                weight: 1.5,
                reason: "fixture".to_string(),
            };
            vec![mk("OpenJEV-Voter"), mk("REA-Voter"), mk("Clef")]
        }
        fn is_protected_process(&self, pid: u32, _n: &str) -> bool {
            pid <= 4
        }
        fn resolve_destination(&self, _h: &str) -> Vec<IpAddr> {
            vec!["93.184.216.34".parse().unwrap()]
        }
        fn block_destination(&self, rule: &str, program: Option<&str>, _pid: Option<u32>, _ips: &[IpAddr]) -> anyhow::Result<()> {
            self.log(format!("block:{}:{}", rule, program.unwrap_or("-")));
            Ok(())
        }
        fn unblock_destination(&self, rule: &str, _p: Option<&str>, _pid: Option<u32>, _ips: &[IpAddr]) -> anyhow::Result<()> {
            self.log(format!("unblock:{}", rule));
            Ok(())
        }
        fn suspend(&self, pid: u32) -> anyhow::Result<()> {
            self.log(format!("suspend:{}", pid));
            Ok(())
        }
        fn resume(&self, pid: u32) -> anyhow::Result<()> {
            self.log(format!("resume:{}", pid));
            Ok(())
        }
        fn terminate(&self, pid: u32) -> anyhow::Result<()> {
            self.log(format!("terminate:{}", pid));
            Ok(())
        }
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("osoosi_dlpc_{}_{}", tag, uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Runs the real DLP inspection path on a payload to build the event under test.
    fn real_event(actor: &str, sink: &str, payload: &str, containment_mode: &str) -> DlpInspectionEventRecord {
        let mut engine = osoosi_dp::OsoosiTwoTierDlpEngine::new();
        let _ = &mut engine;
        let mut state = crate::routes::dlp::DlpDashboardState {
            engine,
            policy_mode: "ENFORCE_BLOCK_AND_SCRUB".to_string(),
            min_phi_threshold: 0.7,
            redactx_detection_mode: "zero_leakage".to_string(),
            redactx_containment_mode: containment_mode.to_string(),
            total_inspections: 0,
            blocked_exfiltrations: 0,
            scrubbed_pii_entities: 0,
            zk_bft_proofs_verified: 0,
            crown_jewels: Vec::new(),
            recent_events: Vec::new(),
        };
        let (_, _, ev) = crate::routes::dlp::inspect_and_record_with_options(
            &mut state,
            actor,
            sink,
            "HAR_HTTP_BODY",
            payload,
            "TEST",
            crate::routes::dlp::DlpInspectOptions::default(),
        );
        ev
    }

    const SENSITIVE: &str = "POST https://dlptest.com/http-post/ HTTP/1.1\nHost: dlptest.com\n\nname=Jane+Doe&ssn=123-45-6789&card=4532015112830366";

    fn ctx(pid: Option<u32>, image: Option<String>) -> ActorContext {
        ActorContext {
            actor: image
                .as_deref()
                .and_then(|p| Path::new(p).file_name().and_then(|n| n.to_str()))
                .unwrap_or("fixture.exe")
                .to_string(),
            pid,
            image_path: image,
            destination_url: "https://dlptest.com/http-post/".to_string(),
            destination_host: "dlptest.com".to_string(),
            injection_indicators: Vec::new(),
        }
    }

    fn engine_with(platform: Arc<FixturePlatform>, tag: &str) -> (DlpContainmentEngine, PathBuf) {
        let dir = temp_dir(tag);
        let e = DlpContainmentEngine::new(platform, dir.join("vault"), Some(dir.join("registry.json")));
        e.set_enabled(true);
        (e, dir)
    }

    #[test]
    fn unsigned_malicious_process_with_dlp_consensus_is_contained_and_restorable() {
        let dir = temp_dir("fixture_bin");
        let bin = dir.join("updater_helper.exe");
        std::fs::write(&bin, b"MZ fixture binary bytes").unwrap();
        let platform = Arc::new(FixturePlatform {
            rea_malicious: true,
            voters_escalate: true,
            pid: Some(4242),
            image: Some(bin.display().to_string()),
            ..Default::default()
        });
        let (engine, edir) = engine_with(platform.clone(), "contain");
        let ev = real_event("updater_helper.exe", "https://dlptest.com/http-post/", SENSITIVE, "balanced_utility");
        assert!(!ev.allowed);
        assert!(ev.redactx_confirmed_containment);
        assert!(ev.openjev_enforcement_agreed);
        let out = engine.evaluate_and_respond(&ev, &ctx(Some(4242), Some(bin.display().to_string())), None);
        assert_eq!(out.decision, ContainmentDecision::ProcessContained, "{:?}", out.reasons);
        let calls = platform.calls();
        assert!(calls.iter().any(|c| c.starts_with("block:OshoosiDLP-")));
        assert!(calls.contains(&"suspend:4242".to_string()));
        assert!(!bin.exists(), "binary must be moved to the vault");
        let vault = out.vault.clone().expect("vault record");
        assert!(Path::new(&vault.vault_path).exists());
        assert_eq!(vault.blake3, blake3::hash(b"MZ fixture binary bytes").to_hex().to_string());
        assert!(edir.join("registry.json").exists(), "registry persisted");
        assert_eq!(out.openjev_choice, "BLOCK_AND_SCRUB");
        assert!(out.redactx_validated_categories.contains(&"CREDIT_CARD_PAN".to_string()));

        let restored = engine.restore(&out.containment_id, "test").expect("restore");
        assert!(restored.restored);
        let calls = platform.calls();
        assert!(calls.iter().any(|c| c.starts_with("unblock:OshoosiDLP-")));
        assert!(calls.contains(&"resume:4242".to_string()));
        assert!(bin.exists(), "binary restored to original path");
        assert_eq!(std::fs::read(&bin).unwrap(), b"MZ fixture binary bytes");
    }

    #[test]
    fn verified_signed_browser_gets_destination_block_only() {
        let platform = Arc::new(FixturePlatform {
            signed: true,
            browser: true,
            voters_escalate: true,
            pid: None,
            image: Some("C:/Program Files/Microsoft/Edge/Application/msedge.exe".to_string()),
            ..Default::default()
        });
        let (engine, _d) = engine_with(platform.clone(), "browser");
        let ev = real_event("msedge.exe", "https://dlptest.com/http-post/", SENSITIVE, "balanced_utility");
        let out = engine.evaluate_and_respond(&ev, &ctx(None, platform.image.clone()), None);
        assert_eq!(out.decision, ContainmentDecision::DestinationBlocked, "{:?}", out.reasons);
        let calls = platform.calls();
        assert!(calls.iter().any(|c| c.contains("msedge.exe")));
        assert!(!calls.iter().any(|c| c.starts_with("suspend:") || c.starts_with("terminate:")));
        assert!(out.vault.is_none());
        assert!(out.expires_at.is_some(), "browser destination blocks auto-expire");
    }

    #[test]
    fn hollowed_signed_binary_forfeits_immunity() {
        let dir = temp_dir("hollow");
        let bin = dir.join("msedge.exe");
        std::fs::write(&bin, b"signed image").unwrap();
        let platform = Arc::new(FixturePlatform {
            signed: true,
            browser: true,
            voters_escalate: true,
            injection: vec!["Sysmon 25 ProcessTampering: image replaced".to_string()],
            pid: Some(5150),
            image: Some(bin.display().to_string()),
            ..Default::default()
        });
        let (engine, _d) = engine_with(platform.clone(), "hollow");
        let ev = real_event("msedge.exe", "https://dlptest.com/http-post/", SENSITIVE, "balanced_utility");
        let out = engine.evaluate_and_respond(&ev, &ctx(Some(5150), Some(bin.display().to_string())), None);
        assert_eq!(out.decision, ContainmentDecision::ProcessContained, "{:?}", out.reasons);
        assert!(platform.calls().contains(&"suspend:5150".to_string()));
        let vault = out.vault.expect("forensic copy");
        assert_eq!(vault.mode, "forensic_copy");
        assert!(bin.exists(), "signed on-disk image stays in place");
    }

    #[test]
    fn rea_only_and_dlp_only_produce_alerts() {
        // REA-malicious process, clean payload (no DLP finding).
        let platform = Arc::new(FixturePlatform {
            rea_malicious: true,
            voters_escalate: false,
            pid: Some(777),
            image: Some("/tmp/x/agent".to_string()),
            ..Default::default()
        });
        let (engine, _d) = engine_with(platform.clone(), "reaonly");
        let ev = real_event("agent", "https://example.org/search", "q=weather+tomorrow", "balanced_utility");
        let out = engine.evaluate_and_respond(&ev, &ctx(Some(777), Some("/tmp/x/agent".to_string())), None);
        assert_eq!(out.decision, ContainmentDecision::AlertOnly);
        assert!(platform.calls().is_empty());

        // DLP consensus from a non-malicious (REA not malicious, unsigned) actor.
        let platform2 = Arc::new(FixturePlatform {
            rea_malicious: false,
            voters_escalate: true,
            pid: Some(778),
            image: Some("/opt/app/sync".to_string()),
            ..Default::default()
        });
        let (engine2, _d2) = engine_with(platform2.clone(), "dlponly");
        let ev2 = real_event("sync", "https://dlptest.com/http-post/", SENSITIVE, "balanced_utility");
        let out2 = engine2.evaluate_and_respond(&ev2, &ctx(Some(778), Some("/opt/app/sync".to_string())), None);
        assert_eq!(out2.decision, ContainmentDecision::AlertOnly);
        assert!(platform2.calls().is_empty());
    }

    #[test]
    fn openjev_low_p_empty_categories_never_contains() {
        let platform = Arc::new(FixturePlatform {
            rea_malicious: true,
            voters_escalate: true,
            pid: Some(900),
            image: Some("/tmp/y/beacon".to_string()),
            ..Default::default()
        });
        let (engine, _d) = engine_with(platform.clone(), "lowp");
        let ev = real_event("beacon", "https://example.org/x", "hello world", "balanced_utility");
        assert!(!ev.openjev_enforcement_agreed);
        let out = engine.evaluate_and_respond(&ev, &ctx(Some(900), Some("/tmp/y/beacon".to_string())), None);
        assert_eq!(out.decision, ContainmentDecision::AlertOnly);
        assert!(platform.calls().is_empty());
    }

    #[test]
    fn format_only_span_between_thresholds_is_alert_only() {
        let platform = Arc::new(FixturePlatform {
            rea_malicious: true,
            voters_escalate: true,
            pid: Some(901),
            image: Some("/tmp/z/mailer".to_string()),
            ..Default::default()
        });
        let (engine, _d) = engine_with(platform.clone(), "span");
        let ev = real_event("mailer", "https://example.org/contact", "contact=jane.doe@example.org", "balanced_utility");
        assert!(ev.redactx_confirmed_detection);
        assert!(!ev.redactx_confirmed_containment);
        let out = engine.evaluate_and_respond(&ev, &ctx(Some(901), Some("/tmp/z/mailer".to_string())), None);
        assert_eq!(out.decision, ContainmentDecision::AlertOnly);
        assert!(platform.calls().is_empty());
    }

    #[test]
    fn repeated_events_inside_debounce_window_contain_once() {
        let dir = temp_dir("debounce_bin");
        let bin = dir.join("dropper.exe");
        std::fs::write(&bin, b"dropper").unwrap();
        let platform = Arc::new(FixturePlatform {
            rea_malicious: true,
            voters_escalate: true,
            pid: Some(6060),
            image: Some(bin.display().to_string()),
            ..Default::default()
        });
        let (engine, _d) = engine_with(platform.clone(), "debounce");
        let ev = real_event("dropper.exe", "https://dlptest.com/http-post/", SENSITIVE, "balanced_utility");
        let c = ctx(Some(6060), Some(bin.display().to_string()));
        let first = engine.evaluate_and_respond(&ev, &c, None);
        let second = engine.evaluate_and_respond(&ev, &c, None);
        let third = engine.evaluate_and_respond(&ev, &c, None);
        assert_eq!(first.decision, ContainmentDecision::ProcessContained);
        assert_eq!(second.decision, ContainmentDecision::Debounced);
        assert_eq!(third.decision, ContainmentDecision::Debounced);
        let suspends = platform.calls().iter().filter(|c| c.starts_with("suspend:")).count();
        assert_eq!(suspends, 1);
    }

    #[test]
    fn disabled_switch_downgrades_to_alert() {
        let platform = Arc::new(FixturePlatform {
            rea_malicious: true,
            voters_escalate: true,
            pid: Some(4343),
            image: Some("/tmp/q/tool".to_string()),
            ..Default::default()
        });
        let (engine, _d) = engine_with(platform.clone(), "disabled");
        engine.set_enabled(false);
        let ev = real_event("tool", "https://dlptest.com/http-post/", SENSITIVE, "balanced_utility");
        let out = engine.evaluate_and_respond(&ev, &ctx(Some(4343), Some("/tmp/q/tool".to_string())), None);
        assert_eq!(out.decision, ContainmentDecision::AlertOnly);
        assert!(platform.calls().is_empty());
    }

    #[test]
    fn voter_quorum_requires_probability_and_two_escalations() {
        let b = |e: bool, c: f64| VoterBallot { voter: "v".into(), escalate: e, confidence: c, weight: 1.0, reason: String::new() };
        assert!(!VoterConsensus::from_ballots(vec![b(true, 0.99)]).reached);
        assert!(VoterConsensus::from_ballots(vec![b(true, 0.95), b(true, 0.9)]).reached);
        assert!(!VoterConsensus::from_ballots(vec![b(true, 0.95), b(true, 0.9), b(false, 0.5), b(false, 0.5)]).reached);
    }
}
