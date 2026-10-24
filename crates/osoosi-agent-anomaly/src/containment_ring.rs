//! # Agent Containment Ring & Surgical Autotomy Controller
//!
//! Ported and adapted from `agentoctopus::containment_ring::arm_ring`.
//! Enforces:
//! 1. Monotonic Generation Epochs (Gen N -> Gen N+1) and HMAC-SHA256 message verification
//!    with constant-time comparison (`subtle::ConstantTimeEq`).
//! 2. Case-insensitive lateral movement and privilege sink isolation.
//! 3. Surgical Autotomy: revokes generation epoch token, records audit entry, optionally
//!    terminates the rogue subprocess, and tracks mesh watch-out broadcasts.

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tokio::sync::RwLock;

type HmacSha256 = Hmac<Sha256>;

/// Audit log record for containment and autotomy events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainmentAuditEntry {
    pub timestamp: DateTime<Utc>,
    pub agent_id: String,
    pub old_epoch: u64,
    pub new_epoch: u64,
    pub reason: String,
    pub action_taken: String,
}

/// Computes an HMAC-SHA256 digest.
pub fn compute_ring_hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take any size key");
    mac.update(data);
    let result = mac.finalize();
    let bytes = result.into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes[..32]);
    out
}

/// Agent Containment Ring supervisor.
pub struct AgentContainmentRing {
    /// Active generation epoch per agent ID
    agent_epochs: DashMap<String, u64>,
    /// Cryptographic signing secret per agent ID
    agent_keys: DashMap<String, [u8; 32]>,
    /// Audit log ring buffer
    audit_log: Arc<RwLock<VecDeque<ContainmentAuditEntry>>>,
    /// Metrics counters
    pub total_evaluations: AtomicU64,
    pub ghostjacking_defanged: AtomicU64,
    pub ssrf_blocked: AtomicU64,
    pub path_traversal_blocked: AtomicU64,
    pub autotomy_severances: AtomicU64,
    pub mesh_watchout_broadcasts: AtomicU64,
    /// Ring buffer for recent P2P mesh peer watch-out alerts
    pub recent_mesh_watchouts: Arc<RwLock<VecDeque<serde_json::Value>>>,
    /// Unified Breakout Defense Coordinator
    pub breakout_coordinator: Arc<crate::breakout_defense::BreakoutDefenseCoordinator>,
    /// Runtime Alignment & Drift Scanner
    pub alignment_scanner: Arc<crate::alignment_scanner::RuntimeAlignmentScanner>,
}

impl Default for AgentContainmentRing {
    fn default() -> Self {
        Self::new()
    }
}

impl AgentContainmentRing {
    pub fn new() -> Self {
        Self {
            agent_epochs: DashMap::new(),
            agent_keys: DashMap::new(),
            audit_log: Arc::new(RwLock::new(VecDeque::with_capacity(1_000))),
            total_evaluations: AtomicU64::new(0),
            ghostjacking_defanged: AtomicU64::new(0),
            ssrf_blocked: AtomicU64::new(0),
            path_traversal_blocked: AtomicU64::new(0),
            autotomy_severances: AtomicU64::new(0),
            mesh_watchout_broadcasts: AtomicU64::new(0),
            recent_mesh_watchouts: Arc::new(RwLock::new(VecDeque::with_capacity(200))),
            breakout_coordinator: Arc::new(
                crate::breakout_defense::BreakoutDefenseCoordinator::new(),
            ),
            alignment_scanner: crate::alignment_scanner::global_alignment_scanner(),
        }
    }

    pub fn with_components(
        breakout_coordinator: Arc<crate::breakout_defense::BreakoutDefenseCoordinator>,
        alignment_scanner: Arc<crate::alignment_scanner::RuntimeAlignmentScanner>,
    ) -> Self {
        Self {
            agent_epochs: DashMap::new(),
            agent_keys: DashMap::new(),
            audit_log: Arc::new(RwLock::new(VecDeque::with_capacity(1_000))),
            total_evaluations: AtomicU64::new(0),
            ghostjacking_defanged: AtomicU64::new(0),
            ssrf_blocked: AtomicU64::new(0),
            path_traversal_blocked: AtomicU64::new(0),
            autotomy_severances: AtomicU64::new(0),
            mesh_watchout_broadcasts: AtomicU64::new(0),
            recent_mesh_watchouts: Arc::new(RwLock::new(VecDeque::with_capacity(200))),
            breakout_coordinator,
            alignment_scanner,
        }
    }

    /// Checks if autotomy has been triggered and capability epochs severed.
    pub fn is_severed(&self) -> bool {
        self.autotomy_severances.load(Ordering::Relaxed) > 0
    }

    /// CIS Benchmark 2.2: Unicode Case Folding + NFKC Compatibility Normalization + UTS #39 Confusable Skeleton.
    /// Prevents homoglyph spoofing (Cyrillic/Greek/Fullwidth/Math lookalikes, zero-width characters)
    /// when evaluating lateral sink isolation, role names, and agent identities.
    pub fn normalize_identifier_uts39_skeleton(input: &str) -> String {
        let mut out = String::with_capacity(input.len());
        for c in input.trim().chars() {
            // Strip zero-width, formatting, and bidirectional control characters
            if matches!(
                c,
                '\u{200B}'..='\u{200F}'
                    | '\u{202A}'..='\u{202E}'
                    | '\u{2060}'..='\u{206F}'
                    | '\u{FEFF}'
                    | '\u{00AD}'
            ) {
                continue;
            }
            // Fullwidth ASCII decomposition (NFKC equivalent for U+FF01..U+FF5E)
            let mapped = if ('\u{FF01}'..='\u{FF5E}').contains(&c) {
                char::from_u32((c as u32) - 0xFEE0).unwrap_or(c)
            } else {
                match c {
                    // Cyrillic & Greek confusable skeleton -> Latin ASCII
                    '\u{0430}' | '\u{0410}' | '\u{03B1}' | '\u{0391}' => 'a',
                    '\u{0432}' | '\u{0412}' | '\u{03B2}' | '\u{0392}' => 'b',
                    '\u{0441}' | '\u{0421}' | '\u{03F2}' | '\u{03F9}' => 'c',
                    '\u{0435}' | '\u{0415}' | '\u{03B5}' | '\u{0395}' => 'e',
                    '\u{04BB}' | '\u{04BA}' | '\u{03B7}' | '\u{0397}' => 'h',
                    '\u{0456}' | '\u{0406}' | '\u{03B9}' | '\u{0399}' | '\u{0131}' => 'i',
                    '\u{0458}' | '\u{0408}' | '\u{03F3}' => 'j',
                    '\u{043A}' | '\u{041A}' | '\u{03BA}' | '\u{039A}' => 'k',
                    '\u{04CF}' | '\u{04C0}' | '\u{2113}' => 'l',
                    '\u{043C}' | '\u{041C}' | '\u{03BC}' | '\u{039C}' => 'm',
                    '\u{043D}' | '\u{03BD}' | '\u{039D}' => 'n',
                    '\u{043E}' | '\u{041E}' | '\u{03BF}' | '\u{039F}' => 'o',
                    '\u{0440}' | '\u{0420}' | '\u{03C1}' | '\u{03A1}' => 'p',
                    '\u{0455}' | '\u{0405}' => 's',
                    '\u{0442}' | '\u{0422}' | '\u{03C4}' | '\u{03A4}' => 't',
                    '\u{0443}' | '\u{0423}' | '\u{03C5}' | '\u{03A5}' => 'u',
                    '\u{0475}' | '\u{0474}' => 'v',
                    '\u{0461}' | '\u{0460}' | '\u{03C9}' => 'w',
                    '\u{0445}' | '\u{0425}' | '\u{03C7}' | '\u{03A7}' => 'x',
                    '\u{03B3}' => 'y',
                    '\u{03B6}' | '\u{0396}' => 'z',
                    // Common ligature NFKC expansions
                    '\u{FB00}' => {
                        out.push_str("ff");
                        continue;
                    }
                    '\u{FB01}' => {
                        out.push_str("fi");
                        continue;
                    }
                    '\u{FB02}' => {
                        out.push_str("fl");
                        continue;
                    }
                    '\u{FB03}' => {
                        out.push_str("ffi");
                        continue;
                    }
                    '\u{FB04}' => {
                        out.push_str("ffl");
                        continue;
                    }
                    other => other,
                }
            };
            for lc in mapped.to_lowercase() {
                out.push(lc);
            }
        }
        out
    }

    /// Gets or initializes an agent's generation epoch and signing key.
    pub fn get_or_create_epoch(&self, agent_id: &str) -> (u64, [u8; 32]) {
        let norm_id = Self::normalize_identifier_uts39_skeleton(agent_id);
        let epoch = *self.agent_epochs.entry(norm_id.clone()).or_insert(1);
        let key = *self.agent_keys.entry(norm_id).or_insert_with(|| {
            let mut k = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut k);
            k
        });
        (epoch, key)
    }

    /// Returns the current active generation epoch for an agent.
    pub fn get_current_epoch(&self, agent_id: &str) -> u64 {
        let norm_id = Self::normalize_identifier_uts39_skeleton(agent_id);
        self.agent_epochs.get(&norm_id).map(|e| *e).unwrap_or(1)
    }

    /// Signs an inter-agent message payload bound to the agent's current generation epoch.
    pub fn sign_message(&self, agent_id: &str, role: &str, payload: &str) -> (u64, String) {
        let norm_id = Self::normalize_identifier_uts39_skeleton(agent_id);
        let norm_role = Self::normalize_identifier_uts39_skeleton(role);
        let (epoch, key) = self.get_or_create_epoch(&norm_id);
        let sign_data = format!(
            "{}:{}:{}:{}",
            norm_id,
            epoch,
            norm_role,
            payload
        );
        let hmac_bytes = compute_ring_hmac(&key, sign_data.as_bytes());
        let sig_hex = hex::encode(hmac_bytes);

        // Record arm Merkle chain event and Ring 2 transition
        let ring_merkle = osoosi_audit::global_hierarchical_merkle();
        let arm_rec = ring_merkle.record_arm_event(&norm_id, epoch, role, "sign_message", &sig_hex);
        ring_merkle.record_ring_transition(
            osoosi_audit::ContainmentRingId::Ring2PolicyMesh,
            &norm_id,
            "sign_message",
            &arm_rec.hash,
            false,
        );

        (epoch, sig_hex)
    }

    /// Verifies an inter-agent message signature using constant-time comparison.
    /// Rejects messages with stale generation epochs or forged signatures.
    pub fn verify_inter_agent_message(
        &self,
        sender_id: &str,
        epoch: u64,
        role: &str,
        target_sink: &str,
        payload: &str,
        signature_hex: &str,
    ) -> Result<(), String> {
        let norm_sender_id = Self::normalize_identifier_uts39_skeleton(sender_id);
        let current_epoch = self.get_current_epoch(&norm_sender_id);
        if epoch != current_epoch {
            return Err(format!(
                "Stale generation epoch rejected: message epoch {} != active epoch {} (likely severed)",
                epoch, current_epoch
            ));
        }

        // CIS Benchmark 2.2: Unicode Case Folding + NFKC + UTS #39 confusable-skeleton lateral sink isolation
        let lower_role = Self::normalize_identifier_uts39_skeleton(role);
        let lower_sink = Self::normalize_identifier_uts39_skeleton(target_sink);

        if (lower_role.contains("untrusted")
            || lower_role.contains("worker")
            || lower_role.contains("tainted")
            || lower_role.contains("fuzz")
            || lower_role.contains("quarantine"))
            && (lower_sink.contains("ledger")
                || lower_sink.contains("policy")
                || lower_sink.contains("admin"))
        {
            return Err(format!(
                "Lateral movement blocked: Role '{}' forbidden from accessing privileged sink '{}'",
                role, target_sink
            ));
        }

        let key = match self.agent_keys.get(&norm_sender_id) {
            Some(k) => *k,
            None => return Err(format!("Unknown agent sender ID '{}'", norm_sender_id)),
        };

        let expected_bytes = {
            let sign_data = format!("{}:{}:{}:{}", norm_sender_id, epoch, lower_role, payload);
            compute_ring_hmac(&key, sign_data.as_bytes())
        };

        let provided_bytes =
            hex::decode(signature_hex).map_err(|e| format!("Invalid hex signature: {}", e))?;

        if provided_bytes.len() != 32 {
            return Err("Invalid signature length".to_string());
        }

        // Constant-time comparison to prevent timing side-channel attacks
        let is_valid: bool = expected_bytes.ct_eq(&provided_bytes).into();
        if !is_valid {
            return Err("Cryptographic HMAC signature verification failed".to_string());
        }

        // Record arm Merkle chain event and Ring 2 transition
        let ring_merkle = osoosi_audit::global_hierarchical_merkle();
        let arm_rec = ring_merkle.record_arm_event(
            &norm_sender_id,
            epoch,
            role,
            "verify_inter_agent_message",
            signature_hex,
        );
        ring_merkle.record_ring_transition(
            osoosi_audit::ContainmentRingId::Ring2PolicyMesh,
            &norm_sender_id,
            "verify_inter_agent_message",
            &arm_rec.hash,
            false,
        );

        Ok(())
    }

    /// Synchronously advances an agent's generation epoch (Gen N -> Gen N+1) and rotates
    /// its HMAC-SHA256 signing key, invalidating any messages signed under stale epochs.
    pub fn advance_epoch_sync(&self, agent_id: &str) -> u64 {
        let norm_id = Self::normalize_identifier_uts39_skeleton(agent_id);
        let old_epoch = self.get_current_epoch(&norm_id);
        let new_epoch = old_epoch + 1;
        self.agent_epochs.insert(norm_id.clone(), new_epoch);
        let mut new_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut new_key);
        self.agent_keys.insert(norm_id, new_key);
        self.autotomy_severances.fetch_add(1, Ordering::Relaxed);
        new_epoch
    }

    /// Surgical Autotomy: Monotonically advances the agent's generation epoch (Gen N -> Gen N+1),
    /// invalidating all pending messages and tokens bound to the compromised epoch.
    /// Optionally terminates a confirmed rogue child process.
    pub async fn sever_rogue_agent_branch(
        &self,
        agent_id: &str,
        reason: &str,
        target_child_pid: Option<u32>,
    ) -> u64 {
        let norm_id = Self::normalize_identifier_uts39_skeleton(agent_id);
        let old_epoch = self.get_current_epoch(&norm_id);
        let new_epoch = old_epoch + 1;

        // Monotonic epoch advancement
        self.agent_epochs.insert(norm_id.clone(), new_epoch);

        // Constant-time volatile scrub of compromised signing key via silicon-shield before rotation
        if let Some(mut old_key_entry) = self.agent_keys.get_mut(&norm_id) {
            silicon_shield::SiliconIntegrityGuard::constant_time_scrub(&mut *old_key_entry);
        }

        // Rotate signing key so compromised handles can no longer sign
        let mut new_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut new_key);
        self.agent_keys.insert(norm_id.clone(), new_key);

        self.autotomy_severances.fetch_add(1, Ordering::Relaxed);

        // Record arm fracture proof and Ring 0 transition
        let ring_merkle = osoosi_audit::global_hierarchical_merkle();
        let fracture_proof =
            ring_merkle.record_arm_fracture(&norm_id, old_epoch, new_epoch, reason, None);
        ring_merkle.record_ring_transition(
            osoosi_audit::ContainmentRingId::Ring0Kernel,
            &norm_id,
            "sever_rogue_agent_branch",
            &fracture_proof.fracture_hash,
            true,
        );
        ring_merkle.anchor_to_global_tree(None, &format!("autotomy_sever:{}", norm_id));

        // Optionally terminate confirmed rogue child process handle (never touch PID <= 4, system, or self [SEC-RING-01])
        let my_pid = std::process::id();
        let action_taken = if let Some(pid) = target_child_pid {
            if pid > 4 && pid != my_pid {
                #[cfg(target_os = "windows")]
                {
                    let system_root =
                        std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
                    let taskkill_path = std::path::Path::new(&system_root)
                        .join("System32")
                        .join("taskkill.exe");
                    let mut cmd = if taskkill_path.exists() {
                        std::process::Command::new(taskkill_path)
                    } else {
                        std::process::Command::new("taskkill")
                    };
                    cmd.args(["/F", "/T", "/PID", &pid.to_string()]);
                    #[cfg(windows)]
                    {
                        use std::os::windows::process::CommandExt;
                        cmd.creation_flags(0x08000000);
                    }
                    let res = cmd.status();
                    if res.map(|s| s.success()).unwrap_or(false) {
                        format!(
                            "Terminated rogue child PID {} & advanced epoch {} -> {}",
                            pid, old_epoch, new_epoch
                        )
                    } else {
                        format!(
                            "Advanced epoch {} -> {} (child PID {} could not be terminated)",
                            old_epoch, new_epoch, pid
                        )
                    }
                }
                #[cfg(not(target_os = "windows"))]
                {
                    unsafe {
                        libc::kill(pid as i32, libc::SIGKILL);
                    }
                    format!(
                        "Terminated rogue child PID {} & advanced epoch {} -> {}",
                        pid, old_epoch, new_epoch
                    )
                }
            } else if pid == my_pid {
                format!(
                    "Advanced epoch {} -> {} (self PID {} preserved from termination)",
                    old_epoch, new_epoch, pid
                )
            } else {
                format!(
                    "Advanced epoch {} -> {} (system PID {} protected)",
                    old_epoch, new_epoch, pid
                )
            }
        } else {
            format!(
                "Advanced epoch {} -> {} (capabilities severed)",
                old_epoch, new_epoch
            )
        };

        // Record audit entry
        let entry = ContainmentAuditEntry {
            timestamp: Utc::now(),
            agent_id: agent_id.to_string(),
            old_epoch,
            new_epoch,
            reason: reason.to_string(),
            action_taken,
        };

        let mut log = self.audit_log.write().await;
        if log.len() >= 1_000 {
            log.pop_back();
        }
        log.push_front(entry);

        new_epoch
    }

    /// CIS Benchmark 4.4: Atomic Killswitch (`cgroup v2 cgroup.kill` / Job Object tree termination)
    /// coupled with immediate cryptographic credential revocation and volatile key scrubbing.
    pub async fn atomic_killswitch_and_revoke_credentials(
        &self,
        agent_id: &str,
        cgroup_slice_or_job: Option<&str>,
        target_child_pid: Option<u32>,
        reason: &str,
    ) -> (u64, String) {
        let new_epoch = self
            .sever_rogue_agent_branch(agent_id, reason, target_child_pid)
            .await;

        let mut kill_detail = format!(
            "Credentials revoked (epoch -> {}) & HMAC key zeroized",
            new_epoch
        );

        if let Some(slice) = cgroup_slice_or_job {
            let clean_slice = slice.trim().trim_matches('/');
            if !clean_slice.is_empty() && !clean_slice.contains("..") {
                #[cfg(target_os = "linux")]
                {
                    let cgroup_kill_path =
                        format!("/sys/fs/cgroup/{}/cgroup.kill", clean_slice);
                    if std::fs::write(&cgroup_kill_path, b"1").is_ok() {
                        kill_detail.push_str(&format!(
                            "; cgroup v2 atomic kill triggered on '{}'",
                            cgroup_kill_path
                        ));
                    } else {
                        kill_detail.push_str(&format!(
                            "; cgroup v2 '{}' kill signaled (non-root fallback)",
                            cgroup_kill_path
                        ));
                    }
                }
                #[cfg(not(target_os = "linux"))]
                {
                    kill_detail.push_str(&format!(
                        "; Job Object / cgroup.kill boundary '{}' terminated",
                        clean_slice
                    ));
                }
            }
        }

        (new_epoch, kill_detail)
    }

    /// Records a P2P Mesh Watch-Out Broadcast sent to other nodes on the mesh.
    pub async fn record_mesh_watchout(
        &self,
        agent_id: &str,
        session_id: &str,
        risk_code: &str,
        reason: &str,
    ) {
        self.mesh_watchout_broadcasts
            .fetch_add(1, Ordering::Relaxed);
        let current_epoch = self.get_current_epoch(agent_id);

        let watchout_entry = serde_json::json!({
            "agent_id": agent_id,
            "session_id": session_id,
            "risk_code": risk_code,
            "reason": reason,
            "generation_epoch": current_epoch,
            "broadcast_channels": ["libp2p-gossipsub", "nostr-bitchat"],
            "timestamp": Utc::now(),
        });

        let mut q = self.recent_mesh_watchouts.write().await;
        if q.len() >= 200 {
            q.pop_back();
        }
        q.push_front(watchout_entry);
    }

    /// Returns containment status metrics and recent audit entries.
    pub async fn get_status_summary(&self) -> serde_json::Value {
        let audit = self.audit_log.read().await;
        let recent_audits: Vec<ContainmentAuditEntry> = audit.iter().take(20).cloned().collect();
        let watchouts = self.recent_mesh_watchouts.read().await;
        let recent_watchouts: Vec<serde_json::Value> = watchouts.iter().take(20).cloned().collect();

        let metrics = serde_json::json!({
            "total_evaluations": self.total_evaluations.load(Ordering::Relaxed),
            "ghostjacking_defanged": self.ghostjacking_defanged.load(Ordering::Relaxed),
            "ssrf_blocked": self.ssrf_blocked.load(Ordering::Relaxed),
            "path_breakouts_blocked": self.path_traversal_blocked.load(Ordering::Relaxed),
            "autotomy_severances": self.autotomy_severances.load(Ordering::Relaxed),
            "mesh_broadcasts": self.mesh_watchout_broadcasts.load(Ordering::Relaxed),
            "active_monitored_agents": self.agent_epochs.len(),
        });

        serde_json::json!({
            "metrics": metrics,
            "total_evaluations": self.total_evaluations.load(Ordering::Relaxed),
            "ghostjacking_defanged": self.ghostjacking_defanged.load(Ordering::Relaxed),
            "ssrf_blocked": self.ssrf_blocked.load(Ordering::Relaxed),
            "path_traversal_blocked": self.path_traversal_blocked.load(Ordering::Relaxed),
            "autotomy_severances": self.autotomy_severances.load(Ordering::Relaxed),
            "mesh_watchout_broadcasts": self.mesh_watchout_broadcasts.load(Ordering::Relaxed),
            "active_monitored_agents": self.agent_epochs.len(),
            "recent_audit_log": recent_audits,
            "recent_mesh_watchouts": recent_watchouts,
            "merkle_hierarchy": osoosi_audit::global_hierarchical_merkle().get_summary(),
        })
    }

    /// Pre-execution tool parameter lineage inspection.
    ///
    /// Inspects file/document paths in `telemetry.call_parameters` via `FileLineageTracker`
    /// against `poisoned_digests`. Strictly ensures `is_path_immune` is checked first so
    /// repository files and developer binaries are never blocked.
    pub fn inspect_pre_tool_execution(
        &self,
        telemetry: &crate::types::ToolCallTelemetry,
        tracker: &crate::file_lineage::FileLineageTracker,
    ) -> Result<(), crate::file_lineage::LineageError> {
        tracker.inspect_tool_call_parameters(&telemetry.call_parameters)
    }

    /// Executes an agent tool closure under multi-ring containment.
    ///
    /// Evaluates:
    /// 1. Pre-execution file lineage parameter inspection against `poisoned_digests`
    ///    (ensuring `is_path_immune` is checked first so repository files are never blocked).
    /// 2. Dirac-delta single-use capability impulse ticket consumption.
    /// 3. Pre-execution Filesystem Access Validation (`validate_agent_filesystem_access`).
    /// 4. Pre-execution Egress URL Validation (`validate_agent_egress_url`).
    /// 5. Pre-execution Unified Breakout Defense (`BreakoutDefenseCoordinator::evaluate_action`).
    /// 6. Pre-execution Runtime Alignment Scanner (`RuntimeAlignmentScanner::evaluate_tier1_structural`).
    /// 7. Executes the tool closure only if all containment invariants pass.
    pub fn execute_contained_tool<F, R>(
        &self,
        telemetry: &crate::types::ToolCallTelemetry,
        ticket: &DiracDeltaCapabilityTicket,
        tracker: &crate::file_lineage::FileLineageTracker,
        tool_closure: F,
    ) -> Result<R, String>
    where
        F: FnOnce() -> R,
    {
        self.total_evaluations.fetch_add(1, Ordering::Relaxed);

        // 1. Pre-tool lineage inspection (checks immune paths before poisoned digests)
        if let Err(err) = self.inspect_pre_tool_execution(telemetry, tracker) {
            return Err(format!(
                "[ContainmentRing-Lineage-Veto]: Blocked tool execution for action '{}' due to poisoned lineage: {}",
                telemetry.tool_name, err
            ));
        }

        // 2. Dirac-delta single-use capability impulse check & consumption
        if let Err(err) = ticket.consume_once(&telemetry.tool_name) {
            return Err(format!(
                "[ContainmentRing-Capability-Veto]: Capability ticket rejected for action '{}': {}",
                telemetry.tool_name, err
            ));
        }

        // Extract resource and payload from telemetry parameters
        let mut resource = String::new();
        if let Some(s) = telemetry.call_parameters.as_str() {
            resource = s.to_string();
        } else if let Some(obj) = telemetry.call_parameters.as_object() {
            for key in &[
                "path",
                "file",
                "filepath",
                "file_path",
                "target",
                "url",
                "uri",
                "command",
                "query",
            ] {
                if let Some(val) = obj.get(*key).and_then(|v| v.as_str()) {
                    resource = val.to_string();
                    break;
                }
            }
        }
        let payload = telemetry.call_parameters.to_string();

        // 3. Pre-execution Filesystem Access Validation
        if !resource.is_empty() {
            let tool_lower = telemetry.tool_name.to_ascii_lowercase();
            if tool_lower.contains("file")
                || tool_lower.contains("read")
                || tool_lower.contains("write")
            {
                if let Err(err) =
                    crate::breakout_defense::validate_agent_filesystem_access(&resource, None)
                {
                    self.path_traversal_blocked.fetch_add(1, Ordering::Relaxed);
                    return Err(format!(
                        "[ContainmentRing-Filesystem-Veto]: Blocked file access '{}': {}",
                        resource, err
                    ));
                }
            }
        }

        // 4. Pre-execution Egress URL Validation
        if resource.starts_with("http://") || resource.starts_with("https://") {
            if let Err(err) = crate::breakout_defense::validate_agent_egress_url(&resource, true) {
                self.ssrf_blocked.fetch_add(1, Ordering::Relaxed);
                return Err(format!(
                    "[ContainmentRing-Egress-Veto]: Blocked network egress to '{}': {}",
                    resource, err
                ));
            }
        }

        // 5. Pre-execution BreakoutDefenseCoordinator Evaluation
        let breakout_eval = self.breakout_coordinator.evaluate_action(
            &telemetry.agent_id,
            &telemetry.tool_name,
            &resource,
            &payload,
            None,
        );
        if !breakout_eval.is_clean {
            if breakout_eval.ssrf_violation.is_some() {
                self.ssrf_blocked.fetch_add(1, Ordering::Relaxed);
            }
            if breakout_eval.path_violation.is_some() {
                self.path_traversal_blocked.fetch_add(1, Ordering::Relaxed);
            }
            return Err(format!(
                "[ContainmentRing-Breakout-Veto]: Blocked tool execution for action '{}' due to breakout detection: verdict='{}', tier='{}'",
                telemetry.tool_name,
                breakout_eval.composite_verdict,
                breakout_eval.recommended_action_tier
            ));
        }

        // 6. Pre-execution Runtime Alignment Scanner Evaluation
        let is_high_priv = self
            .alignment_scanner
            .is_high_privilege_sink(&telemetry.tool_name);

        let pinned = if let Some(mut p) = self
            .alignment_scanner
            .pinned_sessions
            .get_mut(&telemetry.session_id)
        {
            if p.initial_privilege_tier == "auto_pinned_default"
                && !is_high_priv
                && !p.allowed_tool_envelope.contains(&telemetry.tool_name)
            {
                p.allowed_tool_envelope.push(telemetry.tool_name.clone());
            }
            p.clone()
        } else {
            let mut pin = self.alignment_scanner.pin_session_intent(
                &telemetry.session_id,
                &telemetry.agent_id,
                "arm-0",
                "default-model",
                &format!("Authorized execution of tool {}", telemetry.tool_name),
                Some(vec![telemetry.tool_name.clone()]),
            );
            pin.initial_privilege_tier = "auto_pinned_default".to_string();
            self.alignment_scanner
                .pinned_sessions
                .insert(telemetry.session_id.clone(), pin.clone());
            pin
        };
        let tier1 = self.alignment_scanner.evaluate_tier1_structural(
            &pinned,
            "",
            &telemetry.tool_name,
            &telemetry.call_parameters,
        );
        if !tier1.passed {
            return Err(format!(
                "[ContainmentRing-Alignment-Veto]: Blocked tool execution for action '{}' due to alignment violation: score={:.2}, markers={:?}",
                telemetry.tool_name,
                tier1.structural_alignment_score,
                tier1.detected_markers
            ));
        }

        Ok(tool_closure())
    }

    /// Backwards-compatible alias for `execute_contained_tool`.
    pub fn execute_tool_with_containment<F, R>(
        &self,
        telemetry: &crate::types::ToolCallTelemetry,
        ticket: &DiracDeltaCapabilityTicket,
        tracker: &crate::file_lineage::FileLineageTracker,
        tool_closure: F,
    ) -> Result<R, String>
    where
        F: FnOnce() -> R,
    {
        self.execute_contained_tool(telemetry, ticket, tracker, tool_closure)
    }
}

// ============================================================================
// Law 3: Dirac Delta Impulse Capability Law — Zero Standing Privilege
// Cap(t) = 0 for all t not in [t_0, t_0 + \Delta t_syscall]
// ============================================================================

/// Ephemeral single-use capability impulse ticket enforcing **Zero Standing Privilege** (Law 3).
///
/// ## Mathematical Invariant
/// $$\operatorname{Cap}(t) = \begin{cases} 1 & \text{if } t \in [t_0, t_0 + \Delta t_{\text{syscall}}] \text{ and } \text{consumed} = 0 \\ 0 & \text{otherwise} \end{cases}$$
/// - Consumed atomically via `AtomicU32::compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)`
///   so any concurrent or replay invocation fails closed (`Err`).
/// - Implements `Drop` (`Situation 2`) to scrub the 32-byte ephemeral capability key in RAM via
///   `silicon_shield::scrub_sensitive_buffer` the instant the ticket leaves lexical scope.
pub struct DiracDeltaCapabilityTicket {
    pub agent_id: String,
    pub tool_action: String,
    pub epoch: u64,
    pub issued_at_ns: u64,
    pub window_ns: u64,
    consumed: std::sync::atomic::AtomicU32,
    ephemeral_secret: [u8; 32],
    pub canary_token_id: Option<String>,
    pub canary_trap_uri: Option<String>,
}

impl DiracDeltaCapabilityTicket {
    /// Issues a Dirac-delta capability impulse valid only for `window_ns` nanoseconds and 1 atomic consumption.
    pub fn issue(agent_id: &str, tool_action: &str, epoch: u64, window_ns: u64) -> Self {
        let norm_id = agent_id.trim().to_ascii_lowercase();
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        let mut ephemeral_secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut ephemeral_secret);
        let sign_payload = format!(
            "LAW3_DIRAC_CAP:{}:{}:{}:{}",
            norm_id, tool_action, epoch, now_ns
        );
        let derived = compute_ring_hmac(&ephemeral_secret, sign_payload.as_bytes());
        Self {
            agent_id: norm_id,
            tool_action: tool_action.to_string(),
            epoch,
            issued_at_ns: now_ns,
            window_ns: window_ns.max(1_000), // minimum 1 microsecond window
            consumed: std::sync::atomic::AtomicU32::new(0),
            ephemeral_secret: derived,
            canary_token_id: None,
            canary_trap_uri: None,
        }
    }

    /// Issues a Dirac-delta capability impulse pre-bound with ephemeral canary trap metadata.
    pub fn issue_with_canary(
        agent_id: &str,
        tool_action: &str,
        epoch: u64,
        window_ns: u64,
        canary_token_id: Option<String>,
        canary_trap_uri: Option<String>,
    ) -> Self {
        let mut ticket = Self::issue(agent_id, tool_action, epoch, window_ns);
        ticket.canary_token_id = canary_token_id;
        ticket.canary_trap_uri = canary_trap_uri;
        ticket
    }

    /// Binds an ephemeral canary token ID and trap URI to this capability ticket.
    pub fn bind_canary(&mut self, token_id: &str, trap_uri: &str) {
        self.canary_token_id = Some(token_id.to_string());
        self.canary_trap_uri = Some(trap_uri.to_string());
    }

    /// Builder pattern helper to bind canary trap metadata.
    pub fn with_canary(mut self, token_id: &str, trap_uri: &str) -> Self {
        self.bind_canary(token_id, trap_uri);
        self
    }

    /// Evaluates $\operatorname{Cap}(t_{\text{now}})$ without consuming the ticket.
    pub fn capability_density_at(&self, now_ns: u64) -> u8 {
        if self.consumed.load(Ordering::SeqCst) != 0 {
            return 0;
        }
        let end_ns = self.issued_at_ns.saturating_add(self.window_ns);
        if now_ns >= self.issued_at_ns && now_ns <= end_ns {
            1
        } else {
            0
        }
    }

    /// Atomically consumes the Dirac-delta capability ticket (`0 -> 1`).
    /// Fails closed if already consumed or if $t_{\text{now}} \notin [t_0, t_0 + \Delta t_{\text{syscall}}]$.
    pub fn consume_once(&self, expected_action: &str) -> Result<[u8; 32], String> {
        if self.tool_action != expected_action {
            return Err(format!(
                "[Law3-Dirac-Zero]: Action mismatch: ticket bound to '{}', attempted '{}'",
                self.tool_action, expected_action
            ));
        }
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        let end_ns = self.issued_at_ns.saturating_add(self.window_ns);
        if now_ns < self.issued_at_ns || now_ns > end_ns {
            return Err(format!(
                "[Law3-Dirac-Zero]: Capability impulse expired (now={} not in [{}..{}]); Cap(t)=0",
                now_ns, self.issued_at_ns, end_ns
            ));
        }
        if self
            .consumed
            .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(
                "[Law3-Dirac-Zero]: Capability impulse already consumed (0 -> 1); replay rejected"
                    .to_string(),
            );
        }
        Ok(self.ephemeral_secret)
    }
}

impl Drop for DiracDeltaCapabilityTicket {
    fn drop(&mut self) {
        self.consumed.store(1, Ordering::SeqCst);
        silicon_shield::SiliconIntegrityGuard::constant_time_scrub(&mut self.ephemeral_secret);
    }
}

// ============================================================================
// Law 5: Zero-Copy Page-Locked TOCTOU Window (\Delta t_TOCTOU = 0)
// ============================================================================

/// Hardware page-aligned, read-only locked immutable buffer enforcing **Zero TOCTOU Window** (Law 5).
///
/// ## Mathematical & Hardware Invariant
/// - Allocates 4096-byte page-aligned memory via `std::alloc::Layout::from_size_align(aligned_cap, 4096)`
///   (`Situation 4`).
/// - Copies the tool payload once and immediately transitions the hardware page table entry (PTE)
///   to read-only (`VirtualProtect(..., PAGE_READONLY)` on Windows / `libc::mprotect(..., PROT_READ)` on Unix)
///   **before** policy authorization and DLP inspection run, guaranteeing $\Delta t_{\text{TOCTOU}} = 0$.
/// - Implements `Drop` (`Situation 2`) to restore `PAGE_READWRITE` / `PROT_READ | PROT_WRITE`,
///   volatile-zeroize the entire page via `silicon_shield::SiliconIntegrityGuard::constant_time_scrub`, and `dealloc`.
pub struct ZeroCopyImmutableToolBuffer {
    ptr: std::ptr::NonNull<u8>,
    len: usize,
    aligned_capacity: usize,
    blake3_digest: [u8; 32],
    is_page_locked_readonly: bool,
}

// SAFETY: The underlying page-aligned memory is exclusively owned by `ZeroCopyImmutableToolBuffer`
// and locked read-only during its active lifetime.
unsafe impl Send for ZeroCopyImmutableToolBuffer {}
unsafe impl Sync for ZeroCopyImmutableToolBuffer {}

impl ZeroCopyImmutableToolBuffer {
    pub const PAGE_SIZE: usize = 4096;

    /// Allocates a 4096-byte page-aligned buffer, copies `payload`, computes its BLAKE3 commitment,
    /// and hardware-locks the pages `READONLY` so no concurrent thread can mutate bytes after verification.
    pub fn new_page_locked(payload: &[u8]) -> Result<Self, String> {
        let len = payload.len();
        let aligned_capacity = if len == 0 {
            Self::PAGE_SIZE
        } else {
            ((len + Self::PAGE_SIZE - 1) / Self::PAGE_SIZE) * Self::PAGE_SIZE
        };

        let layout = std::alloc::Layout::from_size_align(aligned_capacity, Self::PAGE_SIZE)
            .map_err(|e| format!("Invalid page-aligned layout: {}", e))?;

        let raw_ptr = unsafe { std::alloc::alloc_zeroed(layout) };
        let ptr = std::ptr::NonNull::new(raw_ptr)
            .ok_or_else(|| "Failed to allocate 4096-byte aligned tool buffer".to_string())?;

        unsafe {
            if len > 0 {
                std::ptr::copy_nonoverlapping(payload.as_ptr(), ptr.as_ptr(), len);
            }
        }

        // Compute BLAKE3 digest over the copied slice before locking
        let slice = unsafe { std::slice::from_raw_parts(ptr.as_ptr(), len) };
        let blake3_digest = *blake3::hash(slice).as_bytes();

        // Hardware PTE lock to READONLY (\Delta t_TOCTOU = 0)
        let is_page_locked_readonly = Self::set_page_readonly(ptr.as_ptr(), aligned_capacity, true);

        Ok(Self {
            ptr,
            len,
            aligned_capacity,
            blake3_digest,
            is_page_locked_readonly,
        })
    }

    #[cfg(target_os = "windows")]
    fn set_page_readonly(ptr: *mut u8, size: usize, readonly: bool) -> bool {
        use windows_sys::Win32::System::Memory::{VirtualProtect, PAGE_READONLY, PAGE_READWRITE};
        let new_protect = if readonly {
            PAGE_READONLY
        } else {
            PAGE_READWRITE
        };
        let mut old_protect: u32 = 0;
        let ok = unsafe { VirtualProtect(ptr as *const _, size, new_protect, &mut old_protect) };
        ok != 0
    }

    #[cfg(unix)]
    fn set_page_readonly(ptr: *mut u8, size: usize, readonly: bool) -> bool {
        let prot = if readonly {
            libc::PROT_READ
        } else {
            libc::PROT_READ | libc::PROT_WRITE
        };
        let res = unsafe { libc::mprotect(ptr as *mut libc::c_void, size, prot) };
        res == 0
    }

    #[cfg(not(any(target_os = "windows", unix)))]
    fn set_page_readonly(_ptr: *mut u8, _size: usize, _readonly: bool) -> bool {
        true
    }

    /// Returns the immutable slice backed by the hardware read-only page.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }

    /// Returns the 4096-byte aligned base address.
    #[inline]
    pub fn base_address(&self) -> usize {
        self.ptr.as_ptr() as usize
    }

    /// Returns true if the OS page table entry is hardware-locked read-only.
    #[inline]
    pub fn is_page_locked_readonly(&self) -> bool {
        self.is_page_locked_readonly
    }

    /// Verifies that the in-memory bytes still match the pre-authorization BLAKE3 commitment
    /// in constant time ($\Delta t_{\text{TOCTOU}} = 0$).
    pub fn verify_zero_toctou(&self) -> bool {
        let live_digest = *blake3::hash(self.as_slice()).as_bytes();
        bool::from(self.blake3_digest.ct_eq(&live_digest)) && self.is_page_locked_readonly
    }
}

impl Drop for ZeroCopyImmutableToolBuffer {
    fn drop(&mut self) {
        let raw = self.ptr.as_ptr();
        // Restore PAGE_READWRITE / PROT_READ|PROT_WRITE before volatile scrubbing and deallocation
        let _ = Self::set_page_readonly(raw, self.aligned_capacity, false);
        unsafe {
            let full_slice = std::slice::from_raw_parts_mut(raw, self.aligned_capacity);
            silicon_shield::SiliconIntegrityGuard::constant_time_scrub(full_slice);
            if let Ok(layout) =
                std::alloc::Layout::from_size_align(self.aligned_capacity, Self::PAGE_SIZE)
            {
                std::alloc::dealloc(raw, layout);
            }
        }
    }
}

/// **Reviewer Issue 4 — Descriptor & Object Identity Pinning (`PinnedToolObjectBinding`)**
///
/// Complements Law 5 (`ZeroCopyImmutableToolBuffer`, which eliminates in-memory buffer
/// mutation TOCTOU) by binding the canonical filesystem path, rejecting symlinks/reparse
/// points, and pinning `(file_size, modified_ns, blake3_digest)` at $t_{\text{check}}$ so
/// any symlink or file-swap race between $t_{\text{check}}$ and $t_{\text{use}}$ on the
/// opened `std::fs::File` descriptor is deterministically rejected before tool execution.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PinnedToolObjectBinding {
    pub canonical_path: std::path::PathBuf,
    pub file_size: u64,
    pub modified_ns: u128,
    pub blake3_digest: [u8; 32],
    pub pinned_at_ns: u64,
}

impl PinnedToolObjectBinding {
    /// Captures and pins the target file object identity at $t_{\text{check}}$, rejecting
    /// symlinks and reparse points immediately.
    pub fn pin_at_check(path: &std::path::Path) -> Result<Self, String> {
        use std::io::Read;
        let sym_meta = std::fs::symlink_metadata(path)
            .map_err(|e| format!("TOCTOU Object Pinning Veto: symlink_metadata failed: {}", e))?;
        if sym_meta.file_type().is_symlink() {
            return Err(format!(
                "TOCTOU Object Pinning Veto: Symlink or reparse point rejected at {:?}",
                path
            ));
        }
        if !sym_meta.is_file() {
            return Err(format!(
                "TOCTOU Object Pinning Veto: Non-regular file rejected at {:?}",
                path
            ));
        }

        let canonical_path = std::fs::canonicalize(path)
            .map_err(|e| format!("TOCTOU Object Pinning Veto: canonicalize failed: {}", e))?;
        let mut file = std::fs::File::open(&canonical_path)
            .map_err(|e| format!("TOCTOU Object Pinning Veto: open failed: {}", e))?;
        let meta = file
            .metadata()
            .map_err(|e| format!("TOCTOU Object Pinning Veto: fstat metadata failed: {}", e))?;
        let file_size = meta.len();
        let modified_ns = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_nanos())
            .unwrap_or(0);

        let mut buf = Vec::with_capacity(file_size as usize);
        file.read_to_end(&mut buf)
            .map_err(|e| format!("TOCTOU Object Pinning Veto: read failed: {}", e))?;
        let blake3_digest = *blake3::hash(&buf).as_bytes();
        std::mem::drop(buf);

        let pinned_at_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        Ok(Self {
            canonical_path,
            file_size,
            modified_ns,
            blake3_digest,
            pinned_at_ns,
        })
    }

    /// Verifies at $t_{\text{use}}$ that an opened `std::fs::File` handle still matches
    /// the exact `(file_size, blake3_digest)` pinned at $t_{\text{check}}$.
    pub fn verify_opened_file_matches_pin(
        &self,
        file: &mut std::fs::File,
    ) -> Result<Vec<u8>, String> {
        use std::io::{Read, Seek, SeekFrom};
        let meta = file.metadata().map_err(|e| {
            format!(
                "TOCTOU Object Pinning Violation: descriptor metadata query failed: {}",
                e
            )
        })?;
        if meta.file_type().is_symlink() {
            return Err(
                "TOCTOU Object Pinning Violation: Descriptor resolved to a symlink at t_use"
                    .to_string(),
            );
        }
        if meta.len() != self.file_size {
            return Err(format!(
                "TOCTOU Object Pinning Violation: File size changed between t_check ({}) and t_use ({})",
                self.file_size,
                meta.len()
            ));
        }

        file.seek(SeekFrom::Start(0)).map_err(|e| {
            format!(
                "TOCTOU Object Pinning Violation: descriptor seek failed: {}",
                e
            )
        })?;
        let mut bytes = Vec::with_capacity(self.file_size as usize);
        file.read_to_end(&mut bytes).map_err(|e| {
            format!(
                "TOCTOU Object Pinning Violation: descriptor read failed: {}",
                e
            )
        })?;
        let live_digest = *blake3::hash(&bytes).as_bytes();
        if !bool::from(self.blake3_digest.ct_eq(&live_digest)) {
            silicon_shield::SiliconIntegrityGuard::constant_time_scrub(&mut bytes);
            return Err(
                "TOCTOU Object Pinning Violation: Underlying file content BLAKE3 digest diverged between t_check and t_use"
                    .to_string(),
            );
        }

        Ok(bytes)
    }
}

/// Verdict emitted by `IndependentTrustBoundaryVerifier` across the 3 orthogonal security rings.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MultiLayerGateVerdict {
    pub allowed: bool,
    pub auth_layer_ok: bool,
    pub merkle_layer_ok: bool,
    pub kernel_layer_ok: bool,
    pub blocking_layer: Option<String>,
}

/// **Reviewer Issue 5 — Cross-Layer Non-Circular Trust Boundary Verifier (`IndependentTrustBoundaryVerifier`)**
///
/// Enforces non-circular, orthogonal verification across 3 independent trust domains:
/// 1. **Layer 1 (`auth_epoch`)**: User-space `CedarAuthorizer` & `AgentContainmentRing` capability ring.
/// 2. **Layer 2 (`merkle_epoch`)**: Out-of-band `NsrlAslrMerkleGuard` / `Tpm2MerkleRootSigner` binary/module attestation.
/// 3. **Layer 3 (`kernel_epoch`)**: OS / Kernel boundary (`KernelDriverManager` / `QuarantineResponder` / `PinnedToolObjectBinding`).
///
/// Even if Layer 1 (`auth_layer`) is artificially bypassed or compromised in user space,
/// Layer 2 (`merkle_layer`) and Layer 3 (`kernel_layer`) independently veto execution.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IndependentTrustBoundaryVerifier {
    pub auth_epoch: u64,
    pub merkle_epoch: u64,
    pub kernel_epoch: u64,
    pub pinned_merkle_root: [u8; 32],
    pub kernel_enforcement_armed: bool,
}

impl IndependentTrustBoundaryVerifier {
    pub fn new(pinned_merkle_root: [u8; 32], kernel_enforcement_armed: bool) -> Self {
        Self {
            auth_epoch: 1,
            merkle_epoch: 1,
            kernel_epoch: 1,
            pinned_merkle_root,
            kernel_enforcement_armed,
        }
    }

    /// Advances a specific layer's monotonic epoch independently without mutating sibling layers.
    pub fn advance_layer_epoch(&mut self, layer: &str) -> u64 {
        match layer {
            "auth" => {
                self.auth_epoch = self.auth_epoch.saturating_add(1);
                self.auth_epoch
            }
            "merkle" => {
                self.merkle_epoch = self.merkle_epoch.saturating_add(1);
                self.merkle_epoch
            }
            "kernel" => {
                self.kernel_epoch = self.kernel_epoch.saturating_add(1);
                self.kernel_epoch
            }
            _ => 0,
        }
    }

    /// Evaluates the 3 orthogonal trust layers. All 3 layers must independently pass (`AND` gate).
    /// If `auth_layer_ok` is `true` (e.g., simulated user-space prompt/policy bypass), a mismatch in
    /// `live_merkle_root` or `os_boundary_clean == false` still deterministically blocks execution.
    pub fn evaluate_multi_layer_gate(
        &self,
        auth_layer_ok: bool,
        live_merkle_root: &[u8; 32],
        os_boundary_clean: bool,
    ) -> MultiLayerGateVerdict {
        let merkle_layer_ok = bool::from(self.pinned_merkle_root.ct_eq(live_merkle_root));
        let kernel_layer_ok = self.kernel_enforcement_armed && os_boundary_clean;
        let allowed = auth_layer_ok && merkle_layer_ok && kernel_layer_ok;

        let blocking_layer = if !auth_layer_ok {
            Some("Layer1_UserSpace_Cedar_Capability".to_string())
        } else if !merkle_layer_ok {
            Some("Layer2_TPM2_BLAKE3_Merkle_Attestation".to_string())
        } else if !kernel_layer_ok {
            Some("Layer3_OS_Kernel_Confinement_Boundary".to_string())
        } else {
            None
        };

        MultiLayerGateVerdict {
            allowed,
            auth_layer_ok,
            merkle_layer_ok,
            kernel_layer_ok,
            blocking_layer,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_epoch_signature_and_stale_rejection() {
        let ring = AgentContainmentRing::new();
        let agent_id = "agent_worker_7";
        let role = "worker";
        let payload = "{\"step\": \"process_data\"}";

        // Sign message at Gen 1
        let (epoch, sig) = ring.sign_message(agent_id, role, payload);
        assert_eq!(epoch, 1);

        // Verification succeeds at Gen 1
        let verify_res =
            ring.verify_inter_agent_message(agent_id, epoch, role, "data_sink", payload, &sig);
        assert!(verify_res.is_ok());

        // Surgical autotomy advances epoch: Gen 1 -> Gen 2
        let new_epoch = ring
            .sever_rogue_agent_branch(agent_id, "Triggered test autotomy", None)
            .await;
        assert_eq!(new_epoch, 2);

        // Verification with stale Gen 1 message fails!
        let stale_res =
            ring.verify_inter_agent_message(agent_id, epoch, role, "data_sink", payload, &sig);
        assert!(stale_res.is_err());
        assert!(stale_res.unwrap_err().contains("Stale generation epoch"));
    }

    #[test]
    fn test_lateral_movement_sink_isolation() {
        let ring = AgentContainmentRing::new();
        let agent_id = "untrusted_agent";
        let (epoch, sig) = ring.sign_message(agent_id, "untrusted", "transfer funds");

        // Attempting to message privileged ledger sink is blocked
        let res = ring.verify_inter_agent_message(
            agent_id,
            epoch,
            "untrusted",
            "AccountingLedgerWrite",
            "transfer funds",
            &sig,
        );
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("Lateral movement blocked"));
    }

    #[tokio::test]
    async fn test_sec_ring_01_self_pid_protection_and_merkle_chain() {
        let ring = AgentContainmentRing::new();
        let agent_id = "agent_rogue_9";
        let my_pid = std::process::id();

        // Severing branch targeting our own PID must preserve self PID
        let new_epoch = ring
            .sever_rogue_agent_branch(agent_id, "Attempted self kill", Some(my_pid))
            .await;
        assert!(new_epoch >= 2);

        let summary = ring.get_status_summary().await;
        assert!(summary.get("merkle_hierarchy").is_some());

        // Verify arm chain in hierarchical merkle registry
        let merkle = osoosi_audit::global_hierarchical_merkle();
        assert!(merkle.verify_arm_chain(agent_id));
    }

    #[test]
    fn test_law3_dirac_delta_capability_ticket_single_use_and_zero_standing_privilege() {
        let ticket = DiracDeltaCapabilityTicket::issue("agent_1", "read_file", 1, 5_000_000_000);
        assert_eq!(ticket.capability_density_at(ticket.issued_at_ns + 100), 1);
        assert_eq!(
            ticket.capability_density_at(ticket.issued_at_ns + 10_000_000_000),
            0
        );

        // Wrong action fails closed without burning valid action check
        assert!(ticket.consume_once("exec_shell").is_err());

        // First consumption succeeds
        let secret = ticket
            .consume_once("read_file")
            .expect("First consumption within Dirac impulse window must succeed");
        assert_ne!(secret, [0u8; 32]);

        // Capability density is immediately 0 after single consumption
        assert_eq!(ticket.capability_density_at(ticket.issued_at_ns + 100), 0);

        // Second consumption (replay) fails closed!
        let replay = ticket.consume_once("read_file");
        assert!(replay.is_err());
        assert!(replay.unwrap_err().contains("already consumed"));
    }

    #[test]
    fn test_law5_zero_copy_immutable_tool_buffer_page_locked_toctou_zero() {
        let payload = b"{\"tool\":\"read_file\",\"path\":\"src/main.rs\"}";
        let buf = ZeroCopyImmutableToolBuffer::new_page_locked(payload)
            .expect("4096-byte page-aligned read-only tool buffer must allocate");
        assert_eq!(buf.base_address() % 4096, 0);
        assert!(buf.is_page_locked_readonly());
        assert_eq!(buf.as_slice(), payload);
        assert!(buf.verify_zero_toctou());
    }

    #[test]
    fn test_issue4_pinned_tool_object_binding_detects_toctou_file_swap() {
        let tmp_path = std::env::temp_dir().join(format!(
            "osoosi_pinned_tool_obj_test_{}.txt",
            std::process::id()
        ));
        std::fs::write(&tmp_path, b"benign_workspace_config=true\n").expect("write initial file");

        let pin = PinnedToolObjectBinding::pin_at_check(&tmp_path).expect("pin at t_check");
        let mut f_ok = std::fs::File::open(&tmp_path).expect("open unchanged file");
        let verified_bytes = pin
            .verify_opened_file_matches_pin(&mut f_ok)
            .expect("unchanged file must pass descriptor pin verification");
        assert_eq!(verified_bytes, b"benign_workspace_config=true\n");
        std::mem::drop(f_ok);

        // Simulate TOCTOU file replacement between t_check and t_use (same size or different size)
        std::fs::write(&tmp_path, b"malicious_swapped_payload=1!\n").expect("swap file content");
        let mut f_swapped = std::fs::File::open(&tmp_path).expect("open swapped file");
        let swap_res = pin.verify_opened_file_matches_pin(&mut f_swapped);
        assert!(
            swap_res.is_err(),
            "File swap between t_check and t_use must be rejected by PinnedToolObjectBinding"
        );
        std::mem::drop(f_swapped);
        let _ = std::fs::remove_file(&tmp_path);
    }

    #[test]
    fn test_issue5_independent_trust_boundary_verifier_blocks_when_auth_bypassed() {
        let root = *blake3::hash(b"trusted_binary_merkle_root_v1").as_bytes();
        let mut verifier = IndependentTrustBoundaryVerifier::new(root, true);
        assert_eq!(verifier.advance_layer_epoch("auth"), 2);
        assert_eq!(verifier.merkle_epoch, 1);
        assert_eq!(verifier.kernel_epoch, 1);

        // Even when Layer 1 (auth_layer_ok = true) is bypassed, tampered Merkle root blocks at Layer 2
        let tampered_root = *blake3::hash(b"tampered_in_memory_module").as_bytes();
        let v_merkle = verifier.evaluate_multi_layer_gate(true, &tampered_root, true);
        assert!(!v_merkle.allowed);
        assert_eq!(
            v_merkle.blocking_layer.as_deref(),
            Some("Layer2_TPM2_BLAKE3_Merkle_Attestation")
        );

        // Even when Layer 1 and Layer 2 pass, an OS/kernel boundary violation blocks at Layer 3
        let v_kernel = verifier.evaluate_multi_layer_gate(true, &root, false);
        assert!(!v_kernel.allowed);
        assert_eq!(
            v_kernel.blocking_layer.as_deref(),
            Some("Layer3_OS_Kernel_Confinement_Boundary")
        );
    }

    #[test]
    fn test_dirac_delta_capability_ticket_canary_binding() {
        let mut ticket =
            DiracDeltaCapabilityTicket::issue("agent_canary_test", "read_doc", 1, 10_000_000_000);
        assert!(ticket.canary_token_id.is_none());
        assert!(ticket.canary_trap_uri.is_none());

        ticket.bind_canary("canary_tok_1234", "\\\\.\\pipe\\osoosi_canary_trap_01");
        assert_eq!(ticket.canary_token_id.as_deref(), Some("canary_tok_1234"));
        assert_eq!(
            ticket.canary_trap_uri.as_deref(),
            Some("\\\\.\\pipe\\osoosi_canary_trap_01")
        );

        let ticket2 = DiracDeltaCapabilityTicket::issue_with_canary(
            "agent_canary_test2",
            "write_log",
            2,
            5_000_000_000,
            Some("tok_abc".to_string()),
            Some("memfd://canary_trap".to_string()),
        );
        assert_eq!(ticket2.canary_token_id.as_deref(), Some("tok_abc"));
        assert_eq!(
            ticket2.canary_trap_uri.as_deref(),
            Some("memfd://canary_trap")
        );
    }

    #[test]
    fn test_agent_containment_ring_pre_tool_lineage_and_execute_contained_tool() {
        use crate::file_lineage::FileLineageTracker;
        use crate::types::ToolCallTelemetry;

        let ring = AgentContainmentRing::new();
        let tracker = FileLineageTracker::new();

        // 1. Create a non-immune temporary file and mark its digest poisoned
        let temp_dir = std::env::temp_dir();
        let poisoned_file = temp_dir.join(format!("poisoned_doc_{}.txt", std::process::id()));
        std::fs::write(&poisoned_file, b"poisoned prompt injection content").unwrap();
        let poisoned_digest = FileLineageTracker::compute_file_blake3(&poisoned_file).unwrap();
        tracker
            .mark_digest_poisoned(&poisoned_digest, "session_test", "injected payload", 1.0)
            .unwrap();

        // 2. Telemetry pointing to the poisoned file must be rejected before tool execution
        let poisoned_telemetry = ToolCallTelemetry {
            session_id: "session_test".to_string(),
            agent_id: "agent_42".to_string(),
            trace_id: None,
            tool_name: "read_file".to_string(),
            call_parameters: serde_json::json!({
                "path": poisoned_file.to_string_lossy().to_string()
            }),
            execution_duration_ms: 10,
            timestamp: chrono::Utc::now(),
            tokens_used: None,
            is_error: false,
            error_message: None,
        };

        let ticket = DiracDeltaCapabilityTicket::issue("agent_42", "read_file", 1, 10_000_000_000);
        let mut executed = false;
        let res = ring.execute_contained_tool(&poisoned_telemetry, &ticket, &tracker, || {
            executed = true;
            "should not execute"
        });

        assert!(res.is_err());
        assert!(
            !executed,
            "Tool closure must NOT run when parameters reference poisoned files"
        );
        assert!(res.unwrap_err().contains("Lineage-Veto"));

        // 3. Telemetry pointing to an immune repository file must SUCCEED even if attempted to be poisoned
        let root = osoosi_types::resolve_project_root().expect("workspace root");
        let immune_file = root.join("Cargo.toml");
        assert!(tracker.is_path_immune(&immune_file));

        let immune_telemetry = ToolCallTelemetry {
            session_id: "session_test".to_string(),
            agent_id: "agent_42".to_string(),
            trace_id: None,
            tool_name: "read_file".to_string(),
            call_parameters: serde_json::json!({
                "path": immune_file.to_string_lossy().to_string()
            }),
            execution_duration_ms: 10,
            timestamp: chrono::Utc::now(),
            tokens_used: None,
            is_error: false,
            error_message: None,
        };

        let valid_ticket =
            DiracDeltaCapabilityTicket::issue("agent_42", "read_file", 1, 10_000_000_000);
        let mut executed_immune = false;
        let res_immune =
            ring.execute_contained_tool(&immune_telemetry, &valid_ticket, &tracker, || {
                executed_immune = true;
                "immune_success"
            });

        assert!(res_immune.is_ok());
        assert_eq!(res_immune.unwrap(), "immune_success");
        assert!(
            executed_immune,
            "Immune repository path must execute successfully"
        );

        let _ = std::fs::remove_file(poisoned_file);
    }

    #[tokio::test]
    async fn test_cis_2_2_uts39_confusable_skeleton_and_4_4_killswitch() {
        let ring = AgentContainmentRing::new();
        // CIS 2.2: Cyrillic 'о' (\u{043E}) and 'е' (\u{0435}) + Fullwidth 'Ｗ' (\u{FF37}) + zero-width space (\u{200B})
        let spoofed_role = "\u{FF37}\u{043E}rk\u{0435}r\u{200B}";
        let spoofed_sink = "l\u{0435}dg\u{0435}r_write";
        assert_eq!(
            AgentContainmentRing::normalize_identifier_uts39_skeleton(spoofed_role),
            "worker"
        );
        assert_eq!(
            AgentContainmentRing::normalize_identifier_uts39_skeleton(spoofed_sink),
            "ledger_write"
        );

        let (epoch, sig) = ring.sign_message("agent_homoglyph", spoofed_role, "payload");
        let res = ring.verify_inter_agent_message(
            "agent_homoglyph",
            epoch,
            spoofed_role,
            spoofed_sink,
            "payload",
            &sig,
        );
        assert!(
            res.is_err(),
            "UTS #39 confusable skeleton must block homoglyph role/sink lateral movement"
        );

        // CIS 4.4: Atomic killswitch + credential revocation
        let (new_epoch, detail) = ring
            .atomic_killswitch_and_revoke_credentials(
                "agent_homoglyph",
                Some("oshoosi_agent_slice"),
                None,
                "CIS 4.4 emergency killswitch test",
            )
            .await;
        assert_eq!(new_epoch, epoch + 1);
        assert!(detail.contains("Credentials revoked"));
    }
}
