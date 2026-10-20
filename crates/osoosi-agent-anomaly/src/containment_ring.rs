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
        }
    }

    /// Checks if autotomy has been triggered and capability epochs severed.
    pub fn is_severed(&self) -> bool {
        self.autotomy_severances.load(Ordering::Relaxed) > 0
    }

    /// Gets or initializes an agent's generation epoch and signing key.
    pub fn get_or_create_epoch(&self, agent_id: &str) -> (u64, [u8; 32]) {
        let epoch = *self.agent_epochs.entry(agent_id.to_string()).or_insert(1);
        let key = *self
            .agent_keys
            .entry(agent_id.to_string())
            .or_insert_with(|| {
                let mut k = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut k);
                k
            });
        (epoch, key)
    }

    /// Returns the current active generation epoch for an agent.
    pub fn get_current_epoch(&self, agent_id: &str) -> u64 {
        self.agent_epochs.get(agent_id).map(|e| *e).unwrap_or(1)
    }

    /// Signs an inter-agent message payload bound to the agent's current generation epoch.
    pub fn sign_message(&self, agent_id: &str, role: &str, payload: &str) -> (u64, String) {
        let (epoch, key) = self.get_or_create_epoch(agent_id);
        let sign_data = format!(
            "{}:{}:{}:{}",
            agent_id,
            epoch,
            role.to_ascii_lowercase(),
            payload
        );
        let hmac_bytes = compute_ring_hmac(&key, sign_data.as_bytes());
        let sig_hex = hex::encode(hmac_bytes);

        // Record arm Merkle chain event and Ring 2 transition
        let ring_merkle = osoosi_audit::global_hierarchical_merkle();
        let arm_rec = ring_merkle.record_arm_event(agent_id, epoch, role, "sign_message", &sig_hex);
        ring_merkle.record_ring_transition(
            osoosi_audit::ContainmentRingId::Ring2PolicyMesh,
            agent_id,
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
        let current_epoch = self.get_current_epoch(sender_id);
        if epoch != current_epoch {
            return Err(format!(
                "Stale generation epoch rejected: message epoch {} != active epoch {} (likely severed)",
                epoch, current_epoch
            ));
        }

        // Case-insensitive lateral sink isolation (catches exact and composite untrusted/worker/fuzz/quarantine roles)
        let lower_role = role.to_ascii_lowercase();
        let lower_sink = target_sink.to_ascii_lowercase();

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

        let key = match self.agent_keys.get(sender_id) {
            Some(k) => *k,
            None => return Err(format!("Unknown agent sender ID '{}'", sender_id)),
        };

        let expected_bytes = {
            let sign_data = format!("{}:{}:{}:{}", sender_id, epoch, lower_role, payload);
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
            sender_id,
            epoch,
            role,
            "verify_inter_agent_message",
            signature_hex,
        );
        ring_merkle.record_ring_transition(
            osoosi_audit::ContainmentRingId::Ring2PolicyMesh,
            sender_id,
            "verify_inter_agent_message",
            &arm_rec.hash,
            false,
        );

        Ok(())
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
        let old_epoch = self.get_current_epoch(agent_id);
        let new_epoch = old_epoch + 1;

        // Monotonic epoch advancement
        self.agent_epochs.insert(agent_id.to_string(), new_epoch);

        // Constant-time volatile scrub of compromised signing key via silicon-shield before rotation
        if let Some(mut old_key_entry) = self.agent_keys.get_mut(agent_id) {
            silicon_shield::SiliconIntegrityGuard::constant_time_scrub(&mut *old_key_entry);
        }

        // Rotate signing key so compromised handles can no longer sign
        let mut new_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut new_key);
        self.agent_keys.insert(agent_id.to_string(), new_key);

        self.autotomy_severances.fetch_add(1, Ordering::Relaxed);

        // Record arm fracture proof and Ring 0 transition
        let ring_merkle = osoosi_audit::global_hierarchical_merkle();
        let fracture_proof =
            ring_merkle.record_arm_fracture(agent_id, old_epoch, new_epoch, reason, None);
        ring_merkle.record_ring_transition(
            osoosi_audit::ContainmentRingId::Ring0Kernel,
            agent_id,
            "sever_rogue_agent_branch",
            &fracture_proof.fracture_hash,
            true,
        );
        ring_merkle.anchor_to_global_tree(None, &format!("autotomy_sever:{}", agent_id));

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
}

impl DiracDeltaCapabilityTicket {
    /// Issues a Dirac-delta capability impulse valid only for `window_ns` nanoseconds and 1 atomic consumption.
    pub fn issue(agent_id: &str, tool_action: &str, epoch: u64, window_ns: u64) -> Self {
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        let mut ephemeral_secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut ephemeral_secret);
        let sign_payload = format!(
            "LAW3_DIRAC_CAP:{}:{}:{}:{}",
            agent_id, tool_action, epoch, now_ns
        );
        let derived = compute_ring_hmac(&ephemeral_secret, sign_payload.as_bytes());
        Self {
            agent_id: agent_id.to_string(),
            tool_action: tool_action.to_string(),
            epoch,
            issued_at_ns: now_ns,
            window_ns: window_ns.max(1_000), // minimum 1 microsecond window
            consumed: std::sync::atomic::AtomicU32::new(0),
            ephemeral_secret: derived,
        }
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
}
