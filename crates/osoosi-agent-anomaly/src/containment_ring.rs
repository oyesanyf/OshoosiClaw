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
use subtle::ConstantTimeEq;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
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
        let key = *self.agent_keys.entry(agent_id.to_string()).or_insert_with(|| {
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
        let sign_data = format!("{}:{}:{}:{}", agent_id, epoch, role.to_ascii_lowercase(), payload);
        let hmac_bytes = compute_ring_hmac(&key, sign_data.as_bytes());
        (epoch, hex::encode(hmac_bytes))
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

        // Case-insensitive lateral sink isolation
        let lower_role = role.to_ascii_lowercase();
        let lower_sink = target_sink.to_ascii_lowercase();

        if (lower_role == "untrusted" || lower_role == "worker" || lower_role == "tainted")
            && (lower_sink.contains("ledger") || lower_sink.contains("policy") || lower_sink.contains("admin"))
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

        let provided_bytes = hex::decode(signature_hex)
            .map_err(|e| format!("Invalid hex signature: {}", e))?;

        if provided_bytes.len() != 32 {
            return Err("Invalid signature length".to_string());
        }

        // Constant-time comparison to prevent timing side-channel attacks
        let is_valid: bool = expected_bytes.ct_eq(&provided_bytes).into();
        if !is_valid {
            return Err("Cryptographic HMAC signature verification failed".to_string());
        }

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

        // Rotate signing key so compromised handles can no longer sign
        let mut new_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut new_key);
        self.agent_keys.insert(agent_id.to_string(), new_key);

        self.autotomy_severances.fetch_add(1, Ordering::Relaxed);

        // Optionally terminate confirmed rogue child process handle (never touch PID <= 4 or system)
        let action_taken = if let Some(pid) = target_child_pid {
            if pid > 4 {
                #[cfg(target_os = "windows")]
                {
                    let mut cmd = std::process::Command::new("taskkill");
                    cmd.args(["/F", "/T", "/PID", &pid.to_string()]);
                    #[cfg(windows)]
                    {
                        use std::os::windows::process::CommandExt;
                        cmd.creation_flags(0x08000000);
                    }
                    let res = cmd.status();
                    if res.map(|s| s.success()).unwrap_or(false) {
                        format!("Terminated rogue child PID {} & advanced epoch {} -> {}", pid, old_epoch, new_epoch)
                    } else {
                        format!("Advanced epoch {} -> {} (child PID {} could not be terminated)", old_epoch, new_epoch, pid)
                    }
                }
                #[cfg(not(target_os = "windows"))]
                {
                    unsafe {
                        libc::kill(pid as i32, libc::SIGKILL);
                    }
                    format!("Terminated rogue child PID {} & advanced epoch {} -> {}", pid, old_epoch, new_epoch)
                }
            } else {
                format!("Advanced epoch {} -> {} (system PID {} protected)", old_epoch, new_epoch, pid)
            }
        } else {
            format!("Advanced epoch {} -> {} (capabilities severed)", old_epoch, new_epoch)
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
        self.mesh_watchout_broadcasts.fetch_add(1, Ordering::Relaxed);
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
        })
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
        let verify_res = ring.verify_inter_agent_message(agent_id, epoch, role, "data_sink", payload, &sig);
        assert!(verify_res.is_ok());

        // Surgical autotomy advances epoch: Gen 1 -> Gen 2
        let new_epoch = ring.sever_rogue_agent_branch(agent_id, "Triggered test autotomy", None).await;
        assert_eq!(new_epoch, 2);

        // Verification with stale Gen 1 message fails!
        let stale_res = ring.verify_inter_agent_message(agent_id, epoch, role, "data_sink", payload, &sig);
        assert!(stale_res.is_err());
        assert!(stale_res.unwrap_err().contains("Stale generation epoch"));
    }

    #[test]
    fn test_lateral_movement_sink_isolation() {
        let ring = AgentContainmentRing::new();
        let agent_id = "untrusted_agent";
        let (epoch, sig) = ring.sign_message(agent_id, "untrusted", "transfer funds");

        // Attempting to message privileged ledger sink is blocked
        let res = ring.verify_inter_agent_message(agent_id, epoch, "untrusted", "AccountingLedgerWrite", "transfer funds", &sig);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("Lateral movement blocked"));
    }
}
