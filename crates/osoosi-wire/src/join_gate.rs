//! Join Gate: User approval for agents joining the mesh based on reputation scores.

use super::MeshCommand;
use libp2p::PeerId;
use osoosi_memory::MemoryStore;
use osoosi_types::{PendingJoinRequest, QuarantinedPeer, ReputationScore, tainted_value_for_peer, TaintSink, PeerAnnounce, PeerRulesConfig};
use chrono::Utc;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{info, warn};

/// Gate that holds pending join requests and routes approvals to the mesh.
pub struct JoinGate {
    memory: Arc<MemoryStore>,
    command_tx: mpsc::Sender<MeshCommand>,
    /// Peers with reputation >= this are auto-approved. 1.0 = never auto-approve.
    min_reputation_auto_approve: f32,
    /// Peer rules: require_patched, require_supported_os.
    peer_rules: PeerRulesConfig,
    /// Public key of the Master Node (ed25519 hex).
    master_node_public_key: Option<String>,
    /// Rate-limiter for discovery processing (prevents beacon flooding)
    discovery_rate_limiter: Arc<dashmap::DashMap<String, chrono::DateTime<chrono::Utc>>>,
}

impl JoinGate {
    const QUARANTINE_THRESHOLD: f32 = 0.20;

    /// Create a new JoinGate. `command_tx` is used to send approval commands to the mesh.
    /// `min_reputation_auto_approve`: peers with score >= this are auto-approved; 1.0 = require manual approval.
    pub fn new(
        memory: Arc<MemoryStore>,
        command_tx: mpsc::Sender<MeshCommand>,
        min_reputation_auto_approve: f32,
        peer_rules: PeerRulesConfig,
        master_node_public_key: Option<String>,
    ) -> Self {
        Self {
            memory,
            command_tx,
            min_reputation_auto_approve,
            peer_rules,
            master_node_public_key,
            discovery_rate_limiter: Arc::new(dashmap::DashMap::new()),
        }
    }

    /// Called when a PeerAnnounce is received. Upserts to memory; removes from pending if peer fails rules.
    pub fn on_peer_announce_received(&self, announce: &PeerAnnounce, rules: &PeerRulesConfig) -> anyhow::Result<()> {
        self.memory.upsert_peer_status(announce)?;

        // Master Node Verification
        if let Some(ref master_pk_hex) = self.master_node_public_key {
            let verified = self.verify_membership_proof(master_pk_hex, announce);
            
            if !verified {
                warn!("Peer {} failed Master Node authorization check!", announce.source_node);
                self.memory.remove_pending_join(&announce.source_node).ok();
                return Ok(());
            }
        }

        let fails = (rules.require_patched && !announce.is_patched)
            || (rules.require_supported_os && !announce.os_supported);
        if fails {
            let reason = if !announce.is_patched { "unpatched" } else { "out-of-support OS" };
            if self.memory.get_pending_joins()?.iter().any(|p| p.peer_id == announce.source_node) {
                self.memory.remove_pending_join(&announce.source_node)?;
                info!("Peer {} blocked from mesh: {}", announce.source_node, reason);
            }
        }
        Ok(())
    }

    fn verify_membership_proof(&self, master_node_pk: &str, announce: &osoosi_types::PeerAnnounce) -> bool {
        use ed25519_dalek::{VerifyingKey, Signature, Verifier};
        
        let proof_hex = match &announce.membership_proof {
            Some(p) => p,
            None => return false,
        };

        let pk_bytes = match hex::decode(master_node_pk) {
            Ok(b) => b,
            Err(_) => return false,
        };

        let public_key: VerifyingKey = match VerifyingKey::try_from(pk_bytes.as_slice()) {
            Ok(pk) => pk,
            Err(_) => return false,
        };

        let proof_bytes = match hex::decode(proof_hex) {
            Ok(b) => b,
            Err(_) => return false,
        };

        let signature = match Signature::from_slice(&proof_bytes) {
            Ok(s) => s,
            Err(_) => return false,
        };

        // Verification: Sign the PeerID
        public_key.verify(announce.source_node.as_bytes(), &signature).is_ok()
    }

    /// Called when mDNS discovers a new peer. Auto-approves if reputation >= threshold; otherwise adds to pending.
    /// Blocks immediately if we have peer status and it fails require_patched / require_supported_os.
    pub fn on_peer_discovered(&self, peer_id: PeerId, multiaddr: Option<String>) -> anyhow::Result<()> {
        let peer_id_str = peer_id.to_string();

        // Hardening: Discovery Rate-Limiting (Prevents flooding and UI saturation)
        if let Some(last_discovery) = self.discovery_rate_limiter.get(&peer_id_str) {
            if (Utc::now() - *last_discovery).num_minutes() < 5 {
                // Throttle: don't process discovery beacon for the same peer more than once every 5 minutes
                return Ok(());
            }
        }
        self.discovery_rate_limiter.insert(peer_id_str.clone(), Utc::now());
        if self.is_quarantined(&peer_id_str)? {
            warn!("Ignoring discovered peer {} (quarantined)", peer_id_str);
            return Ok(());
        }
        if let Some(status) = self.memory.get_peer_status(&peer_id_str)? {
            let fails = (self.peer_rules.require_patched && !status.is_patched)
                || (self.peer_rules.require_supported_os && !status.os_supported);
            if fails {
                let reason = if !status.is_patched { "unpatched" } else { "out-of-support OS" };
                warn!("Peer {} blocked from mesh: {}", peer_id_str, reason);
                return Ok(());
            }
        }
        let rep = self.memory.get_reputation(&peer_id_str)?;
        let (score, alerts_verified, false_positives) = rep
            .as_ref()
            .map(|r| (r.score, r.alerts_verified, r.false_positives))
            .unwrap_or((0.5, 0, 0)); // Unknown peer: neutral 0.5

        let req = PendingJoinRequest {
            peer_id: peer_id_str.clone(),
            multiaddr: multiaddr.clone(),
            reputation_score: score,
            alerts_verified,
            false_positives,
            discovered_at: Utc::now(),
        };

        // Autonomous: auto-approve when reputation meets threshold
        if score >= self.min_reputation_auto_approve && self.min_reputation_auto_approve < 1.0 {
            let tainted = tainted_value_for_peer(&req.peer_id, req.reputation_score, req.multiaddr.as_deref());
            let sink = TaintSink::mesh_join();
            if tainted.check_sink(&sink).is_ok() {
                if let Some(ref addr) = multiaddr {
                    let _ = self.command_tx.try_send(MeshCommand::DialPeer(peer_id, addr.clone()));
                }
                if self.command_tx.try_send(MeshCommand::ApprovePeer(peer_id)).is_ok() {
                    info!("Auto-approved peer {} (reputation: {:.2} >= {:.2})", peer_id_str, score, self.min_reputation_auto_approve);
                    return Ok(());
                }
            }
        }

        if let Some(ref addr) = multiaddr {
            let _ = self.command_tx.try_send(MeshCommand::DialPeer(peer_id, addr.clone()));
        }
        
        self.memory.add_pending_join(&req)?;
        info!(
            "Peer {} awaiting user approval (reputation: {:.2})",
            peer_id_str, score
        );
        Ok(())
    }

    /// User approved this peer. Taint check runs during grant access; if pass, adds to mesh and removes from pending.
    pub async fn allow(&self, peer_id: &str) -> anyhow::Result<()> {
        if self.is_quarantined(peer_id)? {
            return Err(anyhow::anyhow!("Peer {} is quarantined and cannot be approved", peer_id));
        }
        if let Some(status) = self.memory.get_peer_status(peer_id)? {
            let fails = (self.peer_rules.require_patched && !status.is_patched)
                || (self.peer_rules.require_supported_os && !status.os_supported);
            if fails {
                let reason = if !status.is_patched {
                    "has pending security patches"
                } else {
                    "runs out-of-support OS"
                };
                return Err(anyhow::anyhow!(
                    "Peer {} cannot join: {} (require_patched={}, require_supported_os={})",
                    peer_id, reason, self.peer_rules.require_patched, self.peer_rules.require_supported_os
                ));
            }
        } else if self.peer_rules.require_patched || self.peer_rules.require_supported_os {
            return Err(anyhow::anyhow!(
                "Peer {} status unknown. Wait for peer to announce or disable peer_rules.",
                peer_id
            ));
        }
        let pending = self.memory.get_pending_joins()?
            .into_iter()
            .find(|p| p.peer_id == peer_id);
        let req = pending.ok_or_else(|| anyhow::anyhow!("Peer {} not in pending joins", peer_id))?;

        let tainted = tainted_value_for_peer(
            &req.peer_id,
            req.reputation_score,
            req.multiaddr.as_deref(),
        );
        let sink = TaintSink::mesh_join();
        if let Err(violation) = tainted.check_sink(&sink) {
            return Err(anyhow::anyhow!(
                "Taint violation during grant access: {} — peer not approved",
                violation
            ));
        }

        let pid = peer_id.parse::<PeerId>().map_err(|e| anyhow::anyhow!("Invalid peer ID: {}", e))?;
        self.memory.remove_pending_join(peer_id)?;
        if self.command_tx.send(MeshCommand::ApprovePeer(pid)).await.is_err() {
            warn!("Mesh may have shut down; approval for {} not delivered", peer_id);
        } else {
            info!("User approved peer {} to join mesh (taint check passed)", peer_id);
        }
        Ok(())
    }

    /// User denied this peer. Removes from pending.
    pub fn deny(&self, peer_id: &str) -> anyhow::Result<()> {
        self.memory.remove_pending_join(peer_id)?;
        info!("User denied peer {} from joining mesh", peer_id);
        Ok(())
    }

    /// Quarantine a peer immediately and remove it from active mesh participation.
    pub fn quarantine_peer(&self, peer_id: &str, reason: &str) -> anyhow::Result<()> {
        let rep = self.memory.get_reputation(peer_id)?;
        let score = rep.as_ref().map(|r| r.score).unwrap_or(0.0);
        self.memory.quarantine_peer(peer_id, reason, score)?;
        self.memory.remove_pending_join(peer_id).ok();

        if let Ok(pid) = peer_id.parse::<PeerId>() {
            let _ = self.command_tx.try_send(MeshCommand::QuarantinePeer(pid));
        }
        warn!("Peer {} quarantined: {}", peer_id, reason);
        Ok(())
    }

    /// Release a quarantined peer so it may be rediscovered/approved again.
    pub fn release_peer(&self, peer_id: &str) -> anyhow::Result<()> {
        self.memory.release_quarantined_peer(peer_id)?;
        if let Ok(pid) = peer_id.parse::<PeerId>() {
            let _ = self.command_tx.try_send(MeshCommand::ReleasePeer(pid));
        }
        info!("Peer {} released from quarantine", peer_id);
        Ok(())
    }

    /// Mark a quarantine as false positive: release peer and restore trust score.
    pub fn mark_false_positive(&self, peer_id: &str) -> anyhow::Result<()> {
        self.release_peer(peer_id)?;
        let current = self.memory.get_reputation(peer_id)?;
        let mut rep = current.unwrap_or(ReputationScore {
            node_id: peer_id.to_string(),
            score: 0.5,
            alerts_verified: 0,
            false_positives: 0,
            last_updated: Utc::now(),
        });
        rep.score = (rep.score + 0.35).min(1.0);
        rep.alerts_verified = rep.alerts_verified.saturating_add(1);
        rep.last_updated = Utc::now();
        self.memory.upsert_reputation(&rep)?;
        info!(
            "Peer {} quarantine marked false positive; score restored to {:.2}",
            peer_id, rep.score
        );
        Ok(())
    }

    /// Penalize suspicious behavior. Can auto-quarantine when score drops under threshold.
    pub fn penalize_peer(&self, peer_id: &str, reason: &str, penalty: f32) -> anyhow::Result<()> {
        let current = self.memory.get_reputation(peer_id)?;
        let mut rep = current.unwrap_or(ReputationScore {
            node_id: peer_id.to_string(),
            score: 0.5,
            alerts_verified: 0,
            false_positives: 0,
            last_updated: Utc::now(),
        });
        rep.score = (rep.score - penalty).max(0.0);
        rep.false_positives = rep.false_positives.saturating_add(1);
        rep.last_updated = Utc::now();
        self.memory.upsert_reputation(&rep)?;

        if rep.score <= Self::QUARANTINE_THRESHOLD {
            self.quarantine_peer(peer_id, reason)?;
        } else {
            warn!(
                "Peer {} penalized (reason: {}, score: {:.2})",
                peer_id, reason, rep.score
            );
        }
        Ok(())
    }

    pub fn is_quarantined(&self, peer_id: &str) -> anyhow::Result<bool> {
        self.memory.is_peer_quarantined(peer_id)
    }

    pub fn quarantined_peers(&self) -> anyhow::Result<Vec<QuarantinedPeer>> {
        self.memory.get_quarantined_peers()
    }

    /// Get all pending join requests (for dashboard API).
    pub fn pending_joins(&self) -> anyhow::Result<Vec<PendingJoinRequest>> {
        self.memory.get_pending_joins()
    }

    /// Automatically approve any pending joins that now meet the reputation threshold.
    /// Useful on startup or after reputation updates.
    pub fn auto_approve_backlog(&self) -> anyhow::Result<()> {
        let pending = self.memory.get_pending_joins()?;
        for req in pending {
            if req.reputation_score >= self.min_reputation_auto_approve && self.min_reputation_auto_approve < 1.0 {
                if let Ok(pid) = req.peer_id.parse::<PeerId>() {
                    if self.command_tx.try_send(MeshCommand::ApprovePeer(pid)).is_ok() {
                        self.memory.remove_pending_join(&req.peer_id)?;
                        info!("Auto-approved backlog peer {} (reputation: {:.2} >= {:.2})", req.peer_id, req.reputation_score, self.min_reputation_auto_approve);
                    }
                }
            }
        }
        Ok(())
    }
}
