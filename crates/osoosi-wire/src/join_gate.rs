//! Join Gate: User approval for agents joining the mesh based on reputation scores.

use super::MeshCommand;
use chrono::Utc;
use libp2p::PeerId;
use osoosi_memory::MemoryStore;
use osoosi_trust::TrustManager;
use osoosi_types::{
    tainted_value_for_peer, AttestationChallenge, AttestationError, AttestationResponse,
    GoldenBaseline, PeerAnnounce, PeerRulesConfig, PendingJoinRequest, QuarantinedPeer,
    ReputationScore, TaintSink,
};
use sha2::Digest;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{info, warn};

/// Gate that holds pending join requests and routes approvals to the mesh.
pub struct JoinGate {
    memory: Arc<MemoryStore>,
    command_tx: mpsc::Sender<MeshCommand>,
    /// Peers with reputation >= this are auto-approved. 1.0 = never auto-approve.
    min_reputation_auto_approve: f32,
    /// Peer rules: require_patched, require_supported_os, require_tpm_attestation.
    peer_rules: PeerRulesConfig,
    /// Public key of the Master Node (ed25519 hex).
    master_node_public_key: Option<String>,
    /// Rate-limiter for discovery processing (prevents beacon flooding)
    discovery_rate_limiter: Arc<dashmap::DashMap<String, chrono::DateTime<chrono::Utc>>>,
    /// TrustManager handle for hardware-anchored attestation verification
    trust_manager: Arc<std::sync::RwLock<Option<Arc<TrustManager>>>>,
    /// Golden Baseline policy for validating peer binary, config, and PCR profiles
    golden_baseline: Arc<std::sync::RwLock<Option<GoldenBaseline>>>,
    /// Active outgoing attestation challenges pending peer response (anti-replay)
    active_challenges: Arc<dashmap::DashMap<String, AttestationChallenge>>,
    /// Set of peer IDs that have successfully passed TPM 2.0 remote attestation
    verified_peers: Arc<dashmap::DashSet<String>>,
    /// Set of seen attestation nonces for broadcast announces (anti-replay)
    seen_announce_nonces: Arc<dashmap::DashSet<[u8; 32]>>,
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
            trust_manager: Arc::new(std::sync::RwLock::new(None)),
            golden_baseline: Arc::new(std::sync::RwLock::new(None)),
            active_challenges: Arc::new(dashmap::DashMap::new()),
            verified_peers: Arc::new(dashmap::DashSet::new()),
            seen_announce_nonces: Arc::new(dashmap::DashSet::new()),
        }
    }

    /// Called when a PeerAnnounce is received. Upserts to memory; removes from pending if peer fails rules.
    pub fn on_peer_announce_received(
        &self,
        announce: &PeerAnnounce,
        rules: &PeerRulesConfig,
    ) -> anyhow::Result<()> {
        if self.is_quarantined(&announce.source_node)? {
            warn!(
                "Ignoring announcement from quarantined peer {}",
                announce.source_node
            );
            return Ok(());
        }

        self.memory.upsert_peer_status(announce)?;

        // Master Node Verification
        if let Some(ref master_pk_hex) = self.master_node_public_key {
            let verified = self.verify_membership_proof(master_pk_hex, announce);

            if !verified {
                warn!(
                    "Peer {} failed Master Node authorization check!",
                    announce.source_node
                );
                self.memory.remove_pending_join(&announce.source_node).ok();
                return Ok(());
            }
        }

        // TPM 2.0 Attestation check in announce
        if let Some(ref att) = announce.attestation {
            // Anti-replay defense: detect replayed announcement nonces
            if !self.seen_announce_nonces.insert(att.challenge_nonce) {
                let reason = "Replayed announce attestation nonce detected";
                warn!("Peer {} quarantined: {}", announce.source_node, reason);
                self.quarantine_peer(&announce.source_node, reason)?;
                return Ok(());
            }

            // Freshness defense: check announcement timestamp age (max 300s TTL)
            let age = (Utc::now() - announce.timestamp).num_seconds();
            if age < 0 || age > 300 {
                let reason = "Expired announce attestation timestamp";
                warn!("Peer {} quarantined: {}", announce.source_node, reason);
                self.quarantine_peer(&announce.source_node, reason)?;
                return Ok(());
            }

            let challenge = AttestationChallenge {
                nonce: att.challenge_nonce,
                challenger_did: osoosi_types::NodeDID {
                    id: format!("did:osoosi:{}", announce.source_node),
                    public_key: att.responder_did.public_key.clone(),
                },
                timestamp: announce.timestamp,
                pcr_selection: att
                    .tpm_quote
                    .as_ref()
                    .map(|q| q.pcr_indices.clone())
                    .unwrap_or_else(|| vec![0, 7, 16]),
            };
            if let Err(e) = self.evaluate_attestation(&announce.source_node, &challenge, att) {
                warn!(
                    "Peer {} announced with invalid TPM attestation: {}. Peer quarantined.",
                    announce.source_node, e
                );
                return Ok(());
            }
        } else if rules.require_tpm_attestation {
            warn!(
                "Peer {} blocked: missing required TPM 2.0 remote attestation",
                announce.source_node
            );
            self.memory.remove_pending_join(&announce.source_node).ok();
            return Ok(());
        }

        let fails = (rules.require_patched && !announce.is_patched)
            || (rules.require_supported_os && !announce.os_supported);
        if fails {
            let reason = if !announce.is_patched {
                "unpatched"
            } else {
                "out-of-support OS"
            };
            if self
                .memory
                .get_pending_joins()?
                .iter()
                .any(|p| p.peer_id == announce.source_node)
            {
                self.memory.remove_pending_join(&announce.source_node)?;
                info!(
                    "Peer {} blocked from mesh: {}",
                    announce.source_node, reason
                );
            }
        }
        Ok(())
    }

    fn verify_membership_proof(
        &self,
        master_node_pk: &str,
        announce: &osoosi_types::PeerAnnounce,
    ) -> bool {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

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
        public_key
            .verify(announce.source_node.as_bytes(), &signature)
            .is_ok()
    }

    /// Called when mDNS discovers a new peer. Auto-approves if reputation >= threshold; otherwise adds to pending.
    /// Blocks immediately if we have peer status and it fails require_patched / require_supported_os.
    pub fn on_peer_discovered(
        &self,
        peer_id: PeerId,
        multiaddr: Option<String>,
    ) -> anyhow::Result<()> {
        let peer_id_str = peer_id.to_string();

        // Hardening: Discovery Rate-Limiting (Prevents flooding and UI saturation)
        if let Some(last_discovery) = self.discovery_rate_limiter.get(&peer_id_str) {
            if (Utc::now() - *last_discovery).num_minutes() < 5 {
                // Throttle: don't process discovery beacon for the same peer more than once every 5 minutes
                return Ok(());
            }
        }
        self.discovery_rate_limiter
            .insert(peer_id_str.clone(), Utc::now());
        if self.is_quarantined(&peer_id_str)? {
            warn!("Ignoring discovered peer {} (quarantined)", peer_id_str);
            return Ok(());
        }
        if let Some(status) = self.memory.get_peer_status(&peer_id_str)? {
            let fails = (self.peer_rules.require_patched && !status.is_patched)
                || (self.peer_rules.require_supported_os && !status.os_supported);
            if fails {
                let reason = if !status.is_patched {
                    "unpatched"
                } else {
                    "out-of-support OS"
                };
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

        // Autonomous: auto-approve when reputation meets threshold (and attestation verified if required)
        let attestation_ok =
            !self.peer_rules.require_tpm_attestation || self.is_attestation_verified(&peer_id_str);
        if score >= self.min_reputation_auto_approve
            && self.min_reputation_auto_approve < 1.0
            && attestation_ok
        {
            let tainted = tainted_value_for_peer(
                &req.peer_id,
                req.reputation_score,
                req.multiaddr.as_deref(),
            );
            let sink = TaintSink::mesh_join();
            if tainted.check_sink(&sink).is_ok() {
                if let Some(ref addr) = multiaddr {
                    let _ = self
                        .command_tx
                        .try_send(MeshCommand::DialPeer(peer_id, addr.clone()));
                }
                if self
                    .command_tx
                    .try_send(MeshCommand::ApprovePeer(peer_id))
                    .is_ok()
                {
                    info!(
                        "Auto-approved peer {} (reputation: {:.2} >= {:.2})",
                        peer_id_str, score, self.min_reputation_auto_approve
                    );
                    return Ok(());
                }
            }
        } else if let Some(ref addr) = multiaddr {
            // Only dial manually if not auto-approved (as auto-approval already dialed or it failed)
            let _ = self
                .command_tx
                .try_send(MeshCommand::DialPeer(peer_id, addr.clone()));
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
            return Err(anyhow::anyhow!(
                "Peer {} is quarantined and cannot be approved",
                peer_id
            ));
        }
        if self.peer_rules.require_tpm_attestation && !self.is_attestation_verified(peer_id) {
            return Err(anyhow::anyhow!(
                "Peer {} cannot join: TPM 2.0 remote attestation required but not verified",
                peer_id
            ));
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
                    peer_id,
                    reason,
                    self.peer_rules.require_patched,
                    self.peer_rules.require_supported_os
                ));
            }
        } else if self.peer_rules.require_patched || self.peer_rules.require_supported_os {
            return Err(anyhow::anyhow!(
                "Peer {} status unknown. Wait for peer to announce or disable peer_rules.",
                peer_id
            ));
        }
        let pending = self
            .memory
            .get_pending_joins()?
            .into_iter()
            .find(|p| p.peer_id == peer_id);
        let req =
            pending.ok_or_else(|| anyhow::anyhow!("Peer {} not in pending joins", peer_id))?;

        let tainted =
            tainted_value_for_peer(&req.peer_id, req.reputation_score, req.multiaddr.as_deref());
        let sink = TaintSink::mesh_join();
        if let Err(violation) = tainted.check_sink(&sink) {
            return Err(anyhow::anyhow!(
                "Taint violation during grant access: {} — peer not approved",
                violation
            ));
        }

        let pid = peer_id
            .parse::<PeerId>()
            .map_err(|e| anyhow::anyhow!("Invalid peer ID: {}", e))?;
        self.memory.remove_pending_join(peer_id)?;
        if self
            .command_tx
            .send(MeshCommand::ApprovePeer(pid))
            .await
            .is_err()
        {
            warn!(
                "Mesh may have shut down; approval for {} not delivered",
                peer_id
            );
        } else {
            info!(
                "User approved peer {} to join mesh (taint check passed)",
                peer_id
            );
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
    /// Drops reputation score to 0.0, ejects from routing, severs socket connectivity, and broadcasts a tripwire alert.
    pub fn quarantine_peer(&self, peer_id: &str, reason: &str) -> anyhow::Result<()> {
        self.verified_peers.remove(peer_id);
        let mut rep = self.memory.get_reputation(peer_id)?.unwrap_or(ReputationScore {
            node_id: peer_id.to_string(),
            score: 0.0,
            alerts_verified: 0,
            false_positives: 0,
            last_updated: Utc::now(),
        });
        rep.score = 0.0;
        rep.last_updated = Utc::now();
        self.memory.upsert_reputation(&rep)?;
        self.memory.quarantine_peer(peer_id, reason, 0.0)?;
        self.memory.remove_pending_join(peer_id).ok();

        if let Ok(pid) = peer_id.parse::<PeerId>() {
            let _ = self.command_tx.try_send(MeshCommand::QuarantinePeer(pid));
        }

        // Broadcast a tripwire alert across the Gossip mesh
        let alert = osoosi_types::MeshTripwireAlert {
            source_node_id: peer_id.to_string(),
            timestamp_utc: Utc::now().timestamp_millis(),
            trigger: osoosi_types::TarpitArtifact::GuardPageViolation {
                virtual_address: 0,
                access_type: format!("Attestation Quarantine: {}", reason),
            },
            offender: osoosi_types::OffendingProcess {
                pid: 0,
                name: format!("Peer-{}", peer_id),
                executable_path: "p2p://mesh/peer".to_string(),
                blake3_hash: hex::encode(blake3::hash(peer_id.as_bytes()).as_bytes()),
                command_line: Some(format!("Quarantine Reason: {}", reason)),
            },
            cryptographic_signature: Vec::new(),
            merkle_proof: None,
        };
        let _ = self.command_tx.try_send(MeshCommand::BroadcastTripwire(alert));

        warn!("Peer {} quarantined (reputation 0.0, severed, tripwire alert broadcast): {}", peer_id, reason);
        Ok(())
    }

    /// Release a quarantined peer so it may be rediscovered/approved again.
    pub fn release_peer(&self, peer_id: &str) -> anyhow::Result<()> {
        self.verified_peers.remove(peer_id);
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
            if self.is_quarantined(&req.peer_id)? {
                continue;
            }
            if self.peer_rules.require_tpm_attestation && !self.is_attestation_verified(&req.peer_id) {
                continue;
            }
            if req.reputation_score >= self.min_reputation_auto_approve
                && self.min_reputation_auto_approve < 1.0
            {
                if let Ok(pid) = req.peer_id.parse::<PeerId>() {
                    if self
                        .command_tx
                        .try_send(MeshCommand::ApprovePeer(pid))
                        .is_ok()
                    {
                        self.memory.remove_pending_join(&req.peer_id)?;
                        info!(
                            "Auto-approved backlog peer {} (reputation: {:.2} >= {:.2})",
                            req.peer_id, req.reputation_score, self.min_reputation_auto_approve
                        );
                    }
                }
            }
        }
        Ok(())
    }

    pub fn peer_rules(&self) -> &PeerRulesConfig {
        &self.peer_rules
    }

    pub fn is_attestation_verified(&self, peer_id: &str) -> bool {
        self.verified_peers.contains(peer_id)
    }

    pub fn mark_attestation_verified(&self, peer_id: &str) {
        self.verified_peers.insert(peer_id.to_string());
    }

    pub fn with_trust_manager(self, tm: Arc<TrustManager>) -> Self {
        *self.trust_manager.write().unwrap() = Some(tm);
        self
    }

    pub fn set_trust_manager(&self, tm: Arc<TrustManager>) {
        *self.trust_manager.write().unwrap() = Some(tm);
    }

    pub fn trust_manager(&self) -> Option<Arc<TrustManager>> {
        self.trust_manager.read().unwrap().clone()
    }

    pub fn with_golden_baseline(self, baseline: GoldenBaseline) -> Self {
        *self.golden_baseline.write().unwrap() = Some(baseline);
        self
    }

    pub fn set_golden_baseline(&self, baseline: GoldenBaseline) {
        *self.golden_baseline.write().unwrap() = Some(baseline);
    }

    pub fn golden_baseline(&self) -> Option<GoldenBaseline> {
        self.golden_baseline.read().unwrap().clone()
    }

    /// Create and record an active TPM 2.0 attestation challenge for a peer.
    pub fn create_attestation_challenge(
        &self,
        peer_id: &str,
        pcr_selection: Option<Vec<u32>>,
    ) -> AttestationChallenge {
        let challenger_did = self
            .trust_manager()
            .map(|tm| tm.did().clone())
            .unwrap_or_else(|| osoosi_types::NodeDID {
                id: "did:osoosi:local_challenger".to_string(),
                public_key: String::new(),
            });

        let pcrs = pcr_selection.unwrap_or_else(|| vec![0, 7, 16]);
        let challenge = AttestationChallenge::new(challenger_did, pcrs);
        self.active_challenges
            .insert(peer_id.to_string(), challenge.clone());
        challenge
    }

    /// Evaluate an attestation response from a peer against challenge and golden baseline.
    /// If attestation fails (PCR mismatch, corrupted binary hash, or invalid signature),
    /// automatically invoke `quarantine_peer(peer_id, ...)` to drop reputation to 0.0,
    /// eject the peer from routing, sever socket connectivity, and broadcast a tripwire alert.
    pub fn evaluate_attestation(
        &self,
        peer_id: &str,
        challenge: &AttestationChallenge,
        response: &AttestationResponse,
    ) -> Result<(), AttestationError> {
        let baseline = self.golden_baseline();
        let tm_opt = self.trust_manager();

        let verification_result = if let Some(ref tm) = tm_opt {
            tm.verify_attestation_with_policy(challenge, response, baseline.as_ref())
        } else {
            osoosi_trust::verify_attestation_with_policy(challenge, response, baseline.as_ref())
        };

        match verification_result {
            Ok(()) => {
                info!("Peer {} passed TPM 2.0 remote attestation", peer_id);
                self.mark_attestation_verified(peer_id);
                let data_hash = hex::encode(sha2::Sha256::digest(
                    format!("{}:{}", peer_id, hex::encode(challenge.nonce)).as_bytes(),
                ));
                osoosi_audit::tpm::extend_audit_to_tpm("peer_attestation_passed", &data_hash);
                Ok(())
            }
            Err(err) => {
                let reason = format!("Attestation failed: {}", err);
                warn!(
                    "Peer {} attestation failure ({}). Automatically initiating quarantine.",
                    peer_id, reason
                );
                self.verified_peers.remove(peer_id);
                let data_hash = hex::encode(sha2::Sha256::digest(
                    format!("{}:{}:{}", peer_id, hex::encode(challenge.nonce), err).as_bytes(),
                ));
                osoosi_audit::tpm::extend_audit_to_tpm("peer_attestation_failed", &data_hash);

                // Automatically quarantine peer (drop reputation to 0.0, sever socket, broadcast tripwire alert)
                if let Err(q_err) = self.quarantine_peer(peer_id, &reason) {
                    tracing::error!(
                        "Failed to quarantine peer {} after attestation failure: {}",
                        peer_id,
                        q_err
                    );
                }
                Err(err)
            }
        }
    }

    /// Verify an attestation response received for a pending challenge on the wire.
    pub fn handle_attestation_response(
        &self,
        peer_id: &str,
        response: &AttestationResponse,
    ) -> Result<(), AttestationError> {
        if self.is_quarantined(peer_id).unwrap_or(false) {
            warn!(
                "Rejecting attestation response from quarantined peer {}",
                peer_id
            );
            return Err(AttestationError::NonceReplayDetected);
        }

        let challenge = match self.active_challenges.remove(peer_id) {
            Some((_, ch)) => ch,
            None => {
                let reason = "Attestation response received without active challenge (replay risk)";
                warn!("Peer {} rejected: {}", peer_id, reason);
                let _ = self.quarantine_peer(peer_id, reason);
                return Err(AttestationError::NonceReplayDetected);
            }
        };

        self.evaluate_attestation(peer_id, &challenge, response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyExecutor;

    #[async_trait::async_trait]
    impl osoosi_types::SecuredExecutor for DummyExecutor {
        async fn execute(&self, _cmd: std::process::Command) -> anyhow::Result<std::process::Output> {
            Ok(std::process::Output {
                status: std::process::ExitStatus::default(),
                stdout: Vec::new(),
                stderr: Vec::new(),
            })
        }
        async fn download(&self, _url: &str, _dest: &std::path::Path, _resume: bool) -> anyhow::Result<()> {
            Ok(())
        }
    }

    fn test_gate_setup() -> (JoinGate, tokio::sync::mpsc::Receiver<MeshCommand>, Arc<MemoryStore>, Arc<TrustManager>) {
        let memory = Arc::new(MemoryStore::new(":memory:").unwrap());
        let (tx, rx) = tokio::sync::mpsc::channel(32);
        let rules = PeerRulesConfig {
            require_patched: true,
            require_supported_os: true,
            require_tpm_attestation: false,
        };
        let tm = Arc::new(TrustManager::new(Arc::new(DummyExecutor)).unwrap());
        let gate = JoinGate::new(memory.clone(), tx, 0.8, rules, None)
            .with_trust_manager(tm.clone());
        (gate, rx, memory, tm)
    }

    #[test]
    fn test_join_gate_attestation_success() {
        let (gate, _rx, memory, _challenger_tm) = test_gate_setup();
        let peer_tm = TrustManager::new(Arc::new(DummyExecutor)).unwrap();
        let peer_id = PeerId::random().to_string();

        let challenge = gate.create_attestation_challenge(&peer_id, None);
        let response = peer_tm.respond_to_attestation(challenge).unwrap();

        let res = gate.handle_attestation_response(&peer_id, &response);
        assert!(res.is_ok(), "Attestation should pass: {:?}", res);

        let quarantined = memory.is_peer_quarantined(&peer_id).unwrap();
        assert!(!quarantined, "Peer should not be quarantined on success");
    }

    #[test]
    fn test_join_gate_attestation_failure_quarantines_peer() {
        let (gate, mut rx, memory, _challenger_tm) = test_gate_setup();
        let mut peer_tm = TrustManager::new(Arc::new(DummyExecutor)).unwrap();
        let peer_id = PeerId::random().to_string();

        // Enforce Golden Baseline expecting specific binary hash
        let baseline = GoldenBaseline::new().allow_binary_hash("strict_golden_hash");
        gate.set_golden_baseline(baseline);

        peer_tm.set_local_binary_hash("rogue_modified_binary_hash".to_string());
        let challenge = gate.create_attestation_challenge(&peer_id, None);
        let response = peer_tm.respond_to_attestation(challenge).unwrap();

        let res = gate.handle_attestation_response(&peer_id, &response);
        assert!(res.is_err(), "Attestation should fail on binary hash mismatch");

        // Verify peer was automatically quarantined
        assert!(gate.is_quarantined(&peer_id).unwrap());
        let rep = memory.get_reputation(&peer_id).unwrap().unwrap();
        assert_eq!(rep.score, 0.0, "Reputation score must drop to 0.0 on quarantine");

        // Verify MeshCommand::QuarantinePeer and MeshCommand::BroadcastTripwire were dispatched
        let mut received_quarantine = false;
        let mut received_tripwire = false;
        while let Ok(cmd) = rx.try_recv() {
            match cmd {
                MeshCommand::QuarantinePeer(_) => received_quarantine = true,
                MeshCommand::BroadcastTripwire(_) => received_tripwire = true,
                _ => (),
            }
        }
        assert!(received_quarantine, "QuarantinePeer mesh command should be dispatched");
        assert!(received_tripwire, "BroadcastTripwire mesh command should be dispatched");
    }

    #[test]
    fn test_join_gate_peer_announce_with_corrupted_attestation() {
        let (gate, mut rx, memory, _challenger_tm) = test_gate_setup();
        let peer_tm = TrustManager::new(Arc::new(DummyExecutor)).unwrap();
        let peer_id = PeerId::random().to_string();

        let challenge = AttestationChallenge::new(peer_tm.did().clone(), vec![0, 7, 16]);
        let mut attestation = peer_tm.respond_to_attestation(challenge).unwrap();

        // Tamper with signature
        let mut sig_bytes = hex::decode(&attestation.signature).unwrap();
        sig_bytes[0] ^= 0x55;
        attestation.signature = hex::encode(sig_bytes);

        let announce = PeerAnnounce {
            source_node: peer_id.clone(),
            is_patched: true,
            os_name: "Windows".to_string(),
            os_version: "11".to_string(),
            os_supported: true,
            timestamp: Utc::now(),
            membership_proof: None,
            attestation: Some(attestation),
        };

        let rules = PeerRulesConfig::default();
        let _ = gate.on_peer_announce_received(&announce, &rules);

        // Verification must fail and trigger quarantine
        assert!(gate.is_quarantined(&peer_id).unwrap());
        let rep = memory.get_reputation(&peer_id).unwrap().unwrap();
        assert_eq!(rep.score, 0.0);

        let mut received_quarantine = false;
        while let Ok(cmd) = rx.try_recv() {
            if let MeshCommand::QuarantinePeer(_) = cmd {
                received_quarantine = true;
            }
        }
        assert!(received_quarantine);
    }

    #[tokio::test]
    async fn test_join_gate_require_tpm_attestation_blocks_unverified_allow() {
        let memory = Arc::new(MemoryStore::new(":memory:").unwrap());
        let (tx, _rx) = tokio::sync::mpsc::channel(32);
        let rules = PeerRulesConfig {
            require_patched: false,
            require_supported_os: false,
            require_tpm_attestation: true,
        };
        let tm = Arc::new(TrustManager::new(Arc::new(DummyExecutor)).unwrap());
        let gate = JoinGate::new(memory.clone(), tx, 0.8, rules, None)
            .with_trust_manager(tm.clone());

        let peer_tm = TrustManager::new(Arc::new(DummyExecutor)).unwrap();
        let peer_id = PeerId::random().to_string();

        let req = PendingJoinRequest {
            peer_id: peer_id.clone(),
            multiaddr: None,
            reputation_score: 0.5,
            alerts_verified: 0,
            false_positives: 0,
            discovered_at: Utc::now(),
        };
        memory.add_pending_join(&req).unwrap();

        // Approval must fail because TPM attestation has not been verified yet
        let res = gate.allow(&peer_id).await;
        assert!(res.is_err(), "Allow should fail when require_tpm_attestation is set and peer not verified");

        // Now run TPM attestation successfully
        let challenge = gate.create_attestation_challenge(&peer_id, None);
        let response = peer_tm.respond_to_attestation(challenge).unwrap();
        let att_res = gate.handle_attestation_response(&peer_id, &response);
        assert!(att_res.is_ok());
        assert!(gate.is_attestation_verified(&peer_id));

        // Now approval should succeed
        let allow_res = gate.allow(&peer_id).await;
        assert!(allow_res.is_ok(), "Allow must succeed once peer passes TPM attestation");
    }

    #[test]
    fn test_join_gate_peer_announce_replay_rejection() {
        let (gate, mut rx, memory, _challenger_tm) = test_gate_setup();
        let peer_tm = TrustManager::new(Arc::new(DummyExecutor)).unwrap();
        let peer_id = PeerId::random().to_string();

        let challenge = AttestationChallenge::new(peer_tm.did().clone(), vec![0, 7, 16]);
        let attestation = peer_tm.respond_to_attestation(challenge).unwrap();

        let announce = PeerAnnounce {
            source_node: peer_id.clone(),
            is_patched: true,
            os_name: "Windows".to_string(),
            os_version: "11".to_string(),
            os_supported: true,
            timestamp: Utc::now(),
            membership_proof: None,
            attestation: Some(attestation),
        };

        let rules = PeerRulesConfig::default();
        // First announce passes
        let res1 = gate.on_peer_announce_received(&announce, &rules);
        assert!(res1.is_ok());
        assert!(!gate.is_quarantined(&peer_id).unwrap());

        // Replaying the exact same announce must be detected as replay and trigger quarantine
        let res2 = gate.on_peer_announce_received(&announce, &rules);
        assert!(res2.is_ok());
        assert!(gate.is_quarantined(&peer_id).unwrap(), "Replayed announce must trigger peer quarantine");

        let rep = memory.get_reputation(&peer_id).unwrap().unwrap();
        assert_eq!(rep.score, 0.0);

        let mut received_quarantine = false;
        while let Ok(cmd) = rx.try_recv() {
            if let MeshCommand::QuarantinePeer(_) = cmd {
                received_quarantine = true;
            }
        }
        assert!(received_quarantine);
    }

    #[test]
    fn test_join_gate_expired_announce_quarantines_peer() {
        let (gate, mut rx, memory, _challenger_tm) = test_gate_setup();
        let peer_tm = TrustManager::new(Arc::new(DummyExecutor)).unwrap();
        let peer_id = PeerId::random().to_string();

        let challenge = AttestationChallenge::new(peer_tm.did().clone(), vec![0, 7, 16]);
        let attestation = peer_tm.respond_to_attestation(challenge).unwrap();

        // Expired announce timestamp (> 300s TTL)
        let stale_timestamp = Utc::now() - chrono::Duration::seconds(350);
        let announce = PeerAnnounce {
            source_node: peer_id.clone(),
            is_patched: true,
            os_name: "Windows".to_string(),
            os_version: "11".to_string(),
            os_supported: true,
            timestamp: stale_timestamp,
            membership_proof: None,
            attestation: Some(attestation),
        };

        let rules = PeerRulesConfig::default();
        let _ = gate.on_peer_announce_received(&announce, &rules);

        assert!(gate.is_quarantined(&peer_id).unwrap(), "Stale announce must trigger quarantine");
        let rep = memory.get_reputation(&peer_id).unwrap().unwrap();
        assert_eq!(rep.score, 0.0);

        let mut received_quarantine = false;
        while let Ok(cmd) = rx.try_recv() {
            if let MeshCommand::QuarantinePeer(_) = cmd {
                received_quarantine = true;
            }
        }
        assert!(received_quarantine);
    }

    #[test]
    fn test_join_gate_unsolicited_attestation_response_rejected() {
        let (gate, mut rx, memory, _challenger_tm) = test_gate_setup();
        let peer_tm = TrustManager::new(Arc::new(DummyExecutor)).unwrap();
        let peer_id = PeerId::random().to_string();

        let challenge = AttestationChallenge::new(peer_tm.did().clone(), vec![0, 7, 16]);
        let response = peer_tm.respond_to_attestation(challenge).unwrap();

        // No active challenge was created on this gate
        let res = gate.handle_attestation_response(&peer_id, &response);
        assert_eq!(res, Err(AttestationError::NonceReplayDetected));

        assert!(gate.is_quarantined(&peer_id).unwrap());
        let rep = memory.get_reputation(&peer_id).unwrap().unwrap();
        assert_eq!(rep.score, 0.0);

        let mut received_quarantine = false;
        while let Ok(cmd) = rx.try_recv() {
            if let MeshCommand::QuarantinePeer(_) = cmd {
                received_quarantine = true;
            }
        }
        assert!(received_quarantine);
    }

    #[tokio::test]
    async fn test_join_gate_cannot_allow_quarantined_peer() {
        let (gate, _rx, _memory, _tm) = test_gate_setup();
        let peer_id = PeerId::random().to_string();

        gate.quarantine_peer(&peer_id, "Hostile behavioral pattern").unwrap();
        assert!(gate.is_quarantined(&peer_id).unwrap());

        let res = gate.allow(&peer_id).await;
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("quarantined"));
    }

    #[test]
    fn test_join_gate_behavioral_penalties_cascade_to_quarantine() {
        let (gate, mut rx, memory, _tm) = test_gate_setup();
        let peer_id = PeerId::random().to_string();

        // Start with high reputation 0.9
        let rep = osoosi_types::ReputationScore {
            node_id: peer_id.clone(),
            score: 0.9,
            alerts_verified: 10,
            false_positives: 0,
            last_updated: Utc::now(),
        };
        memory.upsert_reputation(&rep).unwrap();

        // First penalty: 0.35 -> score becomes 0.55
        gate.penalize_peer(&peer_id, "Suspicious rapid egress", 0.35).unwrap();
        assert!(!gate.is_quarantined(&peer_id).unwrap());
        let rep1 = memory.get_reputation(&peer_id).unwrap().unwrap();
        assert!((rep1.score - 0.55).abs() < 1e-4);

        // Second penalty: 0.40 -> score becomes 0.15 <= 0.20 (quarantine threshold)
        gate.penalize_peer(&peer_id, "Poisoned gossip injection", 0.40).unwrap();
        assert!(gate.is_quarantined(&peer_id).unwrap());
        let rep2 = memory.get_reputation(&peer_id).unwrap().unwrap();
        assert_eq!(rep2.score, 0.0);

        let mut received_quarantine = false;
        let mut received_tripwire = false;
        while let Ok(cmd) = rx.try_recv() {
            match cmd {
                MeshCommand::QuarantinePeer(_) => received_quarantine = true,
                MeshCommand::BroadcastTripwire(_) => received_tripwire = true,
                _ => (),
            }
        }
        assert!(received_quarantine);
        assert!(received_tripwire);
    }
}

