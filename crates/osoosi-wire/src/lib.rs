//! P2P Knowledge Sharing (Gossip Protocol).
//!
//! Uses libp2p to disseminate threat intelligence across the mesh.

pub mod confidential;
pub mod ghost_node;
pub mod holograph;
pub mod join_gate;
pub mod mesh;
pub mod pqc;
pub mod reconciliation;
pub mod tarpit;

pub use confidential::*;
pub use ghost_node::*;
pub use join_gate::JoinGate;
pub use mesh::*;
pub use reconciliation::*;
pub use tarpit::*;

/// Gossipsub topic for self-healing mesh heartbeat gossip.
pub const HEARTBEAT_TOPIC: &str = "osoosi-heartbeat-v1";

/// Gossipsub topic for mesh-wide tarpitting signals.
pub const TARPIT_TOPIC: &str = "osoosi-tarpit-v1";

/// Gossipsub topic for FHE-encrypted IOCs and voting.
pub const CONFIDENTIAL_TOPIC: &str = "osoosi-confidential-v1";

/// Gossipsub topic for TPM 2.0 remote attestation challenge-response.
pub const ATTESTATION_TOPIC: &str = "osoosi-attestation-v1";

/// Mesh heartbeat payload for P2P peer liveness tracking and partition reconciliation.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq)]
pub struct MeshHeartbeat {
    pub peer_id: String,
    pub zone: String,
    pub sequence: u64,
    pub uptime_secs: u64,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Attestation exchange messages across the Gossip mesh.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub enum MeshAttestationMessage {
    Challenge {
        challenger_peer_id: String,
        target_peer_id: String,
        challenge: osoosi_types::AttestationChallenge,
    },
    Response {
        responder_peer_id: String,
        target_peer_id: String,
        response: osoosi_types::AttestationResponse,
    },
}

/// Commands sent to the mesh task.
#[derive(Debug)]
pub enum MeshCommand {
    ApprovePeer(libp2p::PeerId),
    QuarantinePeer(libp2p::PeerId),
    ReleasePeer(libp2p::PeerId),
    Broadcast(osoosi_types::ThreatSignature),
    BroadcastConsensus(osoosi_types::PolicyConsensusMessage),
    PublishPeerAnnounce(osoosi_types::PeerAnnounce),
    BroadcastGhostShard(osoosi_types::GhostShardData),
    BroadcastGlobalIntel(osoosi_types::GlobalIntelligence),
    /// Share malware sample for distributed EMBER-style classifier training.
    BroadcastMalwareSample(osoosi_types::MalwareSample),
    /// Broadcast threat with Differential Privacy (DP) noise.
    BroadcastNoisyThreat(osoosi_types::ThreatSignature, osoosi_dp::PrivacyConfig),
    /// Broadcast audit proof (Shadow Chain) for distributed log witnessing.
    BroadcastAuditProof(String),
    /// Active dial a discovered peer to bootstrap connection.
    DialPeer(libp2p::PeerId, String),
    /// Broadcast a Tarpit signal for collaborative attacker throttling.
    BroadcastTarpit(TarpitSignal),
    /// Broadcast an FHE-encrypted vote or IOC.
    BroadcastConfidential(ConfidentialMessage),
    /// Broadcast a Federated Model Delta for collaborative learning.
    BroadcastModelDelta(osoosi_types::FederatedModelDelta),
    /// Broadcast a Tripwire Alert from the Phantom Memory Flux tarpit.
    BroadcastTripwire(osoosi_types::MeshTripwireAlert),
    /// Broadcast an attestation challenge or response across the mesh.
    BroadcastAttestation(MeshAttestationMessage),
    /// Broadcast a witness / arbiter tie-breaker vote for 2-host stalemate resolution.
    BroadcastWitnessVote(osoosi_types::WitnessVote),
    /// Broadcast peer heartbeat across the mesh for self-healing gossip reconciliation.
    BroadcastHeartbeat(MeshHeartbeat),
    /// Trigger peer liveness reconciliation and partition recovery sweep.
    ReconcilePeers,
}

/// Collaborative attacker throttling signal for the Gossip mesh.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct TarpitSignal {
    pub target_ip: String,
    pub confidence: f32,
    pub attack_type: String, // e.g. "T1021.001 - Remote Desktop Protocol"
}
