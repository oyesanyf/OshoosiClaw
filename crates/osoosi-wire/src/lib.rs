//! P2P Knowledge Sharing (Gossip Protocol).
//!
//! Uses libp2p to disseminate threat intelligence across the mesh.

pub mod join_gate;
pub mod mesh;
pub mod holograph;
pub mod pqc;
pub mod tarpit;
pub mod confidential;
pub mod ghost_node;

pub use join_gate::JoinGate;
pub use mesh::*;
pub use tarpit::*;
pub use confidential::*;
pub use ghost_node::*;

/// Gossipsub topic for mesh-wide tarpitting signals.
pub const TARPIT_TOPIC: &str = "osoosi-tarpit-v1";

/// Gossipsub topic for FHE-encrypted IOCs and voting.
pub const CONFIDENTIAL_TOPIC: &str = "osoosi-confidential-v1";

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
}

/// Collaborative attacker throttling signal for the Gossip mesh.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct TarpitSignal {
    pub target_ip: String,
    pub confidence: f32,
    pub attack_type: String, // e.g. "T1021.001 - Remote Desktop Protocol"
}
