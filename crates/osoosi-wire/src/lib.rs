//! P2P Knowledge Sharing (Gossip Protocol).
//!
//! Uses libp2p to disseminate threat intelligence across the mesh.

pub mod join_gate;
pub mod mesh;
pub mod holograph;
pub mod pqc;

pub use join_gate::JoinGate;
pub use mesh::*;

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
}
