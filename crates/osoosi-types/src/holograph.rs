use serde::{Deserialize, Serialize};

/// Data for a "Holographic Shard" in the HDS algorithm.
/// Defines a deceptive response for a specific network slice.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhostShardData {
    pub attacker_ip: String,
    pub virtual_port: u16,
    pub deception_type: DeceptionType,
    pub shard_owner: String, // Node ID
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeceptionType {
    /// Mirror SSH protocol but fail always after 3 attempts
    SshDelay,
    /// Mirror HTTP but serve ghost-sharding files
    HttpLabyrinth,
    /// Fake Database responses
    DbSimulation,
    /// Random jitter and packet loss to signify "Network Congestion"
    NetworkNoise,
}
