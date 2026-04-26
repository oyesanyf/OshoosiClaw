use osoosi_types::{DeceptionType, GhostShardData};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tracing::info;

/// Holographic Deception Sharding (HDS) Engine.
/// Manages virtual deception targets assigned to this node by the mesh.
pub struct HolographEngine {
    shards: Arc<RwLock<HashMap<String, Vec<GhostShardData>>>>, // Key: attacker_ip
    node_id: String,
}

impl HolographEngine {
    pub fn new(node_id: String) -> Self {
        Self {
            shards: Arc::new(RwLock::new(HashMap::new())),
            node_id,
        }
    }

    /// Add a shard assigned to this node.
    pub fn add_shard(&self, shard: GhostShardData) {
        if shard.shard_owner != self.node_id {
            return;
        }

        let mut guard = self.shards.write().unwrap();
        let attacker = shard.attacker_ip.clone();
        guard
            .entry(shard.attacker_ip.clone())
            .or_default()
            .push(shard);
        info!("HDS: Shard activated locally for attacker {}.", attacker);
    }

    /// Check if this node should "shimmer" (respond deceptively) to an incoming request.
    pub fn should_mirror(&self, attacker_ip: &str, port: u16) -> Option<DeceptionType> {
        let guard = self.shards.read().unwrap();
        if let Some(ip_shards) = guard.get(attacker_ip) {
            for shard in ip_shards {
                if shard.virtual_port == port {
                    return Some(shard.deception_type.clone());
                }
            }
        }
        None
    }

    /// The "Holographic Logic": distributed hash assignment.
    /// Determines which node is responsible for a specific deception slice.
    pub fn calculate_shard_assignment(
        attacker_ip: &str,
        port: u16,
        mesh_nodes: &[String],
    ) -> String {
        if mesh_nodes.is_empty() {
            return "self".to_string();
        }

        // Deterministic hash based on attacker identity and target port
        let seed = format!("{}:{}", attacker_ip, port);
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        use std::hash::{Hash, Hasher};
        seed.hash(&mut hasher);
        let hash = hasher.finish();

        let index = (hash % mesh_nodes.len() as u64) as usize;
        mesh_nodes[index].clone()
    }
}
