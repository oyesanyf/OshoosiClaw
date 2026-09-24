//! Self-Healing Mesh Heartbeat Gossip Reconciliation.
//!
//! Provides peer liveness tracking, missed-heartbeat detection, automatic partition recovery,
//! and state reconciliation across the P2P Gossipsub mesh.

use crate::MeshHeartbeat;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

/// Mesh peer liveness record tracked by the self-healing reconciliation engine.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PeerLiveness {
    pub peer_id: String,
    pub zone: String,
    pub last_seen: DateTime<Utc>,
    pub last_sequence: u64,
    pub missed_heartbeats: u32,
    pub is_healthy: bool,
    pub partition_detected: bool,
    pub uptime_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconciliationAction {
    pub peer_id: String,
    pub action: ReconciliationKind,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReconciliationKind {
    None,
    RedialPartition,
    CatchUpGossip,
    MarkRecovered,
}

/// Self-healing mesh reconciliation engine managing peer liveness and partition healing.
pub struct MeshReconciliationEngine {
    liveness_map: Arc<DashMap<String, PeerLiveness>>,
    heartbeat_interval: Duration,
    max_missed_heartbeats: u32,
}

impl Default for MeshReconciliationEngine {
    fn default() -> Self {
        Self::new(Duration::from_secs(15), 3)
    }
}

impl MeshReconciliationEngine {
    pub fn new(heartbeat_interval: Duration, max_missed_heartbeats: u32) -> Self {
        Self {
            liveness_map: Arc::new(DashMap::new()),
            heartbeat_interval,
            max_missed_heartbeats,
        }
    }

    /// Process an incoming heartbeat from a mesh peer.
    pub fn process_heartbeat(&self, hb: &MeshHeartbeat) -> ReconciliationAction {
        let now = Utc::now();
        let mut action = ReconciliationAction {
            peer_id: hb.peer_id.clone(),
            action: ReconciliationKind::None,
            reason: String::new(),
        };

        let mut entry = self.liveness_map.entry(hb.peer_id.clone()).or_insert_with(|| PeerLiveness {
            peer_id: hb.peer_id.clone(),
            zone: hb.zone.clone(),
            last_seen: now,
            last_sequence: hb.sequence,
            missed_heartbeats: 0,
            is_healthy: true,
            partition_detected: false,
            uptime_secs: hb.uptime_secs,
        });

        // Check if recovering from a detected partition
        if entry.partition_detected {
            info!("Self-healing: Peer {} recovered from partition! Triggering gossip reconciliation.", hb.peer_id);
            entry.partition_detected = false;
            entry.is_healthy = true;
            entry.missed_heartbeats = 0;
            action.action = ReconciliationKind::CatchUpGossip;
            action.reason = format!("Recovered from partition after sequence gap (new seq={})", hb.sequence);
        } else if hb.sequence > entry.last_sequence + 1 {
            // Sequence jump detected: missed intermediate heartbeats or network hiccup
            action.action = ReconciliationKind::CatchUpGossip;
            action.reason = format!("Sequence gap detected: expected {}, got {}", entry.last_sequence + 1, hb.sequence);
        }

        entry.last_seen = now;
        entry.last_sequence = hb.sequence;
        entry.missed_heartbeats = 0;
        entry.uptime_secs = hb.uptime_secs;
        entry.is_healthy = true;

        action
    }

    /// Periodic sweep to detect stale peers or network partitions and initiate self-healing recovery.
    pub fn reconcile_partitions(&self) -> Vec<ReconciliationAction> {
        let now = Utc::now();
        let mut actions = Vec::new();

        for mut entry in self.liveness_map.iter_mut() {
            let elapsed_secs = (now - entry.last_seen).num_seconds().max(0) as u64;
            let missed = (elapsed_secs / self.heartbeat_interval.as_secs().max(1)) as u32;

            if missed >= self.max_missed_heartbeats {
                entry.missed_heartbeats = missed;
                if !entry.partition_detected {
                    entry.partition_detected = true;
                    entry.is_healthy = false;
                    warn!("Self-healing: Network partition detected for peer {} (missed {} heartbeats, {}s silent)", entry.peer_id, missed, elapsed_secs);
                    actions.push(ReconciliationAction {
                        peer_id: entry.peer_id.clone(),
                        action: ReconciliationKind::RedialPartition,
                        reason: format!("Partition detected after {}s without heartbeat", elapsed_secs),
                    });
                }
            }
        }

        actions
    }

    pub fn peer_count(&self) -> usize {
        self.liveness_map.len()
    }

    pub fn healthy_peer_count(&self) -> usize {
        self.liveness_map.iter().filter(|p| p.is_healthy).count()
    }

    pub fn get_liveness(&self, peer_id: &str) -> Option<PeerLiveness> {
        self.liveness_map.get(peer_id).map(|e| e.clone())
    }

    pub fn all_peers(&self) -> Vec<PeerLiveness> {
        self.liveness_map.iter().map(|e| e.clone()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_heartbeat_normal_liveness_flow() {
        let engine = MeshReconciliationEngine::new(Duration::from_secs(5), 2);
        assert_eq!(engine.peer_count(), 0);

        let hb = MeshHeartbeat {
            peer_id: "peer-node-1".to_string(),
            zone: "prod-alpha".to_string(),
            sequence: 1,
            uptime_secs: 100,
            timestamp: Utc::now(),
        };

        let action = engine.process_heartbeat(&hb);
        assert_eq!(action.action, ReconciliationKind::None);
        assert_eq!(engine.peer_count(), 1);
        assert_eq!(engine.healthy_peer_count(), 1);

        let liveness = engine.get_liveness("peer-node-1").expect("must exist");
        assert_eq!(liveness.last_sequence, 1);
        assert_eq!(liveness.uptime_secs, 100);
        assert!(liveness.is_healthy);
    }

    #[test]
    fn test_heartbeat_sequence_jump_triggers_catch_up() {
        let engine = MeshReconciliationEngine::new(Duration::from_secs(5), 2);

        let hb1 = MeshHeartbeat {
            peer_id: "peer-node-2".to_string(),
            zone: "prod-alpha".to_string(),
            sequence: 1,
            uptime_secs: 100,
            timestamp: Utc::now(),
        };
        let act1 = engine.process_heartbeat(&hb1);
        assert_eq!(act1.action, ReconciliationKind::None);

        // Sequence jump: jumped from 1 to 5 (missed 2, 3, 4)
        let hb2 = MeshHeartbeat {
            peer_id: "peer-node-2".to_string(),
            zone: "prod-alpha".to_string(),
            sequence: 5,
            uptime_secs: 120,
            timestamp: Utc::now(),
        };
        let act2 = engine.process_heartbeat(&hb2);
        assert_eq!(act2.action, ReconciliationKind::CatchUpGossip);
        assert!(act2.reason.contains("Sequence gap detected"));
    }

    #[test]
    fn test_partition_detection_and_self_healing_recovery() {
        let engine = MeshReconciliationEngine::new(Duration::from_secs(1), 2);

        let hb = MeshHeartbeat {
            peer_id: "peer-node-3".to_string(),
            zone: "prod-alpha".to_string(),
            sequence: 1,
            uptime_secs: 50,
            timestamp: Utc::now() - chrono::Duration::seconds(5), // 5 seconds ago
        };

        let _ = engine.process_heartbeat(&hb);
        // Force the last_seen back in time to simulate missed heartbeats
        if let Some(mut entry) = engine.liveness_map.get_mut("peer-node-3") {
            entry.last_seen = Utc::now() - chrono::Duration::seconds(5);
        }

        let sweep_actions = engine.reconcile_partitions();
        assert_eq!(sweep_actions.len(), 1);
        assert_eq!(sweep_actions[0].action, ReconciliationKind::RedialPartition);
        assert_eq!(engine.healthy_peer_count(), 0);

        // Now peer recovers and sends new heartbeat
        let hb_recovery = MeshHeartbeat {
            peer_id: "peer-node-3".to_string(),
            zone: "prod-alpha".to_string(),
            sequence: 6,
            uptime_secs: 70,
            timestamp: Utc::now(),
        };

        let recovery_act = engine.process_heartbeat(&hb_recovery);
        assert_eq!(recovery_act.action, ReconciliationKind::CatchUpGossip);
        assert!(recovery_act.reason.contains("Recovered from partition"));
        assert_eq!(engine.healthy_peer_count(), 1);

        let liveness = engine.get_liveness("peer-node-3").unwrap();
        assert!(liveness.is_healthy);
        assert!(!liveness.partition_detected);
    }
}

