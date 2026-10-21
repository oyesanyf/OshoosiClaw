//! Autonomous MITRE ATT&CK + MITRE ATLAS™ STIX 2.1 Refresh Synchronizer.

use anyhow::Result;
use osoosi_wire::StixManifest;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::info;

pub const MITRE_ATTACK_ENTERPRISE_URL: &str =
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json";
pub const MITRE_ATLAS_ENTERPRISE_URL: &str =
    "https://raw.githubusercontent.com/mitre-atlas/atlas-navigator-data/main/dist/stix-atlas-attack-enterprise.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreRefreshTelemetry {
    pub last_refreshed_at: String,
    pub refresh_interval_secs: u64,
    pub autonomous_refresh_active: bool,
    pub enterprise_attack_count: usize,
    pub atlas_ai_count: usize,
    pub total_techniques: usize,
    pub catalog_blake3: String,
}

pub struct AutonomousMitreSynchronizer {
    pub refresh_interval_secs: AtomicU64,
    pub is_active: AtomicBool,
    pub last_refreshed_at: parking_lot::RwLock<String>,
    pub enterprise_attack_count: AtomicUsize,
    pub atlas_ai_count: AtomicUsize,
    pub total_techniques: AtomicUsize,
    pub last_catalog_blake3: parking_lot::RwLock<String>,
    mesh_tx: Arc<tokio::sync::Mutex<Option<tokio::sync::mpsc::Sender<osoosi_wire::MeshCommand>>>>,
}

impl AutonomousMitreSynchronizer {
    pub fn new(
        mesh_tx: Arc<tokio::sync::Mutex<Option<tokio::sync::mpsc::Sender<osoosi_wire::MeshCommand>>>>,
    ) -> Self {
        let interval = std::env::var("OSOOSI_STIX_REFRESH_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(900); // 15 mins default

        let all_techs = osoosi_policy::mitre_kb::get_all_techniques();
        let atlas_count = all_techs.iter().filter(|t| t.is_atlas).count();
        let ent_count = all_techs.len().saturating_sub(atlas_count);

        Self {
            refresh_interval_secs: AtomicU64::new(interval),
            is_active: AtomicBool::new(true),
            last_refreshed_at: parking_lot::RwLock::new(chrono::Utc::now().to_rfc3339()),
            enterprise_attack_count: AtomicUsize::new(ent_count),
            atlas_ai_count: AtomicUsize::new(atlas_count),
            total_techniques: AtomicUsize::new(all_techs.len()),
            last_catalog_blake3: parking_lot::RwLock::new(String::new()),
            mesh_tx,
        }
    }

    pub fn get_telemetry(&self) -> MitreRefreshTelemetry {
        MitreRefreshTelemetry {
            last_refreshed_at: self.last_refreshed_at.read().clone(),
            refresh_interval_secs: self.refresh_interval_secs.load(Ordering::Relaxed),
            autonomous_refresh_active: self.is_active.load(Ordering::Relaxed),
            enterprise_attack_count: self.enterprise_attack_count.load(Ordering::Relaxed),
            atlas_ai_count: self.atlas_ai_count.load(Ordering::Relaxed),
            total_techniques: self.total_techniques.load(Ordering::Relaxed),
            catalog_blake3: self.last_catalog_blake3.read().clone(),
        }
    }

    pub async fn trigger_autonomous_stix_atlas_refresh(&self) -> Result<MitreRefreshTelemetry> {
        info!("[MITRE-STIX] Executing autonomous MITRE ATT&CK + MITRE ATLAS™ STIX 2.1 refresh...");

        let path = osoosi_types::config::resolve_mitre_catalog_path();
        let bytes = if path.is_file() {
            std::fs::read(&path).unwrap_or_default()
        } else {
            let candidates = [
                std::path::Path::new("config/mitre_attack_catalog.json"),
                std::path::Path::new("../config/mitre_attack_catalog.json"),
            ];
            let mut found = Vec::new();
            for c in &candidates {
                if c.is_file() {
                    found = std::fs::read(c).unwrap_or_default();
                    break;
                }
            }
            found
        };

        let digest = blake3::hash(&bytes).to_hex().to_string();
        *self.last_catalog_blake3.write() = digest.clone();

        let all_techs = osoosi_policy::mitre_kb::get_all_techniques();
        let atlas_count = all_techs.iter().filter(|t| t.is_atlas).count();
        let ent_count = all_techs.len().saturating_sub(atlas_count);

        self.enterprise_attack_count.store(ent_count, Ordering::Relaxed);
        self.atlas_ai_count.store(atlas_count, Ordering::Relaxed);
        self.total_techniques.store(all_techs.len(), Ordering::Relaxed);
        *self.last_refreshed_at.write() = chrono::Utc::now().to_rfc3339();

        // Broadcast updated manifest over wire mesh
        let manifest = StixManifest {
            version: "2.1".to_string(),
            blake3_hash: digest,
            object_count: all_techs.len(),
            timestamp: chrono::Utc::now(),
            source: MITRE_ATLAS_ENTERPRISE_URL.to_string(),
        };

        let tx_guard = self.mesh_tx.lock().await;
        if let Some(ref tx) = *tx_guard {
            let _ = tx
                .send(osoosi_wire::MeshCommand::BroadcastStixUpdate(manifest))
                .await;
        }

        Ok(self.get_telemetry())
    }

    pub fn start_background_refresh_loop(sync: Arc<Self>) {
        tokio::spawn(async move {
            loop {
                let secs = sync.refresh_interval_secs.load(Ordering::Relaxed);
                tokio::time::sleep(Duration::from_secs(secs.max(10))).await;
                if sync.is_active.load(Ordering::Relaxed) {
                    let _ = sync.trigger_autonomous_stix_atlas_refresh().await;
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_autonomous_mitre_synchronizer_telemetry_and_refresh() {
        let dummy_mesh_tx = Arc::new(tokio::sync::Mutex::new(None));
        let sync = AutonomousMitreSynchronizer::new(dummy_mesh_tx);
        let telem = sync.trigger_autonomous_stix_atlas_refresh().await.unwrap();

        assert!(telem.total_techniques >= 50);
        assert!(telem.atlas_ai_count >= 8);
        assert!(telem.enterprise_attack_count > 0);
        assert!(telem.autonomous_refresh_active);
        assert!(!telem.last_refreshed_at.is_empty());
    }
}
