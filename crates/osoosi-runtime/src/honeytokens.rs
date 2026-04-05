//! Environment-Keyed Honeytokens (HDS Traps).
//!
//! Deploys dynamic trap files that are uniquely keyed to the asset ID. 
//! Any access to these files triggers a high-confidence autonomy flag.

use std::path::{Path, PathBuf};
use tracing::info;
use std::fs;

pub struct HoneytokenManager {
    pub base_path: PathBuf,
    pub asset_id: String,
}

impl HoneytokenManager {
    pub fn new(base_path: PathBuf, asset_id: String) -> Self {
        Self { base_path, asset_id }
    }

    /// Deploy a deception honeytoken (e.g. 'backup_credentials.txt').
    /// The file content is keyed to the asset_id to track exfiltration.
    pub fn deploy_trap(&self, name: &str) -> anyhow::Result<PathBuf> {
        let trap_path = self.base_path.join(name);
        
        // Environment-keyed payload: Includes asset ID and a unique canary string.
        let payload = format!(
            "--- OSOOSI DECEPTION LAYER ---\n\
             AssetID: {}\n\
             Key: hds-traps-v1-{}\n\
             GeneratedAt: {}\n\n\
             DB_USER=osoosi_admin\n\
             DB_PASS={}\n",
            self.asset_id,
            uuid::Uuid::new_v4(),
            chrono::Utc::now(),
            format!("osoosi_{}", self.asset_id.chars().rev().collect::<String>())
        );

        fs::write(&trap_path, payload)?;
        info!("DECEPTION: Deployed honeytoken trap at {:?}", trap_path);
        
        Ok(trap_path)
    }

    /// Clean up deployed traps.
    pub fn cleanup_traps(&self) -> anyhow::Result<()> {
        if self.base_path.exists() {
             for entry in fs::read_dir(&self.base_path)? {
                 let entry = entry?;
                 let path = entry.path();
                 if path.is_file() {
                      let _ = fs::remove_file(path);
                 }
             }
        }
        Ok(())
    }
}

/// Verify if a file event is a 'trap hit'.
pub fn is_trap_hit(path: &Path, trap_locations: &[PathBuf]) -> bool {
    trap_locations.iter().any(|p| p == path)
}
