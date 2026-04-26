//! Patch file hash store for legitimacy verification.
//! Tracks SHA256 of known-good patch files so we can reject tampered or illegitimate patches.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

/// Single entry in the patch hash store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchHashEntry {
    pub component: String,
    pub version: String,
    pub sha256: String,
    pub source_url: Option<String>,
    pub recorded_at: String,
}

/// In-memory store with optional persistence to JSON.
#[derive(Debug)]
pub struct PatchHashStore {
    entries: RwLock<HashMap<String, PatchHashEntry>>,
    path: Option<PathBuf>,
}

impl PatchHashStore {
    /// Key: component + version.
    fn key(component: &str, version: &str) -> String {
        format!("{}|{}", component, version)
    }

    pub fn new(path: Option<PathBuf>) -> Self {
        let store = Self {
            entries: RwLock::new(HashMap::new()),
            path: path.clone(),
        };
        if let Some(ref p) = path {
            if p.exists() {
                let _ = store.load_from_disk(p);
            }
        }
        store
    }

    fn load_from_disk(&self, path: &Path) -> Result<()> {
        let content = std::fs::read_to_string(path)?;
        let entries: Vec<PatchHashEntry> = serde_json::from_str(&content)
            .map_err(|e| anyhow!("Failed to parse patch hash store: {}", e))?;
        let mut map = self
            .entries
            .write()
            .map_err(|e| anyhow!("Lock poisoned: {}", e))?;
        for e in entries {
            map.insert(Self::key(&e.component, &e.version), e);
        }
        Ok(())
    }

    fn save_to_disk(&self) -> Result<()> {
        if let Some(ref path) = self.path {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let entries: Vec<PatchHashEntry> = self
                .entries
                .read()
                .map_err(|e| anyhow!("Lock poisoned: {}", e))?
                .values()
                .cloned()
                .collect();
            let content = serde_json::to_string_pretty(&entries)?;
            std::fs::write(path, content)?;
        }
        Ok(())
    }

    /// Check if a patch file (by hash) is legitimate (i.e. in our known-good store or matches expected).
    pub fn is_legitimate(&self, component: &str, version: &str, sha256: &str) -> bool {
        let key = Self::key(component, version);
        if let Ok(guard) = self.entries.read() {
            if let Some(entry) = guard.get(&key) {
                return entry.sha256.eq_ignore_ascii_case(sha256);
            }
        }
        false
    }

    /// Record a patch file hash after successful apply (for future verification).
    pub fn record(
        &self,
        component: &str,
        version: &str,
        sha256: &str,
        source_url: Option<&str>,
    ) -> Result<()> {
        let key = Self::key(component, version);
        let entry = PatchHashEntry {
            component: component.to_string(),
            version: version.to_string(),
            sha256: sha256.to_lowercase(),
            source_url: source_url.map(|s| s.to_string()),
            recorded_at: chrono::Utc::now().to_rfc3339(),
        };
        {
            let mut guard = self
                .entries
                .write()
                .map_err(|e| anyhow!("Lock poisoned: {}", e))?;
            guard.insert(key, entry);
        }
        self.save_to_disk()
    }

    /// Get expected hash for this component+version if known.
    pub fn get_expected_hash(&self, component: &str, version: &str) -> Option<String> {
        let key = Self::key(component, version);
        self.entries
            .read()
            .ok()
            .and_then(|g| g.get(&key).map(|e| e.sha256.clone()))
    }
}

/// Compute SHA256 of bytes.
pub fn sha256_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}
