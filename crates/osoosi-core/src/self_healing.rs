use hex;
use osoosi_audit::AuditTrail;
use osoosi_memory::MemoryStore;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tracing::{info, warn};

pub struct SelfHealingEngine {
    audit: Arc<AuditTrail>,
    #[allow(dead_code)]
    memory: Arc<MemoryStore>,
}

impl SelfHealingEngine {
    pub fn new(audit: Arc<AuditTrail>, memory: Arc<MemoryStore>) -> Self {
        Self { audit, memory }
    }

    /// Rollback all changes associated with a specific threat/process
    pub async fn rollback_process_actions(&self, pid: u32) -> anyhow::Result<usize> {
        info!("Initiating Self-Healing Rollback for PID {}...", pid);
        let mut count = 0;

        // 1. Query the Merkle Trail for all events from this PID
        let entries = self.audit.entries();
        for entry in entries {
            if let Some(entry_pid) = entry.data.get("pid").and_then(|v| v.as_u64()) {
                if entry_pid as u32 == pid {
                    match entry.event_type.as_str() {
                        "FILE_CREATED" | "FILE_MODIFIED" => {
                            if let Some(path) = entry.data.get("path").and_then(|v| v.as_str()) {
                                if self.restore_file(path).await.is_ok() {
                                    count += 1;
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        info!("Self-Healing complete. Restored {} file(s).", count);
        Ok(count)
    }

    async fn restore_file(&self, path: &str) -> anyhow::Result<()> {
        let path_obj = std::path::Path::new(path);

        // 1. Try to find a backup (Oshoosi stores backups before modification in some paths)
        let backup_path = path_obj.with_extension("bak");
        if backup_path.exists() {
            let backup_bytes = std::fs::read(&backup_path)?;
            let actual_hash = hex::encode(Sha256::digest(&backup_bytes));

            // Priority 1: Query the immutable Merkle AuditTrail for authoritative expected hash
            let mut audit_hash = None;
            for entry in self.audit.entries().iter().rev() {
                if entry.data.get("path").and_then(|v| v.as_str()) == Some(path) {
                    if let Some(h) = entry
                        .data
                        .get("backup_sha256")
                        .or_else(|| entry.data.get("sha256"))
                        .or_else(|| entry.data.get("hash"))
                        .and_then(|v| v.as_str())
                    {
                        audit_hash = Some(h.to_string());
                        break;
                    }
                }
            }

            // Priority 2: Check adjacent hash file (secondary local fallback)
            let hash_file = path_obj.with_extension("bak.sha256");
            let file_hash = if hash_file.exists() {
                std::fs::read_to_string(&hash_file)
                    .ok()
                    .map(|content| content.trim().to_string())
                    .filter(|s| !s.is_empty())
            } else {
                None
            };

            // Enforce trust hierarchy: Merkle audit trail has absolute primacy.
            // If both exist and conflict, reject immediately as local forgery tampering.
            let expected_hash = match (audit_hash, file_hash) {
                (Some(a), Some(f)) => {
                    if !a.eq_ignore_ascii_case(&f) {
                        tracing::error!(
                            "Local hash file {:?} conflicts with immutable Merkle audit trail for {}: audit={}, file={}",
                            hash_file,
                            path,
                            a,
                            f
                        );
                        anyhow::bail!("Tampered hash file rejected: conflicts with audit trail");
                    }
                    Some(a)
                }
                (Some(a), None) => Some(a),
                (None, Some(f)) => Some(f),
                (None, None) => None,
            };

            // Fail closed: if neither audit trail nor local manifest has expected hash, reject restoration
            let expected = match expected_hash {
                Some(h) => h,
                None => {
                    tracing::error!(
                        "Restoration rejected for {}: no cryptographic SHA-256 hash available in audit trail or manifest",
                        path
                    );
                    anyhow::bail!("Cannot restore file: no expected SHA-256 hash available in audit trail or manifest");
                }
            };

            if !actual_hash.eq_ignore_ascii_case(&expected) {
                tracing::error!(
                    "Cryptographic hash mismatch for backup {}: expected {}, found {}",
                    backup_path.display(),
                    expected,
                    actual_hash
                );
                anyhow::bail!("Tampered backup rejected: hash mismatch");
            }

            warn!(
                "Restoring {} from verified local backup (SHA-256: {})...",
                path, actual_hash
            );
            std::fs::copy(&backup_path, path_obj)?;
            return Ok(());
        }

        // 2. Placeholder: Request clean baseline from mesh peers
        warn!(
            "No local backup for {}. Requesting clean baseline from mesh peers (TODO)...",
            path
        );

        anyhow::bail!("No backup file found for {}", path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_self_healing_restore_with_hash_verification() {
        let dir = tempdir().unwrap();
        let target_file = dir.path().join("config.sys");
        let backup_file = dir.path().join("config.bak");
        let hash_file = dir.path().join("config.bak.sha256");

        // Valid backup
        let original_data = b"trusted_baseline_content";
        std::fs::write(&backup_file, original_data).unwrap();
        let expected_hash = hex::encode(Sha256::digest(original_data));
        std::fs::write(&hash_file, &expected_hash).unwrap();

        let audit = Arc::new(AuditTrail::new());
        let memory = Arc::new(MemoryStore::new(":memory:").unwrap());
        let engine = SelfHealingEngine::new(audit, memory);

        let res = engine.restore_file(target_file.to_str().unwrap()).await;
        assert!(res.is_ok());
        assert_eq!(std::fs::read(&target_file).unwrap(), original_data);

        // Tampered backup
        std::fs::write(&backup_file, b"maliciously_tampered_content").unwrap();
        let bad_res = engine.restore_file(target_file.to_str().unwrap()).await;
        assert!(bad_res.is_err());
    }
}
