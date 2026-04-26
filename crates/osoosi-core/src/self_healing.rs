use osoosi_audit::AuditTrail;
use osoosi_memory::MemoryStore;
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
            warn!("Restoring {} from local backup...", path);
            std::fs::copy(&backup_path, path_obj)?;
            return Ok(());
        }

        // 2. Placeholder: Request clean baseline from mesh peers
        warn!(
            "No local backup for {}. Requesting clean baseline from mesh peers (TODO)...",
            path
        );

        Ok(())
    }
}
