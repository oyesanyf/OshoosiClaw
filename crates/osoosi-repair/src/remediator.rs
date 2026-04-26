//! Standalone File Remediator
//!
//! Downloads and replaces specific vulnerable files found on disk
//! based on CVE remediation URLs.

use anyhow::{anyhow, Result};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{error, info, warn};

#[cfg(target_os = "windows")]
use std::os::windows::ffi::OsStrExt;
#[cfg(target_os = "windows")]
use winapi::um::winbase::{MoveFileExW, MOVEFILE_DELAY_UNTIL_REBOOT, MOVEFILE_REPLACE_EXISTING};

pub struct StandaloneRemediator {
    client: reqwest::Client,
}

impl Default for StandaloneRemediator {
    fn default() -> Self {
        Self::new()
    }
}

impl StandaloneRemediator {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(60))
                .user_agent("Osoosi-Remediator/0.1")
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
        }
    }

    /// Download a file and replace the target path atomically.
    /// Returns the backup path of the original file.
    pub async fn remediate_file(&self, target_path: &str, download_url: &str) -> Result<PathBuf> {
        info!(
            "Remediating standalone file: {} via {}",
            target_path, download_url
        );

        let target = Path::new(target_path);
        if !target.exists() {
            return Err(anyhow!(
                "Target file for remediation does not exist: {}",
                target_path
            ));
        }

        // 1. Download to memory first to ensure it's valid
        let response = self.client.get(download_url).send().await?;
        if !response.status().is_success() {
            return Err(anyhow!(
                "Failed to download remediation file from {}: {}",
                download_url,
                response.status()
            ));
        }
        let data = response.bytes().await?;

        // 2. Create backup of original
        let backup_path = self.create_backup(target)?;
        info!("Backup created at {:?}", backup_path);

        // 3. Write new file (atomic replace if possible on same drive)
        let temp_dir = target.parent().unwrap_or_else(|| Path::new("."));
        let temp_file = temp_dir.join(format!(".remediate_{}.tmp", uuid::Uuid::new_v4()));

        fs::write(&temp_file, &data)?;

        if let Err(e) = fs::rename(&temp_file, target) {
            #[cfg(target_os = "windows")]
            {
                // Error 5 = Access Denied (often file in use)
                if e.raw_os_error() == Some(5) {
                    warn!(
                        "File {} is in use. Scheduling replacement on next reboot...",
                        target_path
                    );
                    if let Ok(_) = self.schedule_reboot_move(&temp_file, target) {
                        info!("Reboot-time replacement scheduled for {}. Patch will complete after restart.", target_path);
                        return Ok(backup_path);
                    }
                }
            }

            error!(
                "Failed to swap remediated file: {}. Attempting rollback from backup.",
                e
            );
            let _ = fs::copy(&backup_path, target);
            let _ = fs::remove_file(&temp_file);
            return Err(anyhow!("Remediation swap failed: {}", e));
        }

        info!("Remediation complete for {}", target_path);
        Ok(backup_path)
    }

    #[cfg(target_os = "windows")]
    fn schedule_reboot_move(&self, from: &Path, to: &Path) -> Result<()> {
        fn to_wide(path: &Path) -> Vec<u16> {
            path.as_os_str()
                .encode_wide()
                .chain(std::iter::once(0))
                .collect()
        }

        let from_w = to_wide(from);
        let to_w = to_wide(to);

        unsafe {
            if MoveFileExW(
                from_w.as_ptr(),
                to_w.as_ptr(),
                MOVEFILE_DELAY_UNTIL_REBOOT | MOVEFILE_REPLACE_EXISTING,
            ) == 0
            {
                let err = std::io::Error::last_os_error();
                error!("MoveFileExW failed: {}", err);
                return Err(anyhow!("Failed to schedule reboot move: {}", err));
            }
        }
        Ok(())
    }

    fn create_backup(&self, path: &Path) -> Result<PathBuf> {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let filename = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");
        let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
        let backup_path = parent.join(format!("{}.{}.bak", filename, timestamp));

        fs::copy(path, &backup_path)?;
        Ok(backup_path)
    }

    /// Rollback a remediation by restoring from backup.
    pub fn rollback(&self, target_path: &str, backup_path: &Path) -> Result<()> {
        warn!(
            "Rolling back remediation for {} from {:?}",
            target_path, backup_path
        );
        if !backup_path.exists() {
            return Err(anyhow!(
                "Backup file missing for rollback: {:?}",
                backup_path
            ));
        }
        fs::copy(backup_path, target_path)?;
        Ok(())
    }
}
