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
        self.remediate_file_with_hash(target_path, download_url, None).await
    }

    /// Download a file with SHA-256 verification and replace target path atomically.
    pub async fn remediate_file_with_hash(
        &self,
        target_path: &str,
        download_url: &str,
        expected_sha256: Option<&str>,
    ) -> Result<PathBuf> {
        info!(
            "Remediating standalone file: {} via {}",
            target_path, download_url
        );

        let target = Path::new(target_path);
        if target.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
            return Err(anyhow!(
                "Path traversal rejected in target file path: {}",
                target_path
            ));
        }

        if !target.exists() {
            return Err(anyhow!(
                "Target file for remediation does not exist: {}",
                target_path
            ));
        }

        if let Ok(meta) = std::fs::symlink_metadata(target) {
            if meta.file_type().is_symlink() {
                return Err(anyhow!(
                    "Target file is a symbolic link; refusing remediation: {}",
                    target_path
                ));
            }
        }

        if !download_url.starts_with("https://") {
            return Err(anyhow!(
                "Remediation download URL must use HTTPS: {}",
                download_url
            ));
        }

        let blocked_hosts = ["localhost", "127.", "10.", "192.168.", "169.254."];
        let url_lower = download_url.to_lowercase();
        for b in blocked_hosts {
            if url_lower.contains(&format!("://{}", b)) || url_lower.contains(&format!("://{}:", b)) {
                return Err(anyhow!(
                    "SSRF Protection: Blocked private/loopback download host in URL: {}",
                    download_url
                ));
            }
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

        // Compute SHA-256
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let computed_sha256 = hex::encode(hasher.finalize());
        info!("Remediation payload SHA-256: {}", computed_sha256);

        let mut verified = false;
        if let Some(expected) = expected_sha256 {
            let expected_clean = expected.trim().to_lowercase();
            if !expected_clean.is_empty() {
                if expected_clean != computed_sha256.to_lowercase() {
                    return Err(anyhow!(
                        "Cryptographic mismatch: expected SHA-256 {}, but downloaded payload has {}",
                        expected_clean,
                        computed_sha256
                    ));
                }
                verified = true;
            }
        }

        // 2. Create backup of original
        let backup_path = self.create_backup(target)?;
        info!("Backup created at {:?}", backup_path);

        // 3. Write new file to temporary path
        let temp_dir = target.parent().unwrap_or_else(|| Path::new("."));
        let temp_file = temp_dir.join(format!(".remediate_{}.tmp", uuid::Uuid::new_v4()));

        fs::write(&temp_file, &data)?;

        // If no hash was provided, verify Authenticode digital signature
        if !verified {
            if osoosi_types::is_trusted_signed_binary(&temp_file) {
                info!("Downloaded remediation payload verified via trusted Authenticode digital signature.");
                verified = true;
            }
        }

        if !verified {
            let _ = fs::remove_file(&temp_file);
            return Err(anyhow!(
                "Supply-chain verification failed: replacement payload from {} has no expected SHA-256 match and is not Authenticode signed with a trusted certificate",
                download_url
            ));
        }

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
        use windows::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_DELAY_UNTIL_REBOOT, MOVEFILE_REPLACE_EXISTING};
        use windows::core::PCWSTR;

        fn to_wide(path: &Path) -> Vec<u16> {
            path.as_os_str()
                .encode_wide()
                .chain(std::iter::once(0))
                .collect()
        }

        let from_w = to_wide(from);
        let to_w = to_wide(to);

        unsafe {
            MoveFileExW(
                PCWSTR::from_raw(from_w.as_ptr()),
                PCWSTR::from_raw(to_w.as_ptr()),
                MOVEFILE_DELAY_UNTIL_REBOOT | MOVEFILE_REPLACE_EXISTING,
            ).map_err(|e| {
                error!("MoveFileExW failed: {}", e);
                anyhow!("Failed to schedule reboot move: {}", e)
            })?;
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
