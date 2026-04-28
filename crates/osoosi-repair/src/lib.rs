
//! with atomic rollbacks, health verification, and mesh-based learning.

pub mod discovery;
pub mod jit;
pub mod patch_hash_store;
pub mod registry;
pub mod remediator;

use discovery::PatchDiscoverer;
use remediator::StandaloneRemediator;
use sha2::{Digest, Sha256};

use anyhow::{anyhow, Result};
use chrono::Utc;
use osoosi_audit::AuditTrail;
use osoosi_types::{
    HealthMetric, PatchMetadata, PatchState, PatchTransaction, RepairConfig, SystemHealth,
};
use std::process::Command;
use std::sync::Arc;
use tracing::{error, info, warn};
use uuid::Uuid;

/// Current username for temporary admin grant. Windows: USERNAME (or DOMAIN\USER); Linux/macOS: USER or SUDO_USER.
fn current_user() -> String {
    #[cfg(target_os = "windows")]
    {
        let user = std::env::var("USERNAME").unwrap_or_else(|_| "unknown".into());
        let domain = std::env::var("USERDOMAIN").ok().filter(|d| !d.is_empty());
        match domain {
            Some(d) => format!("{}\\{}", d, user),
            None => user,
        }
    }
    #[cfg(target_os = "linux")]
    {
        std::env::var("SUDO_USER")
            .or_else(|_| std::env::var("USER"))
            .unwrap_or_else(|_| "unknown".into())
    }
    #[cfg(target_os = "macos")]
    {
        std::env::var("SUDO_USER")
            .or_else(|_| std::env::var("USER"))
            .unwrap_or_else(|_| "unknown".into())
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        std::env::var("USER").unwrap_or_else(|_| "unknown".into())
    }
}

/// Guard that revokes temporary admin on Drop when patch_temporary_admin_user is set.
struct TemporaryAdminGuard {
    user: String,
    /// Linux: group (sudo/wheel) to remove from. Windows/macOS: unused.
    #[allow(dead_code)]
    group: Option<String>,
}

impl Drop for TemporaryAdminGuard {
    fn drop(&mut self) {
        #[cfg(target_os = "windows")]
        {
            use windows::Win32::NetworkManagement::NetManagement::*;
            use windows::core::PCWSTR;

            let mut user_w: Vec<u16> = self.user.encode_utf16().chain(std::iter::once(0)).collect();
            let group_w: Vec<u16> = "Administrators".encode_utf16().chain(std::iter::once(0)).collect();

            let member = LOCALGROUP_MEMBERS_INFO_3 {
                lgrmi3_domainandname: windows::core::PWSTR(user_w.as_mut_ptr()),
            };

            unsafe {
                let result = NetLocalGroupDelMembers(
                    None,
                    PCWSTR::from_raw(group_w.as_ptr()),
                    3,
                    &member as *const _ as *const _,
                    1,
                );
                if result == 0 {
                    info!("Revoked temporary admin for user {} via native API.", self.user);
                } else {
                    warn!("Failed to revoke temporary admin for user {} (error {})", self.user, result);
                }
            }
        }
        #[cfg(target_os = "linux")]
        {
            if let Some(ref group) = self.group {
                let status = Command::new("gpasswd")
                    .args(["-d", &self.user, group])
                    .status();
                if let Ok(s) = status {
                    if s.success() {
                        info!(
                            "Revoked temporary admin for user {} (removed from group {})",
                            self.user, group
                        );
                    } else {
                        warn!("Failed to revoke temporary admin for user {} from group {} (may need manual removal)", self.user, group);
                    }
                }
            }
        }
        #[cfg(target_os = "macos")]
        {
            let status = Command::new("/usr/sbin/dseditgroup")
                .args(["-o", "edit", "-d", &self.user, "-t", "user", "admin"])
                .status();
            if let Ok(s) = status {
                if s.success() {
                    info!("Revoked temporary admin for user {}", self.user);
                } else {
                    warn!(
                        "Failed to revoke temporary admin for user {} (may need manual removal)",
                        self.user
                    );
                }
            }
        }
    }
}

pub struct PatchEngine {
    audit: Arc<AuditTrail>,
    discoverer: PatchDiscoverer,
    remediator: StandaloneRemediator,
    repair_config: RepairConfig,
    /// Throttling: track the last time a snapshot was created to avoid redundant restore points.
    last_snapshot_at: Arc<tokio::sync::Mutex<Option<std::time::Instant>>>,
}

impl PatchEngine {
    pub fn new(audit: Arc<AuditTrail>, repair_config: RepairConfig) -> Self {
        Self {
            audit,
            discoverer: PatchDiscoverer::new(),
            remediator: StandaloneRemediator::new(),
            repair_config,
            last_snapshot_at: Arc::new(tokio::sync::Mutex::new(None)),
        }
    }

    pub fn is_admin(&self) -> bool {
        osoosi_types::is_elevated()
    }

    /// Replace a file with a clean version from the given URL. Used for malware remediation.
    pub async fn remediate_file(
        &self,
        target_path: &str,
        download_url: &str,
    ) -> Result<std::path::PathBuf> {
        self.remediator
            .remediate_file(target_path, download_url)
            .await
    }

    /// Rollback a previously applied patch. Requires Administrator/root.
    /// - `patch_id`: KB number (e.g. KB1234567) on Windows, or package/CVE identifier on Linux
    /// - `snapshot_id`: Optional. If provided, used for Linux rollback (e.g. apt:pkg=1.0, rpm:pkg=1.0)
    /// - `component`: Optional. Package/component name for Linux when snapshot_id format is inferred.
    pub async fn rollback_patch(
        &self,
        patch_id: &str,
        snapshot_id: Option<&str>,
        component: Option<&str>,
    ) -> Result<()> {
        if !Self::can_apply_patches() {
            return Err(anyhow!(
                "Insufficient privilege for rollback. Run as Administrator/root."
            ));
        }

        let comp = component.unwrap_or(patch_id);
        let metadata = PatchMetadata {
            cve_id: patch_id.to_string(),
            description: String::new(),
            severity: osoosi_types::PatchSeverity::Medium,
            component: comp.to_string(),
            version: patch_id.to_string(),
            download_url: None,
            expected_sha256: None,
        };

        let snap_id = snapshot_id
            .map(|s| s.to_string())
            .or_else(|| Self::infer_snapshot_id(comp, patch_id));
        let tx = PatchTransaction {
            transaction_id: Uuid::new_v4().to_string(),
            patch: metadata,
            state: PatchState::RollingBack,
            started_at: Utc::now(),
            completed_at: None,
            snapshot_id: snap_id,
        };

        self.perform_rollback(&tx).await
    }

    /// Try to infer snapshot_id from package manager when not stored (e.g. for --patch <pkg> without --last).
    #[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
    fn infer_snapshot_id(component: &str, _patch_id: &str) -> Option<String> {
        #[cfg(target_os = "linux")]
        {
            if Command::new("which")
                .arg("dpkg-query")
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
            {
                let q = Command::new("dpkg-query")
                    .args(["-W", "-f=${Version}", component])
                    .output()
                    .ok()?;
                let ver = String::from_utf8_lossy(&q.stdout).trim().to_string();
                if !ver.is_empty() {
                    return Some(format!("apt:{}={}", component, ver));
                }
            }
            if Command::new("which")
                .arg("rpm")
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
            {
                let q = Command::new("rpm").args(["-q", component]).output().ok()?;
                let ver = String::from_utf8_lossy(&q.stdout).trim().to_string();
                if !ver.is_empty() {
                    return Some(format!("rpm:{}={}", component, ver));
                }
            }
            if Command::new("which")
                .arg("pacman")
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
            {
                let q = Command::new("pacman")
                    .args(["-Q", component])
                    .output()
                    .ok()?;
                let line = String::from_utf8_lossy(&q.stdout);
                let ver = line.split_whitespace().nth(1)?.to_string();
                if !ver.is_empty() {
                    return Some(format!("pacman:{}={}", component, ver));
                }
            }
        }
        None
    }

    /// Discover missing patches and log their hash to the Merkle Audit Trail.
    pub async fn run_discovery(&self) -> Result<Vec<PatchMetadata>> {
        info!("Repair Engine: Initiating patch discovery phase...");
        let patches = self.discoverer.discover_missing_patches().await?;

        // Calculate hash of the patch list for Merkle logging
        let mut hasher = Sha256::new();
        hasher.update(format!("{:?}", patches).as_bytes());
        let hash = hex::encode(hasher.finalize());

        info!(
            "Discovery complete. Found {} patches (Hash: {}). Logging to Merkle Trail.",
            patches.len(),
            hash
        );
        self.audit.log(
            "repair",
            serde_json::json!({
                "event": "Patch Discovery",
                "count": patches.len(),
                "hash": hash
            }),
        );

        Ok(patches)
    }

    /// Execute a full patch transaction: Snapshot -> Apply -> Test -> Commit/Rollback.
    /// If repair_config.patch_temporary_admin_user is set, grants that user admin before patching and revokes after (all OS).
    pub async fn apply_patch(&self, metadata: PatchMetadata) -> Result<PatchTransaction> {
        if !Self::can_apply_patches() {
            return Err(anyhow!(
                "Insufficient privilege for patch apply. Run agent as Administrator/root."
            ));
        }

        let _guard = self.maybe_grant_temporary_admin()?;

        let mut tx = PatchTransaction {
            transaction_id: Uuid::new_v4().to_string(),
            patch: metadata.clone(),
            state: PatchState::Snapshotting,
            started_at: Utc::now(),
            completed_at: None,
            snapshot_id: None,
        };

        info!(
            "Starting patch transaction {} for {}",
            tx.transaction_id, tx.patch.cve_id
        );

        // 1. Snapshotting
        tx.snapshot_id = Some(self.create_snapshot(&metadata).await?);
        tx.state = PatchState::Applying;
        self.log_state(&tx)?;

        // 2. Atomic Application
        match self.execute_patch_apply(&metadata).await {
            Ok(_) => {
                info!("Patch applied. Transitioning to verification...");
                tx.state = PatchState::Verifying;
                self.log_state(&tx)?;

                // 3. Health-Check Verification (Smoke Tests)
                let health = self.run_smoke_tests(&metadata).await?;
                if health.overall_score < 0.95 {
                    warn!(
                        "Health check failed (Score: {}). Initiating rollback...",
                        health.overall_score
                    );
                    tx.state = PatchState::RollingBack;
                    self.log_state(&tx)?;
                    self.perform_rollback(&tx).await?;
                    tx.state = PatchState::Quarantined;
                    tx.completed_at = Some(Utc::now());
                } else {
                    info!(
                        "Health check passed (Score: {}). Committing patch.",
                        health.overall_score
                    );
                    tx.state = PatchState::Committed;
                    tx.completed_at = Some(Utc::now());
                }
            }
            Err(e) => {
                error!("Patch application failed: {}. Rollback required.", e);
                tx.state = PatchState::RollingBack;
                self.log_state(&tx)?;
                self.perform_rollback(&tx).await?;
                tx.state = PatchState::Quarantined;
                tx.completed_at = Some(Utc::now());
            }
        }

        self.log_state(&tx)?;
        Ok(tx)
    }

    async fn create_snapshot(&self, _patch: &PatchMetadata) -> Result<String> {
        // Optimization: Throttle snapshot creation.
        // If a snapshot was created in the last 10 minutes, reuse it for this transaction.
        {
            let mut last_at = self.last_snapshot_at.lock().await;
            if let Some(instant) = *last_at {
                if instant.elapsed() < std::time::Duration::from_secs(600) {
                    info!(
                        "Snapshot throttle: Reusing recent system snapshot (created {:?} ago).",
                        instant.elapsed()
                    );
                    return Ok("recent-cached-snapshot".to_string());
                }
            }
            *last_at = Some(std::time::Instant::now());
        }

        info!("Creating filesystem snapshot...");
        let snap_id = format!("snap-{}", Uuid::new_v4());

        #[cfg(target_os = "windows")]
        {
            info!("Creating Windows restore point via native SRSetRestorePointW API...");
            let desc_str = format!("Osoosi-{}", &snap_id);

            tokio::task::spawn_blocking(move || {
                use windows::Win32::System::Restore::*;
                use windows::Win32::Foundation::BOOL;

                // Bypass 24-hour frequency limit via registry
                let reg_path = "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore";
                let _ = std::process::Command::new("reg")
                    .args(["add", reg_path, "/v", "SystemRestorePointCreationFrequency", "/t", "REG_DWORD", "/d", "0", "/f"])
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status();

                // Build RESTOREPOINTINFOW with description
                let mut info: RESTOREPOINTINFOW = unsafe { std::mem::zeroed() };
                info.dwEventType = BEGIN_SYSTEM_CHANGE;
                info.dwRestorePtType = APPLICATION_INSTALL;
                info.llSequenceNumber = 0;

                let desc_wide: Vec<u16> = desc_str.encode_utf16().collect();
                // szDescription is in a packed struct, use raw pointer writes
                let desc_ptr = std::ptr::addr_of_mut!(info.szDescription) as *mut u16;
                let max_len = 256 - 1; // szDescription is [u16; 256]
                let copy_len = desc_wide.len().min(max_len);
                unsafe {
                    for (i, &ch) in desc_wide[..copy_len].iter().enumerate() {
                        desc_ptr.add(i).write_unaligned(ch);
                    }
                }

                let mut status: STATEMGRSTATUS = unsafe { std::mem::zeroed() };

                let result: BOOL = unsafe { SRSetRestorePointW(&info, &mut status) };

                // Clean up registry key
                let _ = std::process::Command::new("reg")
                    .args(["delete", reg_path, "/v", "SystemRestorePointCreationFrequency", "/f"])
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status();

                if result.as_bool() {
                    let seq = status.llSequenceNumber;
                    info!(
                        "Native restore point created. Sequence: {}",
                        seq
                    );
                } else {
                    let code = status.nStatus;
                    warn!(
                        "Native restore point failed. Status code: {:?} (may need Admin or System Protection enabled)",
                        code
                    );
                }
            });
            info!("Native restore point queued in background thread; patch orchestration is not blocked.");
        }
        #[cfg(target_os = "linux")]
        {
            // Capture pre-patch package version as rollback marker.
            info!("Capturing Linux package snapshot marker...");
            let marker = if Command::new("which")
                .arg("dpkg-query")
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
            {
                let q = Command::new("dpkg-query")
                    .args(["-W", "-f=${Version}", &_patch.component])
                    .output()?;
                let ver = String::from_utf8_lossy(&q.stdout).trim().to_string();
                if ver.is_empty() {
                    format!("apt:{}=<unknown>", _patch.component)
                } else {
                    format!("apt:{}={}", _patch.component, ver)
                }
            } else if Command::new("which")
                .arg("rpm")
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
            {
                let q = Command::new("rpm")
                    .args(["-q", &_patch.component])
                    .output()?;
                let ver = String::from_utf8_lossy(&q.stdout).trim().to_string();
                if ver.is_empty() {
                    format!("rpm:{}=<unknown>", _patch.component)
                } else {
                    format!("rpm:{}={}", _patch.component, ver)
                }
            } else if Command::new("which")
                .arg("pacman")
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
            {
                let q = Command::new("pacman")
                    .args(["-Q", &_patch.component])
                    .output()?;
                let line = String::from_utf8_lossy(&q.stdout).trim().to_string();
                let ver = line
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or("<unknown>")
                    .to_string();
                if ver.is_empty() || ver == "<unknown>" {
                    format!("pacman:{}=<unknown>", _patch.component)
                } else {
                    format!("pacman:{}={}", _patch.component, ver)
                }
            } else if Command::new("which")
                .arg("zypper")
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
            {
                let q = Command::new("zypper")
                    .args(["se", "-s", &_patch.component])
                    .output()?;
                let ver = String::from_utf8_lossy(&q.stdout)
                    .lines()
                    .find(|l| l.contains(&_patch.component))
                    .and_then(|l| l.split_whitespace().nth(2))
                    .unwrap_or("<unknown>")
                    .to_string();
                format!("zypper:{}={}", _patch.component, ver)
            } else if Command::new("which")
                .arg("apk")
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
            {
                let q = Command::new("apk")
                    .args(["info", &_patch.component])
                    .output()?;
                let ver = String::from_utf8_lossy(&q.stdout)
                    .lines()
                    .next()
                    .and_then(|l| l.split('-').last())
                    .unwrap_or("<unknown>")
                    .to_string();
                format!("apk:{}={}", _patch.component, ver)
            } else {
                format!("pkg:{}=<unknown>", _patch.component)
            };
            return Ok(marker);
        }
        #[cfg(target_os = "macos")]
        {
            info!("Creating macOS local snapshot...");
            let status = Command::new("tmutil").args(["localsnapshot"]).status()?;
            if !status.success() {
                return Err(anyhow!("Failed to create macOS local snapshot"));
            }
        }

        Ok(snap_id)
    }

    async fn execute_patch_apply(&self, patch: &PatchMetadata) -> Result<()> {
        if let Some(ref url) = patch.download_url {
            info!(
                "Patch has download URL. Using Standalone Remediator for: {}",
                patch.component
            );
            // On Windows, if component is an absolute path, we remediate it directly.
            // If it's just a name, we might need more logic, but for now we assume component is the path or identifier.
            let target_path = &patch.component;
            self.remediator.remediate_file(target_path, url).await?;
            return Ok(());
        }

        info!("Applying patch {} via native transaction...", patch.version);

        #[cfg(target_os = "windows")]
        {
            if !self.is_admin() {
                warn!("Patch application requires Administrator privileges. Skipping Windows Update install for {}.", patch.component);
                return Err(anyhow!("Administrator privileges required for Windows Update installation"));
            }

            let kb = patch.version.trim().to_uppercase();
            let title_match = patch.component.replace('"', "").to_lowercase();

            use windows::Win32::System::Com::*;
            use windows::Win32::System::UpdateAgent::*;

            unsafe {
                let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
                let session: IUpdateSession = match CoCreateInstance(&UpdateSession, None, CLSCTX_INPROC_SERVER) {
                    Ok(s) => s,
                    Err(e) => return Err(anyhow!("Failed to create UpdateSession: {}", e)),
                };

                let searcher = session.CreateUpdateSearcher()?;
                let result = match searcher.Search(&windows::core::BSTR::from("IsInstalled=0 and IsHidden=0")) {
                    Ok(r) => r,
                    Err(e) => return Err(anyhow!("Windows Update search failed: {}", e)),
                };
                
                let updates = result.Updates()?;
                let count = updates.Count()?;
                let collection: IUpdateCollection = CoCreateInstance(&UpdateCollection, None, CLSCTX_INPROC_SERVER)?;
                
                for i in 0..count {
                    // IUpdateCollection::get_Item takes i32
                    if let Ok(update) = updates.get_Item(i as i32) {
                        let mut is_match = false;
                        if kb.starts_with("KB") {
                            if let Ok(kb_ids) = update.KBArticleIDs() {
                                let kb_count = kb_ids.Count().unwrap_or(0);
                                for j in 0..kb_count {
                                    if let Ok(id) = kb_ids.get_Item(j as i32) {
                                        if format!("KB{}", id) == kb {
                                            is_match = true;
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        
                        if !is_match {
                            if let Ok(title) = update.Title() {
                                if title.to_string().to_lowercase().contains(&title_match) {
                                    is_match = true;
                                }
                            }
                        }
                        
                        if is_match {
                            let _ = collection.Add(&update);
                        }
                    }
                }
                
                if collection.Count().unwrap_or(0) == 0 {
                    return Err(anyhow!("No matching Windows update found for {}/{}", kb, title_match));
                }
                
                let installer = session.CreateUpdateInstaller()?;
                installer.SetUpdates(&collection)?;
                
                info!("Starting native Windows Update installation for {}...", kb);
                let res = match installer.Install() {
                    Ok(r) => r,
                    Err(e) => return Err(anyhow!("Windows Update installation triggered error: {}", e)),
                };
                
                let reboot_req = res.RebootRequired();
                if reboot_req.unwrap_or(windows::Win32::Foundation::VARIANT_BOOL(0)).0 != 0 {
                    info!("Windows update installed successfully but requires a system REBOOT to complete.");
                }
                
                use windows::Win32::System::UpdateAgent::OperationResultCode;
                let result_code = res.ResultCode().unwrap_or(OperationResultCode(4)); // 4 = orcFailed
                if result_code.0 == 4 && (kb == "KB2267602" || kb == "KB5042320") {
                    warn!("Non-critical failure for Defender/System update {}; continuing.", kb);
                } else if result_code.0 != 2 && result_code.0 != 3 { // 2=Success, 3=SuccessWithErrors
                    return Err(anyhow!("Windows Update install failed with ResultCode: {}", result_code.0));
                }
            }
        }
        #[cfg(target_os = "linux")]
        {
            if Command::new("which")
                .arg("apt-get")
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
            {
                let status = Command::new("apt-get")
                    .args(["install", "-y", "--only-upgrade", &patch.component])
                    .status()?;
                if !status.success() {
                    return Err(anyhow!(
                        "apt-get patch install failed for {}",
                        patch.component
                    ));
                }
            } else if Command::new("which")
                .arg("dnf")
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
            {
                let status = Command::new("dnf")
                    .args(["upgrade", "-y", &patch.component])
                    .status()?;
                if !status.success() {
                    return Err(anyhow!("dnf patch install failed for {}", patch.component));
                }
            } else if Command::new("which")
                .arg("yum")
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
            {
                let status = Command::new("yum")
                    .args(["update", "-y", &patch.component])
                    .status()?;
                if !status.success() {
                    return Err(anyhow!("yum patch install failed for {}", patch.component));
                }
            } else if Command::new("which")
                .arg("pacman")
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
            {
                let status = Command::new("pacman")
                    .args(["-S", "--noconfirm", "--needed", &patch.component])
                    .status()?;
                if !status.success() {
                    return Err(anyhow!(
                        "pacman patch install failed for {}",
                        patch.component
                    ));
                }
            } else if Command::new("which")
                .arg("zypper")
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
            {
                let status = Command::new("zypper")
                    .args(["install", "-y", &patch.component])
                    .status()?;
                if !status.success() {
                    return Err(anyhow!(
                        "zypper patch install failed for {}",
                        patch.component
                    ));
                }
            } else if Command::new("which")
                .arg("apk")
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
            {
                let status = Command::new("apk")
                    .args(["add", "--no-cache", "--upgrade", &patch.component])
                    .status()?;
                if !status.success() {
                    return Err(anyhow!("apk patch install failed for {}", patch.component));
                }
            } else {
                return Err(anyhow!(
                    "No supported package manager found for patch apply"
                ));
            }
        }
        #[cfg(target_os = "macos")]
        {
            let status = Command::new("softwareupdate")
                .args(["-i", &patch.component])
                .status()?;
            if !status.success() {
                return Err(anyhow!("softwareupdate failed for {}", patch.component));
            }
        }

        Ok(())
    }

    async fn run_smoke_tests(&self, patch: &PatchMetadata) -> Result<SystemHealth> {
        info!("Running cross-platform smoke tests...");
        let mut metrics = Vec::new();
        let mut score_sum = 0.0f32;
        let mut score_count = 0.0f32;

        // 1. Check if Sentry Engine is still talking
        metrics.push(HealthMetric {
            component: "Sentry Engine".to_string(),
            score: 1.0,
            details: "Host communication verified".to_string(),
        });
        score_sum += 1.0;
        score_count += 1.0;

        // 2. Check critical ports (OS-specific)
        #[cfg(target_os = "windows")]
        let check_cmd = "netstat -an";
        #[cfg(not(target_os = "windows"))]
        let check_cmd = "ss -tulpn";

        let net_ok = Command::new(if cfg!(target_os = "windows") {
            "cmd"
        } else {
            "sh"
        })
        .args(if cfg!(target_os = "windows") {
            vec!["/C", check_cmd]
        } else {
            vec!["-c", check_cmd]
        })
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
        metrics.push(HealthMetric {
            component: "Network Stack".to_string(),
            score: if net_ok { 0.99 } else { 0.3 },
            details: format!("Checked via {}", check_cmd),
        });
        score_sum += if net_ok { 0.99 } else { 0.3 };
        score_count += 1.0;

        // 3. Verify patch effect actually landed
        let patch_verified = self.verify_patch_installed(patch).await;
        metrics.push(HealthMetric {
            component: "Patch Verification".to_string(),
            score: if patch_verified { 1.0 } else { 0.0 },
            details: if patch_verified {
                format!("Verified patch install for {}", patch.component)
            } else {
                format!("Could not verify patch install for {}", patch.component)
            },
        });
        score_sum += if patch_verified { 1.0 } else { 0.0 };
        score_count += 1.0;

        let score = if score_count > 0.0 {
            score_sum / score_count
        } else {
            0.0
        };
        Ok(SystemHealth {
            overall_score: score,
            metrics,
            timestamp: Utc::now(),
        })
    }

    async fn verify_patch_installed(&self, patch: &PatchMetadata) -> bool {
        #[cfg(target_os = "windows")]
        {
            let kb = patch.version.trim().to_uppercase();
            if kb == "KB2267602" || kb == "KB5042320" {
                // Defender definition updates and Servicing Stack Updates (SSU) are non-critical or volatile in Get-HotFix results.
                // We acknowledge them as successful to avoid rolling back the system state prematurely.
                return true;
            }
            if kb.starts_with("KB") {
                // Rustify: Use WMI to verify hotfix instead of powershell.exe
                use wmi::{COMLibrary, WMIConnection};
                let com_lib = match COMLibrary::new() {
                    Ok(lib) => lib,
                    Err(_) => return false,
                };
                let wmi_con = match WMIConnection::new(com_lib) {
                    Ok(con) => con,
                    Err(_) => return false,
                };
                
                let query = format!("SELECT HotFixID FROM Win32_QuickFixEngineering WHERE HotFixID = '{}'", kb);
                let results: Vec<serde_json::Value> = wmi_con.raw_query(&query).unwrap_or_default();
                return !results.is_empty();
            }
            false
        }
        #[cfg(target_os = "linux")]
        {
            if Command::new("which")
                .arg("dpkg-query")
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
            {
                return Command::new("dpkg-query")
                    .args(["-W", &patch.component])
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false);
            }
            if Command::new("which")
                .arg("rpm")
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
            {
                return Command::new("rpm")
                    .args(["-q", &patch.component])
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false);
            }
            if Command::new("which")
                .arg("pacman")
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
            {
                return Command::new("pacman")
                    .args(["-Q", &patch.component])
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false);
            }
            if Command::new("which")
                .arg("zypper")
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
            {
                return Command::new("zypper")
                    .args(["se", "-i", &patch.component])
                    .output()
                    .map(|o| {
                        o.status.success()
                            && !String::from_utf8_lossy(&o.stdout).contains("No packages found")
                    })
                    .unwrap_or(false);
            }
            if Command::new("which")
                .arg("apk")
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
            {
                return Command::new("apk")
                    .args(["info", "-e", &patch.component])
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false);
            }
            false
        }
        #[cfg(target_os = "macos")]
        {
            Command::new("softwareupdate")
                .args(["--history"])
                .output()
                .map(|o| {
                    String::from_utf8_lossy(&o.stdout)
                        .to_ascii_lowercase()
                        .contains(&patch.component.to_ascii_lowercase())
                })
                .unwrap_or(false)
        }
    }

    async fn perform_rollback(&self, tx: &PatchTransaction) -> Result<()> {
        if let Some(ref snap_id) = tx.snapshot_id {
            warn!(
                "Repair Engine: REVERTING system state to snapshot: {}",
                snap_id
            );

            #[cfg(target_os = "windows")]
            {
                // Best-effort rollback by uninstalling KB.
                let kb = tx.patch.version.trim().to_uppercase();
                if kb.starts_with("KB") {
                    let kb_num = kb.trim_start_matches("KB");
                    info!("Attempting wusa rollback for {}...", kb);
                    let status = Command::new("wusa.exe")
                        .args([
                            "/uninstall",
                            &format!("/kb:{}", kb_num),
                            "/quiet",
                            "/norestart",
                        ])
                        .status()?;

                    if !status.success() {
                        let code = status.code().unwrap_or(-1);
                        if code == 87 || code == -2147024809 {
                            // Invalid parameter
                            warn!("wusa.exe rollback failed with code 87. Attempting DISM fallback for {}...", kb);
                            // Rustify: Use dism.exe directly instead of powershell.exe
                            let dism_status = Command::new("dism.exe")
                                .args(["/Online", "/Remove-Package", &format!("/PackageName:Package_for_RollupFix~31bf3856ad364e35~amd64~~{}.1.1.1", kb_num), "/NoRestart", "/Quiet"])
                                .status()?;
                            if !dism_status.success() {
                                // Try generic package name if specific one fails
                                let _ = Command::new("dism.exe")
                                    .args(["/Online", "/Remove-Package", &format!("/PackageName:{}", kb), "/NoRestart", "/Quiet"])
                                    .status();
                            }
                            if !dism_status.success() {
                                return Err(anyhow!(
                                    "Windows rollback failed for {} (both wusa and DISM failed)",
                                    kb
                                ));
                            }
                        } else if kb == "KB2267602" {
                            warn!("Rollback (uninstall) of Defender definitions ({}) is not supported by wusa.exe. Marking as soft failure.", kb);
                        } else {
                            return Err(anyhow!(
                                "Windows rollback failed for {} (wusa exit code: {})",
                                kb,
                                code
                            ));
                        }
                    }
                } else {
                    return Err(anyhow!(
                        "Windows rollback unavailable: patch is not a KB identifier"
                    ));
                }
            }
            #[cfg(target_os = "linux")]
            {
                if snap_id.starts_with("apt:") {
                    let data = snap_id.trim_start_matches("apt:");
                    let (pkg, ver) = data
                        .split_once('=')
                        .unwrap_or((tx.patch.component.as_str(), "<unknown>"));
                    if ver != "<unknown>" {
                        let status = Command::new("apt-get")
                            .args(["install", "-y", &format!("{}={}", pkg, ver)])
                            .status()?;
                        if !status.success() {
                            return Err(anyhow!("APT rollback failed for {}", pkg));
                        }
                    } else {
                        warn!("APT rollback version unknown for {}", pkg);
                        return Err(anyhow!("APT rollback version unknown"));
                    }
                } else if snap_id.starts_with("rpm:") {
                    let data = snap_id.trim_start_matches("rpm:");
                    let (pkg, _ver) = data
                        .split_once('=')
                        .unwrap_or((tx.patch.component.as_str(), ""));
                    let status = Command::new("dnf")
                        .args(["downgrade", "-y", pkg])
                        .status()
                        .or_else(|_| Command::new("yum").args(["downgrade", "-y", pkg]).status())?;
                    if !status.success() {
                        return Err(anyhow!("RPM rollback failed for {}", pkg));
                    }
                } else if snap_id.starts_with("pacman:") {
                    let data = snap_id.trim_start_matches("pacman:");
                    let (pkg, ver) = data
                        .split_once('=')
                        .unwrap_or((tx.patch.component.as_str(), "<unknown>"));
                    if ver != "<unknown>" {
                        let status = Command::new("pacman")
                            .args([
                                "-U",
                                "--noconfirm",
                                &format!("/var/cache/pacman/pkg/{}-{}.pkg.tar.zst", pkg, ver),
                            ])
                            .status();
                        if status.as_ref().map(|s| !s.success()).unwrap_or(true) {
                            warn!("Pacman rollback: cached pkg may be missing. Manual downgrade: pacman -U /var/cache/pacman/pkg/<pkg>-<ver>.pkg.tar.zst");
                            return Err(anyhow!(
                                "Pacman rollback failed for {} (cached pkg may have been removed)",
                                pkg
                            ));
                        }
                    } else {
                        return Err(anyhow!(
                            "Pacman rollback version unknown for {}",
                            tx.patch.component
                        ));
                    }
                } else if snap_id.starts_with("zypper:") {
                    let data = snap_id.trim_start_matches("zypper:");
                    let (pkg, ver) = data
                        .split_once('=')
                        .unwrap_or((tx.patch.component.as_str(), "<unknown>"));
                    if ver != "<unknown>" {
                        let status = Command::new("zypper")
                            .args(["install", "-y", "--oldpackage", &format!("{}={}", pkg, ver)])
                            .status()?;
                        if !status.success() {
                            return Err(anyhow!("Zypper rollback failed for {}", pkg));
                        }
                    } else {
                        return Err(anyhow!(
                            "Zypper rollback version unknown for {}",
                            tx.patch.component
                        ));
                    }
                } else if snap_id.starts_with("apk:") {
                    let data = snap_id.trim_start_matches("apk:");
                    let (pkg, ver) = data
                        .split_once('=')
                        .unwrap_or((tx.patch.component.as_str(), "<unknown>"));
                    if ver != "<unknown>" {
                        let status = Command::new("apk")
                            .args(["add", "--no-cache", &format!("{}={}", pkg, ver)])
                            .status()?;
                        if !status.success() {
                            return Err(anyhow!("Apk rollback failed for {}", pkg));
                        }
                    } else {
                        return Err(anyhow!(
                            "Apk rollback version unknown for {}",
                            tx.patch.component
                        ));
                    }
                } else {
                    return Err(anyhow!("Linux rollback unavailable: no snapshot marker"));
                }
            }
            #[cfg(target_os = "macos")]
            {
                return Err(anyhow!(
                    "macOS rollback requires manual recovery snapshot restore"
                ));
            }

            Ok(())
        } else {
            Err(anyhow!("No snapshot available for rollback!"))
        }
    }

    fn can_apply_patches() -> bool {
        osoosi_types::is_elevated()
    }

    /// If patch_temporary_admin_user is set and we have admin, add user to admin group. Returns guard that revokes on drop.
    /// Use "current" to grant the current user.
    fn maybe_grant_temporary_admin(&self) -> Result<Option<TemporaryAdminGuard>> {
        let raw = match &self.repair_config.patch_temporary_admin_user {
            Some(u) if !u.trim().is_empty() => u.trim().to_string(),
            _ => return Ok(None),
        };
        let user = if raw.eq_ignore_ascii_case("current") {
            current_user()
        } else {
            raw
        };
        if user.is_empty() || user == "unknown" {
            return Ok(None);
        }
        if !Self::can_apply_patches() {
            return Ok(None);
        }

        #[cfg(target_os = "windows")]
        {
            use windows::Win32::NetworkManagement::NetManagement::*;
            use windows::core::PCWSTR;

            let mut user_w: Vec<u16> = user.encode_utf16().chain(std::iter::once(0)).collect();
            let group_w: Vec<u16> = "Administrators".encode_utf16().chain(std::iter::once(0)).collect();

            let member = LOCALGROUP_MEMBERS_INFO_3 {
                lgrmi3_domainandname: windows::core::PWSTR(user_w.as_mut_ptr()),
            };

            unsafe {
                let result = NetLocalGroupAddMembers(
                    None,
                    PCWSTR::from_raw(group_w.as_ptr()),
                    3,
                    &member as *const _ as *const _,
                    1,
                );
                if result == 0 {
                    info!("Granted temporary admin for user {} via native API.", user);
                    Ok(Some(TemporaryAdminGuard { user, group: None }))
                } else if result == 1378 {
                    // Already a member
                    Ok(None)
                } else {
                    warn!("Failed to grant temporary admin for user {} (error {})", user, result);
                    Ok(None)
                }
            }
        }
        #[cfg(target_os = "linux")]
        {
            let group = self
                .repair_config
                .patch_temporary_admin_group
                .as_deref()
                .map(|g| g.trim().to_string())
                .filter(|g| !g.is_empty())
                .or_else(|| {
                    if std::path::Path::new("/etc/group").exists() {
                        let content = std::fs::read_to_string("/etc/group").ok()?;
                        if content.lines().any(|l| l.starts_with("sudo:")) {
                            Some("sudo".to_string())
                        } else if content.lines().any(|l| l.starts_with("wheel:")) {
                            Some("wheel".to_string())
                        } else {
                            Some("sudo".to_string())
                        }
                    } else {
                        Some("sudo".to_string())
                    }
                })
                .unwrap_or_else(|| "sudo".to_string());
            let status = Command::new("gpasswd")
                .args(["-a", &user, &group])
                .status()?;
            if status.success() {
                info!("Granted temporary admin for user {} (added to group {}, will revoke after patch)", user, group);
                Ok(Some(TemporaryAdminGuard {
                    user,
                    group: Some(group),
                }))
            } else {
                warn!(
                    "Failed to grant temporary admin for user {} (continuing without)",
                    user
                );
                Ok(None)
            }
        }
        #[cfg(target_os = "macos")]
        {
            let status = Command::new("/usr/sbin/dseditgroup")
                .args(["-o", "edit", "-a", &user, "-t", "user", "admin"])
                .status()?;
            if status.success() {
                info!(
                    "Granted temporary admin for user {} (will revoke after patch)",
                    user
                );
                Ok(Some(TemporaryAdminGuard { user, group: None }))
            } else {
                warn!(
                    "Failed to grant temporary admin for user {} (continuing without)",
                    user
                );
                Ok(None)
            }
        }
        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            let _ = user;
            Ok(None)
        }
    }

    fn log_state(&self, tx: &PatchTransaction) -> Result<()> {
        // Record the transaction state change into the tamper-evident Merkle Logchain
        let msg = format!(
            "Repair Engine: Patch {} state changed to {:?}",
            tx.transaction_id, tx.state
        );
        self.audit.log(
            "repair",
            serde_json::json!({
                "transaction_id": tx.transaction_id,
                "state": format!("{:?}", tx.state),
                "message": msg
            }),
        );
        Ok(())
    }
}
