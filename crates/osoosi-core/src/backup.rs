//! Cross-platform backup on agent start.
//! Windows: wbAdmin (full image), Checkpoint-Computer (restore point), Robocopy (file sync)
//! Linux: rsync
//! macOS: tmutil (Time Machine) or rsync

use osoosi_types::BackupConfig;
use std::process::Command;
use std::sync::Arc;
use tracing::{error, info, warn};

/// Run backup based on config. Called at agent start.
/// If memory is provided, stores status for dashboard.
pub fn run_backup_on_start(config: &BackupConfig, memory: Option<Arc<osoosi_memory::MemoryStore>>) {
    if !config.enabled {
        if let Some(ref m) = memory {
            let _ = m.set_backup_status("status", "disabled");
            let _ = m.set_backup_status("enabled", "false");
        }
        return;
    }
    if config.backup_type != "restore_point" && config.target.trim().is_empty() {
        warn!("Backup enabled but target is empty. Skipping.");
        if let Some(ref m) = memory {
            let _ = m.set_backup_status("status", "no_target");
            let _ = m.set_backup_status("message", "Target path is empty");
        }
        return;
    }

    if let Some(ref m) = memory {
        if let Ok(Some(last_at_str)) = m.get_backup_status("last_at") {
            if let Ok(last_time) = chrono::DateTime::parse_from_rfc3339(&last_at_str) {
                let last_utc = last_time.with_timezone(&chrono::Utc);
                let elapsed = chrono::Utc::now() - last_utc;
                let min_interval = config.interval_secs.unwrap_or(86400); // Default 24h
                if elapsed.num_seconds() < min_interval as i64 {
                    info!("Backup throttle: Last backup was {:?} ago (min: {}s). Skipping restore point.", elapsed, min_interval);
                    return;
                }
            }
        }
    }

    if config.backup_type == "restore_point" {
        if let Some(ref m) = memory {
            let _ = m.set_backup_status("enabled", "true");
            let _ = m.set_backup_status("backup_type", &config.backup_type);
            let _ = m.set_backup_status("status", "pending");
            let _ = m.set_backup_status("message", "Restore point creation queued in background");
        }
        let cfg = config.clone();
        let mem = memory.clone();
        std::thread::spawn(move || {
            let result = run_restore_point(&cfg);
            if let Some(ref m) = mem {
                match &result {
                    Ok(msg) => {
                        let _ = m.set_backup_status("status", "ok");
                        let _ = m.set_backup_status("message", msg);
                        let _ = m.set_backup_status("last_at", &chrono::Utc::now().to_rfc3339());
                    }
                    Err(e) => {
                        let _ = m.set_backup_status("status", "failed");
                        let _ = m.set_backup_status("message", &e.to_string());
                    }
                }
            }
            match result {
                Ok(msg) => info!("Background restore point: {}", msg),
                Err(e) => warn!("Background restore point failed: {}", e),
            }
        });
        info!("Restore point queued in background; agent startup is not blocked.");
        return;
    }

    let result = match config.backup_type.as_str() {
        "full_image" => run_full_image(config),
        "file_sync" => run_file_sync(config),
        _ => run_file_sync(config),
    };

    if let Some(ref m) = memory {
        let _ = m.set_backup_status("enabled", "true");
        let _ = m.set_backup_status("target", &config.target);
        let _ = m.set_backup_status("backup_type", &config.backup_type);
        match &result {
            Ok(msg) => {
                let _ = m.set_backup_status("status", "ok");
                let _ = m.set_backup_status("message", msg);
                let _ = m.set_backup_status("last_at", &chrono::Utc::now().to_rfc3339());
            }
            Err(e) => {
                let _ = m.set_backup_status("status", "failed");
                let _ = m.set_backup_status("message", &e.to_string());
            }
        }
    }

    match result {
        Ok(msg) => info!("Backup on start: {}", msg),
        Err(e) => error!("Backup on start failed: {}", e),
    }
}

#[cfg(target_os = "windows")]
fn run_restore_point(_config: &BackupConfig) -> anyhow::Result<String> {
    use windows::Win32::System::Restore::*;
    use windows::Win32::Foundation::BOOL;

    let desc = format!("Osoosi pre-start {}", {
        let now = std::time::SystemTime::now();
        let secs = now
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        format!("{}", secs)
    });

    // Bypass 24-hour frequency limit via registry
    let reg_path = "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore";
    let _ = Command::new("reg")
        .args(["add", reg_path, "/v", "SystemRestorePointCreationFrequency", "/t", "REG_DWORD", "/d", "0", "/f"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    // Build RESTOREPOINTINFOW
    let mut info: RESTOREPOINTINFOW = unsafe { std::mem::zeroed() };
    info.dwEventType = BEGIN_SYSTEM_CHANGE;
    info.dwRestorePtType = APPLICATION_INSTALL;
    info.llSequenceNumber = 0;

    let desc_wide: Vec<u16> = desc.encode_utf16().collect();
    let desc_ptr = std::ptr::addr_of_mut!(info.szDescription) as *mut u16;
    let max_len = 256 - 1;
    let copy_len = desc_wide.len().min(max_len);
    unsafe {
        for (i, &ch) in desc_wide[..copy_len].iter().enumerate() {
            desc_ptr.add(i).write_unaligned(ch);
        }
    }

    let mut status: STATEMGRSTATUS = unsafe { std::mem::zeroed() };
    let result: BOOL = unsafe { SRSetRestorePointW(&info, &mut status) };

    // Clean up registry key
    let _ = Command::new("reg")
        .args(["delete", reg_path, "/v", "SystemRestorePointCreationFrequency", "/f"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    if result.as_bool() {
        let seq = status.llSequenceNumber;
        Ok(format!("System restore point created (seq: {})", seq))
    } else {
        let code = status.nStatus;
        Err(anyhow::anyhow!(
            "SRSetRestorePointW failed. Status code: {:?} (may need Admin or System Protection enabled)",
            code
        ))
    }
}

#[cfg(target_os = "macos")]
fn run_restore_point(_config: &BackupConfig) -> anyhow::Result<String> {
    let label = format!(
        "com.oshoosi.snapshot.{}",
        chrono::Utc::now().timestamp().max(0)
    );
    let status = Command::new("tmutil").args(["localsnapshot"]).status()?;
    if status.success() {
        Ok(format!("APFS local snapshot requested ({})", label))
    } else {
        Err(anyhow::anyhow!("tmutil localsnapshot failed"))
    }
}

#[cfg(target_os = "linux")]
fn run_restore_point(config: &BackupConfig) -> anyhow::Result<String> {
    let target = if config.target.trim().is_empty() {
        "/".to_string()
    } else {
        config.target.clone()
    };
    if Command::new("sh")
        .args(["-c", "command -v btrfs >/dev/null 2>&1"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
    {
        let snap_dir = std::path::Path::new("/.snapshots");
        let _ = std::fs::create_dir_all(snap_dir);
        let snap = snap_dir.join(format!("osoosi-{}", chrono::Utc::now().timestamp().max(0)));
        let status = Command::new("sudo")
            .args([
                "btrfs",
                "subvolume",
                "snapshot",
                "-r",
                &target,
                &snap.to_string_lossy(),
            ])
            .status()?;
        if status.success() {
            return Ok(format!(
                "Btrfs read-only snapshot created at {}",
                snap.display()
            ));
        }
    }
    if Command::new("sh")
        .args(["-c", "command -v lvcreate >/dev/null 2>&1"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
    {
        return Ok(
            "LVM snapshot support detected; configure OSOOSI_LVM_VOLUME for exact LV snapshots"
                .to_string(),
        );
    }
    Ok("No native Linux snapshot provider detected; VM/provider snapshot recommended".to_string())
}

#[cfg(all(
    not(target_os = "windows"),
    not(target_os = "macos"),
    not(target_os = "linux")
))]
fn run_restore_point(_config: &BackupConfig) -> anyhow::Result<String> {
    Ok("No native snapshot provider for this OS; VM/provider snapshot recommended".to_string())
}

#[cfg(target_os = "windows")]
fn run_full_image(config: &BackupConfig) -> anyhow::Result<String> {
    use std::process::Stdio;
    let target = config.target.trim().trim_end_matches('\\');
    let status = Command::new("wbadmin")
        .args([
            "start",
            "backup",
            &format!("-backupTarget:{}", target),
            "-include:C:",
            "-allCritical",
            "-quiet",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .status()?;
    if status.success() {
        Ok(format!("Full image backup started to {}", target))
    } else {
        Err(anyhow::anyhow!(
            "wbadmin failed (requires Admin). Run as Administrator."
        ))
    }
}

#[cfg(not(target_os = "windows"))]
fn run_full_image(_config: &BackupConfig) -> anyhow::Result<String> {
    Err(anyhow::anyhow!(
        "full_image is Windows-only; use file_sync on this OS"
    ))
}

fn default_include_paths() -> Vec<String> {
    #[cfg(target_os = "windows")]
    {
        let user =
            std::env::var("USERPROFILE").unwrap_or_else(|_| "C:\\Users\\Default".to_string());
        vec![
            format!("{}\\Documents", user),
            format!("{}\\Desktop", user),
            format!("{}\\Pictures", user),
        ]
    }
    #[cfg(target_os = "linux")]
    {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
        vec![
            format!("{}/Documents", home),
            format!("{}/Desktop", home),
            format!("{}/.config", home),
        ]
    }
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/Users/Shared".to_string());
        vec![
            format!("{}/Documents", home),
            format!("{}/Desktop", home),
            format!("{}/Pictures", home),
        ]
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        vec![".".to_string()]
    }
}

#[cfg(target_os = "windows")]
fn run_file_sync(config: &BackupConfig) -> anyhow::Result<String> {
    use std::process::Stdio;
    let target = config.target.trim().trim_end_matches('\\');
    let paths: Vec<String> = if config.include_paths.is_empty() {
        default_include_paths()
    } else {
        config.include_paths.clone()
    };

    let mut synced = 0u32;
    for src in &paths {
        if !std::path::Path::new(src).exists() {
            continue;
        }
        let dest = format!(
            "{}\\OsoosiBackup\\{}",
            target,
            std::path::Path::new(src)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("data")
        );
        let status = Command::new("robocopy")
            .args([
                src.as_str(),
                &dest,
                "/MIR",
                "/MT:8",
                "/R:1",
                "/W:1",
                "/NFL",
                "/NDL",
                "/NJH",
                "/NJS",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        // Robocopy exit: 0-7 = success, 8+ = errors
        if status.code().map(|c| c < 8).unwrap_or(false) {
            synced += 1;
        }
    }
    Ok(format!("File sync to {} ({} path(s))", target, synced))
}

#[cfg(target_os = "linux")]
fn run_file_sync(config: &BackupConfig) -> anyhow::Result<String> {
    use std::process::Stdio;
    let target = config.target.trim().trim_end_matches('/');
    let paths: Vec<String> = if config.include_paths.is_empty() {
        default_include_paths()
    } else {
        config.include_paths.clone()
    };

    let backup_root = format!("{}/OsoosiBackup", target);
    let _ = std::fs::create_dir_all(&backup_root);
    let mut synced = 0u32;
    for src in paths {
        if !std::path::Path::new(&src).exists() {
            continue;
        }
        let name = std::path::Path::new(&src)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("data");
        let dest = format!("{}/{}", backup_root, name);
        let status = Command::new("rsync")
            .args(["-a", "--delete", &src, &format!("{}/", dest)])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .status()?;
        if status.success() {
            synced += 1;
        }
    }
    Ok(format!("File sync to {} ({} path(s))", target, synced))
}

#[cfg(target_os = "macos")]
fn run_file_sync(config: &BackupConfig) -> anyhow::Result<String> {
    use std::process::Stdio;
    let target = config.target.trim().trim_end_matches('/');
    let paths: Vec<String> = if config.include_paths.is_empty() {
        default_include_paths()
    } else {
        config.include_paths.clone()
    };

    // rsync to configured target
    let backup_root = format!("{}/OsoosiBackup", target);
    let _ = std::fs::create_dir_all(&backup_root);
    let mut synced = 0u32;
    for src in paths {
        if !std::path::Path::new(&src).exists() {
            continue;
        }
        let name = std::path::Path::new(&src)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("data");
        let dest = format!("{}/{}", backup_root, name);
        let status = Command::new("rsync")
            .args(["-a", "--delete", &src, &format!("{}/", dest)])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .status()?;
        if status.success() {
            synced += 1;
        }
    }
    Ok(format!("File sync to {} ({} path(s))", target, synced))
}

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
fn run_file_sync(config: &BackupConfig) -> anyhow::Result<String> {
    let _ = config;
    Err(anyhow::anyhow!("Backup not implemented for this OS"))
}
