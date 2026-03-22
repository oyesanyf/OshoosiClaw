//! Cross-platform backup on agent start.
//! Windows: wbAdmin (full image), Checkpoint-Computer (restore point), Robocopy (file sync)
//! Linux: rsync
//! macOS: tmutil (Time Machine) or rsync

use osoosi_types::BackupConfig;
use std::process::Command;
use std::sync::Arc;
use tracing::{info, warn, error};

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
    if config.target.trim().is_empty() {
        warn!("Backup enabled but target is empty. Skipping.");
        if let Some(ref m) = memory {
            let _ = m.set_backup_status("status", "no_target");
            let _ = m.set_backup_status("message", "Target path is empty");
        }
        return;
    }

    let result = match config.backup_type.as_str() {
        "restore_point" => run_restore_point(config),
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
    use std::process::Stdio;
    let desc = format!("Osoosi pre-start {}", {
        let now = std::time::SystemTime::now();
        let secs = now.duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
        format!("{}", secs)
    });
    let status = Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &format!("Checkpoint-Computer -Description '{}' -RestorePointType MODIFY_SETTINGS", desc),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .status()?;
    if status.success() {
        Ok("System restore point created".to_string())
    } else {
        let stderr = String::new(); // We'd need to capture it
        Err(anyhow::anyhow!(
            "Checkpoint-Computer failed (may need Admin). Run PowerShell as Administrator. {}",
            stderr
        ))
    }
}

#[cfg(not(target_os = "windows"))]
fn run_restore_point(_config: &BackupConfig) -> anyhow::Result<String> {
    Err(anyhow::anyhow!("restore_point is Windows-only; use file_sync on this OS"))
}

#[cfg(target_os = "windows")]
fn run_full_image(config: &BackupConfig) -> anyhow::Result<String> {
    use std::process::Stdio;
    let target = config.target.trim().trim_end_matches('\\');
    let status = Command::new("wbadmin")
        .args([
            "start", "backup",
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
    Err(anyhow::anyhow!("full_image is Windows-only; use file_sync on this OS"))
}

fn default_include_paths() -> Vec<String> {
    #[cfg(target_os = "windows")]
    {
        let user = std::env::var("USERPROFILE").unwrap_or_else(|_| "C:\\Users\\Default".to_string());
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
        let dest = format!("{}\\OsoosiBackup\\{}", target, std::path::Path::new(src).file_name().and_then(|s| s.to_str()).unwrap_or("data"));
        let status = Command::new("robocopy")
            .args([src.as_str(), &dest, "/MIR", "/MT:8", "/R:1", "/W:1", "/NFL", "/NDL", "/NJH", "/NJS"])
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
        let name = std::path::Path::new(&src).file_name().and_then(|s| s.to_str()).unwrap_or("data");
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
        let name = std::path::Path::new(&src).file_name().and_then(|s| s.to_str()).unwrap_or("data");
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
