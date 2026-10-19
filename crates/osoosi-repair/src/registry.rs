use anyhow::{anyhow, Result};
#[cfg(target_os = "windows")]
use std::process::Command;
use tracing::{info, warn};
#[cfg(target_os = "windows")]
use winreg::enums::*;
#[cfg(target_os = "windows")]
use winreg::RegKey;

/// Registry and cross-platform persistence remediator.
/// Targeted at common 'Run' keys, 'Services', and Unix persistence paths created by malware.
pub struct RegistryRemediator;

impl RegistryRemediator {
    /// Attempt to roll back registry persistence for a specific process image.
    /// Scans Run, RunOnce, and Services (Windows) or ld.so.preload, cron, systemd, and launchd (Linux/macOS).
    pub fn remediate_process_persistence(image_path: &str) -> Result<Vec<String>> {
        let normalized = osoosi_types::normalize_nt_device_path(image_path);
        let lower = normalized.to_ascii_lowercase().replace('/', "\\");
        let basename = std::path::Path::new(&normalized)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        if basename.is_empty() {
            return Err(anyhow!("Invalid image path for persistence remediation"));
        }
        if osoosi_types::is_protected_os_shell_or_desktop_binary(&normalized)
            || osoosi_types::is_protected_os_shell_or_desktop_binary(basename)
            || lower.starts_with("c:\\windows\\")
            || lower.starts_with("\\windows\\")
            || normalized.starts_with("/usr/")
            || normalized.starts_with("/bin/")
            || normalized.starts_with("/sbin/")
            || normalized.starts_with("/lib/")
            || normalized.starts_with("/lib64/")
            || normalized.starts_with("/System/")
        {
            info!(
                "Host Safety Guard: Refusing to remediate persistence or disable services for protected OS binary: {}",
                image_path
            );
            return Ok(Vec::new());
        }

        #[cfg(not(target_os = "windows"))]
        {
            let mut changes = Vec::new();

            // 1. Scan and clean /etc/ld.so.preload
            let ld_preload = std::path::Path::new("/etc/ld.so.preload");
            if ld_preload.exists() {
                if let Ok(content) = std::fs::read_to_string(ld_preload) {
                    if content.contains(image_path) || content.contains(basename) {
                        let filtered: Vec<&str> = content
                            .lines()
                            .filter(|line| !line.contains(image_path) && !line.contains(basename))
                            .collect();
                        let new_content = filtered.join("\n");
                        if std::fs::write(ld_preload, new_content).is_ok() {
                            changes.push(format!("Removed {} from /etc/ld.so.preload", image_path));
                        }
                    }
                }
            }

            // 2. Scan persistence directories
            let dirs = [
                "/etc/cron.d",
                "/var/spool/cron/crontabs",
                "/etc/systemd/system",
                "/etc/xdg/autostart",
                "/Library/LaunchAgents",
                "/Library/LaunchDaemons",
            ];

            for dir in dirs {
                let dir_path = std::path::Path::new(dir);
                if dir_path.is_dir() {
                    if let Ok(entries) = std::fs::read_dir(dir_path) {
                        for entry in entries.filter_map(|e| e.ok()) {
                            let path = entry.path();
                            if path.is_file() {
                                if let Ok(content) = std::fs::read_to_string(&path) {
                                    if content.contains(image_path) || content.contains(basename) {
                                        if std::fs::remove_file(&path).is_ok() {
                                            changes.push(format!(
                                                "Removed malicious persistence file: {:?}",
                                                path
                                            ));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if changes.is_empty() {
                info!("No Linux/macOS persistence found for {}", image_path);
            } else {
                info!(
                    "Persistence remediation complete for {}: {:?}",
                    image_path, changes
                );
            }

            Ok(changes)
        }

        #[cfg(target_os = "windows")]
        {
            let mut changes = Vec::new();
            let basename = std::path::Path::new(image_path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");

            if basename.is_empty() {
                return Err(anyhow!("Invalid image path for registry remediation"));
            }

            // 1. Check 'Run' and 'RunOnce' keys
            let run_keys = [
                r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
                r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            ];

            for key in run_keys {
                match Self::find_and_delete_value(key, image_path) {
                    Ok(Some(val)) => changes.push(format!("Removed {} from {}", val, key)),
                    Ok(None) => {}
                    Err(e) => warn!("Failed to scan registry key {}: {}", key, e),
                }
            }

            // 2. Check for malicious services
            // We look for services whose ImagePath contains our target image.
            match Self::find_and_disable_service(image_path) {
                Ok(Some(svc)) => changes.push(format!("Disabled malicious service: {}", svc)),
                Ok(None) => {}
                Err(e) => warn!("Failed to scan services for {}: {}", image_path, e),
            }

            if changes.is_empty() {
                info!("No registry persistence found for {}", image_path);
            } else {
                info!(
                    "Registry remediation complete for {}: {:?}",
                    image_path, changes
                );
            }

            Ok(changes)
        }
    }

    #[cfg(target_os = "windows")]
    fn find_and_delete_value(key_path: &str, image_path: &str) -> Result<Option<String>> {
        let (root, path) = if key_path.starts_with("HKLM") {
            (RegKey::predef(HKEY_LOCAL_MACHINE), &key_path[5..])
        } else {
            (RegKey::predef(HKEY_CURRENT_USER), &key_path[5..])
        };

        let key = root.open_subkey_with_flags(path, KEY_READ | KEY_SET_VALUE)?;
        let mut deleted = Vec::new();

        for val in key.enum_values().filter_map(|x| x.ok()) {
            let (name, value) = val;
            let val_str = value.to_string().to_lowercase();
            if val_str.contains(&image_path.to_lowercase()) && key.delete_value(&name).is_ok() {
                deleted.push(name);
            }
        }

        if deleted.is_empty() {
            Ok(None)
        } else {
            Ok(Some(deleted.join(", ")))
        }
    }

    #[cfg(target_os = "windows")]
    fn find_and_disable_service(image_path: &str) -> Result<Option<String>> {
        // Enumerate services via registry instead of WMI/PowerShell for performance and reliability
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let services_key = hklm.open_subkey(r"SYSTEM\CurrentControlSet\Services")?;

        let mut disabled_services = Vec::new();
        let target_lower = image_path.to_lowercase();

        for name in services_key.enum_keys().filter_map(|x| x.ok()) {
            if let Ok(svc_key) =
                services_key.open_subkey_with_flags(&name, KEY_READ | KEY_SET_VALUE)
            {
                if let Ok(path) = svc_key.get_value::<String, _>("ImagePath") {
                    if path.to_lowercase().contains(&target_lower) {
                        // Disable service (Start = 4)
                        let _ = svc_key.set_value("Start", &4u32);
                        // Also try to stop it via sc.exe (standard command)
                        let _ = Command::new(osoosi_types::resolve_system_binary("sc.exe"))
                            .args(["stop", &name])
                            .status();
                        disabled_services.push(name);
                    }
                }
            }
        }

        if disabled_services.is_empty() {
            Ok(None)
        } else {
            Ok(Some(disabled_services.join(", ")))
        }
    }
}
