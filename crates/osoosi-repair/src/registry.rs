use std::process::Command;
use tracing::{info, warn};
use anyhow::{Result, anyhow};

/// Registry persistence remediator.
/// Targeted at common 'Run' keys and 'Services' created by malware.
pub struct RegistryRemediator;

impl RegistryRemediator {
    /// Attempt to roll back registry persistence for a specific process image.
    /// Scans Run, RunOnce, and Services for the given image path.
    pub fn remediate_process_persistence(image_path: &str) -> Result<Vec<String>> {
        #[cfg(not(target_os = "windows"))]
        {
            return Ok(vec!["Registry remediation only supported on Windows".to_string()]);
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
                    Ok(None) => {},
                    Err(e) => warn!("Failed to scan registry key {}: {}", key, e),
                }
            }

            // 2. Check for malicious services
            // We look for services whose ImagePath contains our target image.
            match Self::find_and_disable_service(image_path) {
                Ok(Some(svc)) => changes.push(format!("Disabled malicious service: {}", svc)),
                Ok(None) => {},
                Err(e) => warn!("Failed to scan services for {}: {}", image_path, e),
            }

            if changes.is_empty() {
                info!("No registry persistence found for {}", image_path);
            } else {
                info!("Registry remediation complete for {}: {:?}", image_path, changes);
            }

            Ok(changes)
        }
    }

    #[cfg(target_os = "windows")]
    fn find_and_delete_value(key: &str, image_path: &str) -> Result<Option<String>> {
        // Use powershell for easier registry filtering
        let script = format!(
            "Get-ItemProperty -Path 'Registry::{}' | Get-Member -MemberType NoteProperty | Where-Object {{ (Get-ItemProperty -Path 'Registry::{}').$($_.Name) -like '*{}*' }} | Select-Object -ExpandProperty Name",
            key, key, image_path.replace("'", "''")
        );

        let output = Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .output()?;

        if !output.status.success() {
            return Ok(None);
        }

        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if stdout.is_empty() {
            return Ok(None);
        }

        // Delete the identified values
        for val_name in stdout.lines() {
            let del_script = format!("Remove-ItemProperty -Path 'Registry::{}' -Name '{}' -Force", key, val_name);
            let _ = Command::new("powershell")
                .args(["-NoProfile", "-NonInteractive", "-Command", &del_script])
                .status();
        }

        Ok(Some(stdout))
    }

    #[cfg(target_os = "windows")]
    fn find_and_disable_service(image_path: &str) -> Result<Option<String>> {
        // Find services where ImagePath matches our target
        let script = format!(
            "Get-WmiObject win32_service | Where-Object {{ $_.PathName -like '*{}*' }} | Select-Object -ExpandProperty Name",
            image_path.replace("'", "''")
        );

        let output = Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .output()?;

        if !output.status.success() {
            return Ok(None);
        }

        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if stdout.is_empty() {
            return Ok(None);
        }

        // Disable and stop the identified services
        for svc_name in stdout.lines() {
            let _ = Command::new("sc.exe")
                .args(["stop", svc_name])
                .status();
            let _ = Command::new("sc.exe")
                .args(["config", svc_name, "start=", "disabled"])
                .status();
        }

        Ok(Some(stdout))
    }
}
