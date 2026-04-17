//! Patch Discovery Module
//!
//! Executes native OS commands to identify missing security patches.

use osoosi_types::{PatchMetadata, PatchSeverity};
use anyhow::{Result, anyhow};
use std::process::Command;
use tracing::{info, warn};

pub struct PatchDiscoverer;

impl Default for PatchDiscoverer {
    fn default() -> Self {
        Self::new()
    }
}

impl PatchDiscoverer {
    pub fn new() -> Self {
        Self
    }

    /// Discover missing security patches based on the host OS.
    pub async fn discover_missing_patches(&self) -> Result<Vec<PatchMetadata>> {
        #[cfg(target_os = "windows")]
        {
            self.discover_windows()
        }
        #[cfg(target_os = "linux")]
        {
            self.discover_linux()
        }
        #[cfg(target_os = "macos")]
        {
            self.discover_macos()
        }
        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            Err(anyhow!("Unsupported OS for patch discovery"))
        }
    }

    #[cfg(target_os = "windows")]
    fn discover_windows(&self) -> Result<Vec<PatchMetadata>> {
        info!("Querying Windows Update Agent for missing patches...");

        // Use ForEach-Object to properly serialize KBArticleIDs (COM object) to string
        let ps_script = r#"
$Session = New-Object -ComObject Microsoft.Update.Session
$Searcher = $Session.CreateUpdateSearcher()
$Result = $Searcher.Search('IsInstalled=0 and IsHidden=0')
$Result.Updates | ForEach-Object {
    $kb = if ($_.KBArticleIDs.Count -gt 0) { "KB$($_.KBArticleIDs.Item(0))" } else { $null }
    [PSCustomObject]@{
        Title = $_.Title
        Description = $_.Description
        KB = $kb
    }
} | ConvertTo-Json -Compress
"#;

        let output = Command::new("powershell")
            .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_script])
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("Access is denied") || stderr.contains("0x80070005") {
                warn!("Windows Update query requires elevation. Run as Administrator or add to Event Log Readers.");
            }
            return Err(anyhow!("PowerShell query failed: {}", stderr));
        }

        let json_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if json_str.is_empty() || json_str == "null" {
            return Ok(vec![]);
        }

        let patches = Self::parse_windows_updates_json(&json_str)?;
        info!("Windows discovery: {} pending updates", patches.len());
        Ok(patches)
    }

    #[cfg(target_os = "windows")]
    fn parse_windows_updates_json(json_str: &str) -> Result<Vec<PatchMetadata>> {
        let mut patches = Vec::new();
        let parsed: serde_json::Value = serde_json::from_str(json_str)
            .map_err(|e| anyhow!("Failed to parse Windows Update JSON: {}", e))?;

        let items = if parsed.is_array() {
            parsed.as_array().cloned().unwrap_or_default()
        } else if parsed.is_object() {
            vec![parsed]
        } else {
            return Ok(vec![]);
        };

        let mut skipped_non_kb: usize = 0;
        for item in items {
            let obj = item.as_object().ok_or_else(|| anyhow!("Expected object"))?;
            let title = obj.get("Title").and_then(|v| v.as_str()).unwrap_or("Unknown").to_string();
            let desc = obj.get("Description").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let kb = obj
                .get("KB")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .unwrap_or("");
            // Only keep real KB updates for transactional auto-apply on Windows.
            // Placeholder/non-KB updates are skipped to avoid invalid apply/rollback cycles.
            if !kb.to_ascii_uppercase().starts_with("KB") || kb.len() <= 2 {
                skipped_non_kb += 1;
                tracing::debug!(
                    title = %title,
                    "Skipping non-KB Windows update for auto-apply"
                );
                continue;
            }
            let kb = kb.to_string();
            patches.push(PatchMetadata {
                cve_id: kb.clone(),
                description: if desc.is_empty() { title.clone() } else { desc },
                severity: PatchSeverity::High,
                component: title,
                version: kb,
                download_url: None,
                expected_sha256: None,
            });
        }
        if skipped_non_kb > 0 {
            tracing::debug!(
                count = skipped_non_kb,
                "Windows discovery: skipped non-KB updates (not eligible for auto-apply)"
            );
        }
        Ok(patches)
    }

    #[cfg(target_os = "linux")]
    fn discover_linux(&self) -> Result<Vec<PatchMetadata>> {
        info!("Querying Linux package manager for security updates...");

        if self.command_exists("apt") {
            self.discover_apt()
        } else if self.command_exists("dnf") {
            self.discover_dnf()
        } else if self.command_exists("yum") {
            self.discover_yum()
        } else if self.command_exists("pacman") {
            self.discover_pacman()
        } else if self.command_exists("zypper") {
            self.discover_zypper()
        } else if self.command_exists("apk") {
            self.discover_apk()
        } else {
            warn!("No supported Linux package manager (apt/dnf/yum/pacman/zypper/apk) found.");
            Ok(vec![])
        }
    }

    #[cfg(target_os = "linux")]
    fn discover_apt(&self) -> Result<Vec<PatchMetadata>> {
        // apt-get --just-print upgrade
        let output = Command::new("apt-get")
            .args(["--just-print", "upgrade"])
            .env("DEBIAN_FRONTEND", "noninteractive")
            .output()?;

        if !output.status.success() {
            return Err(anyhow!("apt-get upgrade failed: {}", String::from_utf8_lossy(&output.stderr)));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut patches = Vec::new();
        let mut in_upgrade_section = false;

        for line in stdout.lines() {
            if line.contains("will be upgraded") {
                in_upgrade_section = true;
                continue;
            }
            if in_upgrade_section {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with("The following") {
                    break;
                }
                for pkg in trimmed.split_whitespace() {
                    let (name, _version) = pkg.split_once('/').unwrap_or((pkg, ""));
                    if !name.is_empty() && !name.starts_with('.') {
                        patches.push(PatchMetadata {
                            cve_id: format!("apt:{}", name),
                            description: format!("Update for {}", name),
                            severity: PatchSeverity::Medium,
                            component: name.to_string(),
                            version: "latest".to_string(),
                download_url: None,
                expected_sha256: None,
            });
                    }
                }
                break;
            }
        }

        // Fallback: apt list --upgradable
        if patches.is_empty() {
            let out = Command::new("apt")
                .args(["list", "--upgradable"])
                .env("DEBIAN_FRONTEND", "noninteractive")
                .output()?;
            if out.status.success() {
                let s = String::from_utf8_lossy(&out.stdout);
                for line in s.lines() {
                    if let Some(pkg_part) = line.splitn(2, '/').next() {
                        let pkg = pkg_part.trim();
                        if !pkg.is_empty() && !pkg.starts_with("Listing") {
                            patches.push(PatchMetadata {
                                cve_id: format!("apt:{}", pkg),
                                description: format!("Upgrade for {}", pkg),
                                severity: PatchSeverity::Medium,
                                component: pkg.to_string(),
                                version: "latest".to_string(),
                download_url: None,
                expected_sha256: None,
            });
                        }
                    }
                }
            }
        }

        info!("Apt discovery: {} upgradable packages", patches.len());
        Ok(patches)
    }

    #[cfg(target_os = "linux")]
    fn discover_dnf(&self) -> Result<Vec<PatchMetadata>> {
        // dnf updateinfo list sec
        let output = Command::new("dnf")
            .args(["updateinfo", "list", "sec"])
            .output()?;

        if !output.status.success() {
            return Err(anyhow!("dnf updateinfo failed: {}", String::from_utf8_lossy(&output.stderr)));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut patches = Vec::new();

        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                let advisory = parts[0];
                let severity_str = parts[1];
                let pkg = parts[2];
                let severity = if severity_str.contains("Critical") {
                    PatchSeverity::Critical
                } else if severity_str.contains("Important") {
                    PatchSeverity::High
                } else if severity_str.contains("Moderate") {
                    PatchSeverity::Medium
                } else {
                    PatchSeverity::Low
                };
                patches.push(PatchMetadata {
                    cve_id: advisory.to_string(),
                    description: format!("{} - {}", advisory, pkg),
                    severity,
                    component: pkg.to_string(),
                    version: advisory.to_string(),
                download_url: None,
                expected_sha256: None,
            });
            }
        }

        if patches.is_empty() {
            // Fallback: dnf check-update
            let out = Command::new("dnf")
                .args(["check-update"])
                .output()?;
            if out.status.code() == Some(100) {
                let s = String::from_utf8_lossy(&out.stdout);
                for line in s.lines() {
                    let pkg = line.split_whitespace().next().unwrap_or("");
                    if !pkg.is_empty() && !pkg.starts_with("Last") && !pkg.starts_with("Updates") {
                        patches.push(PatchMetadata {
                            cve_id: format!("dnf:{}", pkg),
                            description: format!("Update for {}", pkg),
                            severity: PatchSeverity::Medium,
                            component: pkg.to_string(),
                            version: "latest".to_string(),
                download_url: None,
                expected_sha256: None,
            });
                    }
                }
            }
        }

        info!("Dnf discovery: {} security/updatable packages", patches.len());
        Ok(patches)
    }

    #[cfg(target_os = "linux")]
    fn discover_yum(&self) -> Result<Vec<PatchMetadata>> {
        let output = Command::new("yum")
            .args(["updateinfo", "list", "security"])
            .output()?;

        if !output.status.success() {
            return Err(anyhow!("yum updateinfo failed: {}", String::from_utf8_lossy(&output.stderr)));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut patches = Vec::new();

        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                let advisory = parts[0];
                let severity_str = parts[1];
                let pkg = parts[2];
                let severity = if severity_str.contains("Critical") {
                    PatchSeverity::Critical
                } else if severity_str.contains("Important") {
                    PatchSeverity::High
                } else if severity_str.contains("Moderate") {
                    PatchSeverity::Medium
                } else {
                    PatchSeverity::Low
                };
                patches.push(PatchMetadata {
                    cve_id: advisory.to_string(),
                    description: format!("{} - {}", advisory, pkg),
                    severity,
                    component: pkg.to_string(),
                    version: advisory.to_string(),
                download_url: None,
                expected_sha256: None,
            });
            }
        }

        info!("Yum discovery: {} security packages", patches.len());
        Ok(patches)
    }

    #[cfg(target_os = "linux")]
    fn discover_pacman(&self) -> Result<Vec<PatchMetadata>> {
        info!("Querying pacman for updates...");
        let output = Command::new("pacman")
            .args(["-Qu"])
            .output()?;

        if !output.status.success() && output.status.code() != Some(1) {
            return Err(anyhow!("pacman -Qu failed: {}", String::from_utf8_lossy(&output.stderr)));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut patches = Vec::new();
        for line in stdout.lines() {
            let pkg = line.split_whitespace().next().unwrap_or("");
            if !pkg.is_empty() {
                patches.push(PatchMetadata {
                    cve_id: format!("pacman:{}", pkg),
                    description: format!("Package update for {}", pkg),
                    severity: PatchSeverity::Medium,
                    component: pkg.to_string(),
                    version: "latest".to_string(),
                download_url: None,
                expected_sha256: None,
            });
            }
        }
        info!("Pacman discovery: {} upgradable packages", patches.len());
        Ok(patches)
    }

    #[cfg(target_os = "linux")]
    fn discover_zypper(&self) -> Result<Vec<PatchMetadata>> {
        info!("Querying zypper for updates...");
        let output = Command::new("zypper")
            .args(["list-updates", "-t", "package"])
            .output()?;

        if !output.status.success() && output.status.code() != Some(101) {
            return Err(anyhow!("zypper list-updates failed: {}", String::from_utf8_lossy(&output.stderr)));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut patches = Vec::new();
        let mut in_table = false;
        for line in stdout.lines() {
            if line.starts_with("S |") || line.starts_with("--") {
                in_table = true;
                continue;
            }
            if in_table {
                let parts: Vec<&str> = line.split('|').collect();
                if parts.len() >= 3 {
                    let pkg = parts[2].trim();
                    if !pkg.is_empty() && !pkg.starts_with("Name") {
                        patches.push(PatchMetadata {
                            cve_id: format!("zypper:{}", pkg),
                            description: format!("Update for {}", pkg),
                            severity: PatchSeverity::Medium,
                            component: pkg.to_string(),
                            version: "latest".to_string(),
                download_url: None,
                expected_sha256: None,
            });
                    }
                }
            }
        }

        if patches.is_empty() {
            let out = Command::new("zypper")
                .args(["lu"])
                .output()?;
            if out.status.code() == Some(101) {
                let s = String::from_utf8_lossy(&out.stdout);
                for line in s.lines() {
                    let pkg = line.split_whitespace().next().unwrap_or("");
                    if !pkg.is_empty() && !pkg.starts_with("S") && !pkg.starts_with("--") && pkg != "v" {
                        patches.push(PatchMetadata {
                            cve_id: format!("zypper:{}", pkg),
                            description: format!("Update for {}", pkg),
                            severity: PatchSeverity::Medium,
                            component: pkg.to_string(),
                            version: "latest".to_string(),
                download_url: None,
                expected_sha256: None,
            });
                    }
                }
            }
        }
        info!("Zypper discovery: {} updatable packages", patches.len());
        Ok(patches)
    }

    #[cfg(target_os = "linux")]
    fn discover_apk(&self) -> Result<Vec<PatchMetadata>> {
        info!("Querying apk for updates...");
        let output = Command::new("apk")
            .args(["upgrade", "-s"])
            .output()?;

        if !output.status.success() {
            return Err(anyhow!("apk upgrade -s failed: {}", String::from_utf8_lossy(&output.stderr)));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut patches = Vec::new();
        for line in stdout.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("Upgrading") {
                let pkg = trimmed
                    .strip_prefix("Upgrading")
                    .unwrap_or(trimmed)
                    .split_whitespace()
                    .next()
                    .unwrap_or("");
                if !pkg.is_empty() {
                    patches.push(PatchMetadata {
                        cve_id: format!("apk:{}", pkg),
                        description: format!("Alpine package update for {}", pkg),
                        severity: PatchSeverity::Medium,
                        component: pkg.to_string(),
                        version: "latest".to_string(),
                download_url: None,
                expected_sha256: None,
            });
                }
            }
        }
        info!("Apk discovery: {} upgradable packages", patches.len());
        Ok(patches)
    }

    #[cfg(target_os = "macos")]
    fn discover_macos(&self) -> Result<Vec<PatchMetadata>> {
        info!("Querying macOS softwareupdate for missing patches...");

        let output = Command::new("softwareupdate")
            .args(["-l"])
            .output()?;

        if !output.status.success() {
            return Err(anyhow!("softwareupdate failed: {}", String::from_utf8_lossy(&output.stderr)));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut patches = Vec::new();
        let mut current_label = String::new();

        for line in stdout.lines() {
            let trimmed = line.trim();
            if (trimmed.starts_with('*') || trimmed.starts_with('-')) && trimmed.contains("Label:") {
                let label = trimmed
                    .split("Label:")
                    .nth(1)
                    .unwrap_or("")
                    .trim()
                    .to_string();
                if !label.is_empty() {
                    current_label = label;
                }
            } else if trimmed.starts_with("Title:") && !current_label.is_empty() {
                let title = trimmed
                    .trim_start_matches("Title:")
                    .split(',')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_string();
                let desc = if title.is_empty() {
                    format!("macOS update: {}", current_label)
                } else {
                    title
                };
                patches.push(PatchMetadata {
                    cve_id: format!("macos:{}", current_label),
                    description: desc,
                    severity: PatchSeverity::High,
                    component: current_label.clone(),
                    version: current_label.clone(),
                download_url: None,
                expected_sha256: None,
            });
                current_label.clear();
            }
        }

        info!("macOS discovery: {} updates available", patches.len());
        Ok(patches)
    }

    #[cfg(target_os = "linux")]
    fn command_exists(&self, cmd: &str) -> bool {
        Command::new("which")
            .arg(cmd)
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
}
