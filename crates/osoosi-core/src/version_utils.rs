//! Version Utilities for OpenỌ̀ṣọ́ọ̀sì
//! 
//! Extracts product version information from binary files to enable version-aware 
//! threat detection and reduce false positives.

use std::path::Path;
use std::process::Command;
use tracing::debug;

/// Resolve the product version of a file.
/// 
/// Uses platform-specific methods to extract version strings (e.g. FileVersionInfo on Windows).
pub fn get_file_version_info(path: &Path) -> Option<String> {
    if !path.exists() {
        return None;
    }

    #[cfg(target_os = "windows")]
    {
        get_windows_file_version(path)
    }
    #[cfg(not(target_os = "windows"))]
    {
        get_unix_file_version(path)
    }
}

#[cfg(target_os = "windows")]
fn get_windows_file_version(path: &Path) -> Option<String> {
    let path_str = path.to_string_lossy();
    
    // Use PowerShell to get the ProductVersion from FileVersionInfo.
    // This is more reliable than netsh or other tools for broad version extraction.
    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!("(Get-ItemProperty '{}').VersionInfo.ProductVersion", path_str)
        ])
        .output();

    match output {
        Ok(out) if out.status.success() => {
            let version = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if version.is_empty() {
                None
            } else {
                debug!("Resolved Windows version for {}: {}", path_str, version);
                Some(version)
            }
        }
        _ => None,
    }
}

#[cfg(not(target_os = "windows"))]
fn get_unix_file_version(_path: &Path) -> Option<String> {
    // Unix implementation would ideally check package manager (dpkg, rpm) or ELF headers.
    // Placeholder for now.
    None
}
