//! Version Utilities for OpenỌ̀ṣọ́ọ̀sì
//!
//! Extracts product version information from binary files to enable version-aware
//! threat detection and reduce false positives.

use std::path::Path;

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
    match win32_version_info::VersionInfo::from_file(path) {
        Ok(info) => {
            if info.product_version.is_empty() {
                if !info.file_version.is_empty() {
                    Some(info.file_version)
                } else {
                    None
                }
            } else {
                Some(info.product_version)
            }
        }
        Err(_) => None,
    }
}

#[cfg(not(target_os = "windows"))]
fn get_unix_file_version(_path: &Path) -> Option<String> {
    // Unix implementation would ideally check package manager (dpkg, rpm) or ELF headers.
    // Placeholder for now.
    None
}
