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

#[cfg(target_os = "windows")]
pub fn get_pe_product_info(path: &Path) -> Option<(String, String)> {
    use pelite::pe64::{Pe, PeFile};
    let map = std::fs::read(path).ok()?;
    let pe = PeFile::from_bytes(&map).ok()?;
    
    let mut product_name = String::new();
    let mut version_str = String::new();

    if let Ok(resources) = pe.resources() {
        if let Ok(version_info) = resources.version_info() {
            if let Some(fixed) = version_info.fixed() {
                let v = fixed.dwFileVersion;
                version_str = format!("{}.{}.{}", v.Major, v.Minor, v.Patch);
            }

            if let Some(lang) = version_info.translation().first() {
                version_info.strings(*lang, |key, value| {
                    if key == "ProductName" {
                        product_name = value.to_string();
                    }
                });
            }
        }
    }

    if !product_name.is_empty() && !version_str.is_empty() {
        Some((product_name, version_str))
    } else {
        None
    }
}

#[cfg(not(target_os = "windows"))]
pub fn get_pe_product_info(_path: &Path) -> Option<(String, String)> {
    None
}
