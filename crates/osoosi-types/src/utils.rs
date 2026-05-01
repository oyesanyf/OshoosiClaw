use std::fs::File;
use std::io::{self};
use std::path::Path;

/// Extract a ZIP archive to a destination directory using native Rust.
pub fn extract_zip(zip_path: &Path, dest_dir: &Path) -> anyhow::Result<()> {
    let file = File::open(zip_path)?;
    let mut archive = zip::ZipArchive::new(file)?;

    if !dest_dir.exists() {
        std::fs::create_dir_all(dest_dir)?;
    }

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let outpath = match file.enclosed_name() {
            Some(path) => dest_dir.join(path),
            None => continue,
        };

        if file.name().ends_with('/') {
            std::fs::create_dir_all(&outpath)?;
        } else {
            if let Some(p) = outpath.parent() {
                if !p.exists() {
                    std::fs::create_dir_all(p)?;
                }
            }
            let mut outfile = File::create(&outpath)?;
            io::copy(&mut file, &mut outfile)?;
        }

        // Set permissions if on Unix (best effort)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Some(mode) = file.unix_mode() {
                std::fs::set_permissions(&outpath, std::fs::Permissions::from_mode(mode))?;
            }
        }
    }

    Ok(())
}

/// Check if the current process is running with elevated privileges (Admin on Windows, root on Unix).
pub fn is_elevated() -> bool {
    #[cfg(target_os = "windows")]
    {
        use windows::Win32::Foundation::{CloseHandle, HANDLE};
        use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
        use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        unsafe {
            let mut token = HANDLE::default();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_ok() {
                let mut elevation = TOKEN_ELEVATION::default();
                let mut size = std::mem::size_of::<TOKEN_ELEVATION>() as u32;
                let res = GetTokenInformation(
                    token,
                    TokenElevation,
                    Some(&mut elevation as *mut _ as *mut _),
                    size,
                    &mut size,
                );
                let _ = CloseHandle(token);
                if res.is_ok() {
                    return elevation.TokenIsElevated != 0;
                }
            }
        }
        false
    }
    #[cfg(unix)]
    {
        unsafe { libc::getuid() == 0 }
    }
    #[cfg(not(any(target_os = "windows", unix)))]
    {
        false
    }
}
/// Add a directory or file path to Windows Defender exclusions.
/// Attempts native registry write only; no shell dependency.
pub fn add_defender_exclusion(path: &str) -> anyhow::Result<()> {
    #[cfg(target_os = "windows")]
    {
        use winreg::enums::*;
        use winreg::RegKey;

        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let key_path = r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths";

        if let Ok(key) = hklm.open_subkey_with_flags(key_path, KEY_WRITE) {
            if key.set_value(path, &0u32).is_ok() {
                return Ok(());
            }
        }
        return Err(anyhow::anyhow!(
            "Failed to add Defender exclusion for '{}' via native registry (requires elevation).",
            path
        ));
    }

    // Non-Windows: no-op, return Ok
    #[allow(unreachable_code)]
    {
        let _ = path;
        Ok(())
    }
}
/// Metadata and version info for a Windows PE file.
pub struct BinaryMetadata {
    pub product_name: String,
    pub version: String,
    pub is_signed: bool,
}

/// Extract metadata and version info from a Windows PE file.
#[cfg(target_os = "windows")]
pub fn get_pe_metadata(path: &Path) -> Option<BinaryMetadata> {
    use pelite::pe64::{Pe, PeFile};
    let map = std::fs::read(path).ok()?;
    let pe = PeFile::from_bytes(&map).ok()?;
    
    let mut product_name = "Unknown".to_string();
    let mut version = "0.0.0".to_string();

    if let Ok(resources) = pe.resources() {
        if let Ok(version_info) = resources.version_info() {
            if let Some(fixed) = version_info.fixed() {
                let v = fixed.dwFileVersion;
                version = format!("{}.{}.{}", v.Major, v.Minor, v.Patch);
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

    // Check for Signature (Simplified for Oshoosi)
    let security_dir = pe.data_directory()[pelite::image::IMAGE_DIRECTORY_ENTRY_SECURITY];
    let is_signed = security_dir.VirtualAddress != 0;

    Some(BinaryMetadata { product_name, version, is_signed })
}

#[cfg(not(target_os = "windows"))]
pub fn get_pe_metadata(_path: &Path) -> Option<BinaryMetadata> {
    None
}
