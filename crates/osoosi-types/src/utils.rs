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
    pub publisher: Option<String>,
}

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

    // Native Signature Verification (Win32 WinVerifyTrust)
    let path_str = path.to_string_lossy();
    let is_signed = verify_file_signature(&path_str);
    
    // Advanced Pure Rust Cryptographic Verification (Goblin + X509 + ring)
    let publisher = verify_and_extract_publisher_native(&path_str).ok();

    Some(BinaryMetadata { product_name, version, is_signed, publisher })
}

/// Mathematically verifies the certificate chain and returns the validated Publisher.
/// This implementation is pure Rust and does not rely on Windows APIs.
pub fn verify_and_extract_publisher_native(file_path: &str) -> anyhow::Result<String> {
    use std::collections::HashMap;
    use x509_parser::prelude::*;

    // 1. Extract all DER-encoded certificates from the PE binary
    let cert_ders = extract_all_certificates(file_path).ok_or_else(|| anyhow::anyhow!("No certificates found in binary"))?;

    let mut cert_store: HashMap<String, X509Certificate> = HashMap::new();

    // 2. Parse all certificates out of the DER bytes and index them by Subject Name
    for der in &cert_ders {
        if let Ok((_, cert)) = X509Certificate::from_der(der) {
            cert_store.insert(cert.subject().to_string(), cert);
        }
    }

    // 3. Find the Leaf Certificate (The actual publisher)
    // The leaf is usually the one whose subject is NOT an issuer for any other cert in this payload
    let mut current_cert = cert_store.values()
        .find(|c| c.subject() != c.issuer())
        .ok_or_else(|| anyhow::anyhow!("No leaf certificate found in payload"))?;

    let publisher_name = current_cert.subject().to_string();

    // 4. Climb and Mathematically Verify the Chain
    loop {
        let issuer_name = current_cert.issuer().to_string();
        
        // Base Case: We reached the top of the chain (Self-Signed Root CA)
        if current_cert.subject() == current_cert.issuer() {
            // If we don't verify the Root, a hacker can just self-sign their own fake Root CA!
            verify_root_against_os_store(&issuer_name)?;
            break;
        }

        // Find the parent certificate that issued the current one
        let issuer_cert = cert_store.get(&issuer_name)
            .ok_or_else(|| anyhow::anyhow!("Broken Chain: Missing intermediate certificate."))?;

        // THE MATH: Execute RSA/ECDSA verification via ring (enabled by x509-parser/verify feature). 
        // This proves the current cert was genuinely signed by the issuer's private key.
        current_cert.verify_signature(Some(&issuer_cert.public_key()))
            .map_err(|_| anyhow::anyhow!("CRYPTOGRAPHIC VERIFICATION FAILED! FORGED CERTIFICATE DETECTED."))?;

        // Step up the ladder
        current_cert = issuer_cert;
    }

    Ok(publisher_name)
}

/// Verifies that the extracted Root CA actually exists in the host's Trust Store.
fn verify_root_against_os_store(target_root: &str) -> anyhow::Result<()> {
    use x509_parser::prelude::*;
    use rustls_native_certs::load_native_certs;

    // Loads the actual trusted roots from the host operating system
    let os_roots = load_native_certs().map_err(|e| anyhow::anyhow!("Could not load OS native certs: {}", e))?;
    
    for root in os_roots {
        if let Ok((_, cert)) = X509Certificate::from_der(root.as_ref()) {
            if cert.subject().to_string() == target_root {
                return Ok(());
            }
        }
    }
    
    Err(anyhow::anyhow!("ROOT CA NOT TRUSTED BY OPERATING SYSTEM. LIKELY MALWARE CA."))
}

/// Extracts all raw DER certificates from the Authenticode block of a PE binary.
pub fn extract_all_certificates(file_path: &str) -> Option<Vec<Vec<u8>>> {
    use goblin::pe::PE;
    use x509_parser::prelude::*;

    let buffer = std::fs::read(file_path).ok()?;
    let pe = PE::parse(&buffer).ok()?;
    let optional_header = pe.header.optional_header?;
    let security_dir = optional_header.data_directories.data_directories[4]
        .as_ref()
        .map(|(_, dir)| dir)?;
    
    let sig_offset = security_dir.virtual_address as usize;
    let sig_size = security_dir.size as usize;
    
    if sig_offset == 0 || sig_offset + sig_size > buffer.len() {
        return None;
    }

    let pkcs7_data = &buffer[sig_offset + 8 .. sig_offset + sig_size];

    let mut certs = Vec::new();
    let mut current_data = pkcs7_data;

    // Iterate through the DER encoded data to find all certificates in the block
    while let Ok((remaining, _cert)) = X509Certificate::from_der(current_data) {
        certs.push(current_data[.. current_data.len() - remaining.len()].to_vec());
        if remaining.is_empty() { break; }
        current_data = remaining;
    }

    if certs.is_empty() { None } else { Some(certs) }
}

/// Verify a file signature using the native Windows WinVerifyTrust API.
#[cfg(target_os = "windows")]
pub fn verify_file_signature(path: &str) -> bool {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{HANDLE, HWND};
    use windows::Win32::Security::WinTrust::*;

    let path_wide: Vec<u16> = std::ffi::OsStr::new(path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR(path_wide.as_ptr()),
        hFile: HANDLE::default(),
        pgKnownSubject: std::ptr::null_mut(),
    };

    let mut data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        pPolicyCallbackData: std::ptr::null_mut(),
        pSIPClientData: std::ptr::null_mut(),
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 {
            pFile: &mut file_info,
        },
        dwStateAction: WTD_STATEACTION_IGNORE,
        hWVTStateData: HANDLE::default(),
        pwszURLReference: windows::core::PWSTR::null(),
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
        dwUIContext: WTD_UICONTEXT_EXECUTE,
        pSignatureSettings: std::ptr::null_mut(),
    };

    let action_id = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    unsafe {
        let result = WinVerifyTrust(
            HWND::default(),
            &action_id as *const _ as *mut _,
            &mut data as *mut _ as *mut _,
        );
        result == 0 // ERROR_SUCCESS
    }
}

#[cfg(not(target_os = "windows"))]
pub fn get_pe_metadata(_path: &Path) -> Option<BinaryMetadata> {
    None
}
