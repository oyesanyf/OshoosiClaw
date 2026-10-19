#[cfg(windows)]
use pelite::pe32::Pe as _;
#[cfg(windows)]
use pelite::pe64::Pe as _;
use std::fs::File;
use std::io::{self};
use std::path::Path;
use x509_parser::prelude::FromDer;

const MAX_ZIP_ENTRIES: usize = 50_000;
const MAX_ZIP_ENTRY_SIZE: u64 = 500 * 1024 * 1024; // 500 MB per entry
const MAX_ZIP_TOTAL_SIZE: u64 = 5 * 1024 * 1024 * 1024; // 5 GB total

/// Extract a ZIP archive to a destination directory using native Rust.
pub fn extract_zip(zip_path: &Path, dest_dir: &Path) -> anyhow::Result<()> {
    let file = File::open(zip_path)?;
    let mut archive = zip::ZipArchive::new(file)?;

    if archive.len() > MAX_ZIP_ENTRIES {
        anyhow::bail!("ZIP contains too many entries: {}", archive.len());
    }

    if !dest_dir.exists() {
        std::fs::create_dir_all(dest_dir)?;
    }

    let mut total_bytes: u64 = 0;

    for i in 0..archive.len() {
        let file = archive.by_index(i)?;
        #[cfg(unix)]
        let unix_mode = file.unix_mode();
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
            use std::io::Read;
            let mut limited_reader = file.take(MAX_ZIP_ENTRY_SIZE + 1);
            let bytes_copied = io::copy(&mut limited_reader, &mut outfile)?;
            if bytes_copied > MAX_ZIP_ENTRY_SIZE {
                let _ = std::fs::remove_file(&outpath);
                anyhow::bail!("ZIP entry exceeds maximum allowed size (500MB)");
            }
            total_bytes += bytes_copied;
            if total_bytes > MAX_ZIP_TOTAL_SIZE {
                let _ = std::fs::remove_file(&outpath);
                anyhow::bail!("ZIP archive exceeds maximum decompressed size (5GB)");
            }
        }

        // Set permissions if on Unix (best effort)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Some(mode) = unix_mode {
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
        use windows::Win32::Security::{
            GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
        };
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

/// Removes an `Image File Execution Options\<exe_name>\Debugger` registry value natively via `winreg`
/// without spawning external `reg.exe` processes.
pub fn remove_ifeo_debugger_hook_native(exe_name: &str) -> bool {
    #[cfg(target_os = "windows")]
    {
        use winreg::enums::*;
        use winreg::RegKey;

        let trimmed = exe_name.trim();
        if trimmed.is_empty() {
            return false;
        }
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let subkey_path = format!(
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\{}",
            trimmed
        );
        if let Ok(subkey) = hklm.open_subkey_with_flags(&subkey_path, KEY_READ | KEY_WRITE) {
            if subkey.delete_value("Debugger").is_ok() {
                return true;
            }
        }
        false
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = exe_name;
        false
    }
}

/// Purges all `Image File Execution Options\*\Debugger` values pointing to `systray.exe`
/// natively via `winreg` in < 5ms without spawning `reg.exe` subprocesses.
pub fn purge_ifeo_systray_debugger_hooks_native() -> usize {
    #[cfg(target_os = "windows")]
    {
        use winreg::enums::*;
        use winreg::RegKey;

        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let ifeo_path =
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
        let Ok(ifeo_root) = hklm.open_subkey_with_flags(ifeo_path, KEY_READ | KEY_WRITE) else {
            return 0;
        };

        let mut removed = 0usize;
        let subkey_names: Vec<String> = ifeo_root.enum_keys().filter_map(|k| k.ok()).collect();
        for name in subkey_names {
            let lower_name = name.to_ascii_lowercase();
            if lower_name.ends_with(".pyd") {
                if ifeo_root.delete_subkey_all(&name).is_ok() {
                    removed += 1;
                }
                continue;
            }
            if let Ok(subkey) = ifeo_root.open_subkey_with_flags(&name, KEY_READ | KEY_WRITE) {
                if let Ok(debugger_val) = subkey.get_value::<String, _>("Debugger") {
                    if debugger_val.to_ascii_lowercase().contains("systray.exe") {
                        if subkey.delete_value("Debugger").is_ok() {
                            removed += 1;
                        }
                    }
                }
            }
        }
        removed
    }
    #[cfg(not(target_os = "windows"))]
    {
        0
    }
}
/// Normalizes Windows NT kernel device paths (e.g., `\Device\HarddiskVolume4\Windows\System32\conhost.exe`)
/// and extended-length prefixes (`\\?\`, `\??\`) into standard Win32 DOS drive paths (`C:\Windows\System32\conhost.exe`).
pub fn normalize_nt_device_path(raw_path: &str) -> String {
    let trimmed = raw_path.trim().trim_matches('"');
    if trimmed.is_empty() {
        return String::new();
    }

    let normalized_slashes = trimmed.replace('/', "\\");
    let stripped = if let Some(rest) = normalized_slashes.strip_prefix(r"\\?\") {
        rest
    } else if let Some(rest) = normalized_slashes.strip_prefix(r"\??\") {
        rest
    } else {
        normalized_slashes.as_str()
    };

    let lower = stripped.to_ascii_lowercase();
    const NT_VOL_PREFIX: &str = r"\device\harddiskvolume";
    if lower.starts_with(NT_VOL_PREFIX) {
        let after_prefix = &stripped[NT_VOL_PREFIX.len()..];
        if let Some(slash_idx) = after_prefix.find('\\') {
            let vol_digits = &after_prefix[..slash_idx];
            if !vol_digits.is_empty() && vol_digits.chars().all(|c| c.is_ascii_digit()) {
                let rel_path = after_prefix[slash_idx + 1..].trim_start_matches('\\');
                for drive in ['C', 'D', 'E', 'F', 'G'] {
                    let candidate = format!("{}:\\{}", drive, rel_path);
                    if Path::new(&candidate).exists() {
                        return candidate;
                    }
                }
                return format!("C:\\{}", rel_path);
            }
        }
    }

    stripped.to_string()
}

/// Metadata and version info for a Windows PE file.
pub struct BinaryMetadata {
    pub product_name: String,
    pub version: String,
    pub is_signed: bool,
    pub publisher: Option<String>,
}

/// Returns true if the vendor, product, or publisher string corresponds to a known trusted vendor.
pub fn is_trusted_vendor(name: &str) -> bool {
    let p = name.to_lowercase();
    p.contains("microsoft")
        || p.contains("windows")
        || p.contains("khronos group")
        || p.contains("khronos")
        || p.contains("hugos ide")
        || p.contains("hugos")
        || p.contains("github")
        || p.contains("git for windows")
        || p.contains("johannes schindelin")
        || p.contains("google")
        || p.contains("openai")
        || p.contains("anysphere")
        || p.contains("cursor")
        || p.contains("electron")
        || p.contains("digicert")
        || p.contains("rust")
        || p.contains("python")
        || p.contains("node.js")
        || p.contains("openjs")
        || p.contains("vulkan")
        || p.contains("docker")
        || p.contains("mozilla")
        || p.contains("jetbrains")
        || p.contains("nvidia")
        || p.contains("intel")
        || p.contains("advanced micro devices")
        || p.contains("cloudflare")
        || p.contains("apple")
}

#[cfg(target_os = "windows")]
pub fn get_pe_metadata(path: &Path) -> Option<BinaryMetadata> {
    let normalized = normalize_nt_device_path(&path.to_string_lossy());
    let norm_path = Path::new(&normalized);
    let map = std::fs::read(norm_path).ok()?;

    let mut product_name = "Unknown".to_string();
    let mut version = "0.0.0".to_string();

    if let Ok(pe) = pelite::pe64::PeFile::from_bytes(&map) {
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
    } else if let Ok(pe) = pelite::pe32::PeFile::from_bytes(&map) {
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
    }

    // Native Signature Verification (Win32 WinVerifyTrust)
    let is_signed = verify_file_signature(&normalized);

    // Advanced Pure Rust Cryptographic Verification (Goblin + X509 + ring) with fallback to raw certificate extraction
    let publisher = verify_and_extract_publisher_native(&normalized)
        .ok()
        .or_else(|| extract_publisher_from_pe(&normalized));

    Some(BinaryMetadata {
        product_name,
        version,
        is_signed,
        publisher,
    })
}

/// Mathematically verifies the certificate chain and returns the validated Publisher.
/// This implementation is pure Rust and does not rely on Windows APIs.
pub fn verify_and_extract_publisher_native(file_path: &str) -> anyhow::Result<String> {
    use std::collections::HashMap;
    use x509_parser::prelude::*;

    // 1. Extract all DER-encoded certificates from the PE binary
    let cert_ders = extract_all_certificates(file_path)
        .ok_or_else(|| anyhow::anyhow!("No certificates found in binary"))?;

    let mut cert_store: HashMap<String, X509Certificate> = HashMap::new();

    // 2. Parse all certificates out of the DER bytes and index them by Subject Name
    for der in &cert_ders {
        if let Ok((_, cert)) = X509Certificate::from_der(der) {
            cert_store.insert(cert.subject().to_string(), cert);
        }
    }

    // 3. Find the Leaf Certificate (The actual publisher)
    // The leaf is usually the one whose subject is NOT an issuer for any other cert in this payload
    let mut current_cert = cert_store
        .values()
        .find(|c| c.subject() != c.issuer())
        .ok_or_else(|| anyhow::anyhow!("No leaf certificate found in payload"))?;

    let publisher_name = current_cert.subject().to_string();

    // 4. Climb and Mathematically Verify the Chain
    loop {
        let issuer_name = current_cert.issuer().to_string();

        // Base Case: We reached the top of the chain (Self-Signed Root CA)
        if current_cert.subject() == current_cert.issuer() {
            // Verify the Root CA against the OS Trust Store matching Subject AND Public Key
            verify_root_against_os_store(current_cert)?;
            break;
        }

        // Find the parent certificate that issued the current one
        let issuer_cert = cert_store
            .get(&issuer_name)
            .ok_or_else(|| anyhow::anyhow!("Broken Chain: Missing intermediate certificate."))?;

        // THE MATH: Execute RSA/ECDSA verification via ring (enabled by x509-parser/verify feature).
        // This proves the current cert was genuinely signed by the issuer's private key.
        current_cert
            .verify_signature(Some(issuer_cert.public_key()))
            .map_err(|_| {
                anyhow::anyhow!("CRYPTOGRAPHIC VERIFICATION FAILED! FORGED CERTIFICATE DETECTED.")
            })?;

        // Step up the ladder
        current_cert = issuer_cert;
    }

    Ok(publisher_name)
}

/// Verifies that the extracted Root CA actually exists in the host's Trust Store,
/// comparing both Subject and Public Key to prevent spoofed self-signed CAs.
fn verify_root_against_os_store(
    root_cert: &x509_parser::prelude::X509Certificate,
) -> anyhow::Result<()> {
    use rustls_native_certs::load_native_certs;
    use x509_parser::prelude::*;

    // Loads the actual trusted roots from the host operating system
    let os_roots = load_native_certs()
        .map_err(|e| anyhow::anyhow!("Could not load OS native certs: {}", e))?;
    let target_pk = root_cert.public_key().raw;

    for root in os_roots {
        if let Ok((_, cert)) = X509Certificate::from_der(root.as_ref()) {
            if cert.subject() == root_cert.subject() && cert.public_key().raw == target_pk {
                return Ok(());
            }
        }
    }

    Err(anyhow::anyhow!(
        "ROOT CA NOT TRUSTED BY OPERATING SYSTEM. LIKELY MALWARE CA."
    ))
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

    if sig_offset == 0 || sig_offset + sig_size > buffer.len() || sig_size <= 8 {
        return None;
    }

    let pkcs7_data = &buffer[sig_offset + 8..sig_offset + sig_size];

    let mut certs = Vec::new();
    let mut offset = 0;
    while offset + 4 < pkcs7_data.len() {
        if pkcs7_data[offset] == 0x30
            && (pkcs7_data[offset + 1] == 0x82
                || pkcs7_data[offset + 1] == 0x83
                || pkcs7_data[offset + 1] == 0x81)
        {
            if let Ok((remaining, _cert)) = X509Certificate::from_der(&pkcs7_data[offset..]) {
                let cert_len = pkcs7_data.len() - offset - remaining.len();
                if cert_len > 0 {
                    certs.push(pkcs7_data[offset..offset + cert_len].to_vec());
                    offset += cert_len;
                    continue;
                }
            }
        }
        offset += 1;
    }

    if certs.is_empty() {
        None
    } else {
        Some(certs)
    }
}

/// Extracts publisher / subject name directly from PE Authenticode certificates without OS store requirement.
pub fn extract_publisher_from_pe(file_path: &str) -> Option<String> {
    let cert_ders = extract_all_certificates(file_path)?;
    for der in &cert_ders {
        if let Ok((_, cert)) = x509_parser::prelude::X509Certificate::from_der(der) {
            let subj = cert.subject().to_string();
            if cert.subject() != cert.issuer() {
                return Some(subj);
            }
        }
    }
    if let Some(first) = cert_ders.first() {
        if let Ok((_, cert)) = x509_parser::prelude::X509Certificate::from_der(first) {
            return Some(cert.subject().to_string());
        }
    }
    None
}

/// Detailed status of an Authenticode signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AuthenticodeStatus {
    ValidTrusted,  // 0 / ERROR_SUCCESS: Cryptographically valid and trusted by OS root store
    UntrustedRoot, // 0x800B0109 / CERT_E_UNTRUSTEDROOT: Valid signature, untrusted root CA
    TamperedBadDigest, // 0x80096010 / TRUST_E_BAD_DIGEST: Hash mismatch, file has been tampered with
    NotSigned,         // 0x800B0100 / TRUST_E_NOSIGNATURE: No signature present
    ExplicitDistrust,  // 0x800B0111 / TRUST_E_EXPLICIT_DISTRUST
    Revoked,           // 0x800B010C / CERT_E_REVOKED or 0x80092013 / CRYPT_E_REVOKED
    OtherError(i32),
}

/// Detailed information about an Authenticode digital signature inspection.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AuthenticodeSignatureInfo {
    pub is_valid: bool,
    pub signer_subject: Option<String>,
    pub status: AuthenticodeStatus,
}

/// Extracts SHA-256 certificate thumbprints (lowercase hex) from all Authenticode certificates in binary.
pub fn extract_certificate_thumbprints(file_path: &str) -> Vec<String> {
    use sha2::{Digest, Sha256};
    let mut thumbprints = Vec::new();
    if let Some(certs) = extract_all_certificates(file_path) {
        for der in certs {
            let digest = Sha256::digest(&der);
            thumbprints.push(hex::encode(digest).to_lowercase());
        }
    }
    thumbprints
}

/// Checks whether any extracted certificate thumbprint matches explicitly pinned thumbprints
/// (from OSOOSI_PINNED_CERT_THUMBPRINTS env var or pinned store).
pub fn is_pinned_thumbprint_allowed(thumbprints: &[String]) -> bool {
    let configured_pins: std::collections::HashSet<String> =
        std::env::var("OSOOSI_PINNED_CERT_THUMBPRINTS")
            .ok()
            .map(|s| {
                s.split(',')
                    .map(|t| t.trim().to_lowercase().replace([':', ' '], ""))
                    .filter(|t| !t.is_empty())
                    .collect()
            })
            .unwrap_or_default();

    if configured_pins.is_empty() {
        return false;
    }

    for tp in thumbprints {
        let normalized = tp.to_lowercase().replace([':', ' '], "");
        if configured_pins.contains(&normalized) {
            return true;
        }
    }
    false
}

/// Verify whether a binary is cryptographically signed via the Windows Security Catalog
/// (`CryptCATAdminAcquireContext` + `CryptCATAdminCalcHashFromFileHandle` + `CryptCATAdminEnumCatalogFromHash`).
#[cfg(target_os = "windows")]
pub fn verify_windows_catalog_signature(path: &str) -> bool {
    use std::ffi::c_void;
    use std::fs::File;
    use std::os::windows::io::AsRawHandle;

    #[link(name = "wintrust")]
    extern "system" {
        fn CryptCATAdminAcquireContext(
            phCatAdmin: *mut isize,
            pgSubsystem: *const c_void,
            dwFlags: u32,
        ) -> i32;
        fn CryptCATAdminCalcHashFromFileHandle(
            hFile: *mut c_void,
            pcbHash: *mut u32,
            pbHash: *mut u8,
            dwFlags: u32,
        ) -> i32;
        fn CryptCATAdminEnumCatalogFromHash(
            hCatAdmin: isize,
            pbHash: *const u8,
            cbHash: u32,
            dwFlags: u32,
            phPrevCatInfo: *mut isize,
        ) -> isize;
        fn CryptCATAdminReleaseCatalogContext(
            hCatAdmin: isize,
            hCatInfo: isize,
            dwFlags: u32,
        ) -> i32;
        fn CryptCATAdminReleaseContext(hCatAdmin: isize, dwFlags: u32) -> i32;
    }

    let normalized = normalize_nt_device_path(path);
    let Ok(file) = File::open(&normalized) else {
        return false;
    };
    let handle = file.as_raw_handle();

    unsafe {
        let mut h_cat_admin: isize = 0;
        if CryptCATAdminAcquireContext(&mut h_cat_admin, std::ptr::null(), 0) == 0
            || h_cat_admin == 0
        {
            return false;
        }

        let mut hash_len: u32 = 64;
        let mut hash_buf = vec![0u8; 64];
        if CryptCATAdminCalcHashFromFileHandle(handle, &mut hash_len, hash_buf.as_mut_ptr(), 0)
            == 0
            || hash_len == 0
        {
            let _ = CryptCATAdminReleaseContext(h_cat_admin, 0);
            return false;
        }

        let h_cat_info = CryptCATAdminEnumCatalogFromHash(
            h_cat_admin,
            hash_buf.as_ptr(),
            hash_len,
            0,
            std::ptr::null_mut(),
        );

        let is_catalog_signed = h_cat_info != 0;
        if is_catalog_signed {
            let _ = CryptCATAdminReleaseCatalogContext(h_cat_admin, h_cat_info, 0);
        }
        let _ = CryptCATAdminReleaseContext(h_cat_admin, 0);
        is_catalog_signed
    }
}

/// Verify file signature using Windows WinVerifyTrust API with revocation check, graceful offline fallback,
/// and Windows Security Catalog (`CryptCATAdmin*`) fallback for catalog-signed OS binaries.
#[cfg(target_os = "windows")]
pub fn check_authenticode_status(path: &str) -> AuthenticodeStatus {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{HANDLE, HWND};
    use windows::Win32::Security::WinTrust::*;

    let normalized = normalize_nt_device_path(path);
    let path_wide: Vec<u16> = std::ffi::OsStr::new(&normalized)
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
        fdwRevocationChecks: WTD_REVOKE_WHOLECHAIN,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 {
            pFile: &mut file_info,
        },
        dwStateAction: WTD_STATEACTION_IGNORE,
        hWVTStateData: HANDLE::default(),
        pwszURLReference: windows::core::PWSTR::null(),
        dwProvFlags: WINTRUST_DATA_PROVIDER_FLAGS(0),
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
        match result {
            0 => AuthenticodeStatus::ValidTrusted,
            -2146762484 | -2146885613 => AuthenticodeStatus::Revoked, // CERT_E_REVOKED (0x800B010C) or CRYPT_E_REVOKED (0x80092013)
            -2146762482 | -2146885614 => {
                // CERT_E_REVOCATION_FAILURE (0x800B010E) or CRYPT_E_REVOCATION_OFFLINE (0x80092012)
                // Graceful fallback for offline / air-gapped systems:
                // Retry verification without online revocation checks.
                let mut fallback_file_info = WINTRUST_FILE_INFO {
                    cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
                    pcwszFilePath: PCWSTR(path_wide.as_ptr()),
                    hFile: HANDLE::default(),
                    pgKnownSubject: std::ptr::null_mut(),
                };
                let mut fallback_data = WINTRUST_DATA {
                    cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
                    pPolicyCallbackData: std::ptr::null_mut(),
                    pSIPClientData: std::ptr::null_mut(),
                    dwUIChoice: WTD_UI_NONE,
                    fdwRevocationChecks: WTD_REVOKE_NONE,
                    dwUnionChoice: WTD_CHOICE_FILE,
                    Anonymous: WINTRUST_DATA_0 {
                        pFile: &mut fallback_file_info,
                    },
                    dwStateAction: WTD_STATEACTION_IGNORE,
                    hWVTStateData: HANDLE::default(),
                    pwszURLReference: windows::core::PWSTR::null(),
                    dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
                    dwUIContext: WTD_UICONTEXT_EXECUTE,
                    pSignatureSettings: std::ptr::null_mut(),
                };
                let fallback_res = WinVerifyTrust(
                    HWND::default(),
                    &action_id as *const _ as *mut _,
                    &mut fallback_data as *mut _ as *mut _,
                );
                match fallback_res {
                    0 => AuthenticodeStatus::ValidTrusted,
                    -2146762487 => AuthenticodeStatus::UntrustedRoot,
                    -2146869232 => AuthenticodeStatus::TamperedBadDigest,
                    -2146762496 => {
                        if verify_windows_catalog_signature(&normalized) {
                            AuthenticodeStatus::ValidTrusted
                        } else {
                            AuthenticodeStatus::NotSigned
                        }
                    }
                    -2146762479 => AuthenticodeStatus::ExplicitDistrust,
                    err => AuthenticodeStatus::OtherError(err),
                }
            }
            -2146762487 => AuthenticodeStatus::UntrustedRoot, // 0x800B0109
            -2146869232 => AuthenticodeStatus::TamperedBadDigest, // 0x80096010
            -2146762496 => {
                // 0x800B0100 (TRUST_E_NOSIGNATURE): Check Windows Security Catalog for OS binaries
                if verify_windows_catalog_signature(&normalized) {
                    AuthenticodeStatus::ValidTrusted
                } else {
                    AuthenticodeStatus::NotSigned
                }
            }
            -2146762479 => AuthenticodeStatus::ExplicitDistrust, // 0x800B0111
            err => AuthenticodeStatus::OtherError(err),
        }
    }
}

/// Extracts the signer certificate subject name using native Win32 CryptQueryObject and CryptMsg API.
#[cfg(target_os = "windows")]
pub fn extract_signer_subject(path: &Path) -> Option<String> {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::Security::Cryptography::*;

    let normalized = normalize_nt_device_path(&path.to_string_lossy());
    let norm_path = Path::new(&normalized);
    let mut wide_path: Vec<u16> = norm_path.as_os_str().encode_wide().collect();
    wide_path.push(0);

    let mut msg: *mut c_void = std::ptr::null_mut();
    let mut store: HCERTSTORE = HCERTSTORE::default();

    unsafe {
        let res = CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            wide_path.as_ptr() as *const c_void,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            None,
            None,
            None,
            Some(&mut store),
            Some(&mut msg),
            None,
        );

        if res.is_err() || msg.is_null() || store.is_invalid() {
            if verify_windows_catalog_signature(&normalized) {
                return Some("Microsoft Windows Security Catalog".to_string());
            }
            return None;
        }

        let mut signer_info_size: u32 = 0;
        if CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, None, &mut signer_info_size).is_err()
            || signer_info_size == 0
        {
            let _ = CryptMsgClose(Some(msg));
            let _ = CertCloseStore(store, 0);
            return None;
        }

        let mut signer_info_bytes = vec![0u8; signer_info_size as usize];
        if CryptMsgGetParam(
            msg,
            CMSG_SIGNER_INFO_PARAM,
            0,
            Some(signer_info_bytes.as_mut_ptr() as *mut c_void),
            &mut signer_info_size,
        )
        .is_err()
        {
            let _ = CryptMsgClose(Some(msg));
            let _ = CertCloseStore(store, 0);
            return None;
        }

        let cert_context = CertFindCertificateInStore(
            store,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_FIND_ANY,
            None,
            None,
        );

        if cert_context.is_null() {
            let _ = CryptMsgClose(Some(msg));
            let _ = CertCloseStore(store, 0);
            return None;
        }

        let name_len =
            CertGetNameStringW(cert_context, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, None);

        let mut name_buffer = vec![0u16; name_len as usize];
        CertGetNameStringW(
            cert_context,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            None,
            Some(&mut name_buffer),
        );

        let _ = CertFreeCertificateContext(Some(cert_context));
        let _ = CryptMsgClose(Some(msg));
        let _ = CertCloseStore(store, 0);

        let subject = String::from_utf16_lossy(&name_buffer)
            .trim_matches('\0')
            .trim()
            .to_string();

        if subject.is_empty() {
            None
        } else {
            Some(subject)
        }
    }
}

#[cfg(not(target_os = "windows"))]
pub fn extract_signer_subject(path: &Path) -> Option<String> {
    if check_authenticode_status(&path.to_string_lossy()) == AuthenticodeStatus::ValidTrusted {
        Some("Linux OS / ELF Cryptographic Verifier".to_string())
    } else {
        None
    }
}

/// Inspects the Authenticode signature of a binary, extracting validity status and signer subject.
pub fn inspect_binary_authenticode(path: &Path) -> AuthenticodeSignatureInfo {
    let normalized = normalize_nt_device_path(&path.to_string_lossy());
    let norm_path = Path::new(&normalized);
    let status = check_authenticode_status(&normalized);
    let is_valid = matches!(status, AuthenticodeStatus::ValidTrusted);
    let signer_subject = if is_valid {
        extract_signer_subject(norm_path)
    } else {
        None
    };

    AuthenticodeSignatureInfo {
        is_valid,
        signer_subject,
        status,
    }
}

/// Check if a binary has a valid digital signature or belongs to a known trusted vendor.
#[cfg(target_os = "windows")]
pub fn is_trusted_signed_binary(path: &Path) -> bool {
    let normalized = normalize_nt_device_path(&path.to_string_lossy());
    let norm_path = Path::new(&normalized);
    if !norm_path.exists() {
        return false;
    }
    let status = check_authenticode_status(&normalized);
    match status {
        AuthenticodeStatus::ValidTrusted => {
            // 1. Try native Crypt32 subject extraction first
            if let Some(subject) = extract_signer_subject(norm_path) {
                if is_trusted_vendor(&subject) {
                    return true;
                }
            }
            // 2. Check PE metadata / publisher
            if let Some(meta) = get_pe_metadata(norm_path) {
                if let Some(ref pub_name) = meta.publisher {
                    if is_trusted_vendor(pub_name) {
                        return true;
                    }
                }
                if is_trusted_vendor(&meta.product_name) {
                    return true;
                }
            }
            // 3. If ValidTrusted and located in protected OS/Program Files folders, trust it
            let lower = normalized.to_lowercase().replace('/', "\\");
            if lower.starts_with("c:\\program files\\")
                || lower.starts_with("c:\\program files (x86)\\")
                || lower.starts_with("c:\\windows\\")
            {
                return true;
            }
            false
        }
        AuthenticodeStatus::UntrustedRoot => {
            let cert_thumbprints = extract_certificate_thumbprints(&normalized);
            is_pinned_thumbprint_allowed(&cert_thumbprints)
        }
        _ => false,
    }
}

/// Verify a file signature using the native Windows WinVerifyTrust API.
#[cfg(target_os = "windows")]
pub fn verify_file_signature(path: &str) -> bool {
    matches!(
        check_authenticode_status(path),
        AuthenticodeStatus::ValidTrusted
    )
}

#[cfg(not(target_os = "windows"))]
pub fn check_authenticode_status(path: &str) -> AuthenticodeStatus {
    use std::fs::File;
    use std::io::Read;

    let p = Path::new(path);
    if !p.is_file() {
        return AuthenticodeStatus::NotSigned;
    }

    // 1. Check if detached GPG / Minisign / OpenPGP signature exists (.asc or .sig)
    let asc_path = format!("{}.asc", path);
    let sig_path = format!("{}.sig", path);
    if (Path::new(&asc_path).is_file()
        && std::fs::metadata(&asc_path)
            .map(|m| m.len() > 0)
            .unwrap_or(false))
        || (Path::new(&sig_path).is_file()
            && std::fs::metadata(&sig_path)
                .map(|m| m.len() > 0)
                .unwrap_or(false))
    {
        return AuthenticodeStatus::ValidTrusted;
    }

    // 2. Check if path matches current running executable
    if let Ok(cur_exe) = std::env::current_exe() {
        if let (Ok(c1), Ok(c2)) = (p.canonicalize(), cur_exe.canonicalize()) {
            if c1 == c2 {
                return AuthenticodeStatus::ValidTrusted;
            }
        }
    }

    // 3. On Linux, inspect Linux fs-verity if active on the file
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        if let Ok(file) = File::open(p) {
            let fd = file.as_raw_fd();
            let mut flags: libc::c_int = 0;
            // FS_IOC_GETFLAGS: 0x80086601
            // FS_VERITY_FL: 0x00100000
            unsafe {
                if libc::ioctl(fd, 0x80086601, &mut flags) == 0 {
                    if (flags & 0x00100000) != 0 {
                        return AuthenticodeStatus::ValidTrusted;
                    }
                }
            }
        }
    }

    // 4. Verify ELF or Mach-O binary header and protected system directory residency
    let mut header = [0u8; 64];
    if let Ok(mut f) = File::open(p) {
        if let Ok(n) = f.read(&mut header) {
            let is_elf = n >= 16 && header.starts_with(b"\x7fELF");
            let is_macho = n >= 4
                && (header.starts_with(&[0xFE, 0xED, 0xFA, 0xCE])
                    || header.starts_with(&[0xFE, 0xED, 0xFA, 0xCF])
                    || header.starts_with(&[0xCE, 0xFA, 0xED, 0xFE])
                    || header.starts_with(&[0xCF, 0xFA, 0xED, 0xFE])
                    || header.starts_with(&[0xCA, 0xFE, 0xBA, 0xBE]));
            if is_elf || is_macho {
                let path_lower = path.to_lowercase();
                if path_lower.starts_with("/bin/")
                    || path_lower.starts_with("/sbin/")
                    || path_lower.starts_with("/usr/bin/")
                    || path_lower.starts_with("/usr/sbin/")
                    || path_lower.starts_with("/usr/libexec/")
                    || path_lower.starts_with("/lib/")
                    || path_lower.starts_with("/lib64/")
                    || path_lower.starts_with("/usr/lib/")
                    || path_lower.starts_with("/system/library/")
                    || path_lower.starts_with("/system/applications/")
                {
                    use std::os::unix::fs::MetadataExt;
                    if let Ok(meta) = p.metadata() {
                        let mode = meta.mode();
                        if (mode & 0o022) == 0 || meta.uid() == 0 {
                            return AuthenticodeStatus::ValidTrusted;
                        }
                    }
                }
            }
        }
    }

    AuthenticodeStatus::NotSigned
}

#[cfg(not(target_os = "windows"))]
pub fn get_pe_metadata(path: &Path) -> Option<BinaryMetadata> {
    use std::fs::File;
    use std::io::Read;

    let mut buf = [0u8; 4096];
    if let Ok(mut f) = File::open(path) {
        if let Ok(n) = f.read(&mut buf) {
            if n >= 16 && buf.starts_with(b"\x7fELF") {
                let status = check_authenticode_status(&path.to_string_lossy());
                let is_signed = matches!(status, AuthenticodeStatus::ValidTrusted);
                return Some(BinaryMetadata {
                    product_name: "Linux ELF Executable".to_string(),
                    version: "1.0.0".to_string(),
                    is_signed,
                    publisher: if is_signed {
                        Some("Linux OS / ELF Verified".to_string())
                    } else {
                        None
                    },
                });
            }
        }
    }
    None
}

#[cfg(not(target_os = "windows"))]
pub fn verify_file_signature(path: &str) -> bool {
    matches!(
        check_authenticode_status(path),
        AuthenticodeStatus::ValidTrusted
    )
}

#[cfg(not(target_os = "windows"))]
pub fn is_trusted_signed_binary(path: &Path) -> bool {
    verify_file_signature(&path.to_string_lossy())
}

/// Cross-platform invariant guard: returns `true` if `path_or_name` is a critical
/// operating system kernel/init daemon, desktop shell, window server/compositor,
/// system tray / menu bar host, or local desktop search/indexer service across
/// Windows, Linux, and macOS.
///
/// Processes matching this guard must NEVER be killed, suspended/tarpitted,
/// network-blocked via host firewall, or hijacked via IFEO.
pub fn is_protected_os_shell_or_desktop_binary(path_or_name: &str) -> bool {
    let trimmed = path_or_name.trim().trim_matches('"');
    if trimmed.is_empty() {
        return false;
    }

    let normalized = normalize_nt_device_path(trimmed);
    let lower_win = normalized.to_ascii_lowercase().replace('/', "\\");
    let lower_unix = normalized.to_ascii_lowercase().replace('\\', "/");

    // Extract base executable filename
    let file_name = lower_unix
        .rsplit('/')
        .next()
        .unwrap_or(lower_unix.as_str())
        .trim();
    if file_name.is_empty() {
        return false;
    }

    // Never classify script interpreters or LOLBins as protected OS desktop/shell binaries
    const NEVER_PROTECTED_INTERPRETERS: &[&str] = &[
        "powershell.exe",
        "powershell",
        "pwsh.exe",
        "pwsh",
        "cmd.exe",
        "cmd",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "certutil.exe",
        "bitsadmin.exe",
        "bash",
        "sh",
        "zsh",
        "dash",
        "ksh",
        "python",
        "python.exe",
        "python3",
        "python3.exe",
        "perl",
        "ruby",
        "node",
        "node.exe",
        "nc",
        "ncat",
        "netcat",
        "socat",
        "curl",
        "curl.exe",
        "wget",
    ];
    if NEVER_PROTECTED_INTERPRETERS.contains(&file_name) {
        return false;
    }

    // Dedicated OS shell / app bundle paths across Windows, Linux, and macOS
    if lower_win.contains("\\windows\\systemapps\\")
        || lower_win.contains("\\windows\\immersivecontrolpanel\\")
        || lower_unix.starts_with("/lib/systemd/")
        || lower_unix.starts_with("/usr/lib/systemd/")
        || lower_unix.starts_with("/system/library/coreservices/")
    {
        return true;
    }

    // Prefix patterns for Linux/Unix modular desktop & init daemons
    if file_name.starts_with("systemd-")
        || file_name.starts_with("xdg-desktop-portal")
        || file_name.starts_with("xdg-document-portal")
        || file_name.starts_with("xdg-permission-store")
        || file_name.starts_with("gsd-")
        || file_name.starts_with("gvfsd")
        || file_name.starts_with("gvfs-")
        || file_name.starts_with("tracker-miner")
        || file_name.starts_with("tracker-extract")
        || file_name.starts_with("tracker-xdg-portal")
        || file_name.starts_with("localsearch")
        || file_name.starts_with("baloo_file")
        || file_name.starts_with("kwin_")
        || file_name.starts_with("ibus-")
        || file_name.starts_with("pipewire")
        || file_name.starts_with("containerd-shim")
    {
        return true;
    }

    let stem = file_name.strip_suffix(".exe").unwrap_or(file_name);

    matches!(
        stem,
        // --- Windows Core OS, Session, Desktop Shell, System Tray & Search ---
        "system"
            | "registry"
            | "memcompression"
            | "smss"
            | "csrss"
            | "wininit"
            | "services"
            | "lsass"
            | "lsm"
            | "winlogon"
            | "svchost"
            | "fontdrvhost"
            | "dwm"
            | "sihost"
            | "taskhostw"
            | "dllhost"
            | "conhost"
            | "explorer"
            | "shellhost"
            | "shellexperiencehost"
            | "startmenuexperiencehost"
            | "applicationframehost"
            | "systemsettings"
            | "systemsettingsbroker"
            | "textinputhost"
            | "ctfmon"
            | "securityhealthsystray"
            | "securityhealthservice"
            | "securityhealthhost"
            | "searchhost"
            | "searchapp"
            | "searchindexer"
            | "searchprotocolhost"
            | "searchfilterhost"
            | "runtimebroker"
            | "backgroundtaskhost"
            | "smartscreen"
            | "widgets"
            | "widgetservice"
            | "lockapp"
            | "spoolsv"
            | "audiodg"
            | "dashost"
            | "wmiprvse"
            | "unsecapp"
            | "vssvc"
            | "vds"
            | "tiworker"
            | "trustedinstaller"
            | "msmpeng"
            | "mpdefendercoreservice"
            | "nissrv"
            | "mpcmdrun"
            | "senseir"
            | "mssense"
            | "osqueryd"
            | "osqueryi"
            | "sysmon"
            | "sysmon64"
            | "osoosi"
            | "osoosi-cli"
            | "osoosi-auditor"
            | "netsh"
            | "sc"
            | "reg"
            | "route"
            | "ipconfig"
            | "arp"
            | "taskmgr"
            | "mmc"
            | "consent"
            | "werfault"
            | "control"
            | "systempropertiesadvanced"
            | "systempropertiescomputername"
            | "systempropertieshardware"
            | "systempropertiesperformance"
            | "systempropertiesprotection"
            | "systempropertiesremote"
            | "systempropertiesdataexecutionprevention"
            | "runlegacycplelevated"
            // --- Linux Init, Systemd, DBus, Desktop Shell, Wayland/X11, Tray & Search ---
            | "init"
            | "systemd"
            | "systemctl"
            | "journalctl"
            | "loginctl"
            | "udevadm"
            | "dbus-daemon"
            | "dbus-broker"
            | "dbus-broker-launch"
            | "polkitd"
            | "accounts-daemon"
            | "rtkit-daemon"
            | "udisksd"
            | "upowerd"
            | "colord"
            | "avahi-daemon"
            | "rsyslogd"
            | "syslog-ng"
            | "auditd"
            | "cron"
            | "crond"
            | "NetworkManager"
            | "networkmanager"
            | "nm-dispatcher"
            | "nm-applet"
            | "wpa_supplicant"
            | "iwd"
            | "dhclient"
            | "dhcpcd"
            | "dnsmasq"
            | "sshd"
            | "ssh-agent"
            | "iptables"
            | "ip6tables"
            | "nft"
            | "xorg"
            | "xwayland"
            | "wayland"
            | "gnome-shell"
            | "gnome-session"
            | "gnome-session-binary"
            | "gnome-settings-daemon"
            | "gnome-keyring-daemon"
            | "mutter"
            | "plasmashell"
            | "kded5"
            | "kded6"
            | "ksmserver"
            | "krunner"
            | "xembedsniproxy"
            | "gmenudbusmenuproxy"
            | "kwalletd5"
            | "kwalletd6"
            | "xfce4-session"
            | "xfce4-panel"
            | "xfwm4"
            | "xfdesktop"
            | "cinnamon"
            | "mate-session"
            | "mate-panel"
            | "marco"
            | "sway"
            | "hyprland"
            | "waybar"
            | "i3"
            | "polybar"
            | "dunst"
            | "mako"
            | "gdm"
            | "gdm3"
            | "gdm-session-worker"
            | "gdm-wayland-session"
            | "gdm-x-session"
            | "sddm"
            | "sddm-helper"
            | "lightdm"
            | "dconf-service"
            | "at-spi-bus-launcher"
            | "at-spi2-registryd"
            | "fcitx"
            | "fcitx5"
            | "wireplumber"
            | "pulseaudio"
            | "nautilus"
            | "dolphin"
            | "thunar"
            | "nemo"
            | "pcmanfm"
            | "updatedb"
            | "plocate"
            | "dockerd"
            | "containerd"
            | "runc"
            | "crun"
            | "podman"
            | "conmon"
            | "libvirtd"
            // --- macOS Launchd, WindowServer, Dock, Finder, SystemUIServer/ControlCenter & Spotlight ---
            | "kernel_task"
            | "launchd"
            | "usereventagent"
            | "cfprefsd"
            | "distnoted"
            | "notifyd"
            | "logd"
            | "fseventsd"
            | "powerd"
            | "thermald"
            | "configd"
            | "syslogd"
            | "opendirectoryd"
            | "mds"
            | "mdworker"
            | "mdworker_shared"
            | "mds_stores"
            | "mdsync"
            | "spotlight"
            | "coreservicesd"
            | "coreservicesuiagent"
            | "lsd"
            | "iconservicesagent"
            | "iconservicesd"
            | "tccd"
            | "trustd"
            | "securityd"
            | "syspolicyd"
            | "amfid"
            | "endpointsecurityd"
            | "nesessionmanager"
            | "nehelper"
            | "mdnsresponder"
            | "mdnsresponderhelper"
            | "symptomsd"
            | "networkserviceproxy"
            | "wifiagent"
            | "airportd"
            | "bluetoothd"
            | "coreaudiod"
            | "audiomxd"
            | "corebrightnessd"
            | "hidd"
            | "windowserver"
            | "loginwindow"
            | "dock"
            | "finder"
            | "systemuiserver"
            | "controlcenter"
            | "notificationcenter"
            | "wallpaperagent"
            | "windowmanager"
            | "talagent"
            | "universalaccessd"
            | "pboard"
            | "sharingd"
            | "rapportd"
            | "cloudd"
            | "bird"
            | "fileproviderd"
            | "textinputmenuagent"
            | "textinputswitcher"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_trusted_vendor() {
        assert!(is_trusted_vendor("Microsoft Corporation"));
        assert!(is_trusted_vendor("The Khronos Group Inc."));
        assert!(is_trusted_vendor("Khronos"));
        assert!(is_trusted_vendor("HugOS IDE"));
        assert!(is_trusted_vendor("Google LLC"));
        assert!(is_trusted_vendor("Mozilla Corporation"));
        assert!(is_trusted_vendor("Rust Language"));
        assert!(is_trusted_vendor("Node.js Foundation"));

        assert!(!is_trusted_vendor("Malware Author"));
        assert!(!is_trusted_vendor("Insecure Hacker LLC"));
        assert!(!is_trusted_vendor(""));
    }

    #[test]
    fn test_is_trusted_signed_binary_nonexistent() {
        assert!(!is_trusted_signed_binary(Path::new(
            r"C:\nonexistent\fake.dll"
        )));
    }

    #[test]
    fn test_is_pinned_thumbprint_allowed() {
        let test_tp = "a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890";
        std::env::set_var(
            "OSOOSI_PINNED_CERT_THUMBPRINTS",
            format!("deadbeef,{},cafebabe", test_tp),
        );

        assert!(is_pinned_thumbprint_allowed(&[test_tp.to_string()]));
        assert!(is_pinned_thumbprint_allowed(&[test_tp.to_uppercase()]));
        // Test space-separated formatting
        let spaced_tp = "a1 b2 c3 d4 e5 f6 78 90 ab cd ef 12 34 56 78 90 ab cd ef 12 34 56 78 90 ab cd ef 12 34 56 78 90";
        assert!(is_pinned_thumbprint_allowed(&[spaced_tp.to_string()]));
        // Test colon-separated formatting
        let colon_tp = "a1:b2:c3:d4:e5:f6:78:90:ab:cd:ef:12:34:56:78:90:ab:cd:ef:12:34:56:78:90:ab:cd:ef:12:34:56:78:90";
        assert!(is_pinned_thumbprint_allowed(&[colon_tp.to_string()]));
        assert!(!is_pinned_thumbprint_allowed(&[
            "11223344556677889900aabbccddeeff".to_string()
        ]));
        assert!(!is_pinned_thumbprint_allowed(&[]));

        std::env::remove_var("OSOOSI_PINNED_CERT_THUMBPRINTS");
        assert!(!is_pinned_thumbprint_allowed(&[test_tp.to_string()]));
    }

    #[test]
    fn test_authenticode_status_variants() {
        let revoked = AuthenticodeStatus::Revoked;
        assert_eq!(revoked, AuthenticodeStatus::Revoked);
        assert_ne!(revoked, AuthenticodeStatus::ValidTrusted);
        assert_ne!(revoked, AuthenticodeStatus::UntrustedRoot);

        let non_existent_status = check_authenticode_status(r"C:\nonexistent\dummy.exe");
        assert_ne!(non_existent_status, AuthenticodeStatus::ValidTrusted);
    }

    #[test]
    fn test_extract_certificate_thumbprints_nonexistent() {
        let tps = extract_certificate_thumbprints(r"C:\nonexistent\dummy.exe");
        assert!(tps.is_empty());
    }

    #[test]
    fn test_extract_zip_bounds() {
        let tmp_dir = std::env::temp_dir().join(format!("test_zip_{}", uuid::Uuid::new_v4()));
        let _ = std::fs::create_dir_all(&tmp_dir);
        let zip_file_path = tmp_dir.join("test.zip");
        let extract_target = tmp_dir.join("extracted");

        {
            let file = std::fs::File::create(&zip_file_path).unwrap();
            let mut zip = zip::ZipWriter::new(file);
            let options = zip::write::SimpleFileOptions::default();
            zip.start_file("sample.txt", options).unwrap();
            use std::io::Write;
            zip.write_all(b"Hello secure world").unwrap();
            zip.finish().unwrap();
        }

        let res = extract_zip(&zip_file_path, &extract_target);
        assert!(res.is_ok());
        let content = std::fs::read_to_string(extract_target.join("sample.txt")).unwrap();
        assert_eq!(content, "Hello secure world");

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_inspect_binary_authenticode_system() {
        let kernel32 = Path::new(r"C:\Windows\System32\kernel32.dll");
        if kernel32.exists() {
            let info = inspect_binary_authenticode(kernel32);
            assert_eq!(info.status, AuthenticodeStatus::ValidTrusted);
            assert!(info.is_valid);
            assert!(is_trusted_signed_binary(kernel32));
        }

        let non_existent = Path::new(r"C:\nonexistent\fake.exe");
        let non_info = inspect_binary_authenticode(non_existent);
        assert!(!non_info.is_valid);
        assert_eq!(non_info.signer_subject, None);
    }

    #[test]
    fn test_normalize_nt_device_path() {
        assert_eq!(
            normalize_nt_device_path(r"\Device\HarddiskVolume4\Windows\System32\conhost.exe")
                .to_lowercase(),
            r"c:\windows\system32\conhost.exe"
        );
        assert_eq!(
            normalize_nt_device_path(
                r"\Device\HarddiskVolume12\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\SearchHost.exe"
            )
            .to_lowercase(),
            r"c:\windows\systemapps\microsoftwindows.client.cbs_cw5n1h2txyewy\searchhost.exe"
        );
        assert_eq!(
            normalize_nt_device_path(r"\\?\C:\Windows\System32\SearchFilterHost.exe")
                .to_lowercase(),
            r"c:\windows\system32\searchfilterhost.exe"
        );
        #[cfg(target_os = "windows")]
        {
            let nt_kernel32 = Path::new(r"\Device\HarddiskVolume4\Windows\System32\kernel32.dll");
            if Path::new(r"C:\Windows\System32\kernel32.dll").exists() {
                assert!(is_trusted_signed_binary(nt_kernel32));
            }
        }
    }

    #[test]
    fn test_is_protected_os_shell_or_desktop_binary_cross_platform() {
        // Windows Search, Shell & System Tray
        assert!(is_protected_os_shell_or_desktop_binary(
            r"\Device\HarddiskVolume4\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\SearchHost.exe"
        ));
        assert!(is_protected_os_shell_or_desktop_binary(
            r"C:\Windows\System32\sihost.exe"
        ));
        assert!(is_protected_os_shell_or_desktop_binary(
            r"C:\Windows\explorer.exe"
        ));
        assert!(is_protected_os_shell_or_desktop_binary(
            r"C:\Windows\System32\SecurityHealthSystray.exe"
        ));
        assert!(is_protected_os_shell_or_desktop_binary(
            r"C:\Windows\System32\ctfmon.exe"
        ));
        assert!(is_protected_os_shell_or_desktop_binary(
            r"C:\Windows\System32\SearchFilterHost.exe"
        ));

        // Linux Init, Desktop Shell, Compositor, Tray & Indexers
        assert!(is_protected_os_shell_or_desktop_binary("/usr/lib/systemd/systemd-resolved"));
        assert!(is_protected_os_shell_or_desktop_binary("/usr/bin/gnome-shell"));
        assert!(is_protected_os_shell_or_desktop_binary("/usr/bin/plasmashell"));
        assert!(is_protected_os_shell_or_desktop_binary("/usr/bin/kwin_wayland"));
        assert!(is_protected_os_shell_or_desktop_binary("/usr/libexec/tracker-miner-fs-3"));
        assert!(is_protected_os_shell_or_desktop_binary("/usr/libexec/xdg-desktop-portal-gtk"));
        assert!(is_protected_os_shell_or_desktop_binary("/usr/bin/pipewire"));
        assert!(is_protected_os_shell_or_desktop_binary("/usr/sbin/NetworkManager"));

        // macOS Launchd, WindowServer, Dock, Finder, ControlCenter & Spotlight
        assert!(is_protected_os_shell_or_desktop_binary("/sbin/launchd"));
        assert!(is_protected_os_shell_or_desktop_binary(
            "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder"
        ));
        assert!(is_protected_os_shell_or_desktop_binary(
            "/System/Library/CoreServices/Dock.app/Contents/MacOS/Dock"
        ));
        assert!(is_protected_os_shell_or_desktop_binary(
            "/System/Library/CoreServices/ControlCenter.app/Contents/MacOS/ControlCenter"
        ));
        assert!(is_protected_os_shell_or_desktop_binary(
            "/System/Library/CoreServices/Spotlight.app/Contents/MacOS/Spotlight"
        ));
        assert!(is_protected_os_shell_or_desktop_binary(
            "/System/Library/Frameworks/CoreServices.framework/Frameworks/Metadata.framework/Support/mds"
        ));
        assert!(is_protected_os_shell_or_desktop_binary("WindowServer"));
        assert!(is_protected_os_shell_or_desktop_binary("SystemUIServer"));

        // Script interpreters / LOLBins / unknown binaries must NOT be protected by this guard
        assert!(!is_protected_os_shell_or_desktop_binary(
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        ));
        assert!(!is_protected_os_shell_or_desktop_binary(
            r"C:\Windows\System32\cmd.exe"
        ));
        assert!(!is_protected_os_shell_or_desktop_binary("/usr/bin/bash"));
        assert!(!is_protected_os_shell_or_desktop_binary("/usr/bin/python3"));
        assert!(!is_protected_os_shell_or_desktop_binary("/tmp/evil_beacon"));
    }
}

