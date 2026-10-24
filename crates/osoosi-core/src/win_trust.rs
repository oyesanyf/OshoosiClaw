//! In-memory Authenticode signature verification cache and cryptographic trust evaluation.
//!
//! Eliminates duplicate WinVerifyTrust API lookups and disk reads by maintaining
//! concurrent DashMap caches with a 300-second TTL.

use dashmap::{DashMap, DashSet};
use osoosi_types::AuthenticodeStatus;
pub use osoosi_types::{
    extract_signer_subject, inspect_binary_authenticode, AuthenticodeSignatureInfo,
};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::{LazyLock, OnceLock};
use std::time::{Duration, SystemTime};

/// Cache TTL for Authenticode signature and cryptographic trust verification results (5 minutes).
pub const AUTHENTICODE_CACHE_TTL: Duration = Duration::from_secs(300);

/// Concurrent in-memory cache mapping normalized binary paths to their verified Authenticode status and insertion timestamp.
pub static AUTHENTICODE_CACHE: LazyLock<DashMap<String, (AuthenticodeStatus, SystemTime)>> =
    LazyLock::new(DashMap::new);

/// Concurrent in-memory cache mapping normalized binary paths to their full cryptographic trust verdict.
pub static BINARY_TRUST_CACHE: LazyLock<DashMap<String, (BinaryTrustVerdict, SystemTime)>> =
    LazyLock::new(DashMap::new);

/// In-memory inventory of protected local binary BLAKE3 digests (lowercase hex).
static PROTECTED_LOCAL_BINARY_HASHES: OnceLock<DashSet<String>> = OnceLock::new();

/// Cryptographic trust verdict for an executable binary or shared library.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BinaryTrustVerdict {
    /// Cryptographically verified via embedded Authenticode signature (trusted root).
    TrustedAuthenticode {
        signer_subject: Option<String>,
        thumbprint: Option<String>,
    },
    /// Cryptographically verified via Windows Security Catalog (CatRoot hash lookup).
    TrustedCatalog {
        catalog_name: Option<String>,
    },
    /// Cryptographically verified via matching a known BLAKE3 digest in the protected local inventory.
    TrustedProtectedHash {
        blake3_hash: String,
    },
    /// Cryptographically verified via Linux/Unix package manager or system integrity manifest.
    TrustedSystemPackage {
        package_name: Option<String>,
        digest: Option<String>,
    },
    /// Untrusted: signature or catalog check explicitly failed, was revoked, untrusted root, or tampered.
    UntrustedSignature {
        status: AuthenticodeStatus,
        reason: String,
    },
    /// Untrusted: binary in user-writable/temp directory without valid signature or inventory match.
    UntrustedWritableLocation {
        path: String,
        reason: String,
    },
    /// Untrusted: binary has no digital signature, catalog registration, or inventory digest.
    UntrustedUnsigned {
        blake3_hash: String,
    },
    /// Untrusted: binary path does not exist, cannot be read, or is not a regular file.
    UntrustedIoError {
        error: String,
    },
}

impl BinaryTrustVerdict {
    /// Returns `true` if the verdict represents cryptographic trust.
    pub fn is_trusted(&self) -> bool {
        matches!(
            self,
            BinaryTrustVerdict::TrustedAuthenticode { .. }
                | BinaryTrustVerdict::TrustedCatalog { .. }
                | BinaryTrustVerdict::TrustedProtectedHash { .. }
                | BinaryTrustVerdict::TrustedSystemPackage { .. }
        )
    }

    /// Short human-readable category string for logging, telemetry, and audit records.
    pub fn category(&self) -> &'static str {
        match self {
            BinaryTrustVerdict::TrustedAuthenticode { .. } => "trusted_authenticode",
            BinaryTrustVerdict::TrustedCatalog { .. } => "trusted_catalog",
            BinaryTrustVerdict::TrustedProtectedHash { .. } => "trusted_protected_hash",
            BinaryTrustVerdict::TrustedSystemPackage { .. } => "trusted_system_package",
            BinaryTrustVerdict::UntrustedSignature { .. } => "untrusted_signature",
            BinaryTrustVerdict::UntrustedWritableLocation { .. } => "untrusted_writable_location",
            BinaryTrustVerdict::UntrustedUnsigned { .. } => "untrusted_unsigned",
            BinaryTrustVerdict::UntrustedIoError { .. } => "untrusted_io_error",
        }
    }
}

/// Normalize binary path string for deterministic cache keying.
pub fn normalize_path_key(path: &str) -> String {
    path.replace('/', "\\").to_ascii_lowercase()
}

/// Retrieve the protected local binary hash inventory.
pub fn get_protected_local_binary_hashes() -> &'static DashSet<String> {
    PROTECTED_LOCAL_BINARY_HASHES.get_or_init(init_protected_local_binary_hashes)
}

/// Initialize the protected local binary hash inventory from verified host binaries.
fn init_protected_local_binary_hashes() -> DashSet<String> {
    let set = DashSet::new();

    // 1. Hash current running executable and companion binaries in its directory
    if let Ok(exe_path) = std::env::current_exe() {
        if exe_path.is_file() {
            if let Ok(bytes) = std::fs::read(&exe_path) {
                set.insert(blake3::hash(&bytes).to_hex().to_string().to_ascii_lowercase());
            }
        }
        if let Some(parent) = exe_path.parent() {
            if let Ok(entries) = std::fs::read_dir(parent) {
                for entry in entries.flatten().take(32) {
                    let p = entry.path();
                    let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
                    if (ext.eq_ignore_ascii_case("exe") || ext.eq_ignore_ascii_case("dll"))
                        && p.is_file()
                    {
                        if let Ok(meta) = p.metadata() {
                            if meta.len() > 0 && meta.len() <= 64 * 1024 * 1024 {
                                if let Ok(bytes) = std::fs::read(&p) {
                                    set.insert(
                                        blake3::hash(&bytes)
                                            .to_hex()
                                            .to_string()
                                            .to_ascii_lowercase(),
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // 2. Hash active running OS processes ONLY if cryptographically signed or catalog-verified
    #[cfg(target_os = "windows")]
    {
        use sysinfo::{ProcessRefreshKind, RefreshKind, System, UpdateKind};
        let sys = System::new_with_specifics(
            RefreshKind::new()
                .with_processes(ProcessRefreshKind::new().with_exe(UpdateKind::OnlyIfNotSet)),
        );
        for proc in sys.processes().values().take(64) {
            if let Some(exe) = proc.exe() {
                if exe.is_file() {
                    let exe_str = exe.to_string_lossy();
                    let auth_status = osoosi_types::check_authenticode_status(&exe_str);
                    if auth_status == AuthenticodeStatus::ValidTrusted
                        || osoosi_types::verify_windows_catalog_signature(&exe_str)
                    {
                        if let Ok(meta) = exe.metadata() {
                            if meta.len() > 0 && meta.len() <= 32 * 1024 * 1024 {
                                if let Ok(bytes) = std::fs::read(exe) {
                                    set.insert(
                                        blake3::hash(&bytes)
                                            .to_hex()
                                            .to_string()
                                            .to_ascii_lowercase(),
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    set
}

/// Register a known protected OS or developer binary BLAKE3 hash into the global protection inventory.
pub fn register_protected_binary_hash(hash_hex: &str) {
    let normalized = hash_hex.trim().to_ascii_lowercase();
    if !normalized.is_empty() {
        get_protected_local_binary_hashes().insert(normalized);
    }
}

/// Checks whether a given BLAKE3 hash matches a protected local operating system or developer toolchain binary.
pub fn is_protected_local_binary_hash(hash_hex: &str) -> bool {
    let normalized = hash_hex.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return false;
    }
    get_protected_local_binary_hashes().contains(&normalized)
}

/// Retrieve the cached Authenticode status for a path, or query `check_authenticode_status` and update the cache.
pub fn get_cached_authenticode_status(path: &str) -> AuthenticodeStatus {
    let key = normalize_path_key(path);
    let now = SystemTime::now();

    if let Some(entry) = AUTHENTICODE_CACHE.get(&key) {
        let (status, timestamp) = *entry.value();
        if now.duration_since(timestamp).unwrap_or_default() < AUTHENTICODE_CACHE_TTL {
            return status;
        }
    }

    let p = Path::new(path);
    if !p.exists() {
        return AuthenticodeStatus::NotSigned;
    }

    #[allow(unused_mut)]
    let mut status = osoosi_types::check_authenticode_status(path);

    #[cfg(target_os = "windows")]
    if let AuthenticodeStatus::OtherError(code) = status {
        // -2147024864 (0x80070020): ERROR_SHARING_VIOLATION (file is locked by active installer)
        if code == -2147024864 {
            std::thread::sleep(Duration::from_millis(30));
            status = osoosi_types::check_authenticode_status(path);
        }
        // Never poison the 300-second cache with transient I/O or sharing errors
        if let AuthenticodeStatus::OtherError(_) = status {
            return status;
        }
    }

    AUTHENTICODE_CACHE.insert(key, (status, now));
    status
}

/// Master unified cryptographic binary trust verification function.
///
/// Evaluates:
/// 1. In-memory BLAKE3 protected hash inventory.
/// 2. Windows Authenticode (WinVerifyTrust) with trusted vendor / publisher validation.
/// 3. Windows Security Catalog (`CatRoot` hash lookup via `verify_windows_catalog_signature`).
/// 4. Strict fail-closed rejection for user-writable locations (temp, Downloads, Public, target/).
/// 5. Non-Windows package manager / detached signature verification.
pub fn verify_binary_cryptographic_trust(path: &Path) -> BinaryTrustVerdict {
    if !path.exists() || !path.is_file() {
        return BinaryTrustVerdict::UntrustedIoError {
            error: format!(
                "Path '{}' does not exist or is not a regular file",
                path.display()
            ),
        };
    }

    let path_str = path.to_string_lossy();
    let norm_key = normalize_path_key(&path_str);
    let now = SystemTime::now();

    // Check full verdict cache
    if let Some(entry) = BINARY_TRUST_CACHE.get(&norm_key) {
        let (cached_verdict, timestamp) = entry.value();
        if now.duration_since(*timestamp).unwrap_or_default() < AUTHENTICODE_CACHE_TTL {
            return cached_verdict.clone();
        }
    }

    let is_writable_loc = crate::rea::is_untrusted_writable_or_temp_path(&path_str);

    // Compute BLAKE3 digest of the file on disk
    let file_bytes = std::fs::read(path).ok();
    let b3_hex = file_bytes
        .as_ref()
        .map(|b| blake3::hash(b).to_hex().to_string().to_ascii_lowercase());

    // 1. Check in-memory BLAKE3 protected hash inventory
    if let Some(ref b3) = b3_hex {
        if is_protected_local_binary_hash(b3) {
            let verdict = BinaryTrustVerdict::TrustedProtectedHash {
                blake3_hash: b3.clone(),
            };
            BINARY_TRUST_CACHE.insert(norm_key, (verdict.clone(), now));
            return verdict;
        }
    }

    // 2. Windows Authenticode & Security Catalog Verification
    #[cfg(target_os = "windows")]
    {
        let auth_status = get_cached_authenticode_status(&path_str);
        match auth_status {
            AuthenticodeStatus::ValidTrusted => {
                let subject = extract_signer_subject(path);
                let meta = osoosi_types::get_pe_metadata(path);
                let subject_trusted = subject.as_deref().map(is_trusted_vendor).unwrap_or(false);
                let publisher_trusted = meta
                    .as_ref()
                    .and_then(|m| m.publisher.as_deref())
                    .map(is_trusted_vendor)
                    .unwrap_or(false);
                let product_trusted = meta
                    .as_ref()
                    .map(|m| is_trusted_vendor(&m.product_name))
                    .unwrap_or(false);

                if subject_trusted || publisher_trusted || product_trusted {
                    let verdict = BinaryTrustVerdict::TrustedAuthenticode {
                        signer_subject: subject.or_else(|| meta.and_then(|m| m.publisher)),
                        thumbprint: osoosi_types::extract_certificate_thumbprints(&path_str)
                            .into_iter()
                            .next(),
                    };
                    BINARY_TRUST_CACHE.insert(norm_key, (verdict.clone(), now));
                    return verdict;
                }

                // If not in trusted vendor list, check if catalog-signed OS binary
                if osoosi_types::verify_windows_catalog_signature(&path_str) {
                    let verdict = BinaryTrustVerdict::TrustedCatalog { catalog_name: None };
                    BINARY_TRUST_CACHE.insert(norm_key, (verdict.clone(), now));
                    return verdict;
                }

                // In user-writable location, unknown vendor is NOT trusted
                if is_writable_loc {
                    let verdict = BinaryTrustVerdict::UntrustedWritableLocation {
                        path: path_str.to_string(),
                        reason: "Binary in user-writable location is signed by unapproved vendor"
                            .to_string(),
                    };
                    BINARY_TRUST_CACHE.insert(norm_key, (verdict.clone(), now));
                    return verdict;
                }

                // Outside user-writable location, if ValidTrusted by OS root store
                let verdict = BinaryTrustVerdict::TrustedAuthenticode {
                    signer_subject: subject.or_else(|| meta.and_then(|m| m.publisher)),
                    thumbprint: osoosi_types::extract_certificate_thumbprints(&path_str)
                        .into_iter()
                        .next(),
                };
                BINARY_TRUST_CACHE.insert(norm_key, (verdict.clone(), now));
                return verdict;
            }
            AuthenticodeStatus::UntrustedRoot => {
                let cert_thumbprints = osoosi_types::extract_certificate_thumbprints(&path_str);
                if !is_writable_loc && osoosi_types::is_pinned_thumbprint_allowed(&cert_thumbprints)
                {
                    let verdict = BinaryTrustVerdict::TrustedAuthenticode {
                        signer_subject: extract_signer_subject(path),
                        thumbprint: cert_thumbprints.into_iter().next(),
                    };
                    BINARY_TRUST_CACHE.insert(norm_key, (verdict.clone(), now));
                    return verdict;
                }
                let verdict = BinaryTrustVerdict::UntrustedSignature {
                    status: auth_status,
                    reason: "Untrusted root certificate authority".to_string(),
                };
                BINARY_TRUST_CACHE.insert(norm_key, (verdict.clone(), now));
                return verdict;
            }
            AuthenticodeStatus::TamperedBadDigest
            | AuthenticodeStatus::Revoked
            | AuthenticodeStatus::ExplicitDistrust => {
                let verdict = BinaryTrustVerdict::UntrustedSignature {
                    status: auth_status,
                    reason: format!("Signature verification failed: {:?}", auth_status),
                };
                BINARY_TRUST_CACHE.insert(norm_key, (verdict.clone(), now));
                return verdict;
            }
            AuthenticodeStatus::NotSigned | AuthenticodeStatus::OtherError(_) => {
                // Check Windows Security Catalog explicitly as fallback
                if osoosi_types::verify_windows_catalog_signature(&path_str) {
                    let verdict = BinaryTrustVerdict::TrustedCatalog { catalog_name: None };
                    BINARY_TRUST_CACHE.insert(norm_key, (verdict.clone(), now));
                    return verdict;
                }
            }
        }
    }

    // 3. Non-Windows verification (detached GPG/Minisign signature / Linux fs-verity / system package)
    #[cfg(not(target_os = "windows"))]
    {
        let auth_status = osoosi_types::check_authenticode_status(&path_str);
        if matches!(auth_status, AuthenticodeStatus::ValidTrusted) {
            let verdict = BinaryTrustVerdict::TrustedAuthenticode {
                signer_subject: Some("Detached Signature / Linux fs-verity".to_string()),
                thumbprint: None,
            };
            BINARY_TRUST_CACHE.insert(norm_key, (verdict.clone(), now));
            return verdict;
        }

        // Check if file is in system directory and verified by root ownership
        let path_lower = path_str.to_lowercase();
        let is_system_dir = path_lower.starts_with("/bin/")
            || path_lower.starts_with("/sbin/")
            || path_lower.starts_with("/usr/bin/")
            || path_lower.starts_with("/usr/sbin/")
            || path_lower.starts_with("/usr/lib/")
            || path_lower.starts_with("/lib/");

        if is_system_dir && !is_writable_loc {
            use std::os::unix::fs::MetadataExt;
            if let Ok(meta) = path.metadata() {
                if meta.uid() == 0 && (meta.mode() & 0o022) == 0 {
                    let verdict = BinaryTrustVerdict::TrustedSystemPackage {
                        package_name: None,
                        digest: b3_hex.clone(),
                    };
                    BINARY_TRUST_CACHE.insert(norm_key, (verdict.clone(), now));
                    return verdict;
                }
            }
        }
    }

    // 4. Fail-closed: User-writable location without valid cryptographic proof
    if is_writable_loc {
        let verdict = BinaryTrustVerdict::UntrustedWritableLocation {
            path: path_str.to_string(),
            reason:
                "Binary in user-writable location lacks valid Authenticode, CatRoot catalog, or protected BLAKE3 hash"
                    .to_string(),
        };
        BINARY_TRUST_CACHE.insert(norm_key, (verdict.clone(), now));
        return verdict;
    }

    // 5. Fail-closed: Unsigned binary in any directory
    let digest = b3_hex.unwrap_or_else(|| "unknown".to_string());
    let verdict = BinaryTrustVerdict::UntrustedUnsigned {
        blake3_hash: digest,
    };
    BINARY_TRUST_CACHE.insert(norm_key, (verdict.clone(), now));
    verdict
}

/// Verify a file signature using native Windows WinVerifyTrust with in-memory caching.
pub fn verify_file_signature(path: &str) -> bool {
    matches!(
        get_cached_authenticode_status(path),
        AuthenticodeStatus::ValidTrusted
    )
}

/// Check if a binary has a valid digital signature, catalog signature, or belongs to a protected hash inventory.
pub fn is_trusted_signed_binary(path: &Path) -> bool {
    verify_binary_cryptographic_trust(path).is_trusted()
}

/// Check if a publisher/product name is in the trusted vendor list.
pub fn is_trusted_vendor(name: &str) -> bool {
    osoosi_types::is_trusted_vendor(name)
}

/// Explicitly insert or override a cache entry (useful for tests or pre-warming).
pub fn insert_cached_status(path: &str, status: AuthenticodeStatus) {
    let key = normalize_path_key(path);
    AUTHENTICODE_CACHE.insert(key, (status, SystemTime::now()));
}

/// Evict a specific path from both Authenticode and Binary Trust caches.
pub fn invalidate_cache_entry(path: &str) {
    let key = normalize_path_key(path);
    AUTHENTICODE_CACHE.remove(&key);
    BINARY_TRUST_CACHE.remove(&key);
}

/// Clear the entire Authenticode and Binary Trust caches.
pub fn clear_authenticode_cache() {
    AUTHENTICODE_CACHE.clear();
    BINARY_TRUST_CACHE.clear();
}

/// Return the current number of cached entries.
pub fn cache_len() -> usize {
    AUTHENTICODE_CACHE.len()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn test_authenticode_cache_insertion_and_hit() {
        let test_path = r"C:\fake\vendor_module.dll";
        clear_authenticode_cache();

        insert_cached_status(test_path, AuthenticodeStatus::ValidTrusted);
        assert_eq!(cache_len(), 1);

        let status = get_cached_authenticode_status(test_path);
        assert_eq!(status, AuthenticodeStatus::ValidTrusted);
        assert!(verify_file_signature(test_path));

        // Normalization check: forward slash should hit same cache entry
        let test_path_forward = "C:/fake/vendor_module.dll";
        assert_eq!(
            get_cached_authenticode_status(test_path_forward),
            AuthenticodeStatus::ValidTrusted
        );

        invalidate_cache_entry(test_path);
        assert_eq!(cache_len(), 0);
    }

    #[test]
    fn test_transient_error_not_cached() {
        clear_authenticode_cache();
        let transient_status = AuthenticodeStatus::OtherError(-2147024864);
        assert!(!matches!(
            transient_status,
            AuthenticodeStatus::ValidTrusted
        ));
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_core_inspect_binary_authenticode_system() {
        let kernel32 = Path::new(r"C:\Windows\System32\kernel32.dll");
        if kernel32.exists() {
            let info = inspect_binary_authenticode(kernel32);
            assert!(info.is_valid);
            assert_eq!(info.status, AuthenticodeStatus::ValidTrusted);
            assert!(is_trusted_signed_binary(kernel32));
        }
    }

    // =========================================================================
    // R1 Verification Tests
    // =========================================================================

    #[test]
    fn test_r1_unsigned_system_binary_in_temp_not_trusted() {
        let temp_dir = std::env::temp_dir().join(format!("r1_temp_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let fake_svchost = temp_dir.join("svchost.exe");
        let fake_pe = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00";
        std::fs::write(&fake_svchost, fake_pe).expect("Failed to write fixture");

        invalidate_cache_entry(&fake_svchost.to_string_lossy());

        let verdict = verify_binary_cryptographic_trust(&fake_svchost);
        assert!(
            !verdict.is_trusted(),
            "Unsigned system binary in temp directory must NEVER be trusted"
        );
        assert!(
            matches!(verdict, BinaryTrustVerdict::UntrustedWritableLocation { .. }),
            "Expected UntrustedWritableLocation verdict, got {:?}",
            verdict
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_r1_unsigned_binary_in_target_release_not_trusted() {
        let mock_ws = std::env::temp_dir().join(format!("r1_target_ws_{}", std::process::id()));
        let target_release = mock_ws.join("target").join("release");
        let _ = std::fs::create_dir_all(&target_release);
        let fake_svchost = target_release.join("svchost.exe");
        let fake_pe = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00";
        std::fs::write(&fake_svchost, fake_pe).expect("Failed to write target/release fixture");

        invalidate_cache_entry(&fake_svchost.to_string_lossy());

        let verdict = verify_binary_cryptographic_trust(&fake_svchost);
        assert!(
            !verdict.is_trusted(),
            "Unsigned binary in target/release must NOT be trusted"
        );
        assert!(
            matches!(verdict, BinaryTrustVerdict::UntrustedWritableLocation { .. }),
            "Expected UntrustedWritableLocation, got {:?}",
            verdict
        );

        let _ = std::fs::remove_dir_all(&mock_ws);
    }

    #[test]
    fn test_r1_file_matching_blake3_inventory_trusted() {
        let temp_dir =
            std::env::temp_dir().join(format!("r1_inventory_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let custom_bin = temp_dir.join("trusted_helper.exe");
        let payload = b"MZ\x90\x00\x03\x00\x00\x00DeterministicInventoryTrustPayloadBytes_2026";
        std::fs::write(&custom_bin, payload).expect("Failed to write fixture");

        let hash = blake3::hash(payload).to_hex().to_string().to_ascii_lowercase();
        invalidate_cache_entry(&custom_bin.to_string_lossy());

        register_protected_binary_hash(&hash);
        assert!(is_protected_local_binary_hash(&hash));

        let verdict = verify_binary_cryptographic_trust(&custom_bin);
        assert!(
            verdict.is_trusted(),
            "Binary matching protected inventory must be trusted"
        );
        assert!(
            matches!(verdict, BinaryTrustVerdict::TrustedProtectedHash { ref blake3_hash } if blake3_hash == &hash),
            "Expected TrustedProtectedHash, got {:?}",
            verdict
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_r1_signed_fixture_or_catalog_verified_path_trusted() {
        let sys_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
        let candidates = [
            format!(r"{}\System32\kernel32.dll", sys_root),
            format!(r"{}\System32\notepad.exe", sys_root),
            format!(r"{}\System32\cmd.exe", sys_root),
        ];

        let mut tested = false;
        for cand in &candidates {
            let p = Path::new(cand);
            if p.is_file() {
                tested = true;
                let verdict = verify_binary_cryptographic_trust(p);
                assert!(
                    verdict.is_trusted(),
                    "Real Windows OS binary '{}' must be trusted, got {:?}",
                    cand,
                    verdict
                );
                assert!(
                    matches!(
                        verdict,
                        BinaryTrustVerdict::TrustedAuthenticode { .. }
                            | BinaryTrustVerdict::TrustedCatalog { .. }
                    ),
                    "Expected TrustedAuthenticode or TrustedCatalog for '{}', got {:?}",
                    cand,
                    verdict
                );
                break;
            }
        }
        assert!(tested, "At least one system binary must exist on Windows");
    }
}
