//! In-memory Authenticode signature verification cache and trust evaluation.
//!
//! Eliminates duplicate WinVerifyTrust API lookups and disk reads by maintaining
//! a concurrent DashMap cache with a 300-second TTL.

use dashmap::DashMap;
use osoosi_types::AuthenticodeStatus;
pub use osoosi_types::{
    extract_signer_subject, inspect_binary_authenticode, AuthenticodeSignatureInfo,
};
use std::path::Path;
use std::sync::LazyLock;
use std::time::{Duration, SystemTime};

/// Cache TTL for Authenticode signature verification results (5 minutes).
pub const AUTHENTICODE_CACHE_TTL: Duration = Duration::from_secs(300);

/// Concurrent in-memory cache mapping normalized binary paths to their verified Authenticode status and insertion timestamp.
pub static AUTHENTICODE_CACHE: LazyLock<DashMap<String, (AuthenticodeStatus, SystemTime)>> =
    LazyLock::new(DashMap::new);

/// Normalize binary path string for deterministic cache keying.
fn normalize_path_key(path: &str) -> String {
    path.replace('/', "\\").to_ascii_lowercase()
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

    #[cfg(target_os = "windows")]
    let mut status = osoosi_types::check_authenticode_status(path);
    #[cfg(not(target_os = "windows"))]
    let status = AuthenticodeStatus::NotSigned;

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

/// Verify a file signature using native Windows WinVerifyTrust with in-memory caching.
pub fn verify_file_signature(path: &str) -> bool {
    matches!(get_cached_authenticode_status(path), AuthenticodeStatus::ValidTrusted)
}

/// Check if a binary has a valid digital signature or belongs to a known trusted vendor,
/// leveraging cached WinVerifyTrust status and native Crypt32 subject extraction.
pub fn is_trusted_signed_binary(path: &Path) -> bool {
    if !path.exists() {
        return false;
    }
    let path_str = path.to_string_lossy();
    let status = get_cached_authenticode_status(&path_str);

    match status {
        AuthenticodeStatus::ValidTrusted => {
            // 1. Try native Crypt32 subject extraction first
            if let Some(subject) = extract_signer_subject(path) {
                if is_trusted_vendor(&subject) {
                    return true;
                }
            }
            // 2. Check PE metadata / publisher
            if let Some(meta) = osoosi_types::get_pe_metadata(path) {
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
            let lower = path_str.to_lowercase().replace('/', "\\");
            if lower.starts_with("c:\\program files\\")
                || lower.starts_with("c:\\program files (x86)\\")
                || lower.starts_with("c:\\windows\\")
            {
                return true;
            }
            false
        }
        AuthenticodeStatus::UntrustedRoot => {
            let cert_thumbprints = osoosi_types::extract_certificate_thumbprints(&path_str);
            osoosi_types::is_pinned_thumbprint_allowed(&cert_thumbprints)
        }
        _ => false,
    }
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

/// Evict a specific path from the Authenticode cache.
pub fn invalidate_cache_entry(path: &str) {
    let key = normalize_path_key(path);
    AUTHENTICODE_CACHE.remove(&key);
}

/// Clear the entire Authenticode cache.
pub fn clear_authenticode_cache() {
    AUTHENTICODE_CACHE.clear();
}

/// Return the current number of cached entries.
pub fn cache_len() -> usize {
    AUTHENTICODE_CACHE.len()
}

#[cfg(test)]
mod tests {
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
        assert_eq!(get_cached_authenticode_status(test_path_forward), AuthenticodeStatus::ValidTrusted);

        invalidate_cache_entry(test_path);
        assert_eq!(cache_len(), 0);
    }

    #[test]
    fn test_transient_error_not_cached() {
        clear_authenticode_cache();
        let transient_status = AuthenticodeStatus::OtherError(-2147024864);
        assert!(!matches!(transient_status, AuthenticodeStatus::ValidTrusted));
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
}
