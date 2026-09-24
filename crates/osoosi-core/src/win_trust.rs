//! In-memory Authenticode signature verification cache and trust evaluation.
//!
//! Eliminates duplicate WinVerifyTrust API lookups and disk reads by maintaining
//! a concurrent DashMap cache with a 300-second TTL.

use dashmap::DashMap;
use osoosi_types::AuthenticodeStatus;
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

    #[cfg(target_os = "windows")]
    let status = osoosi_types::check_authenticode_status(path);
    #[cfg(not(target_os = "windows"))]
    let status = AuthenticodeStatus::NotSigned;

    AUTHENTICODE_CACHE.insert(key, (status, now));
    status
}

/// Verify a file signature using native Windows WinVerifyTrust with in-memory caching.
pub fn verify_file_signature(path: &str) -> bool {
    matches!(get_cached_authenticode_status(path), AuthenticodeStatus::ValidTrusted)
}

/// Check if a binary has a valid digital signature or belongs to a known trusted vendor,
/// leveraging cached WinVerifyTrust status.
pub fn is_trusted_signed_binary(path: &Path) -> bool {
    let path_str = path.to_string_lossy();
    let status = get_cached_authenticode_status(&path_str);

    match status {
        AuthenticodeStatus::ValidTrusted => {
            if let Some(meta) = osoosi_types::get_pe_metadata(path) {
                if let Some(ref pub_name) = meta.publisher {
                    return is_trusted_vendor(pub_name);
                }
                if is_trusted_vendor(&meta.product_name) {
                    return true;
                }
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
}
