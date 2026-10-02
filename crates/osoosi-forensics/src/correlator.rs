//! Signal aggregation and forensic evidence corroboration.
//!
//! Validates low-level physical disk/memory artifacts against operating system
//! user-mode APIs to detect rootkits, DKOM hooking, and unbacked process hollowing.

use crate::models::{MftDiscrepancyArtifact, VadMemoryArtifact};
use std::path::Path;

/// Evaluates process VAD memory artifacts to corroborate code injection, hollowing, or reflective DLL loading.
///
/// An unbacked executable region exists when memory protection is executable (`EXECUTE`), but the region
/// is `PRIVATE` memory or has no backing image file on the filesystem.
/// Returns `(corroborated, confidence_delta, flagged_artifacts)`.
pub fn corroborate_process_injection(
    _pid: u32,
    vad_records: &[VadMemoryArtifact],
) -> (bool, f32, Vec<VadMemoryArtifact>) {
    let mut flagged = Vec::new();

    for item in vad_records {
        let prot_upper = item.protection.to_uppercase();
        let map_upper = item.mapping_type.to_uppercase();
        let is_exec = prot_upper.contains("EXECUTE");
        let is_private_or_unbacked = map_upper.contains("PRIVATE") || item.filename.is_none();

        if is_exec && (is_private_or_unbacked || item.is_unbacked_executable) {
            let mut flagged_item = item.clone();
            flagged_item.is_unbacked_executable = true;
            flagged.push(flagged_item);
        }
    }

    if !flagged.is_empty() {
        (true, 0.20, flagged)
    } else {
        (false, 0.0, Vec::new())
    }
}

/// Evaluates raw NTFS Master File Table (MFT) entries against standard Win32 / POSIX filesystem APIs.
///
/// If raw disk MFT indicates a record is marked `InUse`, but standard Win32 `Path::exists()` reports
/// false/missing, this confirms active DKOM file cloaking or rootkit filtering.
/// Returns `(corroborated, confidence_delta, flagged_artifacts)`.
pub fn corroborate_mft_rootkit_hiding(
    mft_records: &[MftDiscrepancyArtifact],
) -> (bool, f32, Vec<MftDiscrepancyArtifact>) {
    let mut flagged = Vec::new();

    for item in mft_records {
        if item.in_use {
            let path = Path::new(&item.full_path);
            let exists_in_win32 = path.exists();

            if !exists_in_win32 || item.is_hidden_from_win32_api {
                let mut flagged_item = item.clone();
                flagged_item.is_hidden_from_win32_api = true;
                flagged.push(flagged_item);
            }
        }
    }

    if !flagged.is_empty() {
        (true, 0.25, flagged)
    } else {
        (false, 0.0, Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_corroborate_process_injection_detects_unbacked_vad() {
        let benign = vec![
            VadMemoryArtifact {
                pid: 100,
                address: "0x7ff70000".to_string(),
                size: 40960,
                protection: "PAGE_EXECUTE_READ".to_string(),
                mapping_type: "IMAGE".to_string(),
                filename: Some("C:\\Windows\\System32\\cmd.exe".to_string()),
                is_unbacked_executable: false,
            },
            VadMemoryArtifact {
                pid: 100,
                address: "0x7ff80000".to_string(),
                size: 8192,
                protection: "PAGE_READWRITE".to_string(),
                mapping_type: "PRIVATE".to_string(),
                filename: None,
                is_unbacked_executable: false,
            },
        ];

        let (corroborated, delta, flagged) = corroborate_process_injection(100, &benign);
        assert!(!corroborated);
        assert_eq!(delta, 0.0);
        assert!(flagged.is_empty());

        let mut malicious = benign.clone();
        malicious.push(VadMemoryArtifact {
            pid: 100,
            address: "0x00550000".to_string(),
            size: 4096,
            protection: "PAGE_EXECUTE_READWRITE".to_string(),
            mapping_type: "PRIVATE".to_string(),
            filename: None,
            is_unbacked_executable: false,
        });

        let (corroborated, delta, flagged) = corroborate_process_injection(100, &malicious);
        assert!(corroborated);
        assert_eq!(delta, 0.20);
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].address, "0x00550000");
        assert!(flagged[0].is_unbacked_executable);
    }

    #[test]
    fn test_corroborate_mft_rootkit_detects_hidden_files() {
        let non_existent_dummy_path = if cfg!(windows) {
            "C:\\Windows\\System32\\drivers\\non_existent_fake_rootkit_98765.sys"
        } else {
            "/tmp/non_existent_fake_rootkit_98765.sys"
        };

        let records = vec![
            MftDiscrepancyArtifact {
                entry_number: 10,
                full_path: "Cargo.toml".to_string(), // Exists in workspace root
                in_use: true,
                size: 1000,
                created: None,
                modified: None,
                is_hidden_from_win32_api: false,
            },
            MftDiscrepancyArtifact {
                entry_number: 11,
                full_path: non_existent_dummy_path.to_string(),
                in_use: true, // Marked in use in raw MFT
                size: 4096,
                created: None,
                modified: None,
                is_hidden_from_win32_api: false,
            },
        ];

        let (corroborated, delta, flagged) = corroborate_mft_rootkit_hiding(&records);
        assert!(corroborated);
        assert_eq!(delta, 0.25);
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].entry_number, 11);
        assert!(flagged[0].is_hidden_from_win32_api);
    }
}
