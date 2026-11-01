//! Empirical Challenger Test Suite for Milestone 1 Remediation (R2):
//! DPAPI Master Key Wrapping, Key Tampering Fail-Closed Invariants,
//! and Companion File Resilience (Missing / Corrupted Fallback).
//!
//! Author: challenger_m1_r2_1 (Empirical Challenger)
//! Roles: critic, specialist

use osoosi_core::protected_env_backup::{
    dpapi_protect_bytes, dpapi_unprotect_bytes, ProtectedEnvBackupVault, VaultError,
};
use sha2::{Digest, Sha256};
use std::sync::Mutex;

static TEST_MUTEX: Mutex<()> = Mutex::new(());

fn compute_sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

/// CHALLENGE 1: DPAPI Master Key Tampering (Bit Flips, Truncations, Garbage)
/// Verifies that any alteration to wrapped DPAPI bytes causes `dpapi_unprotect_bytes`
/// to fail closed (Err) rather than returning a corrupted key or panicking.
#[test]
fn test_challenge_dpapi_tampering_fails_closed() {
    let _guard = TEST_MUTEX.lock().unwrap();

    let sample_key = [0xA5u8; 32];

    #[cfg(windows)]
    {
        // 1. Wrap genuine 32-byte key
        let protected =
            dpapi_protect_bytes(&sample_key).expect("dpapi_protect_bytes must succeed on Windows");
        assert!(!protected.is_empty(), "Wrapped bytes must not be empty");
        assert_ne!(
            protected,
            sample_key.to_vec(),
            "Ciphertext must not match plaintext"
        );

        // Verify baseline unwrapping works
        let unwrapped =
            dpapi_unprotect_bytes(&protected).expect("Baseline dpapi_unprotect_bytes must succeed");
        assert_eq!(
            unwrapped,
            sample_key.to_vec(),
            "Unwrapped bytes must match original key bit-for-bit"
        );

        let len = protected.len();
        println!("[Challenger] DPAPI wrapped key size = {} bytes", len);

        // 2. Comprehensive Bit-Flip Tampering across multiple positions
        let test_positions = vec![
            (0, 0x01, "Byte 0 LSB"),
            (0, 0x80, "Byte 0 MSB"),
            (1, 0x40, "Byte 1 Bit 6"),
            (len / 4, 0x20, "Quarter boundary Bit 5"),
            (len / 2, 0xFF, "Midpoint all bits inverted"),
            (3 * len / 4, 0x10, "Three-quarter boundary Bit 4"),
            (len - 1, 0x01, "Final byte LSB"),
            (len - 1, 0x80, "Final byte MSB"),
        ];

        for (pos, mask, label) in test_positions {
            let mut tampered = protected.clone();
            tampered[pos] ^= mask;
            let res = dpapi_unprotect_bytes(&tampered);
            assert!(
                res.is_err(),
                "CRITICAL: dpapi_unprotect_bytes MUST fail closed on bit flip at {} (pos {})",
                label,
                pos
            );
        }

        // 3. Truncation Tampering
        let truncations = vec![
            (len - 1, "Truncated by 1 byte"),
            (len - 4, "Truncated by 4 bytes"),
            (len / 2, "Truncated to 50% length"),
            (16, "Truncated to 16 bytes"),
            (1, "Truncated to 1 byte"),
        ];

        for (trunc_len, label) in truncations {
            let truncated = &protected[..trunc_len];
            let res = dpapi_unprotect_bytes(truncated);
            assert!(
                res.is_err(),
                "CRITICAL: dpapi_unprotect_bytes MUST fail closed on {}",
                label
            );
        }

        // 4. Zero and Garbage Buffers
        let zero_buf = vec![0u8; 64];
        assert!(
            dpapi_unprotect_bytes(&zero_buf).is_err(),
            "dpapi_unprotect_bytes MUST reject all-zero buffer"
        );

        let ff_buf = vec![0xFFu8; 64];
        assert!(
            dpapi_unprotect_bytes(&ff_buf).is_err(),
            "dpapi_unprotect_bytes MUST reject all-0xFF buffer"
        );

        let noise_buf = b"NOT_A_VALID_WIN32_DPAPI_BLOB_STRUCTURE_RANDOM_NOISE_BYTES";
        assert!(
            dpapi_unprotect_bytes(noise_buf).is_err(),
            "dpapi_unprotect_bytes MUST reject arbitrary ascii noise"
        );

        // 5. Appended Garbage Bytes
        let mut appended = protected.clone();
        appended.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let res_appended = dpapi_unprotect_bytes(&appended);
        if let Ok(unwrapped_appended) = res_appended {
            assert_eq!(
                unwrapped_appended,
                sample_key.to_vec(),
                "If trailing bytes are ignored by Win32 parser, key must still be uncorrupted"
            );
        }
    }

    #[cfg(not(windows))]
    {
        let res = dpapi_unprotect_bytes(&[0x12; 32]);
        assert!(res.is_err());
    }
}

/// CHALLENGE 2: Companion File Missing Handling
/// Tests behavior when companion `<vault_path>.dpapi` is deleted,
/// verifying graceful fallback to host master key and bit-for-bit restoration.
#[test]
fn test_challenge_companion_dpapi_missing_graceful_fallback() {
    let _guard = TEST_MUTEX.lock().unwrap();

    let temp_dir = tempfile::tempdir().expect("tempdir");
    let env_file = temp_dir.path().join(".env");
    let vault_file = temp_dir.path().join("protected_env_backup.vault");

    let original_content = "GEMINI_API_KEY=\"AIzaSyD-MissingDpapiFallbackKey999\"\nHF_TOKEN=hf_MissingDpapiToken888\nPORT=8080\n";
    std::fs::write(&env_file, original_content).expect("write .env");
    let orig_sha = compute_sha256(original_content.as_bytes());

    // 1. Seal vault
    let seal_res = ProtectedEnvBackupVault::seal_and_backup_dynamic(&env_file, &vault_file)
        .expect("seal_and_backup_dynamic must succeed");
    assert!(seal_res.total_selected >= 2);
    assert!(vault_file.exists());

    let dpapi_file = ProtectedEnvBackupVault::companion_dpapi_path(&vault_file);

    #[cfg(windows)]
    {
        assert!(
            dpapi_file.exists(),
            "Companion .dpapi file should exist after seal"
        );

        // Unlock and remove the companion .dpapi file to simulate missing file
        let _ = osoosi_core::protected_env_backup::unlock_protected_ntfs_dacl(&dpapi_file);
        std::fs::remove_file(&dpapi_file).expect("remove companion .dpapi file");
        assert!(
            !dpapi_file.exists(),
            "Companion .dpapi file must now be absent"
        );
    }

    // 2. Query vault status with companion .dpapi file MISSING
    let status = ProtectedEnvBackupVault::get_status(&vault_file)
        .expect("get_status MUST succeed via fallback even when .dpapi is missing");
    assert!(status.exists);
    assert_eq!(status.files.len(), 1);

    // 3. Auto-revert with companion .dpapi file MISSING
    ProtectedEnvBackupVault::auto_revert(&vault_file)
        .expect("auto_revert MUST succeed even when companion .dpapi is missing");

    // 4. Verify bit-for-bit fidelity
    let restored_bytes = std::fs::read(&env_file).expect("read restored .env");
    assert_eq!(compute_sha256(&restored_bytes), orig_sha);
    assert_eq!(
        std::str::from_utf8(&restored_bytes).unwrap(),
        original_content
    );

    // 5. Clean up via remove_backup (must handle absent companion file cleanly)
    ProtectedEnvBackupVault::remove_backup(&vault_file, true)
        .expect("remove_backup must succeed when companion .dpapi is absent");
    assert!(!vault_file.exists());
}

/// CHALLENGE 3: Companion File Corrupted Handling
/// Tests behavior when companion `<vault_path>.dpapi` is corrupted with garbage,
/// verifying graceful fallback to candidate keys and clean shredding.
#[test]
fn test_challenge_companion_dpapi_corrupted_graceful_fallback() {
    let _guard = TEST_MUTEX.lock().unwrap();

    let temp_dir = tempfile::tempdir().expect("tempdir");
    let env_file = temp_dir.path().join(".env");
    let vault_file = temp_dir.path().join("protected_env_backup.vault");

    let original_content = "GEMINI_API_KEY=\"AIzaSyD-CorruptedDpapiTestKey111\"\nANTHROPIC_API_KEY=sk-ant-CorruptedDpapiToken222\n";
    std::fs::write(&env_file, original_content).expect("write .env");
    let orig_sha = compute_sha256(original_content.as_bytes());

    // 1. Seal vault
    ProtectedEnvBackupVault::seal_and_backup_dynamic(&env_file, &vault_file)
        .expect("seal_and_backup_dynamic must succeed");

    let dpapi_file = ProtectedEnvBackupVault::companion_dpapi_path(&vault_file);

    #[cfg(windows)]
    {
        assert!(dpapi_file.exists());

        // Unlock DACL and overwrite companion file with corrupted garbage
        let _ = osoosi_core::protected_env_backup::unlock_protected_ntfs_dacl(&dpapi_file);
        let garbage = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33];
        std::fs::write(&dpapi_file, &garbage).expect("overwrite .dpapi with garbage");
    }

    // 2. Query vault status with CORRUPTED companion .dpapi
    let status = ProtectedEnvBackupVault::get_status(&vault_file)
        .expect("get_status MUST succeed via fallback candidate key when .dpapi is corrupted");
    assert_eq!(status.files.len(), 1);

    // 3. Auto-revert with CORRUPTED companion .dpapi
    ProtectedEnvBackupVault::auto_revert(&vault_file)
        .expect("auto_revert MUST succeed with corrupted companion .dpapi");

    // 4. Verify bit-for-bit fidelity
    let restored_bytes = std::fs::read(&env_file).expect("read restored .env");
    assert_eq!(compute_sha256(&restored_bytes), orig_sha);
    assert_eq!(
        std::str::from_utf8(&restored_bytes).unwrap(),
        original_content
    );

    // 5. remove_backup should shred both the vault and the corrupted companion .dpapi
    ProtectedEnvBackupVault::remove_backup(&vault_file, true)
        .expect("remove_backup must succeed and shred corrupted .dpapi");
    assert!(!vault_file.exists());
    assert!(!dpapi_file.exists());
}

/// CHALLENGE 4: Vault Container Tampering Fail-Closed Verification
/// Verifies that any tampering with ciphertext, MAC tag, or magic header
/// causes `get_status` to reject immediately with IntegrityFailure or InvalidFormat.
#[test]
fn test_challenge_vault_container_tampering_fails_closed() {
    let _guard = TEST_MUTEX.lock().unwrap();

    let temp_dir = tempfile::tempdir().expect("tempdir");
    let env_file = temp_dir.path().join(".env");
    let vault_file = temp_dir.path().join("protected_env_backup.vault");

    let original_content = "GEMINI_API_KEY=\"AIzaSyD-VaultTamperTestKey333\"\n";
    std::fs::write(&env_file, original_content).expect("write .env");

    ProtectedEnvBackupVault::seal_and_backup_dynamic(&env_file, &vault_file)
        .expect("seal_and_backup_dynamic must succeed");

    let vault_bytes = std::fs::read(&vault_file).expect("read vault bytes");
    let total_len = vault_bytes.len();
    assert!(
        total_len > 64 + 32,
        "Vault bytes must contain header, ciphertext, and tag"
    );

    // Case A: Tamper with MAC tag (last 16 bytes)
    {
        let mut tampered = vault_bytes.clone();
        tampered[total_len - 5] ^= 0xFF;
        let tampered_vault = temp_dir.path().join("tampered_tag.vault");
        std::fs::write(&tampered_vault, &tampered).expect("write tampered tag vault");
        let res = ProtectedEnvBackupVault::get_status(&tampered_vault);
        assert!(
            matches!(res, Err(VaultError::IntegrityFailure)),
            "Tampered BLAKE3 MAC tag MUST fail with IntegrityFailure, got {:?}",
            res
        );
    }

    // Case B: Tamper with Ciphertext body
    {
        let mut tampered = vault_bytes.clone();
        tampered[70] ^= 0xAA;
        let tampered_vault = temp_dir.path().join("tampered_ct.vault");
        std::fs::write(&tampered_vault, &tampered).expect("write tampered ct vault");
        let res = ProtectedEnvBackupVault::get_status(&tampered_vault);
        assert!(
            matches!(res, Err(VaultError::IntegrityFailure)),
            "Tampered Ciphertext MUST fail with IntegrityFailure, got {:?}",
            res
        );
    }

    // Case C: Tamper with Magic Header
    {
        let mut tampered = vault_bytes.clone();
        tampered[0] = b'X';
        let tampered_vault = temp_dir.path().join("tampered_magic.vault");
        std::fs::write(&tampered_vault, &tampered).expect("write tampered magic vault");
        let res = ProtectedEnvBackupVault::get_status(&tampered_vault);
        assert!(
            matches!(res, Err(VaultError::InvalidFormat)),
            "Tampered Magic MUST fail with InvalidFormat, got {:?}",
            res
        );
    }

    // Revert and cleanup
    ProtectedEnvBackupVault::auto_revert(&vault_file).expect("auto_revert");
    ProtectedEnvBackupVault::remove_backup(&vault_file, true).expect("remove_backup");
}
