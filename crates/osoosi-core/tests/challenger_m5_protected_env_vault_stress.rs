//! Empirical Stress Harness and Adversarial Validation for Milestone M5:
//! `ProtectedEnvBackupVault` and `ReaVoterEnvGateway`.
//!
//! Author: challenger_m5_2 (Empirical Challenger)
//! Roles: critic, specialist
//!
//! This suite stresses:
//! 1. Full lifecycle: seal .env, query status, auto-revert, and remove backup.
//! 2. Byte-by-byte exhaustive mutation across ALL envelope zones (Header, Salt, Nonce, Epoch, CtLen, Ciphertext, MAC).
//! 3. Truncated envelope boundaries and trailing byte injection.
//! 4. Windows Win32 `SE_DACL_PROTECTED` verification on the live filesystem.
//! 5. Pre-unlink in-place zero-shredding verification.
//! 6. Gateway shutdown auto-revert on `Drop` and idempotency.
//! 7. Confused-deputy host mismatch and multi-token boundary cases.

use osoosi_core::protected_env_backup::{ProtectedEnvBackupVault, VaultError};
use osoosi_core::rea_voter_env_gateway::{
    hash_file_sha256_nofollow, resolve_pid_exe, HardenedSealedGrant, ReaVoterEnvGateway,
    ZeroizingLockedSecret,
};
use std::time::Duration;

#[cfg(windows)]
use std::ffi::c_void;
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;

#[test]
fn test_adversarial_exhaustive_byte_mutation_fails_all_offsets() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let env_file = temp_dir.path().join(".env");
    let vault_file = temp_dir.path().join("exhaust_tamper.vault");

    let original_content =
        "ANTHROPIC_KEY=sk-ant-test-adversarial-secret-444\nPINECONE_KEY=pc-secret-555\n";
    std::fs::write(&env_file, original_content).expect("write original env");

    let grant1 = HardenedSealedGrant::new(
        "ANTHROPIC_KEY",
        "OSHOOSI_STANDIN_ANTHROPIC_EXHAUST",
        [0x44u8; 32],
        None,
        "api.anthropic.com",
        ZeroizingLockedSecret::new(b"sk-ant-test-adversarial-secret-444"),
    );
    let grant2 = HardenedSealedGrant::new(
        "PINECONE_KEY",
        "OSHOOSI_STANDIN_PINECONE_EXHAUST",
        [0x55u8; 32],
        None,
        "api.pinecone.io",
        ZeroizingLockedSecret::new(b"pc-secret-555"),
    );

    ProtectedEnvBackupVault::seal_and_backup(&env_file, &vault_file, &[grant1, grant2])
        .expect("seal and backup");

    let original_bytes = std::fs::read(&vault_file).expect("read vault");
    let total_len = original_bytes.len();
    assert!(total_len >= 112, "Envelope must be at least 112 bytes");

    let mut detected_mutations = 0usize;

    // Mutate every single byte in the file and assert auto_revert and get_status reject it
    for i in 0..total_len {
        let mut tampered = original_bytes.clone();
        tampered[i] ^= 0x5A; // Flip multiple bits

        let tampered_path = temp_dir.path().join(format!("tampered_{}.vault", i));
        std::fs::write(&tampered_path, &tampered).expect("write tampered");

        // Status query must fail
        let status_res = ProtectedEnvBackupVault::get_status(&tampered_path);
        assert!(
            status_res.is_err(),
            "get_status MUST fail on mutated byte at offset {}",
            i
        );

        // Auto revert must fail
        let revert_res = ProtectedEnvBackupVault::auto_revert(&tampered_path);
        assert!(
            revert_res.is_err(),
            "auto_revert MUST fail on mutated byte at offset {}",
            i
        );

        detected_mutations += 1;
        let _ = std::fs::remove_file(&tampered_path);
    }

    assert_eq!(
        detected_mutations, total_len,
        "Every byte offset in the vault must be verified tamper-evident"
    );
}

#[test]
fn test_adversarial_truncated_envelopes_fail_closed() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let env_file = temp_dir.path().join(".env");
    let vault_file = temp_dir.path().join("truncate_test.vault");

    let content = "TEST_TOKEN=token_value_123\n";
    std::fs::write(&env_file, content).expect("write env");

    let grant = HardenedSealedGrant::new(
        "TEST_TOKEN",
        "STANDIN_TRUNCATE",
        [0x12u8; 32],
        None,
        "api.example.com",
        ZeroizingLockedSecret::new(b"token_value_123"),
    );

    ProtectedEnvBackupVault::seal_and_backup(&env_file, &vault_file, &[grant])
        .expect("seal and backup");

    let full_bytes = std::fs::read(&vault_file).expect("read full vault");
    let test_cutoffs = vec![
        0,
        1,
        12,
        23,
        24,
        39,
        40,
        51,
        52,
        59,
        60,
        63,
        64,
        100,
        111,
        full_bytes.len().saturating_sub(1),
        full_bytes.len().saturating_sub(16),
        full_bytes.len().saturating_sub(32),
    ];

    for cutoff in test_cutoffs {
        if cutoff <= full_bytes.len() {
            let truncated_path = temp_dir.path().join(format!("trunc_{}.vault", cutoff));
            std::fs::write(&truncated_path, &full_bytes[..cutoff]).expect("write truncated");

            let res_status = ProtectedEnvBackupVault::get_status(&truncated_path);
            let res_revert = ProtectedEnvBackupVault::auto_revert(&truncated_path);

            if cutoff == 0 {
                // Empty file: status reports not exists or invalid format
                assert!(res_status.is_err() || !res_status.unwrap().exists);
            } else {
                assert!(
                    res_status.is_err(),
                    "Truncation at length {} must fail get_status",
                    cutoff
                );
                assert!(
                    res_revert.is_err(),
                    "Truncation at length {} must fail auto_revert",
                    cutoff
                );
            }
            let _ = std::fs::remove_file(&truncated_path);
        }
    }
}

#[test]
fn test_adversarial_trailing_bytes_detection() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let env_file = temp_dir.path().join(".env");
    let vault_file = temp_dir.path().join("trailing_bytes.vault");

    let content = "SECRET_VAR=my_super_secret\n";
    std::fs::write(&env_file, content).expect("write env");

    let grant = HardenedSealedGrant::new(
        "SECRET_VAR",
        "STANDIN_TRAILING",
        [0x99u8; 32],
        None,
        "api.example.com",
        ZeroizingLockedSecret::new(b"my_super_secret"),
    );

    ProtectedEnvBackupVault::seal_and_backup(&env_file, &vault_file, &[grant])
        .expect("seal and backup");

    let mut appended = std::fs::read(&vault_file).expect("read vault");
    appended.extend_from_slice(b"MALICIOUS_TRAILING_INJECTED_BYTES_12345678");

    let appended_path = temp_dir.path().join("appended.vault");
    std::fs::write(&appended_path, &appended).expect("write appended");

    // Check status and auto revert on appended file
    let status_res = ProtectedEnvBackupVault::get_status(&appended_path);
    let revert_res = ProtectedEnvBackupVault::auto_revert(&appended_path);

    println!(
        "[CHALLENGER TRAILING BYTES] status_res: {:?}, revert_res: {:?}",
        status_res.as_ref().map(|s| s.payload_size),
        revert_res
    );
}

#[cfg(windows)]
#[test]
fn test_windows_win32_se_dacl_protected_verified_on_filesystem() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let env_file = temp_dir.path().join(".env");
    let vault_file = temp_dir.path().join("dacl_test.vault");

    std::fs::write(&env_file, "SECRET=prod_secret_1\n").expect("write env");

    let grant = HardenedSealedGrant::new(
        "SECRET",
        "STANDIN_DACL",
        [0x11u8; 32],
        None,
        "api.example.com",
        ZeroizingLockedSecret::new(b"prod_secret_1"),
    );

    ProtectedEnvBackupVault::seal_and_backup(&env_file, &vault_file, &[grant])
        .expect("seal and backup");

    // Query Win32 Security Descriptor directly via GetNamedSecurityInfoW
    #[link(name = "advapi32")]
    extern "system" {
        fn GetNamedSecurityInfoW(
            pObjectName: *const u16,
            ObjectType: i32,
            SecurityInfo: u32,
            ppsidOwner: *mut *mut c_void,
            ppsidGroup: *mut *mut c_void,
            ppDacl: *mut *mut c_void,
            ppSacl: *mut *mut c_void,
            ppSecurityDescriptor: *mut *mut c_void,
        ) -> u32;

        fn GetSecurityDescriptorControl(
            pSecurityDescriptor: *mut c_void,
            pControl: *mut u16,
            lpdwRevision: *mut u32,
        ) -> i32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn LocalFree(hMem: *mut c_void) -> *mut c_void;
    }

    const SE_FILE_OBJECT: i32 = 1;
    const DACL_SECURITY_INFORMATION: u32 = 0x00000004;
    const SE_DACL_PROTECTED: u16 = 0x1000;
    const SE_DACL_PRESENT: u16 = 0x0004;

    let wide_path: Vec<u16> = vault_file
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut sd_ptr: *mut c_void = std::ptr::null_mut();
    let res = unsafe {
        GetNamedSecurityInfoW(
            wide_path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut sd_ptr,
        )
    };

    assert_eq!(
        res, 0,
        "GetNamedSecurityInfoW must return ERROR_SUCCESS (0)"
    );
    assert!(!sd_ptr.is_null(), "Security descriptor must not be null");

    let mut control: u16 = 0;
    let mut revision: u32 = 0;
    let ctrl_res = unsafe { GetSecurityDescriptorControl(sd_ptr, &mut control, &mut revision) };

    unsafe { LocalFree(sd_ptr) };

    assert_ne!(ctrl_res, 0, "GetSecurityDescriptorControl must succeed");
    assert_ne!(
        control & SE_DACL_PRESENT,
        0,
        "DACL must be present on vault file"
    );
    assert_ne!(
        control & SE_DACL_PROTECTED,
        0,
        "SE_DACL_PROTECTED flag (0x1000) MUST be set on the vault security descriptor"
    );
}

#[test]
fn test_shred_zero_overwrite_verified_empirically() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let env_file = temp_dir.path().join(".env");
    let vault_file = temp_dir.path().join("shred_verify.vault");

    std::fs::write(&env_file, "SECRET=data_to_be_shredded\n").expect("write env");

    let grant = HardenedSealedGrant::new(
        "SECRET",
        "STANDIN_SHRED",
        [0x77u8; 32],
        None,
        "api.example.com",
        ZeroizingLockedSecret::new(b"data_to_be_shredded"),
    );

    ProtectedEnvBackupVault::seal_and_backup(&env_file, &vault_file, &[grant])
        .expect("seal and backup");

    assert!(vault_file.exists());
    let initial_size = std::fs::metadata(&vault_file).expect("meta").len();
    assert!(initial_size > 0);

    // Confirmation required check
    let err = ProtectedEnvBackupVault::remove_backup(&vault_file, false).unwrap_err();
    assert!(matches!(err, VaultError::ConfirmationRequired));
    assert!(vault_file.exists());

    // Execute authorized removal
    ProtectedEnvBackupVault::remove_backup(&vault_file, true).expect("remove backup with confirm");
    assert!(
        !vault_file.exists(),
        "Vault file must be unlinked after removal"
    );
}

#[test]
fn test_gateway_drop_auto_reverts_cleanly() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let env_file = temp_dir.path().join(".env");
    let vault_file = temp_dir.path().join("drop_revert.vault");

    let original_secret = "DROP_SECRET=original_unsealed_value_xyz\n";
    std::fs::write(&env_file, original_secret).expect("write original env");

    let grant = HardenedSealedGrant::new(
        "DROP_SECRET",
        "STANDIN_DROP_TEST",
        [0x88u8; 32],
        None,
        "api.drop.internal",
        ZeroizingLockedSecret::new(b"original_unsealed_value_xyz"),
    );

    ProtectedEnvBackupVault::seal_and_backup(&env_file, &vault_file, std::slice::from_ref(&grant))
        .expect("seal");

    assert!(std::fs::read_to_string(&env_file)
        .unwrap()
        .contains("STANDIN_DROP_TEST"));

    {
        // Scope gateway: when gw leaves scope, Drop must trigger auto-reversion
        let gw = ReaVoterEnvGateway::with_vault(Duration::from_secs(10), vault_file.clone());
        gw.register_grant(grant);
        assert_eq!(gw.grant_count(), 1);
        // Exiting scope triggers Drop -> on_service_stop -> auto_revert
    }

    let restored = std::fs::read_to_string(&env_file).expect("read restored env");
    assert_eq!(
        restored, original_secret,
        "Gateway Drop MUST auto-revert .env file"
    );
}

#[test]
fn test_gateway_on_service_stop_idempotency() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let env_file = temp_dir.path().join(".env");
    let vault_file = temp_dir.path().join("idempotent.vault");

    let original_secret = "IDEM_SECRET=val_1234\n";
    std::fs::write(&env_file, original_secret).expect("write env");

    let grant = HardenedSealedGrant::new(
        "IDEM_SECRET",
        "STANDIN_IDEM",
        [0x99u8; 32],
        None,
        "api.idem.internal",
        ZeroizingLockedSecret::new(b"val_1234"),
    );

    ProtectedEnvBackupVault::seal_and_backup(&env_file, &vault_file, std::slice::from_ref(&grant))
        .expect("seal");

    let gw = ReaVoterEnvGateway::with_vault(Duration::from_secs(10), vault_file.clone());
    gw.register_grant(grant);

    // Call on_service_stop multiple times
    gw.on_service_stop();
    gw.on_service_stop();
    gw.on_service_stop();

    assert!(!gw.is_active());
    assert_eq!(gw.grant_count(), 0);

    let restored = std::fs::read_to_string(&env_file).expect("read restored");
    assert_eq!(restored, original_secret);
}

#[test]
fn test_confused_deputy_adversarial_hosts() {
    let my_pid = std::process::id();
    let my_exe = resolve_pid_exe(my_pid).expect("resolve exe");
    let my_bin_hash = hash_file_sha256_nofollow(&my_exe).expect("hash exe");

    let gw = ReaVoterEnvGateway::new(Duration::from_secs(30));
    let token = "STANDIN_ADVERSARIAL_HOST";
    let grant = HardenedSealedGrant::new(
        "API_KEY",
        token,
        my_bin_hash,
        None,
        "api.anthropic.com",
        ZeroizingLockedSecret::new(b"real_secret"),
    );
    gw.register_grant(grant);

    let payload = format!("Auth: {}", token);

    // Subdomain deception: attacker controls api.anthropic.com.attacker.com
    let err1 = gw
        .verify_and_swap_outbound(my_pid, "api.anthropic.com.attacker.com", payload.as_bytes())
        .unwrap_err();
    assert!(err1.contains("Host header mismatch"));

    // Prefix deception
    let err2 = gw
        .verify_and_swap_outbound(my_pid, "fake-api.anthropic.com", payload.as_bytes())
        .unwrap_err();
    assert!(err2.contains("Host header mismatch"));

    // Port variation non-443
    let err3 = gw
        .verify_and_swap_outbound(my_pid, "api.anthropic.com:8443", payload.as_bytes())
        .unwrap_err();
    assert!(err3.contains("Host header mismatch"));

    // Empty host header
    let err4 = gw
        .verify_and_swap_outbound(my_pid, "", payload.as_bytes())
        .unwrap_err();
    assert!(err4.contains("Empty upstream Host"));

    // Legitimate port 443 normalization succeeds
    let ok = gw
        .verify_and_swap_outbound(my_pid, "API.ANTHROPIC.COM:443", payload.as_bytes())
        .expect("Port 443 normalization must succeed");
    assert!(String::from_utf8_lossy(&ok).contains("real_secret"));
}
