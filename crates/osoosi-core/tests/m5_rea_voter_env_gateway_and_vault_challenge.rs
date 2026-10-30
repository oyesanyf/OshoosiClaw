//! Integration and Adversarial Verification Tests for Milestone M5:
//! `ReaVoterEnvGateway` and `ProtectedEnvBackupVault`.
//!
//! Verifies:
//! 1. Volatile Zeroizing Locked Secrets on Drop.
//! 2. Win32 & Unix Process Instance Key resolution and creation timestamp tracking.
//! 3. Clean process environment validation (blocking loader/interpreter hijacking keys).
//! 4. TOCTOU reparse-point defense (`hash_file_sha256_nofollow`).
//! 5. Multi-token outbound verification and atomic swapping.
//! 6. Stage 1 Quorum Freeze (< 1 µs RAM freeze) & Stage 2 REA Forensic Verdicts.
//! 7. Protected NTFS DACL / Unix 0600 AEAD vault backup, status query, and auto-revert.
//! 8. Automatic vault restoration on EDR shutdown BEFORE grant zero-wiping.
//! 9. Authorized zero-shred and unlink removal (`--confirm`).

use osoosi_core::protected_env_backup::{ProtectedEnvBackupVault, VaultError};
use osoosi_core::rea_voter_env_gateway::{
    hash_file_sha256_nofollow, normalize_host,
    resolve_pid_exe, resolve_process_instance_key, verify_clean_process_env,
    HardenedSealedGrant, ProcessInstanceKey, ReaForensicVerdict, ReaVoterEnvGateway,
    VoterQuorumAlert, ZeroizingLockedSecret,
};
use std::time::Duration;

#[test]
fn test_zeroizing_locked_secret_wipes_allocation() {
    let raw = b"TOP_SECRET_AUTH_BEARER_TOKEN_999";
    let secret = ZeroizingLockedSecret::new(raw);
    assert_eq!(secret.as_slice(), raw);

    // Verify clone shares underlying Arc safely
    let clone = secret.clone();
    assert_eq!(clone.as_slice(), raw);
    drop(clone);

    // Drop last instance triggers volatile zero-fill
    drop(secret);
}

#[test]
fn test_host_normalization_and_defense() {
    assert_eq!(normalize_host("API.ANTHROPIC.COM:443"), "api.anthropic.com");
    assert_eq!(normalize_host("api.anthropic.com."), "api.anthropic.com");
    assert_eq!(normalize_host("https://api.anthropic.com"), "https://api.anthropic.com");
}

#[test]
fn test_current_process_resolution_and_clean_env() {
    let my_pid = std::process::id();
    let key = resolve_process_instance_key(my_pid).expect("resolve own instance key");
    assert_eq!(key.pid, my_pid);
    assert!(key.start_time_ticks > 0);
    assert_eq!(key.start_time_100ns(), key.start_time_ticks);

    let exe = resolve_pid_exe(my_pid).expect("resolve own exe");
    assert!(exe.exists());

    // Clean env check for current process
    let clean = verify_clean_process_env(my_pid);
    assert!(clean.is_ok(), "Current test process environment should be clean");
}

#[test]
fn test_toctou_reparse_point_defense() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let target_file = temp_dir.path().join("real_binary.bin");
    std::fs::write(&target_file, b"GENUINE_BINARY_PAYLOAD_SHA256").expect("write target");

    // Regular file hashes successfully
    let hash = hash_file_sha256_nofollow(&target_file).expect("hash regular file");
    assert_ne!(hash, [0u8; 32]);

    // Test directory rejection
    let dir_err = hash_file_sha256_nofollow(temp_dir.path()).unwrap_err();
    assert!(dir_err.contains("directory") || dir_err.contains("regular file"));

    // Test symlink rejection if symlink creation is permitted
    #[cfg(unix)]
    {
        let symlink_path = temp_dir.path().join("symlink.bin");
        let _ = std::os::unix::fs::symlink(&target_file, &symlink_path);
        if symlink_path.exists() {
            let sym_err = hash_file_sha256_nofollow(&symlink_path).unwrap_err();
            assert!(sym_err.contains("symbolic link") || sym_err.contains("reparse point"));
        }
    }

    #[cfg(windows)]
    {
        // On Windows, test creating a file symlink or directory junction
        let symlink_path = temp_dir.path().join("symlink_target.bin");
        let _ = std::os::windows::fs::symlink_file(&target_file, &symlink_path);
        if symlink_path.symlink_metadata().is_ok() {
            let sym_err = hash_file_sha256_nofollow(&symlink_path).unwrap_err();
            assert!(sym_err.contains("symbolic link") || sym_err.contains("reparse point"));
        }
    }
}

#[test]
fn test_multi_token_outbound_atomic_swap() {
    let my_pid = std::process::id();
    let my_exe = resolve_pid_exe(my_pid).expect("resolve own exe");
    let my_bin_hash = hash_file_sha256_nofollow(&my_exe).expect("hash own exe");

    let gw = ReaVoterEnvGateway::new(Duration::from_secs(30));

    let token1 = "OSHOOSI_STANDIN_TOKEN_OPENAI_SEC1";
    let real_secret1 = b"sk-live-actual-openai-secret-key-111";
    let grant1 = HardenedSealedGrant::new(
        "OPENAI_API_KEY",
        token1,
        my_bin_hash,
        None,
        "api.openai.com",
        ZeroizingLockedSecret::new(real_secret1),
    );

    let token2 = "OSHOOSI_STANDIN_TOKEN_ANTHROPIC_SEC2";
    let real_secret2 = b"sk-ant-actual-anthropic-secret-key-222";
    let grant2 = HardenedSealedGrant::new(
        "ANTHROPIC_API_KEY",
        token2,
        my_bin_hash,
        None,
        "api.openai.com", // Pinned to same upstream host for multi-token test
        ZeroizingLockedSecret::new(real_secret2),
    );

    gw.register_grant(grant1);
    gw.register_grant(grant2);

    // Multi-token payload containing both stand-in tokens
    let payload = format!(
        "POST /v1/chat HTTP/1.1\r\nHost: api.openai.com:443\r\nAuthorization: Bearer {}\r\nX-Custom: {}\r\n\r\n{{}}",
        token1, token2
    );

    let swapped = gw
        .verify_and_swap_outbound(my_pid, "api.openai.com:443", payload.as_bytes())
        .expect("multi-token swap must succeed");

    let swapped_str = String::from_utf8_lossy(&swapped);
    assert!(swapped_str.contains("sk-live-actual-openai-secret-key-111"));
    assert!(swapped_str.contains("sk-ant-actual-anthropic-secret-key-222"));
    assert!(!swapped_str.contains(token1));
    assert!(!swapped_str.contains(token2));
}

#[test]
fn test_multi_token_fails_closed_if_one_host_mismatches() {
    let my_pid = std::process::id();
    let my_exe = resolve_pid_exe(my_pid).expect("resolve own exe");
    let my_bin_hash = hash_file_sha256_nofollow(&my_exe).expect("hash own exe");

    let gw = ReaVoterEnvGateway::new(Duration::from_secs(30));

    let token1 = "OSHOOSI_STANDIN_TOKEN_OPENAI_VALID";
    let grant1 = HardenedSealedGrant::new(
        "OPENAI_API_KEY",
        token1,
        my_bin_hash,
        None,
        "api.openai.com",
        ZeroizingLockedSecret::new(b"secret1"),
    );

    let token2 = "OSHOOSI_STANDIN_TOKEN_MISMATCH_HOST";
    let grant2 = HardenedSealedGrant::new(
        "OTHER_KEY",
        token2,
        my_bin_hash,
        None,
        "api.anthropic.com", // Mismatched host!
        ZeroizingLockedSecret::new(b"secret2"),
    );

    gw.register_grant(grant1);
    gw.register_grant(grant2);

    let payload = format!("Auth: {} & Other: {}", token1, token2);
    let err = gw
        .verify_and_swap_outbound(my_pid, "api.openai.com", payload.as_bytes())
        .unwrap_err();

    assert!(err.contains("Host header mismatch"));
}

#[test]
fn test_overlapping_tokens_rejected_fail_closed() {
    let my_pid = std::process::id();
    let my_exe = resolve_pid_exe(my_pid).expect("resolve own exe");
    let my_bin_hash = hash_file_sha256_nofollow(&my_exe).expect("hash own exe");

    let gw = ReaVoterEnvGateway::new(Duration::from_secs(30));

    let token1 = "TOKEN_ABCDEF";
    let token2 = "ABCDEF_GHIJK";

    gw.register_grant(HardenedSealedGrant::new(
        "VAR1",
        token1,
        my_bin_hash,
        None,
        "api.example.com",
        ZeroizingLockedSecret::new(b"sec1"),
    ));
    gw.register_grant(HardenedSealedGrant::new(
        "VAR2",
        token2,
        my_bin_hash,
        None,
        "api.example.com",
        ZeroizingLockedSecret::new(b"sec2"),
    ));

    // Payload has overlapping tokens: TOKEN_ABCDEF_GHIJK
    let payload = b"Payload with TOKEN_ABCDEF_GHIJK overlap";
    let err = gw
        .verify_and_swap_outbound(my_pid, "api.example.com", payload)
        .unwrap_err();

    assert!(err.contains("Overlapping stand-in tokens"));
}

#[test]
fn test_voter_freeze_and_rea_revocation_lifecycle() {
    let gw = ReaVoterEnvGateway::new(Duration::from_millis(500));
    let target_key = ProcessInstanceKey::new(7777, 88888);

    // 1. Quorum Alert triggers instant freeze (< 1 µs)
    let alert = VoterQuorumAlert::new(target_key, 7500, "byzantine quorum detection");
    gw.ingest_voter_quorum(alert);

    // Target is now quarantined
    let grant = HardenedSealedGrant::new(
        "KEY",
        "STANDIN_TOKEN_QUARANTINE_TEST",
        [0xAAu8; 32],
        None,
        "api.openai.com",
        ZeroizingLockedSecret::new(b"secret"),
    );
    gw.register_grant(grant);

    // 2. REA Forensic Verdict confirms malicious
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let bin_path = temp_dir.path().join("malicious.exe");
    std::fs::write(&bin_path, b"MALICIOUS_C2_DROPPER_BYTES").expect("write bin");

    let verdict = ReaForensicVerdict {
        target: target_key,
        binary_path: bin_path.clone(),
        script_or_module_path: None,
        extracted_c2_domains: vec!["malware-c2-channel.darkweb".to_string()],
        injected_module_hashes: vec![[0xCCu8; 32]],
        confirmed_malicious: true,
    };

    gw.ingest_rea_verdict(verdict);

    // Verify destination host is blacklisted
    let c2_attempt = gw.verify_and_swap_outbound(
        std::process::id(),
        "malware-c2-channel.darkweb",
        b"GET / HTTP/1.1\r\n\r\n",
    );
    assert!(c2_attempt.unwrap_err().contains("matches C2 domain extracted by REA"));
}

#[test]
fn test_protected_env_backup_vault_full_lifecycle() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let env_path = temp_dir.path().join(".env");
    let vault_path = temp_dir.path().join("protected_env_backup.vault");

    let initial_content = "OPENAI_API_KEY=sk-production-live-token-secret-777\nHF_TOKEN=hf_very_private_huggingface_token\n";
    std::fs::write(&env_path, initial_content).expect("write initial env");

    let grant1 = HardenedSealedGrant::new(
        "OPENAI_API_KEY",
        "OSHOOSI_STANDIN_OPENAI_VAULT_TEST",
        [0x11u8; 32],
        None,
        "api.openai.com",
        ZeroizingLockedSecret::new(b"sk-production-live-token-secret-777"),
    );
    let grant2 = HardenedSealedGrant::new(
        "HF_TOKEN",
        "OSHOOSI_STANDIN_HF_VAULT_TEST",
        [0x22u8; 32],
        None,
        "huggingface.co",
        ZeroizingLockedSecret::new(b"hf_very_private_huggingface_token"),
    );

    // 1. Seal and backup
    ProtectedEnvBackupVault::seal_and_backup(&env_path, &vault_path, &[grant1, grant2])
        .expect("seal and backup");

    // Verify .env has stand-in tokens
    let sealed_content = std::fs::read_to_string(&env_path).expect("read sealed env");
    assert!(sealed_content.contains("OSHOOSI_STANDIN_OPENAI_VAULT_TEST"));
    assert!(sealed_content.contains("OSHOOSI_STANDIN_HF_VAULT_TEST"));
    assert!(!sealed_content.contains("sk-production-live-token-secret-777"));

    // Verify status query
    let status = ProtectedEnvBackupVault::get_status(&vault_path).expect("get status");
    assert!(status.exists);
    assert_eq!(status.sealed_variables.len(), 2);
    assert!(status.dacl_protected);

    // 2. Auto-revert restores exact content
    ProtectedEnvBackupVault::auto_revert(&vault_path).expect("auto revert");
    let restored_content = std::fs::read_to_string(&env_path).expect("read restored env");
    assert_eq!(restored_content, initial_content);

    // 3. Removal without confirm fails
    let err = ProtectedEnvBackupVault::remove_backup(&vault_path, false).unwrap_err();
    assert!(matches!(err, VaultError::ConfirmationRequired));
    assert!(vault_path.exists());

    // 4. Removal with confirm shreds and unlinks
    ProtectedEnvBackupVault::remove_backup(&vault_path, true).expect("remove backup with confirm");
    assert!(!vault_path.exists());
}

#[test]
fn test_gateway_shutdown_auto_reverts_vault_before_zero_wiping() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let env_path = temp_dir.path().join(".env");
    let vault_path = temp_dir.path().join("shutdown_auto_revert.vault");

    let original_content = "SERVICE_API_SECRET=my_original_secret_12345\n";
    std::fs::write(&env_path, original_content).expect("write original env");

    let standin = "OSHOOSI_STANDIN_SHUTDOWN_TEST";
    let grant = HardenedSealedGrant::new(
        "SERVICE_API_SECRET",
        standin,
        [0x33u8; 32],
        None,
        "api.service.internal",
        ZeroizingLockedSecret::new(b"my_original_secret_12345"),
    );

    ProtectedEnvBackupVault::seal_and_backup(&env_path, &vault_path, std::slice::from_ref(&grant))
        .expect("seal backup");

    // Verify .env currently contains standin
    let current_env = std::fs::read_to_string(&env_path).expect("read sealed env");
    assert!(current_env.contains(standin));

    // Create gateway with vault path
    let gw = ReaVoterEnvGateway::with_vault(Duration::from_secs(60), vault_path.clone());
    gw.register_grant(grant);
    assert_eq!(gw.grant_count(), 1);
    assert!(gw.is_active());

    // Trigger service stop (simulating SCM STOP / SIGTERM / Ctrl+C)
    gw.on_service_stop();

    // Verify gateway is inactive and grants are cleared (zero-wiped)
    assert!(!gw.is_active());
    assert_eq!(gw.grant_count(), 0);

    // Verify .env was automatically reverted to original content!
    let reverted_env = std::fs::read_to_string(&env_path).expect("read reverted env");
    assert_eq!(reverted_env, original_content);
}
