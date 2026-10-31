//! Empirical Challenger Test Suite for Milestone M1:
//! DACL Error Resilience, Multi-Vault Discovery, and Bit-for-Bit Roundtrip Secret Recovery.
//!
//! Author: challenger_m1_2 (Empirical Challenger)
//! Roles: critic, specialist

use osoosi_core::protected_env_backup::ProtectedEnvBackupVault;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;

static TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn compute_sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

#[test]
fn test_challenge_dacl_permission_denied_fallback() {
    let _guard = TEST_MUTEX.lock().unwrap();
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let valid_vault = temp_dir.path().join("valid.vault");
    let unreadable_vault = temp_dir.path().join("unreadable.vault");
    let env_file = temp_dir.path().join(".env");

    let original_content = "GEMINI_API_KEY=AIzaSyD-DaclFallbackTestSecret12345\nPORT=3000\n";
    std::fs::write(&env_file, original_content).expect("write .env");

    // Create a valid vault
    ProtectedEnvBackupVault::seal_and_backup_dynamic(&env_file, &valid_vault)
        .expect("seal valid vault");
    assert!(valid_vault.exists());

    // Create an unreadable file or simulate permission denied
    std::fs::write(&unreadable_vault, b"DUMMY_UNREADABLE_CONTENT").expect("write unreadable vault");

    #[cfg(windows)]
    {
        // On Windows, set NTFS DACL to deny read access to Everyone
        let unreadable_str = unreadable_vault.to_str().unwrap();
        let _ = std::process::Command::new("icacls")
            .args([unreadable_str, "/deny", "Everyone:(R,RD)"])
            .output();
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&unreadable_vault, std::fs::Permissions::from_mode(0o000))
            .unwrap();
    }

    // 1. Challenge locate_active_vault_path:
    // When custom_path points to an unreadable vault, it should log a warning and fall back
    // to an accessible vault or not panic.
    let located = ProtectedEnvBackupVault::locate_active_vault_path(Some(&unreadable_vault));
    // Must not panic!
    println!(
        "[Challenger] locate_active_vault_path with unreadable custom path returned: {:?}",
        located
    );

    // 2. Challenge auto_revert_all_active_vaults:
    // If auto_revert_all_active_vaults is given a custom path that is unreadable, it must NOT panic,
    // and must handle PermissionDenied (os error 5) gracefully.
    let revert_res =
        ProtectedEnvBackupVault::auto_revert_all_active_vaults(Some(&unreadable_vault));
    println!(
        "[Challenger] auto_revert_all_active_vaults result: {:?}",
        revert_res
    );
    assert!(
        revert_res.is_ok(),
        "auto_revert_all_active_vaults must continue without panic on PermissionDenied"
    );

    // Clean up permissions so temp_dir can be deleted cleanly
    #[cfg(windows)]
    {
        let unreadable_str = unreadable_vault.to_str().unwrap();
        let _ = std::process::Command::new("icacls")
            .args([unreadable_str, "/remove:d", "Everyone"])
            .output();
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&unreadable_vault, std::fs::Permissions::from_mode(0o600));
    }
}

#[test]
fn test_challenge_live_target_release_vault_access_denied_resilience() {
    let _guard = TEST_MUTEX.lock().unwrap();

    // Check if the live target/release/database/protected_env_backup.vault exists on this host
    let target_vault = PathBuf::from("target/release/database/protected_env_backup.vault");
    if target_vault.exists() {
        // Test that locate_active_vault_path handles the live SYSTEM-DACL vault without crashing
        let located = ProtectedEnvBackupVault::locate_active_vault_path(Some(&target_vault));
        println!(
            "[Challenger] Live target/release vault located fallback: {:?}",
            located
        );

        // Test that auto_revert_all_active_vaults handles the live SYSTEM-DACL vault without crashing
        let res = ProtectedEnvBackupVault::auto_revert_all_active_vaults(Some(&target_vault));
        println!(
            "[Challenger] Live target/release auto_revert_all_active_vaults: {:?}",
            res
        );
        assert!(
            res.is_ok(),
            "Live access-denied vault must not cause panic in auto_revert_all_active_vaults"
        );
    }
}

#[test]
fn test_challenge_multi_file_roundtrip_bit_for_bit_integrity_and_no_token_leak() {
    let _guard = TEST_MUTEX.lock().unwrap();
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let root = temp_dir.path();
    let vault_file = root.join("challenge_multi.vault");

    // File 1: Root .env with comments, export syntax, quotes, CRLF
    let f1 = root.join(".env");
    let f1_original = "# Root Configuration\r\nexport GEMINI_API_KEY=\"AIzaSyD-ChallengerTestRootKey12345\" # primary root\r\nPATH=C:\\Windows\\system32;C:\\tools\r\nJAVA_HOME=C:\\Program Files\\Java\\jdk-21\r\nPORT=9090\r\n";
    std::fs::write(&f1, f1_original.as_bytes()).unwrap();

    // File 2: Root .env.local with single quotes and trailing comment
    let f2 = root.join(".env.local");
    let f2_original =
        "HF_TOKEN='hf_ChallengerTestTokenLocal98765' # local token\nNODE_ENV=development\n";
    std::fs::write(&f2, f2_original.as_bytes()).unwrap();

    // File 3: Subdirectory depth-1 .env.production
    let sub1 = root.join("frontend");
    std::fs::create_dir_all(&sub1).unwrap();
    let f3 = sub1.join(".env.production");
    let f3_original = "# Production Frontend\nexport ANTHROPIC_API_KEY=\"sk-ant-ChallengerTestProdSecret999\"\nDEBUG=false\n";
    std::fs::write(&f3, f3_original.as_bytes()).unwrap();

    // File 4: Subdirectory depth-1 .env with unquoted secret and equal signs in other vars
    let sub2 = root.join("backend");
    std::fs::create_dir_all(&sub2).unwrap();
    let f4 = sub2.join(".env");
    let f4_original = "OTX_API_KEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\nBASE64_URL=https://example.com/api?param=1&foo=bar==\nAPP_NAME=OshoosiClaw\n";
    std::fs::write(&f4, f4_original.as_bytes()).unwrap();

    // Store pre-seal SHA-256 for all 4 files
    let mut pre_seal_shas = HashMap::new();
    pre_seal_shas.insert(f1.clone(), compute_sha256(f1_original.as_bytes()));
    pre_seal_shas.insert(f2.clone(), compute_sha256(f2_original.as_bytes()));
    pre_seal_shas.insert(f3.clone(), compute_sha256(f3_original.as_bytes()));
    pre_seal_shas.insert(f4.clone(), compute_sha256(f4_original.as_bytes()));

    // 1. Perform dynamic multi-file seal
    let seal_res = ProtectedEnvBackupVault::seal_and_backup_dynamic(&f1, &vault_file)
        .expect("seal_and_backup_dynamic must succeed across multi-file tree");
    assert!(
        seal_res.total_selected >= 4,
        "Must select all 4 genuine API keys"
    );

    // Verify vault status tracks all files
    let status = ProtectedEnvBackupVault::get_status(&vault_file).expect("get_status");
    assert!(status.exists);
    assert_eq!(
        status.files.len(),
        4,
        "Vault must track all 4 backed-up files"
    );

    // 2. Verify all files have stand-ins and NO raw secrets leak
    let f1_sealed = std::fs::read_to_string(&f1).unwrap();
    assert!(f1_sealed.contains("export GEMINI_API_KEY=\"OSHOOSI_STANDIN_GEMINI_API_KEY_"));
    assert!(!f1_sealed.contains("AIzaSyD-ChallengerTestRootKey12345"));
    assert!(f1_sealed.contains("# primary root"));
    assert!(f1_sealed.contains("PATH=C:\\Windows\\system32;C:\\tools"));
    assert!(f1_sealed.contains("JAVA_HOME=C:\\Program Files\\Java\\jdk-21"));
    assert!(f1_sealed.contains("PORT=9090"));

    let f2_sealed = std::fs::read_to_string(&f2).unwrap();
    assert!(f2_sealed.contains("HF_TOKEN='OSHOOSI_STANDIN_HF_TOKEN_"));
    assert!(!f2_sealed.contains("hf_ChallengerTestTokenLocal98765"));
    assert!(f2_sealed.contains("# local token"));
    assert!(f2_sealed.contains("NODE_ENV=development"));

    let f3_sealed = std::fs::read_to_string(&f3).unwrap();
    assert!(f3_sealed.contains("export ANTHROPIC_API_KEY=\"OSHOOSI_STANDIN_ANTHROPIC_API_KEY_"));
    assert!(!f3_sealed.contains("sk-ant-ChallengerTestProdSecret999"));
    assert!(f3_sealed.contains("DEBUG=false"));

    let f4_sealed = std::fs::read_to_string(&f4).unwrap();
    assert!(f4_sealed.contains("OTX_API_KEY=OSHOOSI_STANDIN_OTX_API_KEY_"));
    assert!(!f4_sealed.contains("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
    assert!(f4_sealed.contains("BASE64_URL=https://example.com/api?param=1&foo=bar=="));
    assert!(f4_sealed.contains("APP_NAME=OshoosiClaw"));

    // 3. Challenge partial unseal: revert single file (f3)
    ProtectedEnvBackupVault::revert_single_file(&vault_file, &f3)
        .expect("revert_single_file for f3 must succeed");

    // f3 must match pre-seal bytes 100% bit-for-bit
    let f3_restored = std::fs::read(&f3).unwrap();
    assert_eq!(compute_sha256(&f3_restored), pre_seal_shas[&f3]);
    assert_eq!(std::str::from_utf8(&f3_restored).unwrap(), f3_original);

    // f1, f2, f4 must STILL be sealed
    assert!(std::fs::read_to_string(&f1)
        .unwrap()
        .contains("OSHOOSI_STANDIN_GEMINI_API_KEY_"));
    assert!(std::fs::read_to_string(&f2)
        .unwrap()
        .contains("OSHOOSI_STANDIN_HF_TOKEN_"));
    assert!(std::fs::read_to_string(&f4)
        .unwrap()
        .contains("OSHOOSI_STANDIN_OTX_API_KEY_"));

    // 4. Challenge full unseal: auto_revert all
    ProtectedEnvBackupVault::auto_revert(&vault_file).expect("auto_revert must succeed");

    // Verify EVERY file matches original SHA-256 bit-for-bit
    for (path, expected_sha) in &pre_seal_shas {
        let content_bytes = std::fs::read(path).expect("read file after revert");
        let actual_sha = compute_sha256(&content_bytes);
        assert_eq!(
            &actual_sha,
            expected_sha,
            "File {} failed bit-for-bit SHA-256 verification after auto_revert",
            path.display()
        );

        // Verify ZERO stand-in tokens remain
        let content_str = String::from_utf8_lossy(&content_bytes);
        assert!(
            !content_str.contains("OSHOOSI_STANDIN_"),
            "Leaked stand-in token in {} after auto_revert!",
            path.display()
        );
    }
}

#[test]
fn test_challenge_double_seal_idempotency_and_zero_standin_contamination() {
    let _guard = TEST_MUTEX.lock().unwrap();
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let env_file = temp_dir.path().join(".env");
    let vault_file = temp_dir.path().join("idempotency.vault");

    let original_secret = "AIzaSyD-DoubleSealIdempotencyTestKey123";
    let original_content = format!("GEMINI_API_KEY=\"{}\"\nPORT=8000\n", original_secret);
    std::fs::write(&env_file, &original_content).unwrap();

    let orig_sha = compute_sha256(original_content.as_bytes());

    // First seal
    ProtectedEnvBackupVault::seal_and_backup_dynamic(&env_file, &vault_file).expect("seal 1");

    // Second seal immediately after (without reverting first)
    ProtectedEnvBackupVault::seal_and_backup_dynamic(&env_file, &vault_file).expect("seal 2");

    // Verify vault status shows sealed variable
    let status = ProtectedEnvBackupVault::get_status(&vault_file).expect("read vault status");
    assert!(status
        .sealed_variables
        .contains(&"GEMINI_API_KEY".to_string()));
    assert!(!status.standin_mappings.is_empty());

    // Revert
    ProtectedEnvBackupVault::auto_revert(&vault_file).expect("auto_revert");

    let restored_bytes = std::fs::read(&env_file).unwrap();
    assert_eq!(compute_sha256(&restored_bytes), orig_sha);
    assert_eq!(
        std::str::from_utf8(&restored_bytes).unwrap(),
        original_content
    );
    assert!(!std::fs::read_to_string(&env_file)
        .unwrap()
        .contains("OSHOOSI_STANDIN_"));
}
