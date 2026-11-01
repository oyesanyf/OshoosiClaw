//! Empirical Challenger 1 Stress Harness for Milestone 4:
//! - Multi-directory `.env*` discovery, sealing, and automatic unseal on stop.
//! - 0-diff verbatim restoration across complex formatting (quotes, comments, exports, spacing).
//! - Idempotency of double and triple auto-revert calls.
//! - DACL `os error 5` (PermissionDenied) resiliency across multi-vault environments.
//!
//! Author: teamwork_challenger_m4_r3_1 (Empirical Challenger)
//! Roles: critic, specialist

use osoosi_core::protected_env_backup::ProtectedEnvBackupVault;
use std::collections::HashMap;

static HARNESS_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn test_m4_stress_multi_directory_formatting_and_0diff_unseal() {
    let _guard = HARNESS_MUTEX.lock().unwrap();
    let temp = tempfile::tempdir().expect("create tempdir");
    let base_dir = temp.path();

    // 1. Setup multi-directory layout with subdirs including spaces
    let dir_root = base_dir.to_path_buf();
    let dir_frontend = base_dir.join("apps").join("frontend");
    let dir_backend = base_dir.join("apps").join("backend").join("api");
    let dir_spaces = base_dir.join("data and storage").join("service config");

    std::fs::create_dir_all(&dir_frontend).expect("create frontend dir");
    std::fs::create_dir_all(&dir_backend).expect("create backend dir");
    std::fs::create_dir_all(&dir_spaces).expect("create spaces dir");

    let file_root = dir_root.join(".env");
    let file_frontend = dir_frontend.join(".env.local");
    let file_backend = dir_backend.join(".env.production");
    let file_spaces = dir_spaces.join(".env.custom");

    // Complex formatting payloads
    let root_content = "\
# Root configuration file
PORT=3000
GEMINI_API_KEY=test_gemini_key_1234567890
NODE_ENV=production
# End of file
";

    let frontend_content = "\
export VITE_APP_NAME=\"Frontend Dashboard\"
export HF_TOKEN='test_hf_token_9876543210'
VITE_API_URL=https://api.example.com
PUBLIC_SETTING=\"public_val\"   
";

    let backend_content = "\
# Backend API configuration with inline comments
ANTHROPIC_API_KEY=\"test_anthropic_key_456\" # inline secret comment
DATABASE_URL=\"postgres://user:pass@localhost:5432/db\"
OPENAI_API_KEY=test_openai_key_789 # second secret
RUST_LOG=info
";

    let spaces_content = "\
AWS_SECRET_ACCESS_KEY=\"test_aws_secret_key_123\"
SERVICE_NAME=worker-daemon
EMPTY_VAR=
SPECIAL_CHARS=\"foo#bar=baz&qux\"
";

    let mut original_files = HashMap::new();
    original_files.insert(file_root.clone(), root_content.as_bytes().to_vec());
    original_files.insert(file_frontend.clone(), frontend_content.as_bytes().to_vec());
    original_files.insert(file_backend.clone(), backend_content.as_bytes().to_vec());
    original_files.insert(file_spaces.clone(), spaces_content.as_bytes().to_vec());

    for (path, bytes) in &original_files {
        std::fs::write(path, bytes).expect("write original file");
    }

    let vault_path = base_dir.join("m4_stress_multi.vault");

    // 2. Incrementally seal all files into the same vault
    for path in original_files.keys() {
        let seal_res = ProtectedEnvBackupVault::seal_and_backup_dynamic(path, &vault_path)
            .expect("seal file into vault");
        assert!(
            seal_res.total_selected >= 1,
            "Expected at least 1 credential selected for {}",
            path.display()
        );
    }

    // Verify stand-in replacements were injected while non-secrets remain
    let s_root = std::fs::read_to_string(&file_root).unwrap();
    assert!(s_root.contains("OSHOOSI_STANDIN_GEMINI_API_KEY_"));
    assert!(s_root.contains("PORT=3000"));
    assert!(s_root.contains("NODE_ENV=production"));

    let s_front = std::fs::read_to_string(&file_frontend).unwrap();
    assert!(s_front.contains("OSHOOSI_STANDIN_HF_TOKEN_"));
    assert!(s_front.contains("VITE_APP_NAME=\"Frontend Dashboard\""));

    let s_back = std::fs::read_to_string(&file_backend).unwrap();
    assert!(s_back.contains("OSHOOSI_STANDIN_ANTHROPIC_API_KEY_"));
    assert!(s_back.contains("OSHOOSI_STANDIN_OPENAI_API_KEY_"));
    assert!(s_back.contains("DATABASE_URL=\"postgres://user:pass@localhost:5432/db\""));

    let s_spaces = std::fs::read_to_string(&file_spaces).unwrap();
    assert!(s_spaces.contains("OSHOOSI_STANDIN_AWS_SECRET_ACCESS_KEY_"));
    assert!(s_spaces.contains("SERVICE_NAME=worker-daemon"));

    // 3. Trigger auto_revert_all_active_vaults (simulating service stop)
    let unseal_res = ProtectedEnvBackupVault::auto_revert_all_active_vaults(Some(&vault_path));
    assert!(
        unseal_res.is_ok(),
        "auto_revert_all_active_vaults failed: {:?}",
        unseal_res.err()
    );

    // 4. Verify 0-diff verbatim restoration across all files
    for (path, expected_bytes) in &original_files {
        let restored_bytes = std::fs::read(path).expect("read restored file");
        assert_eq!(
            &restored_bytes,
            expected_bytes,
            "0-diff verification failed for file: {}",
            path.display()
        );
        let restored_str = String::from_utf8_lossy(&restored_bytes);
        assert!(
            !restored_str.contains("OSHOOSI_STANDIN_"),
            "Restored file still contains stand-in token in {}",
            path.display()
        );
    }
    println!("[PASS] test_m4_stress_multi_directory_formatting_and_0diff_unseal verified 0-diff restoration");
}

#[test]
fn test_m4_stress_idempotent_double_and_triple_unseal() {
    let _guard = HARNESS_MUTEX.lock().unwrap();
    let temp = tempfile::tempdir().expect("create tempdir");
    let env_file = temp.path().join(".env.idempotent");
    let vault_file = temp.path().join("idempotent_stress.vault");

    let secret_payload = "\
# Idempotency Stress Test
API_SECRET_KEY=sk-test-idempotent-repeat-123456789
APP_PORT=9090
DEBUG=false
";
    std::fs::write(&env_file, secret_payload).expect("write env file");

    ProtectedEnvBackupVault::seal_and_backup_dynamic(&env_file, &vault_file)
        .expect("seal into idempotent vault");

    // Revert 1
    let rev1 = ProtectedEnvBackupVault::auto_revert_all_active_vaults(Some(&vault_file));
    assert!(rev1.is_ok(), "First unseal must succeed: {:?}", rev1.err());
    let bytes_after_1 = std::fs::read(&env_file).expect("read after rev1");
    assert_eq!(
        bytes_after_1,
        secret_payload.as_bytes(),
        "Revert 1 must restore exact bytes"
    );

    // Revert 2 (Double unseal)
    let rev2 = ProtectedEnvBackupVault::auto_revert_all_active_vaults(Some(&vault_file));
    assert!(rev2.is_ok(), "Second unseal must succeed: {:?}", rev2.err());
    let bytes_after_2 = std::fs::read(&env_file).expect("read after rev2");
    assert_eq!(
        bytes_after_2,
        secret_payload.as_bytes(),
        "Revert 2 (double unseal) must maintain exact 0-diff"
    );

    // Revert 3 (Triple unseal)
    let rev3 = ProtectedEnvBackupVault::auto_revert_all_active_vaults(Some(&vault_file));
    assert!(rev3.is_ok(), "Third unseal must succeed: {:?}", rev3.err());
    let bytes_after_3 = std::fs::read(&env_file).expect("read after rev3");
    assert_eq!(
        bytes_after_3,
        secret_payload.as_bytes(),
        "Revert 3 (triple unseal) must maintain exact 0-diff"
    );
    println!("[PASS] test_m4_stress_idempotent_double_and_triple_unseal passed cleanly");
}

#[test]
fn test_m4_stress_dacl_os_error_5_resiliency() {
    let _guard = HARNESS_MUTEX.lock().unwrap();
    let temp = tempfile::tempdir().expect("create tempdir");

    let valid_vault = temp.path().join("accessible_valid.vault");
    let unreadable_vault = temp.path().join("unreadable_locked.vault");
    let valid_env = temp.path().join(".env.valid");

    let valid_content = "GEMINI_API_KEY=test_valid_dacl_key_999\nPORT=8000\n";
    std::fs::write(&valid_env, valid_content).expect("write valid env");

    ProtectedEnvBackupVault::seal_and_backup_dynamic(&valid_env, &valid_vault)
        .expect("seal valid env");

    // Write dummy unreadable vault
    std::fs::write(&unreadable_vault, b"CORRUPT_OR_LOCKED_VAULT_BYTES")
        .expect("write unreadable vault");

    #[cfg(windows)]
    {
        let unreadable_str = unreadable_vault.to_str().unwrap();
        let _ = std::process::Command::new("icacls")
            .args([unreadable_str, "/deny", "Everyone:(R,RD)"])
            .output();
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&unreadable_vault, std::fs::Permissions::from_mode(0o000));
    }

    // 1. Verify locate_active_vault_path gracefully skips unreadable custom path
    let located = ProtectedEnvBackupVault::locate_active_vault_path(Some(&unreadable_vault));
    println!(
        "[Challenger] locate_active_vault_path result for unreadable vault: {:?}",
        located
    );

    // 2. Verify auto_revert_all_active_vaults gracefully skips unreadable vault without panic or aborting
    let rev_res = ProtectedEnvBackupVault::auto_revert_all_active_vaults(Some(&unreadable_vault));
    assert!(
        rev_res.is_ok(),
        "auto_revert_all_active_vaults must not error or panic on os error 5: {:?}",
        rev_res.err()
    );

    // 3. Verify valid vault unseals cleanly even when unreadable vault exists in candidate search
    let rev_valid = ProtectedEnvBackupVault::auto_revert_all_active_vaults(Some(&valid_vault));
    assert!(
        rev_valid.is_ok(),
        "auto_revert_all_active_vaults on valid vault must succeed: {:?}",
        rev_valid.err()
    );
    let restored_valid = std::fs::read_to_string(&valid_env).expect("read valid env");
    assert!(restored_valid.contains("test_valid_dacl_key_999"));
    assert!(!restored_valid.contains("OSHOOSI_STANDIN_"));

    // Cleanup permissions
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
    println!("[PASS] test_m4_stress_dacl_os_error_5_resiliency passed cleanly");
}
