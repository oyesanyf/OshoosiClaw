//! Empirical Challenger Stress & Verification Suite for Milestone M9 (Defect 1 Remediation):
//! 1. Dynamic seal without pre-existing `.env` (no OS error 2, zero I/O errors).
//! 2. In-process memory replacement with `OSHOOSI_STANDIN_<KEY>_<16_HEX>` via `std::env::set_var`.
//! 3. Double-seal & multi-seal idempotency (preserving original secret across repeated seal calls and adding new keys).
//! 4. Auto-revert precision (process memory restoration, synthetic .env deletion, vault shredding on target_existed_before == false).
//! 5. Arm 3 prefix vetoes: ANTIGRAVITY_*, VSCODE_*, CARGO_*, RUST_*, TERM_*, NPM_*, SSH_*, GPG_*, GIT_*,
//!    plus PATH, JAVA_HOME, ONEDRIVE, TEMP, case-insensitivity, and confidence == 0 verification.
//!
//! Author: Challenger 1 (Milestone M9 - Defect 1 Remediation)
//! Roles: critic, specialist

use osoosi_core::protected_env_backup::{
    LlmFusionApiKeyEnumerator, ProtectedEnvBackupVault,
};
use osoosi_core::rea_voter_env_gateway::ReaVoterEnvGateway;
use std::sync::Mutex;
use std::time::Duration;

static ENV_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn test_challenge_1_dynamic_seal_without_preexisting_env_file() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let temp_dir = tempfile::tempdir().expect("create tempdir");
    let env_file = temp_dir.path().join("sub_dir").join(".env");
    let vault_file = temp_dir.path().join("vault_dir").join("env.vault");

    // Precondition: target file and its parent directory do NOT exist on disk
    assert!(!env_file.exists());
    assert!(!env_file.parent().unwrap().exists());

    let test_key = "GEMINI_API_KEY";
    let test_secret = "AIzaSyD-NonExistentEnvFileTestKey999888";
    std::env::set_var(test_key, test_secret);

    // Execute dynamic seal: must succeed with ZERO I/O errors (no OS error 2)
    let enum_res = ProtectedEnvBackupVault::seal_and_backup_dynamic(&env_file, &vault_file)
        .expect("seal_and_backup_dynamic must not fail with OS error 2 when .env is missing");

    assert!(enum_res.total_selected >= 1, "Must select GEMINI_API_KEY from process environment");
    assert!(vault_file.exists(), "Vault file must be created");
    assert!(env_file.exists(), "Synthetic .env file must be created");

    // Status query verification
    let status = ProtectedEnvBackupVault::get_status(&vault_file).expect("get_status");
    assert!(status.exists);
    assert!(status.sealed_variables.contains(&test_key.to_string()), "Sealed variables must contain {}", test_key);
    assert!(status.standin_mappings.iter().any(|(k, _)| k == test_key));

    let standin = status.standin_mappings.iter().find(|(k, _)| k == test_key).map(|(_, s)| s).unwrap();
    assert!(standin.starts_with("OSHOOSI_STANDIN_GEMINI_API_KEY_"));

    // Verify .env file content contains the stand-in token and NOT the raw secret
    let env_disk_content = std::fs::read_to_string(&env_file).expect("read synthetic .env");
    assert!(env_disk_content.contains(standin));
    assert!(!env_disk_content.contains(test_secret));

    // Clean up
    ProtectedEnvBackupVault::auto_revert(&vault_file).expect("auto revert");
    std::env::remove_var(test_key);
}

#[test]
fn test_challenge_2_process_memory_replacement_hides_raw_secret() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let temp_dir = tempfile::tempdir().expect("create tempdir");
    let env_file = temp_dir.path().join(".env");
    let vault_file = temp_dir.path().join("mem_test.vault");

    let keys_and_secrets = [
        ("OPENAI_API_KEY", "sk-proj-RealProductionSecretKeyForOpenAI1234567890"),
        ("ANTHROPIC_API_KEY", "sk-ant-api03-RealAnthropicKeyExample987654321012345"),
        ("HF_TOKEN", "hf_RealProductionHuggingFaceTokenExample555666777"),
    ];

    for (k, v) in &keys_and_secrets {
        std::env::set_var(k, v);
    }

    let gateway = ReaVoterEnvGateway::new(Duration::from_secs(60));

    // Dynamic seal with gateway registration
    let res = ProtectedEnvBackupVault::seal_and_register_with_gateway(&env_file, &vault_file, &gateway)
        .expect("seal and register with gateway");

    assert!(res.total_selected >= 3);

    // Verify in-process memory via std::env::var and std::env::vars()
    for (k, raw_v) in &keys_and_secrets {
        let current_val = std::env::var(k).expect("var must be present in process memory");
        assert!(
            current_val.starts_with(&format!("OSHOOSI_STANDIN_{}_", k)),
            "Process memory for {} must start with stand-in prefix, found: {}",
            k,
            current_val
        );
        assert_ne!(current_val, *raw_v, "Process memory MUST NOT match raw secret");
        assert!(!current_val.contains(*raw_v), "Process memory MUST NOT contain raw secret");
    }

    // Verify std::env::vars() iterator also sees only stand-in values
    let all_proc_vars: std::collections::HashMap<String, String> = std::env::vars().collect();
    for (k, raw_v) in &keys_and_secrets {
        let mem_val = all_proc_vars.get(*k).expect("key in env vars map");
        assert!(mem_val.starts_with(&format!("OSHOOSI_STANDIN_{}_", k)));
        assert_ne!(mem_val, *raw_v);
    }

    // Verify gateway has the grants registered
    assert!(gateway.grant_count() >= 3);

    // Clean up via auto_revert
    ProtectedEnvBackupVault::auto_revert(&vault_file).expect("auto_revert");
    for (k, _) in &keys_and_secrets {
        std::env::remove_var(k);
    }
}

#[test]
fn test_challenge_3_double_seal_and_multi_seal_idempotency_preserves_original_secrets() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let temp_dir = tempfile::tempdir().expect("create tempdir");
    let env_file = temp_dir.path().join(".env");
    let vault_file = temp_dir.path().join("idempotent.vault");

    let initial_content = "# Production Configuration\nGEMINI_API_KEY=AIzaSyD-FirstSecretKey111111111111\nPATH=C:\\Windows;C:\\Tools\n";
    std::fs::write(&env_file, initial_content).expect("write initial env");

    std::env::set_var("GEMINI_API_KEY", "AIzaSyD-FirstSecretKey111111111111");

    // PASS 1: Seal
    let res1 = ProtectedEnvBackupVault::seal_and_backup_dynamic(&env_file, &vault_file)
        .expect("pass 1 seal");
    assert!(res1.total_selected >= 1);

    let token_pass1 = std::env::var("GEMINI_API_KEY").expect("standin pass 1");
    assert!(token_pass1.starts_with("OSHOOSI_STANDIN_GEMINI_API_KEY_"));

    // PASS 2: Seal again immediately when tokens are already stand-ins
    let res2 = ProtectedEnvBackupVault::seal_and_backup_dynamic(&env_file, &vault_file)
        .expect("pass 2 seal");
    assert!(res2.total_selected >= 1);

    // PASS 3: Seal a third time
    let res3 = ProtectedEnvBackupVault::seal_and_backup_dynamic(&env_file, &vault_file)
        .expect("pass 3 seal");
    assert!(res3.total_selected >= 1);

    // PASS 4: Introduce a SECOND secret in the environment while the first is already sealed!
    std::env::set_var("ANTHROPIC_API_KEY", "sk-ant-SecondSecretKey22222222222222222222");
    let res4 = ProtectedEnvBackupVault::seal_and_backup_dynamic(&env_file, &vault_file)
        .expect("pass 4 seal with newly introduced secret");
    assert!(res4.total_selected >= 2);

    // Check status: both variables should be tracked
    let status = ProtectedEnvBackupVault::get_status(&vault_file).expect("status after pass 4");
    assert!(status.sealed_variables.contains(&"GEMINI_API_KEY".to_string()));
    assert!(status.sealed_variables.contains(&"ANTHROPIC_API_KEY".to_string()));

    // Verify auto_revert restores BOTH original raw secrets bit-for-bit
    ProtectedEnvBackupVault::auto_revert(&vault_file).expect("auto_revert after multi-seal");

    assert_eq!(
        std::env::var("GEMINI_API_KEY").unwrap(),
        "AIzaSyD-FirstSecretKey111111111111",
        "Original GEMINI_API_KEY must not be corrupted by repeated sealing"
    );
    assert_eq!(
        std::env::var("ANTHROPIC_API_KEY").unwrap(),
        "sk-ant-SecondSecretKey22222222222222222222",
        "Newly added ANTHROPIC_API_KEY must also be restored cleanly"
    );

    let restored_file = std::fs::read_to_string(&env_file).expect("read restored file");
    assert_eq!(restored_file, initial_content, "Original .env content must be 100% bit-exact");

    std::env::remove_var("GEMINI_API_KEY");
    std::env::remove_var("ANTHROPIC_API_KEY");
}

#[test]
fn test_challenge_4_auto_revert_precision_existed_vs_nonexisted() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let temp_dir = tempfile::tempdir().expect("create tempdir");

    // Case A: File DID exist before
    {
        let env_file = temp_dir.path().join("case_a.env");
        let vault_file = temp_dir.path().join("case_a.vault");
        let original_data = "OPENAI_API_KEY=sk-orig-open-ai-secret-val-9999\nDATABASE_URL=postgres://u:p@db:5432/test\n";
        std::fs::write(&env_file, original_data).expect("write original data");
        std::env::set_var("OPENAI_API_KEY", "sk-orig-open-ai-secret-val-9999");

        ProtectedEnvBackupVault::seal_and_backup_dynamic(&env_file, &vault_file).expect("seal case a");
        assert!(vault_file.exists());

        ProtectedEnvBackupVault::auto_revert(&vault_file).expect("revert case a");

        // env_file MUST still exist and match original_data
        assert!(env_file.exists());
        assert_eq!(std::fs::read_to_string(&env_file).unwrap(), original_data);
        assert_eq!(std::env::var("OPENAI_API_KEY").unwrap(), "sk-orig-open-ai-secret-val-9999");
        // Vault file remains unless explicitly removed or target didn't exist
        assert!(vault_file.exists());
        ProtectedEnvBackupVault::remove_backup(&vault_file, true).expect("clean vault");
        std::env::remove_var("OPENAI_API_KEY");
    }

    // Case B: File did NOT exist before
    {
        let env_file = temp_dir.path().join("case_b.env");
        let vault_file = temp_dir.path().join("case_b.vault");
        assert!(!env_file.exists());

        std::env::set_var("GEMINI_API_KEY", "AIzaSyD-CaseBSecretKeyForNonExistentFile");

        ProtectedEnvBackupVault::seal_and_backup_dynamic(&env_file, &vault_file).expect("seal case b");
        assert!(env_file.exists(), "Synthetic .env must exist while sealed");
        assert!(vault_file.exists(), "Vault file must exist while sealed");

        ProtectedEnvBackupVault::auto_revert(&vault_file).expect("revert case b");

        // Crucial invariant: synthetic .env file MUST be removed on auto_revert!
        assert!(!env_file.exists(), "Synthetic .env must be deleted on auto_revert when target_existed_before == false");
        // Crucial invariant: temporary backup vault MUST be shredded and deleted!
        assert!(!vault_file.exists(), "Temporary vault must be shredded on auto_revert when target_existed_before == false");

        assert_eq!(
            std::env::var("GEMINI_API_KEY").unwrap(),
            "AIzaSyD-CaseBSecretKeyForNonExistentFile",
            "Process memory must be restored to original secret"
        );
        std::env::remove_var("GEMINI_API_KEY");
    }

    // Case C: auto_revert on nonexistent vault returns Ok(()) idempotently
    {
        let nonexistent_vault = temp_dir.path().join("never_created.vault");
        let res = ProtectedEnvBackupVault::auto_revert(&nonexistent_vault);
        assert!(res.is_ok(), "auto_revert on missing vault must be a harmless no-op");
    }
}

#[test]
fn test_challenge_5_arm3_prefix_and_system_vetoes_exhaustive() {
    let prefix_and_system_candidates = [
        // Antigravity & IDE prefixes
        ("ANTIGRAVITY_CSRF_TOKEN", "sec_antigravity_token_abc123456789"),
        ("antigravity_session_id", "sess_antigravity_lowercase_99999"),
        ("VSCODE_GIT_IPC_HANDLE", "\\\\.\\pipe\\vscode-git-ipc-1234"),
        ("vscode_pid", "1234567890"),
        ("VSCODE_INJECTION", "injected_payload_secret_1234"),
        // Cargo & Rust prefixes
        ("CARGO_PKG_NAME", "osoosi-core"),
        ("CARGO_HOME", "C:\\Users\\user\\.cargo"),
        ("cargo_manifest_dir", "D:\\repo\\osoosi"),
        ("RUST_BACKTRACE", "full"),
        ("rust_log", "debug,osoosi=trace"),
        ("RUST_FLAGS", "-C target-cpu=native"),
        ("rust_wrapper", "sccache.exe"),
        // Terminal, NPM, SSH, GPG, Git prefixes
        ("TERM_PROGRAM", "vscode"),
        ("term_session_id", "term-guid-1234-5678-90ab"),
        ("NPM_CONFIG_TOKEN", "npm_secret_token_1234567890"),
        ("npm_lifecycle_event", "test"),
        ("SSH_AUTH_SOCK", "/tmp/ssh-auth-sock-12345"),
        ("ssh_agent_pid", "9988776655"),
        ("GPG_AGENT_INFO", "/run/user/1000/gnupg/S.gpg-agent:1234:1"),
        ("gpg_tty", "/dev/pts/0"),
        ("GIT_EXEC_PATH", "C:\\Program Files\\Git\\bin"),
        ("git_ssh_command", "ssh -i /id_rsa"),
        ("GIT_DIR", ".git"),
        // System variables
        ("PATH", "C:\\Windows\\System32;C:\\Windows;D:\\Tools"),
        ("path", "C:\\usr\\bin;/usr/local/bin"),
        ("Path", "D:\\Cargo\\bin;D:\\Rust"),
        ("JAVA_HOME", "C:\\Program Files\\Java\\jdk-21"),
        ("java_home", "/usr/lib/jvm/default"),
        ("ONEDRIVE", "C:\\Users\\user\\OneDrive"),
        ("onedriveconsumer", "C:\\Users\\user\\OneDrive - Personal"),
        ("TEMP", "C:\\Users\\user\\AppData\\Local\\Temp"),
        ("tmp", "C:\\Temp"),
        ("USERPROFILE", "C:\\Users\\user"),
        ("WINDIR", "C:\\Windows"),
        ("COMSPEC", "C:\\Windows\\system32\\cmd.exe"),
        // Suffix guards
        ("DATABASE_URL", "postgres://user:pass@localhost:5432/db"),
        ("BACKEND_HOST", "127.0.0.1:8080"),
        ("SERVICE_PORT", "8080"),
        ("CLIENT_EXE", "osoosi.exe"),
    ];

    for (k, v) in &prefix_and_system_candidates {
        let eval = LlmFusionApiKeyEnumerator::evaluate_variable(k, v);
        assert!(
            !eval.selected,
            "Variable {} with value {} MUST NOT be selected",
            k, v
        );
        assert!(
            eval.vetoed_by_safety_guard,
            "Variable {} MUST be marked as vetoed_by_safety_guard",
            k
        );
        assert!(
            eval.arm3_safety_veto,
            "Variable {} MUST have arm3_safety_veto == true",
            k
        );
        assert_eq!(
            eval.fusion_confidence_bp, 0,
            "Variable {} MUST have 0 confidence bp",
            k
        );
        assert!(
            eval.standin_token.is_none(),
            "Variable {} MUST NOT receive a standin_token",
            k
        );
        assert!(
            eval.veto_reason.is_some(),
            "Variable {} MUST provide a clear veto reason",
            k
        );
    }
}
