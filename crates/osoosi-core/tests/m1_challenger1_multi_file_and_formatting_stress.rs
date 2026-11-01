//! Empirical Stress Harness and Adversarial Validation for Milestone 1:
//! Multi-File Environment Discovery, Formatting Preservation, and Zero-Touch PATH Invariants.
//!
//! Author: challenger_m1_1 (Empirical Challenger)
//! Roles: critic, specialist
//!
//! Objectives:
//! 1. Challenge multi-file discovery: test paths with depth, symlinks, relative traversal (`..`),
//!    spaces, special characters, and verify excluded dirs (`.git`, `node_modules`, `target`, `.cargo`) are ignored.
//! 2. Challenge formatting preservation: verify complex `.env` lines (`export KEY="val # not comment" # real comment`,
//!    unquoted, single-quoted) maintain exact format when non-secrets are preserved and secrets are stand-in replaced.
//! 3. Challenge Zero-Touch PATH preservation: assert that `PATH`/`Path`, `JAVA_HOME`, `TEMP`, `TMP`
//!    are never altered under any circumstances.
//! 4. Full multi-file seal, single-file revert, and full auto-revert roundtrip.

use osoosi_core::protected_env_backup::{LlmFusionApiKeyEnumerator, ProtectedEnvBackupVault};

#[test]
fn challenge_multi_file_discovery_depth_and_exclusions() {
    let temp_dir = tempfile::tempdir().expect("create tempdir");
    let root = temp_dir.path();

    // 1. Root candidate files
    let root_env = root.join(".env");
    let root_env_local = root.join(".env.local");
    let root_env_prod = root.join(".env.production");
    let root_env_dev = root.join(".env.development");
    let root_env_test = root.join(".env.test");
    let root_env_staging = root.join(".env.staging");

    std::fs::write(&root_env, "ROOT=1\n").unwrap();
    std::fs::write(&root_env_local, "LOCAL=1\n").unwrap();
    std::fs::write(&root_env_prod, "PROD=1\n").unwrap();
    std::fs::write(&root_env_dev, "DEV=1\n").unwrap();
    std::fs::write(&root_env_test, "TEST=1\n").unwrap();
    std::fs::write(&root_env_staging, "STAGING=1\n").unwrap();

    // 2. Depth 1 subdirectories
    let sub1 = root.join("frontend_web");
    std::fs::create_dir_all(&sub1).unwrap();
    let sub1_env = sub1.join(".env.production");
    std::fs::write(&sub1_env, "SUB1=1\n").unwrap();

    let sub2 = root.join("backend_api");
    std::fs::create_dir_all(&sub2).unwrap();
    let sub2_env = sub2.join(".env");
    std::fs::write(&sub2_env, "SUB2=1\n").unwrap();

    // 3. Depth 1 subdirectory with spaces
    let sub_spaces = root.join("my service spaces");
    std::fs::create_dir_all(&sub_spaces).unwrap();
    let sub_spaces_env = sub_spaces.join(".env.local");
    std::fs::write(&sub_spaces_env, "SPACES=1\n").unwrap();

    // 4. Depth 1 subdirectory with special characters
    let sub_special = root.join("service#1$test@special");
    std::fs::create_dir_all(&sub_special).unwrap();
    let sub_special_env = sub_special.join(".env.test");
    std::fs::write(&sub_special_env, "SPECIAL=1\n").unwrap();

    // 5. Depth 2 nested subdirectory (should NOT be auto-discovered by depth-1 scan)
    let nested_depth2 = sub1.join("nested_deeper");
    std::fs::create_dir_all(&nested_depth2).unwrap();
    let nested_env = nested_depth2.join(".env");
    std::fs::write(&nested_env, "NESTED=1\n").unwrap();

    // 6. Excluded directories: .git, node_modules, target, .cargo, .hidden_dir
    let git_dir = root.join(".git");
    std::fs::create_dir_all(&git_dir).unwrap();
    let git_env = git_dir.join(".env");
    std::fs::write(&git_env, "GIT_SECRET=1\n").unwrap();

    let node_modules_dir = root.join("node_modules");
    std::fs::create_dir_all(&node_modules_dir).unwrap();
    let nm_env = node_modules_dir.join(".env");
    std::fs::write(&nm_env, "NM_SECRET=1\n").unwrap();

    let target_dir = root.join("target");
    std::fs::create_dir_all(&target_dir).unwrap();
    let target_env = target_dir.join(".env");
    std::fs::write(&target_env, "TARGET_SECRET=1\n").unwrap();

    let cargo_dir = root.join(".cargo");
    std::fs::create_dir_all(&cargo_dir).unwrap();
    let cargo_env = cargo_dir.join(".env");
    std::fs::write(&cargo_env, "CARGO_SECRET=1\n").unwrap();

    let hidden_dir = root.join(".hidden_test");
    std::fs::create_dir_all(&hidden_dir).unwrap();
    let hidden_env = hidden_dir.join(".env");
    std::fs::write(&hidden_env, "HIDDEN_SECRET=1\n").unwrap();

    // 7. Custom paths: relative traversal with `..` and space paths
    let custom_relative = sub1.join("..").join("backend_api").join(".env");
    let custom_file = root.join("custom_config.env");
    std::fs::write(&custom_file, "CUSTOM=1\n").unwrap();

    let custom_paths = vec![custom_relative.clone(), custom_file.clone()];

    // Run discovery
    let discovered = ProtectedEnvBackupVault::discover_environment_files(root, &custom_paths);

    // Verify all legitimate root candidate files were discovered
    assert!(discovered.contains(&root_env), "Missing root .env");
    assert!(
        discovered.contains(&root_env_local),
        "Missing root .env.local"
    );
    assert!(
        discovered.contains(&root_env_prod),
        "Missing root .env.production"
    );
    assert!(
        discovered.contains(&root_env_dev),
        "Missing root .env.development"
    );
    assert!(
        discovered.contains(&root_env_test),
        "Missing root .env.test"
    );
    assert!(
        discovered.contains(&root_env_staging),
        "Missing root .env.staging"
    );

    // Verify depth-1 files were discovered
    assert!(
        discovered.contains(&sub1_env),
        "Missing frontend_web/.env.production"
    );
    assert!(discovered.contains(&sub2_env), "Missing backend_api/.env");
    assert!(
        discovered.contains(&sub_spaces_env),
        "Missing spaces/.env.local"
    );
    assert!(
        discovered.contains(&sub_special_env),
        "Missing special/.env.test"
    );

    // Verify custom file was discovered
    assert!(
        discovered.contains(&custom_file),
        "Missing custom_config.env"
    );

    // Verify relative traversal was deduplicated (sub2_env was already found, custom_relative should not create duplicate)
    let sub2_canonical = sub2_env
        .canonicalize()
        .unwrap()
        .to_string_lossy()
        .to_ascii_lowercase();
    let occurrences = discovered
        .iter()
        .filter(|p| {
            p.canonicalize()
                .map(|c| c.to_string_lossy().to_ascii_lowercase() == sub2_canonical)
                .unwrap_or(false)
        })
        .count();
    assert_eq!(
        occurrences, 1,
        "Relative traversal created duplicate entry in discovered files"
    );

    // Verify depth-2 nested directory was NOT auto-discovered
    assert!(
        !discovered.contains(&nested_env),
        "Nested depth-2 file should NOT be auto-discovered by depth-1 scan"
    );

    // CRITICAL: Verify excluded directories are strictly IGNORED
    assert!(
        !discovered.contains(&git_env),
        "CRITICAL LEAK: .git/.env was discovered!"
    );
    assert!(
        !discovered.contains(&nm_env),
        "CRITICAL LEAK: node_modules/.env was discovered!"
    );
    assert!(
        !discovered.contains(&target_env),
        "CRITICAL LEAK: target/.env was discovered!"
    );
    assert!(
        !discovered.contains(&cargo_env),
        "CRITICAL LEAK: .cargo/.env was discovered!"
    );
    assert!(
        !discovered.contains(&hidden_env),
        "CRITICAL LEAK: .hidden_test/.env was discovered!"
    );
}

#[test]
fn challenge_formatting_preservation_complex_lines() {
    // 1. Complex line: export KEY="val # not comment" # real comment
    let line1 = "export GEMINI_API_KEY=\"AIzaSyD-val # not comment\" # real comment";
    let rep1 = ProtectedEnvBackupVault::replace_env_var_in_line(
        line1,
        "GEMINI_API_KEY",
        "OSHOOSI_STANDIN_GEMINI_12345",
    )
    .expect("should replace GEMINI_API_KEY");
    assert_eq!(
        rep1, "export GEMINI_API_KEY=\"OSHOOSI_STANDIN_GEMINI_12345\" # real comment",
        "Failed to preserve internal quoted '#' and external real comment in double quotes"
    );

    // 2. Complex line: export KEY='val # not comment' # real comment (single quotes)
    let line2 = "export HF_TOKEN='hf_secret # not comment' # real comment single";
    let rep2 = ProtectedEnvBackupVault::replace_env_var_in_line(
        line2,
        "HF_TOKEN",
        "OSHOOSI_STANDIN_HF_12345",
    )
    .expect("should replace HF_TOKEN");
    assert_eq!(
        rep2, "export HF_TOKEN='OSHOOSI_STANDIN_HF_12345' # real comment single",
        "Failed to preserve internal quoted '#' and external real comment in single quotes"
    );

    // 3. Unquoted value with real comment: KEY=secret_value # real comment
    let line3 = "APP_DB_PASSWORD=test_dummy_pass_unquoted_val # production db password";
    let rep3 = ProtectedEnvBackupVault::replace_env_var_in_line(
        line3,
        "APP_DB_PASSWORD",
        "OSHOOSI_STANDIN_DB_12345",
    )
    .expect("should replace APP_DB_PASSWORD");
    assert_eq!(
        rep3, "APP_DB_PASSWORD=OSHOOSI_STANDIN_DB_12345 # production db password",
        "Failed to preserve inline comment on unquoted variable"
    );

    // 4. Leading indentation with spaces and export prefix
    let line4 = "   export   AUTH_SECRET=\"secret-string-12345\"   # indent comment";
    let rep4 = ProtectedEnvBackupVault::replace_env_var_in_line(
        line4,
        "AUTH_SECRET",
        "OSHOOSI_STANDIN_AUTH_12345",
    )
    .expect("should replace AUTH_SECRET");
    assert!(
        rep4.starts_with("   export AUTH_SECRET="),
        "Failed to preserve leading spaces"
    );
    assert!(rep4.contains("\"OSHOOSI_STANDIN_AUTH_12345\""));
    assert!(rep4.ends_with("# indent comment"));

    // 5. Unquoted without comment
    let line5 = "API_KEY=raw_secret_value_12345";
    let rep5 = ProtectedEnvBackupVault::replace_env_var_in_line(
        line5,
        "API_KEY",
        "OSHOOSI_STANDIN_KEY_12345",
    )
    .expect("should replace plain unquoted secret");
    assert_eq!(rep5, "API_KEY=OSHOOSI_STANDIN_KEY_12345");

    // 6. Non-matching key returns None
    let line6 = "PORT=8080 # application port";
    assert!(
        ProtectedEnvBackupVault::replace_env_var_in_line(line6, "GEMINI_API_KEY", "STANDIN")
            .is_none()
    );

    // 7. Pure comments return None
    let line7 = "# export GEMINI_API_KEY=\"AIzaSyD-foo\" # commented out";
    assert!(
        ProtectedEnvBackupVault::replace_env_var_in_line(line7, "GEMINI_API_KEY", "STANDIN")
            .is_none()
    );

    // 8. Empty lines return None
    assert!(
        ProtectedEnvBackupVault::replace_env_var_in_line("", "GEMINI_API_KEY", "STANDIN").is_none()
    );
    assert!(
        ProtectedEnvBackupVault::replace_env_var_in_line("   ", "GEMINI_API_KEY", "STANDIN")
            .is_none()
    );
}

#[test]
fn challenge_zero_touch_path_and_system_invariants() {
    // 1. Assert is_secret_env_key_and_value strictly returns FALSE for all system & non-secret vars
    let protected_system_vars = [
        ("PATH", "C:\\Windows\\System32;C:\\Windows;D:\\Tools"),
        ("Path", "C:\\Program Files\\Rust\\bin;C:\\Windows"),
        ("path", "/usr/local/bin:/usr/bin:/bin"),
        ("JAVA_HOME", "C:\\Program Files\\Java\\jdk-21.0.2"),
        ("TEMP", "C:\\Users\\User\\AppData\\Local\\Temp"),
        ("TMP", "C:\\Users\\User\\AppData\\Local\\Temp"),
        ("TMPDIR", "/tmp"),
        ("OneDrive", "C:\\Users\\User\\OneDrive"),
        ("OneDriveConsumer", "C:\\Users\\User\\OneDrive"),
        ("OLLAMA_ORIGINS", "*"),
        ("OLLAMA_HOST", "127.0.0.1:11434"),
        ("USERPROFILE", "C:\\Users\\User"),
        ("APPDATA", "C:\\Users\\User\\AppData\\Roaming"),
        ("LOCALAPPDATA", "C:\\Users\\User\\AppData\\Local"),
        ("PROGRAMFILES", "C:\\Program Files"),
        ("PROGRAMFILES(X86)", "C:\\Program Files (x86)"),
        ("WINDIR", "C:\\Windows"),
        ("SYSTEMROOT", "C:\\Windows"),
        ("SYSTEMDRIVE", "C:"),
        ("PUBLIC", "C:\\Users\\Public"),
        (
            "PSMODULEPATH",
            "C:\\Program Files\\WindowsPowerShell\\Modules",
        ),
        ("ANTIGRAVITY_CSRF_TOKEN", "csrf-token-1234567890"),
        ("VSCODE_NONCE", "vscode-nonce-1234567890"),
        ("CARGO_HOME", "C:\\Users\\User\\.cargo"),
        ("RUSTUP_HOME", "C:\\Users\\User\\.rustup"),
        ("RUST_LOG", "info,osoosi=debug"),
        ("RUST_BACKTRACE", "1"),
        ("PORT", "3000"),
        ("HOST", "127.0.0.1"),
        ("HOSTNAME", "my-workstation"),
        ("NODE_ENV", "production"),
        ("APP_ENV", "staging"),
        ("DEBUG", "false"),
        ("PUBLIC_URL", "https://example.com/app"),
        ("NEXT_PUBLIC_API_URL", "https://api.example.com/v1"),
        ("VITE_APP_TITLE", "My Web App"),
    ];

    for (k, v) in &protected_system_vars {
        assert!(
            !ProtectedEnvBackupVault::is_secret_env_key_and_value(k, v),
            "CRITICAL VIOLATION: is_secret_env_key_and_value returned true for protected variable '{}'!",
            k
        );

        // Also test through 3-Arm LLM Fusion Evaluator
        let eval = LlmFusionApiKeyEnumerator::evaluate_variable(k, v);
        assert!(
            eval.vetoed_by_safety_guard,
            "CRITICAL VIOLATION: LlmFusionApiKeyEnumerator failed to safety-veto '{}'!",
            k
        );
        assert!(
            !eval.selected,
            "CRITICAL VIOLATION: LlmFusionApiKeyEnumerator marked '{}' as selected!",
            k
        );
        assert_eq!(
            eval.fusion_confidence_bp, 0,
            "CRITICAL VIOLATION: LlmFusionApiKeyEnumerator gave non-zero confidence for '{}'!",
            k
        );
    }

    // 2. Assert genuine secrets MUST be recognized and selected
    let genuine_secrets = [
        (
            "GEMINI_API_KEY",
            "test_gemini_api_key_sample_entropy_9876543210",
        ),
        ("HF_TOKEN", "test_hf_token_sample_entropy_value_9876543210"),
        (
            "OPENAI_API_KEY",
            "test_openai_api_key_sample_entropy_9876543210",
        ),
        (
            "GITHUB_TOKEN",
            "test_github_token_sample_entropy_9876543210",
        ),
        (
            "AWS_SECRET_ACCESS_KEY",
            "test_aws_secret_access_key_entropy_9876543210",
        ),
        (
            "DATABASE_PASSWORD",
            "test_db_password_sample_entropy_9876543210",
        ),
        (
            "STRIPE_SECRET_KEY",
            "test_stripe_secret_key_entropy_9876543210",
        ),
    ];

    for (k, v) in &genuine_secrets {
        assert!(
            ProtectedEnvBackupVault::is_secret_env_key_and_value(k, v),
            "Failed to identify genuine secret '{}'",
            k
        );

        let eval = LlmFusionApiKeyEnumerator::evaluate_variable(k, v);
        assert!(
            !eval.vetoed_by_safety_guard,
            "Genuine secret '{}' was wrongly vetoed by safety guard!",
            k
        );
        assert!(
            eval.selected,
            "Genuine secret '{}' was not selected by LLM Fusion!",
            k
        );
        assert!(
            eval.fusion_confidence_bp >= 8500,
            "Genuine secret '{}' got insufficient confidence {} bp!",
            k,
            eval.fusion_confidence_bp
        );
    }
}

#[test]
fn challenge_multi_file_end_to_end_seal_revert_single_and_auto_revert() {
    let temp_dir = tempfile::tempdir().expect("create tempdir");
    let root = temp_dir.path();
    let vault_file = root.join("challenge_multi.vault");

    // File 1: Root .env with mixed secrets, non-secrets, formatting, comments
    let file1 = root.join(".env");
    let original_file1 = "# Root Environment Configuration\n\
PORT=3000\n\
NODE_ENV=production\n\
export GEMINI_API_KEY=\"AIzaSyD-RootGeminiKey987654321\" # Primary Gemini API\n\
PATH=\"C:\\Windows\\System32;C:\\Tools\"\n\
JAVA_HOME=\"C:\\Program Files\\Java\\jdk-21\"\n\
TEMP=\"C:\\Temp\"\n\
DEBUG=false\n";
    std::fs::write(&file1, original_file1).unwrap();

    // File 2: Subdirectory api/.env.local with single quotes and comments
    let sub_api = root.join("api");
    std::fs::create_dir_all(&sub_api).unwrap();
    let file2 = sub_api.join(".env.local");
    let original_file2 = "# API Configuration\n\
export HF_TOKEN='hf_SubdirHuggingFaceToken12345678' # HuggingFace Token\n\
HOST=0.0.0.0\n\
OLLAMA_ORIGINS=\"*\"\n";
    std::fs::write(&file2, original_file2).unwrap();

    // File 3: Subdirectory worker/.env.production with unquoted secret and comment
    let sub_worker = root.join("worker");
    std::fs::create_dir_all(&sub_worker).unwrap();
    let file3 = sub_worker.join(".env.production");
    let original_file3 = "# Worker Service Config\n\
OPENAI_API_KEY=sk-proj-WorkerOpenAiSecret987654321 # OpenAI key\n\
TMP=\"C:\\Temp\"\n\
RUST_LOG=info\n";
    std::fs::write(&file3, original_file3).unwrap();

    // 1. Perform dynamic multi-file seal
    let seal_result = ProtectedEnvBackupVault::seal_and_backup_dynamic(&file1, &vault_file)
        .expect("seal multi-file dynamic failed");
    assert!(
        seal_result.total_selected >= 3,
        "Expected at least 3 secrets sealed, got {}",
        seal_result.total_selected
    );

    // 2. Assert in-place replacement and formatting preservation in File 1 (Root .env)
    let sealed_text1 = std::fs::read_to_string(&file1).unwrap();
    assert!(
        sealed_text1.contains("export GEMINI_API_KEY=\"OSHOOSI_STANDIN_GEMINI_API_KEY_"),
        "GEMINI_API_KEY not replaced with stand-in in root .env"
    );
    assert!(
        sealed_text1.contains("# Primary Gemini API"),
        "Comment was lost in root .env!"
    );
    assert!(
        sealed_text1.contains("PORT=3000"),
        "PORT=3000 was corrupted!"
    );
    assert!(
        sealed_text1.contains("NODE_ENV=production"),
        "NODE_ENV was corrupted!"
    );
    assert!(
        sealed_text1.contains("PATH=\"C:\\Windows\\System32;C:\\Tools\""),
        "PATH was altered!"
    );
    assert!(
        sealed_text1.contains("JAVA_HOME=\"C:\\Program Files\\Java\\jdk-21\""),
        "JAVA_HOME was altered!"
    );
    assert!(
        sealed_text1.contains("TEMP=\"C:\\Temp\""),
        "TEMP was altered!"
    );
    assert!(sealed_text1.contains("DEBUG=false"), "DEBUG was corrupted!");

    // 3. Assert in-place replacement in File 2 (apps/api/.env.local)
    let sealed_text2 = std::fs::read_to_string(&file2).unwrap();
    assert!(
        sealed_text2.contains("export HF_TOKEN='OSHOOSI_STANDIN_HF_TOKEN_"),
        "HF_TOKEN not replaced with stand-in in apps/api/.env.local"
    );
    assert!(
        sealed_text2.contains("# HuggingFace Token"),
        "Comment was lost in apps/api/.env.local!"
    );
    assert!(sealed_text2.contains("HOST=0.0.0.0"), "HOST was corrupted!");
    assert!(
        sealed_text2.contains("OLLAMA_ORIGINS=\"*\""),
        "OLLAMA_ORIGINS was altered!"
    );

    // 4. Assert in-place replacement in File 3 (worker/.env.production)
    let sealed_text3 = std::fs::read_to_string(&file3).unwrap();
    assert!(
        sealed_text3.contains("OPENAI_API_KEY=OSHOOSI_STANDIN_OPENAI_API_KEY_"),
        "OPENAI_API_KEY not replaced with stand-in in worker/.env.production"
    );
    assert!(
        sealed_text3.contains("# OpenAI key"),
        "Comment was lost in worker/.env.production!"
    );
    assert!(
        sealed_text3.contains("TMP=\"C:\\Temp\""),
        "TMP was altered!"
    );
    assert!(
        sealed_text3.contains("RUST_LOG=info"),
        "RUST_LOG was corrupted!"
    );

    // 5. Test single-file revert on File 2 (apps/api/.env.local)
    ProtectedEnvBackupVault::revert_single_file(&vault_file, &file2)
        .expect("revert_single_file failed on file2");

    // File 2 MUST be restored 100% bit-for-bit to original
    let restored_text2 = std::fs::read_to_string(&file2).unwrap();
    assert_eq!(
        restored_text2, original_file2,
        "File 2 was not restored bit-for-bit on single-file revert!"
    );

    // File 1 and File 3 MUST STILL BE SEALED!
    let text1_still_sealed = std::fs::read_to_string(&file1).unwrap();
    assert!(
        text1_still_sealed.contains("OSHOOSI_STANDIN_GEMINI_API_KEY_"),
        "File 1 was prematurely unsealed during single-file revert of File 2!"
    );
    let text3_still_sealed = std::fs::read_to_string(&file3).unwrap();
    assert!(
        text3_still_sealed.contains("OSHOOSI_STANDIN_OPENAI_API_KEY_"),
        "File 3 was prematurely unsealed during single-file revert of File 2!"
    );

    // 6. Test full auto_revert on vault
    ProtectedEnvBackupVault::auto_revert(&vault_file).expect("auto_revert failed");

    // All files MUST now be restored 100% bit-for-bit
    let restored_text1 = std::fs::read_to_string(&file1).unwrap();
    assert_eq!(
        restored_text1, original_file1,
        "File 1 was not restored bit-for-bit on full auto_revert!"
    );
    let restored_text3 = std::fs::read_to_string(&file3).unwrap();
    assert_eq!(
        restored_text3, original_file3,
        "File 3 was not restored bit-for-bit on full auto_revert!"
    );
}

#[test]
fn challenge_atomic_write_and_symlink_rejection() {
    let temp_dir = tempfile::tempdir().expect("create tempdir");
    let test_file = temp_dir.path().join("atomic_test.env");

    let payload = b"TEST_KEY=OSHOOSI_STANDIN_12345678\nPORT=8080\n";
    ProtectedEnvBackupVault::write_file_atomic(&test_file, payload)
        .expect("write_file_atomic failed");

    let read_back = std::fs::read(&test_file).expect("read atomic file");
    assert_eq!(read_back, payload, "Atomic write content mismatch");

    // Try creating a symlink to verify rejection if supported on current platform
    #[cfg(unix)]
    {
        let symlink_path = temp_dir.path().join("symlink_target.env");
        if std::os::unix::fs::symlink(&test_file, &symlink_path).is_ok() {
            let result =
                ProtectedEnvBackupVault::write_file_atomic(&symlink_path, b"MALICIOUS_PAYLOAD");
            assert!(
                result.is_err(),
                "CRITICAL SECURITY FLAW: write_file_atomic must reject symbolic links!"
            );
        }
    }
    #[cfg(windows)]
    {
        // On Windows with developer mode or admin, test symlink rejection
        let symlink_path = temp_dir.path().join("symlink_target.env");
        if std::os::windows::fs::symlink_file(&test_file, &symlink_path).is_ok() {
            let result =
                ProtectedEnvBackupVault::write_file_atomic(&symlink_path, b"MALICIOUS_PAYLOAD");
            assert!(
                result.is_err(),
                "CRITICAL SECURITY FLAW: write_file_atomic must reject symbolic links on Windows!"
            );
        }
    }
}
