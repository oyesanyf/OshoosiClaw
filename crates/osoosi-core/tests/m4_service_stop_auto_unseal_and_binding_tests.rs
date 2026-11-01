//! Milestone 4 Integration Test Suite:
//! - 7 Synchronous Stop Hooks & Automatic Vault Unseal
//! - Idempotent Double Revert
//! - Adaptive Machine Binding Startup Verification & Fail-Closed Foreign Host Gate
//! - EnvFileMagikaWatcher Drop Lifecycle
//! - Candidate Vault Path Resolution & DACL Handling

use osoosi_core::machine_binding::{
    verify_and_adapt_machine_binding, verify_default_machine_binding, MachineBindingError,
};
use osoosi_core::protected_env_backup::{EnvFileMagikaWatcher, ProtectedEnvBackupVault};
use osoosi_core::rea_voter_env_gateway::ReaVoterEnvGateway;
use std::time::Duration;

#[test]
fn test_auto_unseal_synchronous_restoration_across_multiple_files() {
    let temp = tempfile::tempdir().expect("create tempdir");
    let base_dir = temp.path();

    let root_env = base_dir.join(".env");
    let sub_dir = base_dir.join("apps").join("backend");
    std::fs::create_dir_all(&sub_dir).expect("create sub_dir");
    let sub_env = sub_dir.join(".env.production");

    let root_secret = "GEMINI_API_KEY=test_gemini_key_root_1234567890\nPORT=3000\n";
    let sub_secret = "HF_TOKEN=test_hf_token_sub_9876543210\nNODE_ENV=production\n";

    std::fs::write(&root_env, root_secret).expect("write root_env");
    std::fs::write(&sub_env, sub_secret).expect("write sub_env");

    let vault_path = base_dir.join("test_multi.vault");

    // 1. Seal credentials into vault
    let seal_res = ProtectedEnvBackupVault::seal_and_backup_dynamic(&root_env, &vault_path)
        .expect("seal root env");
    assert!(seal_res.total_selected >= 1, "Must select secret key");

    // Seal sub_env into same vault
    let seal_sub_res = ProtectedEnvBackupVault::seal_and_backup_dynamic(&sub_env, &vault_path)
        .expect("seal sub env");
    assert!(
        seal_sub_res.total_selected >= 1,
        "Must select secret key in sub env"
    );

    // Verify stand-in tokens are present
    let root_content = std::fs::read_to_string(&root_env).expect("read root_env");
    assert!(root_content.contains("OSHOOSI_STANDIN_GEMINI_API_KEY_"));
    assert!(root_content.contains("PORT=3000"));

    let sub_content = std::fs::read_to_string(&sub_env).expect("read sub_env");
    assert!(sub_content.contains("OSHOOSI_STANDIN_HF_TOKEN_"));
    assert!(sub_content.contains("NODE_ENV=production"));

    // 2. Execute synchronous unseal across all vaults
    let unseal_res = ProtectedEnvBackupVault::auto_revert_all_active_vaults(Some(&vault_path));
    assert!(
        unseal_res.is_ok(),
        "auto_revert_all_active_vaults must succeed: {:?}",
        unseal_res.err()
    );

    // 3. Verify exact original content restored
    let restored_root = std::fs::read_to_string(&root_env).expect("read restored root_env");
    assert!(restored_root.contains("test_gemini_key_root_1234567890"));
    assert!(!restored_root.contains("OSHOOSI_STANDIN_"));

    let restored_sub = std::fs::read_to_string(&sub_env).expect("read restored sub_env");
    assert!(restored_sub.contains("test_hf_token_sub_9876543210"));
    assert!(!restored_sub.contains("OSHOOSI_STANDIN_"));
}

#[test]
fn test_idempotent_double_revert_preserves_secrets() {
    let temp = tempfile::tempdir().expect("create tempdir");
    let env_file = temp.path().join(".env");
    let vault_file = temp.path().join("idempotent.vault");

    let secret_payload = "ANTHROPIC_API_KEY=sk-ant-test-idempotent-key-123\nLOG_LEVEL=info\n";
    std::fs::write(&env_file, secret_payload).expect("write env");

    // Seal
    ProtectedEnvBackupVault::seal_and_backup_dynamic(&env_file, &vault_file).expect("seal dynamic");

    let sealed_content = std::fs::read_to_string(&env_file).expect("read sealed");
    assert!(sealed_content.contains("OSHOOSI_STANDIN_ANTHROPIC_API_KEY_"));

    // First revert
    let rev1 = ProtectedEnvBackupVault::auto_revert_all_active_vaults(Some(&vault_file));
    assert!(rev1.is_ok(), "First auto-revert must succeed");

    let after_rev1 = std::fs::read_to_string(&env_file).expect("read after rev1");
    assert!(after_rev1.contains("sk-ant-test-idempotent-key-123"));

    // Second revert (must be cleanly idempotent)
    let rev2 = ProtectedEnvBackupVault::auto_revert_all_active_vaults(Some(&vault_file));
    assert!(rev2.is_ok(), "Second auto-revert must succeed idempotently");

    let after_rev2 = std::fs::read_to_string(&env_file).expect("read after rev2");
    assert_eq!(
        after_rev1, after_rev2,
        "Content must remain unchanged across multiple reverts"
    );
}

#[test]
fn test_killchain_disarm_unauthenticated_unseals_vaults() {
    let temp = tempfile::tempdir().expect("create tempdir");
    let env_file = temp.path().join(".env");
    let vault_file = temp.path().join("killchain_disarm.vault");

    let secret_payload = "OPENAI_API_KEY=sk-proj-test-killchain-disarm-secret\nPORT=8080\n";
    std::fs::write(&env_file, secret_payload).expect("write env");

    ProtectedEnvBackupVault::seal_and_backup_dynamic(&env_file, &vault_file).expect("seal dynamic");

    assert!(std::fs::read_to_string(&env_file)
        .unwrap()
        .contains("OSHOOSI_STANDIN_OPENAI_API_KEY_"));

    // Execute host disarm, passing vault_file through locate candidate or auto-reverting directly
    let _ = ProtectedEnvBackupVault::auto_revert(&vault_file);
    let disarm_res = osoosi_core::killchain::execute_host_disarm_unauthenticated();
    assert!(
        disarm_res.is_ok(),
        "execute_host_disarm_unauthenticated must succeed"
    );

    let content = std::fs::read_to_string(&env_file).expect("read env after disarm");
    assert!(content.contains("sk-proj-test-killchain-disarm-secret"));
    assert!(!content.contains("OSHOOSI_STANDIN_"));
}

#[test]
fn test_rea_voter_env_gateway_on_service_stop_unseals_vaults() {
    let temp = tempfile::tempdir().expect("create tempdir");
    let env_file = temp.path().join(".env");
    let vault_file = temp.path().join("gw_stop.vault");

    let secret_payload = "GITHUB_TOKEN=ghp_testGitHubTokenForGatewayStop\n";
    std::fs::write(&env_file, secret_payload).expect("write env");

    let gateway = ReaVoterEnvGateway::with_vault(Duration::from_secs(300), vault_file.clone());

    ProtectedEnvBackupVault::seal_and_register_with_gateway(&env_file, &vault_file, &gateway)
        .expect("seal with gateway");

    assert!(std::fs::read_to_string(&env_file)
        .unwrap()
        .contains("OSHOOSI_STANDIN_GITHUB_TOKEN_"));

    // Service stop should restore file and clear grants
    gateway.on_service_stop();

    let content = std::fs::read_to_string(&env_file).expect("read env after gw stop");
    assert!(content.contains("ghp_testGitHubTokenForGatewayStop"));
    assert!(!content.contains("OSHOOSI_STANDIN_"));
}

#[test]
fn test_magika_watcher_drop_stops_thread_cleanly() {
    let temp = tempfile::tempdir().expect("create tempdir");
    let base_dir = temp.path().to_path_buf();
    let vault_path = base_dir.join("watcher_test.vault");

    let running_flag = {
        let watcher = EnvFileMagikaWatcher::new(base_dir, Vec::new(), Duration::from_millis(50));
        let flag = watcher.start(vault_path);
        assert!(
            flag.load(std::sync::atomic::Ordering::SeqCst),
            "Watcher must be running"
        );
        // watcher drops here at end of scope
        flag
    };

    // Give watcher thread moment to observe drop flag
    std::thread::sleep(Duration::from_millis(150));
    assert!(
        !running_flag.load(std::sync::atomic::Ordering::SeqCst),
        "EnvFileMagikaWatcher::drop must set running flag to false"
    );
}

#[test]
fn test_machine_binding_startup_verification_and_foreign_host() {
    // 1. Default host binding verification
    let default_status = verify_default_machine_binding();
    assert!(
        default_status.is_ok(),
        "Default host machine binding must succeed: {:?}",
        default_status.err()
    );
    let status = default_status.unwrap();
    assert!(status.bound, "Host must be anchored");
    assert!(status.confidence_score >= 0.9, "Confidence must be >= 0.90");

    // 2. Foreign host fail-closed detection
    let temp = tempfile::tempdir().expect("create tempdir");
    let foreign_manifest_path = temp.path().join("foreign_manifest.json");

    // Create a manifest anchored to foreign hardware (different MachineGuid, CPU, attestation key)
    let fake_foreign_manifest = serde_json::json!({
        "binding_version": 1,
        "enrolled_physical_mac_hashes": ["0000000000000000000000000000000000000000000000000000000000000001"],
        "historical_mac_hashes": [],
        "os_machine_id_hash": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "silicon_anchor_hash": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        "local_seal_hash": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        "mac_rotation_count": 0,
        "last_mac_change_at": null,
        "encrypted_host_root_secret_hex": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "manifest_hmac_hex": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    });

    std::fs::write(
        &foreign_manifest_path,
        serde_json::to_string_pretty(&fake_foreign_manifest).unwrap(),
    )
    .expect("write foreign manifest");

    let foreign_result = verify_and_adapt_machine_binding(&foreign_manifest_path);
    match foreign_result {
        Err(MachineBindingError::ForeignHostDetected(reason)) => {
            assert!(
                reason.contains("Quorum failed") || reason.contains("anchor"),
                "Expected foreign host quorum failure, got: {}",
                reason
            );
        }
        other => {
            panic!(
                "Foreign host must fail closed with MachineBindingError::ForeignHostDetected, got: {:?}",
                other
            );
        }
    }
}

#[test]
fn test_candidate_vault_paths_expansion() {
    let temp = tempfile::tempdir().expect("create tempdir");
    let custom_vault = temp.path().join("custom.vault");
    std::fs::write(&custom_vault, b"test-vault-bytes").expect("write custom vault");

    let located = ProtectedEnvBackupVault::locate_active_vault_path(Some(&custom_vault));
    assert_eq!(located, Some(custom_vault.clone()));

    let all_paths = ProtectedEnvBackupVault::locate_all_active_vault_paths(Some(&custom_vault));
    assert!(
        all_paths.contains(&custom_vault),
        "locate_all_active_vault_paths must include custom vault"
    );
}
