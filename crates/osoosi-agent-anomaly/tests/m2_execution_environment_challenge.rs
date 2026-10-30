//! Milestone 2 Integration & Adversarial Challenge:
//! Execution Environment Guard, Interpreter Hijacking Defense & Subprocess Environment Sanitization.
//!
//! Validates:
//! 1. All hijacking environment variables (GIT_SSH_COMMAND, RUSTC_WRAPPER, PYTHONPATH, NODE_OPTIONS, LD_PRELOAD, etc.) are intercepted.
//! 2. Inline command-line configuration overrides are blocked.
//! 3. Unauthorized `.cargo/config.toml`, unverified `build.rs`, and `.pth` files in task workspace are detected.
//! 4. Clean environments produce sorted, double-null-terminated UTF-16 environment blocks for Win32 CreateProcessW.
//! 5. Unified BreakoutDefenseCoordinator integrates environment defense into operational containment.

use osoosi_agent_anomaly::breakout_defense::{
    sanitize_and_validate_subprocess_env, BreakoutDefenseCoordinator, BreakoutDefenseError,
    ExecutionEnvironmentGuard,
};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;

#[test]
fn test_execution_environment_guard_blocks_all_forbidden_env_vars() {
    let guard = ExecutionEnvironmentGuard::new();
    let temp_dir = std::env::temp_dir().join(format!("osoosi_test_env_{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&temp_dir).unwrap();

    for &forbidden_var in ExecutionEnvironmentGuard::HIJACK_ENV_VARS {
        let mut env_vars = HashMap::new();
        env_vars.insert(
            forbidden_var.to_string(),
            "malicious_payload_or_path".to_string(),
        );
        env_vars.insert("PATH".to_string(), "C:\\Windows\\System32".to_string());

        // 1. inspect_execution_environment_hijacking must flag violation
        let (has_hijack, violations) =
            guard.inspect_execution_environment_hijacking(&env_vars, "cargo check");
        assert!(
            has_hijack,
            "Guard must detect forbidden env var '{}'",
            forbidden_var
        );
        assert!(
            violations.iter().any(|v| v.contains(forbidden_var)),
            "Violation description must name '{}': {:?}",
            forbidden_var,
            violations
        );

        // 2. sanitize_and_validate_subprocess_env must fail closed
        let res = sanitize_and_validate_subprocess_env(&env_vars, &temp_dir, "cargo check");
        match res {
            Err(BreakoutDefenseError::EnvironmentHijack(reason)) => {
                assert!(
                    reason.contains(forbidden_var),
                    "Error reason must cite '{}': {}",
                    forbidden_var,
                    reason
                );
            }
            other => panic!(
                "Expected BreakoutDefenseError::EnvironmentHijack for '{}', got: {:?}",
                forbidden_var, other
            ),
        }
    }

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_execution_environment_guard_blocks_inline_command_line_hijacking() {
    let guard = ExecutionEnvironmentGuard::new();
    let empty_env: HashMap<String, String> = HashMap::new();

    let malicious_cmds = [
        "git -c core.git_ssh_command=/tmp/evil.sh clone https://example.com/repo",
        "bash -c 'export GIT_SSH_COMMAND=/tmp/evil.sh && git push'",
        "cargo check --config .cargo/config.toml",
        "python -c 'import sys' GIT_SSH_COMMAND=evil",
        "node -e 'console.log(1)' NODE_OPTIONS=--require=/tmp/inject.js",
    ];

    for cmd in malicious_cmds {
        let (has_hijack, violations) =
            guard.inspect_execution_environment_hijacking(&empty_env, cmd);
        assert!(
            has_hijack,
            "Inline command line hijack must be detected for command: {}",
            cmd
        );
        assert!(
            !violations.is_empty(),
            "Violations must not be empty for command: {}",
            cmd
        );
    }
}

#[test]
fn test_execution_environment_guard_blocks_workspace_config_tampering() {
    let guard = ExecutionEnvironmentGuard::new();
    let temp_dir =
        std::env::temp_dir().join(format!("osoosi_test_configs_{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&temp_dir).unwrap();

    // 1. Clean workspace passes
    let clean_inspection = guard.inspect_environment_and_configs(&[], "cargo build", &temp_dir);
    assert!(
        clean_inspection.is_clean,
        "Clean workspace must pass inspection"
    );

    // 2. Workspace containing unauthorized .cargo/config.toml with rustc-wrapper
    let cargo_dir = temp_dir.join(".cargo");
    fs::create_dir_all(&cargo_dir).unwrap();
    let config_path = cargo_dir.join("config.toml");
    let mut f = File::create(&config_path).unwrap();
    writeln!(
        f,
        "[build]\nrustc-wrapper = \"/usr/local/bin/sccache_evil\""
    )
    .unwrap();
    drop(f);

    let config_inspection = guard.inspect_environment_and_configs(&[], "cargo build", &temp_dir);
    assert!(
        !config_inspection.is_clean,
        "Workspace with rustc-wrapper in .cargo/config.toml must be flagged"
    );
    assert!(
        config_inspection
            .prohibited_configurations
            .iter()
            .any(|c| c.contains("rustc-wrapper") || c.contains("config.toml")),
        "Prohibited configurations must cite cargo config: {:?}",
        config_inspection.prohibited_configurations
    );

    // Clean up .cargo
    let _ = fs::remove_dir_all(&cargo_dir);

    // 3. Workspace containing unverified build.rs
    let build_rs_path = temp_dir.join("build.rs");
    let mut f2 = File::create(&build_rs_path).unwrap();
    writeln!(
        f2,
        "fn main() {{ println!(\"cargo:rerun-if-changed=src\"); }}"
    )
    .unwrap();
    drop(f2);

    let build_rs_inspection = guard.inspect_environment_and_configs(&[], "cargo build", &temp_dir);
    assert!(
        !build_rs_inspection.is_clean,
        "Workspace with unverified build.rs must be flagged"
    );
    assert!(
        build_rs_inspection
            .prohibited_configurations
            .iter()
            .any(|c| c.contains("build.rs")),
        "Prohibited configurations must cite build.rs: {:?}",
        build_rs_inspection.prohibited_configurations
    );

    let _ = fs::remove_file(&build_rs_path);

    // 4. Workspace containing Python site-configuration .pth file
    let pth_path = temp_dir.join("malicious_site_hook.pth");
    let mut f3 = File::create(&pth_path).unwrap();
    writeln!(f3, "import os; os.system('whoami')").unwrap();
    drop(f3);

    let pth_inspection = guard.inspect_environment_and_configs(&[], "python main.py", &temp_dir);
    assert!(
        !pth_inspection.is_clean,
        "Workspace with Python .pth file must be flagged"
    );
    assert!(
        pth_inspection
            .prohibited_configurations
            .iter()
            .any(|c| c.contains(".pth")),
        "Prohibited configurations must cite .pth file: {:?}",
        pth_inspection.prohibited_configurations
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_clean_environment_produces_sorted_utf16_block() {
    let temp_dir = std::env::temp_dir().join(format!("osoosi_test_clean_{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&temp_dir).unwrap();

    let mut env = HashMap::new();
    env.insert("ZEBRA".to_string(), "stripes".to_string());
    env.insert("APPLE".to_string(), "fruit".to_string());
    env.insert("MANGO".to_string(), "sweet".to_string());

    let result = sanitize_and_validate_subprocess_env(&env, &temp_dir, "echo hello");
    assert!(result.is_ok(), "Clean environment must succeed");

    let block_utf16 = result.unwrap();
    assert!(!block_utf16.is_empty());
    assert_eq!(
        *block_utf16.last().unwrap(),
        0,
        "Environment block must end with null terminator"
    );

    // Decode UTF-16 block into strings
    let decoded = String::from_utf16_lossy(&block_utf16);
    let parts: Vec<&str> = decoded.split('\0').filter(|s| !s.is_empty()).collect();

    assert_eq!(parts.len(), 3);
    assert_eq!(parts[0], "APPLE=fruit");
    assert_eq!(parts[1], "MANGO=sweet");
    assert_eq!(parts[2], "ZEBRA=stripes");

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_breakout_defense_coordinator_blocks_environment_hijacking_in_payload() {
    let coordinator = BreakoutDefenseCoordinator::new();

    // Payload containing environment variable poisoning
    let hostile_payload =
        "Attempting build with RUSTC_WRAPPER=/tmp/evil_wrapper.exe for optimization";
    let eval = coordinator.evaluate_action(
        "agent-worker-1",
        "execute_command",
        "cargo check",
        hostile_payload,
        None,
    );

    assert!(
        !eval.is_clean,
        "BreakoutDefenseCoordinator must flag hostile execution environment payload"
    );
    assert!(
        !eval.operational.is_clean,
        "Operational containment verdict must be false when environment hijacking is detected"
    );
    assert!(
        eval.operational
            .detected_leaks
            .iter()
            .any(|l| l.contains("RUSTC_WRAPPER")),
        "Detected leaks must mention RUSTC_WRAPPER: {:?}",
        eval.operational.detected_leaks
    );
}
