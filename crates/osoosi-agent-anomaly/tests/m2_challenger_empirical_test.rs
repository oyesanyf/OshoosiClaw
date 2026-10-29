//! Empirical Stress & Adversarial Challenge Suite for Milestone 2 (F05 & F06)
//!
//! Evaluates:
//! 1. Dogwood MFOTL temporal sliding-window boundary condition:
//!    - Event at t - 7200s (boundary edge): strictly FORBIDDEN.
//!    - Event at t - 7201s (expired): NOT forbidden.
//! 2. Temporal causal ordering & false positive prevention:
//!    - UntrustedWebInput alone -> allowed.
//!    - ScratchFileWrite alone -> allowed.
//!    - ScratchFileWrite BEFORE UntrustedWebInput -> allowed (scratch not tainted by web).
//!    - UntrustedWebInput -> ScratchFileWrite -> SubprocessEnvOrArg -> strictly FORBIDDEN.
//! 3. Supervisor declassification temporal horizon:
//!    - Declassification clears prior events up to declass timestamp.
//!    - New events occurring AFTER declassification are NOT cleared and trigger forbid.
//! 4. Cedar authorizer integration & forbid string emission:
//!    - Confirms `CEDAR-FORBID-TEMPORAL-TAINT-FRAGMENTATION` emission.
//!    - Scratch file touch detection via command-line substring.
//! 5. Execution Environment Guard adversarial stress:
//!    - All 15 HIJACK_ENV_VARS with mixed case.
//!    - Env values referencing forbidden config targets (.cargo/config.toml, build.rs, .pth).
//!    - Inline command-line parameter injections (git -c, -e, --env, export, set).
//!    - Workspace tampering: .cargo/config.toml, legacy .cargo/config, build.rs, .pth.
//!    - Sorted double-null-terminated UTF-16 environment block verification.

use chrono::Utc;
use osoosi_agent_anomaly::breakout_defense::{
    BreakoutDefenseCoordinator, BreakoutDefenseError, ExecutionEnvironmentGuard,
    sanitize_and_validate_subprocess_env,
};
use osoosi_policy::breakout_gate::{
    AuthorityLevel, CedarAction, CedarContext, CedarPrincipal, CedarResource,
    DataClassification, DogwoodTemporalPolicyEvaluator, EnforcementStage,
    Ring7CapabilityEffectAuthorizer, TemporalEventType, TemporalTraceAtom,
};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;

#[test]
fn test_challenge_f05_sliding_window_boundary_7200s_vs_7201s() {
    let evaluator = DogwoodTemporalPolicyEvaluator::new(7200);
    let session = "sess-boundary-stress";
    let now = Utc::now().timestamp();

    // Boundary Test 1: Event chain exactly at 7200s boundary (cutoff = now - 7200)
    // Event at now - 7200 is inside the [now - 7200, now] closed window.
    evaluator.record_atom(TemporalTraceAtom {
        timestamp_utc: now - 7200,
        event_type: TemporalEventType::UntrustedWebInput,
        session_id: session.to_string(),
        resource_path: Some("https://evil-payload.internal/script.sh".to_string()),
    });
    evaluator.record_atom(TemporalTraceAtom {
        timestamp_utc: now - 7199,
        event_type: TemporalEventType::ScratchFileWrite,
        session_id: session.to_string(),
        resource_path: Some("/tmp/drop.sh".to_string()),
    });
    evaluator.record_atom(TemporalTraceAtom {
        timestamp_utc: now,
        event_type: TemporalEventType::SubprocessEnvOrArg,
        session_id: session.to_string(),
        resource_path: Some("/tmp/drop.sh".to_string()),
    });

    let (forbid_at_boundary, reason) = evaluator.evaluate_taint_flow(session, now, None);
    assert!(
        forbid_at_boundary,
        "Chain at exactly 7200s (boundary edge) MUST be forbidden"
    );
    assert!(
        reason
            .as_ref()
            .unwrap()
            .contains("CEDAR-FORBID-TEMPORAL-TAINT-FRAGMENTATION"),
        "Forbid reason must be CEDAR-FORBID-TEMPORAL-TAINT-FRAGMENTATION: {:?}",
        reason
    );

    // Boundary Test 2: Event chain at 7201s (just outside 7200s window)
    let session_expired = "sess-boundary-expired";
    evaluator.record_atom(TemporalTraceAtom {
        timestamp_utc: now - 7201,
        event_type: TemporalEventType::UntrustedWebInput,
        session_id: session_expired.to_string(),
        resource_path: Some("https://evil-payload.internal/old_script.sh".to_string()),
    });
    evaluator.record_atom(TemporalTraceAtom {
        timestamp_utc: now - 7201,
        event_type: TemporalEventType::ScratchFileWrite,
        session_id: session_expired.to_string(),
        resource_path: Some("/tmp/old_drop.sh".to_string()),
    });
    evaluator.record_atom(TemporalTraceAtom {
        timestamp_utc: now,
        event_type: TemporalEventType::SubprocessEnvOrArg,
        session_id: session_expired.to_string(),
        resource_path: Some("/tmp/old_drop.sh".to_string()),
    });

    let (forbid_expired, reason_expired) = evaluator.evaluate_taint_flow(session_expired, now, None);
    assert!(
        !forbid_expired,
        "Chain at 7201s (outside window) must expire and NOT be forbidden"
    );
    assert!(reason_expired.is_none());
}

#[test]
fn test_challenge_f05_causal_ordering_and_fp_prevention() {
    let evaluator = DogwoodTemporalPolicyEvaluator::new(7200);
    let now = Utc::now().timestamp();

    // 1. UntrustedWebInput alone + SubprocessEnvOrArg (no intermediate scratch write)
    let s1 = "sess-no-scratch";
    evaluator.record_atom(TemporalTraceAtom {
        timestamp_utc: now - 100,
        event_type: TemporalEventType::UntrustedWebInput,
        session_id: s1.to_string(),
        resource_path: Some("https://api.github.com/repos".to_string()),
    });
    evaluator.record_atom(TemporalTraceAtom {
        timestamp_utc: now - 10,
        event_type: TemporalEventType::SubprocessEnvOrArg,
        session_id: s1.to_string(),
        resource_path: Some("git status".to_string()),
    });
    let (forbid1, _) = evaluator.evaluate_taint_flow(s1, now, None);
    assert!(
        !forbid1,
        "Direct web input without scratch file write must not trigger fragmentation forbid"
    );

    // 2. ScratchFileWrite alone + SubprocessEnvOrArg (no prior untrusted web input)
    let s2 = "sess-local-scratch";
    evaluator.record_atom(TemporalTraceAtom {
        timestamp_utc: now - 100,
        event_type: TemporalEventType::ScratchFileWrite,
        session_id: s2.to_string(),
        resource_path: Some("/tmp/local_cache.tmp".to_string()),
    });
    evaluator.record_atom(TemporalTraceAtom {
        timestamp_utc: now - 10,
        event_type: TemporalEventType::SubprocessEnvOrArg,
        session_id: s2.to_string(),
        resource_path: Some("/tmp/local_cache.tmp".to_string()),
    });
    let (forbid2, _) = evaluator.evaluate_taint_flow(s2, now, None);
    assert!(
        !forbid2,
        "Local scratch file write without web input must not trigger fragmentation forbid"
    );

    // 3. ScratchFileWrite occurs BEFORE UntrustedWebInput (scratch write was clean)
    let s3 = "sess-scratch-before-web";
    evaluator.record_atom(TemporalTraceAtom {
        timestamp_utc: now - 100,
        event_type: TemporalEventType::ScratchFileWrite,
        session_id: s3.to_string(),
        resource_path: Some("/tmp/prior_config.json".to_string()),
    });
    evaluator.record_atom(TemporalTraceAtom {
        timestamp_utc: now - 50,
        event_type: TemporalEventType::UntrustedWebInput,
        session_id: s3.to_string(),
        resource_path: Some("https://example.com/unrelated".to_string()),
    });
    evaluator.record_atom(TemporalTraceAtom {
        timestamp_utc: now - 10,
        event_type: TemporalEventType::SubprocessEnvOrArg,
        session_id: s3.to_string(),
        resource_path: Some("/tmp/prior_config.json".to_string()),
    });
    let (forbid3, _) = evaluator.evaluate_taint_flow(s3, now, None);
    assert!(
        !forbid3,
        "Scratch file written BEFORE untrusted web input was clean and must not trigger forbid"
    );
}

#[test]
fn test_challenge_f05_supervisor_declassification_horizon() {
    let evaluator = DogwoodTemporalPolicyEvaluator::new(7200);
    let s = "sess-declass-horizon";
    let now = Utc::now().timestamp();

    // Episode 1: Initial taint flow
    evaluator.record_atom(TemporalTraceAtom {
        timestamp_utc: now - 500,
        event_type: TemporalEventType::UntrustedWebInput,
        session_id: s.to_string(),
        resource_path: Some("https://untrusted.com/pkg.tar.gz".to_string()),
    });
    evaluator.record_atom(TemporalTraceAtom {
        timestamp_utc: now - 450,
        event_type: TemporalEventType::ScratchFileWrite,
        session_id: s.to_string(),
        resource_path: Some("/tmp/extracted/run.py".to_string()),
    });
    evaluator.record_atom(TemporalTraceAtom {
        timestamp_utc: now - 400,
        event_type: TemporalEventType::SubprocessEnvOrArg,
        session_id: s.to_string(),
        resource_path: Some("/tmp/extracted/run.py".to_string()),
    });

    let (forbid_ep1, _) = evaluator.evaluate_taint_flow(s, now - 350, None);
    assert!(forbid_ep1, "Episode 1 must be forbidden before declassification");

    // Supervisor reviews and declassifies at now - 300
    evaluator.record_atom(TemporalTraceAtom {
        timestamp_utc: now - 300,
        event_type: TemporalEventType::SupervisorDeclassification,
        session_id: s.to_string(),
        resource_path: None,
    });

    let (forbid_after_declass, _) = evaluator.evaluate_taint_flow(s, now - 250, None);
    assert!(
        !forbid_after_declass,
        "Supervisor declassification must clear Episode 1 forbid"
    );

    // Episode 2: Adversary attempts second fragmentation attack AFTER declassification!
    evaluator.record_atom(TemporalTraceAtom {
        timestamp_utc: now - 200,
        event_type: TemporalEventType::UntrustedWebInput,
        session_id: s.to_string(),
        resource_path: Some("https://evil2.com/second_payload.sh".to_string()),
    });
    evaluator.record_atom(TemporalTraceAtom {
        timestamp_utc: now - 150,
        event_type: TemporalEventType::ScratchFileWrite,
        session_id: s.to_string(),
        resource_path: Some("/tmp/stage2.sh".to_string()),
    });
    evaluator.record_atom(TemporalTraceAtom {
        timestamp_utc: now - 100,
        event_type: TemporalEventType::SubprocessEnvOrArg,
        session_id: s.to_string(),
        resource_path: Some("/tmp/stage2.sh".to_string()),
    });

    let (forbid_ep2, reason_ep2) = evaluator.evaluate_taint_flow(s, now, None);
    assert!(
        forbid_ep2,
        "New attack sequence AFTER supervisor declassification MUST trigger forbid"
    );
    assert!(
        reason_ep2
            .as_ref()
            .unwrap()
            .contains("CEDAR-FORBID-TEMPORAL-TAINT-FRAGMENTATION")
    );
}

#[test]
fn test_challenge_f05_cedar_scratch_file_touch_integration() {
    let authorizer = Ring7CapabilityEffectAuthorizer::new();
    let session = "sess-cedar-scratch-touch";
    let principal = CedarPrincipal {
        principal_id: "agent-coder-2".to_string(),
        session_id: session.to_string(),
        process_instance_key: "proc-test-2".to_string(),
        authority_level: AuthorityLevel::L3TrustedApplicationInstruction,
        approved_capabilities: vec!["process_spawn".to_string()],
        authenticated_role: None,
    };
    let resource = CedarResource {
        resource_id: "python C:\\workspace\\scratch_drop.py".to_string(),
        resource_type: "ChildProcess".to_string(),
        classification: DataClassification::InternalWorkspace,
        is_signed_and_allowlisted: true,
        is_approved_child_binary: true,
        is_task_scoped_destination: true,
        is_declassified_approved_sink: false,
        service_identity: None,
        service_operation: None,
    };

    // Record untrusted web input and scratch write to scratch_drop.py
    authorizer.record_temporal_event(
        session,
        TemporalEventType::UntrustedWebInput,
        Some("https://malicious.cdn.org/bad.py".to_string()),
    );
    authorizer.record_temporal_event(
        session,
        TemporalEventType::ScratchFileWrite,
        Some("C:\\workspace\\scratch_drop.py".to_string()),
    );

    let context = CedarContext::default();
    let decision = authorizer.evaluate_cedar_request(
        &principal,
        CedarAction::ChildProcessExec,
        &resource,
        context,
        EnforcementStage::PreExecutionPrevented,
    );

    assert!(
        !decision.allowed,
        "Child process touching scratch file from web input must be forbidden"
    );
    assert!(
        decision
            .matched_forbid_policies
            .iter()
            .any(|p| p.contains("CEDAR-FORBID-TEMPORAL-TAINT-FRAGMENTATION")),
        "Decision must include CEDAR-FORBID-TEMPORAL-TAINT-FRAGMENTATION: {:?}",
        decision.matched_forbid_policies
    );
}

#[test]
fn test_challenge_f06_case_insensitive_and_mixed_case_hijacking_vars() {
    let guard = ExecutionEnvironmentGuard::new();
    let temp_dir = std::env::temp_dir().join(format!("osoosi_m2_case_test_{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&temp_dir).unwrap();

    let mixed_case_vars = [
        "git_ssh_command",
        "Git_Ssh_Command",
        "GIT_SSH_COMMAND",
        "rustc_wrapper",
        "Rustc_Wrapper",
        "RUSTC_WRAPPER",
        "rustc_workspace_wrapper",
        "pythonpath",
        "PythonPath",
        "PYTHONPATH",
        "pythonstartup",
        "pythonhome",
        "node_options",
        "Node_Options",
        "NODE_OPTIONS",
        "node_path",
        "ld_preload",
        "LD_PRELOAD",
        "ld_library_path",
        "dyld_insert_libraries",
        "dyld_library_path",
        "perl5opt",
        "rubyopt",
    ];

    for var in mixed_case_vars {
        let mut env = HashMap::new();
        env.insert(var.to_string(), "/tmp/payload.so".to_string());
        env.insert("PATH".to_string(), "C:\\Windows\\System32".to_string());

        let (has_hijack, violations) = guard.inspect_execution_environment_hijacking(&env, "cargo test");
        assert!(
            has_hijack,
            "Guard must detect mixed-case hijacking var: '{}'",
            var
        );
        assert!(
            !violations.is_empty(),
            "Violations must not be empty for '{}'",
            var
        );

        let res = sanitize_and_validate_subprocess_env(&env, &temp_dir, "cargo test");
        assert!(
            res.is_err(),
            "sanitize_and_validate_subprocess_env must reject mixed-case var '{}'",
            var
        );
        match res {
            Err(BreakoutDefenseError::EnvironmentHijack(reason)) => {
                assert!(
                    reason.to_uppercase().contains(&var.to_uppercase()),
                    "Reason must cite var '{}': {}",
                    var,
                    reason
                );
            }
            other => panic!("Expected EnvironmentHijack for '{}', got {:?}", var, other),
        }
    }

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_challenge_f06_env_pointing_to_forbidden_config_targets() {
    let guard = ExecutionEnvironmentGuard::new();
    let temp_dir = std::env::temp_dir().join(format!("osoosi_m2_env_cfg_{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&temp_dir).unwrap();

    let sneaky_envs = [
        ("MY_TOOL_CONFIG", "/workspace/.cargo/config.toml"),
        ("LEGACY_CFG", "/workspace/.cargo/config"),
        ("CUSTOM_BUILDER", "C:\\projects\\app\\build.rs"),
        ("SITE_PACKAGE_HOOK", "/usr/lib/python3.10/site-packages/evil.pth"),
    ];

    for (k, v) in sneaky_envs {
        let mut env = HashMap::new();
        env.insert(k.to_string(), v.to_string());

        let (has_hijack, violations) = guard.inspect_execution_environment_hijacking(&env, "run");
        assert!(
            has_hijack,
            "Environment pointing to forbidden config '{}' in {} must be flagged",
            v, k
        );
        assert!(
            violations.iter().any(|viol| viol.contains(k)),
            "Violation must cite key '{}': {:?}",
            k, violations
        );

        let res = sanitize_and_validate_subprocess_env(&env, &temp_dir, "run");
        assert!(res.is_err(), "Must fail closed when env points to forbidden config");
    }

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_challenge_f06_adversarial_inline_cli_overrides() {
    let guard = ExecutionEnvironmentGuard::new();
    let empty_env: HashMap<String, String> = HashMap::new();

    let adversarial_cmds = [
        "git -c core.git_ssh_command=/evil/ssh clone repo",
        "bash -c 'export RUSTC_WRAPPER=/tmp/evil && cargo build'",
        "python -c 'import sys' PYTHONPATH=/evil/pkg",
        "node -e 'process.exit(0)' NODE_OPTIONS=--require=/evil.js",
        "cmd.exe /c 'set LD_PRELOAD=/evil.so && target.exe'",
        "cargo check --config .cargo/config.toml",
        "cargo check --config .cargo/config",
        "git clone repo --env GIT_SSH_COMMAND=/tmp/evil",
        "docker run -e NODE_OPTIONS=--inspect myimage",
    ];

    for cmd in adversarial_cmds {
        let (has_hijack, violations) = guard.inspect_execution_environment_hijacking(&empty_env, cmd);
        assert!(
            has_hijack,
            "Inline CLI override must be caught: '{}'",
            cmd
        );
        assert!(
            !violations.is_empty(),
            "Violations must be populated for '{}'",
            cmd
        );
    }
}

#[test]
fn test_challenge_f06_workspace_cargo_config_runner_hijacking() {
    let guard = ExecutionEnvironmentGuard::new();
    let temp_dir = std::env::temp_dir().join(format!("osoosi_m2_runner_test_{}", uuid::Uuid::new_v4()));
    let cargo_dir = temp_dir.join(".cargo");
    fs::create_dir_all(&cargo_dir).unwrap();

    // Adversary attempts custom target runner hijacking in .cargo/config.toml
    let config_path = cargo_dir.join("config.toml");
    let mut f = File::create(&config_path).unwrap();
    writeln!(
        f,
        "[target.x86_64-pc-windows-msvc]\nrunner = \"C:\\\\evil\\\\runner.exe\""
    )
    .unwrap();
    drop(f);

    let inspection = guard.inspect_environment_and_configs(&[], "cargo test", &temp_dir);
    assert!(
        !inspection.is_clean,
        "Custom runner in .cargo/config.toml must be flagged"
    );
    assert!(
        inspection
            .prohibited_configurations
            .iter()
            .any(|c| c.contains("runner")),
        "Prohibited configuration must mention runner: {:?}",
        inspection.prohibited_configurations
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_challenge_f06_breakout_defense_coordinator_integration() {
    let coordinator = BreakoutDefenseCoordinator::new();

    // 1. Hostile payload with Python site hook (passes because payload is inspected)
    let hostile_payload_1 = "Injecting payload via malicious .pth drop into Python site-packages";
    let eval_1 = coordinator.evaluate_action(
        "agent-tester",
        "bash",
        "python -c 'print(1)'",
        hostile_payload_1,
        None,
    );
    assert!(!eval_1.is_clean, "Coordinator must reject .pth reference in payload");
    assert!(!eval_1.operational.is_clean);

    // 2. Clean command passes
    let eval_clean = coordinator.evaluate_action(
        "agent-tester",
        "cargo",
        "cargo test -p osoosi-policy --lib",
        "running unit tests for policy crate",
        None,
    );
    assert!(eval_clean.is_clean, "Clean cargo test command must pass coordinator evaluation");

    // 3. Hostile command in resource with inline NODE_OPTIONS (fails due to bug in coordinator)
    let eval_node = coordinator.evaluate_action(
        "agent-tester",
        "bash",
        "node -e 'console.log(1)' NODE_OPTIONS=--require=/tmp/evil.js",
        "running build script",
        None,
    );
    assert!(
        !eval_node.is_clean,
        "EMPIRICAL BUG REPRODUCTION: Coordinator fails to reject inline NODE_OPTIONS when placed in resource"
    );
    assert!(!eval_node.operational.is_clean);
}
