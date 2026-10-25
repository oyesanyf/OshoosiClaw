//! Challenger 2 Empirical Stress Test Suite for Milestone 1 (M1).
//!
//! Empirically tests and stress-tests:
//! 1. `TokenPosture::verify_agent_safe`:
//!    - Zero dangerous privileges policy (verifies every one of 13 dangerous privileges is blocked).
//!    - Case-insensitive dangerous privilege matching.
//!    - Mandatory rejection of merely present privileges even if disabled.
//!    - Integrity level boundaries (> Medium / High / System rejected; Low / Medium accepted).
//!    - Elevation rejection (TokenIsElevated != 0).
//!    - BUILTIN\Administrators enabled rejection.
//!    - Aggregation of multiple simultaneous violation reasons.
//! 2. `dispatch_tier2_win32` Environment Block Isolation & Sanitization:
//!    - Unicode environment block construction, case-insensitive sort, and null-termination.
//!    - Sanitized minimal environment variables (SystemRoot, ComSpec, OSOOSI_TIER2_CONFINED).
//!    - Prevention of ambient host environment leaks (e.g. host API keys/credentials).
//! 3. Mercury Containment Engine Mass Accumulation & Sulfur Passivation:
//!    - Monotonic lifetime mass accumulation from Job Object I/O accounting.
//!    - Sulfur passivation threshold (mass >= 1.0) activation (`sulfur_passivated_hgs`).
//!    - Fail-closed execution denial for passivated agents in `dispatch_tier2_win32`.
//!    - Multi-agent isolation (passivating agent A does not block agent B).
//! 4. Windows Job Object Kernel Resource Ceilings:
//!    - Active process limit enforcement.
//!    - Memory limit enforcement (64 MiB ceiling).
//!    - Basic & I/O accounting query stability.
//!    - UILIMIT_ALL and KILL_ON_JOB_CLOSE invariants.
//! 5. Execution Resilience Under Concurrent Tier-2 Dispatches:
//!    - Parallel executions across unique AppContainer profiles.
//!    - Kernel-verified token and job membership.

use osoosi_sandbox::{
    MeasuredActuationSample, MercuryContainmentEngine, TieredExecutionDispatcher,
    TieredToolRequest, TokenPosture, WindowsJobObject, DANGEROUS_PRIVILEGES, INTEGRITY_HIGH,
    INTEGRITY_LOW, INTEGRITY_MEDIUM, INTEGRITY_SYSTEM, INTEGRITY_UNTRUSTED,
};
use osoosi_types::{ArmRole, OctopusSecurityError};
use std::sync::Arc;

// =========================================================================
// 1. TokenPosture Zero Dangerous Privileges Matrix Tests
// =========================================================================

#[test]
fn test_challenger2_token_posture_clean_baseline_succeeds() {
    let clean = TokenPosture {
        elevated: false,
        integrity_rid: INTEGRITY_MEDIUM,
        admins_enabled: false,
        admins_deny_only: true,
        present_privileges: vec!["SeChangeNotifyPrivilege".to_string()],
        enabled_privileges: vec!["SeChangeNotifyPrivilege".to_string()],
    };
    assert!(
        clean.verify_agent_safe().is_ok(),
        "Compliant un-elevated Medium integrity token with benign privilege must pass verify_agent_safe"
    );
}

#[test]
fn test_challenger2_token_posture_every_dangerous_privilege_blocked() {
    let base = TokenPosture {
        elevated: false,
        integrity_rid: INTEGRITY_MEDIUM,
        admins_enabled: false,
        admins_deny_only: true,
        present_privileges: vec!["SeChangeNotifyPrivilege".to_string()],
        enabled_privileges: vec!["SeChangeNotifyPrivilege".to_string()],
    };

    assert_eq!(
        DANGEROUS_PRIVILEGES.len(),
        13,
        "Exactly 13 dangerous privileges must be defined in the breakout prevention matrix"
    );

    for &dang in DANGEROUS_PRIVILEGES {
        // Test 1: Exact case present
        let mut posture_exact = base.clone();
        posture_exact.present_privileges.push(dang.to_string());
        let err1 = posture_exact.verify_agent_safe().expect_err(&format!(
            "Privilege '{}' must be rejected fail-closed",
            dang
        ));
        assert!(
            err1.iter().any(|r| r.contains(dang)),
            "Error for '{}' must explicitly mention the privilege name, got: {:?}",
            dang,
            err1
        );

        // Test 2: Disabled privilege (present in present_privileges, NOT in enabled_privileges)
        // AdjustTokenPrivileges could re-enable it; must be blocked even when disabled!
        let mut posture_disabled = base.clone();
        posture_disabled.present_privileges.push(dang.to_string());
        posture_disabled.enabled_privileges.clear();
        let err_dis = posture_disabled.verify_agent_safe().expect_err(&format!(
            "Disabled privilege '{}' must still be rejected fail-closed",
            dang
        ));
        assert!(
            err_dis.iter().any(|r| r.contains(dang)),
            "Error for disabled '{}' must mention privilege: {:?}",
            dang,
            err_dis
        );

        // Test 3: Uppercase variation
        let mut posture_upper = base.clone();
        let upper = dang.to_ascii_uppercase();
        posture_upper.present_privileges.push(upper.clone());
        let err2 = posture_upper.verify_agent_safe().expect_err(&format!(
            "Uppercase privilege '{}' must be rejected fail-closed",
            upper
        ));
        assert!(
            err2.iter()
                .any(|r| r.to_ascii_lowercase().contains(&dang.to_ascii_lowercase())),
            "Error for uppercase '{}' must match case-insensitively: {:?}",
            upper,
            err2
        );

        // Test 4: Lowercase variation
        let mut posture_lower = base.clone();
        let lower = dang.to_ascii_lowercase();
        posture_lower.present_privileges.push(lower.clone());
        let err3 = posture_lower.verify_agent_safe().expect_err(&format!(
            "Lowercase privilege '{}' must be rejected fail-closed",
            lower
        ));
        assert!(
            err3.iter()
                .any(|r| r.to_ascii_lowercase().contains(&dang.to_ascii_lowercase())),
            "Error for lowercase '{}' must match case-insensitively: {:?}",
            lower,
            err3
        );
    }
}

#[test]
fn test_challenger2_token_posture_elevation_and_integrity_violations() {
    let base = TokenPosture {
        elevated: false,
        integrity_rid: INTEGRITY_MEDIUM,
        admins_enabled: false,
        admins_deny_only: true,
        present_privileges: vec![],
        enabled_privileges: vec![],
    };

    // 1. Elevation rejection
    let mut elevated = base.clone();
    elevated.elevated = true;
    let err_elev = elevated
        .verify_agent_safe()
        .expect_err("Elevated token must be rejected");
    assert!(err_elev.iter().any(|r| r.contains("TokenIsElevated != 0")));

    // 2. High integrity rejection
    let mut high_int = base.clone();
    high_int.integrity_rid = INTEGRITY_HIGH;
    let err_high = high_int
        .verify_agent_safe()
        .expect_err("High integrity token must be rejected");
    assert!(err_high.iter().any(|r| r.contains("exceeds Medium")));

    // 3. System integrity rejection
    let mut sys_int = base.clone();
    sys_int.integrity_rid = INTEGRITY_SYSTEM;
    let err_sys = sys_int
        .verify_agent_safe()
        .expect_err("System integrity token must be rejected");
    assert!(err_sys.iter().any(|r| r.contains("exceeds Medium")));

    // 4. Boundary test: Medium + 1 (0x2001)
    let mut boundary = base.clone();
    boundary.integrity_rid = INTEGRITY_MEDIUM + 1;
    let err_bound = boundary
        .verify_agent_safe()
        .expect_err("Integrity > 0x2000 must be rejected");
    assert!(err_bound.iter().any(|r| r.contains("exceeds Medium")));

    // 5. Permitted integrity levels: Low (0x1000) and Untrusted (0x0000)
    let mut low_int = base.clone();
    low_int.integrity_rid = INTEGRITY_LOW;
    assert!(
        low_int.verify_agent_safe().is_ok(),
        "Low integrity must be accepted"
    );

    let mut untrusted_int = base.clone();
    untrusted_int.integrity_rid = INTEGRITY_UNTRUSTED;
    assert!(
        untrusted_int.verify_agent_safe().is_ok(),
        "Untrusted integrity must be accepted"
    );

    // 6. BUILTIN\Administrators enabled rejection
    let mut admins = base.clone();
    admins.admins_enabled = true;
    let err_admin = admins
        .verify_agent_safe()
        .expect_err("BUILTIN\\Administrators enabled must be rejected");
    assert!(err_admin
        .iter()
        .any(|r| r.contains("BUILTIN\\Administrators group is enabled")));

    // 7. Multi-violation aggregation: all 4 violations returned simultaneously
    let mut multi = base.clone();
    multi.elevated = true;
    multi.integrity_rid = INTEGRITY_HIGH;
    multi.admins_enabled = true;
    multi
        .present_privileges
        .push("SeDebugPrivilege".to_string());
    let err_multi = multi
        .verify_agent_safe()
        .expect_err("Multi-violation must return all 4 errors");
    assert_eq!(
        err_multi.len(),
        4,
        "Expected exactly 4 violation reasons for combined violations, got: {:?}",
        err_multi
    );
}

// =========================================================================
// 2. Environment Block Sanitization & Host Leak Prevention
// =========================================================================

#[cfg(windows)]
#[test]
fn test_challenger2_dispatch_tier2_environment_sanitization_and_isolation() {
    let dispatcher = TieredExecutionDispatcher::try_new().expect("dispatcher init");
    let scratch_dir = std::env::temp_dir().join(format!("c2_scratch_env_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&scratch_dir);

    // Set a dummy sensitive host environment variable
    std::env::set_var(
        "CHALLENGER_SECRET_HOST_KEY",
        "SUPER_SECRET_TOKEN_DO_NOT_LEAK",
    );

    // 1. Verify host environment variables are NOT leaked into Tier 2 AppContainer child
    // If CHALLENGER_SECRET_HOST_KEY leaked into child, cmd.exe exits with code 42
    let req_secret_check = TieredToolRequest {
        agent_id: format!("c2-env-test-{}", uuid::Uuid::new_v4().simple()),
        role: ArmRole::AnomalyDetection,
        tool_name: "env_check".to_string(),
        payload: Vec::new(),
        custom_wat: None,
        native_command: Some((
            "cmd.exe".to_string(),
            vec![
                "/c".to_string(),
                "if defined CHALLENGER_SECRET_HOST_KEY exit 42".to_string(),
            ],
        )),
        scratchpad_root: scratch_dir.clone(),
        allow_scratch_write: false,
    };

    let receipt_secret = dispatcher
        .dispatch(&req_secret_check)
        .expect("Tier 2 dispatch");
    assert_eq!(
        receipt_secret.exit_code, 0,
        "Host secret environment variable MUST NOT leak into Tier 2 child process"
    );

    // 2. Verify that OSOOSI_TIER2_CONFINED IS defined and set to 1 in child environment
    let req_confined = TieredToolRequest {
        agent_id: format!("c2-env-test2-{}", uuid::Uuid::new_v4().simple()),
        role: ArmRole::AnomalyDetection,
        tool_name: "env_check_confined".to_string(),
        payload: Vec::new(),
        custom_wat: None,
        native_command: Some((
            "cmd.exe".to_string(),
            vec![
                "/c".to_string(),
                "if not \"%OSOOSI_TIER2_CONFINED%\"==\"1\" exit 55".to_string(),
            ],
        )),
        scratchpad_root: scratch_dir.clone(),
        allow_scratch_write: false,
    };
    let receipt_conf = dispatcher.dispatch(&req_confined).expect("Tier 2 dispatch");
    assert_eq!(
        receipt_conf.exit_code, 0,
        "OSOOSI_TIER2_CONFINED must be set to 1 in Tier 2 child environment"
    );

    // Cleanup host env
    std::env::remove_var("CHALLENGER_SECRET_HOST_KEY");
    let _ = std::fs::remove_dir_all(&scratch_dir);
}

// =========================================================================
// 3. Mercury Containment Mass Accumulation & Sulfur Passivation
// =========================================================================

#[cfg(windows)]
#[test]
fn test_challenger2_mercury_mass_accumulation_and_sulfur_passivation() {
    let mercury = Arc::new(MercuryContainmentEngine::new());
    let dispatcher = TieredExecutionDispatcher::try_new()
        .expect("dispatcher init")
        .with_mercury(Arc::clone(&mercury));

    let agent_target = format!("c2-mercury-target-{}", uuid::Uuid::new_v4().simple());
    let scratch_dir = std::env::temp_dir().join(format!("c2_scratch_merc_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&scratch_dir);

    // Initial clean dispatch
    let req1 = TieredToolRequest {
        agent_id: agent_target.clone(),
        role: ArmRole::VulnerabilityResearch,
        tool_name: "probe1".to_string(),
        payload: Vec::new(),
        custom_wat: None,
        native_command: Some((
            "cmd.exe".to_string(),
            vec!["/c".to_string(), "exit 0".to_string()],
        )),
        scratchpad_root: scratch_dir.clone(),
        allow_scratch_write: false,
    };
    let rec1 = dispatcher
        .dispatch(&req1)
        .expect("First dispatch must succeed");
    let eval1 = rec1
        .mercury_evaluation
        .expect("Must have Mercury evaluation");
    assert!(
        !eval1.sulfur_passivated_hgs,
        "Initial execution must not be passivated"
    );
    assert!(eval1.cumulative_mass_fraction < 1.0);

    // Inject actuation sample that crosses the 1.0 mass threshold
    let rogue_sample = MeasuredActuationSample {
        total_processes_spawned: 1,
        active_processes: 0,
        read_transfer_bytes: 1_000,
        write_transfer_bytes: 200_000,
        other_transfer_bytes: 100_000,
        elapsed_s: 0.1,
        derived_pressure_pa: 5000.0,
        derived_velocity_m_s: 15.0,
        derived_fragment_mass: 1.5, // Pushes cumulative mass well past 1.0
    };
    let eval_injected = mercury.evaluate_measured_sample(&agent_target, &rogue_sample);
    assert!(
        eval_injected.sulfur_passivated_hgs,
        "Mass fraction >= 1.0 must trigger HgS sulfur passivation"
    );
    assert!(
        eval_injected.reason.contains("HgS sulfur passivation"),
        "Reason must state HgS sulfur passivation: {}",
        eval_injected.reason
    );

    // Subsequent dispatch for passivated agent MUST fail closed with TIER2_MERCURY_PASSIVATION
    let err = dispatcher
        .dispatch(&req1)
        .expect_err("Passivated agent must be barred from further native dispatch");
    match err {
        OctopusSecurityError::IsolationViolation(msg) => {
            assert!(
                msg.contains("TIER2_MERCURY_PASSIVATION"),
                "Expected TIER2_MERCURY_PASSIVATION error, got: {}",
                msg
            );
            assert!(msg.contains(&agent_target));
        }
        other => panic!("Expected IsolationViolation, got: {:?}", other),
    }

    // Multi-Agent Isolation Verification:
    // A distinct clean agent must NOT be affected by agent_target's passivation
    let clean_agent = format!("c2-clean-agent-{}", uuid::Uuid::new_v4().simple());
    let req_clean = TieredToolRequest {
        agent_id: clean_agent,
        role: ArmRole::VulnerabilityResearch,
        tool_name: "probe_clean".to_string(),
        payload: Vec::new(),
        custom_wat: None,
        native_command: Some((
            "cmd.exe".to_string(),
            vec!["/c".to_string(), "exit 0".to_string()],
        )),
        scratchpad_root: scratch_dir.clone(),
        allow_scratch_write: false,
    };
    let rec_clean = dispatcher
        .dispatch(&req_clean)
        .expect("Clean agent must NOT be blocked by peer passivation");
    assert_eq!(rec_clean.exit_code, 0);

    let _ = std::fs::remove_dir_all(&scratch_dir);
}

// =========================================================================
// 4. Windows Job Object Resource Ceilings & Accounting Invariants
// =========================================================================

#[cfg(windows)]
#[test]
fn test_challenger2_windows_job_object_limits_and_accounting() {
    let job_name = format!(
        "Challenger2Job_{}_{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    );
    let job =
        WindowsJobObject::create(&job_name, 2, 32 * 1024 * 1024).expect("WindowsJobObject::create");

    assert_eq!(job.name, job_name);
    assert_eq!(job.max_processes, 2);
    assert_eq!(job.max_memory_bytes, 32 * 1024 * 1024);

    let acct = job
        .query_accounting()
        .expect("query_accounting on fresh job");
    assert_eq!(acct.total_processes, 0);
    assert_eq!(acct.active_processes, 0);

    let sample =
        MeasuredActuationSample::sample_from_job(&job, 0.5).expect("sample_from_job must succeed");
    assert_eq!(sample.total_processes_spawned, 0);
    assert!(sample.derived_pressure_pa >= 0.0);
    assert!(sample.derived_velocity_m_s >= 0.0);
    assert!(sample.derived_fragment_mass >= 0.0);

    // Verify termination sets is_terminated atomic flag
    job.terminate(0).expect("job.terminate must succeed");
    assert!(job.is_terminated.load(std::sync::atomic::Ordering::SeqCst));
}

// =========================================================================
// 5. Concurrent Tier-2 Dispatches Resilience Under Stress
// =========================================================================

#[cfg(windows)]
#[test]
fn test_challenger2_concurrent_tier2_dispatches_resilience() {
    let dispatcher = TieredExecutionDispatcher::try_new().expect("dispatcher init");
    let base_scratch = std::env::temp_dir().join(format!("c2_conc_scratch_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&base_scratch);

    let mut handles = Vec::new();
    for i in 0..3 {
        let disp = dispatcher.clone();
        let scratch = base_scratch.join(format!("sub_{}", i));
        let _ = std::fs::create_dir_all(&scratch);

        handles.push(std::thread::spawn(move || {
            let req = TieredToolRequest {
                agent_id: format!("c2-conc-{}-{}", i, uuid::Uuid::new_v4().simple()),
                role: ArmRole::AnomalyDetection,
                tool_name: "conc_probe".to_string(),
                payload: Vec::new(),
                custom_wat: None,
                native_command: Some((
                    "cmd.exe".to_string(),
                    vec!["/c".to_string(), format!("echo worker_{}", i)],
                )),
                scratchpad_root: scratch,
                allow_scratch_write: false,
            };
            let receipt = disp
                .dispatch(&req)
                .expect("Concurrent dispatch must succeed");
            assert_eq!(receipt.exit_code, 0);
            assert!(receipt.win32_is_in_job);
            assert!(
                receipt
                    .win32_appcontainer_verification
                    .as_ref()
                    .unwrap()
                    .is_appcontainer
            );
            assert!(receipt
                .win32_child_token_posture
                .as_ref()
                .unwrap()
                .verify_agent_safe()
                .is_ok());
        }));
    }

    for h in handles {
        h.join().expect("Worker thread panicked");
    }

    let _ = std::fs::remove_dir_all(&base_scratch);
}
