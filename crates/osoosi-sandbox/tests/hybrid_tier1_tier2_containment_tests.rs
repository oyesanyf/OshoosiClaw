//! Integration tests for the 3-Layer Pure-Rust Hybrid Containment Architecture in `osoosi-sandbox`:
//! - Tier 1 In-Process Wasmtime Capability Sandbox (`WasmTier1Executor`, `ResourceLimiter`, fuel metering,
//!   and `open_confined` handle-verified scratchpad access).
//! - Tier 2 Native Win32 De-Elevated + JobObject Confinement (`spawn_deelevated_in_job`, `SandboxJobObject`,
//!   `TokenPosture`, and `OS Error 5` proof on `C:\Windows\System32\config\SAM` & `\\.\PhysicalDrive0`).
//! - Unified `TieredExecutionDispatcher` routing Tier 1 vs Tier 2 workloads.

use osoosi_sandbox::{
    build_windows_command_line, detect_renamed_interpreter_marker, open_confined,
    quote_windows_argv_arg, rollback_appcontainer_profile, ExecutableIdentityVerifier,
    ExecutionTier, MeasuredActuationSample, MercuryContainmentEngine, SandboxJobObject,
    TieredExecutionDispatcher, TieredToolRequest, WasmSandboxLimits, WasmTier1Executor,
    WindowsJobObject, INTEGRITY_MEDIUM,
};
use osoosi_types::{ArmRole, OctopusSecurityError};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

#[test]
fn test_tier1_wasm_fuel_metering_halts_infinite_loop() {
    let executor = WasmTier1Executor::try_new().expect("WasmTier1Executor init");
    let infinite_loop_wat = r#"
    (module
        (memory (export "memory") 1 2)
        (func (export "octopus_run") (result i32)
            (loop $inf
                (br $inf)
            )
            (i32.const 0)
        )
    )
    "#;
    let limits = WasmSandboxLimits {
        fuel_budget: 25_000,
        ..WasmSandboxLimits::default()
    };
    let err = executor
        .execute_wat("runaway_loop", infinite_loop_wat, b"", limits)
        .expect_err("Infinite loop must trap deterministically when fuel is exhausted");
    match err {
        OctopusSecurityError::ResourceQuotaExceeded(msg) => {
            assert!(
                msg.contains("TIER1_WASM_OUT_OF_FUEL"),
                "Expected TIER1_WASM_OUT_OF_FUEL error, got: {}",
                msg
            );
        }
        other => panic!("Expected ResourceQuotaExceeded, got: {:?}", other),
    }
}

#[test]
fn test_tier1_wasm_resource_limiter_caps_linear_memory_growth() {
    let executor = WasmTier1Executor::try_new().expect("WasmTier1Executor init");
    // Try to grow memory by 64 pages (4 MiB) when limit is 256 KiB (4 pages).
    let grow_wat = r#"
    (module
        (memory (export "memory") 1)
        (func (export "octopus_run") (result i32)
            (memory.grow (i32.const 64))
        )
    )
    "#;
    let limits = WasmSandboxLimits {
        max_linear_memory_bytes: 256 * 1024, // 256 KiB ceiling
        ..WasmSandboxLimits::default()
    };
    let receipt = executor
        .execute_wat("memory_hog", grow_wat, b"", limits)
        .expect("memory.grow denial returns -1 to guest");
    assert_eq!(
        receipt.exit_code, -1,
        "wasmtime ResourceLimiter must force memory.grow past ceiling to return -1"
    );
    assert!(
        receipt.memory_limit_exceeded,
        "Receipt must record that the linear memory limit was exceeded"
    );
    assert!(receipt.peak_linear_memory_bytes <= 256 * 1024);
}

#[test]
fn test_tier1_wasm_forbids_ambient_wasi_imports() {
    let executor = WasmTier1Executor::try_new().expect("WasmTier1Executor init");
    let ambient_wat = r#"
    (module
        (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
        (memory (export "memory") 1)
        (func (export "octopus_run") (result i32)
            (call $exit (i32.const 0))
            (i32.const 0)
        )
    )
    "#;
    let err = executor
        .execute_wat(
            "ambient_import_attempt",
            ambient_wat,
            b"",
            WasmSandboxLimits::default(),
        )
        .expect_err("Imports outside 'octopus_wasi' must be rejected fail-closed");
    assert!(format!("{}", err).contains("TIER1_AMBIENT_IMPORT_FORBIDDEN"));
}

#[test]
fn test_tier1_wasm_scratchpad_confinement_blocks_sam_junctions_and_hardlinks() {
    let executor = WasmTier1Executor::try_new().expect("WasmTier1Executor init");
    let scratch_dir =
        std::env::temp_dir().join(format!("osoosi_tier1_scratch_{}", std::process::id()));
    let outside_dir =
        std::env::temp_dir().join(format!("osoosi_tier1_outside_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch_dir);
    let _ = std::fs::remove_dir_all(&outside_dir);
    std::fs::create_dir_all(&scratch_dir).unwrap();
    std::fs::create_dir_all(&outside_dir).unwrap();

    std::fs::write(scratch_dir.join("safe.txt"), b"CONFIRMED_SAFE_PAYLOAD").unwrap();
    let outside_secret = outside_dir.join("secret.txt");
    std::fs::write(&outside_secret, b"OUTSIDE_HOST_SECRET").unwrap();

    // Create a hardlink inside scratch_dir pointing to outside_secret
    let hardlink_inside = scratch_dir.join("hardlinked.txt");
    let _ = std::fs::hard_link(&outside_secret, &hardlink_inside);

    // Create an NTFS junction inside scratch_dir pointing to outside_dir
    #[cfg(windows)]
    {
        let junction_inside = scratch_dir.join("junc");
        let _ = std::process::Command::new("cmd.exe")
            .args([
                "/c",
                "mklink",
                "/J",
                &junction_inside.to_string_lossy(),
                &outside_dir.to_string_lossy(),
            ])
            .output();
    }

    // Direct handle-level open_confined checks
    assert!(
        open_confined(&scratch_dir, r"C:\Windows\System32\config\SAM", false).is_err(),
        "open_confined must reject absolute SAM path"
    );
    assert!(
        open_confined(&scratch_dir, "../secret.txt", false).is_err(),
        "open_confined must reject parent traversal"
    );
    if hardlink_inside.exists() {
        let hl_err = open_confined(&scratch_dir, "hardlinked.txt", false)
            .expect_err("open_confined must reject hardlinks (nNumberOfLinks > 1)");
        assert!(format!("{}", hl_err).contains("HARDLINK_BLOCKED"));
    }
    #[cfg(windows)]
    if scratch_dir.join("junc").exists() {
        let junc_err = open_confined(&scratch_dir, r"junc\secret.txt", false)
            .expect_err("open_confined must reject NTFS junctions");
        assert!(format!("{}", junc_err).contains("REPARSE_DIR_BLOCKED"));
    }

    // Wasm guest that tries to read input path via octopus_wasi::scratch_read and emit it
    let reader_wat = r#"
    (module
        (import "octopus_wasi" "input_len" (func $input_len (result i32)))
        (import "octopus_wasi" "read_input" (func $read_input (param i32 i32) (result i32)))
        (import "octopus_wasi" "scratch_read" (func $scratch_read (param i32 i32 i32 i32) (result i32)))
        (import "octopus_wasi" "emit_output" (func $emit_output (param i32 i32) (result i32)))
        (memory (export "memory") 1)
        (func (export "octopus_run") (result i32)
            (local $plen i32)
            (local $nread i32)
            (local.set $plen (call $input_len))
            (drop (call $read_input (i32.const 0) (local.get $plen)))
            (local.set $nread (call $scratch_read (i32.const 0) (local.get $plen) (i32.const 1024) (i32.const 4096)))
            (if (i32.lt_s (local.get $nread) (i32.const 0))
                (then (return (local.get $nread)))
            )
            (call $emit_output (i32.const 1024) (local.get $nread))
        )
    )
    "#;

    let limits = WasmSandboxLimits {
        scratchpad_root: scratch_dir.clone(),
        allow_scratch_write: false,
        ..WasmSandboxLimits::default()
    };

    // 1. Escape attempt to SAM inside Wasm guest -> returns WASI_ERR_ACCESS_DENIED (-5)
    let sam_attempt = executor
        .execute_wat(
            "sam_escape_probe",
            reader_wat,
            br"C:\Windows\System32\config\SAM",
            limits.clone(),
        )
        .unwrap();
    assert_eq!(sam_attempt.exit_code, -5);
    assert!(!sam_attempt.blocked_escape_attempts.is_empty());

    // 2. Confined read of safe.txt inside Wasm guest -> succeeds
    let safe_read = executor
        .execute_wat("safe_reader", reader_wat, b"safe.txt", limits)
        .unwrap();
    assert_eq!(safe_read.exit_code, 22);
    assert_eq!(safe_read.raw_output, "CONFIRMED_SAFE_PAYLOAD");

    let _ = std::fs::remove_dir_all(&scratch_dir);
    let _ = std::fs::remove_dir_all(&outside_dir);
}

#[test]
fn test_tiered_dispatcher_routes_tier1_wasm_and_tier2_win32() {
    let dispatcher = TieredExecutionDispatcher::try_new().expect("TieredExecutionDispatcher init");
    let scratch_dir =
        std::env::temp_dir().join(format!("osoosi_tiered_disp_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&scratch_dir);

    // Tier 1: Document extraction in Wasm
    let req_t1 = TieredToolRequest {
        agent_id: "arm-doc-1".to_string(),
        role: ArmRole::UntrustedDocIngest,
        tool_name: "document_read".to_string(),
        payload: b"Clean report\x00\x07 with control chars stripped".to_vec(),
        custom_wat: None,
        native_command: None,
        scratchpad_root: scratch_dir.clone(),
        allow_scratch_write: false,
    };
    let receipt_t1 = dispatcher.dispatch(&req_t1).expect("Tier 1 dispatch");
    assert_eq!(receipt_t1.selected_tier, ExecutionTier::Tier1InProcessWasm);
    let wasm_rec = receipt_t1.wasm_receipt.expect("wasm receipt present");
    assert_eq!(
        wasm_rec.raw_output,
        "Clean report with control chars stripped"
    );
    assert!(wasm_rec.fuel_consumed > 0);
    assert_eq!(receipt_t1.zero_mi_output.mutual_information_bits, 0);

    // Tier 2: Native Win32 confined child process (cmd.exe /c echo)
    let req_t2 = TieredToolRequest {
        agent_id: "arm-cli-2".to_string(),
        role: ArmRole::AnomalyDetection,
        tool_name: "native_cli_probe".to_string(),
        payload: Vec::new(),
        custom_wat: None,
        native_command: Some((
            "cmd.exe".to_string(),
            vec!["/c".to_string(), "echo".to_string(), "TIER2_OK".to_string()],
        )),
        scratchpad_root: scratch_dir.clone(),
        allow_scratch_write: false,
    };
    let receipt_t2 = dispatcher.dispatch(&req_t2).expect("Tier 2 dispatch");
    assert_eq!(
        receipt_t2.selected_tier,
        ExecutionTier::Tier2NativeWin32Confinement
    );
    assert_eq!(receipt_t2.exit_code, 0);
    assert!(receipt_t2.win32_is_in_job);
    let posture = receipt_t2
        .win32_child_token_posture
        .expect("Child token posture recorded");
    assert!(!posture.elevated, "Tier 2 child must never run elevated");
    assert!(posture.integrity_rid <= INTEGRITY_MEDIUM);
    assert!(posture.dangerous_privileges_present().is_empty());
    let acct = receipt_t2
        .job_accounting
        .expect("Job accounting snapshot recorded");
    assert!(acct.total_processes >= 1);

    #[cfg(windows)]
    {
        assert!(receipt_t2.win32_appcontainer_verification.is_some());
        let ac_ver = receipt_t2.win32_appcontainer_verification.as_ref().unwrap();
        assert!(
            ac_ver.is_appcontainer,
            "Must be verified inside AppContainer"
        );
        assert!(
            ac_ver.job_membership_verified,
            "Job membership must be verified"
        );
        assert!(receipt_t2.verified_executable_metadata.is_some());
        let meta = receipt_t2.verified_executable_metadata.as_ref().unwrap();
        assert!(
            meta.is_system32_binary,
            "cmd.exe must be identified as System32 binary"
        );
        assert_eq!(meta.sha256_hex.len(), 64);
        assert!(
            receipt_t2.job_io_sample.is_some(),
            "Must include MeasuredActuationSample"
        );
        assert!(
            receipt_t2.mercury_evaluation.is_some(),
            "Must include Mercury evaluation"
        );
    }

    let _ = std::fs::remove_dir_all(&scratch_dir);
}

#[derive(Debug, Serialize, Deserialize)]
struct ChildPostureReport {
    elevated: bool,
    integrity_rid: u32,
    admins_enabled: bool,
    admins_deny_only: bool,
    dangerous_privileges: Vec<String>,
    sam_open_os_error: Option<i32>,
    physical_drive0_os_error: Option<i32>,
    reg_save_sam_succeeded: bool,
    reg_save_file_exists: bool,
}

#[cfg(windows)]
#[test]
fn posture_child_probe() {
    let Ok(report_path) = std::env::var("OSOOSI_POSTURE_REPORT_PATH") else {
        return;
    };
    let posture =
        osoosi_sandbox::current_token_posture().expect("child current_token_posture must succeed");

    let sam_open_os_error = std::fs::File::open(r"C:\Windows\System32\config\SAM")
        .err()
        .and_then(|e| e.raw_os_error());

    let physical_drive0_os_error = std::fs::File::open(r"\\.\PhysicalDrive0")
        .err()
        .and_then(|e| e.raw_os_error());

    let hive_out = std::env::temp_dir().join(format!("osoosi_sam_dump_{}.hiv", std::process::id()));
    let _ = std::fs::remove_file(&hive_out);
    let reg_status = std::process::Command::new("reg.exe")
        .args(["save", r"HKLM\SAM", &hive_out.to_string_lossy(), "/y"])
        .output();
    let reg_save_sam_succeeded = reg_status.map(|o| o.status.success()).unwrap_or(false);
    // reg.exe creates a 0-byte destination file before NtSaveKey fails with ERROR_PRIVILEGE_NOT_HELD.
    let reg_save_file_exists = std::fs::metadata(&hive_out)
        .map(|m| m.len() > 0)
        .unwrap_or(false);
    let _ = std::fs::remove_file(&hive_out);

    let report = ChildPostureReport {
        elevated: posture.elevated,
        integrity_rid: posture.integrity_rid,
        admins_enabled: posture.admins_enabled,
        admins_deny_only: posture.admins_deny_only,
        dangerous_privileges: posture.dangerous_privileges_present(),
        sam_open_os_error,
        physical_drive0_os_error,
        reg_save_sam_succeeded,
        reg_save_file_exists,
    };
    std::fs::write(&report_path, serde_json::to_vec(&report).unwrap()).unwrap();
}

#[cfg(windows)]
#[test]
fn test_tier2_deelevated_child_denies_sam_and_physical_drive_with_error_5() {
    let report_file =
        std::env::temp_dir().join(format!("osoosi_posture_report_{}.json", std::process::id()));
    let _ = std::fs::remove_file(&report_file);

    std::env::set_var(
        "OSOOSI_POSTURE_REPORT_PATH",
        report_file.to_string_lossy().as_ref(),
    );
    let exe = std::env::current_exe().expect("test binary path");
    let cmd = format!(
        "\"{}\" --exact posture_child_probe --nocapture",
        exe.display()
    );
    let job = SandboxJobObject::create("OsoosiChildProbeJob", 4, 512 * 1024 * 1024)
        .expect("SandboxJobObject::create");
    let child = osoosi_sandbox::spawn_deelevated_in_job(&cmd, true, Some(&job))
        .expect("spawn_deelevated_in_job must succeed");
    assert!(child.is_in_job, "Child must be verified inside Job Object");
    assert!(!child.posture.elevated);
    assert!(child.posture.integrity_rid <= INTEGRITY_MEDIUM);
    assert!(!child.posture.admins_enabled);
    assert!(child.posture.dangerous_privileges_present().is_empty());

    let exit_code = child.wait().expect("wait on de-elevated child");
    std::env::remove_var("OSOOSI_POSTURE_REPORT_PATH");
    assert_eq!(exit_code, 0, "posture_child_probe must exit 0");

    let mut raw = String::new();
    std::fs::File::open(&report_file)
        .expect("child must have written posture report")
        .read_to_string(&mut raw)
        .unwrap();
    let _ = std::fs::remove_file(&report_file);
    let report: ChildPostureReport = serde_json::from_str(&raw).unwrap();

    assert!(!report.elevated);
    assert!(report.integrity_rid <= INTEGRITY_MEDIUM);
    assert!(!report.admins_enabled);
    assert!(report.dangerous_privileges.is_empty());
    // Must be OS Error 5 (ERROR_ACCESS_DENIED), never OS Error 32 (ERROR_SHARING_VIOLATION)
    assert_eq!(
        report.sam_open_os_error,
        Some(5),
        "De-elevated child must get OS Error 5 (ERROR_ACCESS_DENIED) on SAM, never Error 32"
    );
    assert_eq!(
        report.physical_drive0_os_error,
        Some(5),
        "De-elevated child must get OS Error 5 (ERROR_ACCESS_DENIED) on \\\\.\\PhysicalDrive0"
    );
    assert!(!report.reg_save_sam_succeeded);
    assert!(!report.reg_save_file_exists);
}

#[test]
fn test_executable_identity_verifier_rejects_forbidden_interpreters() {
    let verifier = ExecutableIdentityVerifier::default();
    let forbidden = [
        "powershell.exe",
        "powershell",
        "pwsh.exe",
        "pwsh",
        "python.exe",
        "python",
        "python3.exe",
        "mshta.exe",
        "cscript.exe",
        "wscript.exe",
    ];

    for target in forbidden {
        let err = verifier
            .verify_and_lock(target, None)
            .expect_err(&format!("Target '{}' must be rejected", target));
        match err {
            OctopusSecurityError::IsolationViolation(msg) => {
                assert!(
                    msg.contains("EXEC_ID_FORBIDDEN_INTERPRETER"),
                    "Target '{}' expected EXEC_ID_FORBIDDEN_INTERPRETER, got: {}",
                    target,
                    msg
                );
            }
            other => panic!(
                "Target '{}' expected IsolationViolation, got: {:?}",
                target, other
            ),
        }
    }

    // Space-polluted or non-allowlisted program names must also be rejected fail-closed
    let unapproved = verifier
        .verify_and_lock("cmd.exe /c powershell", None)
        .expect_err("Argument-polluted program target must be rejected");
    assert!(format!("{}", unapproved).contains("EXEC_ID_NOT_ALLOWLISTED"));
}

#[test]
fn test_executable_identity_verifier_renamed_interpreter_pe_markers() {
    // 1. ASCII marker for PowerShell
    let mut fake_ps_pe = b"MZ\x90\x00\x03\x00\x00\x00".to_vec();
    fake_ps_pe.extend_from_slice(b"Some header bytes here");
    fake_ps_pe.extend_from_slice(b"System.Management.Automation");
    fake_ps_pe.extend_from_slice(b"More trailing bytes");
    let marker1 = detect_renamed_interpreter_marker(&fake_ps_pe, "totally_safe_tool");
    assert_eq!(marker1, Some("powershell".to_string()));

    // 2. UTF-16LE marker for PowerShell PDB
    let mut fake_ps_pdb_pe = b"MZ\x90\x00\x03\x00\x00\x00".to_vec();
    let utf16_pdb: Vec<u8> = "powershell.pdb"
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    fake_ps_pdb_pe.extend_from_slice(&utf16_pdb);
    let marker2 = detect_renamed_interpreter_marker(&fake_ps_pdb_pe, "my_custom_worker");
    assert_eq!(marker2, Some("powershell_pdb_utf16".to_string()));

    // 3. Python runtime DLL reference
    let mut fake_py_pe = b"MZ\x90\x00\x03\x00\x00\x00".to_vec();
    fake_py_pe.extend_from_slice(b"import dependencies: python311.dll embedded");
    let marker3 = detect_renamed_interpreter_marker(&fake_py_pe, "harmless_calc");
    assert_eq!(marker3, Some("python_dll".to_string()));

    // 4. Benign bytes -> None
    let benign =
        b"MZ\x90\x00\x03\x00\x00\x00Benign executable content without interpreter signatures";
    assert_eq!(detect_renamed_interpreter_marker(benign, "my_tool"), None);
}

#[cfg(windows)]
#[test]
fn test_executable_identity_verifier_handle_read_lock_blocks_concurrent_write() {
    let verifier = ExecutableIdentityVerifier::default();
    // cmd.exe is guaranteed to exist on Windows in System32
    let handle = verifier
        .verify_and_lock("cmd.exe", None)
        .expect("verify_and_lock on cmd.exe must succeed");

    assert_eq!(handle.metadata.normalized_stem, "cmd");
    assert!(handle.metadata.is_system32_binary);
    assert_eq!(handle.metadata.sha256_hex.len(), 64);

    // Attempt concurrent open with write access against canonical path.
    // Because handle is held with FILE_SHARE_READ (omitting FILE_SHARE_WRITE and FILE_SHARE_DELETE),
    // opening with write access MUST fail with ERROR_SHARING_VIOLATION (32) or ERROR_ACCESS_DENIED (5).
    let write_attempt = std::fs::OpenOptions::new()
        .write(true)
        .open(&handle.metadata.canonical_path);

    let err =
        write_attempt.expect_err("Concurrent write access must be blocked by handle read-lock");
    let raw_err = err.raw_os_error().unwrap_or(0);
    assert!(
        raw_err == 32 || raw_err == 5,
        "Expected OS error 32 (ERROR_SHARING_VIOLATION) or 5 (ERROR_ACCESS_DENIED), got: {}",
        raw_err
    );

    // Dropping handle releases the lock
    drop(handle);
}

#[cfg(windows)]
#[test]
fn test_measured_actuation_sample_mercury_evaluation() {
    let job = WindowsJobObject::create("OsoosiMercuryTestJob", 4, 32 * 1024 * 1024)
        .expect("WindowsJobObject::create");

    let sample =
        MeasuredActuationSample::sample_from_job(&job, 0.5).expect("sample_from_job must succeed");
    assert_eq!(sample.total_processes_spawned, 0);

    let engine = MercuryContainmentEngine::new();
    let eval_clean = engine.evaluate_measured_sample("arm-test-1", &sample);
    assert!(!eval_clean.sulfur_passivated_hgs);
    assert!(eval_clean.cumulative_mass_fraction < 1.0);

    // Extreme rogue sample with high derived_fragment_mass
    let mut rogue_sample = sample.clone();
    rogue_sample.derived_fragment_mass = 1.5;
    let eval_rogue = engine.evaluate_measured_sample("arm-rogue-1", &rogue_sample);
    assert!(eval_rogue.sulfur_passivated_hgs);
    assert!(eval_rogue.reason.contains("HgS sulfur passivation"));
}

#[test]
fn test_open_confined_post_verification_truncation() {
    let scratch_dir = std::env::temp_dir().join(format!(
        "osoosi_open_confined_trunc_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&scratch_dir);
    std::fs::create_dir_all(&scratch_dir).expect("create scratch dir");

    // 1. Write an initial 16-byte file
    {
        let mut f1 =
            open_confined(&scratch_dir, "truncate_test.txt", true).expect("open_confined 1");
        f1.write_all(b"0123456789ABCDEF")
            .expect("write initial 16 bytes");
    }

    // Verify initial file has length 16
    let initial_bytes = std::fs::read(scratch_dir.join("truncate_test.txt")).expect("read initial");
    assert_eq!(initial_bytes.len(), 16);

    // 2. Open with write=true and write a shorter 5-byte payload
    {
        let mut f2 =
            open_confined(&scratch_dir, "truncate_test.txt", true).expect("open_confined 2");
        f2.write_all(b"short").expect("write short 5 bytes");
    }

    // 3. Verify file length is strictly 5 and no stale trailing bytes remain
    let final_bytes =
        std::fs::read(scratch_dir.join("truncate_test.txt")).expect("read overwritten");
    assert_eq!(
        final_bytes, b"short",
        "open_confined(write=true) must truncate existing file post-verification so no stale trailing bytes remain"
    );

    let _ = std::fs::remove_dir_all(&scratch_dir);
}

#[test]
fn test_msvcrt_command_line_quoting_and_construction() {
    // 1. Plain tokens without whitespace or quotes need no quotes
    assert_eq!(quote_windows_argv_arg("simple"), "simple");
    assert_eq!(quote_windows_argv_arg("foo.exe"), "foo.exe");

    // 2. Empty string must be rendered as ""
    assert_eq!(quote_windows_argv_arg(""), "\"\"");

    // 3. Whitespace requires double quotes
    assert_eq!(quote_windows_argv_arg("hello world"), "\"hello world\"");

    // 4. Trailing backslashes before closing quote must be doubled ($2n$)
    let tricky_arg = r#"C:\path with spaces\trailing\"#;
    assert_eq!(
        quote_windows_argv_arg(tricky_arg),
        r#""C:\path with spaces\trailing\\""#,
        "Trailing backslash before closing quote must be doubled per MSVCRT rules"
    );

    // 5. Backslash preceding embedded quote must be doubled ($2n + 1$)
    let embedded_quote_arg = r#"foo\"bar"#;
    assert_eq!(
        quote_windows_argv_arg(embedded_quote_arg),
        r#""foo\\\"bar""#,
        "Backslash immediately preceding quote must be doubled before escaping the quote"
    );

    // 6. Full command line construction
    let full_cmd = build_windows_command_line(
        r"C:\Windows\System32\where.exe",
        &[tricky_arg.to_string(), "".to_string(), "normal".to_string()],
    );
    assert!(full_cmd.starts_with(r#""C:\Windows\System32\where.exe""#));
    assert!(full_cmd.contains(r#""C:\path with spaces\trailing\\""#));
    assert!(full_cmd.ends_with(r#" "" normal"#));
}

#[cfg(windows)]
#[test]
fn test_executable_identity_non_system32_spoof_rejection() {
    let test_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("target")
        .join("test_spoof_bin");
    let _ = std::fs::remove_dir_all(&test_dir);
    std::fs::create_dir_all(&test_dir).expect("create test_spoof_bin dir");

    // Minimal valid DOS PE header
    let mut pe_bytes = vec![0u8; 128];
    pe_bytes[0] = b'M';
    pe_bytes[1] = b'Z';
    pe_bytes[0x3c] = 0x40; // PE signature offset at 0x40
    pe_bytes[0x40] = b'P';
    pe_bytes[0x41] = b'E';
    pe_bytes[0x42] = 0;
    pe_bytes[0x43] = 0;

    let verifier = ExecutableIdentityVerifier::new();

    for stem in ["cmd", "where", "curl"] {
        let fake_path = test_dir.join(format!("{}.exe", stem));
        std::fs::write(&fake_path, &pe_bytes).expect("write fake binary");

        let err = verifier
            .verify_and_lock(&fake_path.to_string_lossy(), None)
            .expect_err(&format!(
                "Fake '{}' outside System32 must be rejected",
                stem
            ));

        match err {
            OctopusSecurityError::IsolationViolation(msg) => {
                assert!(
                    msg.contains("EXEC_ID_NON_SYSTEM32_SPOOF"),
                    "Expected EXEC_ID_NON_SYSTEM32_SPOOF for '{}', got: {}",
                    stem,
                    msg
                );
            }
            other => panic!("Expected IsolationViolation, got: {:?}", other),
        }
    }

    let _ = std::fs::remove_dir_all(&test_dir);
}

#[cfg(windows)]
#[test]
fn test_executable_identity_untrusted_install_root_rejection_and_pinning() {
    use sha2::{Digest, Sha256};

    let temp_dir = std::env::temp_dir().join(format!(
        "osoosi_install_root_test_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&temp_dir);
    std::fs::create_dir_all(&temp_dir).expect("create temp dir");

    let mut pe_bytes = vec![0u8; 128];
    pe_bytes[0] = b'M';
    pe_bytes[1] = b'Z';
    pe_bytes[0x3c] = 0x40;
    pe_bytes[0x40] = b'P';
    pe_bytes[0x41] = b'E';
    pe_bytes[0x42] = 0;
    pe_bytes[0x43] = 0;

    let test_git = temp_dir.join("git.exe");
    std::fs::write(&test_git, &pe_bytes).expect("write git.exe");

    // Case 1: Unpinned git.exe in temp_dir is rejected as EXEC_ID_UNTRUSTED_INSTALL_ROOT
    let verifier_unpinned = ExecutableIdentityVerifier::new();
    let err = verifier_unpinned
        .verify_and_lock(&test_git.to_string_lossy(), None)
        .expect_err("Unpinned git.exe in temp_dir must be rejected");
    match err {
        OctopusSecurityError::IsolationViolation(msg) => {
            assert!(
                msg.contains("EXEC_ID_UNTRUSTED_INSTALL_ROOT")
                    || msg.contains("EXEC_ID_UNTRUSTED_DIRECTORY_BLOCKED"),
                "Expected install root or directory rejection, got: {}",
                msg
            );
        }
        other => panic!("Expected IsolationViolation, got: {:?}", other),
    }

    // Now test in a non-temp writable directory (target/test_install_root)
    let non_temp_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("target")
        .join("test_install_root");
    let _ = std::fs::create_dir_all(&non_temp_dir);
    let test_git_target = non_temp_dir.join("git.exe");
    std::fs::write(&test_git_target, &pe_bytes).expect("write git.exe in target");

    // Without pin -> EXEC_ID_UNTRUSTED_INSTALL_ROOT
    let err_target = verifier_unpinned
        .verify_and_lock(&test_git_target.to_string_lossy(), None)
        .expect_err("Unpinned git.exe outside approved roots must fail");
    match err_target {
        OctopusSecurityError::IsolationViolation(msg) => {
            assert!(
                msg.contains("EXEC_ID_UNTRUSTED_INSTALL_ROOT"),
                "Expected EXEC_ID_UNTRUSTED_INSTALL_ROOT, got: {}",
                msg
            );
        }
        other => panic!("Expected IsolationViolation, got: {:?}", other),
    }

    // With SHA-256 pin -> verification succeeds
    let mut verifier_pinned = ExecutableIdentityVerifier::new();
    let digest = hex::encode(Sha256::digest(&pe_bytes));
    verifier_pinned.pin_executable_sha256("git", &digest);

    let handle = verifier_pinned
        .verify_and_lock(&test_git_target.to_string_lossy(), None)
        .expect("SHA-256 pinned git.exe must succeed even outside default install roots");
    assert_eq!(handle.metadata.normalized_stem, "git");
    assert_eq!(handle.metadata.sha256_hex, digest);

    let _ = std::fs::remove_dir_all(&temp_dir);
    let _ = std::fs::remove_dir_all(&non_temp_dir);
}

#[cfg(windows)]
#[test]
fn test_appcontainer_profile_rollback_cleans_profile() {
    let name = format!("OsoosiClaw.TestRollback.{}", std::process::id());
    // Safe to invoke even if profile does not exist yet (DeleteAppContainerProfile returns HRESULT)
    rollback_appcontainer_profile(&name);
}
