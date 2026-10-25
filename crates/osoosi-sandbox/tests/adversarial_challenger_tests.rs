//! Adversarial Challenger Stress-Test Suite for Milestone 1 (M1).
//! Empirically tests:
//! 1. Handle read-locking against concurrent disk writes, truncations, and deletions.
//! 2. Forbidden interpreter rejection (all stems & case variations) and renamed interpreter PE marker detection.
//! 3. Fail-closed behavior on tampered or uninitialized AppContainer & Job Object configurations.
//! 4. Role/tool gating and control character injection defenses.

use osoosi_sandbox::tiered_executor::{
    create_or_open_appcontainer_profile, verify_process_appcontainer_token,
};
use osoosi_sandbox::{
    detect_renamed_interpreter_marker, ExecutableIdentityVerifier, TieredExecutionDispatcher,
    TieredToolRequest, WindowsJobObject, FORBIDDEN_TIER2_EXECUTABLE_STEMS,
};
use osoosi_types::{ArmRole, OctopusSecurityError};
use sha2::Digest;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[cfg(windows)]
use windows::Win32::System::Threading::GetCurrentProcess;

/// Helper to create a valid minimal PE DOS header (MZ...) with custom payload.
fn build_dummy_pe(extra_payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0u8; 128];
    bytes[0] = b'M';
    bytes[1] = b'Z';
    bytes[0x3c] = 0x80; // Pointer to PE header at offset 0x80
    bytes.extend_from_slice(b"PE\0\0"); // PE signature
    bytes.extend_from_slice(extra_payload);
    while bytes.len() < 256 {
        bytes.push(0);
    }
    bytes
}

// =========================================================================
// 1. Handle Read-Locking Stress Tests
// =========================================================================

#[cfg(windows)]
#[test]
fn test_challenger_handle_read_lock_blocks_concurrent_write_and_truncation_on_writable_file() {
    // Create a writable target binary outside of Temp or scratchpad to avoid directory blocks.
    // We use a folder under target/challenger_test_bin
    let target_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("target")
        .join("challenger_test_bin");
    std::fs::create_dir_all(&target_dir).expect("create challenger_test_bin dir");
    let test_exe = target_dir.join("git.exe");

    let pe_bytes = build_dummy_pe(b"Clean git executable placeholder for testing");
    std::fs::write(&test_exe, &pe_bytes).expect("write initial git.exe");

    let mut verifier = ExecutableIdentityVerifier::new();
    verifier.allow_stem("git");
    let pe_hash = hex::encode(sha2::Sha256::digest(&pe_bytes));
    verifier.pin_executable_sha256("git", &pe_hash);

    let exe_str = test_exe.to_string_lossy().to_string();
    let handle = verifier
        .verify_and_lock(&exe_str, None)
        .expect("verify_and_lock on test git.exe must succeed");

    assert_eq!(handle.metadata.normalized_stem, "git");
    assert_eq!(handle.metadata.file_size, pe_bytes.len() as u64);

    // TEST A: Attempt concurrent open for writing.
    // Because handle is held with FILE_SHARE_READ (no FILE_SHARE_WRITE),
    // opening with write access MUST fail with OS Error 32 (ERROR_SHARING_VIOLATION).
    let write_res = std::fs::OpenOptions::new().write(true).open(&test_exe);
    let err = write_res.expect_err("Concurrent write open MUST fail while handle lock is held");
    let raw_err = err.raw_os_error().unwrap_or(0);
    assert_eq!(
        raw_err, 32,
        "Expected OS error 32 (ERROR_SHARING_VIOLATION) on writable file, got: {}",
        raw_err
    );

    // TEST B: Attempt concurrent open with truncate.
    let trunc_res = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&test_exe);
    let trunc_err =
        trunc_res.expect_err("Concurrent truncation MUST fail while handle lock is held");
    assert_eq!(
        trunc_err.raw_os_error().unwrap_or(0),
        32,
        "Truncation must fail with ERROR_SHARING_VIOLATION (32)"
    );

    // TEST C: Attempt concurrent file deletion.
    let del_res = std::fs::remove_file(&test_exe);
    let del_err = del_res.expect_err("Concurrent deletion MUST fail while handle lock is held");
    assert_eq!(
        del_err.raw_os_error().unwrap_or(0),
        32,
        "Deletion must fail with ERROR_SHARING_VIOLATION (32)"
    );

    // TEST D: Concurrent multi-threaded write flood.
    let stop_signal = Arc::new(AtomicBool::new(false));
    let violations = Arc::new(AtomicUsize::new(0));
    let total_attempts = Arc::new(AtomicUsize::new(0));

    let mut threads = Vec::new();
    for _ in 0..4 {
        let path_clone = test_exe.clone();
        let stop_clone = Arc::clone(&stop_signal);
        let viol_clone = Arc::clone(&violations);
        let attempts_clone = Arc::clone(&total_attempts);

        threads.push(std::thread::spawn(move || {
            while !stop_clone.load(Ordering::Relaxed) {
                attempts_clone.fetch_add(1, Ordering::Relaxed);
                match std::fs::OpenOptions::new().write(true).open(&path_clone) {
                    Ok(_) => {
                        panic!("FATAL: Concurrent write succeeded while handle lock was held!")
                    }
                    Err(e) => {
                        if e.raw_os_error() == Some(32) {
                            viol_clone.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                std::thread::yield_now();
            }
        }));
    }

    std::thread::sleep(Duration::from_millis(50));
    stop_signal.store(true, Ordering::Relaxed);
    for t in threads {
        t.join().unwrap();
    }

    assert!(total_attempts.load(Ordering::Relaxed) > 100);
    assert_eq!(
        total_attempts.load(Ordering::Relaxed),
        violations.load(Ordering::Relaxed),
        "100% of concurrent write attempts MUST be rejected with ERROR_SHARING_VIOLATION"
    );

    // TEST E: Drop the handle lock and verify writing immediately succeeds.
    drop(handle);

    let mut write_after_drop = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&test_exe)
        .expect("Write must succeed after handle lock is dropped");
    write_after_drop
        .write_all(b"Post-unlock overwrite succeeded")
        .unwrap();
    drop(write_after_drop);

    // Clean up test file
    let _ = std::fs::remove_file(&test_exe);
}

// =========================================================================
// 2. Forbidden Interpreter Rejection & Renamed PE Marker Detection Tests
// =========================================================================

#[test]
fn test_challenger_exhaustive_forbidden_interpreter_rejection() {
    let verifier = ExecutableIdentityVerifier::default();

    for &stem in FORBIDDEN_TIER2_EXECUTABLE_STEMS {
        // Direct stem
        let err1 = verifier.verify_and_lock(stem, None).expect_err(&format!(
            "Stem '{}' must be rejected as forbidden interpreter",
            stem
        ));
        assert!(
            format!("{}", err1).contains("EXEC_ID_FORBIDDEN_INTERPRETER"),
            "Stem '{}' error should contain EXEC_ID_FORBIDDEN_INTERPRETER, got: {}",
            stem,
            err1
        );

        // Lowercase with .exe
        let target_exe = format!("{}.exe", stem);
        let err2 = verifier
            .verify_and_lock(&target_exe, None)
            .expect_err(&format!(
                "Target '{}' must be rejected as forbidden interpreter",
                target_exe
            ));
        assert!(format!("{}", err2).contains("EXEC_ID_FORBIDDEN_INTERPRETER"));

        // Uppercase variation with .EXE
        let target_upper = format!("{}.EXE", stem.to_ascii_uppercase());
        let err3 = verifier
            .verify_and_lock(&target_upper, None)
            .expect_err(&format!(
                "Target '{}' must be rejected as forbidden interpreter",
                target_upper
            ));
        assert!(format!("{}", err3).contains("EXEC_ID_FORBIDDEN_INTERPRETER"));

        // Mixed case with quotes
        let target_quoted = format!("\"{}\"", stem);
        let err4 = verifier
            .verify_and_lock(&target_quoted, None)
            .expect_err(&format!(
                "Target '{}' must be rejected as forbidden interpreter",
                target_quoted
            ));
        assert!(format!("{}", err4).contains("EXEC_ID_FORBIDDEN_INTERPRETER"));
    }
}

#[test]
fn test_challenger_renamed_interpreter_pe_markers_comprehensive() {
    // Test all markers: ASCII and UTF-16LE
    let markers_to_test = [
        ("System.Management.Automation", "powershell"),
        ("powershell.pdb", "powershell_pdb"),
        ("pwsh.dll", "pwsh_dll"),
        ("python3", "python_dll"),
        ("Py_Main", "python_core"),
        ("Py_Initialize", "python_run"),
        ("mshta.pdb", "mshta"),
        ("wscript.pdb", "wscript"),
        ("cscript.pdb", "cscript"),
        ("rundll32.pdb", "rundll32"),
        ("regsvr32.pdb", "regsvr32"),
        ("certutil.pdb", "certutil"),
        ("napi_register_module_v1", "node_v8"),
    ];

    for (marker, expected_label) in markers_to_test {
        // ASCII test
        let pe_ascii = build_dummy_pe(format!("Prefix bytes {} suffix", marker).as_bytes());
        let res_ascii = detect_renamed_interpreter_marker(&pe_ascii, "innocent_binary");
        assert!(
            res_ascii.is_some(),
            "Marker '{}' should be detected in ASCII",
            marker
        );
        let label = res_ascii.unwrap();
        assert_eq!(
            label, expected_label,
            "Expected label '{}', got '{}'",
            expected_label, label
        );

        // UTF-16LE test
        let utf16_bytes: Vec<u8> = marker
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        let pe_utf16 = build_dummy_pe(&utf16_bytes);
        let res_utf16 = detect_renamed_interpreter_marker(&pe_utf16, "innocent_binary");
        assert!(
            res_utf16.is_some(),
            "Marker '{}' should be detected in UTF-16LE",
            marker
        );
        let label_u16 = res_utf16.unwrap();
        assert!(
            label_u16.starts_with(expected_label),
            "Expected label starting with '{}', got '{}'",
            expected_label,
            label_u16
        );
    }
}

#[cfg(windows)]
#[test]
fn test_challenger_renamed_interpreter_on_disk_is_blocked_by_verifier() {
    let target_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("target")
        .join("challenger_test_bin");
    std::fs::create_dir_all(&target_dir).expect("create challenger_test_bin dir");
    let test_exe = target_dir.join("cargo.exe");

    // Create a binary disguised as cargo.exe but containing Python Py_Main marker
    let malicious_pe = build_dummy_pe(b"Disguised interpreter: Py_Main inside cargo.exe");
    std::fs::write(&test_exe, &malicious_pe).expect("write disguised cargo.exe");

    let mut verifier = ExecutableIdentityVerifier::new();
    verifier.allow_stem("cargo");
    let pe_hash = hex::encode(sha2::Sha256::digest(&malicious_pe));
    verifier.pin_executable_sha256("cargo", &pe_hash);

    let exe_str = test_exe.to_string_lossy().to_string();
    let err = verifier
        .verify_and_lock(&exe_str, None)
        .expect_err("Disguised interpreter with Py_Main MUST be rejected");

    match err {
        OctopusSecurityError::IsolationViolation(msg) => {
            assert!(
                msg.contains("EXEC_ID_RENAMED_INTERPRETER_DETECTED"),
                "Expected EXEC_ID_RENAMED_INTERPRETER_DETECTED, got: {}",
                msg
            );
            assert!(msg.contains("python_core"));
        }
        other => panic!("Expected IsolationViolation, got: {:?}", other),
    }

    let _ = std::fs::remove_file(&test_exe);
}

// =========================================================================
// 3. Fail-Closed AppContainer & Job Object Invariant Tests
// =========================================================================

#[cfg(windows)]
extern "system" {
    fn FreeSid(pSid: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
    fn EqualSid(pSid1: *mut std::ffi::c_void, pSid2: *mut std::ffi::c_void) -> i32;
}

#[cfg(windows)]
#[test]
fn test_challenger_appcontainer_verification_fails_closed_when_process_not_in_job() {
    let job = WindowsJobObject::create("ChallengerTestJobNotInJob", 2, 16 * 1024 * 1024)
        .expect("create WindowsJobObject");

    // Use current process handle - NOT assigned to `job`
    let cur_proc = unsafe { GetCurrentProcess() }.0;

    let (sid_str, psid) = create_or_open_appcontainer_profile(
        "Challenger.Test.Profile1",
        "Challenger Test Profile",
        "Test profile",
    )
    .expect("create AppContainer profile");

    // Verification MUST fail closed because current process is not in `job`
    let err = verify_process_appcontainer_token(cur_proc, psid, &sid_str, &job)
        .expect_err("Must fail closed when process is not in Job Object");

    match err {
        OctopusSecurityError::IsolationViolation(msg) => {
            assert!(
                msg.contains("FAIL-CLOSED: Suspended child verified NOT in Windows Job Object"),
                "Expected NOT in Windows Job Object error, got: {}",
                msg
            );
        }
        other => panic!("Expected IsolationViolation, got: {:?}", other),
    }

    unsafe {
        FreeSid(psid);
    }
}

#[cfg(windows)]
#[test]
fn test_challenger_appcontainer_verification_fails_closed_when_token_is_not_appcontainer() {
    use std::os::windows::io::AsRawHandle;

    let job = WindowsJobObject::create("ChallengerTestJobNonAc", 2, 16 * 1024 * 1024)
        .expect("create WindowsJobObject");

    // Spawn a dedicated child process instead of using GetCurrentProcess() so that when
    // `job` is dropped and closed, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE only reaps the child
    // rather than terminating the test runner process.
    let mut child = std::process::Command::new("cmd.exe")
        .arg("/c")
        .arg("pause")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn child for non-appcontainer token test");

    let child_handle = child.as_raw_handle();

    // Assign child process to job so job check passes
    let _ = job.assign_process(child_handle);

    let (sid_str, psid) = create_or_open_appcontainer_profile(
        "Challenger.Test.Profile2",
        "Challenger Test Profile 2",
        "Test profile",
    )
    .expect("create AppContainer profile");

    // Child process token is a normal user/admin token, NOT an AppContainer token.
    // Therefore, TokenIsAppContainer check MUST fail closed.
    let err = verify_process_appcontainer_token(child_handle, psid, &sid_str, &job)
        .expect_err("Must fail closed because child process token is NOT an AppContainer token");

    match err {
        OctopusSecurityError::IsolationViolation(msg) => {
            assert!(
                msg.contains("TokenIsAppContainer == 0"),
                "Expected TokenIsAppContainer == 0 error, got: {}",
                msg
            );
        }
        other => panic!("Expected IsolationViolation, got: {:?}", other),
    }

    unsafe {
        FreeSid(psid);
    }

    // Cleanly kill and reap child process
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(windows)]
#[test]
fn test_challenger_appcontainer_verification_fails_closed_on_sid_tampering() {
    let (_sid_str1, psid1) = create_or_open_appcontainer_profile(
        "Challenger.Test.ProfileA",
        "Challenger Test Profile A",
        "Test profile",
    )
    .expect("create AppContainer profile A");

    let (_sid_str2, psid2) = create_or_open_appcontainer_profile(
        "Challenger.Test.ProfileB",
        "Challenger Test Profile B",
        "Test profile",
    )
    .expect("create AppContainer profile B");

    // EqualSid directly with psid1 and psid2:
    let equal = unsafe { EqualSid(psid1, psid2) };
    assert_eq!(equal, 0, "Distinct AppContainer SIDs must NOT be equal");

    unsafe {
        FreeSid(psid1);
        FreeSid(psid2);
    }
}

// =========================================================================
// 4. Role & Tool Gating Stress Tests
// =========================================================================

#[test]
fn test_challenger_tiered_dispatcher_role_mismatch_fails_closed() {
    let dispatcher = TieredExecutionDispatcher::try_new().expect("dispatcher init");
    let scratch_dir =
        std::env::temp_dir().join(format!("challenger_scratch_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&scratch_dir);

    // 1. UntrustedDocIngest attempting Tier 2 CLI spawn
    let req_untrusted_doc = TieredToolRequest {
        agent_id: "challenger-agent-1".to_string(),
        role: ArmRole::UntrustedDocIngest,
        tool_name: "doc_extractor".to_string(),
        payload: Vec::new(),
        custom_wat: None,
        native_command: Some((
            "cmd.exe".to_string(),
            vec!["/c".to_string(), "echo".to_string()],
        )),
        scratchpad_root: scratch_dir.clone(),
        allow_scratch_write: false,
    };
    let err1 = dispatcher
        .dispatch(&req_untrusted_doc)
        .expect_err("UntrustedDocIngest must be barred from Tier 2 native execution");
    assert!(format!("{}", err1).contains("TIER2_ROLE_OR_TOOL_MISMATCH"));

    // 2. AccountingLedgerWrite attempting Tier 2 CLI spawn
    let req_ledger = TieredToolRequest {
        agent_id: "challenger-agent-2".to_string(),
        role: ArmRole::AccountingLedgerWrite,
        tool_name: "ledger_writer".to_string(),
        payload: Vec::new(),
        custom_wat: None,
        native_command: Some((
            "cmd.exe".to_string(),
            vec!["/c".to_string(), "echo".to_string()],
        )),
        scratchpad_root: scratch_dir.clone(),
        allow_scratch_write: false,
    };
    let err2 = dispatcher
        .dispatch(&req_ledger)
        .expect_err("AccountingLedgerWrite must be barred from Tier 2 native execution");
    assert!(format!("{}", err2).contains("TIER2_ROLE_OR_TOOL_MISMATCH"));

    // 3. Control character / NUL injection in native_command
    let req_ctrl_char = TieredToolRequest {
        agent_id: "challenger-agent-3".to_string(),
        role: ArmRole::AnomalyDetection,
        tool_name: "probe".to_string(),
        payload: Vec::new(),
        custom_wat: None,
        native_command: Some((
            "cmd.exe".to_string(),
            vec!["/c\x00echo".to_string(), "bad\x07char".to_string()],
        )),
        scratchpad_root: scratch_dir.clone(),
        allow_scratch_write: false,
    };
    let err3 = dispatcher
        .dispatch(&req_ctrl_char)
        .expect_err("Control characters in command must be rejected");
    assert!(format!("{}", err3).contains("program or arguments contain NUL or control characters"));

    let _ = std::fs::remove_dir_all(&scratch_dir);
}
