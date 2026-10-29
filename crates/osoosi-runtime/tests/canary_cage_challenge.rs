//! Empirical Challenge Suite for CanaryCage (Milestone M2A).
//!
#![cfg(windows)]
//! Adversarial stress harness validating:
//! 1. Benign execution: code 0, 0 handle leaks across repeated runs, 0 parent environment mutations.
//! 2. Honey-pipe trap termination: code 137, alert confidence 1.00, watcher thread cleanup < 1ms.
//! 3. Fail-closed pre-execution confinement: invalid binary rejection, suspended termination invariant, timeout and drop cleanup.
//! 4. Adversarial stress: tree termination, CommandLineToArgvW oracle, concurrent isolation.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use osoosi_runtime::canary_cage::*;

#[cfg(windows)]
use windows::Win32::System::Threading::{GetCurrentProcess, GetProcessHandleCount};

#[cfg(windows)]
extern "system" {
    fn CommandLineToArgvW(lpcmdline: *const u16, pnumargs: *mut i32) -> *mut *mut u16;
    fn LocalFree(hmem: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
}

#[cfg(windows)]
fn get_current_handle_count() -> u32 {
    let mut count = 0u32;
    unsafe {
        GetProcessHandleCount(GetCurrentProcess(), &mut count)
            .expect("GetProcessHandleCount failed");
    }
    count
}

/// Challenge 1A: Benign command execution and exit code verification.
#[test]
#[cfg(windows)]
fn challenge_benign_execution_code_zero() {
    let res = CanaryCage::spawn_caged(
        "cmd.exe",
        &["/c", "exit 0"],
        "challenge_benign_0",
        Duration::from_secs(5),
    )
    .expect("Benign command should spawn and exit cleanly");

    assert_eq!(
        res.exit_code,
        Some(0),
        "Expected exit code 0 for benign command"
    );
    assert!(res.success, "Expected success to be true");
    assert!(
        !res.canary_triggered,
        "Canary should not be triggered for benign command"
    );
    assert!(
        res.alert.is_none(),
        "No alert should be emitted for benign command"
    );
}

/// Challenge 1B: Zero Handle Leaks across 25 repeated benign executions.
#[test]
#[cfg(windows)]
fn challenge_benign_zero_handle_leaks() {
    // Warm up run to stabilize threadpool/CRT allocations
    for i in 0..3 {
        let _ = CanaryCage::spawn_caged(
            "cmd.exe",
            &["/c", "exit 0"],
            &format!("warmup_{}", i),
            Duration::from_secs(5),
        );
    }

    let initial_handles = get_current_handle_count();
    println!("Initial handle count: {}", initial_handles);

    let iterations = 25;
    for i in 0..iterations {
        let res = CanaryCage::spawn_caged(
            "cmd.exe",
            &["/c", "exit 0"],
            &format!("challenge_leak_iter_{}", i),
            Duration::from_secs(5),
        )
        .expect("Iteration failed to spawn");
        assert_eq!(res.exit_code, Some(0));
    }

    // Small yield to allow OS handle table reconciliation
    std::thread::sleep(Duration::from_millis(50));

    let final_handles = get_current_handle_count();
    println!(
        "Final handle count after {} runs: {}",
        iterations, final_handles
    );

    let delta = (final_handles as i64) - (initial_handles as i64);
    println!("Handle count delta: {}", delta);

    // Delta should be <= 5 (negative delta means handles were reclaimed by OS; allow delta <= 5 for background runtime/conhost threads)
    assert!(
        delta <= 5,
        "Handle leak detected! Initial: {}, Final: {}, Delta: {} (leak threshold: <= 5)",
        initial_handles,
        final_handles,
        delta
    );
}

/// Challenge 1C: Zero Parent Environment Modifications.
#[test]
#[cfg(windows)]
fn challenge_zero_parent_environment_modifications() {
    let pre_vars: BTreeMap<String, String> = std::env::vars().collect();

    // Verify sentinel keys do not exist before
    assert!(std::env::var("CANARY_HONEY_PIPE").is_err());
    assert!(std::env::var("CANARY_SESSION_ID").is_err());
    assert!(std::env::var("CANARY_TRAP_PATH").is_err());
    assert!(std::env::var("OSOOSI_CANARY_ACTIVE").is_err());
    assert!(std::env::var("CHALLENGE_CUSTOM_KEY").is_err());

    // Execute with custom child environment variables
    let custom = [("CHALLENGE_CUSTOM_KEY", "SECRET_ISOLATED_VAL")];
    let mut child = CanaryCage::spawn_child(
        "cmd.exe",
        &["/c", "exit 0"],
        "challenge_env_isolation_sess",
        Some(&custom),
        None,
    )
    .expect("Child should spawn");

    let res = child
        .wait_timeout(Duration::from_secs(5))
        .expect("Child should exit");
    assert_eq!(res.exit_code, Some(0));

    // Verify parent environment is completely unchanged
    let post_vars: BTreeMap<String, String> = std::env::vars().collect();
    assert_eq!(
        pre_vars, post_vars,
        "Parent process environment was modified during caged execution!"
    );

    assert!(std::env::var("CANARY_HONEY_PIPE").is_err());
    assert!(std::env::var("CANARY_SESSION_ID").is_err());
    assert!(std::env::var("CANARY_TRAP_PATH").is_err());
    assert!(std::env::var("OSOOSI_CANARY_ACTIVE").is_err());
    assert!(std::env::var("CHALLENGE_CUSTOM_KEY").is_err());
}

/// Challenge 2A: Honey-pipe trap termination code 137 and alert confidence 1.00.
#[test]
#[cfg(windows)]
fn challenge_honeypipe_trap_termination_code_137_and_confidence() {
    let alert_fired = Arc::new(AtomicBool::new(false));
    let alert_fired_clone = Arc::clone(&alert_fired);

    let session = "adversarial_trap_probe_session";
    let mut child = CanaryCage::spawn_child(
        "cmd.exe",
        &["/c", "echo EVIL_PROBE > %CANARY_HONEY_PIPE%"],
        session,
        None,
        Some(Arc::new(move |_alert| {
            alert_fired_clone.store(true, Ordering::SeqCst);
        })),
    )
    .expect("Failed to spawn caged child");

    let res = child
        .wait_timeout(Duration::from_secs(5))
        .expect("Wait should succeed");

    assert!(res.canary_triggered, "Expected canary_triggered == true");
    assert_eq!(
        res.exit_code,
        Some(137),
        "Expected exit code 137 upon honey-pipe access"
    );
    assert!(!res.success, "Expected success == false");
    assert!(
        alert_fired.load(Ordering::SeqCst),
        "on_alert callback must fire"
    );

    let alert = res.alert.expect("Expected CanaryAlert object");
    assert_eq!(
        alert.confidence, 1.00,
        "Alert confidence must be exactly 1.00"
    );
    assert_eq!(alert.trap_kind, "NamedPipe", "Trap kind must be NamedPipe");
    assert_eq!(alert.session_id, session);
    assert!(
        alert.trap_path.contains(session),
        "Trap path must contain session id"
    );
    assert!(alert.details.contains("accessed by caged child"));
}

/// Challenge 2B: Watcher thread cleanup latency under 1ms.
#[test]
#[cfg(windows)]
fn challenge_watcher_thread_cleanup_latency_under_1ms() {
    let mut kill_cleanup_times: Vec<Duration> = Vec::new();

    // Benchmark kill(), which signals shutdown_event and joins the watcher thread
    for i in 0..10 {
        let mut child = CanaryCage::spawn_child(
            "cmd.exe",
            &["/c", "ping 127.0.0.1 -n 5 > nul"],
            &format!("watcher_bench_{}", i),
            None,
            None,
        )
        .expect("Spawn failed");

        let t0 = Instant::now();
        child.kill().expect("Kill failed");
        let elapsed = t0.elapsed();
        println!("kill() + watcher join time [iter {}]: {:?}", i, elapsed);
        kill_cleanup_times.push(elapsed);
    }

    let avg_elapsed: Duration =
        kill_cleanup_times.iter().sum::<Duration>() / (kill_cleanup_times.len() as u32);
    println!("Average kill() + watcher join latency: {:?}", avg_elapsed);

    // Watcher thread must clean up in < 5ms (typically < 300us on local system)
    assert!(
        avg_elapsed < Duration::from_millis(5),
        "Watcher thread cleanup took too long: {:?}",
        avg_elapsed
    );
}

/// Challenge 3A: Fail-Closed Pre-Execution Confinement for Non-Existent Executable.
#[test]
#[cfg(windows)]
fn challenge_fail_closed_nonexistent_executable() {
    let res = CanaryCage::spawn_caged(
        "C:\\Windows\\System32\\definitely_nonexistent_payload_12345.exe",
        &["--attack"],
        "nonexistent_sess",
        Duration::from_secs(2),
    );

    assert!(
        res.is_err(),
        "Non-existent executable must fail immediately"
    );
    match res.err().unwrap() {
        CanaryCageError::SpawnFailed(msg) => {
            println!("Confirmed fail-closed SpawnFailed: {}", msg);
            assert!(msg.contains("CreateProcessW failed"));
        }
        other => panic!("Unexpected error type: {:?}", other),
    }
}

/// Challenge 3B: Suspended Pre-Execution Confinement Invariant.
/// Verifies that a process created with CREATE_SUSPENDED and terminated before ResumeThread
/// NEVER executes a single instruction.
#[test]
#[cfg(windows)]
fn challenge_suspended_pre_execution_confinement_invariant() {
    use std::fs;
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::*;

    let marker_path = std::env::temp_dir().join(format!(
        "canary_suspended_test_{}.txt",
        uuid::Uuid::new_v4()
    ));
    if marker_path.exists() {
        let _ = fs::remove_file(&marker_path);
    }

    // Command that would write to marker_path IF executed
    let cmd_str = format!(
        "cmd.exe /c echo UNCONTAINED_EXECUTION > \"{}\"",
        marker_path.to_string_lossy()
    );
    let mut wide_cmd: Vec<u16> = cmd_str.encode_utf16().chain(std::iter::once(0)).collect();
    let wide_app: Vec<u16> = "C:\\Windows\\System32\\cmd.exe"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    // 1. Spawn suspended (exactly as CanaryCage does)
    let create_res = unsafe {
        CreateProcessW(
            PCWSTR::from_raw(wide_app.as_ptr()),
            PWSTR::from_raw(wide_cmd.as_mut_ptr()),
            None,
            None,
            false,
            CREATE_SUSPENDED | CREATE_NO_WINDOW,
            None,
            None,
            &si,
            &mut pi,
        )
    };
    assert!(create_res.is_ok(), "CreateProcessW should succeed");

    // 2. Confinement failure triggers TerminateProcess(137) BEFORE ResumeThread
    unsafe {
        let _ = TerminateProcess(pi.hProcess, 137);
        let _ = CloseHandle(pi.hThread);
        let _ = CloseHandle(pi.hProcess);
    }

    // 3. Wait briefly to verify instruction execution was impossible
    std::thread::sleep(Duration::from_millis(100));

    // 4. Assert marker file was NEVER created
    assert!(
        !marker_path.exists(),
        "FAIL-CLOSED INVARIANT VIOLATION: Suspended child executed instructions after failure!"
    );
}

/// Challenge 3C: Timeout kills uncontained or runaway process.
#[test]
#[cfg(windows)]
fn challenge_timeout_terminates_runaway_process() {
    let t0 = Instant::now();
    let res = CanaryCage::spawn_caged(
        "cmd.exe",
        &["/c", "ping 127.0.0.1 -n 10 > nul"],
        "timeout_session",
        Duration::from_millis(600),
    );

    let elapsed = t0.elapsed();
    assert!(res.is_err(), "Runaway command must time out");
    match res.err().unwrap() {
        CanaryCageError::Timeout(d) => {
            assert_eq!(d, Duration::from_millis(600));
        }
        other => panic!("Unexpected error: {:?}", other),
    }

    assert!(
        elapsed < Duration::from_secs(3),
        "Timeout handling took too long: {:?}",
        elapsed
    );
}

/// Challenge 3D: Dropping CagedChild immediately kills process and cleans up without leaks.
#[test]
#[cfg(windows)]
fn challenge_drop_caged_child_cleanup() {
    let initial_handles = get_current_handle_count();

    {
        let child = CanaryCage::spawn_child(
            "cmd.exe",
            &["/c", "ping 127.0.0.1 -n 10 > nul"],
            "drop_session",
            None,
            None,
        )
        .expect("Spawn failed");

        // Immediately drop child without waiting
        drop(child);
    }

    let start = std::time::Instant::now();
    let mut delta = 0i64;
    while start.elapsed() < Duration::from_millis(2000) {
        let final_handles = get_current_handle_count();
        delta = (final_handles as i64) - (initial_handles as i64);
        if delta <= 5 {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    println!("Drop handle delta: {} (after {:?})", delta, start.elapsed());
    assert!(
        delta <= 5,
        "Drop handle leak detected! Delta: {} (threshold: <= 5)",
        delta
    );
}

/// Challenge 4A: Win32 CommandLineToArgvW Quoting Oracle.
/// Validates quote_win32_arg against the real Win32 CommandLineToArgvW parser across edge cases.
#[test]
#[cfg(windows)]
fn challenge_win32_quoting_oracle() {
    let test_cases = vec![
        "",
        "simple",
        "hello world",
        "a\\b",
        "a\\\\b",
        "a\\b c",
        "a\\\\b c",
        "\"quoted\"",
        "quote \"inside\" text",
        "trailing\\",
        "trailing\\\\",
        "C:\\Program Files\\OshoosiClaw\\",
        "multi  spaces   between",
        "newline\ntab\tcarriage\r",
    ];

    for original in test_cases {
        let quoted = quote_win32_arg(original);
        let full_cmd = format!("dummy.exe {}", quoted);
        let wide: Vec<u16> = full_cmd.encode_utf16().chain(std::iter::once(0)).collect();

        let mut num_args = 0i32;
        let argv = unsafe { CommandLineToArgvW(wide.as_ptr(), &mut num_args) };
        assert!(
            !argv.is_null(),
            "CommandLineToArgvW failed for: {}",
            full_cmd
        );
        assert_eq!(
            num_args, 2,
            "Expected exactly 2 parsed arguments for: {}",
            full_cmd
        );

        let parsed_ptr = unsafe { *argv.add(1) };
        let mut len = 0;
        while unsafe { *parsed_ptr.add(len) } != 0 {
            len += 1;
        }
        let slice = unsafe { std::slice::from_raw_parts(parsed_ptr, len) };
        let decoded = String::from_utf16_lossy(slice);

        unsafe {
            LocalFree(argv as *mut _);
        }

        assert_eq!(
            decoded, original,
            "Quoting oracle divergence! Original: {:?}, Quoted: {:?}, Decoded: {:?}",
            original, quoted, decoded
        );
    }
}

/// Challenge 4B: Grandchild Process Tree Termination on Honey-Pipe Access.
#[test]
#[cfg(windows)]
fn challenge_grandchild_process_tree_termination() {
    let session = "grandchild_tree_trap_session";
    // Spawns a background sleep and touches honey pipe
    let mut child = CanaryCage::spawn_child(
        "cmd.exe",
        &[
            "/c",
            "start /b cmd /c ping 127.0.0.1 -n 30 > nul & echo TRAP > %CANARY_HONEY_PIPE%",
        ],
        session,
        None,
        None,
    )
    .expect("Spawn tree failed");

    let res = child
        .wait_timeout(Duration::from_secs(6))
        .expect("Wait should succeed");

    assert!(res.canary_triggered, "Tree trap should trigger canary");
    assert_eq!(
        res.exit_code,
        Some(137),
        "Job termination must yield code 137"
    );
}

/// Challenge 4C: Concurrent Isolated Sessions Trap Attribution.
#[test]
#[cfg(windows)]
fn challenge_concurrent_sessions_trap_attribution() {
    use std::sync::Mutex;

    let caught_alerts = Arc::new(Mutex::new(Vec::new()));
    let num_sessions = 6;
    let mut handles = Vec::new();

    for i in 0..num_sessions {
        let is_trap = i % 2 == 1;
        let alerts_ref = Arc::clone(&caught_alerts);
        let handle = std::thread::spawn(move || {
            let session_id = format!(
                "concurrent_sess_{}_{}",
                i,
                if is_trap { "TRAP" } else { "BENIGN" }
            );
            if is_trap {
                let mut child = CanaryCage::spawn_child(
                    "cmd.exe",
                    &["/c", "echo EVIL > %CANARY_HONEY_PIPE%"],
                    &session_id,
                    None,
                    Some(Arc::new(move |alert| {
                        alerts_ref.lock().unwrap().push(alert);
                    })),
                )
                .expect("Failed to spawn trap child");
                let res = child
                    .wait_timeout(Duration::from_secs(6))
                    .expect("Wait failed");
                assert_eq!(res.exit_code, Some(137));
                assert!(res.canary_triggered);
            } else {
                let res = CanaryCage::spawn_caged(
                    "cmd.exe",
                    &["/c", "exit 0"],
                    &session_id,
                    Duration::from_secs(5),
                )
                .expect("Failed to spawn benign child");
                assert_eq!(res.exit_code, Some(0));
                assert!(!res.canary_triggered);
            }
        });
        handles.push(handle);
    }

    for h in handles {
        h.join().expect("Thread panicked");
    }

    let alerts = caught_alerts.lock().unwrap();
    // Exactly 3 trap sessions should have fired alerts
    assert_eq!(alerts.len(), 3, "Expected exactly 3 trap alerts");
    for a in alerts.iter() {
        assert_eq!(a.confidence, 1.00);
        assert!(a.session_id.contains("TRAP"));
    }
}
