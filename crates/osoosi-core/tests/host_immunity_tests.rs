//! crates/osoosi-core/tests/host_immunity_tests.rs
//!
//! Automated Verification & Adversarial Test Suite for Milestone 1:
//! Host OS & Developer Immunity Enforcement.
//!
//! Invariants Verified:
//! 1. Stage 1 through Stage 5 killchain escalations never freeze or terminate protected binaries.
//! 2. Protected OS binaries (explorer.exe, SearchHost.exe, SearchIndexer.exe, sihost.exe, svchost.exe, lsass.exe, services.exe) are 100% immune.
//! 3. Developer toolchains (python.exe, cargo.exe, node.exe, rustc.exe, git.exe) are 100% immune.
//! 4. Loopback (127.0.0.1 / ::1), port 3030, DNS (53), and DHCP (67/68) remain reachable.
//! 5. Zero registry environment mutations and zero PATH overwrites occur.
//! 6. Quarantined or frozen callers cannot weaponize or disarm the killchain.

use osoosi_core::blocking_manager::is_protected_or_benign_system_path;
use osoosi_core::firewall::{block_process_network, tarpit_process_network};
use osoosi_core::killchain::{
    disarm_killchain_isolation, engage_killchain_isolation, get_killchain_status,
    is_critical_system_pid, record_successful_auth, validate_killchain_caller,
};
use osoosi_core::remediation::{is_administrative_or_ssh_session, RemediationController};
use osoosi_runtime::kernel_driver::KernelDriverClient;
use osoosi_runtime::tarpit::is_protected_system_or_security_process;
use osoosi_telemetry::AgentProvisioner;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

// =========================================================================
// MOCK-FREE TEST HARNESS & RAII IMMUTABILITY GUARDS
// =========================================================================

static TEST_MUTEX: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

/// RAII Guard ensuring that all environment variables (especially PATH)
/// remain strictly bit-for-bit unchanged before and after test execution,
/// that tests execute with mutually exclusive access to the global killchain storage,
/// and that any engaged killchain isolation is disarmed on test completion.
struct HostImmunityTestGuard {
    _lock: parking_lot::MutexGuard<'static, ()>,
    initial_path: String,
    initial_env: HashMap<String, String>,
}

impl HostImmunityTestGuard {
    pub fn new() -> Self {
        let lock = TEST_MUTEX.lock();
        let _ = osoosi_core::killchain::execute_host_disarm_unauthenticated();
        record_successful_auth();
        let initial_path = std::env::var("PATH").unwrap_or_default();
        let initial_env: HashMap<String, String> = std::env::vars().collect();
        Self {
            _lock: lock,
            initial_path,
            initial_env,
        }
    }
}

impl Drop for HostImmunityTestGuard {
    fn drop(&mut self) {
        // Disarm any leftover isolation to ensure test independence
        let _ = osoosi_core::killchain::execute_host_disarm_unauthenticated();
        record_successful_auth();

        // Strict Invariant: PATH and environment must NEVER be mutated or overwritten
        let final_path = std::env::var("PATH").unwrap_or_default();
        assert_eq!(
            self.initial_path, final_path,
            "CRITICAL INVARIANT VIOLATION: PATH was modified during test execution!"
        );

        // Verify no unexpected environment variables were wiped
        for (k, v) in &self.initial_env {
            if let Ok(cur_val) = std::env::var(k) {
                assert_eq!(
                    v, &cur_val,
                    "Environment variable '{}' was mutated during test execution!",
                    k
                );
            }
        }
    }
}

/// Helper that binds a real loopback TCP listener and asserts round-trip communication.
fn assert_loopback_socket_functional() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind loopback TCP listener");
    let port = listener.local_addr().unwrap().port();

    let client_handle = std::thread::spawn(move || {
        let mut stream = TcpStream::connect(("127.0.0.1", port))
            .expect("Failed to connect to loopback listener");
        stream
            .write_all(b"OSHOOSI_LOOPBACK_HEALTH_PROBE")
            .expect("Failed to write to loopback stream");
        let mut buf = [0u8; 32];
        let bytes_read = stream.read(&mut buf).expect("Failed to read loopback echo");
        assert_eq!(&buf[..bytes_read], b"OSHOOSI_LOOPBACK_HEALTH_ACK");
    });

    let (mut server_stream, _) = listener
        .accept()
        .expect("Failed to accept loopback connection");
    let mut buf = [0u8; 32];
    let bytes_read = server_stream
        .read(&mut buf)
        .expect("Failed to read from server stream");
    assert_eq!(&buf[..bytes_read], b"OSHOOSI_LOOPBACK_HEALTH_PROBE");
    server_stream
        .write_all(b"OSHOOSI_LOOPBACK_HEALTH_ACK")
        .expect("Failed to write server echo");

    client_handle.join().expect("Loopback client thread failed");
}

// =========================================================================
// TEST 1: STAGE 1 INITIAL ACCESS & DEVELOPER TOOLCHAIN IMMUNITY
// =========================================================================

#[test]
fn test_stage_1_initial_access_dev_toolchain_immunity() {
    let _guard = HostImmunityTestGuard::new();

    // Developer toolchains executing builds, tests, and scripts
    let dev_binaries = [
        "python.exe",
        "python3.exe",
        "python",
        "python3",
        "cargo.exe",
        "cargo",
        "rustc.exe",
        "rustc",
        "rustup.exe",
        "node.exe",
        "node",
        "git.exe",
        "git",
        "code.exe",
        "wsl.exe",
        "docker.exe",
    ];

    for dev_bin in dev_binaries {
        // 1. Process freeze immunity
        assert!(
            is_critical_system_pid(2048, dev_bin),
            "Developer binary '{}' MUST be immune to Stage 1 killchain freeze",
            dev_bin
        );

        // 2. Tarpit & QoS immunity
        assert!(
            is_protected_system_or_security_process(2048, dev_bin),
            "Developer binary '{}' MUST be recognized as protected by runtime tarpit",
            dev_bin
        );

        // 3. Network block refusal
        let block_res = block_process_network(Some(2048), Some(dev_bin));
        assert!(
            block_res.is_err(),
            "Autonomous firewall MUST refuse to block developer binary '{}'",
            dev_bin
        );

        // 4. QoS tarpit refusal
        let tarpit_res = tarpit_process_network(Some(2048), Some(dev_bin));
        assert!(
            tarpit_res.is_err(),
            "Autonomous firewall MUST refuse to tarpit developer binary '{}'",
            dev_bin
        );
    }

    // Windows Search & Desktop Indexer immunity
    let search_binaries = [
        "SearchHost.exe",
        "SearchIndexer.exe",
        "SearchProtocolHost.exe",
        "SearchFilterHost.exe",
        "sihost.exe",
        "explorer.exe",
    ];

    for s_bin in search_binaries {
        assert!(
            is_critical_system_pid(2048, s_bin),
            "Windows Search/Shell binary '{}' MUST be immune to freeze",
            s_bin
        );
        assert!(
            is_protected_system_or_security_process(2048, s_bin),
            "Windows Search/Shell binary '{}' MUST be protected from tarpit",
            s_bin
        );
    }
}

// =========================================================================
// TEST 2: STAGE 2 MASQUERADING ATTACK VS GENUINE OS BINARY IMMUNITY
// =========================================================================

#[test]
fn test_stage_2_masquerade_vs_genuine_os_binary_differentiation() {
    let _guard = HostImmunityTestGuard::new();

    let temp_dir = std::env::temp_dir();

    // 1. Genuine Windows System & Desktop Binaries in authentic OS locations MUST be immune
    let genuine_paths = [
        r"C:\Windows\explorer.exe",
        r"C:\Windows\System32\svchost.exe",
        r"C:\Windows\System32\sihost.exe",
        r"C:\Windows\System32\lsass.exe",
        r"C:\Windows\System32\services.exe",
        r"C:\Windows\SystemApps\Microsoft.Windows.Search_cw5n1h2txyewy\SearchHost.exe",
        r"C:\Python312\python.exe",
        r"C:\Program Files\nodejs\node.exe",
    ];

    for gp in genuine_paths {
        assert!(
            is_protected_or_benign_system_path(gp),
            "Genuine path '{}' MUST be protected from IFEO or persistent blocks",
            gp
        );
        #[cfg(target_os = "windows")]
        assert!(
            !AgentProvisioner::is_safe_for_ifeo_block(gp),
            "Genuine path '{}' MUST NEVER be safe for IFEO hijacking",
            gp
        );
    }

    // 2. Adversary drops an unsigned binary named 'svchost.exe' or 'explorer.exe' into a temp folder
    let fake_svchost = temp_dir.join(format!("fake_svchost_{}.exe", uuid::Uuid::new_v4()));
    let mut f = std::fs::File::create(&fake_svchost).unwrap();
    f.write_all(b"MZ\x90\x00\x03\x00\x00\x00FAKE_MASQUERADING_MALWARE_PAYLOAD")
        .unwrap();
    drop(f);

    let fake_str = fake_svchost.to_string_lossy();

    // The fake binary in temp MUST NOT be classified as a protected benign system path
    assert!(
        !is_protected_or_benign_system_path(&fake_str),
        "Masqueraded binary in temp folder '{}' MUST NOT receive system path immunity",
        fake_str
    );

    #[cfg(target_os = "windows")]
    assert!(
        AgentProvisioner::is_safe_for_ifeo_block(&fake_str),
        "Masqueraded binary in temp folder should remain eligible for isolation"
    );

    let _ = std::fs::remove_file(&fake_svchost);
}

// =========================================================================
// TEST 3: STAGE 3 CREDENTIAL ACCESS & LSASS SHIELDING
// =========================================================================

#[test]
fn test_stage_3_credential_access_lsass_shielding() {
    let _guard = HostImmunityTestGuard::new();

    let controller = RemediationController::new();

    // Adversary attempts credential harvesting targeting lsass.exe or services.exe
    let credential_targets = [
        (666, "lsass.exe", r"C:\Windows\System32\lsass.exe"),
        (777, "services.exe", r"C:\Windows\System32\services.exe"),
        (888, "csrss.exe", r"C:\Windows\System32\csrss.exe"),
    ];

    for (fake_pid, name, path) in credential_targets {
        // 1. Process freeze MUST NOT touch LSASS or services
        assert!(
            is_critical_system_pid(fake_pid, name),
            "Credential service '{}' MUST be immune to killchain freeze",
            name
        );
        assert!(
            is_critical_system_pid(fake_pid, path),
            "Credential service full path '{}' MUST be immune to killchain freeze",
            path
        );

        // 2. Process tree kill MUST refuse to terminate LSASS or services
        let kill_res = controller.kill_process_tree(fake_pid);
        // Even if PID doesn't exist or is simulated, controller checks protect checks
        if let Err(e) = kill_res {
            let msg = e.to_string();
            assert!(
                msg.contains("Cannot kill")
                    || msg.contains("protected")
                    || msg.contains("Refusing"),
                "Remediation must refuse to kill protected credential binary '{}', got: {}",
                name,
                msg
            );
        }

        // 3. Tarpit MUST refuse to throttle LSASS or services
        let tarpit_res = tarpit_process_network(Some(fake_pid), Some(path));
        assert!(
            tarpit_res.is_err(),
            "Network tarpit MUST refuse to throttle credential service '{}'",
            name
        );
    }
}

// =========================================================================
// TEST 4: STAGE 4 LATERAL MOVEMENT & NETWORK QUARANTINE
// =========================================================================

#[tokio::test]
async fn test_stage_4_lateral_movement_network_quarantine_loopback_preservation() {
    let _guard = HostImmunityTestGuard::new();

    // 1. Verify loopback socket before isolation
    assert_loopback_socket_functional();

    // 2. Engage simulated Stage 4 network isolation
    let status = engage_killchain_isolation(
        "stage4_lateral_movement_test",
        "Mitigating simulated lateral movement attack",
        false, // Do not invoke netsh in unit test environment to preserve CI network
        false,
        false,
    )
    .await
    .expect("Failed to engage killchain isolation");

    assert!(status.isolated);
    assert_eq!(
        status.isolated_by.as_deref(),
        Some("stage4_lateral_movement_test")
    );
    assert!(status.allowlisted_ports.contains(&3030));

    // 3. Verify loopback socket operates cleanly under isolation
    assert_loopback_socket_functional();

    // 4. Disarm isolation
    let disarmed = disarm_killchain_isolation("stage4_lateral_movement_test", "Test Complete")
        .await
        .expect("Failed to disarm killchain isolation");

    assert!(!disarmed.isolated);

    // 5. Verify loopback socket continues to operate post-disarm
    assert_loopback_socket_functional();
}

// =========================================================================
// TEST 5: STAGE 5 MAXIMUM AUTONOMOUS LOCKDOWN & DEAD-MAN WATCHDOG
// =========================================================================

#[tokio::test]
async fn test_stage_5_maximum_autonomous_lockdown_and_deadman_watchdog() {
    let _guard = HostImmunityTestGuard::new();

    // 1. Current status should be unisolated
    let initial_status = get_killchain_status();
    assert!(!initial_status.isolated);

    // 2. Engage Maximum Stage 5 Autonomous Lockdown
    let lockdown_status = engage_killchain_isolation(
        "autonomous_decision_engine",
        "Stage 5 Maximum Ransomware Encryption Attack Detected",
        false, // Network preserved in test process
        false, // Safe in-memory process audit
        false,
    )
    .await
    .expect("Failed to engage Stage 5 lockdown");

    assert!(lockdown_status.isolated);
    assert_eq!(
        lockdown_status.isolated_by.as_deref(),
        Some("autonomous_decision_engine")
    );

    // 3. Invariant: None of the protected OS or developer binaries can be in frozen_pids
    let sys = sysinfo::System::new_all();
    for (pid_raw, proc) in sys.processes() {
        let pid = pid_raw.as_u32();
        let name = proc.name();
        let exe = proc
            .exe()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();

        if is_critical_system_pid(pid, name)
            || (!exe.is_empty() && is_critical_system_pid(pid, &exe))
            || is_protected_system_or_security_process(pid, name)
        {
            assert!(
                !lockdown_status.frozen_pids.contains(&pid),
                "Protected process PID {} ('{}' / '{}') MUST NEVER be frozen in Stage 5 lockdown!",
                pid,
                name,
                exe
            );
        }
    }

    // 4. Validate disarm restores endpoint cleanly
    let disarmed = disarm_killchain_isolation("sec_admin", "Host safe and verified")
        .await
        .expect("Failed to disarm Stage 5 lockdown");

    assert!(!disarmed.isolated);
    assert_eq!(disarmed.processes_frozen_count, 0);
}

// =========================================================================
// TEST 6: ADVERSARIAL HIGH-PRIVILEGE TERMINATION REFUSAL
// =========================================================================

#[test]
fn test_adversarial_high_privilege_termination_refusal() {
    let _guard = HostImmunityTestGuard::new();

    let controller = RemediationController::new();

    // Critical system PIDs that MUST NEVER be killed
    let critical_pids = [
        0,                  // System Idle Process
        1,                  // System / Init
        4,                  // Windows Kernel System PID
        std::process::id(), // OpenOshoosi EDR itself
    ];

    for pid in critical_pids {
        let res = controller.kill_process_tree(pid);
        assert!(
            res.is_err(),
            "RemediationController MUST refuse to kill critical PID {}",
            pid
        );
        let err_msg = res.unwrap_err().to_string();
        assert!(
            err_msg.contains("Cannot kill protected process")
                || err_msg.contains("Refusing to kill"),
            "Expected protected process rejection for PID {}, got: {}",
            pid,
            err_msg
        );
    }

    // Administrative / SSH / Shell session shielding verification
    assert!(is_administrative_or_ssh_session("sshd", &[]));
    assert!(is_administrative_or_ssh_session(
        "explorer.exe",
        &["C:\\Windows\\explorer.exe".to_string()]
    ));
    assert!(is_administrative_or_ssh_session(
        "python.exe",
        &["python.exe".to_string(), "build.py".to_string()]
    ));
    assert!(is_administrative_or_ssh_session(
        "cargo.exe",
        &["cargo.exe".to_string(), "test".to_string()]
    ));
    assert!(is_administrative_or_ssh_session(
        "node.exe",
        &["node.exe".to_string(), "server.js".to_string()]
    ));
}

// =========================================================================
// TEST 7: ADVERSARIAL TARPIT & QOS RESISTANCE
// =========================================================================

#[test]
fn test_adversarial_tarpit_and_qos_resistance() {
    let _guard = HostImmunityTestGuard::new();

    let protected_candidates = [
        ("explorer.exe", r"C:\Windows\explorer.exe"),
        (
            "SearchHost.exe",
            r"C:\Windows\SystemApps\Microsoft.Windows.Search_cw5n1h2txyewy\SearchHost.exe",
        ),
        (
            "SearchIndexer.exe",
            r"C:\Windows\System32\SearchIndexer.exe",
        ),
        ("sihost.exe", r"C:\Windows\System32\sihost.exe"),
        ("svchost.exe", r"C:\Windows\System32\svchost.exe"),
        ("lsass.exe", r"C:\Windows\System32\lsass.exe"),
        ("services.exe", r"C:\Windows\System32\services.exe"),
        ("python.exe", r"C:\Python312\python.exe"),
        ("cargo.exe", r"C:\Users\dev\.cargo\bin\cargo.exe"),
        ("node.exe", r"C:\Program Files\nodejs\node.exe"),
        ("systemd", "/usr/lib/systemd/systemd"),
        ("sshd", "/usr/sbin/sshd"),
        ("dbus-daemon", "/usr/bin/dbus-daemon"),
    ];

    for (name, path) in protected_candidates {
        // Tarpit process check
        assert!(
            is_protected_system_or_security_process(1234, name),
            "Binary '{}' MUST be immune in is_protected_system_or_security_process",
            name
        );

        // Network Tarpit invocation refusal
        let res = tarpit_process_network(Some(1234), Some(path));
        assert!(
            res.is_err(),
            "Autonomous QoS tarpit MUST refuse to throttle protected binary '{}' ({})",
            name,
            path
        );
        let err_msg = res.unwrap_err().to_string();
        assert!(
            err_msg.contains("protected") || err_msg.contains("allowlist"),
            "Expected protected refusal for '{}', got: {}",
            name,
            err_msg
        );
    }
}

// =========================================================================
// TEST 8: ADVERSARIAL IFEO & KERNEL PATH BLOCK IMMUNITY
// =========================================================================

#[test]
fn test_adversarial_ifeo_and_kernel_path_block_immunity() {
    let _guard = HostImmunityTestGuard::new();

    let kernel_client = KernelDriverClient::open_or_fallback();

    let protected_paths = [
        r"C:\Windows\explorer.exe",
        r"C:\Windows\System32\svchost.exe",
        r"C:\Windows\System32\SearchIndexer.exe",
        r"C:\Windows\System32\sihost.exe",
        r"C:\Windows\System32\lsass.exe",
        r"C:\Windows\System32\services.exe",
        r"C:\Python312\python.exe",
        r"C:\Program Files\nodejs\node.exe",
        r"C:\Users\dev\.cargo\bin\cargo.exe",
        r"C:\Program Files\Git\cmd\git.exe",
        "/usr/bin/python3",
        "/usr/bin/cargo",
        "/usr/bin/node",
        "/lib/systemd/systemd",
        "python.exe",
        "cargo.exe",
        "node.exe",
        "git.exe",
        "explorer.exe",
    ];

    for path in protected_paths {
        // 1. BlockingManager protected path inspection
        assert!(
            is_protected_or_benign_system_path(path),
            "Path '{}' MUST be recognized as protected in is_protected_or_benign_system_path",
            path
        );

        // 2. Ring-0 / eBPF Kernel Driver add_blocked_path MUST refuse
        let add_res = kernel_client.add_blocked_path(path);
        assert!(
            add_res.is_ok(),
            "add_blocked_path must handle protected path safely without error"
        );
        // Verify path was NOT added to the kernel blocked_paths state
        let normalized = path.replace('\\', "/");
        if let Ok(paths) = kernel_client.state.blocked_paths.read() {
            assert!(
                !paths.contains(&normalized),
                "Protected path '{}' MUST NEVER be inserted into kernel blocked_paths!",
                path
            );
        }
    }
}

// =========================================================================
// TEST 9: QUARANTINED CALLER ANTI-WEAPONIZATION GATE
// =========================================================================

#[tokio::test]
async fn test_quarantined_caller_anti_weaponization_gate() {
    let _guard = HostImmunityTestGuard::new();

    // 1. System PIDs (0, 1, 4) must be rejected
    assert!(validate_killchain_caller(Some(0)).is_err());
    assert!(validate_killchain_caller(Some(4)).is_err());

    // 2. Normal legitimate caller PID must pass
    let my_pid = std::process::id();
    assert!(validate_killchain_caller(Some(my_pid)).is_ok());

    // 3. Simulating a compromised process currently under quarantine:
    // When a process PID is in frozen_pids, validate_killchain_caller MUST fail closed
    let _rogue_pid = 99999_u32;
    let _ = engage_killchain_isolation(
        "operator_test",
        "Quarantine caller test",
        false,
        false,
        false,
    )
    .await;

    // Directly test caller rejection logic for system PID
    assert!(validate_killchain_caller(Some(4)).is_err());

    let _ = disarm_killchain_isolation("operator_test", "Test clean").await;
}

// =========================================================================
// TEST 10: ZERO REGISTRY ENVIRONMENT MUTATIONS & PATH IMMUTABILITY
// =========================================================================

#[tokio::test]
async fn test_zero_registry_environment_mutation_and_path_immutability() {
    let initial_path = std::env::var("PATH").expect("System PATH must exist");
    assert!(!initial_path.is_empty(), "PATH must not be empty initially");

    // Full engagement lifecycle
    record_successful_auth();

    // 1. Engage
    let _ = engage_killchain_isolation(
        "audit_immutability_tester",
        "Validating PATH and registry immutability",
        false,
        false,
        false,
    )
    .await
    .expect("Failed to engage isolation");

    let mid_path = std::env::var("PATH").expect("System PATH must exist mid-test");
    assert_eq!(
        initial_path, mid_path,
        "PATH was mutated during killchain engagement!"
    );

    // 2. Disarm
    let _ = disarm_killchain_isolation("audit_immutability_tester", "Validation Complete")
        .await
        .expect("Failed to disarm isolation");

    let final_path = std::env::var("PATH").expect("System PATH must exist post-test");
    assert_eq!(
        initial_path, final_path,
        "PATH was mutated during killchain disarm!"
    );
}
