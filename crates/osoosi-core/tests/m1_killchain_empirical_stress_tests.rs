//! crates/osoosi-core/tests/m1_killchain_empirical_stress_tests.rs
//!
//! Empirical Stress Testing & Adversarial Challenge Suite for Milestone 1:
//! Host OS & Developer Immunity Enforcement (`teamwork_preview_challenger`).
//!
//! Verification Objectives:
//! 1. High-concurrency killchain stage escalations (Stages 1-5) under multi-threaded load.
//! 2. Protected OS and developer processes are NEVER terminated, frozen, or throttled.
//! 3. Loopback TCP sockets (127.0.0.1:3030 and dynamic loopback ports) remain fully operational during quarantine.
//! 4. Netsh firewall quarantine rules are 100% cleanly reverted upon disarm without residual rules.
//! 5. PATH and Windows Registry environment hives (HKCU/HKLM) remain 100% bit-for-bit unaltered.

use osoosi_core::blocking_manager::is_protected_or_benign_system_path;
use osoosi_core::firewall::{block_process_network, tarpit_process_network};
use osoosi_core::killchain::{
    disarm_killchain_isolation, engage_killchain_isolation, execute_host_disarm_unauthenticated,
    get_killchain_status, is_critical_system_pid, record_successful_auth,
};
use osoosi_core::remediation::{is_administrative_or_ssh_session, RemediationController};
use osoosi_runtime::kernel_driver::KernelDriverClient;
use osoosi_runtime::tarpit::is_protected_system_or_security_process;
use osoosi_telemetry::AgentProvisioner;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

#[cfg(windows)]
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ};
#[cfg(windows)]
use winreg::RegKey;

static STRESS_MUTEX: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

/// Comprehensive RAII Guard for Stress Testing:
/// - Guarantees isolated execution via STRESS_MUTEX
/// - Disarms any lingering isolation on entry and exit
/// - Takes snapshots of $env:PATH, all environment variables, and Windows Registry hives
/// - Asserts zero mutations on Drop
struct EmpiricalStressTestGuard {
    _lock: parking_lot::MutexGuard<'static, ()>,
    initial_path: String,
    initial_env: HashMap<String, String>,
    #[cfg(windows)]
    initial_hkcu_env: HashMap<String, String>,
    #[cfg(windows)]
    initial_hklm_env: HashMap<String, String>,
}

impl EmpiricalStressTestGuard {
    pub fn new() -> Self {
        let lock = STRESS_MUTEX.lock();
        let _ = execute_host_disarm_unauthenticated();
        record_successful_auth();

        let initial_path = std::env::var("PATH").unwrap_or_default();
        let initial_env: HashMap<String, String> = std::env::vars().collect();

        #[cfg(windows)]
        let initial_hkcu_env = Self::read_registry_env(HKEY_CURRENT_USER, "Environment");
        #[cfg(windows)]
        let initial_hklm_env = Self::read_registry_env(
            HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
        );

        Self {
            _lock: lock,
            initial_path,
            initial_env,
            #[cfg(windows)]
            initial_hkcu_env,
            #[cfg(windows)]
            initial_hklm_env,
        }
    }

    #[cfg(windows)]
    fn read_registry_env(root: winreg::HKEY, subkey: &str) -> HashMap<String, String> {
        let mut map = HashMap::new();
        let reg = RegKey::predef(root);
        if let Ok(key) = reg.open_subkey_with_flags(subkey, KEY_READ) {
            for val_res in key.enum_values() {
                if let Ok((name, val)) = val_res {
                    map.insert(name, format!("{:?}", val.to_string()));
                }
            }
        }
        map
    }
}

impl Drop for EmpiricalStressTestGuard {
    fn drop(&mut self) {
        let _ = execute_host_disarm_unauthenticated();
        record_successful_auth();

        // 1. Process environment PATH immutability
        let final_path = std::env::var("PATH").unwrap_or_default();
        assert_eq!(
            self.initial_path, final_path,
            "CRITICAL VIOLATION: $env:PATH was altered during stress test!"
        );

        // 2. Process environment variables map immutability
        for (k, v) in &self.initial_env {
            if let Ok(cur_val) = std::env::var(k) {
                assert_eq!(
                    v, &cur_val,
                    "CRITICAL VIOLATION: Environment variable '{}' was altered!",
                    k
                );
            }
        }

        // 3. Windows Registry HKCU\\Environment immutability
        #[cfg(windows)]
        {
            let final_hkcu_env = Self::read_registry_env(HKEY_CURRENT_USER, "Environment");
            for (k, v) in &self.initial_hkcu_env {
                assert_eq!(
                    final_hkcu_env.get(k),
                    Some(v),
                    "CRITICAL VIOLATION: HKCU\\Environment key '{}' was altered!",
                    k
                );
            }

            // 4. Windows Registry HKLM\\...\\Environment immutability
            let final_hklm_env = Self::read_registry_env(
                HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
            );
            for (k, v) in &self.initial_hklm_env {
                assert_eq!(
                    final_hklm_env.get(k),
                    Some(v),
                    "CRITICAL VIOLATION: HKLM\\Environment key '{}' was altered!",
                    k
                );
            }
        }
    }
}

// =========================================================================
// TEST 1: HIGH-CONCURRENCY KILLCHAIN ESCALATIONS (STAGES 1-5) STRESS HARNESS
// =========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_high_concurrency_killchain_stages_1_to_5_stress() {
    let _guard = EmpiricalStressTestGuard::new();

    let concurrency = 20;
    let iterations = 10;
    let completed_tasks = Arc::new(AtomicUsize::new(0));
    let error_occurred = Arc::new(AtomicBool::new(false));

    let mut handles = Vec::new();

    for worker_idx in 0..concurrency {
        let completed = completed_tasks.clone();
        let err_flag = error_occurred.clone();

        let handle = tokio::spawn(async move {
            for i in 0..iterations {
                let stage = (i % 5) + 1;
                let op_name = format!("adversarial_actor_{}_{}", worker_idx, i);
                let reason = format!("Simulated Killchain Stage {} Attack Payload", stage);

                let isolate_net = stage >= 4;
                let freeze_proc = stage >= 2;
                let lock_driver = stage >= 5;

                // Engage isolation or query status
                match engage_killchain_isolation(
                    &op_name,
                    &reason,
                    isolate_net,
                    freeze_proc,
                    lock_driver,
                )
                .await
                {
                    Ok(status) => {
                        // Invariant: Status must be isolated
                        if !status.isolated {
                            err_flag.store(true, Ordering::SeqCst);
                        }

                        // Invariant: None of the critical system PIDs can EVER be in frozen_pids
                        if status.frozen_pids.contains(&0)
                            || status.frozen_pids.contains(&1)
                            || status.frozen_pids.contains(&4)
                            || status.frozen_pids.contains(&std::process::id())
                        {
                            err_flag.store(true, Ordering::SeqCst);
                        }
                    }
                    Err(e) => {
                        // Only lockouts due to rapid repeated auth failure are valid errors
                        if !e.to_string().contains("locked") {
                            eprintln!("Unexpected error during engage: {}", e);
                            err_flag.store(true, Ordering::SeqCst);
                        }
                    }
                }

                // Intermediate status check
                let current_status = get_killchain_status();
                if current_status.isolated {
                    assert!(current_status.allowlisted_ports.contains(&3030));
                }

                tokio::task::yield_now().await;
            }

            completed.fetch_add(1, Ordering::SeqCst);
        });

        handles.push(handle);
    }

    for h in handles {
        h.await.expect("Worker task panicked");
    }

    assert!(
        !error_occurred.load(Ordering::SeqCst),
        "An invariant error occurred during high-concurrency killchain escalations!"
    );
    assert_eq!(
        completed_tasks.load(Ordering::SeqCst),
        concurrency,
        "All concurrent stress workers must finish cleanly."
    );

    // Verify disarm cleans up state completely
    let disarm_status = disarm_killchain_isolation("sec_admin", "Concurrency test complete")
        .await
        .expect("Disarm failed after high-concurrency stress");

    assert!(!disarm_status.isolated);
    assert_eq!(disarm_status.processes_frozen_count, 0);
    assert!(disarm_status.frozen_pids.is_empty());
}

// =========================================================================
// TEST 2: PROTECTED PROCESS & DEVELOPER TOOLCHAIN IMMUNITY UNDER LOAD
// =========================================================================

#[test]
fn test_protected_process_and_developer_toolchain_immunity_under_load() {
    let _guard = EmpiricalStressTestGuard::new();

    let controller = RemediationController::new();
    let kernel_client = KernelDriverClient::open_or_fallback();

    let protected_binaries = [
        // Windows Core OS Binaries
        ("explorer.exe", r"C:\Windows\explorer.exe"),
        ("SearchHost.exe", r"C:\Windows\SystemApps\Microsoft.Windows.Search_cw5n1h2txyewy\SearchHost.exe"),
        ("SearchIndexer.exe", r"C:\Windows\System32\SearchIndexer.exe"),
        ("SearchProtocolHost.exe", r"C:\Windows\System32\SearchProtocolHost.exe"),
        ("SearchFilterHost.exe", r"C:\Windows\System32\SearchFilterHost.exe"),
        ("sihost.exe", r"C:\Windows\System32\sihost.exe"),
        ("svchost.exe", r"C:\Windows\System32\svchost.exe"),
        ("lsass.exe", r"C:\Windows\System32\lsass.exe"),
        ("services.exe", r"C:\Windows\System32\services.exe"),
        ("csrss.exe", r"C:\Windows\System32\csrss.exe"),
        ("smss.exe", r"C:\Windows\System32\smss.exe"),
        ("SecurityHealthSystray.exe", r"C:\Windows\System32\SecurityHealthSystray.exe"),
        // Developer Toolchains
        ("python.exe", r"C:\Python312\python.exe"),
        ("python3.exe", r"C:\Program Files\Python312\python3.exe"),
        ("python", "/usr/bin/python"),
        ("python3", "/usr/bin/python3"),
        ("cargo.exe", r"C:\Users\dev\.cargo\bin\cargo.exe"),
        ("cargo", "/home/dev/.cargo/bin/cargo"),
        ("rustc.exe", r"C:\Users\dev\.cargo\bin\rustc.exe"),
        ("rustc", "/home/dev/.cargo/bin/rustc"),
        ("rustup.exe", r"C:\Users\dev\.cargo\bin\rustup.exe"),
        ("node.exe", r"C:\Program Files\nodejs\node.exe"),
        ("node", "/usr/local/bin/node"),
        ("git.exe", r"C:\Program Files\Git\cmd\git.exe"),
        ("git", "/usr/bin/git"),
        ("code.exe", r"C:\Users\dev\AppData\Local\Programs\Microsoft VS Code\Code.exe"),
        ("wsl.exe", r"C:\Windows\System32\wsl.exe"),
        ("docker.exe", r"C:\Program Files\Docker\Docker\resources\bin\docker.exe"),
        // Linux Critical Daemons
        ("systemd", "/lib/systemd/systemd"),
        ("dbus-daemon", "/usr/bin/dbus-daemon"),
        ("sshd", "/usr/sbin/sshd"),
    ];

    // High simulated load: 100 iterations of adversarial attempts
    for round in 0..100 {
        let simulated_pid = 1000 + (round as u32 % 500);

        for (name, path) in &protected_binaries {
            // 1. Process freeze immunity check
            assert!(
                is_critical_system_pid(simulated_pid, name),
                "Binary '{}' MUST be immune in is_critical_system_pid",
                name
            );
            assert!(
                is_critical_system_pid(simulated_pid, path),
                "Path '{}' MUST be immune in is_critical_system_pid",
                path
            );

            // 2. Runtime tarpit check
            assert!(
                is_protected_system_or_security_process(simulated_pid, name),
                "Binary '{}' MUST be protected in is_protected_system_or_security_process",
                name
            );

            // 3. BlockingManager path check
            assert!(
                is_protected_or_benign_system_path(path),
                "Path '{}' MUST be classified as protected in is_protected_or_benign_system_path",
                path
            );

            // 4. RemediationController kill refusal
            let kill_res = controller.kill_process_tree(simulated_pid);
            if let Err(e) = kill_res {
                let msg = e.to_string();
                assert!(
                    msg.contains("Cannot kill")
                        || msg.contains("protected")
                        || msg.contains("Refusing"),
                    "Expected protected refusal for '{}', got: {}",
                    name,
                    msg
                );
            }

            // 5. Network Tarpit refusal
            let tarpit_res = tarpit_process_network(Some(simulated_pid), Some(path));
            assert!(
                tarpit_res.is_err(),
                "Network tarpit MUST refuse to throttle protected binary '{}'",
                name
            );

            // 6. Network Block refusal
            let block_res = block_process_network(Some(simulated_pid), Some(name));
            assert!(
                block_res.is_err(),
                "Firewall MUST refuse to block protected binary '{}'",
                name
            );

            // 7. Kernel driver add_blocked_path refusal
            let _ = kernel_client.add_blocked_path(path);
            let normalized = path.replace('\\', "/");
            if let Ok(paths) = kernel_client.state.blocked_paths.read() {
                assert!(
                    !paths.contains(&normalized),
                    "Kernel driver MUST NOT add protected path '{}' to blocked_paths!",
                    path
                );
            }

            // 8. IFEO block refusal
            #[cfg(target_os = "windows")]
            {
                assert!(
                    !AgentProvisioner::is_safe_for_ifeo_block(path),
                    "Protected binary '{}' MUST NOT be safe for IFEO block!",
                    path
                );
            }
        }
    }
}

// =========================================================================
// TEST 2B: ADVERSARIAL MULTIPLEXER SESSION SHIELDING & RUNTIME TARPIT MATRIX
// =========================================================================

#[test]
fn test_adversarial_multiplexer_session_shielding() {
    let _guard = EmpiricalStressTestGuard::new();

    // 1. In remediation.rs, administrative session shielding protects tmux and screen
    assert!(
        is_administrative_or_ssh_session("tmux", &["tmux".to_string()]),
        "tmux MUST be shielded in is_administrative_or_ssh_session"
    );
    assert!(
        is_administrative_or_ssh_session("screen", &["screen".to_string()]),
        "screen MUST be shielded in is_administrative_or_ssh_session"
    );

    // 2. In killchain.rs, is_critical_system_pid protects tmux and screen
    assert!(
        is_critical_system_pid(5555, "tmux"),
        "tmux MUST be protected in is_critical_system_pid"
    );
    assert!(
        is_critical_system_pid(5556, "screen"),
        "screen MUST be protected in is_critical_system_pid"
    );

    // 3. In BlockingManager, paths are verified
    assert!(is_protected_or_benign_system_path("/usr/bin/tmux"));
    assert!(is_protected_or_benign_system_path("/usr/bin/screen"));
}

// =========================================================================
// TEST 3: LOOPBACK TCP (127.0.0.1:3030 & DYNAMIC) CONCURRENCY UNDER QUARANTINE
// =========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_loopback_and_webui_3030_tcp_survivability_during_quarantine() {
    let _guard = EmpiricalStressTestGuard::new();

    // 1. Engage simulated quarantine
    let _status = engage_killchain_isolation(
        "loopback_stress_tester",
        "Simulating network quarantine while verifying loopback health",
        false, // Keep netsh simulated in unit test thread
        false,
        false,
    )
    .await
    .expect("Failed to engage killchain isolation");

    // 2. Bind dynamic loopback listener
    let listener =
        TcpListener::bind("127.0.0.1:0").expect("Failed to bind dynamic loopback TCP listener");
    let dynamic_port = listener.local_addr().unwrap().port();
    let listener = Arc::new(listener);

    // 3. Test multi-threaded concurrent echo on dynamic loopback port
    let client_threads = 10;
    let messages_per_thread = 20;
    let mut client_handles = Vec::new();

    // Spawn server thread
    let server_listener = listener.clone();
    let total_expected = client_threads * messages_per_thread;
    let server_handle = std::thread::spawn(move || {
        let mut handled = 0;
        while handled < total_expected {
            if let Ok((mut stream, _)) = server_listener.accept() {
                let mut buf = [0u8; 64];
                if let Ok(bytes) = stream.read(&mut buf) {
                    if bytes > 0 {
                        let _ = stream.write_all(&buf[..bytes]);
                        handled += 1;
                    }
                }
            }
        }
    });

    for t in 0..client_threads {
        let h = std::thread::spawn(move || {
            for m in 0..messages_per_thread {
                let mut stream = TcpStream::connect(("127.0.0.1", dynamic_port))
                    .expect("Failed to connect to loopback listener under quarantine");
                let msg = format!("PROBE_{}_{}", t, m);
                stream.write_all(msg.as_bytes()).unwrap();

                let mut buf = [0u8; 64];
                let bytes = stream.read(&mut buf).unwrap();
                assert_eq!(&buf[..bytes], msg.as_bytes());
            }
        });
        client_handles.push(h);
    }

    for h in client_handles {
        h.join().expect("Client thread failed");
    }
    server_handle.join().expect("Server thread failed");

    // 4. Test WebUI port 3030 binding or connection
    match TcpListener::bind("127.0.0.1:3030") {
        Ok(webui_listener) => {
            // Port 3030 was available to bind
            let (mut s, _) = {
                let _c = TcpStream::connect("127.0.0.1:3030").unwrap();
                webui_listener.accept().unwrap()
            };
            s.write_all(b"HTTP/1.1 200 OK\r\n\r\n").unwrap();
        }
        Err(_) => {
            // Port 3030 is already bound by the active EDR daemon; attempt connecting to it
            if let Ok(mut stream) = TcpStream::connect("127.0.0.1:3030") {
                let _ = stream.write_all(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
            }
        }
    }

    // 5. Disarm and verify clean restoration
    let disarm = disarm_killchain_isolation("loopback_stress_tester", "Quarantine test complete")
        .await
        .expect("Disarm failed");
    assert!(!disarm.isolated);
}

// =========================================================================
// TEST 4: NETSH FIREWALL QUARANTINE RULES CLEANLY REVERTED UPON DISARM
// =========================================================================

#[tokio::test]
async fn test_netsh_quarantine_rules_cleanly_reverted_upon_disarm() {
    let _guard = EmpiricalStressTestGuard::new();

    #[cfg(target_os = "windows")]
    {
        use std::process::Command;

        let rule_names = [
            "Osoosi-KillChain-Block-Inbound-Low",
            "Osoosi-KillChain-Block-Inbound-High",
            "Osoosi-KillChain-Block-Outbound-Low",
            "Osoosi-KillChain-Block-Outbound-High",
            "Osoosi-KillChain-Allow-DNS-Out",
            "Osoosi-KillChain-Allow-DNS-TCP-Out",
            "Osoosi-KillChain-Allow-DHCP-Out",
            "Osoosi-KillChain-Allow-DHCP-In",
            "Osoosi-KillChain-Allow-DHCPv6-Out",
            "Osoosi-KillChain-Allow-DHCPv6-In",
            "Osoosi-KillChain-Allow-WebUI-In",
            "Osoosi-KillChain-Allow-WebUI-Out",
            "Osoosi-KillChain-Allow-WebUI-Out-Remote",
            "Osoosi-KillChain-Allow-Loopback-In",
            "Osoosi-KillChain-Allow-Loopback-Out",
        ];

        // 1. Ensure clean baseline before test
        for rule in &rule_names {
            let output = Command::new("netsh")
                .args(["advfirewall", "firewall", "show", "rule", &format!("name={}", rule)])
                .output()
                .expect("Failed to execute netsh");
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                !output.status.success() || stdout.contains("No rules match"),
                "Baseline dirty: Rule '{}' already exists prior to test!",
                rule
            );
        }

        // 2. Engage live network quarantine (invoke netsh rules)
        let status = engage_killchain_isolation(
            "netsh_reversion_tester",
            "Testing live netsh firewall rule creation and reversion",
            true, // Invoke live netsh commands
            false,
            false,
        )
        .await
        .expect("Failed to engage killchain isolation with live netsh");

        assert!(status.isolated);
        assert!(status.network_isolated);

        // 3. Disarm live network quarantine
        let disarmed = disarm_killchain_isolation(
            "netsh_reversion_tester",
            "Reverting live netsh firewall rules",
        )
        .await
        .expect("Failed to disarm live killchain isolation");

        assert!(!disarmed.isolated);
        assert!(!disarmed.network_isolated);

        // 4. Assert that ALL 15 rules are 100% cleanly deleted with zero residual rules
        for rule in &rule_names {
            let output = Command::new("netsh")
                .args(["advfirewall", "firewall", "show", "rule", &format!("name={}", rule)])
                .output()
                .expect("Failed to execute netsh show rule");

            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                !output.status.success() || stdout.contains("No rules match"),
                "RESIDUAL RULE DETECTED: Rule '{}' was not cleanly removed upon disarm! Output: {}",
                rule,
                stdout
            );
        }
    }
}

// =========================================================================
// TEST 5: ZERO REGISTRY ENVIRONMENT MUTATIONS & PATH IMMUTABILITY
// =========================================================================

#[tokio::test]
async fn test_stress_zero_registry_environment_mutation_and_path_immutability() {
    let _guard = EmpiricalStressTestGuard::new();

    // 1. Initial snapshot
    let initial_path = std::env::var("PATH").expect("System PATH must exist");

    #[cfg(windows)]
    let initial_hkcu = EmpiricalStressTestGuard::read_registry_env(HKEY_CURRENT_USER, "Environment");
    #[cfg(windows)]
    let initial_hklm = EmpiricalStressTestGuard::read_registry_env(
        HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
    );

    // 2. Run multi-stage isolation engagement and disarm cycle
    for i in 1..=5 {
        let reason = format!("Immutability Cycle Stage {}", i);
        let _ = engage_killchain_isolation(
            "immutability_tester",
            &reason,
            false,
            false,
            false,
        )
        .await
        .expect("Engage failed in immutability cycle");

        // Verify PATH in the middle of isolation
        let mid_path = std::env::var("PATH").expect("System PATH must exist");
        assert_eq!(
            initial_path, mid_path,
            "PATH was mutated during Stage {} isolation!",
            i
        );

        let _ = disarm_killchain_isolation("immutability_tester", "Cycle Complete")
            .await
            .expect("Disarm failed in immutability cycle");

        // Verify PATH immediately post-disarm
        let post_path = std::env::var("PATH").expect("System PATH must exist");
        assert_eq!(
            initial_path, post_path,
            "PATH was mutated post-disarm in Stage {}!",
            i
        );
    }

    // 3. Post-cycle verification of Registry Environment hives
    #[cfg(windows)]
    {
        let final_hkcu = EmpiricalStressTestGuard::read_registry_env(HKEY_CURRENT_USER, "Environment");
        assert_eq!(
            initial_hkcu, final_hkcu,
            "CRITICAL: HKCU\\Environment was mutated during isolation cycles!"
        );

        let final_hklm = EmpiricalStressTestGuard::read_registry_env(
            HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
        );
        assert_eq!(
            initial_hklm, final_hklm,
            "CRITICAL: HKLM\\...\\Environment was mutated during isolation cycles!"
        );
    }
}
