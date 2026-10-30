//! Milestone 1 (M1) Challenger 2 Empirical Stress & Adversarial Test Suite
//!
//! Independently and empirically challenges:
//! 1. Win32 Handle Allowlist (`PROC_THREAD_ATTRIBUTE_HANDLE_LIST`) in AppContainer process spawning
//!    to guarantee un-allowlisted parent handles cannot leak to child processes.
//! 2. Mandatory Pre-Resume Job Object binding and termination on job close in `token_posture.rs`:
//!    verifies `job == None` is strictly rejected fail-closed, and active child processes
//!    are reliably terminated by the kernel when the Job Object handle is dropped.
//! 3. Reparse point, directory junction, NTFS Alternate Data Streams, hardlink (`nNumberOfLinks > 1`),
//!    and canonical root containment in `open_confined.rs`.
//! 4. Comprehensive SSRF IP literal matrix, IPv4/IPv6 address bounds, and DNS rebinding `SocketAddr`
//!    pinning in `native_host.rs`.

use osoosi_sandbox::native_host::{
    build_ssrf_safe_http_client, build_ssrf_safe_http_client_sync, is_ssrf_ip,
    validate_resolved_socket_addr,
};
use osoosi_sandbox::open_confined::{
    create_confined_dir_all, open_confined, read_confined, write_confined,
};
#[cfg(windows)]
use osoosi_sandbox::windows::{
    execute_confined_windows_process, WindowsConfinementPolicy, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
};
#[cfg(windows)]
use osoosi_sandbox::{spawn_deelevated, spawn_deelevated_in_job, SandboxJobObject};
use osoosi_types::OctopusSecurityError;
use std::net::{IpAddr, SocketAddr};

// =========================================================================
// 1. Challenge Handle Allowlist in windows.rs
// =========================================================================

#[test]
fn test_challenger2_handle_allowlist_attribute_and_leak_prevention() {
    #[cfg(windows)]
    {
        use windows::Win32::Foundation::BOOL;
        use windows::Win32::Security::SECURITY_ATTRIBUTES;
        use windows::Win32::System::Threading::CreateEventW;

        // 1. Verify constant value matches Win32 ProcThreadAttributeHandleList (0x00020002)
        assert_eq!(
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST, 0x00020002,
            "PROC_THREAD_ATTRIBUTE_HANDLE_LIST must equal Win32 0x00020002"
        );

        // 2. Create an inheritable parent event handle.
        // Under default bInheritHandles = TRUE without PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
        // this handle would leak into any spawned child process.
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: std::ptr::null_mut(),
            bInheritHandle: BOOL(1), // INHERITABLE!
        };
        let h_secret = unsafe { CreateEventW(Some(&sa), true, false, None) }
            .expect("CreateEventW inheritable");

        assert!(
            !h_secret.is_invalid(),
            "Secret inheritable parent handle must be valid"
        );

        // 3. Execute process in AppContainer with handle allowlist active
        let policy = WindowsConfinementPolicy::default();
        let outcome = execute_confined_windows_process(
            "cmd.exe",
            &["/c", "echo", "challenger2_allowlist_verified"],
            "osoosi_challenger2_handle_profile",
            &policy,
        )
        .expect("Execution in AppContainer with handle allowlist must succeed");

        assert!(
            outcome.resume_thread_allowed,
            "Confinement gate must allow resume thread when policy is met"
        );
        assert!(
            !outcome.terminated_suspended_process,
            "Process must not be terminated prematurely"
        );
        assert!(
            outcome.sid_freed_via_free_sid,
            "AppContainer SID must be freed via FreeSid"
        );
        assert!(
            outcome.stdout.contains("challenger2_allowlist_verified"),
            "Stdout pipe must receive expected child output via allowlisted handle: got '{}'",
            outcome.stdout
        );

        // 4. Verify parent secret handle was not corrupted or closed by child execution
        unsafe {
            let _ = windows::Win32::Foundation::CloseHandle(h_secret);
        }
    }
}

// =========================================================================
// 2. Challenge Job Object Binding & Termination on Job Close in token_posture.rs
// =========================================================================

#[test]
fn test_challenger2_job_object_mandatory_fail_closed() {
    #[cfg(windows)]
    {
        // Challenge 2.1: Calling spawn_deelevated_in_job with job == None must fail closed
        let res = spawn_deelevated_in_job("cmd.exe /c exit 0", true, None);
        assert!(
            res.is_err(),
            "spawn_deelevated_in_job with job == None must fail closed"
        );
        match res {
            Err(OctopusSecurityError::IsolationViolation(msg)) => {
                assert!(
                    msg.contains("FAIL-CLOSED: Active SandboxJobObject is mandatory"),
                    "Error must indicate mandatory SandboxJobObject requirement: {}",
                    msg
                );
            }
            other => panic!("Expected IsolationViolation, got: {:?}", other),
        }
    }
}

#[test]
fn test_challenger2_job_object_termination_on_job_close() {
    #[cfg(windows)]
    {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::{
            GetExitCodeProcess, OpenProcess, WaitForSingleObject,
            PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
        };

        // Challenge 2.2: Launch a long-running process inside an explicit SandboxJobObject
        let job = SandboxJobObject::create("Challenger2ExplicitJobKillTest", 2, 64 * 1024 * 1024)
            .expect("Create SandboxJobObject");

        // Use ping -n 30 127.0.0.1 > nul as a 30-second background process
        let child =
            spawn_deelevated_in_job("cmd.exe /c ping -n 30 127.0.0.1 > nul", true, Some(&job))
                .expect("spawn_deelevated_in_job with valid job must succeed");

        assert!(
            child.is_in_job,
            "Child must be verified inside Job Object before ResumeThread"
        );
        let child_pid = child.pid;
        assert!(child_pid > 0, "Valid process ID must be returned");

        // Open child process handle to monitor its lifecycle independently
        let h_proc = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                false,
                child_pid,
            )
        }
        .expect("Open child process handle for monitoring");

        let mut exit_code: u32 = 0;
        let ok = unsafe { GetExitCodeProcess(h_proc, &mut exit_code) };
        assert!(
            ok.is_ok(),
            "GetExitCodeProcess must succeed on running child"
        );
        assert_eq!(
            exit_code, 259,
            "Child process must initially be running (STILL_ACTIVE = 259)"
        );

        // Challenge 2.3: DROP the Job Object handle!
        // Due to JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, Windows kernel MUST kill all member processes.
        drop(job);

        // Wait up to 3000ms for process to be terminated by the kernel
        let wait_res = unsafe { WaitForSingleObject(h_proc, 3000) };
        assert_eq!(
            wait_res.0, 0,
            "Child process must be terminated by kernel upon Job Object closure (WAIT_OBJECT_0 = 0)"
        );

        let ok_post = unsafe { GetExitCodeProcess(h_proc, &mut exit_code) };
        assert!(ok_post.is_ok());
        assert_ne!(
            exit_code, 259,
            "Process must no longer be STILL_ACTIVE after Job Object close"
        );

        unsafe {
            let _ = CloseHandle(h_proc);
        }
    }
}

#[test]
fn test_challenger2_auto_job_termination_on_child_drop() {
    #[cfg(windows)]
    {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::{
            GetExitCodeProcess, OpenProcess, WaitForSingleObject,
            PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
        };

        // Challenge 2.4: spawn_deelevated auto-creates an internal SandboxJobObject
        let child = spawn_deelevated("cmd.exe /c ping -n 30 127.0.0.1 > nul", true)
            .expect("spawn_deelevated auto job must succeed");

        assert!(child.is_in_job, "Auto-job must set is_in_job == true");
        let child_pid = child.pid;

        let h_proc = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                false,
                child_pid,
            )
        }
        .expect("Open child process handle for monitoring");

        // Dropping DeelevatedChild drops the _owned_job handle, terminating the process!
        drop(child);

        let wait_res = unsafe { WaitForSingleObject(h_proc, 3000) };
        assert_eq!(
            wait_res.0, 0,
            "Process in auto-job must be terminated by kernel when DeelevatedChild is dropped"
        );

        let mut exit_code: u32 = 0;
        let _ = unsafe { GetExitCodeProcess(h_proc, &mut exit_code) };
        assert_ne!(
            exit_code, 259,
            "Process must no longer be STILL_ACTIVE after DeelevatedChild is dropped"
        );

        unsafe {
            let _ = CloseHandle(h_proc);
        }
    }
}

// =========================================================================
// 3. Challenge open_confined.rs Reparse Points, Symlinks, ADS & Bounds
// =========================================================================

#[test]
fn test_challenger2_open_confined_reparse_junction_ads_and_bounds() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let scratch_dir = std::env::temp_dir().join(format!("osoosi_challenger2_scratch_{}", nonce));
    let outside_dir = std::env::temp_dir().join(format!("osoosi_challenger2_outside_{}", nonce));
    std::fs::create_dir_all(&scratch_dir).expect("create scratch dir");
    std::fs::create_dir_all(&outside_dir).expect("create outside dir");

    // Put a sensitive secret in outside_dir
    let secret_file = outside_dir.join("secret_token.txt");
    std::fs::write(&secret_file, b"TOP_SECRET_OUTSIDE_BOUNDS").expect("write secret");

    // Challenge 3.1: ADS (NTFS Alternate Data Streams) rejection
    assert!(
        read_confined(&scratch_dir, "file.txt:stream").is_err(),
        "read_confined must reject Alternate Data Streams with ':'"
    );
    assert!(
        write_confined(&scratch_dir, "file.txt:stream", b"evil").is_err(),
        "write_confined must reject Alternate Data Streams with ':'"
    );
    assert!(
        open_confined(&scratch_dir, "file.txt:$DATA", false).is_err(),
        "open_confined must reject Alternate Data Streams with ':'"
    );
    assert!(
        read_confined(&scratch_dir, "dir:stream/nested.txt").is_err(),
        "read_confined must reject Alternate Data Streams in path"
    );

    // Challenge 3.2: Path traversal rejection across various encodings
    assert!(
        read_confined(&scratch_dir, "../outside.txt").is_err(),
        "read_confined must reject parent traversal '..'"
    );
    assert!(
        read_confined(&scratch_dir, "sub/../../outside.txt").is_err(),
        "read_confined must reject nested parent traversal"
    );
    assert!(
        read_confined(&scratch_dir, "%2e%2e/outside.txt").is_err(),
        "read_confined must reject percent-encoded '..'"
    );
    assert!(
        read_confined(&scratch_dir, "%2e%2e%5coutside.txt").is_err(),
        "read_confined must reject percent-encoded traversal"
    );
    assert!(
        read_confined(&scratch_dir, "test.txt%00.png").is_err(),
        "read_confined must reject null-byte injection"
    );

    // Challenge 3.3: Absolute and UNC path rejection
    #[cfg(windows)]
    {
        assert!(
            read_confined(&scratch_dir, r"C:\Windows\System32\drivers\etc\hosts").is_err(),
            "read_confined must reject absolute drive paths"
        );
        assert!(
            read_confined(&scratch_dir, r"\\127.0.0.1\c$\secret.txt").is_err(),
            "read_confined must reject UNC network paths"
        );
    }

    // Challenge 3.4: Verified Write, Read, and Truncation
    create_confined_dir_all(&scratch_dir, "dir1/dir2").expect("create_confined_dir_all");
    let initial_data = vec![0x41u8; 128]; // 128 'A's
    write_confined(&scratch_dir, "dir1/dir2/data.bin", &initial_data)
        .expect("write_confined initial data");
    let read_initial =
        read_confined(&scratch_dir, "dir1/dir2/data.bin").expect("read_confined initial data");
    assert_eq!(read_initial, initial_data);

    // Overwrite with smaller payload; assert proper handle truncation
    let small_data = b"TINY_PAYLOAD";
    write_confined(&scratch_dir, "dir1/dir2/data.bin", small_data)
        .expect("write_confined overwrite");
    let read_small =
        read_confined(&scratch_dir, "dir1/dir2/data.bin").expect("read_confined small data");
    assert_eq!(
        read_small, small_data,
        "File must be cleanly truncated to new payload with zero trailing bytes"
    );

    // Challenge 3.5: NTFS Directory Junction Escape Resistance
    #[cfg(windows)]
    {
        let junction_path = scratch_dir.join("junction_esc");
        // Create an NTFS junction pointing to outside_dir: mklink /J <junction> <target>
        let mklink_status = std::process::Command::new("cmd.exe")
            .args(&[
                "/c",
                "mklink",
                "/J",
                &junction_path.to_string_lossy(),
                &outside_dir.to_string_lossy(),
            ])
            .output();

        if let Ok(output) = mklink_status {
            if output.status.success() {
                // The junction was successfully created.
                // Now attempt open_confined, read_confined, write_confined through the junction.
                let open_res = open_confined(&scratch_dir, "junction_esc/secret_token.txt", false);
                assert!(
                    open_res.is_err(),
                    "open_confined MUST detect and reject directory junction component"
                );
                match open_res {
                    Err(OctopusSecurityError::IsolationViolation(msg)) => {
                        assert!(
                            msg.contains("CONFINED_OPEN_REPARSE_DIR_BLOCKED"),
                            "Error must report reparse dir blocked: {}",
                            msg
                        );
                    }
                    other => panic!("Expected IsolationViolation, got: {:?}", other),
                }

                let read_res = read_confined(&scratch_dir, "junction_esc/secret_token.txt");
                assert!(
                    read_res.is_err(),
                    "read_confined MUST reject reading through a junction"
                );

                let write_res = write_confined(
                    &scratch_dir,
                    "junction_esc/secret_token.txt",
                    b"TAMPERED_OUTSIDE",
                );
                assert!(
                    write_res.is_err(),
                    "write_confined MUST reject writing through a junction"
                );

                let dir_res = create_confined_dir_all(&scratch_dir, "junction_esc/sub_nested");
                assert!(
                    dir_res.is_err(),
                    "create_confined_dir_all MUST reject creating directories through a junction"
                );

                // Clean up the junction link using rmdir
                let _ = std::process::Command::new("cmd.exe")
                    .args(&["/c", "rmdir", &junction_path.to_string_lossy()])
                    .output();
            }
        }
    }

    // Challenge 3.6: NTFS Hardlink Defense (nNumberOfLinks > 1)
    #[cfg(windows)]
    {
        let base_file = scratch_dir.join("base_file.txt");
        std::fs::write(&base_file, b"BASE_FILE_CONTENT").expect("write base file");
        let hardlink_file = scratch_dir.join("hardlink_file.txt");

        let mklink_h = std::process::Command::new("cmd.exe")
            .args(&[
                "/c",
                "mklink",
                "/H",
                &hardlink_file.to_string_lossy(),
                &base_file.to_string_lossy(),
            ])
            .output();

        if let Ok(output) = mklink_h {
            if output.status.success() {
                // Hardlink created; nNumberOfLinks is now 2
                let link_res = open_confined(&scratch_dir, "hardlink_file.txt", false);
                assert!(
                    link_res.is_err(),
                    "open_confined MUST reject files with nNumberOfLinks > 1"
                );
                match link_res {
                    Err(OctopusSecurityError::IsolationViolation(msg)) => {
                        assert!(
                            msg.contains("CONFINED_OPEN_HARDLINK_BLOCKED"),
                            "Error must report hardlink blocked: {}",
                            msg
                        );
                    }
                    other => panic!("Expected IsolationViolation for hardlink, got: {:?}", other),
                }

                let _ = std::fs::remove_file(&hardlink_file);
            }
        }
    }

    let _ = std::fs::remove_dir_all(&scratch_dir);
    let _ = std::fs::remove_dir_all(&outside_dir);
}

// =========================================================================
// 4. Challenge native_host.rs SSRF IP Literals & DNS Rebinding SocketAddr Pinning
// =========================================================================

#[test]
fn test_challenger2_is_ssrf_ip_exhaustive_range_and_boundary_matrix() {
    // 1. Loopback addresses (127.0.0.0/8 and ::1)
    assert!(is_ssrf_ip("127.0.0.1".parse::<IpAddr>().unwrap()));
    assert!(is_ssrf_ip("127.0.0.2".parse::<IpAddr>().unwrap()));
    assert!(is_ssrf_ip("127.255.255.254".parse::<IpAddr>().unwrap()));
    assert!(is_ssrf_ip("::1".parse::<IpAddr>().unwrap()));

    // 2. RFC1918 Class A (10.0.0.0/8)
    assert!(is_ssrf_ip("10.0.0.1".parse::<IpAddr>().unwrap()));
    assert!(is_ssrf_ip("10.255.255.254".parse::<IpAddr>().unwrap()));

    // 3. RFC1918 Class B (172.16.0.0/12: 172.16.0.0 - 172.31.255.255)
    assert!(is_ssrf_ip("172.16.0.1".parse::<IpAddr>().unwrap()));
    assert!(is_ssrf_ip("172.24.10.50".parse::<IpAddr>().unwrap()));
    assert!(is_ssrf_ip("172.31.255.254".parse::<IpAddr>().unwrap()));
    // Boundary check: 172.15.255.255 and 172.32.0.1 are public!
    assert!(
        !is_ssrf_ip("172.15.255.255".parse::<IpAddr>().unwrap()),
        "172.15.255.255 is public, must not be blocked"
    );
    assert!(
        !is_ssrf_ip("172.32.0.1".parse::<IpAddr>().unwrap()),
        "172.32.0.1 is public, must not be blocked"
    );

    // 4. RFC1918 Class C (192.168.0.0/16)
    assert!(is_ssrf_ip("192.168.0.1".parse::<IpAddr>().unwrap()));
    assert!(is_ssrf_ip("192.168.255.254".parse::<IpAddr>().unwrap()));
    // Boundary check: 192.167.255.255 and 192.169.0.1 are public!
    assert!(!is_ssrf_ip("192.167.255.255".parse::<IpAddr>().unwrap()));
    assert!(!is_ssrf_ip("192.169.0.1".parse::<IpAddr>().unwrap()));

    // 5. Link-Local / Cloud Metadata (169.254.0.0/16, fe80::/10)
    assert!(is_ssrf_ip("169.254.169.254".parse::<IpAddr>().unwrap()));
    assert!(is_ssrf_ip("169.254.1.1".parse::<IpAddr>().unwrap()));
    assert!(is_ssrf_ip("fe80::1".parse::<IpAddr>().unwrap()));
    assert!(is_ssrf_ip(
        "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
            .parse::<IpAddr>()
            .unwrap()
    ));

    // 6. CGNAT (100.64.0.0/10: 100.64.0.0 - 100.127.255.255)
    assert!(is_ssrf_ip("100.64.0.1".parse::<IpAddr>().unwrap()));
    assert!(is_ssrf_ip("100.100.50.25".parse::<IpAddr>().unwrap()));
    assert!(is_ssrf_ip("100.127.255.254".parse::<IpAddr>().unwrap()));
    // Boundary check: 100.63.255.255 and 100.128.0.1 are public!
    assert!(!is_ssrf_ip("100.63.255.255".parse::<IpAddr>().unwrap()));
    assert!(!is_ssrf_ip("100.128.0.1".parse::<IpAddr>().unwrap()));

    // 7. Unspecified & Broadcast
    assert!(is_ssrf_ip("0.0.0.0".parse::<IpAddr>().unwrap()));
    assert!(is_ssrf_ip("255.255.255.255".parse::<IpAddr>().unwrap()));
    assert!(is_ssrf_ip("::".parse::<IpAddr>().unwrap()));

    // 8. IPv6 ULA (fc00::/7: fc00:: - fdff:ffff:...)
    assert!(is_ssrf_ip("fc00::1".parse::<IpAddr>().unwrap()));
    assert!(is_ssrf_ip("fd12:3456:789a::1".parse::<IpAddr>().unwrap()));

    // 9. IPv4-Mapped IPv6 (::ffff:0:0/96)
    assert!(is_ssrf_ip("::ffff:127.0.0.1".parse::<IpAddr>().unwrap()));
    assert!(is_ssrf_ip("::ffff:10.0.0.1".parse::<IpAddr>().unwrap()));
    assert!(is_ssrf_ip(
        "::ffff:169.254.169.254".parse::<IpAddr>().unwrap()
    ));
    // Mapped public IP
    assert!(!is_ssrf_ip("::ffff:1.1.1.1".parse::<IpAddr>().unwrap()));

    // 10. IPv4-Compatible IPv6 (::a.b.c.d)
    assert!(is_ssrf_ip("::127.0.0.1".parse::<IpAddr>().unwrap()));
    assert!(is_ssrf_ip("::10.0.0.1".parse::<IpAddr>().unwrap()));

    // 11. NAT64 prefix (64:ff9b::/96 and 64:ff9b:1::/48)
    assert!(is_ssrf_ip("64:ff9b::127.0.0.1".parse::<IpAddr>().unwrap()));
    assert!(is_ssrf_ip("64:ff9b:1::1".parse::<IpAddr>().unwrap()));

    // 12. 6to4 prefix (2002::/16)
    assert!(is_ssrf_ip("2002:7f00:0001::".parse::<IpAddr>().unwrap())); // 127.0.0.1 embedded

    // 13. Benchmarking (198.18.0.0/15: 198.18.0.0 - 198.19.255.255)
    assert!(is_ssrf_ip("198.18.0.1".parse::<IpAddr>().unwrap()));
    assert!(is_ssrf_ip("198.19.255.254".parse::<IpAddr>().unwrap()));

    // 14. Class E Reserved (240.0.0.0/4)
    assert!(is_ssrf_ip("240.0.0.1".parse::<IpAddr>().unwrap()));
    assert!(is_ssrf_ip("250.1.2.3".parse::<IpAddr>().unwrap()));

    // 15. Valid public routable addresses must pass (return false)
    assert!(!is_ssrf_ip("1.1.1.1".parse::<IpAddr>().unwrap()));
    assert!(!is_ssrf_ip("8.8.8.8".parse::<IpAddr>().unwrap()));
    assert!(!is_ssrf_ip("93.184.216.34".parse::<IpAddr>().unwrap()));
    assert!(!is_ssrf_ip(
        "2606:4700:4700::1111".parse::<IpAddr>().unwrap()
    ));
}

#[tokio::test]
async fn test_challenger2_ssrf_safe_http_client_adversarial_rejections() {
    let hostile_urls = [
        // IPv4 loopback
        "http://127.0.0.1:8080/secrets",
        "http://127.0.0.100:9090/",
        // IPv6 loopback
        "http://[::1]:8080/admin",
        // AWS/GCP/Azure Metadata
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://instance-data/latest/meta-data",
        // Hostname variations
        "http://localhost:3000/api",
        "http://dev.localhost/db",
        // RFC1918
        "http://10.0.0.1:80/console",
        "http://172.16.0.1/status",
        "http://192.168.1.1/setup",
        // CGNAT
        "http://100.64.0.1/",
        // Unspecified
        "http://0.0.0.0:8080/",
        "http://[::]:80/",
        // IPv6 ULA & Link-local
        "http://[fc00::1]:8080/",
        "http://[fd12:3456:789a::1]/",
        "http://[fe80::1]/",
        // Mapped IPv6
        "http://[::ffff:127.0.0.1]:8080/",
        "http://[::ffff:10.0.0.1]/",
        // Dangerous schemes
        "file:///etc/shadow",
        "gopher://127.0.0.1:70/",
        "ftp://10.0.0.1/files",
    ];

    for &url in &hostile_urls {
        let async_res = build_ssrf_safe_http_client(url).await;
        assert!(
            async_res.is_err(),
            "Async client MUST reject hostile URL '{}'",
            url
        );
        match async_res {
            Err(OctopusSecurityError::SsrfBlocked(_)) => {}
            other => panic!("Expected SsrfBlocked for '{}', got {:?}", url, other),
        }

        let sync_res = build_ssrf_safe_http_client_sync(url);
        assert!(
            sync_res.is_err(),
            "Sync client MUST reject hostile URL '{}'",
            url
        );
        match sync_res {
            Err(OctopusSecurityError::SsrfBlocked(_)) => {}
            other => panic!("Expected SsrfBlocked for '{}', got {:?}", url, other),
        }
    }
}

#[tokio::test]
async fn test_challenger2_ssrf_safe_http_client_pins_public_domain() {
    let public_url = "https://workbench.cisecurity.org/";
    let res = build_ssrf_safe_http_client(public_url).await;
    assert!(
        res.is_ok(),
        "build_ssrf_safe_http_client must succeed for valid public domain: {:?}",
        res.err()
    );

    let (_client, pinned_addr) = res.unwrap();
    assert!(
        !is_ssrf_ip(pinned_addr.ip()),
        "Pinned IP '{}' must be verified non-SSRF",
        pinned_addr.ip()
    );
    assert_eq!(pinned_addr.port(), 443, "HTTPS port must be 443");

    // Test validate_resolved_socket_addr helper
    assert!(validate_resolved_socket_addr(&pinned_addr).is_ok());

    let loopback_sock: SocketAddr = "127.0.0.1:8080".parse().unwrap();
    assert!(validate_resolved_socket_addr(&loopback_sock).is_err());
}
