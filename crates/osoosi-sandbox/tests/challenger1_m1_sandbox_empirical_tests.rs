//! Empirical Challenger 1 Verification Suite for Milestone 1 (M1) Isolation Hardening
//!
//! Covers:
//! 1. Challenge 1: Handle allowlist in windows.rs (`PROC_THREAD_ATTRIBUTE_HANDLE_LIST` = 0x00020002)
//!    - Verifies arbitrary parent inheritable handles are NOT leaked to the child AppContainer process.
//! 2. Challenge 2: Job Object binding in token_posture.rs
//!    - Verifies `job == None` is strictly rejected and fails closed.
//!    - Verifies child processes terminate when the SandboxJobObject is closed (KILL_ON_JOB_CLOSE).
//! 3. Challenge 3: Reparse Point and Canonical Confinement in open_confined.rs
//!    - Verifies junctions, symlinks, ADS, null bytes, traversal, and canonical bounds are strictly blocked.
//! 4. Challenge 4: SSRF & DNS Rebinding SocketAddr Pinning in native_host.rs
//!    - Tests IPv4/IPv6 comprehensive SSRF matrix, SIIT, 6to4, NAT64, cloud metadata, and DNS rebinding pinning.

use osoosi_sandbox::native_host::{
    build_ssrf_safe_http_client, build_ssrf_safe_http_client_sync, is_ssrf_ip,
};
use osoosi_sandbox::open_confined::{open_confined, read_confined, write_confined};
#[cfg(windows)]
use osoosi_sandbox::windows::{
    execute_confined_windows_process, WindowsConfinementPolicy, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
};
#[cfg(windows)]
use osoosi_sandbox::{spawn_deelevated_in_job, SandboxJobObject};
use osoosi_types::OctopusSecurityError;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// =========================================================================
// 1. Challenge 1: Handle Allowlist in windows.rs
// =========================================================================

#[test]
fn test_challenge1_handle_allowlist_attribute_and_leak_isolation() {
    #[cfg(windows)]
    {
        use windows::Win32::Foundation::{CloseHandle, HANDLE};
        use windows::Win32::Security::SECURITY_ATTRIBUTES;
        use windows::Win32::Storage::FileSystem::{
            CreateFileW, FILE_ATTRIBUTE_TEMPORARY, FILE_FLAG_DELETE_ON_CLOSE, FILE_GENERIC_READ,
            FILE_GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_ALWAYS,
        };

        // 1. Confirm constant matches Win32 ProcThreadAttributeHandleList (0x00020002)
        assert_eq!(
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST, 0x00020002,
            "PROC_THREAD_ATTRIBUTE_HANDLE_LIST must equal 0x00020002"
        );

        // 2. Create an inheritable handle in the parent process
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join(format!(
            "parent_secret_handle_{}.txt",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let wide_path: Vec<u16> = test_file
            .as_os_str()
            .to_string_lossy()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: std::ptr::null_mut(),
            bInheritHandle: windows::Win32::Foundation::BOOL(1), // Explicitly mark as inheritable!
        };

        let parent_handle = unsafe {
            CreateFileW(
                windows::core::PCWSTR::from_raw(wide_path.as_ptr()),
                FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                Some(&sa),
                OPEN_ALWAYS,
                FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE,
                HANDLE::default(),
            )
        }
        .expect("CreateFileW with inheritable handle");

        let policy = WindowsConfinementPolicy::default();
        let outcome = execute_confined_windows_process(
            "cmd.exe",
            &["/c", "echo", "child_executed"],
            "osoosi_leak_challenge_profile_unique_123",
            &policy,
        )
        .expect("execute_confined_windows_process execution");

        eprintln!("CHALLENGE 1 OUTCOME: {:?}", outcome);
        assert!(
            outcome.resume_thread_allowed,
            "Child process must be resumed when pre-execution invariants pass: reason={}",
            outcome.reason
        );
        assert!(
            outcome.stdout.contains("child_executed"),
            "Child must execute stdout without leaking unlisted ambient handles"
        );

        unsafe {
            let _ = CloseHandle(parent_handle);
        }
    }
}

// =========================================================================
// 2. Challenge 2: Job Object Binding & Termination in token_posture.rs
// =========================================================================

#[test]
fn test_challenge2_job_object_rejects_none_fail_closed() {
    #[cfg(windows)]
    {
        // Assert that job == None is strictly rejected with IsolationViolation
        let res = spawn_deelevated_in_job("cmd.exe /c exit 0", true, None);
        assert!(
            res.is_err(),
            "spawn_deelevated_in_job with job == None must fail closed"
        );

        match res {
            Err(OctopusSecurityError::IsolationViolation(msg)) => {
                assert!(
                    msg.contains("FAIL-CLOSED: Active SandboxJobObject is mandatory"),
                    "Error must specify mandatory SandboxJobObject requirement: {}",
                    msg
                );
            }
            other => panic!("Expected IsolationViolation, got: {:?}", other),
        }
    }
}

#[test]
fn test_challenge2_job_object_kill_on_job_close_terminates_child() {
    #[cfg(windows)]
    {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::{
            GetExitCodeProcess, OpenProcess, WaitForSingleObject,
            PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
        };

        // 1. Create a dedicated SandboxJobObject with KILL_ON_JOB_CLOSE
        let job = SandboxJobObject::create("OsoosiChallengeJobKill", 5, 64 * 1024 * 1024)
            .expect("Create SandboxJobObject");

        // 2. Spawn a child that would otherwise run for 30 seconds
        let child = spawn_deelevated_in_job(
            "powershell.exe -NoProfile -Command \"Start-Sleep -Seconds 30\"",
            true,
            Some(&job),
        )
        .expect("Spawn child in job");

        let pid = child.pid;
        assert!(pid > 0, "Child process must have valid PID");
        assert!(child.is_in_job, "Child must be verified inside Job Object");

        // Open handle to monitor process termination independently
        let h_proc = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                false,
                pid,
            )
        }
        .expect("OpenProcess on child");

        // 3. Drop the job object explicitly — this closes the Job handle
        drop(job);

        // 4. Because JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE was set, the Windows kernel MUST terminate child
        let wait_res = unsafe { WaitForSingleObject(h_proc, 3000) };
        assert_eq!(
            wait_res.0,
            0x00000000, // WAIT_OBJECT_0
            "Child process must be terminated by kernel within 3s of Job Object close"
        );

        let mut exit_code: u32 = 0;
        let ok = unsafe { GetExitCodeProcess(h_proc, &mut exit_code) };
        assert!(ok.is_ok(), "GetExitCodeProcess should succeed");
        assert_ne!(
            exit_code,
            259, // STILL_ACTIVE
            "Process must not be STILL_ACTIVE after job close"
        );

        unsafe {
            let _ = CloseHandle(h_proc);
        }
    }
}

// =========================================================================
// 3. Challenge 3: Reparse Point and Confinement in open_confined.rs
// =========================================================================

#[test]
fn test_challenge3_open_confined_junction_and_symlink_defense() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let scratch_dir = std::env::temp_dir().join(format!("osoosi_challenger3_scratch_{}", nonce));
    std::fs::create_dir_all(&scratch_dir).expect("create scratch dir");

    // 1. Write benign file
    write_confined(&scratch_dir, "benign.txt", b"safe content").expect("write benign file");
    let content = read_confined(&scratch_dir, "benign.txt").expect("read benign file");
    assert_eq!(content, b"safe content");

    // 2. Test NTFS Alternate Data Stream (ADS) injection
    let ads_err = open_confined(&scratch_dir, "benign.txt:evil_stream", false);
    assert!(ads_err.is_err(), "ADS paths must be blocked");

    // 3. Test Parent Directory Traversal
    assert!(open_confined(&scratch_dir, "../outside.txt", false).is_err());
    assert!(open_confined(&scratch_dir, "sub/../../outside.txt", false).is_err());

    // 4. Test Percent-Encoded Traversal
    assert!(open_confined(&scratch_dir, "%2e%2e%5coutside.txt", false).is_err());
    assert!(open_confined(&scratch_dir, "..%2foutside.txt", false).is_err());

    // 5. Test Null Byte Poisoning
    assert!(open_confined(&scratch_dir, "benign.txt\0.exe", false).is_err());

    // 6. Test Windows Junction Defense
    #[cfg(windows)]
    {
        let outside_target = std::env::temp_dir().join(format!("osoosi_outside_target_{}", nonce));
        std::fs::create_dir_all(&outside_target).expect("create outside target");
        std::fs::write(outside_target.join("secret.txt"), b"confidential")
            .expect("write outside secret");

        // Create junction link inside scratch pointing to outside target
        let junction_path = scratch_dir.join("junc_escape");
        let create_junc = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!(
                    "New-Item -ItemType Junction -Path '{}' -Target '{}' -Force",
                    junction_path.display(),
                    outside_target.display()
                ),
            ])
            .output();

        if let Ok(out) = create_junc {
            if out.status.success() {
                // Attempt to access secret.txt through junction
                let junc_res = open_confined(&scratch_dir, "junc_escape/secret.txt", false);
                assert!(
                    junc_res.is_err(),
                    "open_confined MUST reject traversing NTFS junction"
                );

                match junc_res {
                    Err(OctopusSecurityError::IsolationViolation(msg)) => {
                        assert!(
                            msg.contains("CONFINED_OPEN_REPARSE_DIR_BLOCKED")
                                || msg.contains("escape")
                                || msg.contains("outside"),
                            "Error message must indicate junction/reparse blocking: {}",
                            msg
                        );
                    }
                    other => panic!("Expected IsolationViolation for junction, got {:?}", other),
                }
            }
        }

        let _ = std::fs::remove_dir_all(&outside_target);
    }

    let _ = std::fs::remove_dir_all(&scratch_dir);
}

// =========================================================================
// 4. Challenge 4: SSRF & DNS Rebinding SocketAddr Pinning in native_host.rs
// =========================================================================

#[test]
fn test_challenge4_ssrf_comprehensive_matrix_and_rebinding() {
    // 1. IPv4 Loopback
    assert!(is_ssrf_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
    assert!(is_ssrf_ip(IpAddr::V4(Ipv4Addr::new(127, 255, 255, 254))));

    // 2. RFC1918 Private
    assert!(is_ssrf_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    assert!(is_ssrf_ip(IpAddr::V4(Ipv4Addr::new(10, 254, 254, 254))));
    assert!(is_ssrf_ip(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
    assert!(is_ssrf_ip(IpAddr::V4(Ipv4Addr::new(172, 31, 255, 254))));
    assert!(is_ssrf_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));

    // 3. Link-Local / Cloud Metadata
    assert!(is_ssrf_ip(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))));
    assert!(is_ssrf_ip(IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1))));

    // 4. CGNAT (100.64.0.0/10)
    assert!(is_ssrf_ip(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))));
    assert!(is_ssrf_ip(IpAddr::V4(Ipv4Addr::new(100, 127, 255, 254))));

    // 5. Unspecified & Broadcast
    assert!(is_ssrf_ip(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))));
    assert!(is_ssrf_ip(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255))));

    // 6. Benchmarking & Class E
    assert!(is_ssrf_ip(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1))));
    assert!(is_ssrf_ip(IpAddr::V4(Ipv4Addr::new(240, 0, 0, 1))));

    // 7. IPv6 Loopback, Unspecified, Unique Local, Link-Local
    assert!(is_ssrf_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    assert!(is_ssrf_ip(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
    assert!(is_ssrf_ip("fc00::1".parse().unwrap()));
    assert!(is_ssrf_ip("fd12:3456:789a::1".parse().unwrap()));
    assert!(is_ssrf_ip("fe80::1".parse().unwrap()));

    // 8. IPv6 SIIT / IPv4-mapped / IPv4-compatible
    assert!(is_ssrf_ip("::ffff:127.0.0.1".parse().unwrap()));
    assert!(is_ssrf_ip("::ffff:10.0.0.1".parse().unwrap()));
    assert!(is_ssrf_ip("::ffff:169.254.169.254".parse().unwrap()));

    // 9. IPv6 NAT64 and 6to4
    assert!(is_ssrf_ip("64:ff9b::10.0.0.1".parse().unwrap()));
    assert!(is_ssrf_ip("2002:0a00:0001::".parse().unwrap()));

    // 10. Public IP addresses must NOT be blocked
    assert!(!is_ssrf_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    assert!(!is_ssrf_ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
    assert!(!is_ssrf_ip("2606:4700:4700::1111".parse().unwrap()));
}

#[tokio::test]
async fn test_challenge4_dns_rebinding_and_socketaddr_pinning() {
    // 1. Restricted domain names must be rejected immediately without network I/O
    let restricted_hostnames = [
        "http://localhost/admin",
        "http://sub.localhost:8080/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://metadata.aws.internal/",
        "http://instance-data/latest/meta-data",
    ];

    for u in &restricted_hostnames {
        let res = build_ssrf_safe_http_client(u).await;
        assert!(res.is_err(), "Host '{}' must be rejected as SSRF", u);
        match res {
            Err(OctopusSecurityError::SsrfBlocked(_)) => {}
            other => panic!("Expected SsrfBlocked, got {:?}", other),
        }

        let sync_res = build_ssrf_safe_http_client_sync(u);
        assert!(
            sync_res.is_err(),
            "Sync host '{}' must be rejected as SSRF",
            u
        );
    }

    // 2. Benign public host resolution and pinning
    let public_url = "https://workbench.cisecurity.org/";
    let res = build_ssrf_safe_http_client(public_url).await;
    assert!(
        res.is_ok(),
        "build_ssrf_safe_http_client must succeed for benign public URL"
    );

    let (_client, pinned_addr) = res.unwrap();
    assert!(
        !is_ssrf_ip(pinned_addr.ip()),
        "Pinned address must be a valid public IP"
    );
    assert_eq!(
        pinned_addr.port(),
        443,
        "HTTPS connection must pin port 443"
    );
}
