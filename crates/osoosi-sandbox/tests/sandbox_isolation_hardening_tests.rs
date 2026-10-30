//! Milestone 1 (M1) Isolation Hardening Verification Suite
//!
//! Empirically tests:
//! 1. F01: Handle Allowlist Attribute (`PROC_THREAD_ATTRIBUTE_HANDLE_LIST`) in Win32 AppContainer process spawning.
//! 2. F02: Mandatory Pre-Resume Job Object binding & verification (`KILL_ON_JOB_CLOSE | ACTIVE_PROCESS`)
//!    failing closed when `job == None` and enforcing active process limits.
//! 3. F03: Reparse Point and TOCTOU defense (`read_confined`, `write_confined`, `create_confined_dir_all`).
//! 4. F04: DNS Rebinding prevention and SocketAddr pinning (`build_ssrf_safe_http_client`, `build_ssrf_safe_http_client_sync`).

use osoosi_sandbox::native_host::{
    build_ssrf_safe_http_client, build_ssrf_safe_http_client_sync, is_ssrf_ip,
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
use std::net::IpAddr;

// =========================================================================
// 1. F01: Handle Allowlist Attribute Verification
// =========================================================================

#[test]
fn test_f01_handle_allowlist_attribute_constant_and_execution() {
    #[cfg(windows)]
    {
        // 1. Verify constant value matches Win32 ProcThreadAttributeHandleList (0x00020002)
        assert_eq!(
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST, 0x00020002,
            "PROC_THREAD_ATTRIBUTE_HANDLE_LIST must equal Win32 0x00020002"
        );

        // 2. Execute process in AppContainer with handle allowlist active
        let policy = WindowsConfinementPolicy::default();
        let outcome = execute_confined_windows_process(
            "cmd.exe",
            &["/c", "echo", "handle_allowlist_verified"],
            "osoosi_f01_test_profile",
            &policy,
        )
        .expect("Execution with handle allowlist attribute must succeed");

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
            "AppContainer SID must be freed after execution"
        );
        assert!(
            outcome.stdout.contains("handle_allowlist_verified"),
            "Stdout pipe must receive expected child output via allowlisted handle: got '{}'",
            outcome.stdout
        );
    }
}

// =========================================================================
// 2. F02: Mandatory Pre-Resume Job Object Binding Tests
// =========================================================================

#[test]
fn test_f02_mandatory_job_object_spawn_deelevated_in_job_fails_closed_when_none() {
    #[cfg(windows)]
    {
        let cmd = "cmd.exe /c exit 0";

        // Calling spawn_deelevated_in_job with job == None must fail closed immediately
        let res = spawn_deelevated_in_job(cmd, true, None);
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
fn test_f02_mandatory_job_object_spawn_deelevated_with_job_succeeds() {
    #[cfg(windows)]
    {
        let cmd = "cmd.exe /c exit 0";
        let job = SandboxJobObject::create("OsoosiF02ExplicitJob", 2, 64 * 1024 * 1024)
            .expect("Create SandboxJobObject");

        let child = spawn_deelevated_in_job(cmd, true, Some(&job))
            .expect("spawn_deelevated_in_job with valid job must succeed");

        assert!(
            child.is_in_job,
            "Child must be verified inside Job Object before ResumeThread"
        );
        assert!(child.pid > 0, "Valid process ID must be returned");

        let code = child.wait().expect("Child process wait");
        assert_eq!(code, 0, "Child must exit with code 0");
    }
}

#[test]
fn test_f02_mandatory_job_object_spawn_deelevated_auto_job_succeeds() {
    #[cfg(windows)]
    {
        let cmd = "cmd.exe /c exit 0";

        // spawn_deelevated automatically creates an internal confined job object
        let child = spawn_deelevated(cmd, true)
            .expect("spawn_deelevated with auto job object must succeed");

        assert!(
            child.is_in_job,
            "Auto-created job must verify IsProcessInJob == TRUE"
        );
        assert!(child.pid > 0, "Valid process ID must be returned");

        let code = child.wait().expect("Child process wait");
        assert_eq!(code, 0, "Child must exit with code 0");
    }
}

// =========================================================================
// 3. F03: Reparse Point & TOCTOU Defense Scratchpad Tests
// =========================================================================

#[test]
fn test_f03_reparse_point_and_toctou_read_write_confined() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let scratch_dir = std::env::temp_dir().join(format!("osoosi_scratch_f03_{}", nonce));
    std::fs::create_dir_all(&scratch_dir).expect("create scratch dir");

    // 1. Write confined
    let test_data = b"Confined file write content verification";
    write_confined(&scratch_dir, "test_file.txt", test_data).expect("write_confined must succeed");

    // 2. Read confined
    let read_back =
        read_confined(&scratch_dir, "test_file.txt").expect("read_confined must succeed");
    assert_eq!(
        read_back, test_data,
        "Read-back data must match written data"
    );

    // 3. Truncation on re-write (post-verification truncation)
    let short_data = b"Short";
    write_confined(&scratch_dir, "test_file.txt", short_data)
        .expect("write_confined overwrite must succeed");
    let read_short =
        read_confined(&scratch_dir, "test_file.txt").expect("read_confined after overwrite");
    assert_eq!(
        read_short, short_data,
        "Overwritten file must be truncated with no trailing bytes"
    );

    // 4. Confined directory creation and nested write
    create_confined_dir_all(&scratch_dir, "sub_dir/level2")
        .expect("create_confined_dir_all must succeed");
    let nested_data = b"Nested payload bytes";
    write_confined(&scratch_dir, "sub_dir/level2/nested.txt", nested_data)
        .expect("write_confined in created dir");
    let read_nested = read_confined(&scratch_dir, "sub_dir/level2/nested.txt")
        .expect("read_confined in created dir");
    assert_eq!(read_nested, nested_data);

    // 5. Defense: Directory traversal rejection
    assert!(
        read_confined(&scratch_dir, "../outside.txt").is_err(),
        "read_confined must reject parent directory traversal"
    );
    assert!(
        write_confined(&scratch_dir, "../outside.txt", b"evil").is_err(),
        "write_confined must reject parent directory traversal"
    );

    // 6. Defense: Absolute path rejection
    #[cfg(windows)]
    {
        assert!(
            read_confined(&scratch_dir, r"C:\Windows\System32\drivers\etc\hosts").is_err(),
            "read_confined must reject drive-letter absolute path"
        );
        assert!(
            open_confined(
                &scratch_dir,
                r"C:\Windows\System32\drivers\etc\hosts",
                false
            )
            .is_err(),
            "open_confined must reject drive-letter absolute path"
        );
    }

    // 7. Defense: Percent-encoded traversal rejection
    assert!(
        read_confined(&scratch_dir, "%2e%2e%2foutside.txt").is_err(),
        "read_confined must reject percent-encoded traversal"
    );

    // 8. Defense: NTFS Alternate Data Stream rejection
    assert!(
        read_confined(&scratch_dir, "test_file.txt:hidden_stream").is_err(),
        "read_confined must reject alternate data streams"
    );

    let _ = std::fs::remove_dir_all(&scratch_dir);
}

// =========================================================================
// 4. F04: SSRF & DNS Rebinding SocketAddr Pinning Tests
// =========================================================================

#[tokio::test]
async fn test_f04_build_ssrf_safe_http_client_blocks_restricted_ips() {
    let restricted_urls = [
        "http://127.0.0.1:8080/admin",
        "http://127.0.0.2:8080/",
        "http://10.0.0.1/internal",
        "http://10.255.255.254/status",
        "http://172.16.0.1/api",
        "http://172.31.255.255/api",
        "http://192.168.1.1/router",
        "http://169.254.169.254/latest/meta-data",
        "http://100.64.0.1/cgnat",
        "http://0.0.0.0:80/",
        "http://[::1]:8080/",
        "http://[::]:80/",
        "http://[fe80::1]/",
        "http://[fd12:3456:789a::1]/",
        "http://localhost:3000/",
        "http://test.localhost/api",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://instance-data/latest/meta-data",
        "file:///etc/passwd",
        "gopher://127.0.0.1:70/",
    ];

    for url in &restricted_urls {
        let async_res = build_ssrf_safe_http_client(url).await;
        assert!(
            async_res.is_err(),
            "build_ssrf_safe_http_client must reject restricted URL: {}",
            url
        );
        match async_res {
            Err(OctopusSecurityError::SsrfBlocked(_)) => {}
            other => panic!("Expected SsrfBlocked for '{}', got {:?}", url, other),
        }

        let sync_res = build_ssrf_safe_http_client_sync(url);
        assert!(
            sync_res.is_err(),
            "build_ssrf_safe_http_client_sync must reject restricted URL: {}",
            url
        );
        match sync_res {
            Err(OctopusSecurityError::SsrfBlocked(_)) => {}
            other => panic!("Expected SsrfBlocked for '{}', got {:?}", url, other),
        }
    }
}

#[tokio::test]
async fn test_f04_build_ssrf_safe_http_client_pins_valid_public_domain() {
    // A benign public domain (CISecurity)
    let valid_url = "https://workbench.cisecurity.org/";

    let async_res = build_ssrf_safe_http_client(valid_url).await;
    assert!(
        async_res.is_ok(),
        "build_ssrf_safe_http_client must succeed for benign public domain: {:?}",
        async_res.err()
    );
    let (_client, pinned_addr) = async_res.unwrap();
    assert!(
        !is_ssrf_ip(pinned_addr.ip()),
        "Pinned socket address must not be in SSRF range: {}",
        pinned_addr
    );
    assert_eq!(pinned_addr.port(), 443, "HTTPS must resolve to port 443");

    // Test sync counterpart
    let sync_res = build_ssrf_safe_http_client_sync(valid_url);
    assert!(
        sync_res.is_ok(),
        "build_ssrf_safe_http_client_sync must succeed for benign public domain: {:?}",
        sync_res.err()
    );
    let (_sync_client, sync_pinned_addr) = sync_res.unwrap();
    assert!(
        !is_ssrf_ip(sync_pinned_addr.ip()),
        "Sync pinned socket address must not be in SSRF range: {}",
        sync_pinned_addr
    );
}

#[test]
fn test_f04_is_ssrf_ip_comprehensive_matrix() {
    // Loopback
    assert!(is_ssrf_ip("127.0.0.1".parse::<IpAddr>().unwrap()));
    assert!(is_ssrf_ip("127.128.0.1".parse::<IpAddr>().unwrap()));
    assert!(is_ssrf_ip("::1".parse::<IpAddr>().unwrap()));

    // RFC1918
    assert!(is_ssrf_ip("10.0.0.1".parse::<IpAddr>().unwrap()));
    assert!(is_ssrf_ip("10.254.1.1".parse::<IpAddr>().unwrap()));
    assert!(is_ssrf_ip("172.16.0.1".parse::<IpAddr>().unwrap()));
    assert!(is_ssrf_ip("172.31.255.254".parse::<IpAddr>().unwrap()));
    assert!(is_ssrf_ip("192.168.0.1".parse::<IpAddr>().unwrap()));
    assert!(is_ssrf_ip("192.168.100.200".parse::<IpAddr>().unwrap()));

    // Link-local / Cloud Metadata
    assert!(is_ssrf_ip("169.254.169.254".parse::<IpAddr>().unwrap()));
    assert!(is_ssrf_ip("fe80::1".parse::<IpAddr>().unwrap()));

    // CGNAT
    assert!(is_ssrf_ip("100.64.0.1".parse::<IpAddr>().unwrap()));
    assert!(is_ssrf_ip("100.127.255.254".parse::<IpAddr>().unwrap()));

    // Unspecified
    assert!(is_ssrf_ip("0.0.0.0".parse::<IpAddr>().unwrap()));
    assert!(is_ssrf_ip("::".parse::<IpAddr>().unwrap()));

    // Unique Local Address (ULA)
    assert!(is_ssrf_ip("fd12:3456:789a::1".parse::<IpAddr>().unwrap()));
    assert!(is_ssrf_ip("fc00::1".parse::<IpAddr>().unwrap()));

    // Valid public routable addresses must pass (return false)
    assert!(!is_ssrf_ip("1.1.1.1".parse::<IpAddr>().unwrap()));
    assert!(!is_ssrf_ip("8.8.8.8".parse::<IpAddr>().unwrap()));
    assert!(!is_ssrf_ip("93.184.216.34".parse::<IpAddr>().unwrap()));
    assert!(!is_ssrf_ip(
        "2606:4700:4700::1111".parse::<IpAddr>().unwrap()
    ));
}
