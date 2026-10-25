use osoosi_audit::AuditTrail;
use osoosi_memory::MemoryStore;
use osoosi_model::MalwareScanner;
use osoosi_sandbox::{Capability, SandboxConfig, SandboxExecutor, SandboxSecurityConfig};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::time::Duration;

#[tokio::test]
async fn test_wasm_traps_attack() {
    std::env::set_var("OSOOSI_NO_ORT", "1");
    let audit = Arc::new(AuditTrail::new());
    let memory = Arc::new(MemoryStore::new(":memory:").unwrap());
    let scanner = Arc::new(MalwareScanner::new(std::path::Path::new("dummy.json")));

    let executor = SandboxExecutor::new(audit, memory, scanner).unwrap();

    // Malicious WASM module that reads DB then tries to exfiltrate via network,
    // and finally attempts a destructive OS command.
    let wat = r#"
        (module
            (import "oso_brain" "host_read_db" (func $host_read_db (param i32 i32) (result i32)))
            (import "oso_brain" "host_fetch_url" (func $host_fetch_url (param i32 i32) (result i32)))
            (import "oso_brain" "host_exec_command" (func $host_exec_command (param i32 i32) (result i32)))
            
            (memory (export "memory") 1)
            
            ;; Data offset 0: "SELECT * FROM users" (19 bytes)
            (data (i32.const 0) "SELECT * FROM users")
            
            ;; Data offset 30: "http://169.254.169.254" (22 bytes)
            (data (i32.const 30) "http://169.254.169.254")
            
            ;; Data offset 60: "rm -rf /" (8 bytes)
            (data (i32.const 60) "rm -rf /")

            (func (export "_start")
                ;; 1. Read DB
                (call $host_read_db (i32.const 0) (i32.const 19))
                drop

                ;; 2. Attempt SSRF Exfiltration to cloud metadata
                (call $host_fetch_url (i32.const 30) (i32.const 22))
                drop

                ;; 3. Attempt Destructive Command
                (call $host_exec_command (i32.const 60) (i32.const 8))
                drop
            )
        )
    "#;

    let wasm_bytes = wat::parse_str(wat).expect("Failed to parse WAT");

    let config = SandboxConfig {
        max_fuel: 1_000_000,
        memory_limit_bytes: 50 * 1024 * 1024,
        wall_clock_timeout: Duration::from_secs(5),
        workspace_dir: PathBuf::from("."),
        allowed_capabilities: vec![
            Capability::FileRead("*".to_string()),
            Capability::NetworkOut("*".to_string()),
            Capability::ExecuteTool("*".to_string()),
        ],
        security_config: SandboxSecurityConfig::default(),
    };

    let result = executor
        .run_script(&wasm_bytes, config, HashSet::new())
        .await
        .unwrap();

    // Assertion: The agent's SandboxResult should flag this sequence as CRITICAL
    assert_eq!(
        result.triage_level, "CRITICAL",
        "The behavior must be detected as critical exfiltration"
    );
    assert!(
        result.suspicious_sequence,
        "The syscall sequence is highly suspicious"
    );
    assert_eq!(
        result.syscall_count, 3,
        "The sandbox must meter all 3 syscalls"
    );

    // Output forensic story showing the trap working
    println!("Forensic Story Generated:\n{}", result.forensic_story);
}

#[tokio::test]
async fn test_clean_script() {
    std::env::set_var("OSOOSI_NO_ORT", "1");
    let audit = Arc::new(AuditTrail::new());
    let memory = Arc::new(MemoryStore::new(":memory:").unwrap());
    let scanner = Arc::new(MalwareScanner::new(std::path::Path::new("dummy.json")));

    let executor = SandboxExecutor::new(audit, memory, scanner).unwrap();

    // Benign WASM module
    let wat = r#"
        (module
            (func (export "_start")
                nop
            )
        )
    "#;

    let wasm_bytes = wat::parse_str(wat).unwrap();

    let config = SandboxConfig {
        max_fuel: 1_000_000,
        memory_limit_bytes: 50 * 1024 * 1024,
        wall_clock_timeout: Duration::from_secs(5),
        workspace_dir: PathBuf::from("."),
        allowed_capabilities: vec![],
        security_config: SandboxSecurityConfig::default(),
    };

    let result = executor
        .run_script(&wasm_bytes, config, HashSet::new())
        .await
        .unwrap();

    assert_eq!(result.triage_level, "INFO");
    assert!(!result.suspicious_sequence);
    assert_eq!(result.syscall_count, 0);
}

#[tokio::test]
async fn test_capability_denial_fails_closed() {
    std::env::set_var("OSOOSI_NO_ORT", "1");
    let audit = Arc::new(AuditTrail::new());
    let memory = Arc::new(MemoryStore::new(":memory:").unwrap());
    let scanner = Arc::new(MalwareScanner::new(std::path::Path::new("dummy.json")));

    let executor = SandboxExecutor::new(audit, memory, scanner).unwrap();

    let wat = r#"
        (module
            (import "oso_brain" "host_exec_command" (func $host_exec_command (param i32 i32) (result i32)))
            (memory (export "memory") 1)
            (data (i32.const 0) "whoami")
            (func (export "_start")
                (call $host_exec_command (i32.const 0) (i32.const 6))
                drop
            )
        )
    "#;

    let wasm_bytes = wat::parse_str(wat).unwrap();

    // No capabilities granted -> execution must fail closed with an error (trap)
    let config = SandboxConfig {
        max_fuel: 1_000_000,
        memory_limit_bytes: 50 * 1024 * 1024,
        wall_clock_timeout: Duration::from_secs(5),
        workspace_dir: PathBuf::from("."),
        allowed_capabilities: vec![],
        security_config: SandboxSecurityConfig::default(),
    };

    let result = executor
        .run_script(&wasm_bytes, config, HashSet::new())
        .await;

    assert!(
        result.is_err(),
        "WASM module calling unpermitted host function must be trapped and rejected"
    );
    let err_msg = format!("{:#}", result.err().unwrap());
    assert!(
        err_msg.contains("Access denied") || err_msg.contains("capability"),
        "Error message should indicate missing capability: {}",
        err_msg
    );
}

#[tokio::test]
async fn test_capability_single_use_prevents_reuse() {
    std::env::set_var("OSOOSI_NO_ORT", "1");
    let audit = Arc::new(AuditTrail::new());
    let memory = Arc::new(MemoryStore::new(":memory:").unwrap());
    let scanner = Arc::new(MalwareScanner::new(std::path::Path::new("dummy.json")));

    let executor = SandboxExecutor::new(audit, memory, scanner).unwrap();

    // Calls host_scan_file twice in succession
    let wat = r#"
        (module
            (import "oso_brain" "host_scan_file" (func $host_scan_file (param i32 i32) (result i32)))
            (memory (export "memory") 1)
            (data (i32.const 0) "payload")
            (func (export "_start")
                ;; First call consumes capability
                (call $host_scan_file (i32.const 0) (i32.const 7))
                drop

                ;; Second call must fail because capability was consumed
                (call $host_scan_file (i32.const 0) (i32.const 7))
                drop
            )
        )
    "#;

    let wasm_bytes = wat::parse_str(wat).unwrap();

    // Only grant ONE FileRead capability token
    let config = SandboxConfig {
        max_fuel: 1_000_000,
        memory_limit_bytes: 50 * 1024 * 1024,
        wall_clock_timeout: Duration::from_secs(5),
        workspace_dir: PathBuf::from("."),
        allowed_capabilities: vec![
            Capability::FileRead("scan".to_string()),
        ],
        security_config: SandboxSecurityConfig::default(),
    };

    let result = executor
        .run_script(&wasm_bytes, config, HashSet::new())
        .await;

    assert!(
        result.is_err(),
        "Second call must trap because single-use capability was already consumed"
    );
    let err_msg = format!("{:#}", result.err().unwrap());
    assert!(
        err_msg.contains("Access denied") || err_msg.contains("capability"),
        "Error must report access denied on reuse: {}",
        err_msg
    );
}

#[tokio::test]
async fn test_dns_pinning_ssrf() {
    std::env::set_var("OSOOSI_NO_ORT", "1");
    let audit = Arc::new(AuditTrail::new());
    let memory = Arc::new(MemoryStore::new(":memory:").unwrap());
    let scanner = Arc::new(MalwareScanner::new(std::path::Path::new("dummy.json")));

    let host = osoosi_sandbox::native_host::NativeHost::new(audit, memory, scanner);

    // 1. SSRF Cloud Metadata should be blocked
    let envelope_imds = osoosi_sandbox::host_interface::HostCallEnvelope {
        call_id: "test-ssrf-1".to_string(),
        caller_module: "test".to_string(),
        call: osoosi_sandbox::host_interface::HostCall::FetchUrl {
            url: "http://169.254.169.254/latest/meta-data/".to_string(),
            method: "GET".to_string(),
            headers: vec![],
        },
        fuel_remaining: 1000,
        taint_labels: vec![],
        timestamp: chrono::Utc::now(),
    };
    let resp = host.dispatch(envelope_imds).await;
    match resp.response {
        osoosi_sandbox::host_interface::HostResponse::Error { message } => {
            assert!(message.contains("SSRF Violation") || message.contains("blocked"), "Unexpected message: {}", message);
        }
        other => panic!("Expected Error response for SSRF metadata, got: {:?}", other),
    }

    // 2. Loopback should be blocked
    let envelope_loopback = osoosi_sandbox::host_interface::HostCallEnvelope {
        call_id: "test-ssrf-2".to_string(),
        caller_module: "test".to_string(),
        call: osoosi_sandbox::host_interface::HostCall::FetchUrl {
            url: "http://127.0.0.1:11434/api/tags".to_string(),
            method: "GET".to_string(),
            headers: vec![],
        },
        fuel_remaining: 1000,
        taint_labels: vec![],
        timestamp: chrono::Utc::now(),
    };
    let resp_loop = host.dispatch(envelope_loopback).await;
    match resp_loop.response {
        osoosi_sandbox::host_interface::HostResponse::Error { message } => {
            assert!(message.contains("SSRF Violation") || message.contains("blocked"), "Unexpected message: {}", message);
        }
        other => panic!("Expected Error response for loopback, got: {:?}", other),
    }

    // 3. GSB Phishing test vector should be blocked
    let envelope_gsb = osoosi_sandbox::host_interface::HostCallEnvelope {
        call_id: "test-gsb-1".to_string(),
        caller_module: "test".to_string(),
        call: osoosi_sandbox::host_interface::HostCall::FetchUrl {
            url: "http://testsafebrowsing.appspot.com/s/phishing.html".to_string(),
            method: "GET".to_string(),
            headers: vec![],
        },
        fuel_remaining: 1000,
        taint_labels: vec![],
        timestamp: chrono::Utc::now(),
    };
    let resp_gsb = host.dispatch(envelope_gsb).await;
    match resp_gsb.response {
        osoosi_sandbox::host_interface::HostResponse::Error { message } => {
            assert!(message.contains("Google Safe Browsing blocked") || message.contains("threat"), "Unexpected message: {}", message);
        }
        other => panic!("Expected Error response for GSB threat, got: {:?}", other),
    }
}
