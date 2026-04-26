use osoosi_audit::AuditTrail;
use osoosi_memory::MemoryStore;
use osoosi_model::MalwareScanner;
use osoosi_sandbox::{SandboxConfig, SandboxExecutor, SandboxSecurityConfig};
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
        allowed_capabilities: vec![],
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
