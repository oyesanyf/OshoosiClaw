//! Adversarial Stress Testing of Tier-1 Wasmtime Confinement
//!
//! Empirically challenges and verifies:
//! 1. Linear memory growth > 64 MiB is blocked (both initial declaration and dynamic memory.grow).
//! 2. Infinite loops and recursive loops exhaust fuel and terminate execution without hanging.
//! 3. Capability tokens cannot be reused once consumed (single-use validation across hostcalls and wildcards).
//! 4. Unauthorized hostcalls without capabilities fail closed immediately.

use osoosi_audit::AuditTrail;
use osoosi_memory::MemoryStore;
use osoosi_model::MalwareScanner;
use osoosi_sandbox::{Capability, SandboxConfig, SandboxExecutor, SandboxSecurityConfig};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::time::{Duration, Instant};

fn setup_executor() -> SandboxExecutor {
    std::env::set_var("OSOOSI_NO_ORT", "1");
    let audit = Arc::new(AuditTrail::new());
    let memory = Arc::new(MemoryStore::new(":memory:").expect("Failed to create memory store"));
    let scanner = Arc::new(MalwareScanner::new(std::path::Path::new("dummy.json")));
    SandboxExecutor::new(audit, memory, scanner).expect("Failed to create SandboxExecutor")
}

// =========================================================================
// CHALLENGE 1: Linear memory growth > 64 MiB is blocked
// =========================================================================

#[tokio::test]
async fn challenge_1a_linear_memory_initial_exceeding_64mib_fails_closed() {
    let executor = setup_executor();

    // 1025 pages * 64 KiB = 67,174,400 bytes (> 64 MiB = 67,108,864 bytes)
    let wat = r#"
        (module
            (memory (export "memory") 1025)
            (func (export "_start")
                nop
            )
        )
    "#;
    let wasm_bytes = wat::parse_str(wat).expect("WAT parse error");

    let config = SandboxConfig::default(); // default has 64 MiB limit
    let result = executor.run_script(&wasm_bytes, config, HashSet::new()).await;

    assert!(
        result.is_err(),
        "Instantiating a module with initial memory exceeding 64 MiB must fail closed"
    );
    let err_str = format!("{:#}", result.err().unwrap());
    assert!(
        err_str.to_lowercase().contains("resource")
            || err_str.to_lowercase().contains("memory")
            || err_str.to_lowercase().contains("limit"),
        "Error message should reflect memory/resource limit: {}",
        err_str
    );
}

#[tokio::test]
async fn challenge_1b_linear_memory_dynamic_grow_beyond_64mib_blocked() {
    let executor = setup_executor();

    // Starts with 1 page (64 KiB).
    // Attempts to grow by 1024 pages (total 1025 pages > 64 MiB).
    // In WebAssembly, memory.grow returns -1 (0xFFFFFFFF) when resource limiter denies growth.
    // If growth succeeded, the function intentionally traps with unreachable.
    // If growth was denied (as required), it attempts to store to page 2 (offset 70,000),
    // which must trap with out-of-bounds memory access because memory was NOT grown.
    let wat = r#"
        (module
            (memory (export "memory") 1)
            (func (export "_start")
                ;; Attempt to grow by 1024 pages
                (i32.const 1024)
                (memory.grow)
                ;; If return value != -1, memory.grow erroneously succeeded -> trap immediately
                (i32.const -1)
                (i32.ne)
                (if
                    (then
                        unreachable
                    )
                )
                ;; Storing to offset 70,000 (> 65536) must trap with out of bounds
                (i32.const 70000)
                (i32.const 1337)
                (i32.store)
            )
        )
    "#;
    let wasm_bytes = wat::parse_str(wat).expect("WAT parse error");

    let config = SandboxConfig::default();
    let result = executor.run_script(&wasm_bytes, config, HashSet::new()).await;

    assert!(
        result.is_err(),
        "Writing to unallocated memory after denied memory.grow must trap"
    );
    let err_str = format!("{:#}", result.err().unwrap());
    assert!(
        err_str.contains("out of bounds") || err_str.contains("bounds"),
        "Expected out of bounds memory trap, got: {}",
        err_str
    );
}

#[tokio::test]
async fn challenge_1c_linear_memory_exact_boundary_64mib_allowed_and_64mib_plus_one_page_denied() {
    let executor = setup_executor();

    // 1024 pages * 64 KiB = exactly 64 MiB (67,108,864 bytes).
    // Exactly 64 MiB should be permitted.
    let wat_exact = r#"
        (module
            (memory (export "memory") 1024)
            (func (export "_start")
                nop
            )
        )
    "#;
    let wasm_exact = wat::parse_str(wat_exact).expect("WAT parse error");
    let config = SandboxConfig::default();
    let res_exact = executor.run_script(&wasm_exact, config.clone(), HashSet::new()).await;
    assert!(
        res_exact.is_ok(),
        "Module with exactly 64 MiB (1024 pages) should be permitted under 64 MiB cap: {:?}",
        res_exact.err()
    );

    // Now test that growing from 1024 by 1 additional page returns -1
    let wat_plus_one = r#"
        (module
            (memory (export "memory") 1024)
            (func (export "_start")
                ;; Attempt to grow by 1 page (1024 -> 1025 pages)
                (i32.const 1)
                (memory.grow)
                ;; Assert return value is -1 (failure)
                (i32.const -1)
                (i32.eq)
                ;; If NOT -1 (eq returned 0), trap
                (i32.eqz)
                (if
                    (then
                        unreachable
                    )
                )
            )
        )
    "#;
    let wasm_plus_one = wat::parse_str(wat_plus_one).expect("WAT parse error");
    let res_plus_one = executor.run_script(&wasm_plus_one, config, HashSet::new()).await;
    assert!(
        res_plus_one.is_ok(),
        "memory.grow(1) beyond 1024 pages must return -1 without trapping: {:?}",
        res_plus_one.err()
    );
}

// =========================================================================
// CHALLENGE 2: Infinite loops exhaust fuel and terminate execution
// =========================================================================

#[tokio::test]
async fn challenge_2a_infinite_loop_exhausts_fuel_and_terminates() {
    let executor = setup_executor();

    let wat = r#"
        (module
            (func (export "_start")
                (loop $infinite
                    (br $infinite)
                )
            )
        )
    "#;
    let wasm_bytes = wat::parse_str(wat).expect("WAT parse error");

    let config = SandboxConfig {
        max_fuel: 50_000,
        memory_limit_bytes: 64 * 1024 * 1024,
        wall_clock_timeout: Duration::from_secs(10), // large timeout to prove fuel halts it first
        workspace_dir: PathBuf::from("."),
        allowed_capabilities: vec![],
        security_config: SandboxSecurityConfig::default(),
    };

    let start = Instant::now();
    let result = executor.run_script(&wasm_bytes, config, HashSet::new()).await;
    let elapsed = start.elapsed();

    assert!(
        result.is_err(),
        "Infinite loop must be terminated when fuel is exhausted"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "Fuel exhaustion should terminate in milliseconds, took {:?}",
        elapsed
    );

    let err_str = format!("{:#}", result.err().unwrap());
    assert!(
        err_str.contains("fuel") || err_str.contains("Fuel"),
        "Error message must indicate fuel exhaustion: {}",
        err_str
    );
}

#[tokio::test]
async fn challenge_2b_infinite_recursion_exhausts_fuel_and_terminates() {
    let executor = setup_executor();

    let wat = r#"
        (module
            (func $recurse (export "_start")
                (call $recurse)
            )
        )
    "#;
    let wasm_bytes = wat::parse_str(wat).expect("WAT parse error");

    let config = SandboxConfig {
        max_fuel: 100_000,
        memory_limit_bytes: 64 * 1024 * 1024,
        wall_clock_timeout: Duration::from_secs(10),
        workspace_dir: PathBuf::from("."),
        allowed_capabilities: vec![],
        security_config: SandboxSecurityConfig::default(),
    };

    let start = Instant::now();
    let result = executor.run_script(&wasm_bytes, config, HashSet::new()).await;
    let elapsed = start.elapsed();

    assert!(
        result.is_err(),
        "Infinite recursion must trap deterministically"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "Recursion trap must trigger promptly, took {:?}",
        elapsed
    );
}

#[tokio::test]
async fn challenge_2c_hostcall_fuel_exhaustion_terminates_execution() {
    let executor = setup_executor();

    // host_scan_file requires at least 500 fuel.
    // If only 100 fuel is configured, the hostcall must reject execution with out of fuel.
    let wat = r#"
        (module
            (import "oso_brain" "host_scan_file" (func $host_scan_file (param i32 i32) (result i32)))
            (memory (export "memory") 1)
            (data (i32.const 0) "test")
            (func (export "_start")
                (call $host_scan_file (i32.const 0) (i32.const 4))
                drop
            )
        )
    "#;
    let wasm_bytes = wat::parse_str(wat).expect("WAT parse error");

    let config = SandboxConfig {
        max_fuel: 100, // Insufficient fuel for host_scan_file (costs 500 + len)
        memory_limit_bytes: 64 * 1024 * 1024,
        wall_clock_timeout: Duration::from_secs(5),
        workspace_dir: PathBuf::from("."),
        allowed_capabilities: vec![Capability::FileRead("scan".to_string())],
        security_config: SandboxSecurityConfig::default(),
    };

    let result = executor.run_script(&wasm_bytes, config, HashSet::new()).await;
    assert!(
        result.is_err(),
        "Hostcall without sufficient fuel must fail closed"
    );
    let err_str = format!("{:#}", result.err().unwrap());
    assert!(
        err_str.contains("fuel") || err_str.contains("Fuel"),
        "Error must report fuel exhaustion: {}",
        err_str
    );
}

// =========================================================================
// CHALLENGE 3: Capability tokens cannot be reused once consumed
// =========================================================================

#[tokio::test]
async fn challenge_3a_single_use_capability_token_exhausted_on_second_call() {
    let executor = setup_executor();

    let wat = r#"
        (module
            (import "oso_brain" "host_write_audit" (func $host_write_audit (param i32 i32) (result i32)))
            (memory (export "memory") 1)
            ;; JSON: {"action":"test"} (17 bytes)
            (data (i32.const 0) "{\"action\":\"test\"}")
            (func (export "_start")
                ;; First call consumes the single FileWrite("audit") capability
                (call $host_write_audit (i32.const 0) (i32.const 17))
                drop

                ;; Second call must fail because token was consumed
                (call $host_write_audit (i32.const 0) (i32.const 17))
                drop
            )
        )
    "#;
    let wasm_bytes = wat::parse_str(wat).expect("WAT parse error");

    let config = SandboxConfig {
        max_fuel: 500_000,
        memory_limit_bytes: 64 * 1024 * 1024,
        wall_clock_timeout: Duration::from_secs(5),
        workspace_dir: PathBuf::from("."),
        allowed_capabilities: vec![Capability::FileWrite("audit".to_string())],
        security_config: SandboxSecurityConfig::default(),
    };

    let result = executor.run_script(&wasm_bytes, config, HashSet::new()).await;
    assert!(
        result.is_err(),
        "Second host_write_audit must fail because capability was consumed on first call"
    );
    let err_str = format!("{:#}", result.err().unwrap());
    assert!(
        err_str.contains("Access denied") || err_str.contains("capability"),
        "Error message should indicate missing/consumed capability: {}",
        err_str
    );
}

#[tokio::test]
async fn challenge_3b_wildcard_capability_consumed_on_first_use() {
    let executor = setup_executor();

    // Module attempts to use a wildcard FileRead("*") token twice.
    let wat = r#"
        (module
            (import "oso_brain" "host_scan_file" (func $host_scan_file (param i32 i32) (result i32)))
            (memory (export "memory") 1)
            (data (i32.const 0) "file_a")
            (data (i32.const 16) "file_b")
            (func (export "_start")
                ;; First scan consumes the single wildcard capability
                (call $host_scan_file (i32.const 0) (i32.const 6))
                drop

                ;; Second scan must fail because the wildcard token was consumed
                (call $host_scan_file (i32.const 16) (i32.const 6))
                drop
            )
        )
    "#;
    let wasm_bytes = wat::parse_str(wat).expect("WAT parse error");

    let config = SandboxConfig {
        max_fuel: 500_000,
        memory_limit_bytes: 64 * 1024 * 1024,
        wall_clock_timeout: Duration::from_secs(5),
        workspace_dir: PathBuf::from("."),
        allowed_capabilities: vec![Capability::FileRead("*".to_string())],
        security_config: SandboxSecurityConfig::default(),
    };

    let result = executor.run_script(&wasm_bytes, config, HashSet::new()).await;
    assert!(
        result.is_err(),
        "Wildcard capability token must be single-use and rejected on second call"
    );
    let err_str = format!("{:#}", result.err().unwrap());
    assert!(
        err_str.contains("Access denied") || err_str.contains("capability"),
        "Error message should indicate missing capability: {}",
        err_str
    );
}

// =========================================================================
// CHALLENGE 4: Unauthorized hostcalls without capabilities fail closed
// =========================================================================

#[tokio::test]
async fn challenge_4a_unauthorized_hostcalls_with_zero_capabilities_fail_closed() {
    let executor = setup_executor();

    // Test each hostcall with 0 capabilities granted
    let test_cases = vec![
        ("host_scan_file", r#"
            (module
                (import "oso_brain" "host_scan_file" (func $f (param i32 i32) (result i32)))
                (memory (export "memory") 1)
                (data (i32.const 0) "data")
                (func (export "_start")
                    (call $f (i32.const 0) (i32.const 4))
                    drop
                )
            )
        "#),
        ("host_read_db", r#"
            (module
                (import "oso_brain" "host_read_db" (func $f (param i32 i32) (result i32)))
                (memory (export "memory") 1)
                (data (i32.const 0) "SELECT 1")
                (func (export "_start")
                    (call $f (i32.const 0) (i32.const 8))
                    drop
                )
            )
        "#),
        ("host_send_mesh", r#"
            (module
                (import "oso_brain" "host_send_mesh" (func $f (param i32 i32 i32 i32) (result i32)))
                (memory (export "memory") 1)
                (data (i32.const 0) "topic")
                (data (i32.const 16) "data")
                (func (export "_start")
                    (call $f (i32.const 0) (i32.const 5) (i32.const 16) (i32.const 4))
                    drop
                )
            )
        "#),
        ("host_write_audit", r#"
            (module
                (import "oso_brain" "host_write_audit" (func $f (param i32 i32) (result i32)))
                (memory (export "memory") 1)
                (data (i32.const 0) "{\"k\":\"v\"}")
                (func (export "_start")
                    (call $f (i32.const 0) (i32.const 9))
                    drop
                )
            )
        "#),
    ];

    for (name, wat) in test_cases {
        let wasm_bytes = wat::parse_str(wat).expect("WAT parse error");
        let config = SandboxConfig {
            max_fuel: 500_000,
            memory_limit_bytes: 64 * 1024 * 1024,
            wall_clock_timeout: Duration::from_secs(5),
            workspace_dir: PathBuf::from("."),
            allowed_capabilities: vec![], // Zero capabilities
            security_config: SandboxSecurityConfig::default(),
        };

        let result = executor.run_script(&wasm_bytes, config, HashSet::new()).await;
        assert!(
            result.is_err(),
            "Hostcall {} without capabilities must fail closed",
            name
        );
        let err_str = format!("{:#}", result.err().unwrap());
        assert!(
            err_str.contains("Access denied") || err_str.contains("capability"),
            "Error for {} should indicate missing capability: {}",
            name,
            err_str
        );
    }
}

#[tokio::test]
async fn challenge_4b_mismatched_capability_fails_closed() {
    let executor = setup_executor();

    // Module attempts host_exec_command ("whoami"), but only has FileRead("scan") capability
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
    let wasm_bytes = wat::parse_str(wat).expect("WAT parse error");

    let config = SandboxConfig {
        max_fuel: 500_000,
        memory_limit_bytes: 64 * 1024 * 1024,
        wall_clock_timeout: Duration::from_secs(5),
        workspace_dir: PathBuf::from("."),
        allowed_capabilities: vec![Capability::FileRead("scan".to_string())], // Mismatched capability
        security_config: SandboxSecurityConfig::default(),
    };

    let result = executor.run_script(&wasm_bytes, config, HashSet::new()).await;
    assert!(
        result.is_err(),
        "Hostcall with mismatched capability type must fail closed"
    );
    let err_str = format!("{:#}", result.err().unwrap());
    assert!(
        err_str.contains("Access denied") || err_str.contains("capability"),
        "Error must indicate missing required capability: {}",
        err_str
    );
}
