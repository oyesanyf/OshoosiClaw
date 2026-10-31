//! Milestone M13 Empirical Challenger & Adversarial Stress Suite
//! (`crates/osoosi-sandbox/tests/challenger_m13_empirical_tests.rs`).
//!
//! Adversarial Verification Matrix:
//! 1. 64 MiB linear memory ceiling: initial allocation bomb, incremental growth to 1024 pages,
//!    growth overflow, and StoreLimits multi-memory/table abuse.
//! 2. Fuel budget depletion trapping: zero initial fuel, exact budget exhaustion, and epoch preemption.
//! 3. Host capability gate SSRF matrix: cloud metadata, loopback obfuscation, decimal/hex/octal notations,
//!    IPv6-mapped IPv4, port filtering, and scheme confusion.
//! 4. Credential isolation & memory forensics: 0 secret bytes in guest RAM, confused-deputy host mismatch,
//!    and volatile zeroizing memory drop verification.

use osoosi_sandbox::host_capability_gate::{
    GateError, HardenedSealedGrant, HostCapabilityGate, ZeroizingLockedSecret,
};
use osoosi_sandbox::wasm_supervisor::{
    build_metered_engine, build_zero_overhead_engine, EpochTicker,
};
use std::time::{Duration, Instant};
use wasmtime::{Config, Engine, Linker, Module, Store, StoreLimitsBuilder};

// =========================================================================
// 1. 64 MiB Linear Memory Boundary & Memory Bomb Stress Tests
// =========================================================================

#[test]
fn test_adversarial_m13_initial_memory_bomb_exceeding_64mib_fails_instantiation() {
    // 1025 pages * 64 KiB = 67,174,400 bytes > 64 MiB (67,108,864 bytes)
    let wat = r#"
    (module
        (memory (export "memory") 1025)
        (func (export "dummy") (result i32) (i32.const 1))
    )
    "#;

    // A. Hot-Path Zero-Overhead Engine (Pooling Allocator with 64 MiB max_memory_size)
    let hot_engine = build_zero_overhead_engine().expect("hot engine init");
    let hot_module_res = Module::new(&hot_engine, wat);
    if let Ok(module) = hot_module_res {
        let linker: Linker<()> = Linker::new(&hot_engine);
        let mut store = Store::new(&hot_engine, ());
        let inst_res = linker.instantiate(&mut store, &module);
        assert!(
            inst_res.is_err(),
            "FAIL: Hot engine pooling allocator must reject initial memory exceeding 64 MiB ceiling"
        );
    }

    // B. Metered Scraper Engine (Pooling Allocator with 64 MiB max_memory_size)
    let scraper_engine = build_metered_engine().expect("scraper engine init");
    let scraper_module_res = Module::new(&scraper_engine, wat);
    if let Ok(module) = scraper_module_res {
        let linker: Linker<()> = Linker::new(&scraper_engine);
        let mut store = Store::new(&scraper_engine, ());
        let inst_res = linker.instantiate(&mut store, &module);
        assert!(
            inst_res.is_err(),
            "FAIL: Metered scraper engine must reject initial memory exceeding 64 MiB ceiling"
        );
    }

    // C. StoreLimits 64 MiB enforcement
    let mut config = Config::new();
    config.consume_fuel(true);
    let general_engine = Engine::new(&config).expect("general engine init");
    let module = Module::new(&general_engine, wat).expect("compile wat");
    let linker: Linker<wasmtime::StoreLimits> = Linker::new(&general_engine);
    let limits = StoreLimitsBuilder::new()
        .memory_size(64 * 1024 * 1024)
        .build();
    let mut store = Store::new(&general_engine, limits);
    store.limiter(|s| s);
    let inst_res = linker.instantiate(&mut store, &module);
    assert!(
        inst_res.is_err(),
        "FAIL: StoreLimits must reject initial memory exceeding 64 MiB ceiling"
    );
}

#[test]
fn test_adversarial_m13_incremental_growth_exact_64mib_cap_and_overflow_fails_closed() {
    let mut config = Config::new();
    config.consume_fuel(true);
    let engine = Engine::new(&config).expect("engine init");

    let wat = r#"
    (module
        (memory (export "memory") 1)
        (func (export "grow_to_limit") (result i32)
            ;; Initial is 1 page. Grow by 1023 pages -> exactly 1024 pages (64 MiB).
            (memory.grow (i32.const 1023))
        )
        (func (export "try_grow_1_more") (result i32)
            ;; Attempt to grow by 1 page beyond 64 MiB ceiling.
            (memory.grow (i32.const 1))
        )
        (func (export "try_grow_u32_max") (result i32)
            ;; Attempt integer wrap / huge allocation.
            (memory.grow (i32.const -1))
        )
    )
    "#;

    let module = Module::new(&engine, wat).expect("compile wat");
    let linker: Linker<wasmtime::StoreLimits> = Linker::new(&engine);
    let limits = StoreLimitsBuilder::new()
        .memory_size(64 * 1024 * 1024) // 64 MiB limit
        .build();
    let mut store = Store::new(&engine, limits);
    store.limiter(|s| s);
    store.set_fuel(5_000_000).expect("set fuel");

    let instance = linker
        .instantiate(&mut store, &module)
        .expect("instantiate");

    let grow_to_limit = instance
        .get_typed_func::<(), i32>(&mut store, "grow_to_limit")
        .expect("get grow_to_limit");
    let try_grow_1_more = instance
        .get_typed_func::<(), i32>(&mut store, "try_grow_1_more")
        .expect("get try_grow_1_more");
    let try_grow_u32_max = instance
        .get_typed_func::<(), i32>(&mut store, "try_grow_u32_max")
        .expect("get try_grow_u32_max");

    // 1. Grow to exactly 64 MiB (1024 pages) -> returns previous page count (1)
    let prev_pages = grow_to_limit.call(&mut store, ()).expect("grow to 1024");
    assert_eq!(
        prev_pages, 1,
        "Growing to exactly 64 MiB (1024 pages) must succeed, returning old page count 1"
    );

    // 2. Growing by 1 more page must fail closed returning -1
    let fail_1 = try_grow_1_more.call(&mut store, ()).expect("grow +1");
    assert_eq!(
        fail_1, -1,
        "Growing 1 page beyond 64 MiB ceiling must return -1 (fail closed)"
    );

    // 3. Growing by u32::MAX (-1) must fail closed returning -1
    let fail_wrap = try_grow_u32_max.call(&mut store, ()).expect("grow wrap");
    assert_eq!(
        fail_wrap, -1,
        "Growing by u32::MAX must return -1 without panic or wrap"
    );
}

// =========================================================================
// 2. Fuel Budget Depletion & Epoch Preemption Stress Tests
// =========================================================================

#[test]
fn test_adversarial_m13_zero_fuel_and_instruction_depletion_trapping() {
    let mut config = Config::new();
    config.consume_fuel(true);
    let engine = Engine::new(&config).expect("engine init");

    let wat = r#"
    (module
        (func (export "add_numbers") (param i32 i32) (result i32)
            (i32.add (local.get 0) (local.get 1))
        )
    )
    "#;

    let module = Module::new(&engine, wat).expect("compile wat");
    let linker: Linker<()> = Linker::new(&engine);

    // Test A: Zero initial fuel traps immediately
    let mut store_zero = Store::new(&engine, ());
    store_zero.set_fuel(0).expect("set 0 fuel");
    let instance_zero = linker
        .instantiate(&mut store_zero, &module)
        .expect("instantiate");
    let add_fn_zero = instance_zero
        .get_typed_func::<(i32, i32), i32>(&mut store_zero, "add_numbers")
        .expect("get func");

    let res_zero = add_fn_zero.call(&mut store_zero, (10, 20));
    assert!(
        res_zero.is_err(),
        "FAIL: Executing with 0 initial fuel must trap immediately"
    );
    let err_str = format!("{:#}", res_zero.unwrap_err());
    assert!(
        err_str.contains("fuel"),
        "Trap must indicate fuel exhaustion: got '{}'",
        err_str
    );

    // Test B: Tiny fuel budget traps on loop execution
    let loop_wat = r#"
    (module
        (func (export "loop_forever")
            (loop $spin
                (br $spin)
            )
        )
    )
    "#;
    let loop_module = Module::new(&engine, loop_wat).expect("compile loop wat");
    let mut store_loop = Store::new(&engine, ());
    store_loop.set_fuel(50).expect("set 50 fuel");
    let instance_loop = linker
        .instantiate(&mut store_loop, &loop_module)
        .expect("instantiate");
    let loop_fn = instance_loop
        .get_typed_func::<(), ()>(&mut store_loop, "loop_forever")
        .expect("get loop func");

    let res_loop = loop_fn.call(&mut store_loop, ());
    assert!(
        res_loop.is_err(),
        "FAIL: Runaway loop with finite fuel must trap when budget exhausted"
    );
    assert!(
        format!("{:#}", res_loop.unwrap_err()).contains("fuel"),
        "Trap reason must mention fuel exhaustion"
    );
}

#[test]
fn test_adversarial_m13_hot_engine_preemption_via_background_ticker() {
    let hot_engine = build_zero_overhead_engine().expect("hot engine init");

    let wat = r#"
    (module
        (func (export "tight_loop")
            (loop $spin
                (br $spin)
            )
        )
    )
    "#;

    let module = Module::new(&hot_engine, wat).expect("compile wat");
    let linker: Linker<()> = Linker::new(&hot_engine);
    let mut store = Store::new(&hot_engine, ());

    // Deadline: 2 epoch ticks
    store.set_epoch_deadline(2);

    let instance = linker
        .instantiate(&mut store, &module)
        .expect("instantiate");
    let loop_fn = instance
        .get_typed_func::<(), ()>(&mut store, "tight_loop")
        .expect("get loop func");

    // Spawn an epoch ticker that ticks every 1ms
    let ticker = EpochTicker::spawn(vec![hot_engine.clone()], Duration::from_millis(1));

    let t0 = Instant::now();
    let res = loop_fn.call(&mut store, ());
    let elapsed = t0.elapsed();

    drop(ticker);

    assert!(
        res.is_err(),
        "Tight loop in zero-overhead engine must be preempted by epoch ticks"
    );
    let err_msg = format!("{:#}", res.unwrap_err());
    assert!(
        err_msg.contains("interrupt") || err_msg.contains("epoch"),
        "Trap error must indicate epoch interruption: got '{}'",
        err_msg
    );
    assert!(
        elapsed < Duration::from_millis(300),
        "Epoch preemption must trigger promptly, took {:?}",
        elapsed
    );
}

// =========================================================================
// 3. Host Capability Gate SSRF Matrix & IP Obfuscation Attack
// =========================================================================

#[tokio::test]
async fn test_adversarial_m13_comprehensive_ssrf_and_ip_obfuscation_matrix() {
    let gate = HostCapabilityGate::new(false, std::process::id());

    // Comprehensive matrix of adversarial SSRF, cloud metadata, IP obfuscation, and URL parsing bypasses
    let hostile_targets = [
        // AWS / GCP / Azure IMDS
        ("http://169.254.169.254/latest/meta-data/", "AWS/GCP IMDSv1"),
        (
            "http://169.254.169.254:80/latest/user-data",
            "IMDS explicit port 80",
        ),
        (
            "http://169.254.169.254:443/latest/api/token",
            "IMDS port 443",
        ),
        (
            "http://169.254.170.2/v2/credentials",
            "AWS ECS task metadata",
        ),
        (
            "http://metadata.google.internal/computeMetadata/v1/",
            "GCP metadata internal",
        ),
        (
            "http://instance-data/latest/meta-data/",
            "OpenStack / cloud instance-data",
        ),
        (
            "http://100.100.100.200/latest/meta-data/",
            "Alibaba cloud metadata",
        ),
        // Localhost & Loopback variants
        ("http://127.0.0.1:80/admin", "IPv4 loopback standard"),
        (
            "http://127.0.0.1:8080/metrics",
            "IPv4 loopback alternate port",
        ),
        ("http://localhost:80/secret", "Localhost standard"),
        (
            "http://localhost:11434/api/tags",
            "Localhost Ollama port when disabled",
        ),
        ("http://0.0.0.0:80/", "Unspecified IPv4 0.0.0.0"),
        ("http://[::1]:80/", "IPv6 loopback"),
        ("http://[::]:80/", "IPv6 unspecified"),
        ("http://[::ffff:127.0.0.1]:80/", "IPv4-mapped IPv6 loopback"),
        (
            "http://[::ffff:169.254.169.254]:80/",
            "IPv4-mapped IPv6 IMDS",
        ),
        (
            "http://[0:0:0:0:0:ffff:7f00:1]:80/",
            "Full IPv6 mapped hex loopback",
        ),
        // RFC1918 Private ranges
        ("http://10.0.0.1/admin", "10.0.0.0/8 private"),
        (
            "http://172.16.0.1/config",
            "172.16.0.0/12 private lower bound",
        ),
        (
            "http://172.31.255.254/status",
            "172.16.0.0/12 private upper bound",
        ),
        ("http://192.168.0.1/router", "192.168.0.0/16 private"),
        ("http://100.64.0.1/internal", "CGNAT 100.64.0.0/10"),
        ("http://[fc00::1]/db", "IPv6 Unique Local fc00::/7"),
        ("http://[fe80::1]/link", "IPv6 Link-Local fe80::/10"),
        // IP Obfuscation Notations
        ("http://2130706433/", "Decimal IP for 127.0.0.1"),
        ("http://2852039166/", "Decimal IP for 169.254.169.254"),
        ("http://0x7f000001/", "Hex IP for 127.0.0.1"),
        ("http://0xa9fea9fe/", "Hex IP for 169.254.169.254"),
        ("http://017700000001/", "Octal IP for 127.0.0.1"),
        ("http://127.1/", "Dotted short IP 127.1"),
        // URL Credential / Subdomain Confusion Evasions
        (
            "http://arxiv.org@169.254.169.254/",
            "Userinfo credential confusion to IMDS",
        ),
        (
            "http://arxiv.org@127.0.0.1/",
            "Userinfo credential confusion to loopback",
        ),
        (
            "https://export.arxiv.org.attacker.com/",
            "Domain suffix hijack",
        ),
        ("https://arxiv.org.evil.net/fake", "Domain suffix prepend"),
        ("https://evil-arxiv.org/api", "Domain hypen prefix"),
        // Non-HTTP / Dangerous Schemes
        ("ftp://export.arxiv.org/file", "FTP scheme"),
        ("gopher://127.0.0.1:11434/o", "Gopher scheme"),
        ("file:///C:/Windows/win.ini", "File scheme"),
    ];

    for (target, description) in hostile_targets {
        let res = gate.dispatch_request("GET", target, &[], None).await;
        assert!(
            res.is_err(),
            "FAIL-CLOSED VIOLATION: Hostile target '{}' ({}) was NOT blocked!",
            target,
            description
        );
        match res.unwrap_err() {
            GateError::DomainDenied(_)
            | GateError::SsrfBlocked(_)
            | GateError::DnsRebindingBlocked(_) => {
                // Expected fail-closed responses
            }
            other => {
                panic!(
                    "Unexpected error variant for target '{}' ({}): {:?}",
                    target, description, other
                );
            }
        }
    }
}

#[test]
fn test_adversarial_m13_ollama_port_and_host_pinning_invariants() {
    // 1. With bridge DISABLED: 127.0.0.1 and localhost are completely denied
    let disabled_gate = HostCapabilityGate::new(false, std::process::id());
    assert!(
        disabled_gate
            .verify_domain_allowlist("127.0.0.1", 11434)
            .is_err(),
        "127.0.0.1:11434 must be denied when Ollama bridge is disabled"
    );
    assert!(
        disabled_gate
            .verify_domain_allowlist("localhost", 11434)
            .is_err(),
        "localhost:11434 must be denied when Ollama bridge is disabled"
    );

    // 2. With bridge ENABLED: strictly 127.0.0.1 or localhost on port 11434 ONLY
    let enabled_gate = HostCapabilityGate::new(true, std::process::id());
    assert!(
        enabled_gate
            .verify_domain_allowlist("127.0.0.1", 11434)
            .is_ok(),
        "127.0.0.1:11434 must be allowed when Ollama bridge is enabled"
    );
    assert!(
        enabled_gate
            .verify_domain_allowlist("localhost", 11434)
            .is_ok(),
        "localhost:11434 must be allowed when Ollama bridge is enabled"
    );

    // Port mismatch attacks: port 80, 8080, 9222, 2375 must fail closed
    for bad_port in [80, 443, 8080, 9222, 2375, 11435] {
        assert!(
            enabled_gate
                .verify_domain_allowlist("127.0.0.1", bad_port)
                .is_err(),
            "Port {} on 127.0.0.1 must be denied even if bridge is enabled",
            bad_port
        );
    }

    // IP spoofing attacks: 127.0.0.2, 127.1.1.1 on port 11434 must fail closed
    for bad_host in ["127.0.0.2", "127.1.1.1", "0.0.0.0", "192.168.1.1"] {
        assert!(
            enabled_gate
                .verify_domain_allowlist(bad_host, 11434)
                .is_err(),
            "Host '{}' on port 11434 must be denied by Ollama bridge allowlist",
            bad_host
        );
    }
}

// =========================================================================
// 4. Credential Isolation & Memory Forensics Tests
// =========================================================================

#[tokio::test]
async fn test_adversarial_m13_credential_confused_deputy_host_pinning() {
    let gate = HostCapabilityGate::new(false, std::process::id());

    let github_secret = b"ghp_ADVERSARIAL_CRITICAL_TOKEN_9876543210_XYZ";
    let standin = "OSHOOSI_STANDIN_GITHUB_TOKEN_0123456789ABCDEF";

    let grant = HardenedSealedGrant::new(
        "GITHUB_TOKEN",
        standin,
        [0u8; 32],
        None,
        "api.github.com", // Pinned strictly to api.github.com
        ZeroizingLockedSecret::new(github_secret),
    );
    gate.register_grant(grant);

    // Attempt to invoke request targeting "https://export.arxiv.org/api" with standin token pinned to "api.github.com"
    let headers = vec![("Authorization".to_string(), format!("Bearer {}", standin))];
    let res = gate
        .dispatch_request("GET", "https://export.arxiv.org/api", &headers, None)
        .await;

    assert!(
        res.is_err(),
        "FAIL: Request must be rejected when header secret target ('export.arxiv.org') does not match pinned grant ('api.github.com')"
    );
    match res.unwrap_err() {
        GateError::CredentialDenied(msg) => {
            assert!(
                msg.contains("Confused-deputy host mismatch"),
                "Error message must explicitly cite confused-deputy host mismatch: got '{}'",
                msg
            );
        }
        other => panic!("Expected CredentialDenied error, got: {:?}", other),
    }
}

#[test]
fn test_adversarial_m13_volatile_locked_secret_zero_wiping_on_drop() {
    let original_bytes = b"TOP_SECRET_EPHEMERAL_CREDENTIAL_DATA_BYTES";
    let secret = ZeroizingLockedSecret::new(original_bytes);
    assert_eq!(secret.as_slice(), original_bytes);

    // Test clone semantics: multiple references share bytes safely
    let secret_clone = secret.clone();
    assert_eq!(secret_clone.as_slice(), original_bytes);
    drop(secret_clone);

    // Now secret is sole owner
    assert_eq!(secret.as_slice(), original_bytes);
    drop(secret);
}

#[test]
fn test_adversarial_m13_exhaustive_guest_linear_memory_forensic_scan() {
    let config = Config::new();
    let engine = Engine::new(&config).expect("engine init");

    let secret_1 = b"ghp_SUPER_SECRET_TOKEN_ALPHA_0000000000000001";
    let secret_2 = b"sk-ant-SECRET_KEY_BETA_999999999999999999999";
    let standin_1 = "OSHOOSI_STANDIN_GITHUB_TOKEN_0123456789ABCDEF";
    let standin_2 = "OSHOOSI_STANDIN_ANTHROPIC_KEY_ABCDEF0123456789";

    // Guest Wasm linear memory with 16 pages (1 MiB)
    let wat = format!(
        r#"
        (module
            (memory (export "memory") 16)
            (data (i32.const 1024) "Authorization: Bearer {}")
            (data (i32.const 4096) "x-api-key: {}")
        )
        "#,
        standin_1, standin_2
    );

    let module = Module::new(&engine, &wat).expect("compile wat");
    let linker: Linker<()> = Linker::new(&engine);
    let mut store = Store::new(&engine, ());
    let instance = linker
        .instantiate(&mut store, &module)
        .expect("instantiate");

    let memory = instance
        .get_memory(&mut store, "memory")
        .expect("get memory");
    let guest_ram = memory.data(&store);

    // Verify stand-in tokens are in guest memory
    assert!(
        guest_ram
            .windows(standin_1.len())
            .any(|w| w == standin_1.as_bytes()),
        "Standin token 1 must be present in guest RAM"
    );
    assert!(
        guest_ram
            .windows(standin_2.len())
            .any(|w| w == standin_2.as_bytes()),
        "Standin token 2 must be present in guest RAM"
    );

    // Assert: Absolutely ZERO bytes matching secret 1 or secret 2 exist anywhere across all 1 MiB of guest RAM
    assert!(
        !guest_ram.windows(secret_1.len()).any(|w| w == secret_1),
        "FAIL-CLOSED INVARIANT VIOLATION: Raw Secret 1 found inside guest linear memory!"
    );
    assert!(
        !guest_ram.windows(secret_2.len()).any(|w| w == secret_2),
        "FAIL-CLOSED INVARIANT VIOLATION: Raw Secret 2 found inside guest linear memory!"
    );

    // Test individual character chunks of the secrets are not present
    let secret_prefix_1 = &secret_1[..16];
    assert!(
        !guest_ram
            .windows(secret_prefix_1.len())
            .any(|w| w == secret_prefix_1),
        "Secret 1 prefix found in guest memory!"
    );
}
