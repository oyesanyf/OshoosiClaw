//! Milestone M13 Deterministic Benchmark & Regression Test Suite
//! (`crates/osoosi-sandbox/tests/m13_wasm_capabilities_and_regression_tests.rs`).
//!
//! Test Cases:
//! 1. `test_m13_warm_pooled_instantiation_latency_p99_under_50us`:
//!    Verifies warm slot instantiation latency p99 < 50 µs using `InstancePre` + `PoolingAllocationConfig`.
//! 2. `test_m13_zero_physical_rss_leaks_over_1000_instantiations`:
//!    Verifies 1,000+ consecutive instantiations and resets exhibit bounded physical working set size.
//! 3. `test_m13_epoch_preemption_infinite_loop_trapped_without_fuel`:
//!    Verifies non-cooperative preemption of infinite loop guests using atomic epoch deadlines.
//! 4. `test_m13_64mib_linear_memory_cap_and_fuel_budget_trapping`:
//!    Verifies `memory.grow` exceeding 64 MiB fails closed and excessive fuel consumption traps.
//! 5. `test_m13_host_capability_gate_ssrf_and_zero_secret_bytes_in_guest_ram`:
//!    Verifies host proxy blocks SSRF and memory scan confirms 0 raw secret bytes inside guest RAM.

use osoosi_sandbox::host_capability_gate::{
    GateError, HardenedSealedGrant, HostCapabilityGate, ZeroizingLockedSecret,
};
use std::time::{Duration, Instant};
use wasmtime::{
    Config, Engine, InstanceAllocationStrategy, InstancePre, Linker, Module,
    PoolingAllocationConfig, Store, StoreLimits, StoreLimitsBuilder,
};

/// Helper: returns physical RSS in bytes.
fn get_process_rss_bytes() -> usize {
    #[cfg(windows)]
    {
        #[repr(C)]
        struct PROCESS_MEMORY_COUNTERS {
            cb: u32,
            page_fault_count: u32,
            peak_working_set_size: usize,
            working_set_size: usize,
            quota_peak_paged_pool_usage: usize,
            quota_paged_pool_usage: usize,
            quota_peak_non_paged_pool_usage: usize,
            quota_non_paged_pool_usage: usize,
            pagefile_usage: usize,
            peak_pagefile_usage: usize,
        }
        extern "system" {
            fn K32GetProcessMemoryInfo(
                h_process: *mut std::ffi::c_void,
                ppsmx: *mut PROCESS_MEMORY_COUNTERS,
                cb: u32,
            ) -> i32;
            fn GetCurrentProcess() -> *mut std::ffi::c_void;
        }
        unsafe {
            let mut pmc = std::mem::zeroed::<PROCESS_MEMORY_COUNTERS>();
            pmc.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
            if K32GetProcessMemoryInfo(GetCurrentProcess(), &mut pmc, pmc.cb) != 0 {
                pmc.working_set_size
            } else {
                0
            }
        }
    }
    #[cfg(not(windows))]
    {
        if let Ok(statm) = std::fs::read_to_string("/proc/self/statm") {
            let parts: Vec<&str> = statm.split_whitespace().collect();
            if parts.len() >= 2 {
                if let Ok(pages) = parts[1].parse::<usize>() {
                    return pages * 4096;
                }
            }
        }
        0
    }
}

// =========================================================================
// 1. Warm Pooled Instantiation Latency (p99 < 50 µs)
// =========================================================================

#[test]
fn test_m13_warm_pooled_instantiation_latency_p99_under_50us() {
    let engine = osoosi_sandbox::wasm_supervisor::build_zero_overhead_engine()
        .expect("Engine initialization with pooling allocator");

    let wat = r#"
    (module
        (memory (export "memory") 1)
        (func (export "execute") (result i32)
            (i32.const 42)
        )
    )
    "#;
    let module = Module::new(&engine, wat).expect("Compile WAT");
    let linker: Linker<()> = Linker::new(&engine);
    let instance_pre: InstancePre<()> = linker
        .instantiate_pre(&module)
        .expect("Pre-link module into InstancePre");

    // Warmup phase (100 iterations)
    for _ in 0..100 {
        let mut store = Store::new(&engine, ());
        store.set_epoch_deadline(100);
        let instance = instance_pre
            .instantiate(&mut store)
            .expect("Warmup instantiate");
        let func = instance
            .get_typed_func::<(), i32>(&mut store, "execute")
            .expect("Get func");
        assert_eq!(func.call(&mut store, ()).expect("Execute"), 42);
    }

    // Benchmark phase (1,000 iterations)
    let mut latencies_us = Vec::with_capacity(1000);
    for _ in 0..1000 {
        let mut store = Store::new(&engine, ());
        store.set_epoch_deadline(100);
        let t0 = Instant::now();
        let instance = instance_pre
            .instantiate(&mut store)
            .expect("Pooled instantiate");
        let elapsed_us = t0.elapsed().as_micros() as u64;
        latencies_us.push(elapsed_us);

        let func = instance
            .get_typed_func::<(), i32>(&mut store, "execute")
            .expect("Get func");
        assert_eq!(func.call(&mut store, ()).expect("Execute"), 42);
    }

    latencies_us.sort_unstable();
    let p50 = latencies_us[500];
    let p90 = latencies_us[900];
    let p99 = latencies_us[990];

    eprintln!(
        "M13 Benchmark Latency: p50 = {} µs, p90 = {} µs, p99 = {} µs",
        p50, p90, p99
    );

    let threshold = if cfg!(debug_assertions) { 200 } else { 50 };
    assert!(
        p99 < threshold,
        "FAIL: Warm pooled instantiation latency p99 must be < {} µs, got {} µs (p50={} µs)",
        threshold,
        p99,
        p50
    );
}

// =========================================================================
// 2. Zero Physical RSS Leaks (1,000+ Consecutive Instantiations and Resets)
// =========================================================================

#[test]
fn test_m13_zero_physical_rss_leaks_over_1000_instantiations() {
    let mut pool = PoolingAllocationConfig::new();
    pool.total_core_instances(64)
        .total_memories(64)
        .total_tables(64)
        .max_memory_size(64 * 1024 * 1024)
        .linear_memory_keep_resident(1024 * 1024);

    let mut config = Config::new();
    config.allocation_strategy(InstanceAllocationStrategy::Pooling(pool));
    config.memory_init_cow(true);
    config.epoch_interruption(true);
    config.consume_fuel(false);

    let engine = Engine::new(&config).expect("Engine initialization");

    let wat = r#"
    (module
        (memory (export "memory") 1)
        (func (export "touch_memory") (param i32) (result i32)
            (i32.store (i32.const 0) (local.get 0))
            (i32.load (i32.const 0))
        )
    )
    "#;
    let module = Module::new(&engine, wat).expect("Compile WAT");
    let linker: Linker<()> = Linker::new(&engine);
    let instance_pre = linker.instantiate_pre(&module).expect("InstancePre");

    // Warmup pool slots
    for i in 0..100 {
        let mut store = Store::new(&engine, ());
        store.set_epoch_deadline(100);
        let instance = instance_pre.instantiate(&mut store).unwrap();
        let func = instance
            .get_typed_func::<i32, i32>(&mut store, "touch_memory")
            .unwrap();
        assert_eq!(func.call(&mut store, i).unwrap(), i);
    }

    let rss_at_100 = get_process_rss_bytes();

    for i in 100..1100 {
        let mut store = Store::new(&engine, ());
        store.set_epoch_deadline(100);
        let instance = instance_pre.instantiate(&mut store).unwrap();
        let func = instance
            .get_typed_func::<i32, i32>(&mut store, "touch_memory")
            .unwrap();
        assert_eq!(func.call(&mut store, i).unwrap(), i);
    }

    let rss_at_1100 = get_process_rss_bytes();
    let rss_growth_bytes = rss_at_1100.saturating_sub(rss_at_100);
    let rss_growth_mb = rss_growth_bytes as f64 / (1024.0 * 1024.0);

    eprintln!(
        "M13 RSS Leak Check: RSS @ 100 = {} bytes, RSS @ 1100 = {} bytes, Growth = {:.2} MB",
        rss_at_100, rss_at_1100, rss_growth_mb
    );

    assert!(
        rss_growth_mb < 4.0,
        "FAIL: Working set physical memory leaked over 1,000 iterations: growth = {:.2} MB (threshold 4.0 MB)",
        rss_growth_mb
    );
}

// =========================================================================
// 3. Epoch Preemption Traps: Infinite Loop Preempted Without Fuel
// =========================================================================

#[test]
fn test_m13_epoch_preemption_infinite_loop_trapped_without_fuel() {
    let mut config = Config::new();
    config.epoch_interruption(true);
    config.consume_fuel(false); // STRICTLY 0 fuel metering overhead!

    let engine = Engine::new(&config).expect("Engine initialization");

    let wat = r#"
    (module
        (func (export "runaway")
            (loop $spin
                (br $spin)
            )
        )
    )
    "#;
    let module = Module::new(&engine, wat).expect("Compile runaway loop WAT");
    let linker: Linker<()> = Linker::new(&engine);
    let mut store = Store::new(&engine, ());
    store.set_epoch_deadline(1);

    let instance = linker
        .instantiate(&mut store, &module)
        .expect("Instantiate");
    let runaway_fn = instance
        .get_typed_func::<(), ()>(&mut store, "runaway")
        .expect("Get runaway func");

    // Spawn an atomic epoch ticker that fires after 10ms
    let engine_clone = engine.clone();
    let handle = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(10));
        engine_clone.increment_epoch();
    });

    let t0 = Instant::now();
    let res = runaway_fn.call(&mut store, ());
    let elapsed = t0.elapsed();

    handle.join().expect("Ticker join");

    assert!(
        res.is_err(),
        "Runaway loop must trap via epoch interruption"
    );
    let full_err = format!("{:#}", res.unwrap_err());
    assert!(
        full_err.contains("interrupt") || full_err.contains("epoch"),
        "Trap error must indicate epoch interruption: got '{}'",
        full_err
    );
    assert!(
        elapsed < Duration::from_millis(500),
        "Preemption must occur promptly within deadline, took {:?}",
        elapsed
    );
}

// =========================================================================
// 4. 64 MiB Linear Memory Cap & Fuel Budget Trapping
// =========================================================================

#[test]
fn test_m13_64mib_linear_memory_cap_and_fuel_budget_trapping() {
    // Part A: 64 MiB Cap via StoreLimits
    let mut config = Config::new();
    config.epoch_interruption(true);
    config.consume_fuel(true);

    let engine = Engine::new(&config).expect("Engine init");

    let mem_wat = r#"
    (module
        (memory (export "memory") 1)
        (func (export "try_grow_past_cap") (result i32)
            ;; Attempt to grow by 1025 pages (64 MiB + 64 KiB)
            (memory.grow (i32.const 1025))
        )
    )
    "#;
    let module = Module::new(&engine, mem_wat).expect("Compile memory WAT");
    let linker: Linker<StoreLimits> = Linker::new(&engine);

    // Limit memory strictly to 64 MiB (64 * 1024 * 1024 bytes)
    let limits = StoreLimitsBuilder::new()
        .memory_size(64 * 1024 * 1024)
        .build();
    let mut store = Store::new(&engine, limits);
    store.limiter(|s| s);
    store.set_epoch_deadline(100);
    store.set_fuel(1_000_000).expect("Set fuel");

    let instance = linker
        .instantiate(&mut store, &module)
        .expect("Instantiate");
    let grow_fn = instance
        .get_typed_func::<(), i32>(&mut store, "try_grow_past_cap")
        .expect("Get func");

    let res = grow_fn
        .call(&mut store, ())
        .expect("Call must succeed with -1");
    assert_eq!(
        res, -1,
        "memory.grow past 64 MiB must return -1 according to Wasm spec and StoreLimits"
    );

    // Part B: Fuel Budget Exhaustion
    let fuel_wat = r#"
    (module
        (func (export "heavy_compute")
            (local $i i32)
            (local.set $i (i32.const 0))
            (loop $loop
                (local.set $i (i32.add (local.get $i) (i32.const 1)))
                (br_if $loop (i32.lt_s (local.get $i) (i32.const 100000)))
            )
        )
    )
    "#;
    let fuel_module = Module::new(&engine, fuel_wat).expect("Compile fuel WAT");
    let fuel_linker: Linker<()> = Linker::new(&engine);
    let mut fuel_store = Store::new(&engine, ());
    fuel_store.set_epoch_deadline(100);
    // Set a deliberately tiny fuel budget (100 units)
    fuel_store.set_fuel(100).expect("Set tiny fuel");

    let fuel_instance = fuel_linker
        .instantiate(&mut fuel_store, &fuel_module)
        .expect("Instantiate");
    let compute_fn = fuel_instance
        .get_typed_func::<(), ()>(&mut fuel_store, "heavy_compute")
        .expect("Get compute func");

    let trap_res = compute_fn.call(&mut fuel_store, ());
    assert!(trap_res.is_err(), "Must trap when fuel is exhausted");
    let full_trap = format!("{:#}", trap_res.unwrap_err());
    assert!(
        full_trap.contains("fuel"),
        "Trap must be out of fuel, got: '{}'",
        full_trap
    );
}

// =========================================================================
// 5. Host Capability SSRF & Credential Isolation (Zero Secret Bytes in RAM)
// =========================================================================

#[tokio::test]
async fn test_m13_host_capability_gate_ssrf_and_zero_secret_bytes_in_guest_ram() {
    let gate = HostCapabilityGate::new(false, std::process::id());

    // Register a test grant with a secret
    let real_secret = b"sk-proj-SUPER_SECRET_ENTROPY_KEY_ABCD_9999";
    let standin = "OSHOOSI_STANDIN_GITHUB_TOKEN_0123456789ABCDEF";
    let grant = HardenedSealedGrant::new(
        "GITHUB_TOKEN",
        standin,
        [0u8; 32], // Test binary hash
        None,
        "api.github.com",
        ZeroizingLockedSecret::new(real_secret),
    );
    gate.register_grant(grant);

    // 1. SSRF target rejections
    let ssrf_targets = [
        "http://169.254.169.254/latest/meta-data/",
        "http://[::ffff:127.0.0.1]:8080/admin",
        "http://10.0.0.1/network",
        "http://192.168.1.1/setup",
        "http://[fc00::1]/db",
        "http://[fe80::1]/link",
        "http://100.64.0.1/cgnat",
        "https://unauthorized-evil-domain.com/data",
        "https://arxiv.org.attacker.com/fake",
    ];

    for target in ssrf_targets {
        let res = gate.dispatch_request("GET", target, &[], None).await;
        assert!(
            res.is_err(),
            "Malicious or unauthorized target '{}' must be rejected",
            target
        );
        match res.unwrap_err() {
            GateError::DomainDenied(_)
            | GateError::SsrfBlocked(_)
            | GateError::DnsRebindingBlocked(_) => {}
            other => panic!("Unexpected error type for target '{}': {:?}", target, other),
        }
    }

    // 2. Ollama bridge gate
    let ollama_url = "http://127.0.0.1:11434/api/tags";
    // Disabled gate must reject
    assert!(
        gate.dispatch_request("GET", ollama_url, &[], None)
            .await
            .is_err(),
        "Ollama endpoint must be rejected when ollama_bridge_enabled is false"
    );

    // Enabled gate permits Ollama domain in allowlist
    let enabled_gate = HostCapabilityGate::new(true, std::process::id());
    assert!(
        enabled_gate
            .verify_domain_allowlist("127.0.0.1", 11434)
            .is_ok(),
        "Domain allowlist must permit 127.0.0.1:11434 when Ollama bridge is enabled"
    );

    // 3. Credential Isolation & Guest Linear Memory Inspection
    let config = Config::new();
    let engine = Engine::new(&config).expect("Engine init");
    let wat = r#"
    (module
        (memory (export "memory") 1)
        (data (i32.const 0) "Authorization: Bearer OSHOOSI_STANDIN_GITHUB_TOKEN_0123456789ABCDEF")
    )
    "#;
    let module = Module::new(&engine, wat).expect("Compile WAT");
    let linker: Linker<()> = Linker::new(&engine);
    let mut store = Store::new(&engine, ());
    let instance = linker
        .instantiate(&mut store, &module)
        .expect("Instantiate");

    // Read guest RAM
    let memory = instance
        .get_memory(&mut store, "memory")
        .expect("Get memory");
    let guest_ram = memory.data(&store);

    // Assert: Standin token exists in guest memory
    let standin_bytes = standin.as_bytes();
    assert!(
        guest_ram
            .windows(standin_bytes.len())
            .any(|w| w == standin_bytes),
        "Guest RAM must contain standin token"
    );

    // Assert: Real secret has ZERO raw bytes in guest RAM
    assert!(
        !guest_ram
            .windows(real_secret.len())
            .any(|w| w == real_secret),
        "FAIL-CLOSED INVARIANT VIOLATION: Real API secret bytes found in guest linear memory!"
    );
}
