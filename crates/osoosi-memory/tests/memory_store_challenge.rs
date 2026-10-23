//! Empirical Challenge Suite for MemoryStore (Milestone M2A).
//!
//! Adversarial verification harness validating:
//! 1. Empty String / None Fast Path: Calls with empty strings or None return immediately (< 1ms)
//!    without acquiring the SQLite database lock.
//! 2. IDE / Component Allowlist Fast Path: Legitimate IDE paths with allowlisted components
//!    return Ok(true) immediately (< 1ms) without acquiring the database lock.
//! 3. Lock Non-Blocking Guard: When the SQLite connection is actively locked by a long-running
//!    database query, calls to `is_false_positive_pattern` for slow-path queries time out after ~5ms
//!    and return Ok(false) rather than blocking HTTP endpoints or deadlocking.

use osoosi_memory::MemoryStore;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Challenge 4A: Fast-path return for empty / None inputs without database queries.
#[test]
fn challenge_memory_store_empty_inputs_fast_path() {
    let mem = MemoryStore::new(":memory:").expect("Create in-memory store");

    let t0 = Instant::now();
    for _ in 0..1000 {
        assert!(!mem.is_false_positive_pattern(None, None).unwrap());
        assert!(!mem.is_false_positive_pattern(Some(""), Some("")).unwrap());
        assert!(!mem
            .is_false_positive_pattern(Some("   "), Some("   "))
            .unwrap());
    }
    let elapsed = t0.elapsed();
    let per_call_micros = elapsed.as_micros() / 3000;
    println!("Empty input fast-path avg latency: {} µs", per_call_micros);
    assert!(
        per_call_micros < 100,
        "Empty input checks must be sub-millisecond in-memory operations (took {} µs)",
        per_call_micros
    );
}

/// Challenge 4B: Fast-path return for allowlisted IDE components without database queries.
#[test]
fn challenge_memory_store_ide_allowlist_fast_path() {
    let mem = MemoryStore::new(":memory:").expect("Create in-memory store");

    let ide_cases = [
        r"D:\harfile\ModelFusion\IDE\VSCode-win32-x64\vulkan-1.dll",
        r"C:\Users\dev\.vscode\extensions\microsoft\msalruntime.dll",
        r"C:\Users\dev\AppData\Local\Programs\Microsoft VS Code\resources\app\vsda.node",
        r"D:\harfile\ModelFusion\resources\app\msal-node-runtime.node",
        r"C:\vscode\win32-app-container-tokens.dll",
    ];

    let t0 = Instant::now();
    for path in &ide_cases {
        let is_fp = mem.is_false_positive_pattern(Some(path), None).unwrap();
        assert!(
            is_fp,
            "IDE path {:?} must match false positive pattern",
            path
        );
    }
    let elapsed = t0.elapsed();
    let avg_micros = elapsed.as_micros() / (ide_cases.len() as u128);
    println!("IDE allowlist fast-path avg latency: {} µs", avg_micros);
    assert!(
        avg_micros < 100,
        "IDE allowlist fast-path must execute in memory before database lock (took {} µs)",
        avg_micros
    );

    // Negative cases: Identical binaries in untrusted paths must NOT match fast-path
    let untrusted_cases = [
        r"C:\Windows\Temp\vulkan-1.dll",
        r"C:\Users\victim\Downloads\msalruntime.dll",
        r"C:\temp\vsda.node",
    ];
    for path in &untrusted_cases {
        assert!(
            !mem.is_false_positive_pattern(Some(path), None).unwrap(),
            "Untrusted path {:?} must NOT be granted false positive exemption",
            path
        );
    }
}

/// Challenge 4C: Lock non-blocking guard under active database contention.
/// Proves that `is_false_positive_pattern` never blocks on background SQLite baseline writes.
#[test]
fn challenge_memory_store_lock_non_blocking_under_contention() {
    let mem = Arc::new(MemoryStore::new(":memory:").expect("Create in-memory store"));

    // Spawn a background thread that executes a long-running SQLite query holding `conn.lock()`
    let mem_bg = Arc::clone(&mem);
    let bg_thread = std::thread::spawn(move || {
        let slow_query = "SELECT count(*) FROM (WITH RECURSIVE cnt(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM cnt WHERE x < 2000000) SELECT x FROM cnt)";
        let res = mem_bg.query_json(slow_query, &[]);
        assert!(res.is_ok(), "Slow query must succeed, got {:?}", res.err());
    });

    // Give background thread 20ms to acquire the lock
    std::thread::sleep(Duration::from_millis(20));

    // 1. Empty strings: must return Ok(false) immediately (< 1ms) because it checks BEFORE acquiring lock
    let t_empty = Instant::now();
    let res_empty = mem
        .is_false_positive_pattern(None, None)
        .expect("Empty fast-path");
    let dur_empty = t_empty.elapsed();
    assert!(!res_empty);
    assert!(
        dur_empty < Duration::from_millis(2),
        "Empty input check took {:?}, should be < 2ms without acquiring lock",
        dur_empty
    );

    // 2. IDE allowlist: must return Ok(true) immediately (< 1ms) because it checks BEFORE acquiring lock
    let t_ide = Instant::now();
    let res_ide = mem
        .is_false_positive_pattern(
            Some(r"D:\harfile\ModelFusion\IDE\VSCode-win32-x64\vulkan-1.dll"),
            None,
        )
        .expect("IDE allowlist fast-path");
    let dur_ide = t_ide.elapsed();
    assert!(res_ide);
    assert!(
        dur_ide < Duration::from_millis(2),
        "IDE allowlist check took {:?}, should be < 2ms without acquiring lock",
        dur_ide
    );

    // 3. Slow path (untrusted process needing DB query):
    // Lock is currently held by background thread. `try_lock_for(5ms)` must timeout and return Ok(false)
    // without blocking for the full duration of the background query.
    let t_slow = Instant::now();
    let res_slow = mem
        .is_false_positive_pattern(
            Some(r"C:\untrusted\suspicious_app.exe"),
            Some("fedcba0987654321"),
        )
        .expect("Lock timeout fallback must return Ok(false)");
    let dur_slow = t_slow.elapsed();

    assert!(
        !res_slow,
        "Fallback on lock timeout must return false safely"
    );
    println!("Slow path duration under lock contention: {:?}", dur_slow);
    assert!(
        dur_slow < Duration::from_millis(50),
        "Slow path with lock contention must return within ~5-50ms (took {:?}), NOT block indefinitely",
        dur_slow
    );
    assert!(
        dur_slow >= Duration::from_millis(4),
        "Slow path should wait for try_lock_for timeout (5ms), took {:?}",
        dur_slow
    );

    // Join background thread to ensure clean shutdown
    bg_thread.join().expect("Background query thread finished");
}
