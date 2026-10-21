// Empirical Adversarial Challenger Test Suite
// Milestone M2D: History View Sub-5ms Caching, Bounded Audit Retrieval, WebUI 0-Diff Parity, and Lineage Eviction
//
// Complies with:
// - Empirical Challenger Invariants: Real tests, genuine statistical oracles, stress harnesses, zero mocks
// - Production Code Only: No mocks, no fake shortcuts
// - PATH & Environment Immutability

use osoosi_agent_anomaly::file_lineage::{FileLineageTracker, LineageError};
use osoosi_audit::AuditTrail;
use osoosi_memory::MemoryStore;
use osoosi_types::ThreatSignature;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

/// Helper: recursive file collector
fn collect_files_recursive(dir: &Path, base: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                files.extend(collect_files_recursive(&p, base));
            } else if p.is_file() {
                if let Ok(rel) = p.strip_prefix(base) {
                    files.push(rel.to_path_buf());
                }
            }
        }
    }
    files
}

// ====================================================================================
// Challenge 1: Sub-5ms History Caching Stress Harness (MemoryStore::get_recent_threats)
// ====================================================================================
#[test]
fn challenge_1_sub5ms_history_caching_and_concurrency_stress() {
    println!("\n=== Challenge 1: Sub-5ms History Caching & Concurrency Stress Harness ===");

    let mem = Arc::new(MemoryStore::new(":memory:").expect("in-memory db init"));

    // 1. Log 50 synthetic threats to populate table
    for i in 0..50 {
        let sig = ThreatSignature {
            id: format!("threat_bench_{}", i),
            cve_id: Some(format!("CVE-2026-900{}", i)),
            hash_blake3: Some(format!("blake3_hash_bench_{:064x}", i)),
            process_name: Some(format!("suspicious_proc_{}.exe", i)),
            confidence: 0.95,
            detected_at: chrono::Utc::now(),
            source_node: "node-bench-alpha".to_string(),
            reason: Some("Adversarial injection probe".to_string()),
            parent_process: Some("cmd.exe".to_string()),
            version: Some("1.0".to_string()),
            ..Default::default()
        };
        mem.log_threat(&sig).expect("log threat succeeds");
    }

    // 2. Prime the cache (initial call hits SQLite)
    let t_prime_start = Instant::now();
    let initial_threats = mem.get_recent_threats(500).expect("initial fetch");
    let prime_elapsed = t_prime_start.elapsed();
    println!("Initial cache priming query took: {:?}", prime_elapsed);
    assert_eq!(initial_threats.len(), 50, "Expected 50 threats returned");

    // 3. Sequential cached stress harness (1,000 iterations)
    const ITERATIONS: usize = 1_000;
    let mut latencies_us = Vec::with_capacity(ITERATIONS);

    for iter in 0..ITERATIONS {
        let t0 = Instant::now();
        let cached = mem.get_recent_threats(500).expect("cached get succeeds");
        let elapsed = t0.elapsed();
        latencies_us.push(elapsed.as_micros());

        assert_eq!(cached.len(), 50);
        assert!(
            elapsed.as_millis() < 5,
            "Iteration {}: cached get_recent_threats(500) took {:?} (exceeds 5ms bound!)",
            iter,
            elapsed
        );
    }

    latencies_us.sort_unstable();
    let min_us = latencies_us[0];
    let max_us = latencies_us[ITERATIONS - 1];
    let median_us = latencies_us[ITERATIONS / 2];
    let p95_us = latencies_us[(ITERATIONS as f64 * 0.95) as usize];
    let p99_us = latencies_us[(ITERATIONS as f64 * 0.99) as usize];
    let avg_us: f64 = latencies_us.iter().sum::<u128>() as f64 / (ITERATIONS as f64);

    println!(
        "Sequential Cached Latency (1,000 runs) -> Min: {}µs, Median: {}µs, Avg: {:.2}µs, P95: {}µs, P99: {}µs, Max: {}µs",
        min_us, median_us, avg_us, p95_us, p99_us, max_us
    );
    assert!(
        p99_us < 5_000,
        "P99 latency must be strictly < 5,000µs (5ms), got {}µs",
        p99_us
    );

    // 4. Test boundary limits on cache (1, 200, 500, 1000)
    for &test_limit in &[1, 10, 50, 200, 500, 1000] {
        let t0 = Instant::now();
        let res = mem.get_recent_threats(test_limit).expect("limit query succeeds");
        let elapsed = t0.elapsed();
        assert!(
            elapsed.as_millis() < 5,
            "Query with limit {} took {:?} (must be < 5ms)",
            test_limit,
            elapsed
        );
        let expected_count = test_limit.min(50);
        assert_eq!(
            res.len(),
            expected_count,
            "Limit {} should return {} threats",
            test_limit,
            expected_count
        );
    }

    // 5. Test cache invalidation and re-priming
    let new_sig = ThreatSignature {
        id: "threat_bench_999".to_string(),
        cve_id: Some("CVE-2026-9999".to_string()),
        hash_blake3: Some("blake3_new_999".to_string()),
        process_name: Some("new_malware.exe".to_string()),
        confidence: 1.0,
        detected_at: chrono::Utc::now(),
        source_node: "node-bench-alpha".to_string(),
        reason: Some("New threat for invalidation".to_string()),
        parent_process: Some("explorer.exe".to_string()),
        version: Some("1.0".to_string()),
        ..Default::default()
    };
    mem.log_threat(&new_sig).expect("log new threat");

    // Next query refreshes cache
    let reprime_start = Instant::now();
    let reloaded = mem.get_recent_threats(500).expect("reload after invalidation");
    let reprime_elapsed = reprime_start.elapsed();
    println!("Reload after invalidation took: {:?}", reprime_elapsed);
    assert_eq!(reloaded.len(), 51);

    // Sub-5ms verified on newly primed cache
    let t_post = Instant::now();
    let cached_new = mem.get_recent_threats(500).expect("cached get after re-prime");
    let post_elapsed = t_post.elapsed();
    assert_eq!(cached_new.len(), 51);
    assert!(
        post_elapsed.as_millis() < 5,
        "Post-invalidation cached get took {:?} (expected < 5ms)",
        post_elapsed
    );

    // 6. Concurrent multi-threaded stress harness (8 threads x 250 requests = 2,000 concurrent calls)
    let thread_count = 8;
    let requests_per_thread = 250;
    let mut handles = Vec::new();

    for th_id in 0..thread_count {
        let mem_clone = Arc::clone(&mem);
        handles.push(std::thread::spawn(move || {
            let mut thread_latencies = Vec::with_capacity(requests_per_thread);
            for _ in 0..requests_per_thread {
                let t_start = Instant::now();
                let res = mem_clone.get_recent_threats(500).expect("concurrent get succeeds");
                let dur = t_start.elapsed();
                assert_eq!(res.len(), 51);
                thread_latencies.push(dur.as_micros());
            }
            let max_thread_us = *thread_latencies.iter().max().unwrap();
            let avg_thread_us: f64 =
                thread_latencies.iter().sum::<u128>() as f64 / (requests_per_thread as f64);
            (th_id, max_thread_us, avg_thread_us)
        }));
    }

    for h in handles {
        let (th_id, max_th, avg_th) = h.join().expect("thread completes cleanly");
        println!(
            "Thread {}: avg latency {:.2}µs, max latency {}µs",
            th_id, avg_th, max_th
        );
        assert!(
            max_th < 15_000,
            "Thread {} max latency {}µs exceeded 15ms contention threshold",
            th_id,
            max_th
        );
    }

    println!("✔ Challenge 1 Passed: Sub-5ms history caching invariant verified under stress and concurrency.");
}

// ====================================================================================
// Challenge 2: Bounded Audit Retrieval Invariant (AuditTrail::get_recent_entries)
// ====================================================================================
#[test]
fn challenge_2_bounded_audit_retrieval_and_merkle_integrity() {
    println!("\n=== Challenge 2: Bounded Audit Retrieval & Merkle Integrity ===");

    let audit = AuditTrail::new();
    assert!(audit.verify(), "Empty Merkle audit tree must verify");

    // 1. Populate 3,000 distinct audit entries
    const TOTAL_ENTRIES: usize = 3_000;
    for i in 0..TOTAL_ENTRIES {
        let leaf_hash = audit.log(
            "CHALLENGE_AUDIT_EVENT",
            serde_json::json!({
                "sequence": i,
                "actor": format!("agent_{}", i % 10),
                "action": "containment_challenge",
                "details": format!("Adversarial audit payload sequence {}", i)
            }),
        );
        assert!(!leaf_hash.is_empty(), "Leaf hash must not be empty");
    }

    // Verify total entries count
    assert_eq!(audit.entries().len(), TOTAL_ENTRIES);
    assert!(audit.verify(), "Populated Merkle audit tree must verify");

    // 2. Query bounded recent entries with limit = 400
    const BOUND: usize = 400;
    let t_audit = Instant::now();
    let recent = audit.get_recent_entries(BOUND);
    let audit_elapsed = t_audit.elapsed();

    println!(
        "get_recent_entries(400) retrieved {} entries in {:?}",
        recent.len(),
        audit_elapsed
    );

    // Invariant: returned slice MUST strictly have exactly BOUND entries
    assert_eq!(
        recent.len(),
        BOUND,
        "get_recent_entries({}) must return exactly {} entries, got {}",
        BOUND,
        BOUND,
        recent.len()
    );

    // Invariant: returned entries MUST be the MOST RECENT 400 entries in FIFO append order
    // (i.e. sequences 2600..3000)
    for (idx, entry) in recent.iter().enumerate() {
        let expected_seq = TOTAL_ENTRIES - BOUND + idx;
        let actual_seq = entry.data["sequence"].as_u64().expect("valid sequence u64") as usize;
        assert_eq!(
            actual_seq, expected_seq,
            "Entry at index {} has sequence {}, expected {}",
            idx, actual_seq, expected_seq
        );
    }

    // 3. Edge-case testing:
    // Limit = 0 -> 0 entries
    let zero_lim = audit.get_recent_entries(0);
    assert_eq!(zero_lim.len(), 0, "Limit 0 must return 0 entries");

    // Limit = 1 -> exactly 1 newest entry (sequence 2999)
    let one_lim = audit.get_recent_entries(1);
    assert_eq!(one_lim.len(), 1);
    assert_eq!(one_lim[0].data["sequence"].as_u64().unwrap(), (TOTAL_ENTRIES - 1) as u64);

    // Limit = TOTAL_ENTRIES -> all 3,000 entries
    let all_lim = audit.get_recent_entries(TOTAL_ENTRIES);
    assert_eq!(all_lim.len(), TOTAL_ENTRIES);

    // Limit > TOTAL_ENTRIES (e.g. 10,000) -> saturates to TOTAL_ENTRIES without panic
    let over_lim = audit.get_recent_entries(10_000);
    assert_eq!(over_lim.len(), TOTAL_ENTRIES);

    // 4. Under-capacity tree testing
    let small_audit = AuditTrail::new();
    for i in 0..25 {
        small_audit.log("SMALL_EVENT", serde_json::json!({ "seq": i }));
    }
    let under_cap = small_audit.get_recent_entries(400);
    assert_eq!(
        under_cap.len(),
        25,
        "Under-capacity audit log should return all 25 entries when limit is 400"
    );

    // 5. Memory compaction test with get_recent_entries
    let evicted = audit.compact_memory(500);
    assert_eq!(evicted, 2_500, "Should evict exactly 2,500 entries");
    assert_eq!(audit.entries().len(), 500);
    assert!(audit.verify(), "Post-compaction audit tree must verify");

    let post_compact_recent = audit.get_recent_entries(400);
    assert_eq!(post_compact_recent.len(), 400);
    let post_compact_all = audit.get_recent_entries(500);
    assert_eq!(post_compact_all.len(), 500);

    println!("✔ Challenge 2 Passed: Bounded audit retrieval strictly enforces capacity limit and FIFO order.");
}

// ====================================================================================
// Challenge 3: WebUI 0-Diff Parity Invariant (dashboard/src vs dashboard/dist)
// ====================================================================================
#[test]
fn challenge_3_webui_parity_exhaustive_sha256_and_appjs_invariants() {
    println!("\n=== Challenge 3: WebUI 0-Diff Parity Exhaustive SHA-256 Verification ===");

    let src_dir = Path::new("dashboard/src");
    let dist_dir = Path::new("dashboard/dist");

    assert!(src_dir.exists(), "dashboard/src must exist");
    assert!(dist_dir.exists(), "dashboard/dist must exist");

    let src_files = collect_files_recursive(src_dir, src_dir);
    let dist_files = collect_files_recursive(dist_dir, dist_dir);

    assert!(
        !src_files.is_empty(),
        "dashboard/src must contain files to compare"
    );

    let src_set: HashSet<PathBuf> = src_files.into_iter().collect();
    let dist_set: HashSet<PathBuf> = dist_files.into_iter().collect();

    // 1. Assert bidirectional set equality (no missing or orphaned files)
    let missing_in_dist: Vec<&PathBuf> = src_set.difference(&dist_set).collect();
    let orphaned_in_dist: Vec<&PathBuf> = dist_set.difference(&src_set).collect();

    assert!(
        missing_in_dist.is_empty(),
        "Files present in dashboard/src but missing in dashboard/dist: {:?}",
        missing_in_dist
    );
    assert!(
        orphaned_in_dist.is_empty(),
        "Orphaned files present in dashboard/dist but missing in dashboard/src: {:?}",
        orphaned_in_dist
    );

    // 2. Exhaustive SHA-256 and BLAKE3 equality comparison
    let mut verified_count = 0;
    for file_rel in &src_set {
        let src_path = src_dir.join(file_rel);
        let dist_path = dist_dir.join(file_rel);

        let src_bytes = fs::read(&src_path).unwrap_or_else(|e| {
            panic!("Failed to read {}: {}", src_path.display(), e);
        });
        let dist_bytes = fs::read(&dist_path).unwrap_or_else(|e| {
            panic!("Failed to read {}: {}", dist_path.display(), e);
        });

        // SHA-256
        let mut hasher_src = Sha256::new();
        hasher_src.update(&src_bytes);
        let hash_src = hex::encode(hasher_src.finalize());

        let mut hasher_dist = Sha256::new();
        hasher_dist.update(&dist_bytes);
        let hash_dist = hex::encode(hasher_dist.finalize());

        assert_eq!(
            hash_src,
            hash_dist,
            "SHA-256 mismatch for file {:?}\nsrc: {}\ndist: {}",
            file_rel,
            hash_src,
            hash_dist
        );

        // BLAKE3
        let blake3_src = blake3::hash(&src_bytes);
        let blake3_dist = blake3::hash(&dist_bytes);
        assert_eq!(
            blake3_src,
            blake3_dist,
            "BLAKE3 mismatch for file {:?}",
            file_rel
        );

        verified_count += 1;
    }

    println!(
        "Verified {} files between dashboard/src and dashboard/dist: 100% byte-for-byte identical.",
        verified_count
    );

    // 3. Verify specific R13 & R7 code patterns in app.js
    let app_js_content = fs::read_to_string("dashboard/src/app.js").expect("read app.js");

    // R13: fetchWithRetry timeoutMs || 12000
    assert!(
        app_js_content.contains("opts.timeoutMs || 12000"),
        "dashboard/src/app.js must configure fetchWithRetry default timeout to 12000ms"
    );

    // R13: lastHistoryData fallback
    assert!(
        app_js_content.contains("state.lastHistoryData"),
        "dashboard/src/app.js must maintain state.lastHistoryData fallback"
    );

    // R7: CanaryCage telemetry rendering
    assert!(
        app_js_content.contains("renderDeceptionCard") || app_js_content.contains("canary_files"),
        "dashboard/src/app.js must render deception telemetry"
    );

    println!("✔ Challenge 3 Passed: 0-diff byte-for-byte SHA-256 parity and code invariants verified.");
}

// ====================================================================================
// Challenge 4: FileLineageTracker Bounded FIFO Eviction & Alert Attribution
// ====================================================================================
#[test]
fn challenge_4_file_lineage_tracker_fifo_eviction_and_attribution() {
    println!("\n=== Challenge 4: FileLineageTracker FIFO Eviction & Attribution ===");

    // 1. Verify default capacity
    let default_tracker = FileLineageTracker::new();
    assert_eq!(default_tracker.max_capacity, 16_384);

    // 2. Small-scale FIFO eviction testing (capacity = 20)
    const TEST_CAP: usize = 20;
    let tracker = FileLineageTracker::with_capacity(TEST_CAP);

    // Ingest 60 distinct sessions
    for i in 0..60 {
        let session = format!("sess_{:03}", i);
        let path_str = format!("C:\\external_temp\\doc_{:03}.pdf", i);
        let path = Path::new(&path_str);
        let content = format!("Payload content for session {}", i);

        let digest = tracker
            .record_ingested_file(&session, path, content.as_bytes())
            .expect("record ingested file");

        assert_eq!(
            digest,
            FileLineageTracker::compute_blake3(content.as_bytes())
        );
    }

    // Invariant: session_count must NOT exceed TEST_CAP
    assert!(
        tracker.session_count() <= TEST_CAP,
        "session_count {} must not exceed capacity {}",
        tracker.session_count(),
        TEST_CAP
    );

    // Invariant: oldest sessions (0..40) must be evicted, newest (40..60) must be retained
    for i in 0..40 {
        let session = format!("sess_{:03}", i);
        assert!(
            tracker.get_session_lineage(&session).is_empty(),
            "Old session {} should have been evicted by FIFO rule",
            session
        );
    }
    for i in 40..60 {
        let session = format!("sess_{:03}", i);
        assert_eq!(
            tracker.get_session_lineage(&session).len(),
            1,
            "Recent session {} must be retained",
            session
        );
    }

    // 3. Large-scale FIFO eviction test (capacity = 16,384)
    println!("Testing large-scale bounded eviction (16,384 capacity with 16,500 entries)...");
    let large_tracker = FileLineageTracker::with_capacity(16_384);
    for i in 0..16_500 {
        let session = format!("lg_sess_{}", i);
        let path_str = format!("C:\\sandbox_volume\\file_{}.bin", i);
        let path = Path::new(&path_str);
        let payload = [((i % 256) as u8); 16];

        let _ = large_tracker
            .record_ingested_file(&session, path, &payload)
            .expect("record succeeds");
    }

    assert!(
        large_tracker.session_count() <= 16_384,
        "Large tracker session count {} must not exceed 16,384",
        large_tracker.session_count()
    );

    // Oldest 100 sessions must be evicted
    for i in 0..100 {
        let session = format!("lg_sess_{}", i);
        assert!(
            large_tracker.get_session_lineage(&session).is_empty(),
            "Session {} should have been evicted",
            session
        );
    }

    // 4. Alert Attribution & Swarm Immunization Flow
    let attr_tracker = FileLineageTracker::with_capacity(100);
    let attack_session = "agent_session_adversary_007";
    let attack_path = Path::new("C:\\temp\\exploit_document.docx");
    let attack_content = b"PK\x03\x04 malicious macro binary payload";

    let attack_digest = attr_tracker
        .record_ingested_file(attack_session, attack_path, attack_content)
        .expect("ingest initial payload");

    assert!(!attr_tracker.is_poisoned_digest(&attack_digest));

    // Canary alert triggers
    let attributed = attr_tracker.attribute_canary_alert(
        attack_session,
        "ALERT_CANARY_TEST_01",
        "\\\\.\\pipe\\osoosi_canary_test_pipe",
    );

    assert_eq!(
        attributed,
        Some(attack_digest.clone()),
        "Canary alert must be attributed to the ingested attack file"
    );
    assert!(
        attr_tracker.is_poisoned_digest(&attack_digest),
        "Digest must now be recorded as poisoned"
    );

    // Ingesting the same poisoned payload again in another session MUST be rejected immediately
    let reject_err = attr_tracker.record_ingested_file(
        "agent_session_innocent_target",
        attack_path,
        attack_content,
    );
    assert!(
        reject_err.is_err(),
        "Ingesting poisoned file must return error"
    );
    match reject_err {
        Err(LineageError::PoisonedDigest(msg)) => {
            assert!(msg.contains(&attack_digest));
        }
        other => panic!("Expected LineageError::PoisonedDigest, got {:?}", other),
    }

    // Tool call parameter inspection MUST detect the poisoned digest
    let tool_call_params = serde_json::json!({
        "action": "open_document",
        "file_hash": attack_digest,
        "path": "C:\\temp\\exploit_document.docx"
    });
    let inspect_res = attr_tracker.inspect_tool_call_parameters(&tool_call_params);
    assert!(
        inspect_res.is_err(),
        "Tool call with poisoned hash must be rejected"
    );

    // 5. Hard Repository & Developer Immunity Invariants
    // Repo path or developer toolchain cannot be poisoned
    let repo_root = osoosi_types::resolve_project_root().expect("resolve project root");
    let safe_repo_path = repo_root.join("Cargo.toml");
    let safe_content = b"[workspace]\nmembers = []";

    let safe_digest = attr_tracker
        .record_ingested_file("safe_dev_session", &safe_repo_path, safe_content)
        .expect("ingest repo file");

    let repo_lineage = attr_tracker.get_session_lineage("safe_dev_session");
    assert_eq!(repo_lineage.len(), 1);
    assert!(
        repo_lineage[0].is_immune,
        "Repository file must be marked is_immune = true"
    );

    // Attempting to poison an immune file must be refused
    let poison_result = attr_tracker.mark_digest_poisoned(
        &safe_digest,
        "safe_dev_session",
        "False alert on repo file",
        1.0,
    );
    assert!(
        poison_result.is_err(),
        "Attempting to poison immune repo file must fail"
    );

    println!("✔ Challenge 4 Passed: FileLineageTracker FIFO eviction and alert attribution invariants verified.");
}
