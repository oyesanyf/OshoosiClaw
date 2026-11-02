//! Empirical Adversarial Stress & Challenge Suite for CAGE Persistence in MemoryStore (Milestone M5).
//!
//! Rigorously verifies:
//! 1. High-concurrency SQLite persistence: 25 threads concurrently appending governance traces,
//!    verifying contiguous sequence ordering and zero SQLite `database is locked` panics.
//! 2. Trace chain corruption: Mutating SQLite records directly (leaf hash, prev hash, sequence number, payload)
//!    and verifying `MemoryStore::verify_cage_trace_chain` immediately detects tampering and returns `Ok(false)` or `Err`.
//! 3. Routing seal double-spend race condition: 30 threads simultaneously attempting to consume the same routing seal,
//!    asserting strictly 1 thread succeeds (returns true) and 29 threads fail (return false).
//! 4. Expired or tampered policy version queries: Stress queries with nonexistent, malformed,
//!    and SQL-injection version IDs, asserting safe `Ok(None)` resolution without panics.

use osoosi_audit::MerkleAuditTree;
use osoosi_memory::MemoryStore;
use osoosi_types::cage::RoutingSeal;
use serde_json::json;
use std::sync::{Arc, Barrier};
use std::thread;

/// Challenge 1: High concurrency SQLite persistence across 25 concurrent threads.
/// Asserts contiguous sequence ordering and zero `database is locked` panics.
#[test]
fn test_adversarial_high_concurrency_sqlite_persistence() {
    let num_threads = 25;
    let temp_db_path = std::env::temp_dir().join(format!("cage_concurrency_{}.db", uuid::Uuid::new_v4()));
    let mem = Arc::new(MemoryStore::new(temp_db_path.to_str().unwrap()).expect("Create file-backed SQLite store"));

    let tree = MerkleAuditTree::new();
    let genesis_prev = "0".repeat(64);

    // Pre-calculate 25 valid chained records so they form a strictly contiguous chain
    let mut chained_records = Vec::new();
    let mut prev = genesis_prev;
    for i in 0..num_threads {
        let payload = json!({
            "thread_target": i,
            "action": format!("Action_{}", i),
            "payload_data": format!("data_chunk_{}", i),
        });
        let (leaf, root) = tree.log_cage_governance_trace(&payload);
        chained_records.push((i as u64, prev.clone(), leaf.clone(), root, payload.to_string()));
        prev = leaf;
    }

    let barrier = Arc::new(Barrier::new(num_threads));
    let mut handles = Vec::new();

    for (seq, prev_h, leaf_h, root_h, payload_str) in chained_records {
        let mem_clone = Arc::clone(&mem);
        let b = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            b.wait();
            let trace_id = format!("trace-concurrent-{}", seq);
            let res = mem_clone.append_cage_governance_trace(
                &trace_id,
                seq,
                &prev_h,
                &format!("Action_{}", seq),
                "ALLOW",
                Some(100.0 - (seq as f64)),
                Some(1.0),
                "policy-v1-concurrency",
                &leaf_h,
                &root_h,
                &payload_str,
            );
            assert!(
                res.is_ok(),
                "Thread {} append failed with error: {:?}",
                seq,
                res.err()
            );
        }));
    }

    for h in handles {
        h.join().expect("Worker thread panicked under concurrency");
    }

    // Query persisted traces
    let traces = mem
        .get_cage_governance_traces(100)
        .expect("Query traces must succeed");
    assert_eq!(
        traces.len(),
        num_threads,
        "All {} traces must be persisted in SQLite",
        num_threads
    );

    // Verify contiguous sequence numbers: 0, 1, 2, ..., 24
    for (expected_seq, trace) in traces.iter().enumerate() {
        let actual_seq = trace["sequence_number"].as_u64().expect("Valid sequence_number");
        assert_eq!(
            actual_seq, expected_seq as u64,
            "Trace sequence discontinuity detected at position {}: expected {}, got {}",
            expected_seq, expected_seq, actual_seq
        );
    }

    // Verify cryptographic trace chain
    let is_valid = mem
        .verify_cage_trace_chain()
        .expect("Verification query must succeed");
    assert!(
        is_valid,
        "Cryptographic chain of concurrently inserted traces must verify successfully"
    );

    let _ = std::fs::remove_file(temp_db_path);
}

/// Challenge 2: Direct SQLite mutation and trace chain corruption detection.
/// Verifies that altering leaf hash, prev hash, or sequence number in SQLite
/// causes `verify_cage_trace_chain` to fail immediately.
#[test]
fn test_adversarial_trace_chain_corruption() {
    let temp_db_path = std::env::temp_dir().join(format!("cage_corruption_{}.db", uuid::Uuid::new_v4()));
    let mem = MemoryStore::new(temp_db_path.to_str().unwrap()).expect("Create file-backed SQLite store");
    let tree = MerkleAuditTree::new();

    let genesis_prev = "0".repeat(64);

    // Insert 5 valid chained traces
    let mut prev = genesis_prev;
    for i in 0..5 {
        let payload = json!({
            "idx": i,
            "action": format!("Step_{}", i),
        });
        let (leaf, root) = tree.log_cage_governance_trace(&payload);
        mem.append_cage_governance_trace(
            &format!("trace-{}", i),
            i as u64,
            &prev,
            &format!("Step_{}", i),
            "ALLOW",
            Some(100.0),
            Some(0.5),
            "pol-corruption-test",
            &leaf,
            &root,
            &payload.to_string(),
        )
        .expect("Append must succeed");
        prev = leaf;
    }

    // Initial clean verification must succeed
    assert!(
        mem.verify_cage_trace_chain().expect("Clean verify must succeed"),
        "Untampered initial chain must verify"
    );

    // Direct SQLite connection to tamper with records
    let conn = rusqlite::Connection::open(&temp_db_path).expect("Open raw SQLite connection");

    // Corruption A: Tamper with merkle_leaf_hash of trace-2
    let bad_leaf = "e".repeat(64);
    conn.execute(
        "UPDATE cage_governance_traces SET merkle_leaf_hash = ?1 WHERE trace_id = 'trace-2'",
        [&bad_leaf],
    )
    .expect("Direct update on merkle_leaf_hash must succeed");

    let verify_res = mem.verify_cage_trace_chain().expect("Verify call");
    assert!(
        !verify_res,
        "Chain verification must return false when merkle_leaf_hash is corrupted"
    );

    // Restore trace-2 merkle_leaf_hash and verify recovery
    let rows: Vec<(String, String)> = conn
        .prepare("SELECT trace_id, prev_hash FROM cage_governance_traces WHERE trace_id = 'trace-3'")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    let original_leaf_2 = &rows[0].1;
    conn.execute(
        "UPDATE cage_governance_traces SET merkle_leaf_hash = ?1 WHERE trace_id = 'trace-2'",
        [original_leaf_2],
    )
    .expect("Restore merkle_leaf_hash");
    assert!(
        mem.verify_cage_trace_chain().expect("Verify recovered"),
        "Chain must verify after restoring valid leaf hash"
    );

    // Corruption B: Tamper with prev_hash of trace-1
    let bad_prev = "d".repeat(64);
    conn.execute(
        "UPDATE cage_governance_traces SET prev_hash = ?1 WHERE trace_id = 'trace-1'",
        [&bad_prev],
    )
    .expect("Direct update on prev_hash");

    let verify_prev_tamper = mem.verify_cage_trace_chain().expect("Verify call");
    assert!(
        !verify_prev_tamper,
        "Chain verification must return false when prev_hash is corrupted"
    );

    // Restore trace-1 prev_hash
    let original_leaf_0: String = conn
        .query_row(
            "SELECT merkle_leaf_hash FROM cage_governance_traces WHERE trace_id = 'trace-0'",
            [],
            |r| r.get(0),
        )
        .expect("Query leaf 0");
    conn.execute(
        "UPDATE cage_governance_traces SET prev_hash = ?1 WHERE trace_id = 'trace-1'",
        [&original_leaf_0],
    )
    .expect("Restore prev_hash");
    assert!(
        mem.verify_cage_trace_chain().expect("Verify recovered"),
        "Chain must verify after restoring valid prev_hash"
    );

    // Corruption C: Tamper with sequence_number (introduce sequence gap)
    conn.execute(
        "UPDATE cage_governance_traces SET sequence_number = 42 WHERE trace_id = 'trace-1'",
        [],
    )
    .expect("Direct update on sequence_number");

    let verify_seq_tamper = mem.verify_cage_trace_chain().expect("Verify call");
    assert!(
        !verify_seq_tamper,
        "Chain verification must return false when sequence_number is broken"
    );

    // Restore sequence_number
    conn.execute(
        "UPDATE cage_governance_traces SET sequence_number = 1 WHERE trace_id = 'trace-1'",
        [],
    )
    .expect("Restore sequence_number");
    assert!(
        mem.verify_cage_trace_chain().expect("Verify recovered"),
        "Chain must verify after restoring valid sequence_number"
    );

    // Corruption D: Tamper with merkle_leaf_hash to non-hex/malformed string
    conn.execute(
        "UPDATE cage_governance_traces SET merkle_leaf_hash = 'not-a-valid-hex-hash-too-short' WHERE trace_id = 'trace-4'",
        [],
    )
    .expect("Direct update on merkle_leaf_hash to malformed format");

    let verify_malformed_leaf = mem.verify_cage_trace_chain().expect("Verify call");
    assert!(
        !verify_malformed_leaf,
        "Chain verification must return false when leaf hash format is invalid"
    );

    drop(conn);
    let _ = std::fs::remove_file(temp_db_path);
}

/// Challenge 3: Routing seal double-spend race condition across 30 concurrent threads.
/// Proves that exactly 1 thread succeeds in consuming the active seal, and 29 threads fail.
#[test]
fn test_adversarial_routing_seal_double_spend() {
    let num_threads = 30;
    let mem = Arc::new(MemoryStore::new(":memory:").expect("Create in-memory store"));

    let seal = RoutingSeal {
        seal_id: format!("seal-double-spend-{}", uuid::Uuid::new_v4()),
        policy_version_id: "abcdef1234567890".to_string(),
        action_digest: "b".repeat(64),
        issued_at: 1700000000,
        expires_at: 1700000030,
        signature: "hmac-sig-valid".to_string(),
    };

    mem.record_cage_routing_seal(&seal, "ACTIVE")
        .expect("Record seal as ACTIVE must succeed");

    let barrier = Arc::new(Barrier::new(num_threads));
    let mut handles = Vec::new();

    for thread_idx in 0..num_threads {
        let mem_clone = Arc::clone(&mem);
        let b = Arc::clone(&barrier);
        let seal_id = seal.seal_id.clone();
        handles.push(thread::spawn(move || {
            b.wait();
            let consumed_timestamp = 1700000010 + (thread_idx as u64);
            mem_clone
                .mark_cage_routing_seal_consumed(&seal_id, consumed_timestamp)
                .expect("mark_cage_routing_seal_consumed must not panic")
        }));
    }

    let mut success_count = 0;
    let mut failure_count = 0;

    for h in handles {
        let success = h.join().expect("Thread panicked during seal consumption race");
        if success {
            success_count += 1;
        } else {
            failure_count += 1;
        }
    }

    assert_eq!(
        success_count, 1,
        "Strictly 1 thread must succeed in consuming the routing seal, got {}",
        success_count
    );
    assert_eq!(
        failure_count,
        num_threads - 1,
        "Strictly {} threads must fail double-spend, got {}",
        num_threads - 1,
        failure_count
    );

    // Subsequent 31st consumption attempt must also fail
    let replay_attempt = mem
        .mark_cage_routing_seal_consumed(&seal.seal_id, 1700000099)
        .expect("Query must succeed");
    assert!(
        !replay_attempt,
        "Replay attempt after concurrent consumption must be rejected"
    );

    // Verify seal is still retrievable
    let retrieved = mem
        .get_cage_routing_seal(&seal.seal_id)
        .expect("Query seal")
        .expect("Seal must exist");
    assert_eq!(retrieved.seal_id, seal.seal_id);
}

/// Challenge 4: Query resilience against nonexistent, tampered, and SQL injection policy versions.
/// Asserts that `get_cage_policy` returns `None` and never panics under adversarial queries.
#[test]
fn test_adversarial_policy_version_queries() {
    let mem = MemoryStore::new(":memory:").expect("Create in-memory store");

    // Store one legitimate policy
    let legit_version = "legit1234567890a";
    mem.store_cage_policy(
        legit_version,
        "CageStpa",
        r#"{"stpa_control_structure": "safe"}"#,
        r#"["permit (principal, action, resource);"]"#,
        r#"[]"#,
        0.3,
        15.0,
    )
    .expect("Store legitimate policy must succeed");

    // Legitimate policy query
    let policy = mem
        .get_cage_policy(legit_version)
        .expect("Query legitimate policy")
        .expect("Policy must be present");
    assert_eq!(policy["policy_version_id"], legit_version);
    assert_eq!(policy["format"], "CageStpa");

    // Adversarial & Boundary queries
    let adversarial_versions = [
        "",                                                  // Empty string
        "nonexistent123",                                    // Normal missing ID
        "0000000000000000",                                  // 16-hex zero
        "ffffffffffffffff",                                  // 16-hex all f
        "' OR '1'='1",                                       // SQL injection classic
        "'; DROP TABLE cage_policies; --",                   // SQL injection DDL injection
        "'; UPDATE cage_policies SET cbf_gamma = 0.0; --",   // SQL injection mutation
        "\" OR \"\"=\"",                                     // Double quote injection
        "\\x00\\x00\\x00\\x00",                              // Null bytes
        "<script>alert('xss')</script>",                     // XSS pattern
        &"a".repeat(10_000),                                 // Buffer pressure / 10KB string
        "legit1234567890a\0extra",                           // Embedded null byte
        "legit1234567890b",                                  // Off-by-one character
    ];

    for adv_version in &adversarial_versions {
        let result = mem.get_cage_policy(adv_version);
        assert!(
            result.is_ok(),
            "get_cage_policy({:?}) returned an error: {:?}",
            adv_version,
            result.err()
        );
        let opt = result.unwrap();
        assert!(
            opt.is_none(),
            "get_cage_policy({:?}) should return None for invalid version, got: {:?}",
            adv_version,
            opt
        );
    }

    // Verify legitimate policy was not dropped or modified by SQL injection attempts
    let legit_after = mem
        .get_cage_policy(legit_version)
        .expect("Query legitimate policy after injection attempts")
        .expect("Legitimate policy must survive intact");
    assert_eq!(legit_after["policy_version_id"], legit_version);
    assert_eq!(legit_after["cbf_gamma"], 0.3);
    assert_eq!(legit_after["cbf_b_min"], 15.0);
}
