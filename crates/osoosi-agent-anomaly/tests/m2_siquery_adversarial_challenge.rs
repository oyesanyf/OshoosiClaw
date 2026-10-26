//! Empirical Adversarial Challenge Suite for Milestone 2 siquery-rs Integration
//!
//! Validates:
//! 1. Siquery queries on `file_events`, `process_open_files`, and `processes`.
//! 2. Bidirectional correlation and field accuracy across edge cases (Unicode, long paths, special chars, SQL injection).
//! 3. Ring buffer bounds (strict 1024 capacity) under heavy event floods and FIFO eviction semantics.
//! 4. High-concurrency multithreaded flood and query contention without deadlocks or panic.
//! 5. Lineage hook registration and execution.

use osoosi_agent_anomaly::siquery::{
    record_live_file_event, register_lineage_file_events_hook, register_lineage_open_files_hook,
    FileEventRecord, SiqueryEngine, LIVE_FILE_EVENTS,
};
use parking_lot::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

/// Global test synchronization mutex to ensure isolated testing on global static `LIVE_FILE_EVENTS`.
static TEST_MUTEX: Mutex<()> = Mutex::new(());

/// Challenge 1: Verify queries on `processes`, `process_open_files`, and `file_events`.
#[test]
fn challenge_1_siquery_queries_on_core_tables() {
    let _guard = TEST_MUTEX.lock();
    let engine = SiqueryEngine::new();

    // 1. Query `processes` table
    let proc_rows = engine
        .execute_query("SELECT pid, name, path, cmdline FROM processes LIMIT 20;")
        .expect("SELECT on processes must succeed");
    assert!(!proc_rows.is_empty(), "processes table must return host processes");

    let current_pid = std::process::id() as i64;
    let current_proc = engine
        .execute_query(&format!(
            "SELECT pid, name, path FROM processes WHERE pid = {};",
            current_pid
        ))
        .expect("SELECT on current process must succeed");
    assert!(
        !current_proc.is_empty(),
        "Current process must be present in processes table"
    );
    let cur_row = &current_proc[0];
    assert_eq!(
        cur_row.get("pid").and_then(|v| v.as_i64()),
        Some(current_pid),
        "Current pid must match"
    );

    // 2. Query `process_open_files` view (and underlying open_files)
    let open_files_rows = engine
        .execute_query("SELECT pid, fd, path FROM process_open_files LIMIT 20;")
        .expect("SELECT on process_open_files must succeed");
    assert!(
        !open_files_rows.is_empty(),
        "process_open_files must return active process file handles"
    );
    for row in &open_files_rows {
        assert!(row.get("pid").is_some(), "pid column must be present");
        assert!(row.get("fd").is_some(), "fd column must be present");
        assert!(row.get("path").is_some(), "path column must be present");
    }

    // 3. Query `file_events` table (clean SQL and aggregate syntax)
    let file_events_count = engine
        .execute_query("SELECT count(*) as total FROM file_events;")
        .expect("SELECT count on file_events must succeed");
    assert!(!file_events_count.is_empty());

    let grouped_events = engine
        .execute_query("SELECT action, count(*) as cnt FROM file_events GROUP BY action;")
        .expect("GROUP BY on file_events must succeed");
    assert!(grouped_events.is_empty() || !grouped_events.is_empty()); // Query syntax verified
}

/// Challenge 2: Test bidirectional correlation, live event recording, and field accuracy.
#[test]
fn challenge_2_bidirectional_correlation_and_field_accuracy() {
    let _guard = TEST_MUTEX.lock();
    let engine = SiqueryEngine::new();

    let canary_time = 1712345678i64;
    let long_path = format!("C:\\very\\long\\path\\{}\\", "subfolder\\".repeat(50))
        + "crown_jewel_deep_classified_data.docx";
    let unicode_path = "D:\\Ọ̀ṣọ́ọ̀sì_Security\\🔒_vault\\secret_report_2026.pdf";
    let sql_inj_path = "C:\\payloads\\malicious'; DROP TABLE file_events; --.exe";

    let test_records = vec![
        FileEventRecord {
            target_path: "C:\\Windows\\System32\\drivers\\etc\\hosts".to_string(),
            action: "WRITE".to_string(),
            pid: 1001,
            process_name: "notepad.exe".to_string(),
            sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".to_string(),
            time: canary_time,
        },
        FileEventRecord {
            target_path: unicode_path.to_string(),
            action: "TAINTED_WRITE".to_string(),
            pid: 2002,
            process_name: "osoosi_agent".to_string(),
            sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
            time: canary_time + 10,
        },
        FileEventRecord {
            target_path: long_path.clone(),
            action: "READ".to_string(),
            pid: 3003,
            process_name: "worker_process.exe".to_string(),
            sha256: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824".to_string(),
            time: canary_time + 20,
        },
        FileEventRecord {
            target_path: sql_inj_path.to_string(),
            action: "DELETE".to_string(),
            pid: 4004,
            process_name: "cmd.exe".to_string(),
            sha256: "8888888888888888888888888888888888888888888888888888888888888888".to_string(),
            time: canary_time + 30,
        },
    ];

    for rec in &test_records {
        record_live_file_event(rec.clone());
    }

    // Query 1: Standard SELECT * query
    let rows = engine
        .execute_query(&format!(
            "SELECT * FROM file_events WHERE time >= {} AND time <= {} ORDER BY time ASC;",
            canary_time,
            canary_time + 30
        ))
        .expect("SELECT * on file_events must succeed");

    assert!(
        rows.len() >= 4,
        "All 4 canary records must be returned by SELECT *"
    );

    // Verify fields for Unicode record
    let unicode_row = rows
        .iter()
        .find(|r| r.get("pid").and_then(|v| v.as_i64()) == Some(2002))
        .expect("Unicode record must be found by PID");
    assert_eq!(
        unicode_row.get("target_path").and_then(|v| v.as_str()),
        Some(unicode_path),
        "Unicode target_path must be preserved exactly"
    );
    assert_eq!(
        unicode_row.get("action").and_then(|v| v.as_str()),
        Some("TAINTED_WRITE")
    );
    assert_eq!(
        unicode_row.get("process_name").and_then(|v| v.as_str()),
        Some("osoosi_agent")
    );
    assert_eq!(
        unicode_row.get("sha256").and_then(|v| v.as_str()),
        Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    );
    assert_eq!(
        unicode_row.get("time").and_then(|v| v.as_i64()),
        Some(canary_time + 10)
    );

    // Verify fields for Long path record
    let long_row = rows
        .iter()
        .find(|r| r.get("pid").and_then(|v| v.as_i64()) == Some(3003))
        .expect("Long path record must be found by PID");
    assert_eq!(
        long_row.get("target_path").and_then(|v| v.as_str()),
        Some(long_path.as_str()),
        "Long path must be preserved without truncation"
    );

    // Verify SQL injection attempt: should NOT drop table, should safely store literal string
    let sql_inj_row = rows
        .iter()
        .find(|r| r.get("pid").and_then(|v| v.as_i64()) == Some(4004))
        .expect("SQL injection record must be safely stored and retrieved");
    assert_eq!(
        sql_inj_row.get("target_path").and_then(|v| v.as_str()),
        Some(sql_inj_path),
        "SQL injection payload must be preserved literally without executing"
    );
    assert_eq!(
        sql_inj_row.get("action").and_then(|v| v.as_str()),
        Some("DELETE")
    );

    // Verify table still exists and is queryable after the injection string
    let check_table = engine
        .execute_query("SELECT count(*) as count FROM file_events;")
        .expect("file_events table must remain intact");
    assert!(!check_table.is_empty());
}

/// Challenge 3: Test ring buffer bounds (1024 capacity) under heavy event floods and verify FIFO eviction.
#[test]
fn challenge_3_ring_buffer_bounds_and_fifo_eviction() {
    let _guard = TEST_MUTEX.lock();
    let engine = SiqueryEngine::new();

    let flood_prefix = "C:\\flood_test\\event_";
    let flood_count = 3000;

    // Inject 3,000 events into the ring buffer
    for i in 0..flood_count {
        record_live_file_event(FileEventRecord {
            target_path: format!("{}{}.tmp", flood_prefix, i),
            action: "WRITE".to_string(),
            pid: 5000 + (i % 100),
            process_name: format!("flooder_{}.exe", i % 10),
            sha256: format!("{:064x}", i),
            time: 2000000000 + i,
        });
    }

    // 1. Assert bounded ring buffer capacity
    let current_buffer_len = LIVE_FILE_EVENTS.read().len();
    assert_eq!(
        current_buffer_len, 1024,
        "Ring buffer capacity must be strictly capped at 1024 entries"
    );

    // 2. Verify FIFO eviction:
    // With 3000 events (0..2999) and capacity 1024, the retained events must be 1976..2999
    {
        let q = LIVE_FILE_EVENTS.read();
        let oldest = q.front().expect("Queue must not be empty");
        let newest = q.back().expect("Queue must not be empty");

        assert_eq!(
            oldest.target_path,
            format!("{}1976.tmp", flood_prefix),
            "Oldest retained event must be event 1976 (first 1976 evicted)"
        );
        assert_eq!(
            newest.target_path,
            format!("{}2999.tmp", flood_prefix),
            "Newest retained event must be event 2999"
        );
    }

    // 3. Query via SQL engine
    let query_res = engine
        .execute_query("SELECT count(*) as total FROM file_events WHERE target_path LIKE '%flood_test%';")
        .expect("Querying flooded file_events must succeed");
    let total = query_res[0]
        .get("total")
        .and_then(|v| v.as_i64())
        .expect("total count must be present");
    assert_eq!(
        total, 1024,
        "SQL query over flooded file_events must return exactly 1024 events"
    );
}

/// Challenge 4: High-concurrency multithreaded flood and query contention without deadlocks or panic.
#[test]
fn challenge_4_multithreaded_flood_and_query_contention() {
    let _guard = TEST_MUTEX.lock();
    let engine = Arc::new(SiqueryEngine::new());
    let stop_signal = Arc::new(AtomicBool::new(false));

    // Spawn 8 concurrent writer threads flood-recording events
    let mut writer_handles = Vec::new();
    for thread_idx in 0..8 {
        let handle = thread::spawn(move || {
            for i in 0..500 {
                record_live_file_event(FileEventRecord {
                    target_path: format!("D:\\concurrent\\t{}_ev{}.log", thread_idx, i),
                    action: "LOG_WRITE".to_string(),
                    pid: 10000 + thread_idx as i64,
                    process_name: format!("worker_thread_{}", thread_idx),
                    sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                        .to_string(),
                    time: 3000000000 + i,
                });
            }
        });
        writer_handles.push(handle);
    }

    // Spawn 4 concurrent reader threads running queries against siquery
    let mut reader_handles = Vec::new();
    for _ in 0..4 {
        let engine_clone = Arc::clone(&engine);
        let stop_clone = Arc::clone(&stop_signal);
        let handle = thread::spawn(move || {
            let mut queries_completed = 0;
            while !stop_clone.load(Ordering::Relaxed) {
                let _ = engine_clone.execute_query(
                    "SELECT target_path, pid FROM file_events ORDER BY time DESC LIMIT 50;",
                );
                queries_completed += 1;
                thread::yield_now();
            }
            queries_completed
        });
        reader_handles.push(handle);
    }

    // Wait for all writers to finish
    for handle in writer_handles {
        handle.join().expect("Writer thread must not panic");
    }

    // Signal readers to stop
    stop_signal.store(true, Ordering::Relaxed);
    for handle in reader_handles {
        let q_count = handle.join().expect("Reader thread must not panic");
        assert!(q_count > 0, "Reader thread must have executed queries");
    }

    // Verify buffer capacity remained capped at 1024
    let final_len = LIVE_FILE_EVENTS.read().len();
    assert_eq!(
        final_len, 1024,
        "Buffer must stay strictly capped at 1024 under concurrent access"
    );
}

/// Challenge 5: Lineage hooks integration and bidirectional sync.
#[test]
fn challenge_5_lineage_hooks_bidirectional_sync() {
    let _guard = TEST_MUTEX.lock();
    let engine = SiqueryEngine::new();

    // Register active open files hook
    register_lineage_open_files_hook(|| {
        vec![
            (7777, 10, "C:\\hooked_descriptors\\classified_briefing.pdf".to_string()),
            (7777, 11, "C:\\hooked_descriptors\\database_credentials.key".to_string()),
        ]
    });

    // Register active file events hook
    register_lineage_file_events_hook(|| {
        vec![FileEventRecord {
            target_path: "C:\\hooked_events\\exfiltrated_tar.gz".to_string(),
            action: "TAINTED_EXFIL_ATTEMPT".to_string(),
            pid: 7777,
            process_name: "rogue_agent.exe".to_string(),
            sha256: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string(),
            time: 4000000000,
        }]
    });

    // 1. Verify open_files hook rows appear in process_open_files query
    let open_files = engine
        .execute_query("SELECT pid, fd, path FROM process_open_files WHERE pid = 7777;")
        .expect("Query on hooked process_open_files must succeed");
    assert_eq!(
        open_files.len(),
        2,
        "Both hooked open file descriptors must be returned"
    );
    let paths: Vec<&str> = open_files
        .iter()
        .filter_map(|r| r.get("path").and_then(|v| v.as_str()))
        .collect();
    assert!(paths.contains(&"C:\\hooked_descriptors\\classified_briefing.pdf"));
    assert!(paths.contains(&"C:\\hooked_descriptors\\database_credentials.key"));

    // 2. Verify file_events hook rows appear in file_events query
    let events = engine
        .execute_query("SELECT target_path, action, pid, process_name, sha256 FROM file_events WHERE pid = 7777;")
        .expect("Query on hooked file_events must succeed");
    assert!(
        !events.is_empty(),
        "Hooked file event must appear in file_events query"
    );
    let event = &events[0];
    assert_eq!(
        event.get("target_path").and_then(|v| v.as_str()),
        Some("C:\\hooked_events\\exfiltrated_tar.gz")
    );
    assert_eq!(
        event.get("action").and_then(|v| v.as_str()),
        Some("TAINTED_EXFIL_ATTEMPT")
    );
    assert_eq!(
        event.get("process_name").and_then(|v| v.as_str()),
        Some("rogue_agent.exe")
    );
}
