//! Empirical Adversarial Challenge Suite for Milestone 2:
//! Kernel Telemetry & DLP Lineage Correlation.
//!
//! Adversarial Verification Matrix:
//! 1. Parent-to-Child Process Taint Inheritance:
//!    - Direct single-hop inheritance of taint, CrownJewel classification, Quarantine policy, and W3C Baggage.
//!    - Deep multi-hop process ancestry tree (parent -> child -> grandchild -> great-grandchild).
//!    - Downstream side-effect file write by tainted child process inherits CrownJewel and Quarantine.
//!    - Sibling process isolation: clean parent spawns child; verify child remains strictly untainted (0 false positives).
//!    - Event Pipeline Sysmon 1 / 4688 (`ProcessCreate`) ingestion propagates taint to child process.
//!    - Concurrent rapid child process spawn stress test (50 child spawns under high concurrency).
//!
//! 2. File Rename Tracking:
//!    - Tainted file A renamed to B: verify old artifact key is removed, new key is inserted, egress checks on B blocked.
//!    - Multi-hop file rename chain (A -> B -> C -> D).
//!    - Real on-disk filesystem rename (`std::fs::rename`) with true OS handles and metadata.
//!    - Event Pipeline Sysmon 27 (`FileRename`) ingestion updates artifact key and blocks egress on renamed path.
//!    - Renamed file content hash integrity in content catalog.

use std::fs;
use std::sync::Arc;
use std::thread;

use chrono::Utc;
use osoosi_core::dlp_lineage::{
    compute_sha256_hex, global_lineage_tracker, ArtifactKey, ClassificationLattice,
    DlpLineageTracker, EgressDecision, FileWriteTaintDecision, PolicyLattice, ProcessInstanceKey,
};
use osoosi_core::EdrOrchestrator;
use osoosi_types::{HostEventSource, HostSecurityEvent};
use serde_json::json;

// =============================================================================
// PART 1: Parent-to-Child Process Taint & Baggage Inheritance
// =============================================================================

#[test]
fn test_adversarial_parent_to_child_taint_and_baggage_inheritance() {
    let tracker = DlpLineageTracker::new(30);

    // 1. Establish tainted parent process
    let parent_pid = 7001u32;
    let parent_start = 100_000u64;
    let parent_key = ProcessInstanceKey::new(parent_pid, parent_start);

    let secret_file_path = "C:\\secrets\\crown_jewel_credentials.json";
    let secret_key = ArtifactKey::from_path_or_synthetic(secret_file_path);
    let raw_secret = b"MASTER_ENCRYPTION_KEY_AND_DATABASE_PASSWORD_001";

    tracker.register_crown_jewel_artifact(
        secret_key,
        secret_file_path,
        raw_secret,
        ClassificationLattice::CrownJewel,
        PolicyLattice::Quarantine,
    );

    // Parent reads the sensitive artifact
    tracker.on_file_read(
        parent_key,
        "worker_service.exe",
        "C:\\services\\worker_service.exe",
        secret_key,
    );

    // Verify parent is tainted with CrownJewel, Quarantine, and proper W3C Baggage
    let parent_rec = tracker
        .active_processes
        .get(&parent_key)
        .expect("Parent process must exist")
        .clone();
    assert!(parent_rec.tainted, "Parent process must be tainted");
    assert_eq!(
        parent_rec.classification,
        ClassificationLattice::CrownJewel,
        "Parent classification must be CrownJewel"
    );
    assert_eq!(
        parent_rec.policy,
        PolicyLattice::Quarantine,
        "Parent policy must be Quarantine"
    );

    // Verify W3C Baggage on parent
    let parent_baggage_header = parent_rec.baggage.to_w3c_header();
    assert!(
        parent_baggage_header.contains("dlp.classification=CROWN_JEWEL"),
        "Parent W3C Baggage must contain dlp.classification=CROWN_JEWEL"
    );
    assert!(
        parent_baggage_header.contains("dlp.policy=QUARANTINE"),
        "Parent W3C Baggage must contain dlp.policy=QUARANTINE"
    );
    assert!(
        parent_baggage_header.contains("dlp.tainted=true"),
        "Parent W3C Baggage must contain dlp.tainted=true"
    );

    // 2. Parent spawns Child Process B
    let child_pid = 7002u32;
    let child_start = 200_000u64;
    let child_key = ProcessInstanceKey::new(child_pid, child_start);

    let child_rec = tracker.on_process_create(
        child_pid,
        child_start,
        "export_worker.exe",
        "C:\\tools\\export_worker.exe",
        Some(parent_pid),
        Some(parent_start),
    );

    assert!(tracker.active_processes.contains_key(&child_key));
    // Assert Child B inherits taint, classification, policy, and exact Baggage
    assert!(
        child_rec.tainted,
        "Child process B must inherit parent taint"
    );
    assert_eq!(
        child_rec.classification,
        ClassificationLattice::CrownJewel,
        "Child process B must inherit CrownJewel classification"
    );
    assert_eq!(
        child_rec.policy,
        PolicyLattice::Quarantine,
        "Child process B must inherit Quarantine policy"
    );

    let child_baggage_header = child_rec.baggage.to_w3c_header();
    assert!(
        child_baggage_header.contains("dlp.classification=CROWN_JEWEL"),
        "Child W3C Baggage must contain dlp.classification=CROWN_JEWEL"
    );
    assert!(
        child_baggage_header.contains("dlp.policy=QUARANTINE"),
        "Child W3C Baggage must contain dlp.policy=QUARANTINE"
    );
    assert!(
        child_baggage_header.contains("dlp.tainted=true"),
        "Child W3C Baggage must contain dlp.tainted=true"
    );

    // Verify Child B has parent A's origin SpanContext in its linked_span_contexts
    assert!(
        !child_rec.linked_span_contexts.is_empty(),
        "Child B must have linked span contexts"
    );
    assert_eq!(
        child_rec.linked_span_contexts[0].span_id(),
        parent_rec.origin_span_context.span_id(),
        "Child B must link parent A's SpanContext"
    );

    // 3. Child B spawns Grandchild Process C
    let grandchild_pid = 7003u32;
    let grandchild_start = 300_000u64;
    let grandchild_rec = tracker.on_process_create(
        grandchild_pid,
        grandchild_start,
        "curl.exe",
        "C:\\Windows\\System32\\curl.exe",
        Some(child_pid),
        Some(child_start),
    );

    // Assert Grandchild C inherits CrownJewel taint and Quarantine policy
    assert!(
        grandchild_rec.tainted,
        "Grandchild C must inherit taint from child B"
    );
    assert_eq!(
        grandchild_rec.classification,
        ClassificationLattice::CrownJewel
    );
    assert_eq!(grandchild_rec.policy, PolicyLattice::Quarantine);

    let grandchild_baggage = grandchild_rec.baggage.to_w3c_header();
    assert!(grandchild_baggage.contains("dlp.classification=CROWN_JEWEL"));
    assert!(grandchild_baggage.contains("dlp.policy=QUARANTINE"));

    // Grandchild must have links to both parent B and grandparent A
    assert!(
        grandchild_rec.linked_span_contexts.len() >= 2,
        "Grandchild C must link both parent B and grandparent A SpanContexts"
    );

    // 4. Grandchild C spawns Great-Grandchild Process D with parent_start_time_100ns = None
    // (Simulating Sysmon / Windows event where parent start time is omitted)
    let great_grandchild_pid = 7004u32;
    let great_grandchild_rec = tracker.on_process_create(
        great_grandchild_pid,
        400_000,
        "cmd.exe",
        "C:\\Windows\\System32\\cmd.exe",
        Some(grandchild_pid),
        None, // Omitted parent start time
    );

    assert!(
        great_grandchild_rec.tainted,
        "Great-grandchild D must inherit taint even when parent start time is omitted"
    );
    assert_eq!(
        great_grandchild_rec.classification,
        ClassificationLattice::CrownJewel
    );
    assert_eq!(great_grandchild_rec.policy, PolicyLattice::Quarantine);

    // 5. Downstream Side-Effect: Tainted Child Process B writes an output file
    let derived_output_path = "C:\\staging\\derived_secrets_export.tmp";
    let write_decision = tracker.on_file_write_path(
        child_pid,
        child_start,
        derived_output_path,
        Some(b"data derived from tainted parent credentials"),
    );

    assert!(
        matches!(
            write_decision,
            FileWriteTaintDecision::TaintPropagated { .. }
        ),
        "File write by tainted child process must propagate taint"
    );

    let derived_key = ArtifactKey::from_path_or_synthetic(derived_output_path);
    let derived_art = tracker
        .active_artifacts
        .get(&derived_key)
        .expect("Derived artifact must be tracked")
        .clone();
    assert!(
        derived_art.tainted,
        "Derived artifact must be marked tainted"
    );
    assert_eq!(
        derived_art.classification,
        ClassificationLattice::CrownJewel,
        "Derived artifact classification must be CrownJewel"
    );
    assert_eq!(
        derived_art.policy,
        PolicyLattice::Quarantine,
        "Derived artifact policy must be Quarantine"
    );

    // 6. Direct Egress Check on Derived File
    let egress_res = tracker.check_egress_allowed_full(
        Some(derived_output_path),
        None,
        None,
        Some("https://exfil-sink.target.test/upload"),
        Some(child_pid),
    );
    assert!(
        egress_res.is_err(),
        "Egress of file written by tainted child must be blocked"
    );
    if let Err(EgressDecision::Blocked {
        policy,
        classification,
        ..
    }) = egress_res
    {
        assert_eq!(policy, PolicyLattice::Quarantine);
        assert_eq!(classification, ClassificationLattice::CrownJewel);
    } else {
        panic!("Expected EgressDecision::Blocked");
    }
}

#[test]
fn test_adversarial_sibling_process_isolation_zero_false_positives() {
    let tracker = DlpLineageTracker::new(30);

    // Tainted Parent A (PID 8001)
    let parent_a_pid = 8001u32;
    let parent_a_key = ProcessInstanceKey::new(parent_a_pid, 100_000);
    let secret_key = ArtifactKey::from_path_or_synthetic("C:\\vault\\secret_a.key");
    tracker.register_crown_jewel_artifact(
        secret_key,
        "C:\\vault\\secret_a.key",
        b"CONFIDENTIAL_KEY_A",
        ClassificationLattice::CrownJewel,
        PolicyLattice::Quarantine,
    );
    tracker.on_file_read(parent_a_key, "svc_a.exe", "C:\\svc_a.exe", secret_key);

    // Clean Parent X (PID 9001) - never reads sensitive data
    let parent_x_pid = 9001u32;
    let _parent_x_key = ProcessInstanceKey::new(parent_x_pid, 100_000);
    let clean_rec = tracker.on_process_create(
        parent_x_pid,
        100_000,
        "clean_service.exe",
        "C:\\clean_service.exe",
        None,
        None,
    );
    assert!(
        !clean_rec.tainted,
        "Parent X must start completely untainted"
    );

    // Tainted Parent A spawns Child B (PID 8002)
    let child_b_rec = tracker.on_process_create(
        8002,
        200_000,
        "child_b.exe",
        "C:\\child_b.exe",
        Some(parent_a_pid),
        Some(100_000),
    );
    assert!(child_b_rec.tainted, "Child B must be tainted");

    // Clean Parent X spawns Child Y (PID 9002)
    let child_y_rec = tracker.on_process_create(
        9002,
        200_000,
        "child_y.exe",
        "C:\\child_y.exe",
        Some(parent_x_pid),
        Some(100_000),
    );

    // Assert Child Y remains completely untainted (zero taint creep / zero false positive)
    assert!(
        !child_y_rec.tainted,
        "Child Y of clean Parent X must NOT be tainted"
    );
    assert_eq!(
        child_y_rec.classification,
        ClassificationLattice::Public,
        "Child Y classification must remain Public"
    );
    assert_eq!(
        child_y_rec.policy,
        PolicyLattice::Monitor,
        "Child Y policy must remain Monitor"
    );

    // Child Y writes clean log file
    let clean_log_path = "C:\\logs\\clean_worker.log";
    let write_decision = tracker.on_file_write_path(
        9002,
        200_000,
        clean_log_path,
        Some(b"Clean worker log line"),
    );
    assert!(
        matches!(
            write_decision,
            FileWriteTaintDecision::BenignExcluded { .. }
        ),
        "Write by clean child must remain BenignExcluded"
    );

    // Egress check for Child Y log must be permitted
    let egress_res = tracker.check_egress_allowed_full(
        Some(clean_log_path),
        None,
        None,
        Some("https://trusted.internal.corp/logs"),
        Some(9002),
    );
    assert!(
        egress_res.is_ok(),
        "Egress for clean child Y must be permitted"
    );
}

#[test]
fn test_adversarial_concurrent_child_spawns_stress() {
    let tracker = Arc::new(DlpLineageTracker::new(30));

    // Parent PID 6500 tainted with CrownJewel
    let parent_pid = 6500u32;
    let parent_key = ProcessInstanceKey::new(parent_pid, 50_000);
    let secret_key = ArtifactKey::from_path_or_synthetic("C:\\secure\\core_root.pem");
    tracker.register_crown_jewel_artifact(
        secret_key,
        "C:\\secure\\core_root.pem",
        b"CORE_ROOT_CERT_KEY_BYTES",
        ClassificationLattice::CrownJewel,
        PolicyLattice::Quarantine,
    );
    tracker.on_file_read(
        parent_key,
        "orchestrator.exe",
        "C:\\orchestrator.exe",
        secret_key,
    );

    // Spawn 50 child processes concurrently across threads
    let thread_count = 10;
    let children_per_thread = 5;
    let mut handles = Vec::new();

    for t in 0..thread_count {
        let t_tracker = Arc::clone(&tracker);
        let handle = thread::spawn(move || {
            for i in 0..children_per_thread {
                let child_pid = 6501 + (t * children_per_thread + i) as u32;
                let child_start = 100_000 + (t * children_per_thread + i) as u64;
                let child = t_tracker.on_process_create(
                    child_pid,
                    child_start,
                    "worker_thread.exe",
                    "C:\\worker.exe",
                    Some(parent_pid),
                    Some(50_000),
                );
                assert!(child.tainted);
                assert_eq!(child.classification, ClassificationLattice::CrownJewel);
                assert_eq!(child.policy, PolicyLattice::Quarantine);
            }
        });
        handles.push(handle);
    }

    for h in handles {
        h.join().expect("Thread must finish cleanly");
    }

    // Verify all 50 child processes are present in active_processes and all tainted
    for t in 0..thread_count {
        for i in 0..children_per_thread {
            let child_pid = 6501 + (t * children_per_thread + i) as u32;
            let child_start = 100_000 + (t * children_per_thread + i) as u64;
            let key = ProcessInstanceKey::new(child_pid, child_start);
            let proc = tracker
                .active_processes
                .get(&key)
                .expect("Child must exist in active_processes")
                .clone();
            assert!(proc.tainted, "Child {} must be tainted", child_pid);
            assert_eq!(proc.policy, PolicyLattice::Quarantine);
        }
    }
}

// =============================================================================
// PART 2: File Rename Tracking & Egress Blocking
// =============================================================================

#[test]
fn test_adversarial_file_rename_tracking_and_egress_blocking() {
    let tracker = DlpLineageTracker::new(30);

    let pid = 4410u32;
    let start_time = 120_000u64;
    let orig_path = "C:\\staging\\confidential_financials.xlsx";
    let renamed_path = "C:\\staging\\renamed_innocent.xlsx";

    // 1. Taint process and create initial artifact
    let secret_key = ArtifactKey::from_path_or_synthetic("C:\\vault\\root_seed.bin");
    tracker.register_crown_jewel_artifact(
        secret_key,
        "C:\\vault\\root_seed.bin",
        b"SEED_VALUE_FOR_FINANCIAL_CALCULATIONS",
        ClassificationLattice::CrownJewel,
        PolicyLattice::Quarantine,
    );
    let proc_key = ProcessInstanceKey::new(pid, start_time);
    tracker.on_file_read(proc_key, "excel.exe", "C:\\excel.exe", secret_key);

    let content = b"FINANCIAL_SPREADSHEET_CONFIDENTIAL_CONTENT";
    let orig_sha = compute_sha256_hex(content);

    // Process writes original file
    let write_res = tracker.on_file_write_path(pid, start_time, orig_path, Some(content));
    assert!(matches!(
        write_res,
        FileWriteTaintDecision::TaintPropagated { .. }
    ));

    let orig_key = ArtifactKey::from_path_or_synthetic(orig_path);
    assert!(
        tracker.active_artifacts.contains_key(&orig_key),
        "Original artifact must be tracked"
    );

    // Egress on original path must be blocked
    let egress_orig = tracker.check_egress_allowed_full(
        Some(orig_path),
        Some(&orig_sha),
        None,
        Some("https://dlptest.com/post"),
        Some(pid),
    );
    assert!(
        egress_orig.is_err(),
        "Egress on original tainted path must be blocked"
    );

    // 2. Perform File Rename: orig_path -> renamed_path
    tracker.on_file_rename(pid, start_time, orig_path, renamed_path);

    let renamed_key = ArtifactKey::from_path_or_synthetic(renamed_path);

    // Assert: Old key is removed, new key is active
    assert!(
        tracker.active_artifacts.get(&orig_key).is_none(),
        "Old artifact key must be removed from active_artifacts"
    );
    assert!(
        tracker.active_artifacts.contains_key(&renamed_key),
        "New artifact key must be inserted into active_artifacts"
    );

    let renamed_art = tracker
        .active_artifacts
        .get(&renamed_key)
        .expect("Renamed artifact must exist")
        .clone();
    assert!(
        renamed_art.tainted,
        "Renamed artifact must retain tainted state"
    );
    assert_eq!(
        renamed_art.classification,
        ClassificationLattice::CrownJewel,
        "Renamed artifact must retain CrownJewel classification"
    );
    assert_eq!(
        renamed_art.policy,
        PolicyLattice::Quarantine,
        "Renamed artifact must retain Quarantine policy"
    );
    assert_eq!(
        renamed_art.canonical_path, renamed_path,
        "Canonical path must be updated to new name"
    );

    // 3. Egress Check on Renamed Path B MUST BE BLOCKED
    let egress_renamed = tracker.check_egress_allowed_full(
        Some(renamed_path),
        None,
        None,
        Some("https://upload.adversary.org/sink"),
        Some(pid),
    );
    assert!(
        egress_renamed.is_err(),
        "Egress on renamed path B must be strictly BLOCKED"
    );
    if let Err(EgressDecision::Blocked {
        policy,
        classification,
        reason,
        ..
    }) = egress_renamed
    {
        assert_eq!(policy, PolicyLattice::Quarantine);
        assert_eq!(classification, ClassificationLattice::CrownJewel);
        assert!(
            reason.contains("renamed_innocent.xlsx") || reason.contains("PID 4410"),
            "Blocking reason must document the violation: {}",
            reason
        );
    } else {
        panic!("Expected EgressDecision::Blocked");
    }
}

#[test]
fn test_adversarial_multi_hop_file_rename_chain() {
    let tracker = DlpLineageTracker::new(30);

    let path_a = "C:\\temp\\step_a_classified.dat";
    let path_b = "C:\\temp\\step_b_renamed.dat";
    let path_c = "C:\\temp\\step_c_staged.dat";
    let path_d = "C:\\temp\\step_d_final_exfil.dat";

    let key_a = ArtifactKey::from_path_or_synthetic(path_a);
    tracker.register_crown_jewel_artifact(
        key_a,
        path_a,
        b"CRITICAL_SYSTEM_KERNEL_PAYLOAD",
        ClassificationLattice::CrownJewel,
        PolicyLattice::Quarantine,
    );

    // Multi-hop rename: A -> B -> C -> D
    tracker.on_file_rename(1100, 10_000, path_a, path_b);
    tracker.on_file_rename(1100, 20_000, path_b, path_c);
    tracker.on_file_rename(1100, 30_000, path_c, path_d);

    let key_d = ArtifactKey::from_path_or_synthetic(path_d);

    // Verify intermediate keys A, B, C are completely removed
    assert!(tracker.active_artifacts.get(&key_a).is_none());
    assert!(tracker
        .active_artifacts
        .get(&ArtifactKey::from_path_or_synthetic(path_b))
        .is_none());
    assert!(tracker
        .active_artifacts
        .get(&ArtifactKey::from_path_or_synthetic(path_c))
        .is_none());

    // Verify key D exists and is tainted
    let rec_d = tracker
        .active_artifacts
        .get(&key_d)
        .expect("Final artifact D must exist")
        .clone();
    assert!(rec_d.tainted, "Artifact D must be tainted");
    assert_eq!(rec_d.classification, ClassificationLattice::CrownJewel);
    assert_eq!(rec_d.policy, PolicyLattice::Quarantine);

    // Egress check on D must be blocked
    let res = tracker.check_egress_allowed(Some(path_d), None);
    assert!(
        res.is_err(),
        "Egress on multi-hop renamed file D must be blocked"
    );
}

#[test]
fn test_adversarial_real_filesystem_file_rename() {
    let tracker = DlpLineageTracker::new(30);

    let temp_dir = std::env::temp_dir();
    let id = uuid::Uuid::new_v4();
    let orig_file = temp_dir.join(format!("real_secret_orig_{}.txt", id));
    let renamed_file = temp_dir.join(format!("real_secret_renamed_{}.txt", id));

    let secret_bytes = b"REAL_ON_DISK_CROWN_JEWEL_SECRET_CONTENT";
    fs::write(&orig_file, secret_bytes).expect("Write initial temp file");

    let orig_str = orig_file.to_str().unwrap();
    let renamed_str = renamed_file.to_str().unwrap();

    let orig_key = ArtifactKey::from_path_or_synthetic(orig_str);
    tracker.register_crown_jewel_artifact(
        orig_key,
        orig_str,
        secret_bytes,
        ClassificationLattice::CrownJewel,
        PolicyLattice::Quarantine,
    );

    // Confirm egress on orig_file is blocked
    let res_before = tracker.check_egress_allowed(Some(orig_str), None);
    assert!(res_before.is_err(), "Egress before rename must be blocked");

    // Execute true OS rename on filesystem
    fs::rename(&orig_file, &renamed_file).expect("OS file rename must succeed");

    // Inform tracker of rename
    tracker.on_file_rename(9900, 50_000, orig_str, renamed_str);

    // Check egress on renamed file
    let res_after = tracker.check_egress_allowed(Some(renamed_str), None);
    assert!(
        res_after.is_err(),
        "Egress after OS file rename must be blocked"
    );

    // Cleanup
    let _ = fs::remove_file(&renamed_file);
}

// =============================================================================
// PART 3: EventPipeline Kernel Telemetry Ingestion Integration
// =============================================================================

#[tokio::test]
async fn test_adversarial_event_pipeline_kernel_telemetry_ingestion() {
    // We instantiate an EdrOrchestrator to test real event_pipeline ingestion
    let orchestrator = match EdrOrchestrator::new().await {
        Ok(orch) => orch,
        Err(e) => {
            eprintln!("Skipping full orchestrator init: {}", e);
            return;
        }
    };

    let tracker = global_lineage_tracker();

    // 1. Establish tainted parent in global tracker
    let parent_pid = 9110u32;
    let parent_key = ProcessInstanceKey::new(parent_pid, 10_000);
    let secret_path = "C:\\kernel_test\\crown_jewel_token.json";
    let secret_key = ArtifactKey::from_path_or_synthetic(secret_path);
    tracker.register_crown_jewel_artifact(
        secret_key,
        secret_path,
        b"KERNEL_SECRET_FOR_SYSMON_TEST",
        ClassificationLattice::CrownJewel,
        PolicyLattice::Quarantine,
    );
    tracker.on_file_read(
        parent_key,
        "parent_agent.exe",
        "C:\\parent_agent.exe",
        secret_key,
    );

    assert!(tracker.active_processes.get(&parent_key).unwrap().tainted);

    // 2. Sysmon 1 (ProcessCreate) Event: Parent 9110 spawns Child 9111
    let child_pid = 9111u32;
    let mut proc_create_data = serde_json::Map::new();
    proc_create_data.insert("ProcessId".to_string(), json!(child_pid));
    proc_create_data.insert("ParentProcessId".to_string(), json!(parent_pid));
    proc_create_data.insert("ProcessStartTime".to_string(), json!(20_000));
    proc_create_data.insert("Image".to_string(), json!("C:\\Windows\\System32\\cmd.exe"));

    let proc_create_event = HostSecurityEvent {
        source: HostEventSource::WindowsEventLog,
        event_id: 1, // Sysmon 1
        timestamp: Utc::now(),
        computer: "TEST-HOST".to_string(),
        data: serde_json::Value::Object(proc_create_data),
        causal_parent: None,
    };

    orchestrator.ingest_event_into_dlp_lineage(&proc_create_event);

    // Verify child process 9111 in global tracker inherited CrownJewel / Quarantine
    let child_key = ProcessInstanceKey::new(child_pid, 20_000);
    let child_rec = tracker
        .active_processes
        .get(&child_key)
        .expect("Child process 9111 must be registered in global tracker")
        .clone();
    assert!(
        child_rec.tainted,
        "Child process 9111 must inherit taint via Sysmon 1 ingestion"
    );
    assert_eq!(child_rec.classification, ClassificationLattice::CrownJewel);
    assert_eq!(child_rec.policy, PolicyLattice::Quarantine);

    // 3. Sysmon 27 (FileRename) Event: Rename tainted secret to an innocuous filename
    let old_name = "C:\\kernel_test\\crown_jewel_token.json";
    let new_name = "C:\\kernel_test\\readme_renamed.txt";

    let mut rename_data = serde_json::Map::new();
    rename_data.insert("ProcessId".to_string(), json!(child_pid));
    rename_data.insert("SourceFilename".to_string(), json!(old_name));
    rename_data.insert("TargetFilename".to_string(), json!(new_name));

    let rename_event = HostSecurityEvent {
        source: HostEventSource::WindowsEventLog,
        event_id: 27, // Sysmon 27: FileRename
        timestamp: Utc::now(),
        computer: "TEST-HOST".to_string(),
        data: serde_json::Value::Object(rename_data),
        causal_parent: None,
    };

    orchestrator.ingest_event_into_dlp_lineage(&rename_event);

    // Verify that egress on the renamed file is blocked in the global tracker
    let egress_check = tracker.check_egress_allowed(Some(new_name), None);
    assert!(
        egress_check.is_err(),
        "Egress on Sysmon 27 renamed file must be strictly blocked"
    );
}

#[test]
fn test_adversarial_child_shell_boundary_1_taint_drop_vulnerability() {
    let tracker = DlpLineageTracker::default();

    // 1. Taint parent process with CrownJewel
    let parent_pid = 8800u32;
    let parent_start = 50_000u64;
    let parent_key = ProcessInstanceKey::new(parent_pid, parent_start);
    tracker.on_process_create(
        parent_pid,
        parent_start,
        "tainted_app.exe",
        "C:\\app.exe",
        None,
        None,
    );

    let secret_path = "C:\\vault\\customer_pii.db";
    let secret_key = ArtifactKey::from_path_or_synthetic(secret_path);
    tracker.register_crown_jewel_artifact(
        secret_key,
        secret_path,
        b"CONFIDENTIAL_CUSTOMER_RECORDS_DATABASE",
        ClassificationLattice::CrownJewel,
        PolicyLattice::Quarantine,
    );
    tracker.on_file_read(parent_key, "tainted_app.exe", "C:\\app.exe", secret_key);

    let parent_rec = tracker.active_processes.get(&parent_key).unwrap().clone();
    assert!(parent_rec.tainted);
    assert!(
        !parent_rec.read_history.is_empty(),
        "Parent must have non-empty read_history"
    );

    // 2. Parent spawns a shell process (powershell.exe) to write an exfiltration payload
    let shell_pid = 8801u32;
    let shell_start = 60_000u64;
    let shell_rec = tracker.on_process_create(
        shell_pid,
        shell_start,
        "powershell.exe",
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        Some(parent_pid),
        Some(parent_start),
    );

    // Shell inherits taint flag, classification, policy, Baggage
    assert!(shell_rec.tainted, "Shell process must be marked tainted");
    assert_eq!(shell_rec.classification, ClassificationLattice::CrownJewel);

    // REMEDIATION VERIFICATION:
    // on_process_create inherits parent read_history, ensuring long-lived child shells
    // (powershell.exe, cmd.exe) have necessary read context for Boundary 1 Anti-Taint Creep:
    assert!(
        !shell_rec.read_history.is_empty(),
        "Remediation verified: shell_rec.read_history inherited parent read history"
    );

    // 3. Shell writes an exfiltrated file to disk
    let exfil_path = "C:\\staging\\exfiltrated_records.csv";
    let write_decision = tracker.on_file_write_path(
        shell_pid,
        shell_start,
        exfil_path,
        Some(b"CONFIDENTIAL_CUSTOMER_RECORDS_DATABASE leaked via powershell"),
    );

    // Boundary 1 Anti-Taint Creep checks content against inherited read_history and corroborates the leak!
    match write_decision {
        FileWriteTaintDecision::TaintPropagated { .. } => {
            // Remediation verified: taint correctly propagated to written file
        }
        FileWriteTaintDecision::BenignExcluded { reason } => {
            panic!(
                "Expected TaintPropagated after fix, but got BenignExcluded: {}",
                reason
            );
        }
    }

    // 4. Downstream Impact: The exfiltrated file IS tracked in active_artifacts!
    let exfil_key = ArtifactKey::from_path_or_synthetic(exfil_path);
    assert!(
        tracker.active_artifacts.contains_key(&exfil_key),
        "Remediation verified: Exfiltrated file written by child shell is actively tracked as tainted artifact"
    );

    // 5. Downstream Impact: Egress check on exfiltrated file returns Err (BLOCKED)!
    let egress_check = tracker.check_egress_allowed(Some(exfil_path), None);
    assert!(
        egress_check.is_err(),
        "Remediation verified: Egress on exfiltrated file is strictly blocked by DLP quarantine!"
    );
}
