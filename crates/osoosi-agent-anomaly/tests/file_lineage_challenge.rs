//! Empirical Challenge Suite for FileLineageTracker (Milestone M2A).
//!
//! Adversarial verification harness validating:
//! 1. Lineage Hashing: BLAKE3 hashes match known standard test vectors and reference values.
//! 2. Repository & System Immunity: Attempts to poison paths inside `resolve_project_root()`
//!    or developer toolchains (python.exe, cargo.exe, git.exe, node.exe) return `LineageError::ImmuneTarget`
//!    and refuse addition to `poisoned_digests`.
//! 3. Bounded Capacity: Ingesting > 16,384 entries evicts oldest entries without panicking,
//!    exceeding bounds, or leaking memory.
//! 4. Attributed Canary Alert Immunity: Sessions with only immune files reject attribution.

use std::path::PathBuf;
use osoosi_agent_anomaly::file_lineage::{
    FileLineageTracker, LineageError, DEFAULT_MAX_CAPACITY,
};
use osoosi_types::resolve_project_root;

/// Challenge 1: Lineage Hashing against authoritative BLAKE3 reference test vectors.
#[test]
fn challenge_lineage_blake3_reference_vectors() {
    // Standard BLAKE3 official test vectors
    // Empty input:
    // af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262
    let empty_hash = FileLineageTracker::compute_blake3(b"");
    assert_eq!(
        empty_hash,
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
        "Empty byte slice BLAKE3 hash mismatch"
    );

    // "hello world"
    // BLAKE3: d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24
    let hello_hash = FileLineageTracker::compute_blake3(b"hello world");
    assert_eq!(
        hello_hash,
        "d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24",
        "Reference 'hello world' BLAKE3 hash mismatch"
    );

    // Direct comparison with standalone blake3 crate hash
    let sample_data = b"OpenOsoosi-BLAKE3-Verification-Payload-2026-Empirical-Challenge";
    let tracker_hash = FileLineageTracker::compute_blake3(sample_data);
    let reference_hash = blake3::hash(sample_data).to_hex().to_string();
    assert_eq!(tracker_hash, reference_hash);

    // Verify disk file hashing matches memory hashing
    let temp_dir = std::env::temp_dir();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let temp_file = temp_dir.join(format!("test_lineage_blake3_{}.tmp", now));
    std::fs::write(&temp_file, sample_data).expect("Write temp file");

    let file_hash = FileLineageTracker::compute_file_blake3(&temp_file)
        .expect("Compute file BLAKE3");
    let _ = std::fs::remove_file(&temp_file);

    assert_eq!(file_hash, reference_hash, "File BLAKE3 hash must match slice hash");
}

/// Challenge 2: Repository and System Immunity
/// Verifies that repository files, developer toolchains, and critical OS processes can NEVER be poisoned.
#[test]
fn challenge_repository_and_system_immunity() {
    let tracker = FileLineageTracker::new();

    // 1. Project Root Immunity
    let root = resolve_project_root().expect("Must resolve project root in workspace");
    let cargo_toml = root.join("Cargo.toml");
    let lib_rs = root.join("crates").join("osoosi-agent-anomaly").join("src").join("lib.rs");

    assert!(tracker.is_path_immune(&cargo_toml), "Cargo.toml in root must be immune");
    assert!(tracker.is_path_immune(&lib_rs), "crates/.../lib.rs must be immune");

    // Ingest Cargo.toml into tracker
    let cargo_digest = tracker
        .record_ingested_file("test_session_root", &cargo_toml, &[])
        .expect("Recording immune file must succeed");

    // Attempting to poison its digest must fail with ImmuneTarget error
    let poison_res = tracker.mark_digest_poisoned(
        &cargo_digest,
        "test_session_root",
        "Adversarial attempt on Cargo.toml",
        1.0,
    );
    match poison_res {
        Err(LineageError::ImmuneTarget(msg)) => {
            assert!(msg.contains("immune"), "Error must mention immunity: {}", msg);
        }
        other => panic!("Expected Err(LineageError::ImmuneTarget), got {:?}", other),
    }
    assert!(
        !tracker.is_poisoned_digest(&cargo_digest),
        "Immune Cargo.toml digest must NOT be marked poisoned"
    );

    // Swarm immunization attempt on immune Cargo.toml must also fail
    let swarm_res = tracker.immunize_poisoned_digest(&cargo_digest, "Malicious swarm claim");
    assert!(
        matches!(swarm_res, Err(LineageError::ImmuneTarget(_))),
        "Swarm immunization must reject immune target"
    );

    // 2. Developer Toolchain & Protected Binary Immunity
    let toolchains = [
        "python.exe",
        "python",
        "python3.exe",
        "cargo.exe",
        "cargo",
        "git.exe",
        "git",
        "node.exe",
        "node",
        r"C:\Program Files\Git\cmd\git.exe",
        r"C:\Users\dev\.cargo\bin\cargo.exe",
        r"C:\Python314\python.exe",
    ];

    for tool in &toolchains {
        let p = PathBuf::from(tool);
        assert!(
            tracker.is_path_immune(&p),
            "Toolchain binary {:?} must be classified as immune",
            p
        );

        let ingest_res = tracker.record_ingested_file(
            "dev_session",
            &p,
            tool.as_bytes(),
        );
        let digest = ingest_res.expect("Recording developer binary should succeed");

        // Attempt to poison toolchain digest
        let poison_tool = tracker.mark_digest_poisoned(
            &digest,
            "dev_session",
            "Poison attempt on developer binary",
            1.0,
        );
        match poison_tool {
            Err(LineageError::ImmuneTarget(_)) => {}
            other => panic!("Toolchain {:?} poisoning was not blocked! Got {:?}", tool, other),
        }
        assert!(
            !tracker.is_poisoned_digest(&digest),
            "Toolchain {:?} digest must NOT be marked poisoned",
            tool
        );
    }
}

/// Challenge 2B: Attribute Canary Alert on sessions containing ONLY immune files must return None.
#[test]
fn challenge_canary_alert_attribution_rejects_immune_only_sessions() {
    let tracker = FileLineageTracker::new();
    let root = resolve_project_root().expect("Must resolve project root");
    let immune_file1 = root.join("Cargo.toml");
    let immune_file2 = PathBuf::from("git.exe");

    let _ = tracker.record_ingested_file("immune_session", &immune_file1, &[]);
    let _ = tracker.record_ingested_file("immune_session", &immune_file2, b"git binary simulation");

    // All files in session are immune. Canary alert attribution should find NO non-immune files!
    let attributed = tracker.attribute_canary_alert(
        "immune_session",
        "alert_canary_1",
        r"\\.\pipe\osoosi_canary_trap",
    );

    assert_eq!(
        attributed, None,
        "Canary alert attribution MUST NOT attribute or poison immune files"
    );
    assert_eq!(tracker.poisoned_count(), 0);
}

/// Challenge 3: Bounded Capacity Stress Harness (> 16,384 entries).
/// Verifies strict bounded capacity with FIFO eviction, zero panics, and zero memory leaks.
#[test]
fn challenge_bounded_capacity_stress_exceeding_16384() {
    let tracker = FileLineageTracker::new();
    assert_eq!(tracker.max_capacity, DEFAULT_MAX_CAPACITY);
    assert_eq!(tracker.max_capacity, 16_384);

    let test_count = 20_000usize;
    println!("Beginning stress harness: inserting {} entries into bounded map...", test_count);

    // 1. Stress poisoned_digests map
    for i in 0..test_count {
        let digest = format!("{:064x}", i);
        let res = tracker.mark_digest_poisoned(
            &digest,
            "stress_session",
            "bounded_stress_test",
            1.0,
        );
        assert!(res.is_ok(), "Insertion {} should succeed without panic", i);
    }

    // Assert strictly bounded
    let count = tracker.poisoned_count();
    assert_eq!(
        count, DEFAULT_MAX_CAPACITY,
        "Poisoned count must be capped strictly at 16,384 (got {})",
        count
    );

    // Verify FIFO eviction:
    // First (test_count - 16,384) = 3,616 entries (0..3616) must be evicted
    let evicted_boundary = test_count - DEFAULT_MAX_CAPACITY;
    for i in 0..100 {
        let evicted_digest = format!("{:064x}", i);
        assert!(
            !tracker.is_poisoned_digest(&evicted_digest),
            "Oldest entry {} should have been evicted",
            i
        );
    }
    let boundary_evicted = format!("{:064x}", evicted_boundary - 1);
    assert!(
        !tracker.is_poisoned_digest(&boundary_evicted),
        "Entry {} right before boundary should have been evicted",
        evicted_boundary - 1
    );

    // Latest entries must remain present
    for i in evicted_boundary..(evicted_boundary + 100) {
        let retained_digest = format!("{:064x}", i);
        assert!(
            tracker.is_poisoned_digest(&retained_digest),
            "Entry {} at or above boundary must be retained",
            i
        );
    }
    let last_digest = format!("{:064x}", test_count - 1);
    assert!(
        tracker.is_poisoned_digest(&last_digest),
        "Last inserted entry must be retained"
    );

    // 2. Stress session_files map per session
    let single_session = "single_session_high_volume";
    for i in 0..17_000usize {
        let path = PathBuf::from(format!("C:\\temp\\untrusted_file_{}.dat", i));
        let content = format!("Payload content {}", i).into_bytes();
        let _ = tracker.record_ingested_file(single_session, &path, &content);
    }

    let session_lineage = tracker.get_session_lineage(single_session);
    assert_eq!(
        session_lineage.len(),
        DEFAULT_MAX_CAPACITY,
        "Session lineage queue must be bounded to 16,384"
    );
    // Oldest file in session must be evicted
    assert_eq!(
        session_lineage.first().unwrap().path,
        PathBuf::from("C:\\temp\\untrusted_file_616.dat")
    );
    assert_eq!(
        session_lineage.last().unwrap().path,
        PathBuf::from("C:\\temp\\untrusted_file_16999.dat")
    );
}
