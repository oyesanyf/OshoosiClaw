//! Empirical Adversarial Challenge Suite for DlpLineageTracker + Siquery-rs Bidirectional Correlation (Milestone 2)
//!
//! Validates:
//! 1. End-to-end bidirectional correlation between DlpLineageTracker and SiqueryEngine.
//! 2. Causal taint propagation across child process creation (on_process_create) and derived file writes.
//! 3. Siquery hooks correctly surfacing active open files and live file events.
//! 4. Synchronous inline egress blocking on tainted files correlated through lineage/siquery.
//! 5. Zero-PII OpenTelemetry resource and span attributes sanitization (basic auth stripping).

use chrono::Utc;
use osoosi_agent_anomaly::siquery::{record_live_file_event, FileEventRecord, SiqueryEngine};
use osoosi_core::dlp_lineage::{
    build_zero_pii_otel_attributes, ArtifactKey, ClassificationLattice, DlpLineageTracker,
    EgressDecision, FileWriteTaintDecision, PolicyLattice, ProcessInstanceKey,
};

#[test]
fn challenge_dlp_lineage_siquery_bidirectional_correlation_and_egress() {
    let tracker: &'static DlpLineageTracker = Box::leak(Box::new(DlpLineageTracker::new(60)));
    let engine = SiqueryEngine::new();

    // 1. Register a Crown Jewel asset in DlpLineageTracker
    let cj_path = "C:\\confidential\\financial_model_q3.xlsx";
    let cj_key = ArtifactKey::from_path_or_synthetic(cj_path);
    let cj_bytes = b"CONFIDENTIAL_FINANCIAL_FORECAST_DATA_2026";
    let cj_record = tracker.register_crown_jewel_artifact(
        cj_key,
        cj_path,
        cj_bytes,
        ClassificationLattice::CrownJewel,
        PolicyLattice::Quarantine,
    );
    assert!(cj_record.tainted);
    assert_eq!(cj_record.classification, ClassificationLattice::CrownJewel);

    // 2. Process reads the crown jewel
    let parent_pid = 6543u32;
    let parent_start = 1_000_000u64;
    let parent_key = ProcessInstanceKey::new(parent_pid, parent_start);
    tracker.on_file_read(
        parent_key,
        "calc_engine.exe",
        "C:\\bin\\calc_engine.exe",
        cj_key,
    );

    // Verify parent process is tainted
    let parent_rec = tracker
        .active_processes
        .get(&parent_key)
        .expect("Parent process must be tracked");
    assert!(parent_rec.tainted, "Parent process must be tainted after reading Crown Jewel");
    assert_eq!(parent_rec.classification, ClassificationLattice::CrownJewel);
    assert_eq!(parent_rec.policy, PolicyLattice::Quarantine);
    drop(parent_rec);

    // 3. Child process is spawned from tainted parent: on_process_create propagates taint
    let child_pid = 6544u32;
    let child_start = 1_000_500u64;
    let child_rec = tracker.on_process_create(
        child_pid,
        child_start,
        "exporter.exe",
        "C:\\bin\\exporter.exe",
        Some(parent_pid),
        Some(parent_start),
    );
    assert!(
        child_rec.tainted,
        "Child process must inherit taint from parent process"
    );
    assert_eq!(
        child_rec.classification,
        ClassificationLattice::CrownJewel,
        "Child must inherit CrownJewel classification"
    );
    assert_eq!(
        child_rec.policy,
        PolicyLattice::Quarantine,
        "Child must inherit Quarantine policy"
    );

    // 4. Child process writes a derived file
    let derived_path = "C:\\temp\\export_summary.csv";
    let derived_bytes = b"DERIVED_AGGREGATE_REVENUE_NUMBERS";
    let write_decision =
        tracker.on_file_write_path(child_pid, child_start, derived_path, Some(derived_bytes));
    assert!(
        matches!(write_decision, FileWriteTaintDecision::TaintPropagated { .. }),
        "Derived file write by tainted child process must propagate taint"
    );

    // 5. Register bidirectional hooks with siquery
    tracker.register_siquery_hooks();

    // Record a live file event into siquery-rs matching the derived file
    record_live_file_event(FileEventRecord {
        target_path: derived_path.to_string(),
        action: "WRITE".to_string(),
        pid: child_pid as i64,
        process_name: "exporter.exe".to_string(),
        sha256: cj_record.sha256.clone(),
        time: Utc::now().timestamp(),
    });

    // 6. Correlate with siquery engine
    let corr_count = tracker
        .correlate_with_siquery(&engine)
        .expect("correlate_with_siquery must succeed");
    assert!(
        corr_count >= 1,
        "correlate_with_siquery must correlate at least 1 file event or open file"
    );

    // 7. Verify egress blocking:
    // Tainted derived file MUST be blocked on outbound egress
    let egress_res = tracker.check_egress_allowed(Some(derived_path), None);
    assert!(
        egress_res.is_err(),
        "Egress of tainted derived file must be blocked"
    );
    if let Err(EgressDecision::Blocked { policy, classification, .. }) = egress_res {
        assert_eq!(policy, PolicyLattice::Quarantine);
        assert_eq!(classification, ClassificationLattice::CrownJewel);
    } else {
        panic!("Expected EgressDecision::Blocked");
    }

    // Untainted file MUST be allowed
    let untainted_res = tracker.check_egress_allowed(Some("C:\\public\\normal_document.txt"), None);
    assert!(
        untainted_res.is_ok(),
        "Untainted file egress must be permitted"
    );

    // 8. Verify Zero-PII OpenTelemetry attributes
    let raw_auth_url = "https://admin:super_secret_password_999@attacker-leak.io/upload";
    let attrs = build_zero_pii_otel_attributes(
        Some(child_pid),
        Some(parent_pid),
        Some("C:\\bin\\exporter.exe"),
        Some(derived_path),
        Some(raw_auth_url),
        Some("export_task"),
        Some(derived_bytes),
        None,
        None,
    );

    let attr_map: std::collections::HashMap<String, String> = attrs
        .into_iter()
        .map(|kv| (kv.key.as_str().to_string(), kv.value.to_string()))
        .collect();

    assert_eq!(
        attr_map.get("process.pid").map(|s| s.as_str()),
        Some("6544")
    );
    assert_eq!(
        attr_map.get("process.parent_pid").map(|s| s.as_str()),
        Some("6543")
    );
    assert!(attr_map.contains_key("file.hash.sha256"));
    assert!(attr_map.contains_key("file.hash.ssdeep"));
    assert!(attr_map.contains_key("file.hash.blake3"));

    // Verify sanitization of basic auth credentials in URL
    let sanitized_url = attr_map.get("url.full").expect("url.full must be present");
    assert!(
        !sanitized_url.contains("super_secret_password_999"),
        "URL attributes must NEVER contain raw passwords or basic auth credentials"
    );
    assert!(
        !sanitized_url.contains("admin:"),
        "URL attributes must NEVER contain raw usernames"
    );
    assert!(sanitized_url.starts_with("https://attacker-leak.io/"));
}
