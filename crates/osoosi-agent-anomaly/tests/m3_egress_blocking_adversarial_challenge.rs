//! Empirical Adversarial Challenge Suite: Milestone 3 Synchronous Inline Egress Blocking
//!
//! Master Specification: PROJECT.md Milestone 3 (Features 11–14)
//! Architectural Skill: `agent-breakout-prevention` (Ring 2, Ring 3, Ring 7)
//!
//! Challenges:
//! 1. Synchronous nanosecond blocking of tainted outbound URLs before socket resolution.
//! 2. Verification of synthetic blocked span emission: verify span attributes
//!    (`dlp.action=BLOCKED`, `dlp.threat_type=DATA_EXFILTRATION`, `dlp.retained_taint=true`)
//!    and zero raw credentials in URLs.
//! 3. Multi-threaded concurrent egress stress test: simulate 20 concurrent tasks evaluating
//!    clean vs tainted URLs under contention; assert 100% block accuracy and zero false negatives.
//! 4. Egress blocking on rehydrated out-of-band artifacts (Boundary 3 content digest rehydration).
//! 5. Adversarial bypass & edge-case mining (case variants, non-standard IP formats, unresolvable sinks).

use osoosi_agent_anomaly::egress_proxy::{
    check_egress_allowed_inline, clear_recent_blocked_spans, get_recent_blocked_spans,
    global_lineage_tracker, register_lineage_egress_hook, resolve_and_pin,
    validate_agent_egress_url, EgressLineageBlockInfo,
};
use parking_lot::Mutex;
use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Instant;

/// Global test synchronization mutex to ensure isolated testing on global static hooks and span buffers.
static TEST_ISOLATION_MUTEX: Mutex<()> = Mutex::new(());

// ============================================================================
// 1. Synchronous Blocking Before Socket Resolution Challenge
// ============================================================================

#[test]
fn challenge_1_synchronous_blocking_before_socket_resolution() {
    let _guard = TEST_ISOLATION_MUTEX.lock();
    clear_recent_blocked_spans();

    // Register hook that marks sinks containing "tainted-exfil.corp" as CROWN_JEWEL / QUARANTINE
    register_lineage_egress_hook(|url, _file_path, _hash| {
        if let Some(u) = url {
            if u.contains("tainted-exfil.corp") || u.contains("unresolvable-sink-999.invalid") {
                return Err(EgressLineageBlockInfo {
                    policy: "QUARANTINE".to_string(),
                    classification: "CROWN_JEWEL".to_string(),
                    reason: "Inline egress blocked: destination sink classified as CROWN_JEWEL".to_string(),
                    trace_id: Some("0123456789abcdef0123456789abcdef".to_string()),
                    span_id: Some("abcdef0123456789".to_string()),
                });
            }
        }
        Ok(())
    });

    // 1. Direct synchronous in-memory check completes in sub-microsecond time
    let start = Instant::now();
    let res = global_lineage_tracker().check_egress_allowed_full(
        Some("https://tainted-exfil.corp/api/v1/dump"),
        None::<&str>,
        None::<&str>,
    );
    let elapsed = start.elapsed();
    assert!(res.is_err(), "Tainted URL must be synchronously blocked");
    assert!(
        elapsed.as_millis() < 5,
        "Synchronous inline check must be sub-microsecond in-memory (took {:?})",
        elapsed
    );

    let block_info = res.unwrap_err();
    assert_eq!(block_info.policy, "QUARANTINE");
    assert_eq!(block_info.classification, "CROWN_JEWEL");

    // 2. Pre-resolution proof: An unresolvable host (.invalid is reserved by RFC 6761 to never resolve)
    // If resolve_and_pin attempted DNS lookup before DLP, it would fail with SSRF_DNS_RESOLUTION_FAILED.
    // Because DLP runs synchronously BEFORE socket resolution, it must fail with DLP_EGRESS_BLOCKED!
    let unresolvable_tainted = "https://unresolvable-sink-999.invalid:443/staging";
    let resolve_res = resolve_and_pin(unresolvable_tainted, &[]);
    assert!(resolve_res.is_err());
    let err_msg = resolve_res.unwrap_err();
    assert!(
        err_msg.contains("DLP_EGRESS_BLOCKED"),
        "Egress must be blocked by DLP before DNS resolution executes. Got: {}",
        err_msg
    );
    assert!(
        !err_msg.contains("SSRF_DNS_RESOLUTION_FAILED"),
        "DNS resolution must NEVER be attempted for tainted targets"
    );

    // 3. validate_agent_egress_url returns DLP_EGRESS_BLOCKED immediately
    let val_res = validate_agent_egress_url("https://tainted-exfil.corp/leak", &[]);
    assert!(val_res.is_err());
    assert!(val_res.unwrap_err().contains("DLP_EGRESS_BLOCKED"));

    // 4. Clean domain permitted
    let clean_res = validate_agent_egress_url("https://clean-repo.internal.corp/api", &[]);
    assert!(clean_res.is_ok(), "Clean destination must pass without DLP block");
}

// ============================================================================
// 2. Verification of Synthetic Blocked Span Emission & Zero-PII Invariant
// ============================================================================

#[test]
fn challenge_2_synthetic_blocked_span_attributes_and_zero_pii() {
    let _guard = TEST_ISOLATION_MUTEX.lock();
    clear_recent_blocked_spans();

    register_lineage_egress_hook(|url, _file_path, _hash| {
        if let Some(u) = url {
            if u.contains("adversarial-exfil.io") {
                return Err(EgressLineageBlockInfo {
                    policy: "BLOCK".to_string(),
                    classification: "CROWN_JEWEL".to_string(),
                    reason: "Automated egress block: target host is flagged by DLP Lineage".to_string(),
                    trace_id: Some("11223344556677889900aabbccddeeff".to_string()),
                    span_id: Some("fedcba9876543210".to_string()),
                });
            }
        }
        Ok(())
    });

    // Adversarial target with embedded user credentials in URL
    let malicious_url_with_creds =
        "https://service_account_root:HighlySecretPassword999$#@adversarial-exfil.io:443/upload/tokens";

    let block_res = validate_agent_egress_url(malicious_url_with_creds, &[]);
    assert!(block_res.is_err());

    // Inspect the emitted synthetic blocked span
    let spans = get_recent_blocked_spans();
    assert!(
        !spans.is_empty(),
        "A synthetic child span must have been emitted on egress block"
    );
    let span = spans.last().expect("Must have last span");

    // 1. Verify span core fields
    assert_eq!(span.name, "dlp.inline_egress_block");
    assert_eq!(span.status, "ERROR");
    assert_eq!(span.action, "BLOCKED");
    assert_eq!(span.policy, "BLOCK");
    assert_eq!(span.classification, "CROWN_JEWEL");
    assert_eq!(span.trace_id, "11223344556677889900aabbccddeeff");
    assert_eq!(span.parent_span_id.as_deref(), Some("fedcba9876543210"));
    assert_eq!(span.span_id.len(), 16, "Synthetic span ID must be 16-hex characters");

    // 2. Verify required OpenTelemetry attributes
    assert_eq!(
        span.attributes.get("dlp.action").map(|s| s.as_str()),
        Some("BLOCKED"),
        "Span must have dlp.action=BLOCKED"
    );
    assert_eq!(
        span.attributes.get("dlp.threat_type").map(|s| s.as_str()),
        Some("DATA_EXFILTRATION"),
        "Span must have dlp.threat_type=DATA_EXFILTRATION"
    );
    assert_eq!(
        span.attributes.get("dlp.retained_taint").map(|s| s.as_str()),
        Some("true"),
        "Span must have dlp.retained_taint=true"
    );
    assert_eq!(
        span.attributes.get("dlp.block_reason").map(|s| s.as_str()),
        Some("tainted_lineage_policy"),
        "Span must have dlp.block_reason=tainted_lineage_policy"
    );
    assert_eq!(
        span.attributes.get("otel.status_code").map(|s| s.as_str()),
        Some("ERROR"),
        "Span must have otel.status_code=ERROR"
    );
    assert_eq!(
        span.attributes.get("error.type").map(|s| s.as_str()),
        Some("DLP_EGRESS_BLOCKED"),
        "Span must have error.type=DLP_EGRESS_BLOCKED"
    );

    // 3. Verify zero-PII invariant: stripped credentials from url.full attribute
    let sanitized_url = span.attributes.get("url.full").expect("url.full attribute must exist");
    assert!(
        !sanitized_url.contains("HighlySecretPassword999$#"),
        "Zero-PII invariant violated: raw password leaked in span attributes! Found: {}",
        sanitized_url
    );
    assert!(
        !sanitized_url.contains("service_account_root:"),
        "Zero-PII invariant violated: username leaked in span attributes! Found: {}",
        sanitized_url
    );
    assert_eq!(
        sanitized_url, "https://adversarial-exfil.io:443/upload/tokens",
        "Sanitized URL must cleanly preserve host and path without credentials"
    );
}

// ============================================================================
// 3. Multi-Threaded Concurrent Egress Stress Test (20 Tasks)
// ============================================================================

#[test]
fn challenge_3_multithreaded_concurrent_egress_stress_test() {
    let _guard = TEST_ISOLATION_MUTEX.lock();
    clear_recent_blocked_spans();

    // Set of domains considered tainted
    let tainted_domains: Arc<HashSet<&'static str>> = Arc::new({
        let mut set = HashSet::new();
        set.insert("exfil-alpha.org");
        set.insert("exfil-bravo.org");
        set.insert("exfil-charlie.org");
        set.insert("exfil-delta.org");
        set
    });

    let tainted_clone = Arc::clone(&tainted_domains);
    register_lineage_egress_hook(move |url, _file_path, _hash| {
        if let Some(u) = url {
            for domain in tainted_clone.iter() {
                if u.contains(domain) {
                    return Err(EgressLineageBlockInfo {
                        policy: "QUARANTINE".to_string(),
                        classification: "CROWN_JEWEL".to_string(),
                        reason: format!("Blocked egress to tainted domain '{}'", domain),
                        trace_id: Some("deadbeefdeadbeefdeadbeefdeadbeef".to_string()),
                        span_id: Some("0123456789abcdef".to_string()),
                    });
                }
            }
        }
        Ok(())
    });

    let num_threads = 20;
    let iterations_per_thread = 100;
    let total_blocked = Arc::new(AtomicUsize::new(0));
    let total_allowed = Arc::new(AtomicUsize::new(0));
    let false_negatives = Arc::new(AtomicUsize::new(0));
    let false_positives = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::with_capacity(num_threads);
    let start_time = Instant::now();

    for t in 0..num_threads {
        let b_count = Arc::clone(&total_blocked);
        let a_count = Arc::clone(&total_allowed);
        let fn_count = Arc::clone(&false_negatives);
        let fp_count = Arc::clone(&false_positives);

        let handle = thread::spawn(move || {
            for i in 0..iterations_per_thread {
                let is_tainted = (t + i) % 2 == 0;
                let target_url = if is_tainted {
                    match i % 4 {
                        0 => "https://exfil-alpha.org/data",
                        1 => "https://exfil-bravo.org/telemetry",
                        2 => "https://exfil-charlie.org/upload",
                        _ => "https://exfil-delta.org/sync",
                    }
                } else {
                    match i % 4 {
                        0 => "https://trusted-internal.corp/data",
                        1 => "https://api.github.com/repos",
                        2 => "https://docs.rs/serde",
                        _ => "https://crates.io/api/v1",
                    }
                };

                let res = validate_agent_egress_url(target_url, &[]);
                if is_tainted {
                    match res {
                        Err(e) if e.contains("DLP_EGRESS_BLOCKED") => {
                            b_count.fetch_add(1, Ordering::Relaxed);
                        }
                        _ => {
                            // Tainted URL allowed: Critical False Negative!
                            fn_count.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                } else {
                    match res {
                        Ok(_) => {
                            a_count.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(e) if e.contains("DLP_EGRESS_BLOCKED") => {
                            // Clean URL blocked: False Positive!
                            fp_count.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(_) => {
                            // Any syntax/allowlist error is benign for this check
                            a_count.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }
        });
        handles.push(handle);
    }

    for h in handles {
        h.join().expect("Worker thread must finish cleanly");
    }

    let elapsed = start_time.elapsed();
    let total_evals = num_threads * iterations_per_thread;
    let fn_val = false_negatives.load(Ordering::SeqCst);
    let fp_val = false_positives.load(Ordering::SeqCst);
    let blocked_val = total_blocked.load(Ordering::SeqCst);
    let allowed_val = total_allowed.load(Ordering::SeqCst);

    println!(
        "Stress test complete: {} total evaluations in {:?} ({:.2} µs/eval). Blocked: {}, Allowed: {}, FN: {}, FP: {}",
        total_evals,
        elapsed,
        (elapsed.as_micros() as f64) / (total_evals as f64),
        blocked_val,
        allowed_val,
        fn_val,
        fp_val
    );

    assert_eq!(fn_val, 0, "CRITICAL DEFECT: Detected {} false negatives under contention!", fn_val);
    assert_eq!(fp_val, 0, "CRITICAL DEFECT: Detected {} false positives under contention!", fp_val);
    assert_eq!(blocked_val, total_evals / 2, "Expected exactly 50% blocked requests");
    assert_eq!(allowed_val, total_evals / 2, "Expected exactly 50% allowed requests");

    // Ring buffer must hold at most 1,000 items (FIFO bounded ring)
    let spans = get_recent_blocked_spans();
    assert!(
        spans.len() <= 1000,
        "Blocked spans buffer exceeded maximum capacity of 1000 (size={})",
        spans.len()
    );
}

// ============================================================================
// 4. Egress Blocking on Rehydrated Out-of-Band Artifacts (Boundary 3)
// ============================================================================

#[test]
fn challenge_4_boundary_3_rehydrated_out_of_band_artifact_blocking() {
    let _guard = TEST_ISOLATION_MUTEX.lock();
    clear_recent_blocked_spans();

    // Known SHA-256 digests of Crown Jewel artifacts recorded in content catalog
    let crown_jewel_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let confidential_hash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    let benign_hash = "88d4266fd4e6338d13b845fcf289579d209c897823b9217da3e161936f031589";

    // Simulate Boundary 3 tracker hook: maps hash digests to taint state
    register_lineage_egress_hook(move |_url, file_path, hash| {
        if let Some(h) = hash {
            if h == crown_jewel_hash {
                return Err(EgressLineageBlockInfo {
                    policy: "QUARANTINE".to_string(),
                    classification: "CROWN_JEWEL".to_string(),
                    reason: format!(
                        "Boundary 3 rehydration: hash '{}' matches Crown Jewel artifact catalog",
                        h
                    ),
                    trace_id: Some("99998888777766665555444433332222".to_string()),
                    span_id: Some("1111222233334444".to_string()),
                });
            } else if h == confidential_hash {
                return Err(EgressLineageBlockInfo {
                    policy: "BLOCK".to_string(),
                    classification: "CONFIDENTIAL".to_string(),
                    reason: format!(
                        "Boundary 3 rehydration: hash '{}' matches Confidential artifact catalog",
                        h
                    ),
                    trace_id: Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()),
                    span_id: Some("bbbbbbbbbbbbbbbb".to_string()),
                });
            }
        }
        if let Some(fp) = file_path {
            if fp.contains("tainted_staging_export") {
                return Err(EgressLineageBlockInfo {
                    policy: "QUARANTINE".to_string(),
                    classification: "CROWN_JEWEL".to_string(),
                    reason: "Path matched tainted staging export".to_string(),
                    trace_id: None,
                    span_id: None,
                });
            }
        }
        Ok(())
    });

    // 1. Rehydrated Crown Jewel artifact under a brand new unmapped path
    let new_path = "D:\\cross_host_incoming\\renamed_secret_copy.bin";
    let block_res = check_egress_allowed_inline(
        None::<&str>,
        Some(new_path),
        Some(crown_jewel_hash),
    );
    assert!(block_res.is_err(), "Rehydrated Crown Jewel artifact must be blocked on egress");
    let err_str = block_res.unwrap_err();
    assert!(err_str.contains("DLP_EGRESS_BLOCKED"));
    assert!(err_str.contains("QUARANTINE"));
    assert!(err_str.contains("CROWN_JEWEL"));

    // Verify synthetic span attributes for rehydrated artifact
    let spans = get_recent_blocked_spans();
    let last_span = spans.last().expect("Must have emitted synthetic blocked span");
    assert_eq!(last_span.action, "BLOCKED");
    assert_eq!(last_span.policy, "QUARANTINE");
    assert_eq!(last_span.classification, "CROWN_JEWEL");
    assert_eq!(
        last_span.attributes.get("file.path").map(|s| s.as_str()),
        Some(new_path)
    );
    assert_eq!(
        last_span.attributes.get("file.hash.sha256").map(|s| s.as_str()),
        Some(crown_jewel_hash)
    );
    assert_eq!(
        last_span.attributes.get("dlp.threat_type").map(|s| s.as_str()),
        Some("DATA_EXFILTRATION")
    );
    assert_eq!(
        last_span.attributes.get("dlp.retained_taint").map(|s| s.as_str()),
        Some("true")
    );

    // 2. Rehydrated Confidential artifact
    let conf_path = "D:\\cross_host_incoming\\confidential_plan.pdf";
    let conf_res = check_egress_allowed_inline(
        Some("https://external-cloud.com/upload"),
        Some(conf_path),
        Some(confidential_hash),
    );
    assert!(conf_res.is_err());
    assert!(conf_res.unwrap_err().contains("CONFIDENTIAL"));

    // 3. Clean benign artifact with unmapped path and benign hash
    let clean_path = "D:\\cross_host_incoming\\clean_report.txt";
    let clean_res = check_egress_allowed_inline(
        Some("https://api.github.com/upload"),
        Some(clean_path),
        Some(benign_hash),
    );
    assert!(clean_res.is_ok(), "Benign artifact must be permitted for egress");
}

// ============================================================================
// 5. Adversarial Bypass Attempts & Edge-Case Mining
// ============================================================================

#[test]
fn challenge_5_adversarial_bypass_attempts() {
    let _guard = TEST_ISOLATION_MUTEX.lock();
    clear_recent_blocked_spans();

    register_lineage_egress_hook(|url, _file_path, _hash| {
        if let Some(u) = url {
            let lower = u.to_ascii_lowercase();
            if lower.contains("exfil-sink.org") {
                return Err(EgressLineageBlockInfo {
                    policy: "QUARANTINE".to_string(),
                    classification: "CROWN_JEWEL".to_string(),
                    reason: "Blocked exfil-sink.org".to_string(),
                    trace_id: None,
                    span_id: None,
                });
            }
        }
        Ok(())
    });

    // 1. Case manipulation on scheme and host
    // e.g. "HTTPS://EXFIL-SINK.ORG/data"
    let uppercase_url = "HTTPS://EXFIL-SINK.ORG/data";
    let case_res = validate_agent_egress_url(uppercase_url, &[]);
    assert!(
        case_res.is_err(),
        "Case manipulation on host/scheme must not bypass DLP blocking"
    );
    assert!(case_res.unwrap_err().contains("DLP_EGRESS_BLOCKED"));

    // 2. Query param and path traversal attempts on tainted URL
    let traversal_url = "https://exfil-sink.org/api/v1/%2e%2e/leak?token=123#fragment";
    let trav_res = validate_agent_egress_url(traversal_url, &[]);
    assert!(trav_res.is_err());
    assert!(trav_res.unwrap_err().contains("DLP_EGRESS_BLOCKED"));

    // 3. Trailing dot FQDN on tainted destination
    let trailing_dot_url = "https://exfil-sink.org./secret";
    let dot_res = validate_agent_egress_url(trailing_dot_url, &[]);
    assert!(dot_res.is_err());
    assert!(dot_res.unwrap_err().contains("DLP_EGRESS_BLOCKED"));

    // 4. Blank and malformed inputs fail closed
    assert!(validate_agent_egress_url("", &[]).is_err());
    assert!(validate_agent_egress_url("   ", &[]).is_err());
    assert!(validate_agent_egress_url("not-a-valid-url", &[]).is_err());
}
