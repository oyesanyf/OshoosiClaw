//! Verification integration tests for Milestone M2D:
//! - WebUI Telemetry, CanaryCage metrics, session lineage & swarm immunization (R7)
//! - History View sub-5ms caching & zero VIEW_RENDER_ERROR timeout fix (R13)
//! - Built-In 9-Vector Adversarial Gauntlet with 100% prevention (R9, R10, R11, R12)
//! - WebUI 0-diff byte-for-byte SHA-256 parity between src and dist (Feature 16)

use std::path::Path;
use std::time::Instant;

/// (a) Verify History View sub-5ms latency on cached hits & bounded audit entries (R13).
#[tokio::test]
async fn test_m2d_history_view_sub5ms_latency_and_bounds() {
    let mem = osoosi_memory::MemoryStore::new(":memory:").expect("in-memory db");
    let _ = mem.get_recent_threats(100);

    // Warm-up cache hit on MemoryStore recent threats cache
    let t0 = Instant::now();
    let threats = mem.get_recent_threats(200).expect("cached get succeeds");
    let elapsed = t0.elapsed();

    assert!(
        elapsed.as_millis() < 5,
        "Cached get_recent_threats must respond in < 5ms, took {:?}",
        elapsed
    );
    let _ = threats;

    // Verify AuditTrail bounded recent entries (< 400 entries cap)
    let audit = osoosi_audit::AuditTrail::new();
    let recent = audit.get_recent_entries(400);
    assert!(
        recent.len() <= 400,
        "get_recent_entries must respect bounded limit (got {})",
        recent.len()
    );

    // If live EDR daemon is running on port 3030, assert live HTTP /api/history caching latency
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(500))
        .build()
        .unwrap();

    let history_url = "http://127.0.0.1:3030/api/history?page=1&limit=50&category=all&severity=all";
    if let Ok(resp1) = client.get(history_url).send().await {
        if resp1.status().is_success() {
            // First call primes the 2,000ms TTL in-memory cache
            let t_start = Instant::now();
            let resp2 = client.get(history_url).send().await;
            let req_elapsed = t_start.elapsed();
            if let Ok(r) = resp2 {
                if r.status().is_success() {
                    assert!(
                        req_elapsed.as_millis() < 25,
                        "Live cached /api/history HTTP request took {:?}, expected < 25ms over local loopback",
                        req_elapsed
                    );
                }
            }
        }
    }
}

/// (b) Verify that all 9 Red Team Gauntlet vectors execute and pass with 100% prevention (R9).
#[test]
fn test_m2d_built_in_9_vector_adversarial_gauntlet_all_passed() {
    let scorecard =
        osoosi_core::adversarial_gauntlet::AdversarialRedTeamGauntlet::run_full_gauntlet();

    // 1. Overall quantitative scorecard invariants
    assert_eq!(
        scorecard.prevention_rate_pct, 100.0,
        "Gauntlet prevention rate must be exactly 100%"
    );
    assert_eq!(
        scorecard.detection_rate_pct, 100.0,
        "Gauntlet detection rate must be exactly 100%"
    );
    assert_eq!(
        scorecard.bypass_success_rate_pct, 0.0,
        "Gauntlet bypass success rate must be 0%"
    );
    assert_eq!(
        scorecard.false_positive_rate_pct, 0.0,
        "Benign false-positive rate must be 0%"
    );
    assert_eq!(
        scorecard.os_stability_score_pct, 100.0,
        "OS stability score must be 100%"
    );
    assert!(
        scorecard.os_oracle_report.all_os_invariants_verified,
        "Independent OS Boundary Oracle must physically verify all invariants"
    );

    // 2. Specific 9-vector category verification
    let required_vector_ids = [
        // Vector 1: Core LOLBin, injection, ADS, SSRF, temporal policies, PQC
        "ART-T1055.001-T1055.012",
        "ART-T1003.001",
        "ART-T1068-BYOVD",
        "ART-T1071.004",
        "ART-T1562.001",
        "CALDERA-APT-CHAIN-01",
        "GARAK-PI-01",
        "PROMPTFOO-HMAC-EPOCH-02",
        "GARAK-DIRAC-REPLAY-03",
        "PROMPTFOO-CONFUSED-DEPUTY-04",
        "GARAK-STARK-TRACE-05",
        "OWASP-ASI01-ASI05-LLM01-A10",
        "OWASP-ASI06-ASI10-LLM06-LLM10",
        "BYPASS-TOCTOU-PIN-01",
        "BYPASS-DLP-ENCODED-ZK-02",
        "BYPASS-COVERT-CHANNEL-03",
        "CROSS-LAYER-CEDAR-BYPASS-ESCAPE-04",
        "BYPASS-PQC-SHOR-DOWNGRADE-05",
        // Vector 2: Ephemeral CanaryCage Subprocess Trap
        "VECTOR-02-CANARY-CAGE-SUBPROCESS-TRAP",
        // Vector 3: BLAKE3 Input-File Lineage & Swarm Pre-Immunization
        "VECTOR-03-BLAKE3-LINEAGE-SWARM-IMMUNIZATION",
        // Vector 4: Multi-Ring Capability Ticket Canary Binding & Tainted-Session Forced Caging
        "VECTOR-04-CAPABILITY-TICKET-CANARY-FORCED-CAGING",
        // Vector 5: Browser HAR Cross-Domain Context Hijacking Lineage
        "VECTOR-05-BROWSER-HAR-CROSS-DOMAIN-LINEAGE",
        // Vector 6: REA Caged Detonation & False-Positive Immunity
        "VECTOR-06-REA-CAGED-DETONATION-AND-IMMUNITY",
        // Vector 7: Repository & OS Self-Quarantine Immunity
        "VECTOR-07-REPOSITORY-AND-OS-QUARANTINE-IMMUNITY",
        // Vector 8: Zero-Trust Policy Consensus Voters & RL Controller Update
        "VECTOR-08-ZERO-TRUST-VOTERS-AND-RL-UPDATE",
        // Vector 9: MITRE ATT&CK + MITRE ATLAS™ STIX 2.1 Autonomous Catalog Sync & Hardware TPM 2.0
        "VECTOR-09-MITRE-STIX-ATLAS-SYNC-AND-TPM2",
    ];

    for vid in &required_vector_ids {
        let v = scorecard
            .vector_results
            .iter()
            .find(|r| r.vector_id == *vid)
            .unwrap_or_else(|| {
                panic!(
                    "Required vector '{}' must be present in gauntlet results",
                    vid
                )
            });

        assert!(
            v.prevented,
            "Vector '{}' must be prevented, got evidence: {}",
            vid, v.evidence
        );
        assert!(
            v.detected,
            "Vector '{}' must be detected, got evidence: {}",
            vid, v.evidence
        );
        assert!(
            !v.bypass_succeeded,
            "Vector '{}' must not allow bypass",
            vid
        );
    }
}

/// (c) Verify Deception and Agent Anomaly telemetry structures & live endpoints (R7).
#[tokio::test]
async fn test_m2d_deception_and_agent_anomaly_telemetry_structures() {
    use osoosi_agent_anomaly::file_lineage::FileLineageTracker;

    // 1. Verify FileLineageTracker lineage mapping & bounded capacity
    let tracker = FileLineageTracker::with_capacity(16);
    let path = Path::new("C:\\temp\\test_m2d_doc.pdf");
    let content = b"M2D Telemetry Verification Payload";
    let digest = tracker
        .record_ingested_file("session_m2d_test", path, content)
        .expect("record ingested file succeeds");

    assert_eq!(digest, FileLineageTracker::compute_blake3(content));
    let lineage = tracker.get_session_lineage("session_m2d_test");
    assert_eq!(lineage.len(), 1);
    assert_eq!(lineage[0].blake3_digest, digest);

    // 2. If live daemon is responding on port 3030, verify live /api/deception/status
    // and /api/agent-anomalies/summary JSON payload enrichment
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(500))
        .build()
        .unwrap();

    if let Ok(resp) = client
        .get("http://127.0.0.1:3030/api/deception/status")
        .send()
        .await
    {
        if resp.status().is_success() {
            let json: serde_json::Value = resp.json().await.unwrap();
            assert!(
                json.get("canary_files").is_some() || json.get("canary_count").is_some(),
                "Deception status must contain canary info"
            );
        }
    }

    if let Ok(resp) = client
        .get("http://127.0.0.1:3030/api/agent-anomalies/summary")
        .send()
        .await
    {
        if resp.status().is_success() {
            let json: serde_json::Value = resp.json().await.unwrap();
            assert!(
                json.get("monitored_sessions").is_some(),
                "Agent anomaly summary must report monitored sessions"
            );
            assert!(
                json.get("containment_ring").is_some(),
                "Agent anomaly summary must contain containment ring status"
            );
        }
    }
}

/// (d) Verify WebUI 0-diff byte-for-byte SHA-256 parity between dashboard/src and dashboard/dist (Feature 16).
#[test]
fn test_m2d_webui_parity_src_and_dist_byte_identical() {
    let src_app = Path::new("dashboard/src/app.js");
    let dist_app = Path::new("dashboard/dist/app.js");

    assert!(src_app.exists(), "dashboard/src/app.js must exist");
    assert!(dist_app.exists(), "dashboard/dist/app.js must exist");

    let src_bytes = std::fs::read(src_app).expect("read src/app.js");
    let dist_bytes = std::fs::read(dist_app).expect("read dist/app.js");

    let src_blake3 = blake3::hash(&src_bytes);
    let dist_blake3 = blake3::hash(&dist_bytes);

    assert_eq!(
        src_blake3, dist_blake3,
        "dashboard/src/app.js and dashboard/dist/app.js must maintain 0-diff byte-for-byte parity"
    );

    let src_html = Path::new("dashboard/src/index.html");
    let dist_html = Path::new("dashboard/dist/index.html");
    if src_html.exists() && dist_html.exists() {
        let src_h_bytes = std::fs::read(src_html).unwrap();
        let dist_h_bytes = std::fs::read(dist_html).unwrap();
        assert_eq!(
            blake3::hash(&src_h_bytes),
            blake3::hash(&dist_h_bytes),
            "dashboard/src/index.html and dashboard/dist/index.html must maintain 0-diff parity"
        );
    }
}
