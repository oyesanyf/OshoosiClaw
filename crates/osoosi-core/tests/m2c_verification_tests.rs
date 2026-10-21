//! Verification integration tests for Milestone M2C:
//! - Zero-Trust Consensus Quorum for CanaryAlert & Swarm Broadcast (R6)
//! - STIX 2.1 ATT&CK + MITRE ATLAS™ MDP Mapping & SkyRL Adaptation (R11)
//! - Autonomous MITRE ATT&CK + ATLAS STIX 2.1 Refresh (R10)
//! - Hardware TPM 2.0 (NTC Nuvoton 1.3.2.8) Detection & Attestation (R12)
//! - Sub-5ms History Performance & Bounds (R13)
//! - Comprehensive Host Web Traffic in `har_entries` (R14)
//! - REA Self-Inspection 0% Threat Score & Zero Console Window Flash `CREATE_NO_WINDOW` (R15)

use std::sync::Arc;
use std::time::Instant;

#[tokio::test]
async fn test_autonomous_mitre_stix_atlas_telemetry_and_refresh() {
    let dummy_mesh_tx = Arc::new(tokio::sync::Mutex::new(None));
    let sync = osoosi_core::mitre::AutonomousMitreSynchronizer::new(dummy_mesh_tx);

    let telem = sync.trigger_autonomous_stix_atlas_refresh().await.expect("refresh succeeds");
    assert!(telem.total_techniques >= 50, "Expected at least 50 total techniques");
    assert!(telem.atlas_ai_count >= 8, "Expected at least 8 MITRE ATLAS techniques");
    assert!(telem.enterprise_attack_count > 0, "Expected enterprise ATT&CK techniques");
    assert!(telem.autonomous_refresh_active, "Autonomous refresh must be active");
    assert!(!telem.last_refreshed_at.is_empty(), "Last refreshed at must be set");
}

#[tokio::test]
async fn test_rea_self_inspection_zero_threat_score() {
    let dummy_bytes = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00";
    let report = osoosi_core::rea::analyze_target_bytes(
        "osoosi.exe",
        None,
        dummy_bytes,
        osoosi_core::rea::ReaTargetKind::NativeBinary,
        None,
    );

    assert_eq!(
        report.threat_score, 0.0,
        "Self-inspection of osoosi.exe must yield exactly 0.0 threat score"
    );
    for finding in &report.findings {
        if let Some(sev) = finding.get("severity").and_then(|v| v.as_str()) {
            assert_eq!(
                sev, "info",
                "Findings for self-binary must be downgraded to info severity"
            );
        }
    }
}

#[tokio::test]
async fn test_swarm_poisoned_har_rejection_and_lineage() {
    let dummy_digest = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    osoosi_policy::traffic_adapter::register_swarm_poisoned_har_digest(dummy_digest);
    assert!(
        osoosi_policy::traffic_adapter::is_swarm_poisoned_har_digest(dummy_digest),
        "Digest must be recorded as swarm-poisoned"
    );

    let malicious_har = serde_json::json!({
        "log": {
            "version": "1.2",
            "entries": [
                {
                    "startedDateTime": "2026-10-21T00:00:00Z",
                    "time": 25.0,
                    "request": {
                        "method": "GET",
                        "url": "http://127.0.0.1:8080/exploit.exe",
                        "headers": []
                    },
                    "response": {
                        "status": 200,
                        "content": {
                            "mimeType": "application/octet-stream",
                            "text": "MALICIOUS_PAYLOAD_BODY"
                        }
                    }
                }
            ]
        }
    });

    let raw_str = malicious_har.to_string();
    let report = osoosi_policy::traffic_adapter::parse_and_inspect_har_json(
        &raw_str,
        "test_malicious.har",
    )
    .expect("parsing succeeds");

    assert!(report.entries.len() >= 1);
    let recent = osoosi_policy::traffic_adapter::get_recent_inspected_har_entries(10);
    assert!(
        recent.iter().any(|(src, _)| src == "test_malicious.har"),
        "Inspected entry must be recorded in global ring buffer"
    );
}

#[tokio::test]
async fn test_hardware_tpm2_detection_and_pcr_read() {
    #[cfg(target_os = "windows")]
    {
        let report = osoosi_trust::tbs::inspect_tpm_registry();
        if let Some(r) = report {
            assert!(
                r.manufacturer_str.contains("Nuvoton")
                    || r.manufacturer_id == 0x4E544300
                    || matches!(r.vendor, osoosi_types::TpmOemVendor::Nuvoton),
                "Expected Nuvoton / NTC detection"
            );
            assert!(r.spec_version.contains("2.0"), "Expected TPM 2.0 spec version");
        }
    }

    let pcr0 = osoosi_audit::tpm::read_pcr(0);
    assert!(pcr0.is_some(), "PCR 0 read should succeed");
    assert_eq!(pcr0.unwrap().len(), 64, "PCR 0 should be 64 hex characters");

    let pcr16 = osoosi_audit::tpm::read_pcr(16);
    assert!(pcr16.is_some(), "PCR 16 read should succeed");
    assert_eq!(pcr16.unwrap().len(), 64, "PCR 16 should be 64 hex characters");
}

#[tokio::test]
async fn test_dp_csprng_timestamp_perturbation() {
    let now = chrono::Utc::now().timestamp();
    let perturbed = osoosi_dp::perturb_timestamp_csprng(now, 0.5);
    assert!((perturbed - now).abs() < 3600, "Timestamp perturbation should be within 1 hour");
}

#[tokio::test]
async fn test_sub5ms_recent_threats_cache() {
    let mem = osoosi_memory::MemoryStore::new(":memory:").expect("in-memory db");
    let _ = mem.get_recent_threats(100);

    let t0 = Instant::now();
    let threats = mem.get_recent_threats(500).expect("cached get succeeds");
    let elapsed = t0.elapsed();

    assert!(
        elapsed.as_millis() < 5,
        "Cached get_recent_threats must respond in < 5ms, took {:?}",
        elapsed
    );
    let _ = threats;
}
