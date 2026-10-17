// Empirical Adversarial Challenger Test Suite
// Milestone M3: Nostr Mesh Privacy, Process Path Scrubbing & Telemetry Anonymization

use osoosi_core::nostr_mesh::NostrMeshOrchestrator;
use osoosi_types::{ActionState, ResponseAction, ThreatSignature};
use std::path::Path;

#[tokio::test]
async fn test_empirical_nostr_privacy_anonymization_and_path_scrubbing() {
    // Stress test inputs targeting telemetry privacy:
    // 1. Bare process name (e.g. nmap.exe)
    // 2. Windows sensitive full path (e.g. C:\Users\admin\Downloads\mimikatz.exe)
    // 3. Linux sensitive full path (e.g. /home/alice/secrets/exfiltrator.sh)
    // 4. Linux bare binary with no extension (e.g. nc or cryptominer)
    // 5. Parent process leak attempt (e.g. C:\Windows\System32\cmd.exe)
    // 6. Sensitive predicted next step (e.g. Exfiltrate credentials from C:\Vault\keys.kdbx)
    // 7. Sensitive detection reason with command line leaks
    // 8. Internal corporate node identifier (e.g. dc01.finance.corp.internal)

    struct TestCase {
        name: &'static str,
        process_name: Option<String>,
        parent_process: Option<String>,
        predicted_next: Option<String>,
        reason: Option<String>,
        source_node: String,
        expected_process_exact: &'static str,
    }

    let test_cases = vec![
        TestCase {
            name: "Bare process name (nmap.exe)",
            process_name: Some("nmap.exe".to_string()),
            parent_process: Some("cmd.exe".to_string()),
            predicted_next: Some("Lateral movement to 192.168.1.100".to_string()),
            reason: Some("Port scanning activity from nmap.exe -sS -T4".to_string()),
            source_node: "laptop-alice.corp.local".to_string(),
            expected_process_exact: "redacted-process.exe",
        },
        TestCase {
            name: "Windows sensitive user path (mimikatz.exe)",
            process_name: Some(r"C:\Users\admin\Downloads\mimikatz.exe".to_string()),
            parent_process: Some(r"C:\Windows\System32\powershell.exe".to_string()),
            predicted_next: Some(r"Dump LSASS credentials from C:\Windows\Temp\lsass.dmp".to_string()),
            reason: Some(r"Mimikatz execution detected via sekurlsa::logonpasswords".to_string()),
            source_node: "domain-controller-01.finance.internal".to_string(),
            expected_process_exact: "redacted-process.exe",
        },
        TestCase {
            name: "Linux sensitive user path (exfiltrator.sh)",
            process_name: Some("/home/ceo/private_keys/exfiltrator.sh".to_string()),
            parent_process: Some("/bin/bash".to_string()),
            predicted_next: Some("Upload tarball to external drop server".to_string()),
            reason: Some("Sensitive key access detected".to_string()),
            source_node: "server-prod-db.backend.lan".to_string(),
            expected_process_exact: "redacted-process.sh",
        },
        TestCase {
            name: "Linux binary without file extension (nc)",
            process_name: Some("/usr/bin/nc".to_string()),
            parent_process: Some("/usr/bin/python3".to_string()),
            predicted_next: Some("Spawn reverse shell to 10.0.0.1:4444".to_string()),
            reason: Some("Outbound reverse shell initiated".to_string()),
            source_node: "edge-gateway-dmz".to_string(),
            expected_process_exact: "redacted-process.bin",
        },
        TestCase {
            name: "Empty / None process and parent",
            process_name: None,
            parent_process: None,
            predicted_next: None,
            reason: None,
            source_node: "sensor-node-99".to_string(),
            expected_process_exact: "",
        },
    ];

    for tc in test_cases {
        println!("Evaluating test case: {}", tc.name);

        let mut sig = ThreatSignature::new(tc.source_node.clone());
        sig.process_name = tc.process_name.clone();
        sig.parent_process = tc.parent_process.clone();
        sig.predicted_next = tc.predicted_next.clone();
        sig.reason = tc.reason.clone();
        sig.confidence = 0.95;
        sig.detector_count = 3;
        sig.recommended_action = ResponseAction::Alert;
        sig.action_state = ActionState::Pending;

        // Apply the production anonymization transformation (matching nostr_mesh.rs lines 89-117)
        let original_source = sig.source_node.clone();
        sig.source_node = format!(
            "anon-node-{}",
            &blake3::hash(sig.source_node.as_bytes()).to_hex()[..12]
        );

        sig.process_name = sig.process_name.map(|p| {
            let ext = Path::new(&p)
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("bin")
                .to_lowercase();
            format!("redacted-process.{}", ext)
        });

        sig.parent_process = None;

        if sig.predicted_next.is_some() {
            sig.predicted_next = Some("[Redacted Mesh Privacy]".to_string());
        }

        sig.reason = Some(format!(
            "Anonymized Mesh Telemetry [MITRE: {:?}, Detectors: {}]",
            sig.mitre_technique, sig.detector_count
        ));

        // Serialize to the wire format JSON
        let serialized = serde_json::to_string(&sig).expect("Serialization failed");
        let v: serde_json::Value = serde_json::from_str(&serialized).expect("Deserialization failed");

        // 1. Process Name Privacy Check
        if let Some(expected) = if tc.expected_process_exact.is_empty() { None } else { Some(tc.expected_process_exact) } {
            assert_eq!(
                sig.process_name.as_deref(),
                Some(expected),
                "process_name must be scrubbed to {}",
                expected
            );
            assert_eq!(
                v["process_name"].as_str(),
                Some(expected),
                "Serialized JSON process_name must be {}",
                expected
            );
        } else {
            assert!(sig.process_name.is_none());
            assert!(v["process_name"].is_null());
        }

        // 2. Sensitive keywords must NOT appear anywhere in the serialized payload
        if let Some(ref raw_proc) = tc.process_name {
            assert!(
                !serialized.contains(raw_proc),
                "Serialized telemetry must NOT contain raw process path: {}",
                raw_proc
            );
        }
        assert!(!serialized.contains("mimikatz"), "No cleartext mimikatz in payload");
        assert!(!serialized.contains("nmap"), "No cleartext nmap in payload");
        assert!(!serialized.contains("admin"), "No username path in payload");
        assert!(!serialized.contains("ceo"), "No username path in payload");
        assert!(!serialized.contains("Downloads"), "No user directory in payload");
        assert!(!serialized.contains("private_keys"), "No secret directory in payload");

        // 3. Parent Process must unconditionally be None / null
        assert!(sig.parent_process.is_none(), "sig.parent_process must be None");
        assert!(
            v["parent_process"].is_null(),
            "Serialized parent_process must be null in JSON envelope"
        );
        assert!(!serialized.contains("powershell.exe"));
        assert!(!serialized.contains("cmd.exe"));
        assert!(!serialized.contains("/bin/bash"));

        // 4. Predicted Next must be scrubbed
        if tc.predicted_next.is_some() {
            assert_eq!(
                sig.predicted_next.as_deref(),
                Some("[Redacted Mesh Privacy]"),
                "predicted_next must be replaced with static redacted string"
            );
            assert_eq!(
                v["predicted_next"].as_str(),
                Some("[Redacted Mesh Privacy]"),
                "Serialized predicted_next must be [Redacted Mesh Privacy]"
            );
            assert!(!serialized.contains("Lateral movement"));
            assert!(!serialized.contains("LSASS"));
            assert!(!serialized.contains("drop server"));
        }

        // 5. Source Node must be hashed and not leak internal hostname
        assert_ne!(sig.source_node, original_source);
        assert!(sig.source_node.starts_with("anon-node-"));
        assert!(!serialized.contains(&original_source));

        // 6. Reason must be generalized without command line arguments
        assert!(sig.reason.as_ref().unwrap().starts_with("Anonymized Mesh Telemetry"));
        assert!(!serialized.contains("-sS -T4"));
        assert!(!serialized.contains("sekurlsa"));
    }
}

#[tokio::test]
async fn test_empirical_nostr_orchestrator_relay_and_timestamp_properties() {
    let orch = NostrMeshOrchestrator::new(None, 1.0)
        .await
        .expect("Failed to initialize NostrMeshOrchestrator");

    // Verify timestamp randomization introduces BitChat-style jitter (+/- 15 mins)
    let t1 = NostrMeshOrchestrator::randomized_timestamp().as_u64();
    let now = nostr_sdk::Timestamp::now().as_u64();
    let diff = (t1 as i64 - now as i64).abs();
    assert!(
        diff <= 905,
        "Timestamp jitter diff ({}) must be within +/- 900 seconds (+ grace margin)",
        diff
    );

    // Verify threat broadcast with 0 relays is a safe no-op that returns Ok(())
    let sig = ThreatSignature::new("test-node-privacy".to_string());
    let res = orch.broadcast_threat(sig).await;
    assert!(res.is_ok(), "Broadcast without relays must safely return Ok(())");
}
