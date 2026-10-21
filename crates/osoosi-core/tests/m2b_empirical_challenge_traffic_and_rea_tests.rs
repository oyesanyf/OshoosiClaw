// Empirical Adversarial Challenger Test Suite
// Milestone M2B: HAR Traffic Lineage, Swarm Poison Rejection, Caged REA Detonation, and Benign Immunity

use osoosi_core::rea::{
    is_rea_benign_system_or_dev_process, run_caged_rea_detonation_probe, ReaError,
};
use osoosi_policy::traffic_adapter::{
    clear_har_lineage_hook, clear_swarm_poisoned_har_digests, is_swarm_poisoned_har_digest,
    parse_and_inspect_har_json, parse_and_inspect_har_json_with_session,
    register_swarm_poisoned_har_digest, set_har_lineage_hook,
};
use serde_json::json;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use std::sync::Mutex;
static TEST_MUTEX: Mutex<()> = Mutex::new(());

#[test]
fn test_challenge_har_blake3_hashing_and_lineage_edge_cases() {
    let _guard = TEST_MUTEX.lock().unwrap();
    clear_swarm_poisoned_har_digests();
    clear_har_lineage_hook();

    let clean_body_1 = "{\"status\": \"ok\", \"data\": [1, 2, 3]}";
    let clean_body_2 = "<html><body>Hello World Multi-Line\nWith Unicode: Ọ̀ṣọ́ọ̀sì</body></html>";
    let expected_hash_1 = blake3::hash(clean_body_1.as_bytes()).to_hex().to_string().to_lowercase();
    let expected_hash_2 = blake3::hash(clean_body_2.as_bytes()).to_hex().to_string().to_lowercase();

    // HAR with 4 entries:
    // Entry 0: Clean JSON body -> has body_blake3
    // Entry 1: Clean HTML body with Unicode -> has body_blake3
    // Entry 2: Empty string body "" -> body_blake3 is None
    // Entry 3: No "text" key in content -> body_blake3 is None
    let har_data = json!({
        "log": {
            "version": "1.2",
            "creator": {"name": "TestHarGenerator", "version": "1.0"},
            "entries": [
                {
                    "startedDateTime": "2026-10-21T00:00:00.000Z",
                    "time": 25.0,
                    "request": {"method": "GET", "url": "https://api.example.com/v1/items"},
                    "response": {
                        "status": 200,
                        "content": {"mimeType": "application/json", "text": clean_body_1}
                    }
                },
                {
                    "startedDateTime": "2026-10-21T00:00:01.000Z",
                    "time": 30.0,
                    "request": {"method": "GET", "url": "https://site.example.com/page.html"},
                    "response": {
                        "status": 200,
                        "content": {"mimeType": "text/html", "text": clean_body_2}
                    }
                },
                {
                    "startedDateTime": "2026-10-21T00:00:02.000Z",
                    "time": 10.0,
                    "request": {"method": "POST", "url": "https://site.example.com/empty"},
                    "response": {
                        "status": 204,
                        "content": {"mimeType": "text/plain", "text": ""}
                    }
                },
                {
                    "startedDateTime": "2026-10-21T00:00:03.000Z",
                    "time": 15.0,
                    "request": {"method": "GET", "url": "https://site.example.com/binary.bin"},
                    "response": {
                        "status": 200,
                        "content": {"mimeType": "application/octet-stream", "size": 1024}
                    }
                }
            ]
        }
    });

    let report = parse_and_inspect_har_json_with_session(
        &har_data.to_string(),
        "default_label",
        Some("session-empirical-01"),
    )
    .expect("HAR JSON should parse cleanly");

    assert_eq!(report.total_entries, 4);
    assert_eq!(report.entries[0].body_blake3.as_deref(), Some(expected_hash_1.as_str()));
    assert_eq!(report.entries[1].body_blake3.as_deref(), Some(expected_hash_2.as_str()));
    assert_eq!(report.entries[2].body_blake3, None, "Empty text must produce None body_blake3");
    assert_eq!(report.entries[3].body_blake3, None, "Missing text field must produce None body_blake3");
    assert_eq!(report.malicious_entries, 0);
    assert_eq!(report.primary_verdict, "BENIGN");
}

#[test]
fn test_challenge_swarm_poisoned_payload_rejection_and_registry_lifecycle() {
    let _guard = TEST_MUTEX.lock().unwrap();
    clear_swarm_poisoned_har_digests();
    clear_har_lineage_hook();

    let clean_body = "Regular unpoisoned search response payload";
    let poisoned_body = "POISONED_SWARM_PAYLOAD_WITH_EMBEDDED_MALICIOUS_WEIGHTS_42";

    let clean_digest = blake3::hash(clean_body.as_bytes()).to_hex().to_string().to_lowercase();
    let poisoned_digest_raw = blake3::hash(poisoned_body.as_bytes()).to_hex().to_string();
    let poisoned_digest_upper = poisoned_digest_raw.to_uppercase();
    let poisoned_digest_lower = poisoned_digest_raw.to_lowercase();

    // 1. Verify case-insensitive registration
    register_swarm_poisoned_har_digest(&poisoned_digest_upper);
    assert!(is_swarm_poisoned_har_digest(&poisoned_digest_upper));
    assert!(is_swarm_poisoned_har_digest(&poisoned_digest_lower));
    assert!(!is_swarm_poisoned_har_digest(&clean_digest));

    let har_data = json!({
        "log": {
            "version": "1.2",
            "entries": [
                {
                    "startedDateTime": "2026-10-21T00:00:00.000Z",
                    "time": 20.0,
                    "request": {"method": "GET", "url": "https://example.com/clean"},
                    "response": {
                        "status": 200,
                        "content": {"mimeType": "text/plain", "text": clean_body}
                    }
                },
                {
                    "startedDateTime": "2026-10-21T00:00:01.000Z",
                    "time": 45.0,
                    "request": {"method": "GET", "url": "https://example.com/poison"},
                    "response": {
                        "status": 200,
                        "content": {"mimeType": "text/plain", "text": poisoned_body}
                    }
                }
            ]
        }
    });

    // 2. Parse while poisoned: must be flagged
    let report_poisoned = parse_and_inspect_har_json(&har_data.to_string(), "test_session")
        .expect("HAR parse should succeed");

    assert_eq!(report_poisoned.total_entries, 2);
    assert_eq!(report_poisoned.malicious_entries, 1);
    assert_eq!(report_poisoned.highest_threat_score, 1.00);
    assert_eq!(report_poisoned.primary_verdict, "MALICIOUS");
    assert!(report_poisoned.detected_vectors.contains(&"HAR:SWARM_POISONED_PAYLOAD".to_string()));

    let entry_0 = &report_poisoned.entries[0];
    assert_eq!(entry_0.verdict, "benign");
    assert_ne!(entry_0.threat_score, 1.00);

    let entry_1 = &report_poisoned.entries[1];
    assert_eq!(entry_1.verdict, "malicious");
    assert_eq!(entry_1.threat_score, 1.00);
    assert!(entry_1.threat_tags.contains(&"HAR:SWARM_POISONED_PAYLOAD".to_string()));
    assert!(entry_1.threat_reasons[0].contains(&poisoned_digest_lower));

    // 3. Clear registry and re-inspect: must return to benign
    clear_swarm_poisoned_har_digests();
    assert!(!is_swarm_poisoned_har_digest(&poisoned_digest_lower));

    let report_cleared = parse_and_inspect_har_json(&har_data.to_string(), "test_session")
        .expect("HAR parse should succeed");
    assert_eq!(report_cleared.malicious_entries, 0);
    assert_eq!(report_cleared.primary_verdict, "BENIGN");
    assert_eq!(report_cleared.entries[1].verdict, "benign");
    assert_ne!(report_cleared.entries[1].threat_score, 1.00);
}

#[test]
fn test_challenge_har_lineage_callback_hook() {
    let _guard = TEST_MUTEX.lock().unwrap();
    clear_swarm_poisoned_har_digests();
    clear_har_lineage_hook();

    let hook_invoked = Arc::new(AtomicBool::new(false));
    let hook_invoked_clone = hook_invoked.clone();

    let body = "callback test payload";
    let expected_digest = blake3::hash(body.as_bytes()).to_hex().to_string().to_lowercase();
    let expected_digest_clone = expected_digest.clone();

    set_har_lineage_hook(move |sess, url, domain, digest| {
        if sess == "session-hook-challenge" {
            hook_invoked_clone.store(true, Ordering::SeqCst);
            assert_eq!(domain, "api.target.org");
            assert!(url.contains("https://api.target.org/fetch"));
            assert_eq!(digest, expected_digest_clone.as_str());
            // Return true to simulate dynamic swarm poison rejection
            return true;
        }
        false
    });

    let har = json!({
        "log": {
            "version": "1.2",
            "entries": [{
                "startedDateTime": "2026-10-21T00:00:00.000Z",
                "request": {"method": "GET", "url": "https://api.target.org/fetch"},
                "response": {"status": 200, "content": {"text": body}}
            }]
        }
    });

    let report = parse_and_inspect_har_json_with_session(
        &har.to_string(),
        "fallback_label",
        Some("session-hook-challenge"),
    )
    .expect("parse should succeed");

    assert!(hook_invoked.load(Ordering::SeqCst), "Lineage callback hook must be called");
    assert_eq!(report.malicious_entries, 1);
    assert_eq!(report.highest_threat_score, 1.00);
    assert_eq!(report.primary_verdict, "MALICIOUS");
    assert!(report.entries[0].threat_tags.contains(&"HAR:SWARM_POISONED_PAYLOAD".to_string()));

    clear_har_lineage_hook();
}


#[test]
fn test_challenge_rea_benign_system_immunity_matrix() {
    // 1. Stress-test is_rea_benign_system_or_dev_process against various paths & casings
    let benign_cases = [
        "C:\\Windows\\System32\\cmd.exe",
        "c:\\windows\\system32\\cmd.exe",
        "cmd.exe",
        "C:/Windows/System32/powershell.exe",
        "powershell.exe",
        "pwsh.exe",
        "C:\\Program Files\\Git\\bin\\git.exe",
        "cargo.exe",
        "rustc.exe",
        "signtool.exe",
        "python.exe",
        "node.exe",
        "osoosi.exe",
        "osoosi-cli.exe",
    ];

    for path in &benign_cases {
        assert!(
            is_rea_benign_system_or_dev_process(path, None),
            "Expected benign immunity for {}",
            path
        );
    }

    // 2. Untrusted / unknown binaries must NOT be granted immunity
    let malicious_or_unknown = [
        "C:\\Users\\victim\\Downloads\\malware_payload.exe",
        "C:\\temp\\dropper.exe",
        "unknown_exploit_sample.dll",
        "beacon_x64.exe",
    ];

    for path in &malicious_or_unknown {
        assert!(
            !is_rea_benign_system_or_dev_process(path, None),
            "Non-benign binary must NOT receive immunity: {}",
            path
        );
    }

    // 3. Test run_caged_rea_detonation_probe immunity on actual cmd.exe
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
    let cmd_path = Path::new(&system_root).join("System32").join("cmd.exe");
    if cmd_path.exists() {
        let rep = run_caged_rea_detonation_probe(&cmd_path, "session_immunity_challenge", 1000)
            .expect("Detonation check on cmd.exe must succeed with immunity");
        assert_eq!(rep.verdict, "BENIGN_VERIFIED");
        assert_eq!(rep.threat_score, 0.0);
        assert!(!rep.canary_triggered);
        assert_eq!(rep.exit_code, Some(0));
        assert!(rep.mitre_attack_ids.is_empty());
        assert_eq!(rep.findings[0]["category"], "immunity_adjudication");
    }
}

#[test]
#[cfg(windows)]
fn test_challenge_rea_detonation_honeypipe_and_benign_script_differential() {
    let temp_dir = std::env::temp_dir();
    let rand_id = format!("{:016x}", rand::random::<u128>());

    // 1. Benign batch script: executes cleanly without touching honeypipe
    let benign_bat = temp_dir.join(format!("benign_test_{}_{}.bat", std::process::id(), rand_id));
    std::fs::write(&benign_bat, b"@echo off\r\necho BENIGN_OK\r\nexit /b 0\r\n").expect("write benign bat");

    let benign_rep = run_caged_rea_detonation_probe(&benign_bat, "sess_benign_diff", 4000)
        .expect("benign probe should execute");
    let _ = std::fs::remove_file(&benign_bat);

    assert!(!benign_rep.canary_triggered, "Benign script must NOT trigger canary");
    assert_eq!(benign_rep.verdict, "CLEAN");
    assert_eq!(benign_rep.threat_score, 0.05);
    assert_eq!(benign_rep.exit_code, Some(0));

    // 2. Malicious batch script: touches the honeypipe decoy
    let trap_bat = temp_dir.join(format!("malicious_trap_test_{}_{}.bat", std::process::id(), rand_id));
    std::fs::write(
        &trap_bat,
        b"@echo off\r\necho PROBE_MALICIOUS_CANARY > %CANARY_HONEY_PIPE%\r\n",
    )
    .expect("write trap bat");

    let trap_rep = run_caged_rea_detonation_probe(&trap_bat, "sess_trap_diff", 6000)
        .expect("trap probe should execute and intercept");
    let _ = std::fs::remove_file(&trap_bat);

    assert!(trap_rep.canary_triggered, "Touching honeypipe must trigger canary trap");
    assert_eq!(trap_rep.exit_code, Some(137), "Caged child must be terminated with exit code 137");
    assert_eq!(trap_rep.threat_score, 1.00);
    assert_eq!(trap_rep.verdict, "MALICIOUS");
    assert!(trap_rep.mitre_attack_ids.contains(&"AML.T0043".to_string()));
    assert!(trap_rep.mitre_attack_ids.contains(&"T1552.001".to_string()));
    assert!(trap_rep.alert.is_some());

    // 3. Non-existent target must return NotFound
    let non_existent = temp_dir.join(format!("non_existent_{}.exe", rand_id));
    let err_res = run_caged_rea_detonation_probe(&non_existent, "sess_not_found", 1000);
    assert!(err_res.is_err());
    match err_res.unwrap_err() {
        ReaError::NotFound(_) => {}
        other => panic!("Expected ReaError::NotFound, got {:?}", other),
    }
}
