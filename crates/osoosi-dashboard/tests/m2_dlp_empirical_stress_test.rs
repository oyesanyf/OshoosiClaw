// Empirical Stress Test Harness for Milestone 2 DLP Pipeline
// Tests:
// 1. Alternating benign (covergeneral.docx -> allow & auto-release) vs sensitive (10-MB-Test.xlsx -> 4-voter quorum + WFP block)
// 2. Immediate re-blocking after auto-release
// 3. Rapid repeated uploads within debounce window (DestinationBlocked -> Debounced -> Reset upon benign)
// 4. Live sink deduplication key transition across alternating selections

use axum::Json;
use osoosi_dashboard::routes::dlp::post_dlp_browser_event;
use osoosi_dashboard::routes::dlp_containment::global_containment_engine;
use serde_json::json;
use std::sync::Mutex;

static DLP_STRESS_TEST_LOCK: Mutex<()> = Mutex::new(());

#[tokio::test]
async fn test_alternating_benign_and_sensitive_uploads_with_auto_release_cycle() {
    let _guard = DLP_STRESS_TEST_LOCK.lock().unwrap();
    let engine = global_containment_engine();
    let unique_host = format!("dlptest-{}.internal.test", uuid::Uuid::new_v4().simple());
    let dest_url = format!("https://{}/https-post/", unique_host);

    // Initial state: Host must NOT have an active browser block
    assert!(!engine.has_active_browser_block_for_host(&unique_host));

    // =========================================================================
    // STEP 1: Upload sensitive file `10-MB-Test.xlsx` containing PHI/PII
    // =========================================================================
    let sens_payload = json!({
        "actor_process": "chrome.exe",
        "url": dest_url,
        "channel": "BROWSER_FILE_UPLOAD",
        "file_name": "10-MB-Test.xlsx",
        "content": format!(
            "patient_name,mrn,ssn,credit_card,diagnosis\nJohn Sensitive Doe,MRN-90210,123-45-6789,4532015112830366,Hypertension I10 case_{}\n",
            uuid::Uuid::new_v4()
        )
    });

    let Json(sens_res) = post_dlp_browser_event(Json(sens_payload)).await;
    assert_eq!(sens_res.get("ok").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(sens_res.get("allowed").and_then(|v| v.as_bool()), Some(false), "Sensitive upload must be DENIED");
    assert_eq!(sens_res.get("authorization_decision").and_then(|v| v.as_str()), Some("DENY"));
    assert_eq!(sens_res.get("dlp_response").and_then(|v| v.as_str()), Some("QUARANTINE"));

    // Verify 4-voter quorum in containment outcome
    let event_obj = sens_res.get("event").and_then(|v| v.as_object()).expect("event object");
    let containment = event_obj.get("containment").and_then(|v| v.as_object()).expect("containment object");
    assert_eq!(containment.get("decision").and_then(|v| v.as_str()), Some("DestinationBlocked"));
    let voters = containment.get("voters").and_then(|v| v.as_object()).expect("voters object");
    assert_eq!(voters.get("reached").and_then(|v| v.as_bool()), Some(true), "4-voter quorum must be reached");

    let ballots = voters.get("ballots").and_then(|v| v.as_array()).expect("ballots array");
    assert!(ballots.iter().any(|b| b.get("voter").and_then(|v| v.as_str()) == Some("OpenJEV-Voter")));
    assert!(ballots.iter().any(|b| b.get("voter").and_then(|v| v.as_str()) == Some("REA-Voter")));
    assert!(ballots.iter().any(|b| b.get("voter").and_then(|v| v.as_str()) == Some("RedactX-Deterministic-Validators")));
    assert!(ballots.iter().any(|b| b.get("voter").and_then(|v| v.as_str()) == Some("Google-SafeBrowsing-Voter")));

    // Host must now be blocked in WFP/containment engine
    assert!(engine.has_active_browser_block_for_host(&unique_host), "Host must be blocked after sensitive upload");

    // =========================================================================
    // STEP 2: Upload benign file `covergeneral.docx`
    // Must be ALLOWED and must automatically release stale destination block
    // =========================================================================
    let benign_payload = json!({
        "actor_process": "chrome.exe",
        "url": dest_url,
        "channel": "BROWSER_FILE_UPLOAD",
        "file_name": "covergeneral.docx",
        "content": "Dear Hiring Manager,\nI am applying for the Senior Systems Security Engineer role.\nPlease find my resume attached.\nBest regards,\nJane Applicant\n"
    });

    let Json(benign_res) = post_dlp_browser_event(Json(benign_payload)).await;
    assert_eq!(benign_res.get("ok").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(benign_res.get("allowed").and_then(|v| v.as_bool()), Some(true), "Benign upload must be ALLOWED");
    assert_eq!(benign_res.get("authorization_decision").and_then(|v| v.as_str()), Some("ALLOW"));

    // Host block must be auto-released!
    assert!(
        !engine.has_active_browser_block_for_host(&unique_host),
        "Host block must be automatically released upon benign upload"
    );

    // =========================================================================
    // STEP 3: Upload sensitive file `10-MB-Test.xlsx` again
    // Must immediately re-block the host (verifying auto-release didn't permanently bypass)
    // =========================================================================
    let sens_payload_2 = json!({
        "actor_process": "chrome.exe",
        "url": dest_url,
        "channel": "BROWSER_FILE_UPLOAD",
        "file_name": "10-MB-Test.xlsx",
        "content": format!(
            "patient_name,mrn,ssn,credit_card,diagnosis\nBob Patient,MRN-11223,123-45-6789,4532015112830366,Diabetes Type 2 ICD10-E11 case_{}\n",
            uuid::Uuid::new_v4()
        )
    });

    let Json(sens_res_2) = post_dlp_browser_event(Json(sens_payload_2)).await;
    assert_eq!(sens_res_2.get("allowed").and_then(|v| v.as_bool()), Some(false), "Re-upload of sensitive file must be DENIED");
    assert!(
        engine.has_active_browser_block_for_host(&unique_host),
        "Host must be immediately re-blocked on subsequent sensitive upload"
    );

    let event_2 = sens_res_2.get("event").and_then(|v| v.as_object()).expect("event 2");
    let cont_2 = event_2.get("containment").and_then(|v| v.as_object()).expect("containment 2");
    assert_eq!(cont_2.get("decision").and_then(|v| v.as_str()), Some("DestinationBlocked"));

    // Cleanup: restore host blocks to leave engine clean
    let _ = engine.restore_browser_destination_blocks_for_host(&unique_host, "test-teardown");
    assert!(!engine.has_active_browser_block_for_host(&unique_host));
    assert!(!engine.has_active_browser_block_for_host(&unique_host));
}

#[tokio::test]
async fn test_rapid_repeated_uploads_debounce_and_reset_behavior() {
    let _guard = DLP_STRESS_TEST_LOCK.lock().unwrap();
    let engine = global_containment_engine();
    let unique_host = format!("debounce-{}.internal.test", uuid::Uuid::new_v4().simple());
    let dest_url = format!("https://{}/https-post/", unique_host);

    let sens_content_1 = format!(
        "name,ssn,icd10\nPatient One,111-22-3333,Asthma J45 case_{}\n",
        uuid::Uuid::new_v4()
    );
    let sens_content_2 = format!(
        "name,ssn,icd10\nPatient Two,444-55-6666,Bronchitis J20 case_{}\n",
        uuid::Uuid::new_v4()
    );

    // 1. First sensitive upload -> triggers initial DestinationBlocked
    let payload_1 = json!({
        "actor_process": "chrome.exe",
        "url": dest_url,
        "channel": "BROWSER_FILE_UPLOAD",
        "file_name": "10-MB-Test.xlsx",
        "content": sens_content_1
    });
    let Json(res_1) = post_dlp_browser_event(Json(payload_1)).await;
    assert_eq!(res_1.get("allowed").and_then(|v| v.as_bool()), Some(false));
    let event_1 = res_1.get("event").and_then(|v| v.as_object()).expect("event 1");
    let cont_1 = event_1.get("containment").and_then(|v| v.as_object()).expect("containment 1");
    assert_eq!(cont_1.get("decision").and_then(|v| v.as_str()), Some("DestinationBlocked"));
    assert!(engine.has_active_browser_block_for_host(&unique_host));

    // 2. Second sensitive upload immediately within debounce window (0ms delay)
    // Upload is STILL DENIED by DLP, but containment decision is Debounced (preventing rule explosion)
    let payload_2 = json!({
        "actor_process": "chrome.exe",
        "url": dest_url,
        "channel": "BROWSER_FILE_UPLOAD",
        "file_name": "10-MB-Test.xlsx",
        "content": sens_content_2
    });
    let Json(res_2) = post_dlp_browser_event(Json(payload_2)).await;
    assert_eq!(res_2.get("allowed").and_then(|v| v.as_bool()), Some(false), "Debounced repeat upload must STILL be DENIED");
    let event_2 = res_2.get("event").and_then(|v| v.as_object()).expect("event 2");
    let cont_2 = event_2.get("containment").and_then(|v| v.as_object()).expect("containment 2");
    assert_eq!(
        cont_2.get("decision").and_then(|v| v.as_str()),
        Some("Debounced"),
        "Containment decision within debounce window must be Debounced"
    );

    // 3. Upload clean covergeneral.docx -> clears block AND clears debounce key
    let clean_payload = json!({
        "actor_process": "chrome.exe",
        "url": dest_url,
        "channel": "BROWSER_FILE_UPLOAD",
        "file_name": "covergeneral.docx",
        "content": "Clean cover letter. Attached resume.\n"
    });
    let Json(res_clean) = post_dlp_browser_event(Json(clean_payload)).await;
    assert_eq!(res_clean.get("allowed").and_then(|v| v.as_bool()), Some(true));
    assert!(!engine.has_active_browser_block_for_host(&unique_host));

    // 4. Sensitive upload immediately after clean upload -> must get fresh DestinationBlocked (not Debounced!)
    let sens_content_3 = format!(
        "name,ssn,icd10\nPatient Three,777-88-9999,Diabetes E11 case_{}\n",
        uuid::Uuid::new_v4()
    );
    let payload_3 = json!({
        "actor_process": "chrome.exe",
        "url": dest_url,
        "channel": "BROWSER_FILE_UPLOAD",
        "file_name": "10-MB-Test.xlsx",
        "content": sens_content_3
    });
    let Json(res_3) = post_dlp_browser_event(Json(payload_3)).await;
    assert_eq!(res_3.get("allowed").and_then(|v| v.as_bool()), Some(false));
    let event_3 = res_3.get("event").and_then(|v| v.as_object()).expect("event 3");
    let cont_3 = event_3.get("containment").and_then(|v| v.as_object()).expect("containment 3");
    assert_eq!(
        cont_3.get("decision").and_then(|v| v.as_str()),
        Some("DestinationBlocked"),
        "Debounce must be cleared upon clean upload so new sensitive upload immediately re-blocks"
    );

    // Teardown
    let _ = engine.restore_browser_destination_blocks_for_host(&unique_host, "test-teardown");
}
