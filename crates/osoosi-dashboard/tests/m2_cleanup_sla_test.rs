// Empirical SLA & Progress Verification Test Suite
// Milestone M2: R7 Async Request Hygiene & Non-Blocking Cleanup

use osoosi_dashboard::{get_or_init_dashboard_api_token, spawn_dashboard_with_backend};
use reqwest::StatusCode;
use serde_json::Value;
use std::time::Instant;

#[tokio::test]
async fn test_system_cleanup_endpoint_sla_and_progress_tracking() {
    let bound_port = spawn_dashboard_with_backend(0, None, None)
        .await
        .expect("Failed to spawn dashboard on ephemeral port");

    let base_url = format!("http://127.0.0.1:{}", bound_port);
    let valid_token = get_or_init_dashboard_api_token();
    let client = reqwest::Client::new();

    // 1. Benchmark POST /api/system/cleanup response latency (SLA: < 5s, target: < 500ms)
    let cleanup_url = format!("{}/api/system/cleanup", base_url);
    let start_time = Instant::now();

    let resp = client
        .post(&cleanup_url)
        .header("Authorization", format!("Bearer {}", valid_token))
        .json(&serde_json::json!({
            "aggressive": false,
            "days_retention": 30
        }))
        .send()
        .await
        .expect("Failed to send cleanup request");

    let elapsed = start_time.elapsed();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "POST /api/system/cleanup must return 200 OK"
    );

    assert!(
        elapsed.as_millis() < 5000,
        "SLA Violation: POST /api/system/cleanup took {:?}, exceeding 5-second SLA",
        elapsed
    );

    let body: Value = resp.json().await.expect("Expected JSON response");
    assert!(
        matches!(
            body["status"].as_str(),
            Some("success" | "scheduled" | "ok" | "completed")
        ),
        "Cleanup response status must be 'success' or 'scheduled', got {:?}",
        body["status"]
    );
    assert!(
        body["job_id"]
            .as_str()
            .is_some_and(|id| id.starts_with("cleanup-")),
        "Response must contain a valid job_id starting with 'cleanup-'"
    );

    // 2. Verify GET /api/disk-cleanup/status reflects the active/scheduled job
    let status_url = format!("{}/api/disk-cleanup/status", base_url);
    let status_resp = client
        .get(&status_url)
        .header("Authorization", format!("Bearer {}", valid_token))
        .send()
        .await
        .expect("Failed to query disk cleanup status");

    assert_eq!(
        status_resp.status(),
        StatusCode::OK,
        "GET /api/disk-cleanup/status must return 200 OK"
    );

    let status_json: Value = status_resp.json().await.expect("Expected status JSON");
    assert!(
        status_json.get("active_job").is_some(),
        "Status snapshot must contain 'active_job' progress tracking field"
    );

    // 3. Verify GET /disk-cleanup/status route alias
    let alias_url = format!("{}/disk-cleanup/status", base_url);
    let alias_resp = client
        .get(&alias_url)
        .header("Authorization", format!("Bearer {}", valid_token))
        .send()
        .await
        .expect("Failed to query alias status");

    assert_eq!(
        alias_resp.status(),
        StatusCode::OK,
        "GET /disk-cleanup/status alias route must return 200 OK"
    );
}
