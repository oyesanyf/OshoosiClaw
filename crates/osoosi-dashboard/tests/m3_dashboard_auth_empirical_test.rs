// Empirical Adversarial Challenger Test Suite
// Milestone M3: Dashboard Authentication, API Key Validation & Bypass Resistance

use osoosi_dashboard::{get_or_init_dashboard_api_token, spawn_dashboard_with_backend};
use reqwest::StatusCode;
use serde_json::{json, Value};

#[tokio::test]
async fn test_empirical_dashboard_auth_enforcement_and_bypass_resistance() {
    let bound_port = spawn_dashboard_with_backend(0, None, None)
        .await
        .expect("Failed to spawn dashboard on ephemeral port");

    let base_url = format!("http://127.0.0.1:{}", bound_port);
    let valid_token = get_or_init_dashboard_api_token();
    assert!(!valid_token.is_empty(), "Dashboard API token must not be empty");

    let client = reqwest::Client::new();
    let conversation_url = format!("{}/api/traffic/conversation", base_url);
    let sample_traffic_payload = json!({
        "human_instruction": "Analyze suspicious DNS packet stream",
        "traffic_data": "<packet> 192.168.1.50:53 -> 1.1.1.1:53 DNS query A evil.example.com </packet>"
    });

    // =========================================================================
    // 1. NEGATIVE TESTS: Requests without valid authentication must receive 401
    // =========================================================================

    // Case 1a: Unauthenticated POST to /api/traffic/conversation
    let resp = client
        .post(&conversation_url)
        .header("x-test-require-auth", "1")
        .json(&sample_traffic_payload)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "Unauthenticated POST to /api/traffic/conversation must return 401 Unauthorized"
    );

    let err_json: Value = resp.json().await.expect("Expected JSON error response");
    assert_eq!(err_json["status"], "error");
    assert_eq!(err_json["error_code"], "UNAUTHORIZED");
    assert!(
        err_json["message"]
            .as_str()
            .unwrap_or("")
            .contains("State-changing dashboard request requires a valid Bearer, X-API-Key, or X-Osoosi-Token header"),
        "Error message must specify supported auth headers"
    );

    // Case 1b: Invalid X-API-Key
    let resp = client
        .post(&conversation_url)
        .header("x-test-require-auth", "1")
        .header("X-API-Key", "invalid_forged_key_0000000000000000")
        .json(&sample_traffic_payload)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "Invalid X-API-Key must return 401");

    // Case 1c: Invalid x-api-key (lowercase)
    let resp = client
        .post(&conversation_url)
        .header("x-test-require-auth", "1")
        .header("x-api-key", "invalid_forged_key_0000000000000000")
        .json(&sample_traffic_payload)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "Invalid x-api-key must return 401");

    // Case 1d: Invalid Bearer token
    let resp = client
        .post(&conversation_url)
        .header("x-test-require-auth", "1")
        .header("Authorization", "Bearer invalid_forged_bearer_token")
        .json(&sample_traffic_payload)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "Invalid Bearer token must return 401");

    // Case 1e: Invalid X-Osoosi-Token
    let resp = client
        .post(&conversation_url)
        .header("x-test-require-auth", "1")
        .header("X-Osoosi-Token", "invalid_forged_token")
        .json(&sample_traffic_payload)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "Invalid X-Osoosi-Token must return 401");

    // =========================================================================
    // 2. POSITIVE TESTS: Requests with valid keys/tokens must authenticate
    // =========================================================================

    // Case 2a: Valid X-API-Key (standard casing)
    let resp = client
        .post(&conversation_url)
        .header("x-test-require-auth", "1")
        .header("X-API-Key", &valid_token)
        .json(&sample_traffic_payload)
        .send()
        .await
        .expect("Failed to send request");
    assert_ne!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "Valid X-API-Key must authenticate successfully (not 401)"
    );

    // Case 2b: Valid x-api-key (lowercase)
    let resp = client
        .post(&conversation_url)
        .header("x-test-require-auth", "1")
        .header("x-api-key", &valid_token)
        .json(&sample_traffic_payload)
        .send()
        .await
        .expect("Failed to send request");
    assert_ne!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "Valid lowercase x-api-key must authenticate successfully (not 401)"
    );

    // Case 2c: Valid Authorization: Bearer
    let resp = client
        .post(&conversation_url)
        .header("x-test-require-auth", "1")
        .header("Authorization", format!("Bearer {}", valid_token))
        .json(&sample_traffic_payload)
        .send()
        .await
        .expect("Failed to send request");
    assert_ne!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "Valid Bearer token must authenticate successfully (not 401)"
    );

    // Case 2d: Valid Authorization: bearer (case-insensitive scheme)
    let resp = client
        .post(&conversation_url)
        .header("x-test-require-auth", "1")
        .header("Authorization", format!("bearer {}", valid_token))
        .json(&sample_traffic_payload)
        .send()
        .await
        .expect("Failed to send request");
    assert_ne!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "Valid lowercase bearer scheme must authenticate successfully (not 401)"
    );

    // Case 2e: Valid X-Osoosi-Token
    let resp = client
        .post(&conversation_url)
        .header("x-test-require-auth", "1")
        .header("X-Osoosi-Token", &valid_token)
        .json(&sample_traffic_payload)
        .send()
        .await
        .expect("Failed to send request");
    assert_ne!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "Valid X-Osoosi-Token must authenticate successfully (not 401)"
    );

    // =========================================================================
    // 3. ADVERSARIAL BYPASS RESISTANCE ON /api/traffic/conversation
    // =========================================================================

    // Case 3a: Empty API key string
    let resp = client
        .post(&conversation_url)
        .header("x-test-require-auth", "1")
        .header("X-API-Key", "")
        .json(&sample_traffic_payload)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "Empty X-API-Key must be rejected with 401");

    // Case 3b: Whitespace-only API key
    let resp = client
        .post(&conversation_url)
        .header("x-test-require-auth", "1")
        .header("X-API-Key", "    ")
        .json(&sample_traffic_payload)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "Whitespace X-API-Key must be rejected with 401");

    // Case 3c: Bare "Bearer" without token
    let resp = client
        .post(&conversation_url)
        .header("x-test-require-auth", "1")
        .header("Authorization", "Bearer ")
        .json(&sample_traffic_payload)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "Bare Bearer must be rejected with 401");

    // Case 3d: Non-bearer authorization (e.g. Basic auth)
    let resp = client
        .post(&conversation_url)
        .header("x-test-require-auth", "1")
        .header("Authorization", "Basic YWRtaW46cGFzc3dvcmQ=")
        .json(&sample_traffic_payload)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "Basic auth must be rejected with 401");

    // Case 3e: Trailing slash bypass attempt
    let resp = client
        .post(format!("{}/api/traffic/conversation/", base_url))
        .header("x-test-require-auth", "1")
        .json(&sample_traffic_payload)
        .send()
        .await
        .expect("Failed to send request");
    assert!(
        resp.status() == StatusCode::UNAUTHORIZED || resp.status() == StatusCode::NOT_FOUND,
        "Trailing slash must not bypass auth (got {})",
        resp.status()
    );

    // Case 3f: Query string tampering bypass attempt
    let resp = client
        .post(format!("{}/api/traffic/conversation?health=true&public=1", base_url))
        .header("x-test-require-auth", "1")
        .json(&sample_traffic_payload)
        .send()
        .await
        .expect("Failed to send request");
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "Query parameter tampering must not bypass auth"
    );

    // =========================================================================
    // 4. OTHER STATE-CHANGING ENDPOINTS REQUIRE AUTHENTICATION
    // =========================================================================
    let state_changing_endpoints = [
        ("POST", "/api/mitre/stix/update", json!({})),
        ("POST", "/api/yara/reload", json!({})),
        ("POST", "/api/scan-trigger", json!({"path": "C:\\Windows\\Temp"})),
        ("POST", "/api/quarantine", json!({"path": "C:\\Windows\\Temp\\bad.exe"})),
        ("POST", "/api/false-positive", json!({"file_hash": "abc"})),
        ("POST", "/api/triage/decide", json!({"threat_id": "t1", "action": "Alert"})),
        ("POST", "/api/har/inspect", json!({"entries": []})),
    ];

    for (method, endpoint, body) in &state_changing_endpoints {
        let url = format!("{}{}", base_url, endpoint);

        // Without auth -> 401
        let unauth_resp = client
            .post(&url)
            .header("x-test-require-auth", "1")
            .json(body)
            .send()
            .await
            .unwrap_or_else(|e| panic!("Failed sending to {}: {}", endpoint, e));
        assert_eq!(
            unauth_resp.status(),
            StatusCode::UNAUTHORIZED,
            "State-changing endpoint {} {} without auth must return 401",
            method,
            endpoint
        );

        // With valid X-API-Key -> authenticated (not 401)
        let auth_resp = client
            .post(&url)
            .header("x-test-require-auth", "1")
            .header("X-API-Key", &valid_token)
            .json(body)
            .send()
            .await
            .unwrap_or_else(|e| panic!("Failed sending to {}: {}", endpoint, e));
        assert_ne!(
            auth_resp.status(),
            StatusCode::UNAUTHORIZED,
            "State-changing endpoint {} {} with valid X-API-Key must authenticate (not 401)",
            method,
            endpoint
        );
    }

    // =========================================================================
    // 5. PUBLIC & READ-ONLY LOOPBACK ENDPOINTS REMAIN ACCESSIBLE
    // =========================================================================
    let health_resp = client
        .get(format!("{}/health", base_url))
        .send()
        .await
        .expect("Health GET failed");
    assert_eq!(health_resp.status(), StatusCode::OK);

    let api_health_resp = client
        .get(format!("{}/api/health", base_url))
        .send()
        .await
        .expect("API health GET failed");
    assert_eq!(api_health_resp.status(), StatusCode::OK);

    let status_resp = client
        .get(format!("{}/api/status", base_url))
        .send()
        .await
        .expect("API status GET failed");
    assert_eq!(status_resp.status(), StatusCode::OK);
    // Verify Set-Cookie header is provided on GET /api/status
    let cookies = status_resp.headers().get("set-cookie");
    assert!(
        cookies.is_some(),
        "GET /api/status must deliver osoosi_token cookie for browser session"
    );
}
