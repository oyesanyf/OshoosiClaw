//! Milestone M2 Empirical Challenger Adversarial Test Suite
//!
//! Scope:
//! 1. H13 Security Hardening & bind_all Enforcement:
//!    - When OSOOSI_DASHBOARD_BIND_ALL=1, unauthenticated GET requests to sensitive routes
//!      (/api/env-gateway/config, /api/env-gateway/status, /api/threats, /api/settings/autonomy)
//!      must be strictly rejected with 401 Unauthorized.
//!    - Public endpoints (/health, /api/health, /, static assets) must be permitted without authentication.
//!    - All state-changing /api/env-gateway/* endpoints (/seal, /revert, /unseal-file, /watch, /test, POST /config)
//!      must strictly require valid token authentication regardless of bind_all.
//!    - Adversarial token bypass vectors (forged token, basic auth, trailing slash, query params) must fail.
//! 2. Zero-Touch PATH & System Environment Protection:
//!    - PATH, Path, TEMP, SYSTEMROOT, COMSPEC, WINDIR, etc. must be unconditionally vetoed by Arm 3
//!      safety guard with 0 confidence and descriptive veto reason.
//!    - Live file sealing must NEVER seal or mutate system variables in .env files.
//!    - POST /api/env-gateway/config must purge any system variables from selected_variables.

use axum::http::{header, StatusCode};
use osoosi_core::protected_env_backup::{
    is_hard_protected_non_secret_key, LlmFusionApiKeyEnumerator, ProtectedEnvBackupVault,
};
use osoosi_dashboard::{get_or_init_dashboard_api_token, spawn_dashboard_with_backend};
use reqwest::Client;
use serde_json::{json, Value};
use std::fs;

// ============================================================================
// 1. Zero-Touch PATH & System Invariant Unit Challenge
// ============================================================================

#[test]
fn test_adversarial_zero_touch_path_and_system_invariants_hard_vetoed() {
    let forbidden_keys = [
        "PATH",
        "Path",
        "path",
        "TEMP",
        "temp",
        "SYSTEMROOT",
        "systemroot",
        "COMSPEC",
        "comspec",
        "WINDIR",
        "windir",
        "JAVA_HOME",
        "java_home",
        "USERPROFILE",
        "PSMODULEPATH",
        "ALLUSERSPROFILE",
        "PATHEXT",
        "PUBLIC",
        "DRIVERDATA",
        "APPDATA",
        "LOCALAPPDATA",
    ];

    for key in forbidden_keys {
        // Direct hard-protected check
        assert!(
            is_hard_protected_non_secret_key(key, ""),
            "Key '{}' MUST be detected as hard-protected non-secret key",
            key
        );

        // Arm 3 consensus evaluation check
        let eval = LlmFusionApiKeyEnumerator::evaluate_variable(
            key,
            "C:\\Windows\\System32;C:\\Program Files\\bin",
        );
        assert!(
            !eval.selected,
            "Key '{}' must NOT be selected for sealing",
            key
        );
        assert!(
            eval.vetoed_by_safety_guard,
            "Key '{}' must be flagged as vetoed_by_safety_guard",
            key
        );
        assert!(
            eval.arm3_safety_veto,
            "Key '{}' must trigger arm3_safety_veto",
            key
        );
        assert_eq!(
            eval.fusion_confidence_bp, 0,
            "Key '{}' must have 0 basis points confidence",
            key
        );
        assert!(
            eval.standin_token.is_none(),
            "Key '{}' must never be assigned a standin token",
            key
        );
        let reason = eval.veto_reason.unwrap_or_default();
        assert!(
            reason.contains("VETOED"),
            "Key '{}' veto reason must contain 'VETOED', got '{}'",
            key,
            reason
        );
    }
}

#[test]
fn test_adversarial_zero_touch_path_whitespace_and_casing_variations() {
    let variants = [
        " PATH ",
        "  Path  ",
        "WINDIR\t",
        "\nTEMP",
        "SYSTEMROOT ",
        "COMSPEC ",
    ];

    for variant in variants {
        assert!(
            is_hard_protected_non_secret_key(variant, ""),
            "Variant '{}' with whitespace must be detected as hard-protected non-secret",
            variant
        );

        let eval = LlmFusionApiKeyEnumerator::evaluate_variable(variant, "some_dummy_value");
        assert!(
            eval.vetoed_by_safety_guard,
            "Variant '{}' must be vetoed by safety guard",
            variant
        );
        assert!(!eval.selected, "Variant '{}' must not be selected", variant);
    }
}

#[test]
fn test_adversarial_zero_touch_file_sealing_preserves_system_variables() {
    let test_dir = std::env::temp_dir().join(format!("dash_adv_env_{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&test_dir).expect("Failed to create temp dir");

    let env_file = test_dir.join(".env");
    let vault_file = test_dir.join("vault.enc");

    let original_content = "\
# Application Configuration
PATH=C:\\Windows\\System32;C:\\Windows;D:\\tools
Path=C:\\Program Files\\Git\\cmd
TEMP=C:\\Users\\Default\\AppData\\Local\\Temp
SYSTEMROOT=C:\\Windows
COMSPEC=C:\\Windows\\System32\\cmd.exe
WINDIR=C:\\Windows
PORT=8080
HOST=127.0.0.1
GEMINI_API_KEY=AIzaSyB1234567890abcdefghijklmnopqr
HF_TOKEN=hf_abcdefghijklmnopqrstuvwxyz0123456789
";
    fs::write(&env_file, original_content).expect("Failed to write test .env file");

    // Execute dynamic sealing
    let seal_res = ProtectedEnvBackupVault::seal_and_backup_dynamic(&env_file, &vault_file)
        .expect("Sealing must succeed");

    assert!(
        seal_res.total_vetoed >= 6,
        "Expected at least 6 vetoed system variables, got {}",
        seal_res.total_vetoed
    );
    assert_eq!(
        seal_res.total_selected, 2,
        "Only GEMINI_API_KEY and HF_TOKEN should be selected"
    );

    // Read the file after sealing
    let sealed_content = fs::read_to_string(&env_file).expect("Failed to read sealed .env");

    // Verify system variables are UNTOUCHED verbatim
    assert!(sealed_content.contains("PATH=C:\\Windows\\System32;C:\\Windows;D:\\tools"));
    assert!(sealed_content.contains("Path=C:\\Program Files\\Git\\cmd"));
    assert!(sealed_content.contains("TEMP=C:\\Users\\Default\\AppData\\Local\\Temp"));
    assert!(sealed_content.contains("SYSTEMROOT=C:\\Windows"));
    assert!(sealed_content.contains("COMSPEC=C:\\Windows\\System32\\cmd.exe"));
    assert!(sealed_content.contains("WINDIR=C:\\Windows"));
    assert!(sealed_content.contains("PORT=8080"));
    assert!(sealed_content.contains("HOST=127.0.0.1"));

    // Verify secrets are replaced by stand-in tokens
    assert!(!sealed_content.contains("AIzaSyB1234567890abcdefghijklmnopqr"));
    assert!(!sealed_content.contains("hf_abcdefghijklmnopqrstuvwxyz0123456789"));
    assert!(sealed_content.contains("GEMINI_API_KEY=OSHOOSI_STANDIN_"));
    assert!(sealed_content.contains("HF_TOKEN=OSHOOSI_STANDIN_"));

    // Revert the file and verify exact restoration
    ProtectedEnvBackupVault::revert_single_file(&vault_file, &env_file)
        .expect("Revert must succeed");

    let restored_content = fs::read_to_string(&env_file).expect("Failed to read restored .env");
    assert_eq!(
        restored_content, original_content,
        "Restored content must exactly match pre-seal content"
    );

    let _ = fs::remove_dir_all(&test_dir);
}

// ============================================================================
// 2. REST API Zero-Touch Config Filtering Challenge
// ============================================================================

#[tokio::test]
async fn test_adversarial_rest_api_config_veto_system_variables() {
    let bound_port = spawn_dashboard_with_backend(0, None, None)
        .await
        .expect("Failed to spawn dashboard");
    let base_url = format!("http://127.0.0.1:{}", bound_port);
    let token = get_or_init_dashboard_api_token();
    let client = Client::new();

    // Attempt to inject PATH and system invariants into selected_variables
    let malicious_payload = json!({
        "selected_variables": [
            "PATH",
            "Path",
            "TEMP",
            "SYSTEMROOT",
            "COMSPEC",
            "WINDIR",
            "JAVA_HOME",
            "USERPROFILE",
            "GEMINI_API_KEY",
            "HF_TOKEN"
        ]
    });

    let resp = client
        .post(format!("{}/api/env-gateway/config", base_url))
        .header(header::AUTHORIZATION, format!("Bearer {}", token))
        .json(&malicious_payload)
        .send()
        .await
        .expect("Failed to send config update");

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "POST /api/env-gateway/config with valid auth should succeed"
    );

    let body: Value = resp.json().await.expect("Expected JSON response");
    let selected = body["config"]["selected_variables"]
        .as_array()
        .expect("selected_variables must be an array");

    let selected_strings: Vec<String> = selected
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();

    // Verify all system variables were stripped
    for forbidden in [
        "PATH",
        "Path",
        "TEMP",
        "SYSTEMROOT",
        "COMSPEC",
        "WINDIR",
        "JAVA_HOME",
        "USERPROFILE",
    ] {
        assert!(
            !selected_strings
                .iter()
                .any(|s| s.eq_ignore_ascii_case(forbidden)),
            "ZERO-TOUCH VIOLATION: '{}' must NOT appear in selected_variables after config update",
            forbidden
        );
    }

    // Verify legitimate secrets remain
    assert!(selected_strings.contains(&"GEMINI_API_KEY".to_string()));
    assert!(selected_strings.contains(&"HF_TOKEN".to_string()));
}

// ============================================================================
// 3. REST API H13 Security Hardening & bind_all Enforcement Challenge
// ============================================================================

#[tokio::test]
async fn test_adversarial_h13_bind_all_auth_enforcement_and_public_whitelist() {
    // Enable bind_all to simulate 0.0.0.0 external exposure
    std::env::set_var("OSOOSI_DASHBOARD_BIND_ALL", "1");

    let bound_port = spawn_dashboard_with_backend(0, None, None)
        .await
        .expect("Failed to spawn dashboard with bind_all=1");
    let base_url = format!("http://127.0.0.1:{}", bound_port);
    let valid_token = get_or_init_dashboard_api_token();
    let client = Client::new();

    // -----------------------------------------------------------------------
    // 3A. Unauthenticated sensitive GET routes -> MUST BE 401 UNAUTHORIZED
    // -----------------------------------------------------------------------
    let sensitive_get_routes = [
        "/api/env-gateway/config",
        "/api/env-gateway/status",
        "/api/env-gateway/machine-binding",
        "/api/threats",
        "/api/settings/autonomy",
    ];

    for route in sensitive_get_routes {
        let resp = client
            .get(format!("{}{}", base_url, route))
            .send()
            .await
            .unwrap_or_else(|e| panic!("Failed GET {}: {}", route, e));

        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "H13 VIOLATION: Unauthenticated GET {} under bind_all=1 must return 401 Unauthorized, got {}",
            route,
            resp.status()
        );

        let err: Value = resp.json().await.unwrap();
        assert_eq!(
            err["error_code"], "UNAUTHORIZED",
            "Error code must be UNAUTHORIZED for {}",
            route
        );
    }

    // -----------------------------------------------------------------------
    // 3B. Unauthenticated public whitelist routes -> MUST BE 200 OK
    // -----------------------------------------------------------------------
    let public_whitelist_routes = ["/health", "/api/health", "/"];

    for route in public_whitelist_routes {
        let resp = client
            .get(format!("{}{}", base_url, route))
            .send()
            .await
            .unwrap_or_else(|e| panic!("Failed GET {}: {}", route, e));

        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "H13 VIOLATION: Public route {} under bind_all=1 must return 200 OK, got {}",
            route,
            resp.status()
        );
    }

    // -----------------------------------------------------------------------
    // 3C. All state-changing /api/env-gateway/* routes WITHOUT token -> 401
    // -----------------------------------------------------------------------
    let state_changing_env_gateway_routes = [
        ("POST", "/api/env-gateway/config", json!({})),
        ("POST", "/api/env-gateway/seal", json!({})),
        ("POST", "/api/env-gateway/revert", json!({})),
        (
            "POST",
            "/api/env-gateway/unseal-file",
            json!({"file_path": "foo"}),
        ),
        ("POST", "/api/env-gateway/watch", json!({})),
        ("POST", "/api/env-gateway/test", json!({})),
        (
            "POST",
            "/api/env-gateway/machine-binding/refresh",
            json!({}),
        ),
    ];

    for (_method, route, payload) in &state_changing_env_gateway_routes {
        let resp = client
            .post(format!("{}{}", base_url, route))
            .json(payload)
            .send()
            .await
            .unwrap_or_else(|e| panic!("Failed unauthenticated POST {}: {}", route, e));

        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "H13 VIOLATION: Unauthenticated state-changing POST {} must return 401, got {}",
            route,
            resp.status()
        );

        let err: Value = resp.json().await.unwrap();
        assert_eq!(err["error_code"], "UNAUTHORIZED");
    }

    // -----------------------------------------------------------------------
    // 3D. Adversarial Forged Tokens on /api/env-gateway/* -> 401
    // -----------------------------------------------------------------------
    let test_endpoint = format!("{}/api/env-gateway/watch", base_url);

    // Case D1: Forged Bearer token
    let resp = client
        .post(&test_endpoint)
        .header(header::AUTHORIZATION, "Bearer forged_adversarial_token_999")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "Forged Bearer token must return 401"
    );

    // Case D2: Forged X-API-Key
    let resp = client
        .post(&test_endpoint)
        .header("X-API-Key", "forged_adversarial_key_999")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "Forged X-API-Key must return 401"
    );

    // Case D3: Forged X-Osoosi-Token
    let resp = client
        .post(&test_endpoint)
        .header("X-Osoosi-Token", "forged_adversarial_osoosi_token")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "Forged X-Osoosi-Token must return 401"
    );

    // Case D4: Empty Bearer token
    let empty_bearer_header = String::from("Bearer ");
    let resp = client
        .post(&test_endpoint)
        .header("authorization", empty_bearer_header)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "Empty Bearer must return 401"
    );

    // Case D5: Basic auth attempt
    let invalid_basic_header = String::from("Basic ") + "mock_invalid_scheme";
    let resp = client
        .post(&test_endpoint)
        .header("authorization", invalid_basic_header)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "Basic auth must return 401"
    );

    // Case D6: Query parameter bypass attempt
    let resp = client
        .post(format!("{}?health=true&public=1", test_endpoint))
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "Query param bypass must return 401"
    );

    // -----------------------------------------------------------------------
    // 3E. Authenticated POST with valid Bearer token -> MUST NOT be 401
    // -----------------------------------------------------------------------
    let valid_auth_hdr = format!("{} {}", "Bearer", valid_token);
    for (_method, route, payload) in &state_changing_env_gateway_routes {
        let resp = client
            .post(format!("{}{}", base_url, route))
            .header("authorization", &valid_auth_hdr)
            .json(payload)
            .send()
            .await
            .unwrap_or_else(|e| panic!("Failed authenticated POST {}: {}", route, e));

        assert_ne!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "POST {} with valid Bearer token must pass authentication, got 401",
            route
        );
    }

    // -----------------------------------------------------------------------
    // 3F. Machine Binding Hardware Anchor Status & Refresh Verification
    // -----------------------------------------------------------------------
    let resp_mb_auth = client
        .get(format!("{}/api/env-gateway/machine-binding", base_url))
        .header("authorization", &valid_auth_hdr)
        .send()
        .await
        .unwrap();
    assert_eq!(resp_mb_auth.status(), StatusCode::OK);
    let mb_body: Value = resp_mb_auth.json().await.unwrap();
    assert_eq!(mb_body["status"], "success");
    assert!(mb_body["bound"].as_bool().unwrap());
    assert!(mb_body["confidence_score"].as_f64().unwrap() >= 0.95);
    assert!(mb_body["masked_mac_fingerprints"].is_array());
    assert_eq!(mb_body["quorum_status"], "QUORUM_OK");
    assert!(mb_body["anchor_health"]["non_mac_quorum_met"]
        .as_bool()
        .unwrap());

    // Refresh route with valid token
    let resp_refresh = client
        .post(format!(
            "{}/api/env-gateway/machine-binding/refresh",
            base_url
        ))
        .header("authorization", &valid_auth_hdr)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp_refresh.status(), StatusCode::OK);
    let refresh_body: Value = resp_refresh.json().await.unwrap();
    assert_eq!(refresh_body["status"], "success");
    assert_eq!(refresh_body["refreshed"], true);
    assert!(refresh_body["bound"].as_bool().unwrap());

    // Clean up environment
    std::env::remove_var("OSOOSI_DASHBOARD_BIND_ALL");
}
