// Empirical Adversarial Challenger Test Suite
// Milestone M5: Control Plane Auth, Origin Hardening, Win32 NTFS DACL, and Sec-Fetch-Site Defenses
// Conducted by teamwork_challenger_m5_2 (Empirical Challenger)

use axum::http::HeaderMap;
use osoosi_dashboard::{
    get_or_init_dashboard_api_token, harden_file_ntfs_dacl, is_valid_loopback_origin,
    spawn_dashboard_with_backend, validate_csrf_origin_and_fetch_site, PROTECTED_NTFS_SDDL,
};
use reqwest::StatusCode;
use serde_json::Value;

#[test]
fn test_adversarial_loopback_origin_spoofing_vectors() {
    // 1. Adversarial Domain Suffix / Subdomain Spoofing
    let adversarial_origins = [
        "http://127.0.0.1.attacker.com",
        "http://127.0.0.1:3030.attacker.com",
        "http://localhost.attacker.com",
        "http://[::1].attacker.com",
        "https://127.0.0.1.attacker.com",
        "https://localhost.attacker.com",
        "https://[::1].attacker.com",
        "http://127.0.0.1:80.evil.org",
        "http://localhost:3000.spoof.net",
        "http://[::1]:8080.phishing.io",
        // 2. Port Parsing Boundary & Overflow Attacks
        "http://127.0.0.1:999999",      // u16 overflow (> 65535)
        "http://127.0.0.1:65536",       // 65535 + 1
        "http://127.0.0.1:100000",
        "http://127.0.0.1:-1",          // negative port
        "http://127.0.0.1:+3030",       // leading plus sign
        "http://127.0.0.1: 3030",       // leading space
        "http://127.0.0.1:3030 ",       // trailing space
        "http://127.0.0.1:0x30",        // hex port
        "http://127.0.0.1:",            // empty port after colon
        // 3. Path / Query / Fragment Injections
        "http://127.0.0.1:3030/api",
        "http://localhost:3000?auth=1",
        "http://127.0.0.1:3030#frag",
        // 4. External IP / Host Spoofing
        "ftp://127.0.0.1:3030",
        "ws://127.0.0.1:3030",
        "http://192.168.1.1:3030",
        "http://10.0.0.1:3030",
        "http://8.8.8.8:3030",
        "http://attacker.com",
        "http://attacker.com:3030",
        // 5. Embedded Credentials
        "http://admin:secret@127.0.0.1:3030",
        "http://attacker.com@127.0.0.1:3030",
        // 6. Trailing Control Bytes
        "http://127.0.0.1:3030\0",
        "http://127.0.0.1:3030\r\n",
        // 7. Malformed IPv6 Brackets
        "http://::1:8080",
        "http://[::1:8080",
        "http://::1]:8080",
    ];

    for vec in &adversarial_origins {
        assert!(
            !is_valid_loopback_origin(vec),
            "SECURITY CRITICAL: Adversarial origin vector '{}' was incorrectly accepted!",
            vec
        );
    }

    // Legitimate loopback origins must be accepted
    let legitimate_origins = [
        "http://127.0.0.1:3030",
        "http://localhost:3000",
        "http://[::1]:8080",
        "https://127.0.0.1:3030",
        "https://localhost:8443",
        "https://[::1]:9443",
        "http://127.0.0.1",
        "https://127.0.0.1",
        "http://localhost",
        "https://localhost",
        "http://[::1]",
        "https://[::1]",
        "null",
        "http://127.0.0.1:0",
        "http://127.0.0.1:65535",
    ];

    for legit in &legitimate_origins {
        assert!(
            is_valid_loopback_origin(legit),
            "Legitimate loopback origin '{}' was incorrectly rejected!",
            legit
        );
    }
}

#[test]
fn test_sec_fetch_site_csrf_matrix() {
    // 1. Untrusted Sec-Fetch-Site values must return 403 FORBIDDEN
    let untrusted_sfs = [
        "cross-site",
        "same-site",
        "null",
        "invalid",
        "unknown",
        "cross_site",
        "none.attacker.com",
    ];

    for sfs in &untrusted_sfs {
        let mut headers = HeaderMap::new();
        headers.insert("sec-fetch-site", sfs.parse().unwrap());
        headers.insert("origin", "http://127.0.0.1:3030".parse().unwrap());
        let res = validate_csrf_origin_and_fetch_site(&headers);
        assert!(
            res.is_err(),
            "Untrusted Sec-Fetch-Site '{}' must be rejected",
            sfs
        );
        let (status, body) = res.unwrap_err();
        assert_eq!(status, axum::http::StatusCode::FORBIDDEN);
        assert_eq!(body["error_code"], "CSRF_CROSS_SITE_BLOCKED");
    }

    // 2. Trusted Sec-Fetch-Site values must pass
    let trusted_sfs = ["same-origin", "none", "SAME-ORIGIN", "None", " same-origin "];

    for sfs in &trusted_sfs {
        let mut headers = HeaderMap::new();
        headers.insert("sec-fetch-site", sfs.trim().parse().unwrap());
        headers.insert("origin", "http://127.0.0.1:3030".parse().unwrap());
        let res = validate_csrf_origin_and_fetch_site(&headers);
        assert!(
            res.is_ok(),
            "Trusted Sec-Fetch-Site '{}' was incorrectly rejected",
            sfs
        );
    }

    // 3. Permitted Sec-Fetch-Site but untrusted Origin must fail with CSRF_ORIGIN_MISMATCH
    let mut headers = HeaderMap::new();
    headers.insert("sec-fetch-site", "same-origin".parse().unwrap());
    headers.insert("origin", "http://evil-attacker.com".parse().unwrap());
    let res = validate_csrf_origin_and_fetch_site(&headers);
    assert!(res.is_err());
    let (status, body) = res.unwrap_err();
    assert_eq!(status, axum::http::StatusCode::FORBIDDEN);
    assert_eq!(body["error_code"], "CSRF_ORIGIN_MISMATCH");
}

#[test]
fn test_harden_file_ntfs_dacl_execution() {
    let temp_file = std::env::temp_dir().join(format!("test_dacl_{}.db", uuid::Uuid::new_v4()));
    std::fs::write(&temp_file, b"DACL_TEST_DATA").expect("Failed to write temp file");

    let res = harden_file_ntfs_dacl(&temp_file);
    assert!(res.is_ok(), "harden_file_ntfs_dacl failed: {:?}", res);
    assert_eq!(res.unwrap(), PROTECTED_NTFS_SDDL);

    // Clean up
    let _ = std::fs::remove_file(&temp_file);
}

#[tokio::test]
async fn test_live_dashboard_control_plane_session_auth_and_csrf() {
    let bound_port = spawn_dashboard_with_backend(0, None, None)
        .await
        .expect("Failed to spawn live dashboard on ephemeral port");

    let base_url = format!("http://127.0.0.1:{}", bound_port);
    let expected_token = get_or_init_dashboard_api_token();
    let client = reqwest::Client::new();

    // 1. Unauthenticated POST to /api/auth/session must fail closed with 401 Unauthorized
    let session_url = format!("{}/api/auth/session", base_url);
    let resp_unauth = client
        .post(&session_url)
        .header("sec-fetch-site", "same-origin")
        .header("origin", "http://127.0.0.1:3030")
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(
        resp_unauth.status(),
        StatusCode::UNAUTHORIZED,
        "Unauthenticated session bootstrap must return 401 Unauthorized"
    );
    let err_body: Value = resp_unauth.json().await.unwrap();
    assert_eq!(err_body["error_code"], "UNAUTHORIZED_SESSION_BOOTSTRAP");
    assert_eq!(err_body["authenticated"], false);

    // 2. Cross-site request to /api/auth/session with Sec-Fetch-Site: cross-site must fail with 403 Forbidden
    let resp_cross = client
        .post(&session_url)
        .header("sec-fetch-site", "cross-site")
        .header("origin", "http://127.0.0.1:3030")
        .json(&serde_json::json!({ "token": expected_token }))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(
        resp_cross.status(),
        StatusCode::FORBIDDEN,
        "Cross-site request to /api/auth/session must return 403 Forbidden"
    );

    // 3. Preflight OPTIONS request to /api/auth/session must succeed with 200 OK (CSRF bypass)
    let resp_options = client
        .request(reqwest::Method::OPTIONS, &session_url)
        .header("sec-fetch-site", "cross-site") // OPTIONS bypasses CSRF
        .send()
        .await
        .expect("Failed to send OPTIONS request");

    assert_eq!(
        resp_options.status(),
        StatusCode::OK,
        "OPTIONS preflight request must cleanly bypass CSRF checks"
    );

    // 4. Authenticated POST to /api/auth/session with valid token must succeed with 200 OK + HttpOnly cookie
    let resp_auth = client
        .post(&session_url)
        .header("sec-fetch-site", "same-origin")
        .header("origin", "http://127.0.0.1:3030")
        .json(&serde_json::json!({ "token": expected_token }))
        .send()
        .await
        .expect("Failed to send authenticated session request");

    assert_eq!(
        resp_auth.status(),
        StatusCode::OK,
        "Authenticated session request must return 200 OK"
    );

    let cookie_hdr = resp_auth
        .headers()
        .get(reqwest::header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    assert!(
        cookie_hdr.contains("osoosi_token="),
        "Cookie must set osoosi_token"
    );
    assert!(
        cookie_hdr.contains("HttpOnly"),
        "Cookie must have HttpOnly flag"
    );
    assert!(
        cookie_hdr.contains("SameSite=Strict"),
        "Cookie must have SameSite=Strict flag"
    );
    assert!(
        cookie_hdr.contains("Secure"),
        "Cookie must have Secure flag"
    );

    let auth_body: Value = resp_auth.json().await.unwrap();
    assert_eq!(auth_body["authenticated"], true);
    assert_eq!(auth_body["status"], "ok");
    assert_eq!(auth_body["token"], expected_token);
}
