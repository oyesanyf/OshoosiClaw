//! Milestone M14: Strict Loopback-Only WebUI Isolation Regression & Challenger Suite
//!
//! Evaluates the 5 defensive layers:
//! - Layer A: Peer TCP Check: Only 127.0.0.0/8, ::1, and ::ffff:127.x.x.x permitted
//! - Layer B: Reverse Proxy Header Rejection: Non-loopback hops in X-Forwarded-For, X-Real-IP, etc. fail closed
//! - Layer C: Host Header & DNS Rebinding Check: Non-loopback Host rejected with NON_LOOPBACK_HOST_FORBIDDEN
//! - Layer D: Origin & Referer Checks: External Origin/Referer rejected with 403 Forbidden
//! - Layer E: Unconditional Loopback Bind: OSOOSI_DASHBOARD_BIND_ALL is ignored and socket binds strictly to 127.0.0.1

use axum::http::{header, StatusCode};
use osoosi_dashboard::spawn_dashboard_with_backend;
use reqwest::Client;
use serde_json::Value;

#[tokio::test]
async fn test_m14_case1_remote_tcp_peer_blocked() {
    let port = spawn_dashboard_with_backend(0, None, None)
        .await
        .expect("Failed to spawn dashboard");
    let base_url = format!("http://127.0.0.1:{}", port);
    let client = Client::new();

    let remote_ips = ["192.168.1.100", "10.0.0.50", "172.16.0.1", "8.8.8.8"];
    for remote_ip in remote_ips {
        let resp = client
            .get(format!("{}/health", base_url))
            .header("x-test-client-ip", remote_ip)
            .send()
            .await
            .unwrap_or_else(|e| panic!("Failed request: {}", e));

        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "Remote peer IP {} must be rejected with 403 Forbidden",
            remote_ip
        );

        let body: Value = resp.json().await.unwrap();
        assert_eq!(
            body["error_code"], "REMOTE_HOST_ACCESS_FORBIDDEN",
            "Error code must be REMOTE_HOST_ACCESS_FORBIDDEN for remote peer IP {}",
            remote_ip
        );
    }
}

#[tokio::test]
async fn test_m14_case2_local_loopback_allowed() {
    let port = spawn_dashboard_with_backend(0, None, None)
        .await
        .expect("Failed to spawn dashboard");
    let base_url = format!("http://127.0.0.1:{}", port);
    let client = Client::new();

    let loopback_ips = ["127.0.0.1", "127.0.0.2", "127.255.255.254", "::1"];
    for loopback_ip in loopback_ips {
        let resp = client
            .get(format!("{}/health", base_url))
            .header("x-test-client-ip", loopback_ip)
            .send()
            .await
            .unwrap_or_else(|e| panic!("Failed request: {}", e));

        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "Loopback IP {} must be permitted with 200 OK",
            loopback_ip
        );
        let body: Value = resp.json().await.unwrap();
        assert_eq!(body["ok"], true);
    }
}

#[tokio::test]
async fn test_m14_case3_non_loopback_host_blocked_dns_rebinding() {
    let port = spawn_dashboard_with_backend(0, None, None)
        .await
        .expect("Failed to spawn dashboard");
    let base_url = format!("http://127.0.0.1:{}", port);
    let client = Client::new();

    let forbidden_hosts = [
        "evil.com",
        "evil.com:3030",
        "192.168.1.1",
        "192.168.1.1:3030",
        "attacker.internal:80",
        "localhost.evil.com",
    ];

    for host in forbidden_hosts {
        let resp = client
            .get(format!("{}/health", base_url))
            .header(header::HOST, host)
            .header("x-test-client-ip", "127.0.0.1")
            .send()
            .await
            .unwrap_or_else(|e| panic!("Failed request with host {}: {}", host, e));

        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "Non-loopback Host header {} must be rejected with 403 Forbidden",
            host
        );

        let body: Value = resp.json().await.unwrap();
        assert_eq!(
            body["error_code"], "NON_LOOPBACK_HOST_FORBIDDEN",
            "Error code must be NON_LOOPBACK_HOST_FORBIDDEN for host {}",
            host
        );
    }
}

#[tokio::test]
async fn test_m14_case4_reverse_proxy_headers_rejected() {
    let port = spawn_dashboard_with_backend(0, None, None)
        .await
        .expect("Failed to spawn dashboard");
    let base_url = format!("http://127.0.0.1:{}", port);
    let client = Client::new();

    let proxy_tests: Vec<(&str, &str)> = vec![
        ("x-forwarded-for", "198.51.100.1, 127.0.0.1"),
        ("x-forwarded-for", "10.0.0.1"),
        ("x-real-ip", "192.168.1.25"),
        ("cf-connecting-ip", "203.0.113.195"),
        ("true-client-ip", "198.51.100.5"),
        ("forwarded", "for=192.0.2.60;proto=http"),
        ("x-forwarded-host", "proxy.evil.com"),
    ];

    for (header_name, header_val) in proxy_tests {
        let resp = client
            .get(format!("{}/health", base_url))
            .header(header_name, header_val)
            .header("x-test-client-ip", "127.0.0.1")
            .send()
            .await
            .unwrap_or_else(|e| panic!("Failed request with proxy header {}: {}", header_name, e));

        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "Proxy header {}: {} must be rejected with 403 Forbidden",
            header_name,
            header_val
        );

        let body: Value = resp.json().await.unwrap();
        assert_eq!(
            body["error_code"], "REMOTE_PROXY_ACCESS_FORBIDDEN",
            "Error code must be REMOTE_PROXY_ACCESS_FORBIDDEN for {}: {}",
            header_name, header_val
        );
    }
}

#[tokio::test]
async fn test_m14_case5_external_origin_and_referer_blocked() {
    let port = spawn_dashboard_with_backend(0, None, None)
        .await
        .expect("Failed to spawn dashboard");
    let base_url = format!("http://127.0.0.1:{}", port);
    let client = Client::new();

    // 1. External Origin
    let bad_origins = [
        "http://evil.com",
        "https://attacker.org",
        "http://192.168.1.1:3030",
        "http://127.0.0.1.attacker.com",
    ];
    for origin in bad_origins {
        let resp = client
            .get(format!("{}/health", base_url))
            .header(header::ORIGIN, origin)
            .header("x-test-client-ip", "127.0.0.1")
            .send()
            .await
            .unwrap_or_else(|e| panic!("Failed request with Origin {}: {}", origin, e));

        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "External origin {} must be rejected with 403 Forbidden",
            origin
        );
        let body: Value = resp.json().await.unwrap();
        assert_eq!(body["error_code"], "CSRF_ORIGIN_MISMATCH");
    }

    // 2. External Referer
    let bad_referers = [
        "http://evil.com/exploit",
        "https://attacker.org/phish",
        "http://192.168.1.1/admin",
    ];
    for referer in bad_referers {
        let resp = client
            .get(format!("{}/health", base_url))
            .header(header::REFERER, referer)
            .header("x-test-client-ip", "127.0.0.1")
            .send()
            .await
            .unwrap_or_else(|e| panic!("Failed request with Referer {}: {}", referer, e));

        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "External referer {} must be rejected with 403 Forbidden",
            referer
        );
        let body: Value = resp.json().await.unwrap();
        assert_eq!(body["error_code"], "REMOTE_REFERER_FORBIDDEN");
    }
}

#[tokio::test]
async fn test_m14_case6_bind_all_env_ignored_unconditional_loopback_bind() {
    // Set OSOOSI_DASHBOARD_BIND_ALL to 1
    std::env::set_var("OSOOSI_DASHBOARD_BIND_ALL", "1");

    let bound_port = spawn_dashboard_with_backend(0, None, None)
        .await
        .expect("Failed to spawn dashboard even when OSOOSI_DASHBOARD_BIND_ALL=1");

    // Clean up env
    std::env::remove_var("OSOOSI_DASHBOARD_BIND_ALL");

    // Verify it bound on 127.0.0.1 loopback
    let local_addr = format!("http://127.0.0.1:{}/health", bound_port);
    let client = Client::new();
    let resp = client
        .get(&local_addr)
        .header("x-test-client-ip", "127.0.0.1")
        .send()
        .await
        .expect("Must connect successfully via 127.0.0.1");

    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["ok"], true);
}
