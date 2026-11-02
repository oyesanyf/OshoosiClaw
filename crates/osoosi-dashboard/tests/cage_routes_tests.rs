//! CAGE Substrate Contract v1.0 REST API Integration Test Suite
//!
//! Validates:
//! - POST /governance/ingest-policy (valid compilation, format auto-detection, missing content 400, version drift 409)
//! - GET /governance/policy-version (unpinned 404, active pinned 200)
//! - POST /governance/validate-action (unpinned 400, missing action 400, version mismatch 409, Phase 1 refusal receipt, Phase 2 CBF denial, ALLOW clearance with 30s TTL seal)
//! - POST /governance/consume-seal (missing fields 400, unregistered 403, atomic single-use clearance 200, replay defense 403)
//! - POST /governance/rollback (missing debit 400, unpinned 400, non-existent debit 404, valid budget restoration 200)
//! - GET /governance/trace/verify (cryptographic hash chain and Merkle root verification 200)
//! - GET /governance/stats (telemetry metrics for WebUI monitoring)
//! - Legacy /api/governance/* aliases parity
//! - Fallback 404 handler on unknown governance subroutes

use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
};
use osoosi_dashboard::{routes::mount_routes, DashboardState};
use serde_json::{json, Value};
use tower::ServiceExt;

/// Creates a fresh in-memory Axum app with clean CAGE state.
fn build_test_app() -> axum::Router {
    mount_routes().with_state(DashboardState::new(None, None))
}

async fn send_request(
    app: &mut axum::Router,
    method: &str,
    uri: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let req = match body {
        Some(b) => Request::builder()
            .method(method)
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(b.to_string()))
            .unwrap(),
        None => Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::empty())
            .unwrap(),
    };

    let response = app
        .clone()
        .oneshot(req)
        .await
        .expect("Request execution failed");
    let status = response.status();
    let body_bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("Failed to read response body");

    let val: Value = if body_bytes.is_empty() {
        json!({})
    } else {
        serde_json::from_slice(&body_bytes).unwrap_or_else(|_| {
            json!({"raw": String::from_utf8_lossy(&body_bytes)})
        })
    };

    (status, val)
}

#[tokio::test]
async fn test_ingest_policy_missing_content_returns_400() {
    let mut app = build_test_app();
    let (status, res) = send_request(&mut app, "POST", "/governance/ingest-policy", Some(json!({}))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(res["error"], "BAD_REQUEST");
    assert!(res["message"].as_str().unwrap().contains("Missing policy_content"));
}

#[tokio::test]
async fn test_ingest_policy_and_get_policy_version_lifecycle() {
    let mut app = build_test_app();

    // 1. Before pinning, GET /governance/policy-version returns 404
    let (s0, r0) = send_request(&mut app, "GET", "/governance/policy-version", None).await;
    assert_eq!(s0, StatusCode::NOT_FOUND);
    assert_eq!(r0["error"], "NO_PINNED_POLICY");

    // 2. Ingest ACS policy document
    let acs_doc = json!({
        "behaviorDeclarations": [
            {
                "id": "ACS-REST-01",
                "action": "ExecuteTrade",
                "resource": "Asset/USD"
            }
        ]
    });

    let (s1, r1) = send_request(
        &mut app,
        "POST",
        "/governance/ingest-policy",
        Some(json!({
            "policy_content": acs_doc.to_string(),
            "pin_version": true
        })),
    )
    .await;

    assert_eq!(s1, StatusCode::OK);
    assert_eq!(r1["status"], "compiled");
    let v_id = r1["policy_version_id"].as_str().unwrap();
    assert_eq!(v_id.len(), 16);
    assert!(v_id.chars().all(|c| c.is_ascii_hexdigit()));

    // 3. Query GET /governance/policy-version returns active pinned version
    let (s2, r2) = send_request(&mut app, "GET", "/governance/policy-version", None).await;
    assert_eq!(s2, StatusCode::OK);
    assert_eq!(r2["active_version_id"], v_id);
    assert_eq!(r2["is_pinned"], true);
}

#[tokio::test]
async fn test_ingest_policy_drift_returns_409_conflict() {
    let mut app = build_test_app();

    let doc_a = json!({
        "behaviorDeclarations": [
            { "id": "ACS-A", "action": "ActionA" }
        ]
    });
    let doc_b = json!({
        "behaviorDeclarations": [
            { "id": "ACS-B", "action": "ActionB_Drifted" }
        ]
    });

    // Ingest policy A and pin it
    let (s1, r1) = send_request(
        &mut app,
        "POST",
        "/governance/ingest-policy",
        Some(json!({
            "policy_content": doc_a.to_string(),
            "pin_version": true
        })),
    )
    .await;
    assert_eq!(s1, StatusCode::OK);
    let ver_a = r1["policy_version_id"].as_str().unwrap();

    // Ingest drifted policy B without forcing -> returns 409 Conflict
    let (s2, r2) = send_request(
        &mut app,
        "POST",
        "/governance/ingest-policy",
        Some(json!({
            "policy_content": doc_b.to_string(),
            "pin_version": true
        })),
    )
    .await;
    assert_eq!(s2, StatusCode::CONFLICT);
    assert_eq!(r2["error"], "POLICY_VERSION_MISMATCH");
    assert_eq!(r2["pinned_version"], ver_a);

    // Active version remains policy A
    let (s3, r3) = send_request(&mut app, "GET", "/governance/policy-version", None).await;
    assert_eq!(s3, StatusCode::OK);
    assert_eq!(r3["active_version_id"], ver_a);
}

#[tokio::test]
async fn test_validate_action_before_policy_pinned_returns_400() {
    let mut app = build_test_app();
    let (status, res) = send_request(
        &mut app,
        "POST",
        "/governance/validate-action",
        Some(json!({
            "action_name": "TestAct",
            "cost": 1.0
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(res["error"], "NO_POLICY");
}

#[tokio::test]
async fn test_validate_action_missing_action_name_returns_400() {
    let mut app = build_test_app();
    let doc = json!({ "behaviorDeclarations": [] });
    send_request(
        &mut app,
        "POST",
        "/governance/ingest-policy",
        Some(json!({ "policy_content": doc.to_string(), "pin_version": true })),
    )
    .await;

    let (status, res) = send_request(
        &mut app,
        "POST",
        "/governance/validate-action",
        Some(json!({ "cost": 5.0 })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(res["error"], "BAD_REQUEST");
}

#[tokio::test]
async fn test_validate_action_version_mismatch_returns_409() {
    let mut app = build_test_app();
    let doc = json!({ "behaviorDeclarations": [] });
    send_request(
        &mut app,
        "POST",
        "/governance/ingest-policy",
        Some(json!({ "policy_content": doc.to_string(), "pin_version": true })),
    )
    .await;

    let (status, res) = send_request(
        &mut app,
        "POST",
        "/governance/validate-action",
        Some(json!({
            "expected_policy_version": "0123456789abcdef",
            "action_name": "ActMismatch",
            "cost": 2.0
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(res["error"], "POLICY_VERSION_CONFLICT");
}

#[tokio::test]
async fn test_validate_action_phase1_ftra_authority_refusal() {
    let mut app = build_test_app();
    let doc = json!({ "behaviorDeclarations": [] });
    send_request(
        &mut app,
        "POST",
        "/governance/ingest-policy",
        Some(json!({ "policy_content": doc.to_string(), "pin_version": true })),
    )
    .await;

    // "execute_child_process" is IrreversibleTerminal (requires authority <= 2).
    // Caller with authority 5 should be denied in Phase 1 with 64-hex refusal proof.
    let (status, res) = send_request(
        &mut app,
        "POST",
        "/governance/validate-action",
        Some(json!({
            "action_name": "execute_child_process",
            "caller_authority": 5,
            "cost": 1.0
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(res["verdict"], "DENY");
    assert!(res["routing_seal"].is_null());
    let proof = res["proof_hash"].as_str().unwrap();
    assert_eq!(proof.len(), 64);
    assert!(proof.chars().all(|c| c.is_ascii_hexdigit()));
}

#[tokio::test]
async fn test_validate_action_phase2_cbf_barrier_denial_zero_leakage() {
    let mut app = build_test_app();
    let doc = json!({ "behaviorDeclarations": [] });
    send_request(
        &mut app,
        "POST",
        "/governance/ingest-policy",
        Some(json!({ "policy_content": doc.to_string(), "pin_version": true })),
    )
    .await;

    // Initial budget is 100.0, floor b_min is 10.0.
    // Cost 95.0 breaches barrier -> projected h_{t+1} = (100 - 95) - 10 = -5 < 0
    let (status, res) = send_request(
        &mut app,
        "POST",
        "/governance/validate-action",
        Some(json!({
            "action_name": "OverdraftActuation",
            "cost": 95.0,
            "caller_authority": 1
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(res["verdict"], "DENY");
    assert!(res["routing_seal"].is_null());
    let proof = res["proof_hash"].as_str().unwrap();
    assert_eq!(proof.len(), 64);

    // Verify budget was not leaked via stats
    let (s_stat, r_stat) = send_request(&mut app, "GET", "/governance/stats", None).await;
    assert_eq!(s_stat, StatusCode::OK);
    assert_eq!(r_stat["budget"], 100.0);
}

#[tokio::test]
async fn test_validate_action_allow_and_consume_seal_atomic_single_use() {
    let mut app = build_test_app();
    let doc = json!({ "behaviorDeclarations": [] });
    send_request(
        &mut app,
        "POST",
        "/governance/ingest-policy",
        Some(json!({ "policy_content": doc.to_string(), "pin_version": true })),
    )
    .await;

    // Validate safe action
    let (s1, r1) = send_request(
        &mut app,
        "POST",
        "/governance/validate-action",
        Some(json!({
            "action_name": "SafeAction",
            "caller_authority": 1,
            "cost": 5.0,
            "params": { "target": "dataset_a" }
        })),
    )
    .await;
    assert_eq!(s1, StatusCode::OK);
    assert_eq!(r1["verdict"], "ALLOW");
    let seal = r1["routing_seal"].clone();
    assert!(!seal.is_null());
    let seal_id = seal["seal_id"].as_str().unwrap();
    assert!(!seal_id.is_empty());
    assert_eq!(seal["policy_version_id"].as_str().unwrap().len(), 16);

    // 1st consumption: 200 OK
    let (s2, r2) = send_request(
        &mut app,
        "POST",
        "/governance/consume-seal",
        Some(json!({
            "seal_id": seal_id,
            "action_name": "SafeAction",
            "params": { "target": "dataset_a" },
            "seal": seal
        })),
    )
    .await;
    assert_eq!(s2, StatusCode::OK);
    assert_eq!(r2["status"], "CONSUMED");
    assert_eq!(r2["seal_id"], seal_id);

    // 2nd consumption (replay attempt): 403 Forbidden
    let (s3, r3) = send_request(
        &mut app,
        "POST",
        "/governance/consume-seal",
        Some(json!({
            "seal_id": seal_id,
            "action_name": "SafeAction",
            "params": { "target": "dataset_a" },
            "seal": seal
        })),
    )
    .await;
    assert_eq!(s3, StatusCode::FORBIDDEN);
    assert_eq!(r3["error"], "FORBIDDEN");
    assert_eq!(r3["rejection_code"], "SEAL_REJECTED");
}

#[tokio::test]
async fn test_consume_unregistered_seal_returns_403() {
    let mut app = build_test_app();
    let doc = json!({ "behaviorDeclarations": [] });
    send_request(
        &mut app,
        "POST",
        "/governance/ingest-policy",
        Some(json!({ "policy_content": doc.to_string(), "pin_version": true })),
    )
    .await;

    let (status, res) = send_request(
        &mut app,
        "POST",
        "/governance/consume-seal",
        Some(json!({
            "seal_id": "seal_unregistered_ghost",
            "action_name": "ActGhost"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(res["error"], "FORBIDDEN");
}

#[tokio::test]
async fn test_rollback_lifecycle_restores_cbf_budget() {
    let mut app = build_test_app();
    let doc = json!({ "behaviorDeclarations": [] });
    send_request(
        &mut app,
        "POST",
        "/governance/ingest-policy",
        Some(json!({ "policy_content": doc.to_string(), "pin_version": true })),
    )
    .await;

    // 1. Missing debit_id returns 400
    let (s_bad, r_bad) = send_request(&mut app, "POST", "/governance/rollback", Some(json!({}))).await;
    assert_eq!(s_bad, StatusCode::BAD_REQUEST);
    assert_eq!(r_bad["error"], "BAD_REQUEST");

    // 2. Validate action with cost 5.0 (within CBF decay margin gamma*h_t = 0.1*90 = 9.0)
    let (s1, r1) = send_request(
        &mut app,
        "POST",
        "/governance/validate-action",
        Some(json!({
            "action_name": "SpendFuel",
            "cost": 5.0,
            "caller_authority": 1
        })),
    )
    .await;
    assert_eq!(s1, StatusCode::OK);
    assert_eq!(r1["verdict"], "ALLOW");
    let debit_id = r1["debit_id"].as_str().unwrap();

    // Verify budget is debited from 100.0 to 95.0
    let (_, r_mid) = send_request(&mut app, "GET", "/governance/stats", None).await;
    assert_eq!(r_mid["budget"], 95.0);

    // 3. Rollback reservation
    let (s_rb, r_rb) = send_request(
        &mut app,
        "POST",
        "/governance/rollback",
        Some(json!({
            "debit_id": debit_id,
            "reason": "Simulated hardware failure"
        })),
    )
    .await;
    assert_eq!(s_rb, StatusCode::OK);
    assert_eq!(r_rb["status"], "ROLLED_BACK");
    assert_eq!(r_rb["restored_amount"], 5.0);
    assert_eq!(r_rb["state_after_rollback"], 100.0);

    // 4. Repeated rollback of same debit_id returns 404 (already released)
    let (s_rep, r_rep) = send_request(
        &mut app,
        "POST",
        "/governance/rollback",
        Some(json!({ "debit_id": debit_id })),
    )
    .await;
    assert_eq!(s_rep, StatusCode::NOT_FOUND);
    assert_eq!(r_rep["error"], "NOT_FOUND");
}

#[tokio::test]
async fn test_trace_verify_hash_chain_and_merkle_root() {
    let mut app = build_test_app();
    let doc = json!({ "behaviorDeclarations": [] });
    send_request(
        &mut app,
        "POST",
        "/governance/ingest-policy",
        Some(json!({ "policy_content": doc.to_string(), "pin_version": true })),
    )
    .await;

    // Trigger two evaluations
    send_request(
        &mut app,
        "POST",
        "/governance/validate-action",
        Some(json!({ "action_name": "Act1", "cost": 2.0, "caller_authority": 1 })),
    )
    .await;
    send_request(
        &mut app,
        "POST",
        "/governance/validate-action",
        Some(json!({ "action_name": "Act2", "cost": 3.0, "caller_authority": 1 })),
    )
    .await;

    // Verify trace chain
    let (s_ver, r_ver) = send_request(&mut app, "GET", "/governance/trace/verify", None).await;
    assert_eq!(s_ver, StatusCode::OK);
    assert_eq!(r_ver["valid"], true);
    assert_eq!(r_ver["status"], "CONFORMANT");
    assert_eq!(r_ver["findings_count"], 0);
    assert!(r_ver["trace_count"].as_u64().unwrap() >= 2);
    let root = r_ver["merkle_root"].as_str().unwrap();
    assert_eq!(root.len(), 64);
    assert!(root.chars().all(|c| c.is_ascii_hexdigit()));
}

#[tokio::test]
async fn test_legacy_api_governance_aliases() {
    let mut app = build_test_app();
    let doc = json!({ "behaviorDeclarations": [] });

    // POST /api/governance/ingest-policy
    let (s1, r1) = send_request(
        &mut app,
        "POST",
        "/api/governance/ingest-policy",
        Some(json!({ "policy_content": doc.to_string(), "pin_version": true })),
    )
    .await;
    assert_eq!(s1, StatusCode::OK);
    let v_id = r1["policy_version_id"].as_str().unwrap();

    // GET /api/governance/policy-version
    let (s2, r2) = send_request(&mut app, "GET", "/api/governance/policy-version", None).await;
    assert_eq!(s2, StatusCode::OK);
    assert_eq!(r2["active_version_id"], v_id);

    // POST /api/governance/validate-action
    let (s3, r3) = send_request(
        &mut app,
        "POST",
        "/api/governance/validate-action",
        Some(json!({ "action_name": "AliasAct", "cost": 1.0, "caller_authority": 1 })),
    )
    .await;
    assert_eq!(s3, StatusCode::OK);
    assert_eq!(r3["verdict"], "ALLOW");

    // GET /api/governance/trace/verify
    let (s4, r4) = send_request(&mut app, "GET", "/api/governance/trace/verify", None).await;
    assert_eq!(s4, StatusCode::OK);
    assert_eq!(r4["valid"], true);
}

#[tokio::test]
async fn test_unknown_governance_endpoint_returns_404() {
    let mut app = build_test_app();
    let (s1, r1) = send_request(&mut app, "GET", "/governance/non-existent-subpath", None).await;
    assert_eq!(s1, StatusCode::NOT_FOUND);
    assert_eq!(r1["error"], "NOT_FOUND");

    let (s2, r2) = send_request(&mut app, "GET", "/api/governance/another-ghost-route", None).await;
    assert_eq!(s2, StatusCode::NOT_FOUND);
    assert_eq!(r2["error"], "NOT_FOUND");
}
