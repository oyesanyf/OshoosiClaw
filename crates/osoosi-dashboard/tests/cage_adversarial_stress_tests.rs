//! Empirical Adversarial Stress Test Suite for CAGE Substrate Contract REST API
//! (`crates/osoosi-dashboard/src/routes/cage.rs`)
//!
//! Validates:
//! 1. Malformed JSON payloads, unknown fields, and truncated bodies across all 7 endpoints
//!    return clean 400 Bad Request or 422 Unprocessable without crashing/panicking the Axum router.
//! 2. Concurrent race stress: multi-threaded simultaneous requests attempting to consume
//!    the same routing seal concurrently (assert exactly 1 succeeds with 200 and all others fail with 403 Forbidden).
//! 3. Budget boundary stress: flood `/governance/validate-action` with actions whose fuel expenditure
//!    exceeds the CBF decay bound gamma * h_t, asserting CBF barrier denial and zero fiscal leakage.
//! 4. Rollback idempotency and out-of-order stress: test double rollback, nonexistent reservation rollback,
//!    and interleaving validate/rollback cycles.
//! 5. Legacy `/api/governance/*` alias stress under concurrent calls.

use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
    Router,
};
use osoosi_dashboard::{routes::mount_routes, DashboardState};
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::sync::Barrier;
use tower::ServiceExt;

/// Creates a fresh in-memory Axum app with clean CAGE state.
fn build_test_app() -> Router {
    mount_routes().with_state(DashboardState::new(None, None))
}

/// Helper: sends a request with raw byte content and optional Content-Type header.
async fn send_raw(
    app: &Router,
    method: &str,
    uri: &str,
    content_type: Option<&str>,
    body_bytes: Vec<u8>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(ct) = content_type {
        builder = builder.header(header::CONTENT_TYPE, ct);
    }
    let req = builder
        .body(Body::from(body_bytes))
        .expect("Failed to build request");

    let response = app
        .clone()
        .oneshot(req)
        .await
        .expect("Request execution failed");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("Failed to read response body");

    let val: Value = if bytes.is_empty() {
        json!({})
    } else {
        serde_json::from_slice(&bytes).unwrap_or_else(|_| {
            json!({"raw": String::from_utf8_lossy(&bytes)})
        })
    };

    (status, val)
}

/// Helper: sends a request with a JSON payload.
async fn send_json(
    app: &Router,
    method: &str,
    uri: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    match body {
        Some(b) => {
            send_raw(
                app,
                method,
                uri,
                Some("application/json"),
                b.to_string().into_bytes(),
            )
            .await
        }
        None => send_raw(app, method, uri, None, Vec::new()).await,
    }
}

/// Helper: inits and pins a minimal valid policy.
async fn init_and_pin_policy(app: &Router) -> String {
    let doc = json!({
        "behaviorDeclarations": [
            {
                "id": "ACS-STRESS-01",
                "action": "SafeAction",
                "resource": "Dataset/SecOps"
            }
        ]
    });

    let (status, res) = send_json(
        app,
        "POST",
        "/governance/ingest-policy",
        Some(json!({
            "policy_content": doc.to_string(),
            "pin_version": true
        })),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "Policy ingestion failed: {:?}", res);
    let v_id = res["policy_version_id"]
        .as_str()
        .expect("Missing policy_version_id")
        .to_string();
    assert_eq!(v_id.len(), 16);
    v_id
}

// =========================================================================
// 1. Malformed JSON, Unknown Fields, and Truncated Bodies Stress
// =========================================================================

#[tokio::test]
async fn test_malformed_json_and_truncated_payloads_across_all_endpoints() {
    let app = build_test_app();
    let _policy_id = init_and_pin_policy(&app).await;

    // Test cases for POST endpoints: (name, path, raw_body, content_type)
    let post_malformed_cases: Vec<(&str, &str, Vec<u8>)> = vec![
        // Truncated bodies
        (
            "ingest_truncated",
            "/governance/ingest-policy",
            b"{\"policy_content\": \"some text that is not closed".to_vec(),
        ),
        (
            "validate_truncated",
            "/governance/validate-action",
            b"{\"action_name\": \"SafeAction\", \"params\": {\"foo\":".to_vec(),
        ),
        (
            "consume_truncated",
            "/governance/consume-seal",
            b"{\"seal_id\": \"seal_".to_vec(),
        ),
        (
            "rollback_truncated",
            "/governance/rollback",
            b"{\"debit_id\": \"deb".to_vec(),
        ),
        // Broken JSON syntax
        (
            "ingest_bad_syntax",
            "/governance/ingest-policy",
            b"{ unquoted_key: 1234 }".to_vec(),
        ),
        (
            "validate_bad_syntax",
            "/governance/validate-action",
            b"{\"action_name\": \"foo\", \"cost\": [}}}".to_vec(),
        ),
        (
            "consume_bad_syntax",
            "/governance/consume-seal",
            b"{\"seal_id\": ,,,}".to_vec(),
        ),
        (
            "rollback_bad_syntax",
            "/governance/rollback",
            b"{\"debit_id\": null, }".to_vec(),
        ),
        // Type mismatches (e.g. number for string, string for number, array for object)
        (
            "ingest_type_mismatch_num",
            "/governance/ingest-policy",
            b"{\"policy_content\": 123456}".to_vec(),
        ),
        (
            "validate_type_mismatch_auth",
            "/governance/validate-action",
            b"{\"action_name\": \"SafeAction\", \"caller_authority\": \"superadmin\"}".to_vec(),
        ),
        (
            "validate_type_mismatch_cost",
            "/governance/validate-action",
            b"{\"action_name\": \"SafeAction\", \"cost\": \"free\"}".to_vec(),
        ),
        (
            "validate_type_mismatch_name",
            "/governance/validate-action",
            b"{\"action_name\": true}".to_vec(),
        ),
        (
            "consume_type_mismatch_seal",
            "/governance/consume-seal",
            b"{\"seal_id\": \"s1\", \"seal\": \"not_a_seal_object\"}".to_vec(),
        ),
        (
            "rollback_type_mismatch_debit",
            "/governance/rollback",
            b"{\"debit_id\": 98765}".to_vec(),
        ),
        (
            "rollback_type_mismatch_reason",
            "/governance/rollback",
            b"{\"debit_id\": \"d1\", \"reason\": [1, 2, 3]}".to_vec(),
        ),
        // Top-level JSON array with incompatible element types
        (
            "ingest_array_root",
            "/governance/ingest-policy",
            b"[1, 2, 3]".to_vec(),
        ),
        (
            "validate_array_root",
            "/governance/validate-action",
            b"[1, 2, 3]".to_vec(),
        ),
        (
            "consume_array_root",
            "/governance/consume-seal",
            b"[{\"seal_id\": \"s1\"}]".to_vec(),
        ),
        (
            "rollback_array_root",
            "/governance/rollback",
            b"[12345]".to_vec(),
        ),
        // Empty body with application/json
        (
            "ingest_empty_body",
            "/governance/ingest-policy",
            Vec::new(),
        ),
        (
            "validate_empty_body",
            "/governance/validate-action",
            Vec::new(),
        ),
        (
            "consume_empty_body",
            "/governance/consume-seal",
            Vec::new(),
        ),
        (
            "rollback_empty_body",
            "/governance/rollback",
            Vec::new(),
        ),
        // Garbage non-utf8 / binary bytes
        (
            "validate_garbage_binary",
            "/governance/validate-action",
            vec![0xFF, 0xFE, 0x00, 0x01, 0x80, 0x90],
        ),
        // Legacy /api/governance/* aliases with malformed payload
        (
            "alias_ingest_malformed",
            "/api/governance/ingest-policy",
            b"{ malformed json".to_vec(),
        ),
        (
            "alias_validate_malformed",
            "/api/governance/validate-action",
            b"{\"action_name\": 42}".to_vec(),
        ),
        (
            "alias_consume_malformed",
            "/api/governance/consume-seal",
            b"{\"seal_id\": {}}".to_vec(),
        ),
        (
            "alias_rollback_malformed",
            "/api/governance/rollback",
            b"{\"debit_id\": [true]}".to_vec(),
        ),
    ];

    for (name, path, payload) in post_malformed_cases {
        let (status, res) = send_raw(&app, "POST", path, Some("application/json"), payload).await;
        // Axum's Json extractor returns 400 Bad Request or 422 Unprocessable Entity
        assert!(
            status == StatusCode::BAD_REQUEST || status == StatusCode::UNPROCESSABLE_ENTITY,
            "Endpoint '{}' on case '{}' returned unexpected status {:?}: {:?}",
            path,
            name,
            status,
            res
        );
        // Assert router never panics and never returns 500
        assert_ne!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    // Test unknown / extra fields in payloads: they must be safely deserialized without panic
    let (s_unk1, r_unk1) = send_json(
        &app,
        "POST",
        "/governance/validate-action",
        Some(json!({
            "action_name": "SafeAction",
            "caller_authority": 1,
            "cost": 1.0,
            "unknown_extra_field_1": "arbitrary_attacker_value",
            "nested_unrecognized_struct": { "depth": [1, 2, 3], "flag": true }
        })),
    )
    .await;
    assert_eq!(s_unk1, StatusCode::OK);
    assert_eq!(r_unk1["verdict"], "ALLOW");

    let (s_unk2, r_unk2) = send_json(
        &app,
        "POST",
        "/governance/rollback",
        Some(json!({
            "debit_id": "nonexistent_debit_with_extra_fields",
            "reason": "Test unknown fields",
            "attacker_injected_metadata": 999999
        })),
    )
    .await;
    // Handled cleanly (returns 404 for nonexistent debit, no panic)
    assert_eq!(s_unk2, StatusCode::NOT_FOUND);
    assert_eq!(r_unk2["error"], "NOT_FOUND");

    // Test GET endpoints with unexpected bodies and ensure they respond cleanly
    let get_endpoints = vec![
        "/governance/policy-version",
        "/governance/trace/verify",
        "/governance/stats",
        "/api/governance/policy-version",
        "/api/governance/trace/verify",
        "/api/governance/stats",
    ];

    for path in get_endpoints {
        let (status, res) = send_raw(
            &app,
            "GET",
            path,
            Some("application/json"),
            b"{\"unexpected_get_body\": true}".to_vec(),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "GET endpoint '{}' failed on unexpected body: {:?}",
            path,
            res
        );
    }
}

// =========================================================================
// 2. Concurrent Race Stress: Multi-Threaded Seal Single-Use Replay Defense
// =========================================================================

#[tokio::test]
async fn test_concurrent_race_stress_single_use_seal() {
    let app = build_test_app();
    let _policy_id = init_and_pin_policy(&app).await;

    // Issue a valid routing seal via /governance/validate-action
    let params = json!({ "target_cluster": "prod-east", "nonce": "stress-nonce-99" });
    let (s_val, r_val) = send_json(
        &app,
        "POST",
        "/governance/validate-action",
        Some(json!({
            "action_name": "SafeAction",
            "caller_authority": 1,
            "cost": 2.0,
            "params": params
        })),
    )
    .await;

    assert_eq!(s_val, StatusCode::OK);
    assert_eq!(r_val["verdict"], "ALLOW");
    let seal = r_val["routing_seal"].clone();
    assert!(!seal.is_null());
    let seal_id = seal["seal_id"].as_str().unwrap().to_string();

    // Concurrently fire 25 simultaneous requests to consume the exact same seal
    let concurrency = 25;
    let barrier = Arc::new(Barrier::new(concurrency));
    let mut handles = Vec::with_capacity(concurrency);

    for task_idx in 0..concurrency {
        let app_clone = app.clone();
        let b = barrier.clone();
        let s_id = seal_id.clone();
        let s_obj = seal.clone();
        let p_obj = params.clone();

        let handle = tokio::spawn(async move {
            // Align all threads to hit the router simultaneously
            b.wait().await;

            let (status, res) = send_json(
                &app_clone,
                "POST",
                "/governance/consume-seal",
                Some(json!({
                    "seal_id": s_id,
                    "action_name": "SafeAction",
                    "params": p_obj,
                    "seal": s_obj,
                    "task_worker": task_idx
                })),
            )
            .await;

            (status, res)
        });

        handles.push(handle);
    }

    let mut ok_count = 0;
    let mut forbidden_count = 0;
    let mut other_count = 0;

    for h in handles {
        let (status, res) = h.await.expect("Task join failed");
        match status {
            StatusCode::OK => {
                ok_count += 1;
                assert_eq!(res["status"], "CONSUMED");
                assert_eq!(res["seal_id"], seal_id);
            }
            StatusCode::FORBIDDEN => {
                forbidden_count += 1;
                assert_eq!(res["error"], "FORBIDDEN");
                assert_eq!(res["rejection_code"], "SEAL_REJECTED");
            }
            other => {
                other_count += 1;
                eprintln!("Unexpected status {:?}: {:?}", other, res);
            }
        }
    }

    // Critical Invariant: Exactly 1 request succeeds (200 OK), all 24 others fail (403 Forbidden)
    assert_eq!(
        ok_count, 1,
        "Expected exactly 1 successful seal consumption, got {}",
        ok_count
    );
    assert_eq!(
        forbidden_count,
        concurrency - 1,
        "Expected {} 403 Forbidden responses, got {}",
        concurrency - 1,
        forbidden_count
    );
    assert_eq!(other_count, 0, "No unexpected status codes allowed");

    // Subsequent sequential replay must also fail with 403 Forbidden
    let (s_seq, r_seq) = send_json(
        &app,
        "POST",
        "/governance/consume-seal",
        Some(json!({
            "seal_id": seal_id,
            "action_name": "SafeAction",
            "params": params,
            "seal": seal
        })),
    )
    .await;
    assert_eq!(s_seq, StatusCode::FORBIDDEN);
    assert_eq!(r_seq["rejection_code"], "SEAL_REJECTED");

    // Verify stats record exactly 1 consumed seal
    let (s_stat, r_stat) = send_json(&app, "GET", "/governance/stats", None).await;
    assert_eq!(s_stat, StatusCode::OK);
    assert_eq!(r_stat["consumed_seals"], 1);
}

// =========================================================================
// 3. Budget Boundary Stress: CBF Decay Flooding & Zero Fiscal Leakage
// =========================================================================

#[tokio::test]
async fn test_cbf_budget_decay_boundary_stress_and_zero_leakage() {
    let app = build_test_app();
    let _policy_id = init_and_pin_policy(&app).await;

    // Default policy CBF: Initial budget B_0 = 100.0, floor B_min = 10.0, gamma = 0.1
    // Safety margin h_0 = 100.0 - 10.0 = 90.0
    // Maximum allowable single-step expenditure: gamma * h_0 = 0.1 * 90.0 = 9.0
    // Any cost > 9.0 breaches the discrete-time exponential CBF decay bound!

    // Verify initial budget
    let (s_init, r_init) = send_json(&app, "GET", "/governance/stats", None).await;
    assert_eq!(s_init, StatusCode::OK);
    assert_eq!(r_init["budget"], 100.0);
    assert_eq!(r_init["cbf_barrier_val"], 90.0);

    // Flood with a mix of borderline-exceeding and catastrophic overdraft costs
    let violating_costs = vec![
        9.001,   // Epsilon above gamma * h_t
        9.05,    // Just above bound
        9.1,     // Decay breach
        10.0,    // Clear decay breach
        15.0,    // Medium decay breach
        25.0,    // Large decay breach
        50.0,    // Half budget
        89.0,    // Near total barrier
        90.0,    // Exact barrier margin
        91.0,    // Floor breach: (100 - 91) = 9 < 10
        100.0,   // Total balance
        150.0,   // Complete deficit
        1000.0,  // Massive overdraft
        10000.0, // Absurd overdraft
    ];

    // 1. Sequential flood
    for &cost in &violating_costs {
        let (status, res) = send_json(
            &app,
            "POST",
            "/governance/validate-action",
            Some(json!({
                "action_name": "SafeAction",
                "caller_authority": 1,
                "cost": cost
            })),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(res["verdict"], "DENY", "Cost {} should have been denied", cost);
        assert!(res["routing_seal"].is_null(), "No seal should be issued on denial");
        assert!(res["debit_id"].is_null(), "No debit_id should be issued on denial");
        assert_eq!(res["barrier_state"]["barrier_satisfied"], false);

        // Verify refusal proof receipt is 64-character hex
        let proof = res["proof_hash"].as_str().expect("Missing proof_hash");
        assert_eq!(proof.len(), 64);
        assert!(proof.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // Assert zero fiscal leakage after sequential flood
    let (s_post_seq, r_post_seq) = send_json(&app, "GET", "/governance/stats", None).await;
    assert_eq!(s_post_seq, StatusCode::OK);
    assert_eq!(r_post_seq["budget"], 100.0, "Fiscal leakage detected after sequential flood!");
    assert_eq!(r_post_seq["cbf_barrier_val"], 90.0);

    // 2. Concurrent flood: 30 simultaneous overdraft requests
    let concurrent_flooders = 30;
    let barrier = Arc::new(Barrier::new(concurrent_flooders));
    let mut handles = Vec::with_capacity(concurrent_flooders);

    for idx in 0..concurrent_flooders {
        let app_clone = app.clone();
        let b = barrier.clone();
        let cost = 15.0 + (idx as f64 * 3.5); // All strictly > 9.0

        let handle = tokio::spawn(async move {
            b.wait().await;
            let (status, res) = send_json(
                &app_clone,
                "POST",
                "/governance/validate-action",
                Some(json!({
                    "action_name": "SafeAction",
                    "caller_authority": 1,
                    "cost": cost
                })),
            )
            .await;
            (status, res)
        });

        handles.push(handle);
    }

    for h in handles {
        let (status, res) = h.await.expect("Task join failed");
        assert_eq!(status, StatusCode::OK);
        assert_eq!(res["verdict"], "DENY");
        assert!(res["routing_seal"].is_null());
        assert_eq!(res["barrier_state"]["barrier_satisfied"], false);
    }

    // Invariant: Available budget remains exactly 100.0 with 0 fiscal leakage
    let (s_final, r_final) = send_json(&app, "GET", "/governance/stats", None).await;
    assert_eq!(s_final, StatusCode::OK);
    assert_eq!(r_final["budget"], 100.0, "Fiscal leakage detected after concurrent flood!");
    assert_eq!(r_final["cbf_barrier_val"], 90.0);
}

// =========================================================================
// 4. Rollback Idempotency and Out-of-Order Lifecycle Stress
// =========================================================================

#[tokio::test]
async fn test_rollback_idempotency_and_out_of_order_lifecycle() {
    let app = build_test_app();
    let _policy_id = init_and_pin_policy(&app).await;

    // 4a. Nonexistent reservation rollback returns 404 NOT_FOUND
    let (s_ghost, r_ghost) = send_json(
        &app,
        "POST",
        "/governance/rollback",
        Some(json!({ "debit_id": "debit_nonexistent_reservation_ghost" })),
    )
    .await;
    assert_eq!(s_ghost, StatusCode::NOT_FOUND);
    assert_eq!(r_ghost["error"], "NOT_FOUND");

    // 4b. Double rollback test
    // Reserve an action with cost 4.0 (within bound 9.0)
    let (s_act, r_act) = send_json(
        &app,
        "POST",
        "/governance/validate-action",
        Some(json!({
            "action_name": "SafeAction",
            "caller_authority": 1,
            "cost": 4.0
        })),
    )
    .await;
    assert_eq!(s_act, StatusCode::OK);
    assert_eq!(r_act["verdict"], "ALLOW");
    let debit_single = r_act["debit_id"].as_str().unwrap().to_string();

    // Verify budget deducted to 96.0
    let (_, r_mid1) = send_json(&app, "GET", "/governance/stats", None).await;
    assert_eq!(r_mid1["budget"], 96.0);

    // First rollback: succeeds with 200 OK
    let (s_rb1, r_rb1) = send_json(
        &app,
        "POST",
        "/governance/rollback",
        Some(json!({ "debit_id": debit_single })),
    )
    .await;
    assert_eq!(s_rb1, StatusCode::OK);
    assert_eq!(r_rb1["status"], "ROLLED_BACK");
    assert_eq!(r_rb1["restored_amount"], 4.0);
    assert_eq!(r_rb1["state_after_rollback"], 100.0);

    // Second rollback on SAME debit_id: must return 404 NOT_FOUND (already released)
    let (s_rb2, r_rb2) = send_json(
        &app,
        "POST",
        "/governance/rollback",
        Some(json!({ "debit_id": debit_single })),
    )
    .await;
    assert_eq!(s_rb2, StatusCode::NOT_FOUND);
    assert_eq!(r_rb2["error"], "NOT_FOUND");

    // Third rollback attempt: still 404 NOT_FOUND
    let (s_rb3, _r_rb3) = send_json(
        &app,
        "POST",
        "/governance/rollback",
        Some(json!({ "debit_id": debit_single })),
    )
    .await;
    assert_eq!(s_rb3, StatusCode::NOT_FOUND);

    // Budget remains exactly 100.0 without double-crediting
    let (_, r_mid2) = send_json(&app, "GET", "/governance/stats", None).await;
    assert_eq!(r_mid2["budget"], 100.0);

    // 4c. Out-of-order & interleaved validate / rollback cycles
    // Sequence:
    // 1. Validate D1 (cost 2.0) -> budget = 98.0
    // 2. Validate D2 (cost 3.0) -> budget = 95.0
    // 3. Validate D3 (cost 2.5) -> budget = 92.5
    // 4. Rollback D2 (out of order!) -> budget = 95.5
    // 5. Validate D4 (cost 1.5) -> budget = 94.0
    // 6. Rollback D1 -> budget = 96.0
    // 7. Double rollback D2 -> 404 NOT_FOUND, budget stays 96.0
    // 8. Rollback D3 -> budget = 98.5
    // 9. Rollback D4 -> budget = 100.0

    let (_, r_d1) = send_json(
        &app,
        "POST",
        "/governance/validate-action",
        Some(json!({ "action_name": "SafeAction", "caller_authority": 1, "cost": 2.0 })),
    )
    .await;
    let d1 = r_d1["debit_id"].as_str().unwrap().to_string();

    let (_, r_d2) = send_json(
        &app,
        "POST",
        "/governance/validate-action",
        Some(json!({ "action_name": "SafeAction", "caller_authority": 1, "cost": 3.0 })),
    )
    .await;
    let d2 = r_d2["debit_id"].as_str().unwrap().to_string();

    let (_, r_d3) = send_json(
        &app,
        "POST",
        "/governance/validate-action",
        Some(json!({ "action_name": "SafeAction", "caller_authority": 1, "cost": 2.5 })),
    )
    .await;
    let d3 = r_d3["debit_id"].as_str().unwrap().to_string();

    let (_, r_stat_3) = send_json(&app, "GET", "/governance/stats", None).await;
    assert_eq!(r_stat_3["budget"], 92.5);

    // Rollback D2 out of order
    let (s_rb_d2, r_rb_d2) = send_json(
        &app,
        "POST",
        "/governance/rollback",
        Some(json!({ "debit_id": d2 })),
    )
    .await;
    assert_eq!(s_rb_d2, StatusCode::OK);
    assert_eq!(r_rb_d2["restored_amount"], 3.0);
    assert_eq!(r_rb_d2["state_after_rollback"], 95.5);

    // Validate D4
    let (_, r_d4) = send_json(
        &app,
        "POST",
        "/governance/validate-action",
        Some(json!({ "action_name": "SafeAction", "caller_authority": 1, "cost": 1.5 })),
    )
    .await;
    let d4 = r_d4["debit_id"].as_str().unwrap().to_string();

    let (_, r_stat_4) = send_json(&app, "GET", "/governance/stats", None).await;
    assert_eq!(r_stat_4["budget"], 94.0);

    // Rollback D1
    let (s_rb_d1, r_rb_d1) = send_json(
        &app,
        "POST",
        "/governance/rollback",
        Some(json!({ "debit_id": d1 })),
    )
    .await;
    assert_eq!(s_rb_d1, StatusCode::OK);
    assert_eq!(r_rb_d1["restored_amount"], 2.0);
    assert_eq!(r_rb_d1["state_after_rollback"], 96.0);

    // Attempt double rollback on D2 (out-of-order item) -> 404
    let (s_rb_d2_rep, _) = send_json(
        &app,
        "POST",
        "/governance/rollback",
        Some(json!({ "debit_id": d2 })),
    )
    .await;
    assert_eq!(s_rb_d2_rep, StatusCode::NOT_FOUND);

    // Rollback D3
    let (s_rb_d3, r_rb_d3) = send_json(
        &app,
        "POST",
        "/governance/rollback",
        Some(json!({ "debit_id": d3 })),
    )
    .await;
    assert_eq!(s_rb_d3, StatusCode::OK);
    assert_eq!(r_rb_d3["restored_amount"], 2.5);
    assert_eq!(r_rb_d3["state_after_rollback"], 98.5);

    // Rollback D4
    let (s_rb_d4, r_rb_d4) = send_json(
        &app,
        "POST",
        "/governance/rollback",
        Some(json!({ "debit_id": d4 })),
    )
    .await;
    assert_eq!(s_rb_d4, StatusCode::OK);
    assert_eq!(r_rb_d4["restored_amount"], 1.5);
    assert_eq!(r_rb_d4["state_after_rollback"], 100.0);

    // Verify final budget is exactly 100.0
    let (_, r_stat_final) = send_json(&app, "GET", "/governance/stats", None).await;
    assert_eq!(r_stat_final["budget"], 100.0);

    // Verify trace audit chain is completely conformant
    let (s_tr, r_tr) = send_json(&app, "GET", "/governance/trace/verify", None).await;
    assert_eq!(s_tr, StatusCode::OK);
    assert_eq!(r_tr["valid"], true);
    assert_eq!(r_tr["status"], "CONFORMANT");
    assert_eq!(r_tr["findings_count"], 0);
}

// =========================================================================
// 5. Legacy /api/governance/* Alias Stress Under Concurrent Calls
// =========================================================================

#[tokio::test]
async fn test_legacy_api_governance_aliases_concurrent_stress() {
    let app = build_test_app();
    let policy_id = init_and_pin_policy(&app).await;

    let concurrency = 30;
    let barrier = Arc::new(Barrier::new(concurrency));
    let mut handles = Vec::with_capacity(concurrency);

    for idx in 0..concurrency {
        let app_clone = app.clone();
        let b = barrier.clone();
        let pid = policy_id.clone();

        let handle = tokio::spawn(async move {
            b.wait().await;

            // Divide tasks across canonical and legacy endpoints
            match idx % 5 {
                0 => {
                    // /api/governance/policy-version
                    let (s, r) = send_json(&app_clone, "GET", "/api/governance/policy-version", None).await;
                    assert_eq!(s, StatusCode::OK);
                    assert_eq!(r["active_version_id"], pid);
                }
                1 => {
                    // /api/governance/stats
                    let (s, r) = send_json(&app_clone, "GET", "/api/governance/stats", None).await;
                    assert_eq!(s, StatusCode::OK);
                    assert!(r["budget"].as_f64().is_some());
                }
                2 => {
                    // /api/governance/trace/verify
                    let (s, r) = send_json(&app_clone, "GET", "/api/governance/trace/verify", None).await;
                    assert_eq!(s, StatusCode::OK);
                    assert_eq!(r["valid"], true);
                }
                3 => {
                    // /api/governance/validate-action
                    let (s, r) = send_json(
                        &app_clone,
                        "POST",
                        "/api/governance/validate-action",
                        Some(json!({
                            "action_name": "SafeAction",
                            "caller_authority": 1,
                            "cost": 0.5,
                            "params": { "worker": idx }
                        })),
                    )
                    .await;
                    assert_eq!(s, StatusCode::OK);
                    assert_eq!(r["verdict"], "ALLOW");
                    assert!(!r["routing_seal"].is_null());
                }
                _ => {
                    // Canonical endpoint equivalent for concurrent parity check
                    let (s, r) = send_json(&app_clone, "GET", "/governance/policy-version", None).await;
                    assert_eq!(s, StatusCode::OK);
                    assert_eq!(r["active_version_id"], pid);
                }
            }
        });

        handles.push(handle);
    }

    for h in handles {
        h.await.expect("Concurrent alias worker panicked or failed");
    }

    // Verify trace chain after concurrent bombardment
    let (s_tr, r_tr) = send_json(&app, "GET", "/api/governance/trace/verify", None).await;
    assert_eq!(s_tr, StatusCode::OK);
    assert_eq!(r_tr["valid"], true);
    assert_eq!(r_tr["status"], "CONFORMANT");
}
