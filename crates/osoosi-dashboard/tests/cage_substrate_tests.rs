//! CAGE Layer 3 `actuator_04` Substrate End-to-End Integration Tests (`OshoosiClaw`).
//!
//! Verifies all 6 CAGE host-kernel containment substrate endpoints, RFC 8785 ECMAScript JCS
//! (`2^63` float precision & UTF-16 key ordering), Ed25519 domain-separated signature
//! verification against `/.well-known/jwks.json`, `QuarantineJournal` hash-chain persistence,
//! single-use nonce anti-replay (`409`), quorum release (`quorum_count >= 2`, epoch `1 -> 2`),
//! 24-hour sliding-window CBF accumulators, and live TCP socket peer-PID anti-spoofing.

use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use osoosi_dashboard::{
    routes::{
        cage_substrate::{
            canonicalize_substrate_jcs, canonicalize_substrate_jcs_string, CageAttestationResponse,
            CageConformalBaselineResponse, CageConformalValidateResponse,
            CageQuarantineReceiptResponse, CageQuarantineReleaseReceiptResponse,
            CageSubstrateState, Cumulative24hTracker, KeyedCumulative24hTracker, QuarantineJournal,
        },
        mount_routes,
    },
    DashboardState,
};
use rand::rngs::OsRng;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tower::ServiceExt;

fn build_substrate_test_app() -> (axum::Router, DashboardState, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("osoosi_cage_it_{}", uuid::Uuid::new_v4()));
    let _ = std::fs::remove_dir_all(&dir);
    let mut state = DashboardState::new(None, None);
    state.cage_substrate = Arc::new(CageSubstrateState::with_state_dir(dir.clone()));
    let app = mount_routes().with_state(state.clone());
    (app, state, dir)
}

fn parse_verifying_key_from_jwks(jwks: &Value, expected_kid: &str) -> VerifyingKey {
    let keys = jwks["keys"].as_array().expect("keys array");
    assert_eq!(keys.len(), 1);
    let k = &keys[0];
    assert_eq!(k["kty"], "OKP");
    assert_eq!(k["crv"], "Ed25519");
    assert_eq!(k["use"], "sig");
    assert_eq!(k["alg"], "EdDSA");
    assert_eq!(k["kid"], expected_kid);
    let x = k["x"].as_str().expect("x base64url");
    let raw = URL_SAFE_NO_PAD.decode(x).expect("valid base64url");
    assert_eq!(raw.len(), 32);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&raw);
    VerifyingKey::from_bytes(&arr).expect("valid Ed25519 key")
}

fn verify_domain_separated_envelope(
    vk: &VerifyingKey,
    domain_prefix: &[u8],
    unsigned_val: &Value,
    sig_b64: &str,
) {
    let canonical = canonicalize_substrate_jcs(unsigned_val).expect("canonical JCS");
    let mut preimage = domain_prefix.to_vec();
    preimage.extend_from_slice(&canonical);

    let sig_bytes = URL_SAFE_NO_PAD.decode(sig_b64).expect("base64url sig");
    assert_eq!(sig_bytes.len(), 64);
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&sig_bytes);
    let sig = Signature::from_bytes(&arr);
    vk.verify(&preimage, &sig)
        .expect("Ed25519 signature must verify over domain-separated JCS preimage");
}

#[tokio::test]
async fn test_all_six_cage_substrate_endpoints_and_journal_chain() {
    let (app, state, state_dir) = build_substrate_test_app();
    let sub = &state.cage_substrate;

    // 1. GET /.well-known/jwks.json
    let resp_jwks = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/.well-known/jwks.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_jwks.status(), StatusCode::OK);
    let jwks_bytes = to_bytes(resp_jwks.into_body(), 1024 * 1024).await.unwrap();
    let jwks_val: Value = serde_json::from_slice(&jwks_bytes).unwrap();
    let substrate_vk = parse_verifying_key_from_jwks(&jwks_val, &sub.ed25519_kid);

    // 2. GET /v1/cage/normative-baseline/us-central1
    let resp_base = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/cage/normative-baseline/us-central1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_base.status(), StatusCode::OK);
    let base_bytes = to_bytes(resp_base.into_body(), 1024 * 1024).await.unwrap();
    let base: CageConformalBaselineResponse = serde_json::from_slice(&base_bytes).unwrap();
    assert_eq!(base.region, "us-central1");
    assert_eq!(base.calibration_size, 500);
    verify_domain_separated_envelope(
        &substrate_vk,
        b"CAGE_CONFORMAL_BASELINE_V1:",
        &json!({
            "region": base.region,
            "alpha": base.alpha,
            "calibration_size": base.calibration_size,
            "nonconformity_threshold": base.nonconformity_threshold,
            "timestamp_utc": base.timestamp_utc,
            "kid": base.kid,
        }),
        &base.signature,
    );

    // 3. GET /v1/cage/attest
    let resp_att = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/cage/attest")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_att.status(), StatusCode::OK);
    let att_bytes = to_bytes(resp_att.into_body(), 1024 * 1024).await.unwrap();
    let att: CageAttestationResponse = serde_json::from_slice(&att_bytes).unwrap();
    assert_eq!(att.attestation_type, "HOST_TPM_PCR");
    assert!(att.pcr_values.contains_key("0"));
    assert!(att.pcr_values.contains_key("7"));
    verify_domain_separated_envelope(
        &substrate_vk,
        b"CAGE_ATTESTATION_RECEIPT_V1:",
        &json!({
            "attestation_type": att.attestation_type,
            "ring0_posture": att.ring0_posture,
            "tpm_pcr_quote": att.tpm_pcr_quote,
            "pcr_values": att.pcr_values,
            "timestamp_utc": att.timestamp_utc,
            "kid": att.kid,
        }),
        &att.signature,
    );

    // 4. POST /v1/cage/conformal/validate (empty -> 400, [0.5] -> ALLOW, replay -> 409, [20.0] -> DENY)
    let resp_empty = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/cage/conformal/validate")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"scores":[],"nonce":"n_empty"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_empty.status(), StatusCode::BAD_REQUEST);

    let ok_payload = json!({
        "scores": [0.5],
        "alpha": 0.05,
        "action": "read_telemetry",
        "nonce": "nonce_conf_ok_01"
    });
    let ok_bytes = serde_json::to_vec(&ok_payload).unwrap();
    let resp_ok = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/cage/conformal/validate")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(ok_bytes.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_ok.status(), StatusCode::OK);
    let conf_ok_bytes = to_bytes(resp_ok.into_body(), 1024 * 1024).await.unwrap();
    let conf_ok: CageConformalValidateResponse = serde_json::from_slice(&conf_ok_bytes).unwrap();
    assert!(conf_ok.admitted);
    assert_eq!(conf_ok.voter_consensus, "CONSENSUS_ALLOW");
    let expected_digest = hex::encode(Sha256::digest(
        canonicalize_substrate_jcs(&ok_payload).unwrap(),
    ));
    assert_eq!(
        conf_ok.envelope_digest.as_deref(),
        Some(expected_digest.as_str())
    );
    verify_domain_separated_envelope(
        &substrate_vk,
        b"CAGE_CONFORMAL_VALIDATION_V1:",
        &json!({
            "admitted": conf_ok.admitted,
            "p_value": conf_ok.p_value,
            "alpha": conf_ok.alpha,
            "voter_consensus": conf_ok.voter_consensus,
            "timestamp_utc": conf_ok.timestamp_utc,
            "envelope_digest": conf_ok.envelope_digest,
            "kid": conf_ok.kid,
        }),
        &conf_ok.signature,
    );

    // Duplicate nonce -> 409 Conflict
    let resp_replay = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/cage/conformal/validate")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(ok_bytes))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_replay.status(), StatusCode::CONFLICT);

    // Outlier [20.0] -> CONSENSUS_DENY
    let deny_payload = json!({
        "scores": [20.0],
        "alpha": 0.05,
        "action": "read_telemetry",
        "nonce": "nonce_conf_deny_02"
    });
    let resp_deny = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/cage/conformal/validate")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&deny_payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_deny.status(), StatusCode::OK);
    let conf_deny_bytes = to_bytes(resp_deny.into_body(), 1024 * 1024).await.unwrap();
    let conf_deny: CageConformalValidateResponse =
        serde_json::from_slice(&conf_deny_bytes).unwrap();
    assert!(!conf_deny.admitted);
    assert_eq!(conf_deny.voter_consensus, "CONSENSUS_DENY");

    // 5. POST /v1/cage/quarantine
    let gov_sk = SigningKey::generate(&mut OsRng);
    let gov_vk = gov_sk.verifying_key();
    let gov_kid = hex::encode(Sha256::digest(gov_vk.to_bytes()));
    sub.cage_key_manifest.register_key(&gov_kid, gov_vk);

    let q_payload = json!({
        "workload_id": "spiffe://cage.local/ns/prod/sa/claw-04",
        "target_pid": 42424,
        "trigger_reason": "CBF_SAFETY_BARRIER_BREACH",
        "rule_id": "RULE-SC-7-CBF-LETHAL",
        "nonce": "nonce_quar_01"
    });
    let q_bytes = serde_json::to_vec(&q_payload).unwrap();
    let mut q_pre = b"CAGE_QUARANTINE_ASSERTION_V1:".to_vec();
    q_pre.extend_from_slice(&canonicalize_substrate_jcs(&q_payload).unwrap());
    let q_sig_b64 = URL_SAFE_NO_PAD.encode(gov_sk.sign(&q_pre).to_bytes());

    // Unknown kid -> 403 Forbidden
    let resp_unk = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/cage/quarantine")
                .header("X-CAGE-Quarantine-Assertion", &q_sig_b64)
                .header("X-CAGE-Signer-Kid", "deadbeef")
                .body(Body::from(q_bytes.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_unk.status(), StatusCode::FORBIDDEN);

    // Invalid signature -> 401 Unauthorized
    let bad_sig = URL_SAFE_NO_PAD.encode([0u8; 64]);
    let resp_bad = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/cage/quarantine")
                .header("X-CAGE-Quarantine-Assertion", &bad_sig)
                .header("X-CAGE-Signer-Kid", &gov_kid)
                .body(Body::from(q_bytes.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_bad.status(), StatusCode::UNAUTHORIZED);

    // Valid quarantine -> 200 OK
    let resp_q = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/cage/quarantine")
                .header("X-CAGE-Quarantine-Assertion", &q_sig_b64)
                .header("X-CAGE-Signer-Kid", &gov_kid)
                .body(Body::from(q_bytes.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_q.status(), StatusCode::OK);
    let q_resp_bytes = to_bytes(resp_q.into_body(), 1024 * 1024).await.unwrap();
    let q_resp: CageQuarantineReceiptResponse = serde_json::from_slice(&q_resp_bytes).unwrap();
    assert!(q_resp.quarantined);
    assert_eq!(q_resp.status, "QUARANTINED");
    assert_eq!(q_resp.enforcement_plane, "HOST_OS_KERNEL");
    assert_eq!(q_resp.target_pid, Some(42424));
    assert_eq!(sub.journal.unexpired_leases().len(), 1);
    verify_domain_separated_envelope(
        &substrate_vk,
        b"CAGE_QUARANTINE_RECEIPT_V1:",
        &json!({
            "status": q_resp.status,
            "quarantined": q_resp.quarantined,
            "enforcement_plane": q_resp.enforcement_plane,
            "rule_id": q_resp.rule_id,
            "quarantined_at": q_resp.quarantined_at,
            "target_pid": q_resp.target_pid,
            "envelope_digest": q_resp.envelope_digest,
            "kid": q_resp.kid,
        }),
        &q_resp.signature,
    );

    // Replay quarantine -> 409 Conflict
    let resp_q_rep = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/cage/quarantine")
                .header("X-CAGE-Quarantine-Assertion", &q_sig_b64)
                .header("X-CAGE-Signer-Kid", &gov_kid)
                .body(Body::from(q_bytes))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_q_rep.status(), StatusCode::CONFLICT);

    // 6. POST /v1/cage/release (quorum_count < 2 -> 400, valid quorum_count = 2 -> epoch 1 -> 2)
    let low_rel = json!({
        "workload_id": "spiffe://cage.local/ns/prod/sa/claw-04",
        "quorum_approval_digest": "a".repeat(64),
        "quorum_count": 1,
        "nonce": "nonce_rel_low_01"
    });
    let mut low_pre = b"CAGE_QUARANTINE_RELEASE_V1:".to_vec();
    low_pre.extend_from_slice(&canonicalize_substrate_jcs(&low_rel).unwrap());
    let low_sig = URL_SAFE_NO_PAD.encode(gov_sk.sign(&low_pre).to_bytes());
    let resp_low = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/cage/release")
                .header("X-CAGE-Quarantine-Release", &low_sig)
                .header("X-CAGE-Signer-Kid", &gov_kid)
                .body(Body::from(serde_json::to_vec(&low_rel).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_low.status(), StatusCode::BAD_REQUEST);

    let rel_payload = json!({
        "workload_id": "spiffe://cage.local/ns/prod/sa/claw-04",
        "quorum_approval_digest": "b".repeat(64),
        "quorum_count": 2,
        "nonce": "nonce_rel_ok_01"
    });
    let mut rel_pre = b"CAGE_QUARANTINE_RELEASE_V1:".to_vec();
    rel_pre.extend_from_slice(&canonicalize_substrate_jcs(&rel_payload).unwrap());
    let rel_sig = URL_SAFE_NO_PAD.encode(gov_sk.sign(&rel_pre).to_bytes());

    let resp_rel = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/cage/release")
                .header("X-CAGE-Quarantine-Release", &rel_sig)
                .header("X-CAGE-Signer-Kid", &gov_kid)
                .body(Body::from(serde_json::to_vec(&rel_payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_rel.status(), StatusCode::OK);
    let rel_resp_bytes = to_bytes(resp_rel.into_body(), 1024 * 1024).await.unwrap();
    let rel_resp: CageQuarantineReleaseReceiptResponse =
        serde_json::from_slice(&rel_resp_bytes).unwrap();
    assert!(rel_resp.released);
    assert_eq!(rel_resp.epoch_before, 1);
    assert_eq!(rel_resp.epoch_after, 2);
    assert_eq!(rel_resp.outcome, "RELEASED");
    assert!(sub.journal.unexpired_leases().is_empty());

    verify_domain_separated_envelope(
        &substrate_vk,
        b"CAGE_QUARANTINE_RELEASE_RECEIPT_V1:",
        &json!({
            "released": rel_resp.released,
            "enforcement_plane": rel_resp.enforcement_plane,
            "epoch_before": rel_resp.epoch_before,
            "epoch_after": rel_resp.epoch_after,
            "outcome": rel_resp.outcome,
            "released_at": rel_resp.released_at,
            "envelope_digest": rel_resp.envelope_digest,
            "kid": rel_resp.kid,
        }),
        &rel_resp.signature,
    );

    // Reload journal from disk & verify cryptographic Ed25519 seal + SHA-256 hash chain
    let reloaded = QuarantineJournal::new(
        state_dir.clone(),
        Arc::clone(&sub.signing_key),
        sub.ed25519_kid.clone(),
    );
    assert!(reloaded.verify_hash_chain().unwrap());
    assert_eq!(reloaded.current_seq(), 3);
    assert_eq!(
        reloaded.get_generation_epoch("spiffe://cage.local/ns/prod/sa/claw-04"),
        2
    );

    let _ = std::fs::remove_dir_all(&state_dir);
}

#[test]
fn test_substrate_jcs_2_pow_63_trackers_and_live_peer_pid() {
    assert_eq!(
        canonicalize_substrate_jcs_string(&json!(9223372036854775808.0)).unwrap(),
        "9223372036854775808"
    );
    assert_eq!(
        canonicalize_substrate_jcs_string(&json!(-9223372036854775808.0)).unwrap(),
        "-9223372036854775808"
    );
    assert_eq!(
        canonicalize_substrate_jcs_string(&json!(-0.0)).unwrap(),
        "0"
    );
    assert_eq!(
        canonicalize_substrate_jcs_string(&json!(1e21)).unwrap(),
        "1e+21"
    );
    assert_eq!(
        canonicalize_substrate_jcs_string(&json!(1e-7)).unwrap(),
        "1e-7"
    );

    let val = json!({ "\u{E000}": 1, "\u{10000}": 2 });
    assert_eq!(
        canonicalize_substrate_jcs_string(&val).unwrap(),
        format!(r#"{{"{}":2,"{}":1}}"#, "\u{10000}", "\u{E000}")
    );

    let scalar = Cumulative24hTracker::new();
    let t0 = 1_000_000_000_000u64;
    assert_eq!(scalar.record_at(t0, 100.0), 100.0);
    assert_eq!(scalar.record_at(t0 + 1_000, 50.0), 150.0);
    assert_eq!(scalar.total_at(t0 + 86_400_001), 50.0);

    let keyed = KeyedCumulative24hTracker::new();
    assert_eq!(keyed.record_key_at(t0, "tenant-a"), 1);
    assert_eq!(keyed.record_key_at(t0 + 500, "tenant-b"), 2);
    assert_eq!(keyed.distinct_count_at(t0 + 86_400_001), 1);

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let bound_port = listener.local_addr().unwrap().port();
    let client = std::net::TcpStream::connect(("127.0.0.1", bound_port)).unwrap();
    let (_srv, peer_addr) = listener.accept().unwrap();
    let _ = client;
    let pid = osoosi_core::peer_pid::resolve_loopback_peer_pid(peer_addr, bound_port).unwrap();
    assert_eq!(pid, std::process::id());
}
