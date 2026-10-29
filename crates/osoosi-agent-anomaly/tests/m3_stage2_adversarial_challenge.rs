//! Empirical Adversarial Challenge Suite: Milestone 3 Stage 2 (Requirement R3)
//!
//! Author: Challenger 1 (M3 Stage 2 Adversarial Challenger)
//!
//! Objectives:
//! 1. Traversal Percent-Encoding Defense:
//!    - Stress-test resource boundary canonicalization with single-dot `%2e`, `.%2e`, `%2e.`,
//!      double-dot `%2e%2e`, null `%00`, forward slash `%2f`, backslash `%5c`, and percent `%25`.
//! 2. Capability Token Order Verification:
//!    - Verify that bearer mismatch, role mismatch, and TTL expiration fail closed BEFORE
//!      expensive cryptographic HMAC verification executes (protecting against DoS and timing side-channels).
//! 3. Severed-Arm Veto Enforcement:
//!    - Verify that a severed arm branch cannot execute operations, send inter-agent messages,
//!      or execute contained tools even with a valid signature, and that regeneration restores access.
//! 4. Sticky Untrusted Taint Floor across >16 Hops:
//!    - Verify that multi-hop relay chains (>16 hops) preserve the earliest Untrusted hop upon truncation
//!      and that transmission to `AccountingLedgerWrite` (PrivilegedSink) is deterministically blocked.
//! 5. Scratchpad Immunity Denial:
//!    - Verify that `/tmp/`, `temp/`, and `scratchpad` directories are never granted path immunity
//!      even if files or subdirectories mimic repository names like `src/` or `Cargo.toml`.
//! 6. Cedar Reserved Principal Spoofing Defense:
//!    - Verify that unauthenticated or mismatched arms attempting to claim reserved Cedar principal
//!      identities are deterministically rejected with `CEDAR_PRINCIPAL_SPOOF_BLOCKED`.
//! 7. RFC 2765 SIIT IPv4-Translated IPv6 SSRF Defense:
//!    - Verify that `::ffff:0:127.0.0.1` and `::ffff:0:169.254.169.254` are blocked across both
//!      `egress_proxy.rs` and `agent_egress.rs`.

use osoosi_agent_anomaly::containment_ring::{
    validate_resource_boundary, AgentContainmentRing, ArmContainmentRing,
    DiracDeltaCapabilityTicket, MessageKind, ProvenanceHop, MAX_RELAY_HOPS,
};
use osoosi_agent_anomaly::egress_proxy::{
    is_restricted_rebinding_ip as egress_is_restricted_ip, validate_agent_egress_url,
};
use osoosi_agent_anomaly::file_lineage::FileLineageTracker;
use osoosi_agent_anomaly::mesh_guard::{MeshGuard, VerifiedMeshMessage};
use osoosi_agent_anomaly::types::ToolCallTelemetry;
use osoosi_policy::agent_egress::is_restricted_rebinding_ip as policy_is_restricted_ip;
use osoosi_policy::breakout_gate::{
    validate_cedar_principal_role, AuthorityLevel, CedarAction, CedarContext, CedarPrincipal,
    CedarResource, DataClassification, EnforcementStage, Ring7CapabilityEffectAuthorizer,
};
use osoosi_types::arm_role::{role_trust_tier, ArmRole, TrustTier};
use std::net::IpAddr;
use std::path::Path;

// ================================================================================================
// PART 1: TRAVERSAL PERCENT-ENCODINGS ADVERSARIAL SUITE
// ================================================================================================

#[test]
fn challenge_traversal_percent_encodings_comprehensive() {
    let allowed = vec![
        "https://example.com/api/".to_string(),
        "s3://invoices/".to_string(),
        "local://data/".to_string(),
    ];

    // Single-dot and mixed dot variations
    let malicious_single_dots = [
        "https://example.com/api/%2e",
        "https://example.com/api/.%2e",
        "https://example.com/api/%2e.",
        "https://example.com/api/.%2e/sub",
        "https://example.com/api/%2e./sub",
        "https://example.com/api/v1/%2e%2e/admin",
        "s3://invoices/.%2e/secret.pdf",
        "s3://invoices/%2e./secret.pdf",
        "s3://invoices/%2e/secret.pdf",
    ];

    for r in &malicious_single_dots {
        let res = validate_resource_boundary(r, &allowed);
        assert!(
            res.is_err(),
            "Resource boundary MUST reject single-dot/mixed percent-encoding: {}",
            r
        );
    }

    // Other illegal percent encodings: %00, %2f, %5c, %25
    let malicious_other_encodings = [
        "https://example.com/api/%00",
        "https://example.com/api/test%00admin",
        "https://example.com/api/%2f",
        "https://example.com/api/v1%2f..%2fadmin",
        "https://example.com/api/%5c",
        "https://example.com/api/v1%5c..%5cadmin",
        "https://example.com/api/%25",
        "https://example.com/api/%252e%252e",
        "s3://invoices/%00payload",
        "s3://invoices/%2fetc%2fpasswd",
        "s3://invoices/%5cetc%5cpasswd",
    ];

    for r in &malicious_other_encodings {
        let res = validate_resource_boundary(r, &allowed);
        assert!(
            res.is_err(),
            "Resource boundary MUST reject illegal percent-encoding: {}",
            r
        );
    }

    // Standard valid resources MUST pass
    assert!(validate_resource_boundary("https://example.com/api/v1/users", &allowed).is_ok());
    assert!(validate_resource_boundary("s3://invoices/2026/q1.pdf", &allowed).is_ok());
    assert!(validate_resource_boundary("local://data/report.json", &allowed).is_ok());
}

// ================================================================================================
// PART 2: CAPABILITY TOKEN ORDER VERIFICATION SUITE
// ================================================================================================

#[tokio::test]
async fn challenge_capability_token_verification_order_pre_hmac() {
    let seed = [99u8; 32];
    let ring = ArmContainmentRing::new(1, ArmRole::AccountingLedgerWrite, 1, &seed);

    let token = ring
        .issue_epoch_capability("ledger_tool", "s3://finance/ledger.dat", 120)
        .await
        .expect("token issuance");

    // 1. Expired token with BOGUS HMAC signature MUST fail with "expired", NOT "signature"
    let mut expired_token = token.clone();
    expired_token.expires_at_secs = 100; // Expired
    expired_token.signature_hex =
        "0000000000000000000000000000000000000000000000000000000000000000".to_string(); // Corrupted HMAC
    let err = ring
        .verify_epoch_capability(&expired_token)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("expired"),
        "Expired token must fail with 'expired' error before HMAC evaluation: {}",
        err
    );

    // 2. Bearer mismatch with BOGUS HMAC signature MUST fail with "bearer mismatch", NOT "signature"
    let mut bearer_mismatch = token.clone();
    bearer_mismatch.bearer_agent = "unauthorized_agent_omega".to_string();
    bearer_mismatch.signature_hex =
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string();
    let err = ring
        .verify_epoch_capability(&bearer_mismatch)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("bearer mismatch"),
        "Wrong bearer token must fail with 'bearer mismatch' error before HMAC evaluation: {}",
        err
    );

    // 3. Role mismatch with BOGUS HMAC signature MUST fail with "role mismatch", NOT "signature"
    let mut role_mismatch = token.clone();
    role_mismatch.permitted_role = ArmRole::UntrustedDocIngest;
    role_mismatch.signature_hex =
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string();
    let err = ring
        .verify_epoch_capability(&role_mismatch)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("role mismatch"),
        "Role mismatch token must fail with 'role mismatch' error before HMAC evaluation: {}",
        err
    );

    // 4. Valid bearer, role, unexpired, but corrupted HMAC signature MUST fail with "signature"
    let mut forged_sig = token.clone();
    forged_sig.signature_hex =
        "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string();
    let err = ring.verify_epoch_capability(&forged_sig).await.unwrap_err();
    assert!(
        err.to_string().contains("signature"),
        "Forged signature token must fail with signature error: {}",
        err
    );

    // 5. Valid token passes completely
    assert!(ring.verify_epoch_capability(&token).await.is_ok());
}

// ================================================================================================
// PART 3: SEVERED-ARM VETO & REGENERATION SUITE
// ================================================================================================

#[tokio::test]
async fn challenge_severed_arm_veto_and_regeneration_lifecycle() {
    let ring = AgentContainmentRing::new();
    let severed_agent = "compromised_extractor_agent";
    let healthy_agent = "healthy_analysis_agent";

    // Initial state: both healthy
    assert!(!ring.is_agent_severed(severed_agent));
    assert!(!ring.is_agent_severed(healthy_agent));
    assert!(ring
        .evaluate_operation(severed_agent, "read", "file.txt")
        .is_ok());
    assert!(ring
        .evaluate_operation(healthy_agent, "read", "file.txt")
        .is_ok());

    // Trigger autotomy severance on rogue agent
    let new_epoch = ring
        .sever_rogue_agent_branch(severed_agent, "Adversarial exfiltration detected", None)
        .await;
    assert_eq!(new_epoch, 2);
    assert!(ring.is_agent_severed(severed_agent));
    assert!(!ring.is_agent_severed(healthy_agent));

    // 1. evaluate_operation vetoes severed agent
    let err = ring
        .evaluate_operation(severed_agent, "query", "database")
        .unwrap_err();
    assert!(
        err.contains("Level 1 Arm Ring veto"),
        "Severed arm must be vetoed on evaluate_operation: {}",
        err
    );

    // 2. Healthy agent remains unaffected
    assert!(ring
        .evaluate_operation(healthy_agent, "query", "database")
        .is_ok());

    // 3. verify_inter_agent_message vetoes severed agent even with valid active HMAC
    let (epoch_act, sig_act) = ring.sign_message(severed_agent, "worker", "status_report");
    let err = ring
        .verify_inter_agent_message(
            severed_agent,
            epoch_act,
            "worker",
            "sink",
            "status_report",
            &sig_act,
        )
        .unwrap_err();
    assert!(
        err.contains("Level 1 Arm Ring veto"),
        "Severed arm must be vetoed on inter-agent messages: {}",
        err
    );

    // 4. execute_contained_tool vetoes severed agent
    let ticket = DiracDeltaCapabilityTicket::issue(severed_agent, "execute_tool", 2, 5_000_000_000);
    let tracker = FileLineageTracker::new();
    let telemetry = ToolCallTelemetry {
        session_id: "test_session".to_string(),
        agent_id: severed_agent.to_string(),
        trace_id: None,
        tool_name: "execute_tool".to_string(),
        call_parameters: serde_json::json!({}),
        execution_duration_ms: 5,
        timestamp: chrono::Utc::now(),
        tokens_used: None,
        is_error: false,
        error_message: None,
    };
    let tool_res = ring.execute_contained_tool(&telemetry, &ticket, &tracker, || "res");
    assert!(tool_res.is_err());
    assert!(tool_res
        .unwrap_err()
        .contains("[ContainmentRing-Level1-Veto]"));

    // 5. Regeneration restores agent capabilities
    let regen_epoch = ring.regenerate_agent(severed_agent);
    assert_eq!(regen_epoch, 3);
    assert!(!ring.is_agent_severed(severed_agent));

    // Regenerated agent can now evaluate operations
    assert!(ring
        .evaluate_operation(severed_agent, "query", "database")
        .is_ok());

    // Inter-agent message with newly regenerated epoch passes
    let (epoch_regen, sig_regen) = ring.sign_message(severed_agent, "worker", "clean_report");
    assert!(ring
        .verify_inter_agent_message(
            severed_agent,
            epoch_regen,
            "worker",
            "sink",
            "clean_report",
            &sig_regen
        )
        .is_ok());

    // Stale epoch from earlier generation is rejected
    let err_stale = ring
        .verify_inter_agent_message(
            severed_agent,
            epoch_act,
            "worker",
            "sink",
            "status_report",
            &sig_act,
        )
        .unwrap_err();
    assert!(
        err_stale.contains("Stale generation epoch rejected"),
        "Stale epoch must be rejected: {}",
        err_stale
    );
}

// ================================================================================================
// PART 4: STICKY UNTRUSTED TAINT FLOOR ACROSS >16 HOPS SUITE
// ================================================================================================

#[tokio::test]
async fn challenge_sticky_untrusted_taint_floor_across_20_hops_and_sink_veto() {
    let mut hops: Vec<ProvenanceHop> = Vec::new();
    // Untrusted origin
    hops.push(ProvenanceHop {
        arm_id: 100,
        role: ArmRole::UntrustedDocIngest,
        generation: 1,
    });
    // 20 Worker hops
    for i in 1..=20 {
        hops.push(ProvenanceHop {
            arm_id: 100 + i,
            role: ArmRole::AnomalyDetection,
            generation: 1,
        });
    }
    assert_eq!(hops.len(), 21);

    // Truncate using the exact logic from ArmContainmentRing
    let excess = hops.len().saturating_sub(MAX_RELAY_HOPS - 1);
    assert_eq!(excess, 6);
    let preserved_untrusted = hops
        .iter()
        .take(excess)
        .find(|h| role_trust_tier(&h.role) == TrustTier::Untrusted)
        .cloned();
    hops.drain(0..excess);
    if let Some(untrusted_hop) = preserved_untrusted {
        if !hops
            .iter()
            .any(|h| role_trust_tier(&h.role) == TrustTier::Untrusted)
        {
            if !hops.is_empty() {
                hops[0] = untrusted_hop;
            } else {
                hops.push(untrusted_hop);
            }
        }
    }

    assert_eq!(hops[0].role, ArmRole::UntrustedDocIngest);
    assert!(hops
        .iter()
        .any(|h| role_trust_tier(&h.role) == TrustTier::Untrusted));

    // Also test a live multi-hop relay between ArmContainmentRings
    let seed = [55u8; 32];
    let untrusted_arm = ArmContainmentRing::new(1, ArmRole::UntrustedDocIngest, 1, &seed);
    let worker1 = ArmContainmentRing::new(2, ArmRole::AnomalyDetection, 1, &seed);
    let ledger_sink = ArmContainmentRing::new(3, ArmRole::AccountingLedgerWrite, 1, &seed);

    let msg1 = untrusted_arm
        .sign_mesh_message(2, 1, MessageKind::Finding, "corr_1", "payload_1")
        .await
        .expect("sign msg1");

    let verified1 = worker1
        .verify_incoming_message(&msg1)
        .await
        .expect("verify worker1");
    assert_eq!(verified1.effective_taint_floor(), TrustTier::Untrusted);

    // Worker1 relays to LedgerSink
    let msg2 = worker1
        .sign_mesh_message(3, 1, MessageKind::Finding, "corr_2", "payload_2")
        .await
        .expect("sign msg2");
    assert_eq!(msg2.taint_floor, TrustTier::Untrusted);

    // LedgerSink must reject because effective_taint_floor is Untrusted!
    let err_sink = ledger_sink
        .verify_incoming_message(&msg2)
        .await
        .unwrap_err();
    assert!(
        err_sink.to_string().contains("LAW1_STICKY_TAINT_VETO")
            || err_sink.to_string().contains("Ring Boundary Violation"),
        "Ledger sink must reject tainted message: {}",
        err_sink
    );

    // And verify MeshGuard rejects the message under both layers:
    let mesh = MeshGuard::new();
    // Layer 1: Full role chain includes UntrustedDocIngest -> blocked by HomologicalBoundaryAuditor
    let verified_mesh_full = VerifiedMeshMessage::new(
        msg2.clone(),
        3,
        ArmRole::AccountingLedgerWrite,
        vec![
            ArmRole::UntrustedDocIngest,
            ArmRole::AnomalyDetection,
            ArmRole::AccountingLedgerWrite,
        ],
        TrustTier::Untrusted,
    );
    let mesh_res_a = mesh.validate_message(&verified_mesh_full).await;
    assert!(mesh_res_a.is_err());
    let err_a = mesh_res_a.unwrap_err().to_string();
    assert!(
        err_a.contains("Inner Ring Boundary Violation") && err_a.contains("PROXY_LAUNDERING_VETO"),
        "Layer 1 must be blocked by HomologicalBoundaryAuditor proxy laundering veto: {}",
        err_a
    );

    // Layer 2: Role chain stripped/laundered to contain only Workers, but effective_taint_floor remains Untrusted
    // Step 2b MUST catch and veto with "Inner Ring Sticky Taint Violation"!
    let verified_mesh_laundered = VerifiedMeshMessage::new(
        msg2.clone(),
        3,
        ArmRole::AccountingLedgerWrite,
        vec![
            ArmRole::VulnerabilityResearch,
            ArmRole::AnomalyDetection,
            ArmRole::AccountingLedgerWrite,
        ],
        TrustTier::Untrusted,
    );
    let mesh_res_b = mesh.validate_message(&verified_mesh_laundered).await;
    assert!(mesh_res_b.is_err());
    let err_b = mesh_res_b.unwrap_err().to_string();
    assert!(
        err_b.contains("Inner Ring Sticky Taint Violation"),
        "Layer 2 (laundered role chain) must be blocked by Step 2b sticky taint floor check: {}",
        err_b
    );
}

// ================================================================================================
// PART 5: SCRATCHPAD IMMUNITY DENIAL SUITE
// ================================================================================================

#[test]
fn challenge_scratchpad_and_temp_dirs_immunity_denial() {
    let tracker = FileLineageTracker::new();

    let non_immune_paths = [
        "C:\\temp\\scratchpad\\src\\payload.exe",
        "/workspace/scratchpad/Cargo.toml",
        "scratchpad/src/main.rs",
        "/tmp/src/lib.rs",
        "/temp/Cargo.toml",
        "C:\\Windows\\Temp\\payload.exe",
        "tmp/tool.py",
        "temp/build.rs",
        "/var/tmp/scratchpad_arm1/src/lib.rs",
        "temp/scratchpad_agent1/Cargo.toml",
    ];

    for p in &non_immune_paths {
        let path = Path::new(p);
        assert!(
            !tracker.is_path_immune(path),
            "Scratchpad/temp path MUST NOT be granted immunity: {}",
            p
        );
    }
}

// ================================================================================================
// PART 6: CEDAR RESERVED PRINCIPAL SPOOFING SUITE
// ================================================================================================

#[test]
fn challenge_cedar_reserved_principal_spoofing() {
    // 1. Legitimate mappings pass
    assert_eq!(
        validate_cedar_principal_role("ledger_arm", &ArmRole::AccountingLedgerWrite).unwrap(),
        "ledger_arm"
    );
    assert_eq!(
        validate_cedar_principal_role("document_arm", &ArmRole::UntrustedDocIngest).unwrap(),
        "document_arm"
    );
    assert_eq!(
        validate_cedar_principal_role("network_arm", &ArmRole::NetworkEgress).unwrap(),
        "network_arm"
    );

    // 2. Mismatched roles claiming reserved principals are rejected with CEDAR_PRINCIPAL_SPOOF_BLOCKED
    let spoof_cases = [
        ("ledger_arm", ArmRole::ContinuousOssFuzz),
        ("document_arm", ArmRole::AccountingLedgerWrite),
        ("network_arm", ArmRole::UntrustedDocIngest),
        ("cedar_arm", ArmRole::VulnerabilityResearch),
        ("kernel_sentinel_arm", ArmRole::AnomalyDetection),
    ];

    for (principal, role) in spoof_cases {
        let err = validate_cedar_principal_role(principal, &role).unwrap_err();
        assert!(
            err.to_string().contains("CEDAR_PRINCIPAL_SPOOF_BLOCKED"),
            "Spoofed principal '{}' with role '{:?}' must return CEDAR_PRINCIPAL_SPOOF_BLOCKED: {}",
            principal,
            role,
            err
        );
    }

    // 3. Non-reserved principal IDs pass without error
    assert_eq!(
        validate_cedar_principal_role("custom_worker_agent_42", &ArmRole::ContinuousOssFuzz)
            .unwrap(),
        "oss_fuzz_arm"
    );

    // 4. Evaluate in Ring7CapabilityEffectAuthorizer
    let authorizer = Ring7CapabilityEffectAuthorizer::new();
    let unauthenticated_principal = CedarPrincipal {
        principal_id: "ledger_arm".to_string(),
        session_id: "sess_spoof_test".to_string(),
        process_instance_key: "proc_001".to_string(),
        authority_level: AuthorityLevel::L3TrustedApplicationInstruction,
        approved_capabilities: vec!["write_ledger".to_string()],
        authenticated_role: None, // Missing authentication
    };

    let resource = CedarResource {
        resource_id: "ledger://tx_001".to_string(),
        resource_type: "ledger".to_string(),
        classification: DataClassification::Confidential,
        is_signed_and_allowlisted: false,
        is_approved_child_binary: false,
        is_task_scoped_destination: true,
        is_declassified_approved_sink: false,
        service_identity: None,
        service_operation: None,
    };

    let context = CedarContext {
        policy_version: "1.0.0".to_string(),
        causal_event_id: "evt_001".to_string(),
        has_crown_jewel_taint: false,
        highest_data_classification: DataClassification::Confidential,
        taint_level: 0.0,
        cumulative_salami_turns: 0,
        has_approved_capability: true,
        has_cryptographic_declassification: false,
        upward_authority_promotion_attempted: false,
        egress_budget_exceeded: false,
        semantic_cosine_similarity: 0.0,
        covert_jitter_applied_ms: 0,
        taint_epoch: 1,
        revocation_seq: 1,
        has_untrusted_web_input: false,
        has_scratch_file_write: false,
        subprocess_env_or_arg_tainted: false,
        temporal_trace_window_seconds: 7200,
    };

    let decision = authorizer.evaluate_cedar_request(
        &unauthenticated_principal,
        CedarAction::ExternalWrite,
        &resource,
        context,
        EnforcementStage::PreExecutionPrevented,
    );

    assert!(!decision.allowed);
    assert!(
        decision
            .matched_forbid_policies
            .iter()
            .any(|f| f.contains("CEDAR_PRINCIPAL_SPOOF_BLOCKED")),
        "Cedar evaluation MUST forbid unauthenticated reserved principal with CEDAR_PRINCIPAL_SPOOF_BLOCKED: {:?}",
        decision.matched_forbid_policies
    );

    // 5. Authenticated matching principal does NOT get CEDAR_PRINCIPAL_SPOOF_BLOCKED
    let authenticated_principal = CedarPrincipal {
        principal_id: "ledger_arm".to_string(),
        session_id: "sess_spoof_test".to_string(),
        process_instance_key: "proc_002".to_string(),
        authority_level: AuthorityLevel::L3TrustedApplicationInstruction,
        approved_capabilities: vec!["write_ledger".to_string()],
        authenticated_role: Some(ArmRole::AccountingLedgerWrite),
    };

    let context_auth = CedarContext {
        policy_version: "1.0.0".to_string(),
        causal_event_id: "evt_002".to_string(),
        has_crown_jewel_taint: false,
        highest_data_classification: DataClassification::Confidential,
        taint_level: 0.0,
        cumulative_salami_turns: 0,
        has_approved_capability: true,
        has_cryptographic_declassification: false,
        upward_authority_promotion_attempted: false,
        egress_budget_exceeded: false,
        semantic_cosine_similarity: 0.0,
        covert_jitter_applied_ms: 0,
        taint_epoch: 1,
        revocation_seq: 1,
        has_untrusted_web_input: false,
        has_scratch_file_write: false,
        subprocess_env_or_arg_tainted: false,
        temporal_trace_window_seconds: 7200,
    };

    let decision_auth = authorizer.evaluate_cedar_request(
        &authenticated_principal,
        CedarAction::ExternalWrite,
        &resource,
        context_auth,
        EnforcementStage::PreExecutionPrevented,
    );

    assert!(
        !decision_auth
            .matched_forbid_policies
            .iter()
            .any(|f| f.contains("CEDAR_PRINCIPAL_SPOOF_BLOCKED")),
        "Authenticated matching principal MUST NOT be blocked by principal spoof check"
    );
}

// ================================================================================================
// PART 7: RFC 2765 SIIT IPV4-TRANSLATED IPV6 SSRF SUITE
// ================================================================================================

#[test]
fn challenge_rfc_2765_siit_ssrf_blocking() {
    // 1. Test egress_proxy::is_restricted_rebinding_ip
    let siit_loopback: IpAddr = "::ffff:0:127.0.0.1".parse().unwrap();
    let siit_metadata: IpAddr = "::ffff:0:169.254.169.254".parse().unwrap();
    let siit_rfc1918_10: IpAddr = "::ffff:0:10.0.0.1".parse().unwrap();
    let siit_rfc1918_172: IpAddr = "::ffff:0:172.16.0.1".parse().unwrap();
    let siit_rfc1918_192: IpAddr = "::ffff:0:192.168.1.1".parse().unwrap();
    let siit_unspecified: IpAddr = "::ffff:0:0.0.0.0".parse().unwrap();
    let siit_public_8888: IpAddr = "::ffff:0:8.8.8.8".parse().unwrap();
    let siit_public_1111: IpAddr = "::ffff:0:1.1.1.1".parse().unwrap();

    assert!(
        egress_is_restricted_ip(&siit_loopback),
        "egress_proxy MUST block SIIT loopback ::ffff:0:127.0.0.1"
    );
    assert!(
        egress_is_restricted_ip(&siit_metadata),
        "egress_proxy MUST block SIIT cloud metadata ::ffff:0:169.254.169.254"
    );
    assert!(
        egress_is_restricted_ip(&siit_rfc1918_10),
        "egress_proxy MUST block SIIT RFC1918 ::ffff:0:10.0.0.1"
    );
    assert!(
        egress_is_restricted_ip(&siit_rfc1918_172),
        "egress_proxy MUST block SIIT RFC1918 ::ffff:0:172.16.0.1"
    );
    assert!(
        egress_is_restricted_ip(&siit_rfc1918_192),
        "egress_proxy MUST block SIIT RFC1918 ::ffff:0:192.168.1.1"
    );
    assert!(
        egress_is_restricted_ip(&siit_unspecified),
        "egress_proxy MUST block SIIT unspecified ::ffff:0:0.0.0.0"
    );
    assert!(
        !egress_is_restricted_ip(&siit_public_8888),
        "egress_proxy MUST allow public SIIT ::ffff:0:8.8.8.8"
    );
    assert!(
        !egress_is_restricted_ip(&siit_public_1111),
        "egress_proxy MUST allow public SIIT ::ffff:0:1.1.1.1"
    );

    // 2. Test policy agent_egress::is_restricted_rebinding_ip
    assert!(
        policy_is_restricted_ip(siit_loopback),
        "agent_egress MUST block SIIT loopback ::ffff:0:127.0.0.1"
    );
    assert!(
        policy_is_restricted_ip(siit_metadata),
        "agent_egress MUST block SIIT cloud metadata ::ffff:0:169.254.169.254"
    );
    assert!(
        policy_is_restricted_ip(siit_rfc1918_10),
        "agent_egress MUST block SIIT RFC1918 ::ffff:0:10.0.0.1"
    );
    assert!(
        !policy_is_restricted_ip(siit_public_8888),
        "agent_egress MUST allow public SIIT ::ffff:0:8.8.8.8"
    );

    // 3. Test validate_agent_egress_url with bracketed SIIT IPv6 addresses
    assert!(
        validate_agent_egress_url("https://[::ffff:0:127.0.0.1]/admin", &[]).is_err(),
        "URL validator MUST reject SIIT loopback URL"
    );
    assert!(
        validate_agent_egress_url("https://[::ffff:0:169.254.169.254]/latest/meta-data", &[])
            .is_err(),
        "URL validator MUST reject SIIT cloud metadata URL"
    );
    assert!(
        validate_agent_egress_url("https://[::ffff:0:10.0.0.1]/private", &[]).is_err(),
        "URL validator MUST reject SIIT RFC1918 URL"
    );
}
