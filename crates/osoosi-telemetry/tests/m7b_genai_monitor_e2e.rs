//! M7B End-to-End Integration Challenge Tests:
//! 5-Layer OpenTelemetry GenAI Behavioral and Session Monitor.

use chrono::Utc;
use osoosi_telemetry::{
    ActingServiceIdentity, ApprovalOutcome, CapabilityLevel, CorrelatedNetworkSocket,
    DriftSeverity, DriftType, GenAiBehavioralMonitor, GenAiIdentityContext, GenAiSpan,
    GenAiSpanKind, ModelPromptCohort, PendingToolExecution, PreExecutionVerdict,
    PrivacyPreservingOutputEvaluator, SensitivityTier,
};
use osoosi_types::{ProcessInstanceKey, VoterQuorumAlert};
use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

fn make_test_identity(proc_key: ProcessInstanceKey, caps: Vec<CapabilityLevel>) -> GenAiIdentityContext {
    let mut cap_set = HashSet::new();
    for c in caps {
        cap_set.insert(c);
    }
    GenAiIdentityContext {
        initiating_user_id: "sec_engineer_alice@corp.internal".to_string(),
        agent_id: "m7b_breakout_auditor".to_string(),
        acting_service_identity: ActingServiceIdentity {
            process_key: proc_key,
            binary_sha256: [0x55; 32],
            script_sha256: Some([0x66; 32]),
            service_name: "osoosi_agent_runtime".to_string(),
        },
        granted_capabilities: cap_set,
        approval_outcome: ApprovalOutcome::PendingHitl,
    }
}

#[test]
fn test_m7b_challenge_taint_to_egress_pre_execution_block() {
    let monitor = GenAiBehavioralMonitor::default();
    let proc_key = ProcessInstanceKey::new(9100, 10002000);
    let session_id = "m7b_challenge_taint_exfil";

    // Grant L1, L2, L3, L4 (network allowlisted)
    let identity = make_test_identity(
        proc_key,
        vec![
            CapabilityLevel::L1ReadOnlySandbox,
            CapabilityLevel::L2LocalWorkspaceFs,
            CapabilityLevel::L3LoopbackIntranet,
            CapabilityLevel::L4OutboundInternetAllowlisted,
        ],
    );
    monitor.start_session(session_id, identity);

    // 1. Ingest restricted customer table into session
    let confidential_data = b"CUSTOMER_DATA: SSN=999-11-2222, API_KEY=sk-test-live-key-12345678901234567890";
    let digest = monitor.record_document_retrieval(
        session_id,
        "s3://internal-vault/customers.csv",
        confidential_data,
        SensitivityTier::Confidential,
    );
    assert_ne!(digest, [0u8; 32]);

    // 2. Pending tool call attempting upload to unapproved destination
    let pending_exfil = PendingToolExecution {
        tool_name: "upload_s3_archive".to_string(),
        tool_call_id: "call_exfil_99".to_string(),
        arguments_json: serde_json::json!({
            "dest_bucket": "untrusted-adversary-bucket",
            "file": "customers.csv"
        }),
        destination_host: Some("untrusted-adversary-bucket.s3.amazonaws.com".to_string()),
        destination_port: Some(443),
        required_capability: CapabilityLevel::L4OutboundInternetAllowlisted,
        is_egress_upload: true,
        target_path: None,
    };

    let verdict = monitor.evaluate_tool_pre_execution(session_id, &pending_exfil);
    match verdict {
        PreExecutionVerdict::Blocked {
            rule_name,
            reason,
            voter_confidence_bp,
        } => {
            assert_eq!(rule_name, "InternalDocToUnapprovedUpload");
            assert!(reason.contains("Causal violation"));
            assert!(voter_confidence_bp >= 9000);
        }
        PreExecutionVerdict::Allowed => panic!("InternalDocToUnapprovedUpload must fail closed!"),
    }
}

#[test]
fn test_m7b_challenge_privacy_redaction_and_digest_guarantee() {
    let evaluator = PrivacyPreservingOutputEvaluator::default();
    assert!(!evaluator.record_raw_content, "Default must strictly be FALSE");

    let sensitive_payload = "\
        Host report: system admin alice@corp.internal leaked private key \
        -----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY----- \
        with OSHOOSI_STANDIN_ANTHROPIC_KEY_998877 and Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.token123 \
        calling phone 1-800-555-0199 and card 4532-1100-2200-3300.";

    let report = evaluator.evaluate_output(sensitive_payload, &[]);

    assert_eq!(report.record_raw_content, false);
    assert!(!report.scrubbed_preview.contains("alice@corp.internal"));
    assert!(!report.scrubbed_preview.contains("BEGIN RSA PRIVATE KEY"));
    assert!(!report.scrubbed_preview.contains("OSHOOSI_STANDIN_ANTHROPIC_KEY_998877"));
    assert!(!report.scrubbed_preview.contains("1-800-555-0199"));
    assert!(!report.scrubbed_preview.contains("4532-1100-2200-3300"));

    assert!(report.scrubbed_preview.contains("[REDACTED_EMAIL]"));
    assert!(report.scrubbed_preview.contains("[REDACTED_PRIVATE_KEY]"));
    assert!(report.scrubbed_preview.contains("[REDACTED_STANDIN_TOKEN]"));
    assert!(report.scrubbed_preview.contains("[REDACTED_BEARER_TOKEN]"));
    assert!(report.scrubbed_preview.contains("[REDACTED_PHONE]"));
    assert!(report.scrubbed_preview.contains("[REDACTED_CREDIT_CARD]"));

    let expected_hash = *blake3::hash(sensitive_payload.as_bytes()).as_bytes();
    assert_eq!(report.scrubbed_content_hash, expected_hash);
    assert_eq!(
        report.vault_ref,
        format!("vault_ref://genai/{}", hex::encode(expected_hash))
    );
}

#[test]
fn test_m7b_challenge_causal_spans_and_process_socket_binding() {
    let monitor = GenAiBehavioralMonitor::default();
    let proc_key = ProcessInstanceKey::new(12345, 99998888);
    let session_id = "m7b_challenge_causal_spans";
    monitor.start_session(session_id, make_test_identity(proc_key, vec![CapabilityLevel::L1ReadOnlySandbox, CapabilityLevel::L2LocalWorkspaceFs]));

    let trace_id = "trace_m7b_audit_100".to_string();

    // Span 1: UserRequest
    monitor.record_span(
        session_id,
        GenAiSpan {
            span_id: "span_req_1".to_string(),
            trace_id: trace_id.clone(),
            session_id: session_id.to_string(),
            parent_span_id: None,
            kind: GenAiSpanKind::UserRequest,
            system: "anthropic".to_string(),
            model: "claude-3-5-sonnet".to_string(),
            prompt_version: "sys_v3.2".to_string(),
            operation_name: "chat".to_string(),
            tool_name: None,
            tool_call_id: None,
            start_time_utc: Utc::now(),
            end_time_utc: Some(Utc::now()),
            document_digest: None,
            document_sensitivity: None,
            correlated_process: Some(proc_key),
            correlated_network: None,
            scrubbed_content_hash: [0x11; 32],
            vault_ref: Some("vault_ref://genai/req1".to_string()),
        },
    );

    // Span 2: ModelCall with bound Network Socket
    let socket = CorrelatedNetworkSocket {
        protocol: "tcp".to_string(),
        local_addr: None,
        remote_addr: None,
        destination_host: "api.anthropic.com".to_string(),
        destination_port: 443,
        dns_query: Some("api.anthropic.com".to_string()),
        tls_sni: Some("api.anthropic.com".to_string()),
    };
    monitor.record_span(
        session_id,
        GenAiSpan {
            span_id: "span_call_2".to_string(),
            trace_id: trace_id.clone(),
            session_id: session_id.to_string(),
            parent_span_id: Some("span_req_1".to_string()),
            kind: GenAiSpanKind::ModelCall,
            system: "anthropic".to_string(),
            model: "claude-3-5-sonnet".to_string(),
            prompt_version: "sys_v3.2".to_string(),
            operation_name: "chat_completion".to_string(),
            tool_name: None,
            tool_call_id: None,
            start_time_utc: Utc::now(),
            end_time_utc: Some(Utc::now()),
            document_digest: None,
            document_sensitivity: None,
            correlated_process: Some(proc_key),
            correlated_network: Some(socket.clone()),
            scrubbed_content_hash: [0x22; 32],
            vault_ref: Some("vault_ref://genai/call2".to_string()),
        },
    );

    let session = monitor.get_session(session_id).expect("Session must exist");
    assert_eq!(session.spans.len(), 2);
    assert_eq!(session.spans[0].correlated_process.unwrap(), proc_key);
    assert_eq!(
        session.spans[1].correlated_network.as_ref().unwrap().destination_host,
        "api.anthropic.com"
    );
}

#[test]
fn test_m7b_challenge_voter_quorum_alerts_on_severe_violations() {
    let monitor = GenAiBehavioralMonitor::default();
    let proc_key = ProcessInstanceKey::new(4455, 667788);
    let session_id = "m7b_challenge_quorum";

    let quorum_received = Arc::new(AtomicUsize::new(0));
    let q_clone = quorum_received.clone();

    monitor.add_voter_quorum_sink(Arc::new(move |alert: VoterQuorumAlert| {
        assert_eq!(alert.target, proc_key);
        assert!(alert.voter_confidence_bp >= 6667);
        q_clone.fetch_add(1, Ordering::SeqCst);
    }));

    monitor.start_session(session_id, make_test_identity(proc_key, vec![CapabilityLevel::L1ReadOnlySandbox]));

    // Attempt unauthorized L5 host administration tool
    let pending_unauth = PendingToolExecution {
        tool_name: "install_kernel_driver".to_string(),
        tool_call_id: "call_driver_9".to_string(),
        arguments_json: serde_json::json!({"driver": "malicious.sys"}),
        destination_host: None,
        destination_port: None,
        required_capability: CapabilityLevel::L5HostAdminPrivileged,
        is_egress_upload: false,
        target_path: None,
    };

    let verdict = monitor.evaluate_tool_pre_execution(session_id, &pending_unauth);
    assert!(verdict.is_blocked());
    assert_eq!(quorum_received.load(Ordering::SeqCst), 1);
}

#[test]
fn test_m7b_challenge_behavior_drift_alerts() {
    let monitor = GenAiBehavioralMonitor::default();
    let cohort = ModelPromptCohort::new("claude-3-5-sonnet", "v2.0_hardened");

    // Establish healthy baseline: 5% violation rate, 95% success, 98% compliance
    monitor.drift_monitor.set_baseline(&cohort, 0.05, 0.95, 0.98);

    let mut drift_alert = None;
    for i in 0..12 {
        let alert = monitor.record_model_call_metrics(
            "claude-3-5-sonnet",
            "v2.0_hardened",
            80,
            false,
            0.50,
            0.65,
            Some("bash_exec"),
            if i % 2 == 0 { Some("InternalDocToUnapprovedUpload") } else { Some("UnexpectedDestination") },
        );
        if alert.is_some() {
            drift_alert = alert;
        }
    }

    assert!(drift_alert.is_some(), "Drift alert must trigger on violation spike");
    let alert = drift_alert.unwrap();
    assert_eq!(alert.drift_type, DriftType::ViolationSpike);
    assert_eq!(alert.severity, DriftSeverity::Critical);
    assert!(alert.divergence_score >= 0.15);
}
