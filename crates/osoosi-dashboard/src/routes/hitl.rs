//! # HITL Cognitive Red-Team Interceptor Routes (Feature F31)
//!
//! Exposes control plane endpoints under `/api/hitl/*` for:
//! - Listing pending actions with stripped blast radius (`GET /api/hitl/pending`)
//! - Fetching polymorphic verification challenges (`GET /api/hitl/challenge/:id`)
//! - Submitting actions for cognitive red-team evaluation (`POST /api/hitl/evaluate`)
//! - Submitting operator challenge solution and dual-custody approval (`POST /api/hitl/approve`)
//! - Rejecting deceptive or non-compliant actions (`POST /api/hitl/reject`)
//! - Telemetry status reporting (`GET /api/hitl/status`)

use axum::{
    extract::Path,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use osoosi_agent_anomaly::cognitive_redteam::{
    global_cognitive_redteam, CognitiveRedTeamAssessment, CognitiveRedTeamStatus,
    PendingExecutionGraphNode,
};
use osoosi_runtime::mesh_guard::MeshTaintLevel;
use serde::Deserialize;
use serde_json::json;

use crate::DashboardState;

pub fn routes() -> Router<DashboardState> {
    Router::new()
        .route("/api/hitl/pending", get(get_hitl_pending))
        .route("/api/hitl/challenge/:id", get(get_hitl_challenge))
        .route("/api/hitl/evaluate", post(post_hitl_evaluate))
        .route("/api/hitl/approve", post(post_hitl_approve))
        .route("/api/hitl/reject", post(post_hitl_reject))
        .route("/api/hitl/status", get(get_hitl_status))
}

async fn get_hitl_pending() -> Json<Vec<CognitiveRedTeamAssessment>> {
    let pending = global_cognitive_redteam().get_pending_actions();
    Json(pending)
}

async fn get_hitl_challenge(Path(request_id): Path<String>) -> impl IntoResponse {
    if let Some(challenge) = global_cognitive_redteam().get_public_challenge(&request_id) {
        (StatusCode::OK, Json(json!(challenge))).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": format!("No active challenge found for request '{}'", request_id)
            })),
        )
            .into_response()
    }
}

#[derive(Debug, Deserialize)]
pub struct EvaluateActionRequest {
    #[serde(default = "default_session_id")]
    pub session_id: String,
    #[serde(default = "default_arm_id")]
    pub arm_id: usize,
    #[serde(default = "default_gen")]
    pub arm_generation: u64,
    #[serde(default = "default_agent_id")]
    pub agent_id: String,
    #[serde(default = "default_corr_id")]
    pub correlation_id: String,
    pub tool_name: String,
    pub target_resource: String,
    #[serde(default)]
    pub command_args: String,
    #[serde(default)]
    pub stated_justification: String,
    #[serde(default)]
    pub incoming_taint: Option<String>,
    #[serde(default)]
    pub user_objective: String,
}

fn default_session_id() -> String {
    format!("sess-{}", uuid::Uuid::new_v4())
}
fn default_arm_id() -> usize {
    1
}
fn default_gen() -> u64 {
    1
}
fn default_agent_id() -> String {
    "agent_worker".to_string()
}
fn default_corr_id() -> String {
    format!("corr-{}", uuid::Uuid::new_v4())
}

async fn post_hitl_evaluate(Json(payload): Json<EvaluateActionRequest>) -> impl IntoResponse {
    let taint = match payload.incoming_taint.as_deref() {
        Some("UntrustedExternal") | Some("untrusted") => MeshTaintLevel::UntrustedExternal,
        Some("Suspect") | Some("suspect") => MeshTaintLevel::Suspect,
        Some("Quarantined") | Some("quarantined") => MeshTaintLevel::Quarantined,
        _ => MeshTaintLevel::TrustedInternal,
    };

    let node = PendingExecutionGraphNode {
        session_id: payload.session_id,
        arm_id: payload.arm_id,
        arm_generation: payload.arm_generation,
        agent_id: payload.agent_id,
        correlation_id: payload.correlation_id,
        tool_name: payload.tool_name,
        target_resource: payload.target_resource,
        command_args: payload.command_args,
        stated_justification: payload.stated_justification,
        incoming_taint: taint,
        user_objective: payload.user_objective,
    };

    let assessment = global_cognitive_redteam().evaluate_pending_action(node);
    (StatusCode::OK, Json(assessment)).into_response()
}

#[derive(Debug, Deserialize)]
pub struct ApproveActionRequest {
    pub request_id: String,
    pub operator_id: String,
    pub selected_option_index: usize,
    pub challenge_nonce: String,
    pub confirmation_token: Option<String>,
}

async fn post_hitl_approve(Json(payload): Json<ApproveActionRequest>) -> impl IntoResponse {
    let res = global_cognitive_redteam().submit_approval(
        &payload.request_id,
        &payload.operator_id,
        payload.selected_option_index,
        &payload.challenge_nonce,
        payload.confirmation_token.as_deref(),
    );

    match res {
        Ok(approval_state) => (
            StatusCode::OK,
            Json(json!({
                "status": "success",
                "request_id": payload.request_id,
                "approval_state": approval_state,
            })),
        )
            .into_response(),
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": err.to_string(),
                "request_id": payload.request_id,
            })),
        )
            .into_response(),
    }
}

#[derive(Debug, Deserialize)]
pub struct RejectActionRequest {
    pub request_id: String,
    pub operator_id: String,
    pub reason: String,
}

async fn post_hitl_reject(Json(payload): Json<RejectActionRequest>) -> impl IntoResponse {
    let res = global_cognitive_redteam().submit_rejection(
        &payload.request_id,
        &payload.operator_id,
        &payload.reason,
    );

    match res {
        Ok(approval_state) => (
            StatusCode::OK,
            Json(json!({
                "status": "rejected",
                "request_id": payload.request_id,
                "approval_state": approval_state,
            })),
        )
            .into_response(),
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": err.to_string(),
                "request_id": payload.request_id,
            })),
        )
            .into_response(),
    }
}

async fn get_hitl_status() -> Json<CognitiveRedTeamStatus> {
    let status = global_cognitive_redteam().get_status();
    Json(status)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_hitl_routes_construction() {
        let _router = routes();
        let status = global_cognitive_redteam().get_status();
        let _ = status.total_evaluations;
    }
}
