//! # HITL Cognitive Red-Team Interceptor & Oso/AWS Agent Containment Routes (Feature F31 + Oso/AWS R1-R5)
//!
//! Exposes control plane endpoints under `/api/hitl/*` and `/api/oso-aws-containment/*` for:
//! - Listing pending actions with stripped blast radius (`GET /api/hitl/pending`)
//! - Fetching polymorphic verification challenges (`GET /api/hitl/challenge/:id`)
//! - Submitting actions for cognitive red-team evaluation (`POST /api/hitl/evaluate`)
//! - Submitting operator challenge solution and dual-custody approval (`POST /api/hitl/approve`)
//! - Rejecting deceptive or non-compliant actions (`POST /api/hitl/reject`)
//! - Telemetry status reporting (`GET /api/hitl/status`)
//! - Oso 3-Way Intersection + AWS R1-R5 Containment Watchdog status (`GET /api/oso-aws-containment/status`)
//! - Running the 4-Invariant Independent Watchdog & Breach Drill (`POST /api/oso-aws-containment/watchdog-verify`)
//! - Evaluating Oso 3-Way Delegated Intersection + AWS R4/R5 Velocity Alarm (`POST /api/oso-aws-containment/evaluate-intersection`)

use std::collections::BTreeSet;

use axum::{
    extract::Path,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use osoosi_agent_anomaly::cognitive_redteam::{
    global_cognitive_redteam, CognitiveRedTeamAssessment, CognitiveRedTeamStatus,
    PendingExecutionGraphNode,
};
use osoosi_agent_anomaly::oso_aws_containment::{
    global_oso_aws_containment, ContainmentEnvironmentSnapshot, DelegatingUserContext,
    SandboxEgressRule, SandboxRouteEntry, TaskScopeEnvelope,
};
use osoosi_runtime::mesh_guard::MeshTaintLevel;
use osoosi_types::ArmRole;
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
        .route(
            "/api/oso-aws-containment/status",
            get(get_oso_aws_containment_status),
        )
        .route(
            "/api/oso-aws-containment/watchdog-verify",
            post(post_oso_aws_watchdog_verify),
        )
        .route(
            "/api/oso-aws-containment/evaluate-intersection",
            post(post_oso_aws_evaluate_intersection),
        )
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

async fn get_oso_aws_containment_status() -> impl IntoResponse {
    let engine = global_oso_aws_containment();
    let now = Utc::now();
    let baseline = ContainmentEnvironmentSnapshot::default();
    let watchdog =
        engine.verify_four_containment_invariants("octopus-agent-cluster", &baseline, now);
    let cluster = engine.get_cluster_state("octopus-agent-cluster");
    let kill_history = engine.kill_switch_reports("octopus-agent-cluster");

    (
        StatusCode::OK,
        Json(json!({
            "engine": "Oso 3-Way Intersection + AWS R1-R5 Containment-Response",
            "oso_capabilities": [
                "3-Way Delegated Identity Intersection: Perm(User) ∩ Cap(AgentRole) ∩ Scope(Task)",
                "Pre-Retrieval RAG Context Filtering (ReBAC Owner/Shared ACL + Classification Clearance)",
                "MCP Tool-Call Parameter & Row-Ownership Gate (Valid JSON != Valid Authority)",
                "Out-of-Band HMAC-SHA256 HITL Step-Up Ticket Verification (subtle::ConstantTimeEq)"
            ],
            "aws_r1_r5_controls": {
                "R1_trust_separation": "Isolated VPC/Namespace + DNS Firewall (*.amazonaws.com / localhost NXDOMAIN lock)",
                "R2_behavioral_monitoring": "Continuous Runtime Process, Network & File Telemetry",
                "R3_four_invariant_watchdog": "Security Group (0.0.0.0/0 & ::/0), Route Table (igw-*), IAM Policy Count + ARN Set Swap Detection, DNS Firewall COMPLETE check",
                "R4_adversarial_audit_isolation": "Explicit Deny on iam:*, cloudtrail:*, cloudwatch:*, guardduty:*, osoosi:watchdog:*, osoosi:audit:*",
                "R5_capability_envelope_alarm": {
                    "denied_threshold": engine.r5_denied_threshold,
                    "window_seconds": engine.r5_window_secs
                }
            },
            "watchdog_assessment": watchdog,
            "cluster_state": cluster,
            "kill_switch_history": kill_history
        })),
    )
        .into_response()
}

#[derive(Debug, Deserialize, Default)]
pub struct WatchdogVerifyRequest {
    #[serde(default)]
    pub drill_mode: Option<String>,
}

async fn post_oso_aws_watchdog_verify(Json(req): Json<WatchdogVerifyRequest>) -> impl IntoResponse {
    let engine = global_oso_aws_containment();
    let now = Utc::now();
    let mut snap = ContainmentEnvironmentSnapshot::default();

    match req.drill_mode.as_deref() {
        Some("restore_healthy") => {
            engine.register_agent_service(
                "octopus-agent-cluster",
                "octopus-worker-service",
                2,
                vec![
                    "task-arm-01-doc-ingest".to_string(),
                    "task-arm-02-network-egress".to_string(),
                ],
            );
        }
        Some("policy_swap") => {
            snap.actual_attached_policy_arns.clear();
            snap.actual_attached_policy_arns
                .insert("arn:aws:iam::aws:policy/AdministratorAccess".to_string());
        }
        Some("open_egress") => {
            snap.egress_rules.push(SandboxEgressRule {
                rule_id: "sgr-rogue-open-0000".to_string(),
                protocol: "tcp".to_string(),
                cidr_ipv4: Some("0.0.0.0/0".to_string()),
                cidr_ipv6: None,
                description: "Simulated unrestricted outbound egress breach".to_string(),
            });
        }
        Some("igw_route") => {
            snap.route_entries.push(SandboxRouteEntry {
                route_table_id: "rtb-osoosi-isolated".to_string(),
                destination_cidr: "0.0.0.0/0".to_string(),
                gateway_id: "igw-0breachroute".to_string(),
            });
        }
        Some("dns_firewall_removed") => {
            snap.dns_firewall_associations.clear();
        }
        _ => {}
    }

    let report = engine.verify_four_containment_invariants("octopus-agent-cluster", &snap, now);
    let cluster = engine.get_cluster_state("octopus-agent-cluster");

    (
        StatusCode::OK,
        Json(json!({
            "watchdog_report": report,
            "cluster_state": cluster
        })),
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
pub struct EvaluateIntersectionRequest {
    #[serde(default = "default_agent_id")]
    pub agent_id: String,
    #[serde(default = "default_role_name")]
    pub arm_role: String,
    #[serde(default = "default_user_id")]
    pub user_id: String,
    pub user_permissions: Vec<String>,
    pub user_allowed_resources: Vec<String>,
    pub task_allowed_actions: Vec<String>,
    pub task_allowed_prefixes: Vec<String>,
    pub action: String,
    pub resource: String,
}

fn default_role_name() -> String {
    "UntrustedDocIngest".to_string()
}
fn default_user_id() -> String {
    "operator@osoosi.local".to_string()
}

async fn post_oso_aws_evaluate_intersection(
    Json(req): Json<EvaluateIntersectionRequest>,
) -> impl IntoResponse {
    let engine = global_oso_aws_containment();
    let now = Utc::now();

    let role = match req.arm_role.as_str() {
        "AccountingLedgerWrite" => ArmRole::AccountingLedgerWrite,
        "NetworkEgress" => ArmRole::NetworkEgress,
        "KernelLevelSentinel" => ArmRole::KernelLevelSentinel,
        "CedarPolicyEvaluation" => ArmRole::CedarPolicyEvaluation,
        _ => ArmRole::UntrustedDocIngest,
    };

    let user = DelegatingUserContext {
        user_id: req.user_id,
        permissions: req.user_permissions.into_iter().collect::<BTreeSet<_>>(),
        allowed_resources: req
            .user_allowed_resources
            .into_iter()
            .collect::<BTreeSet<_>>(),
        max_clearance_tier: 2,
    };

    let task = TaskScopeEnvelope {
        task_id: "live-ui-task".to_string(),
        workspace_id: "default-workspace".to_string(),
        allowed_actions: req
            .task_allowed_actions
            .into_iter()
            .collect::<BTreeSet<_>>(),
        allowed_resource_prefixes: req.task_allowed_prefixes,
        max_query_limit: 50,
        allow_production_mutation: false,
    };

    let decision = engine.evaluate_intersection_authority(
        &req.agent_id,
        "octopus-agent-cluster",
        &role,
        &user,
        &task,
        &req.action,
        &req.resource,
        now,
    );
    let recent_denied = engine.recent_denied_count(&req.agent_id, now);
    let cluster = engine.get_cluster_state("octopus-agent-cluster");

    (
        StatusCode::OK,
        Json(json!({
            "decision": decision,
            "recent_denied_60s": recent_denied,
            "r5_threshold": engine.r5_denied_threshold,
            "cluster_state": cluster
        })),
    )
        .into_response()
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
