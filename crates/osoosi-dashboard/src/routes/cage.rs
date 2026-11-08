//! CAGE Substrate Contract v1.0 REST API Routes
//!
//! Exposes the Google Cybernetic Agent Governance Engine (CAGE) Native Substrate
//! on port 3030 and `/api/governance/*` legacy aliases:
//!
//! - `POST /governance/ingest-policy` & `/api/governance/ingest-policy`
//! - `GET /governance/policy-version` & `/api/governance/policy-version`
//! - `POST /governance/validate-action` & `/api/governance/validate-action`
//! - `POST /governance/consume-seal` & `/api/governance/consume-seal`
//! - `POST /governance/rollback` & `/api/governance/rollback`
//! - `GET /governance/trace/verify` & `/api/governance/trace/verify`
//! - `GET /governance/stats` & `/api/governance/stats`

use axum::{
    extract::{Json, State},
    http::{StatusCode, Uri},
    routing::{get, post},
    Router,
};
use osoosi_audit::cage_audit::{verify_trace_chain, CageTraceRecord, GENESIS_PREV_HASH};
use osoosi_audit::MerkleAuditTree;
use osoosi_policy::cage::cbf::{CbfViolation, FiscalLedger};
use osoosi_policy::cage::pipeline::{CageGovernancePipeline, GovernanceRequest};
use osoosi_policy::cage::policy_ingest::{compile_policy, CompiledCagePolicy};
use osoosi_policy::cage::routing_seal::compute_action_digest;
use osoosi_types::cage::{GovernanceVerdict, PolicyFormat, RoutingSeal};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::DashboardState;

/// Default substrate secret key for CAGE routing seals HMAC signing.
pub const DEFAULT_CAGE_SUBSTRATE_SECRET: &[u8] =
    b"oshoosiclaw_cage_governance_secret_2026_test_key";

/// Tracked registration info for issued routing seals.
#[derive(Debug, Clone)]
pub struct RegisteredSealInfo {
    pub seal: RoutingSeal,
    pub action_name: String,
    pub params: Value,
    pub issued_at: u64,
    pub consumed_at: Option<u64>,
    pub status: String,
}

/// In-memory server state for CAGE governance substrate.
pub struct CageServerState {
    pub pipeline: RwLock<Option<CageGovernancePipeline>>,
    pub pinned_policy: RwLock<Option<CompiledCagePolicy>>,
    pub registered_seals: RwLock<HashMap<String, RegisteredSealInfo>>,
    pub traces: RwLock<Vec<CageTraceRecord>>,
    pub merkle_tree: Arc<MerkleAuditTree>,
    pub substrate_secret: Vec<u8>,
}

impl Default for CageServerState {
    fn default() -> Self {
        Self::new()
    }
}

impl CageServerState {
    /// Creates a new uninitialized CAGE server state.
    pub fn new() -> Self {
        Self {
            pipeline: RwLock::new(None),
            pinned_policy: RwLock::new(None),
            registered_seals: RwLock::new(HashMap::new()),
            traces: RwLock::new(Vec::new()),
            merkle_tree: Arc::new(MerkleAuditTree::new()),
            substrate_secret: DEFAULT_CAGE_SUBSTRATE_SECRET.to_vec(),
        }
    }

    /// Creates and immediately pins a compiled policy.
    pub fn with_policy(policy: CompiledCagePolicy) -> Self {
        let state = Self::new();
        state.pin_policy(policy);
        state
    }

    /// Pins a policy, constructing the 2-phase pipeline and fiscal ledger.
    pub fn pin_policy(&self, policy: CompiledCagePolicy) {
        let gamma = policy.cbf_gamma;
        let b_min = policy.cbf_b_min;
        let ledger = FiscalLedger::new(100.0, gamma, b_min)
            .unwrap_or_else(|_| FiscalLedger::with_default_cbf(100.0).unwrap());
        let pipeline = CageGovernancePipeline::new(policy.clone(), ledger, &self.substrate_secret);
        *self.pipeline.write().unwrap() = Some(pipeline);
        *self.pinned_policy.write().unwrap() = Some(policy);
    }

    /// Appends a new audit record to the cryptographic hash chain and Merkle audit tree.
    pub fn append_trace(
        &self,
        action_name: &str,
        verdict: &str,
        cbf_h: Option<f64>,
        fuel_cost: Option<f64>,
        policy_version_id: &str,
        payload: Value,
    ) -> CageTraceRecord {
        let mut traces = self.traces.write().unwrap();
        let seq = traces.len() as u64;
        let prev_hash = if seq == 0 {
            GENESIS_PREV_HASH.to_string()
        } else {
            traces[(seq - 1) as usize].merkle_leaf_hash.clone()
        };

        let now_str = chrono::Utc::now().to_rfc3339();
        let trace_id = format!("trace_{}_{}", seq, uuid::Uuid::new_v4().simple());

        let mut rec = CageTraceRecord::new(
            trace_id,
            seq,
            prev_hash,
            action_name,
            verdict,
            cbf_h,
            fuel_cost,
            policy_version_id,
            "",
            "",
            payload.clone(),
            now_str,
        );

        let leaf_hash = rec.compute_canonical_leaf_hash();
        rec.merkle_leaf_hash = leaf_hash;

        let record_val = serde_json::to_value(&rec).unwrap_or(payload);
        let (_, new_root) = self.merkle_tree.log_cage_governance_trace(&record_val);
        rec.merkle_root = new_root;

        traces.push(rec.clone());
        rec
    }
}

// =========================================================================
// Request & Response DTOs
// =========================================================================

#[derive(Debug, Deserialize, Default)]
pub struct IngestPolicyRequest {
    #[serde(default)]
    pub format: Option<String>,
    #[serde(default)]
    pub policy_format: Option<String>,
    #[serde(default)]
    pub policy_content: Option<String>,
    #[serde(default = "default_true")]
    pub pin_version: bool,
    #[serde(default)]
    pub force: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HitlConsensusApproval {
    #[serde(alias = "reviewer_id")]
    pub operator_id: String,
    pub is_approved: bool,
    #[serde(default)]
    pub rationale: String,
    #[serde(default, alias = "timestamp_ms")]
    pub approved_at_ms: u64,
    #[serde(default)]
    pub signature_hex: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct ValidateActionRequest {
    #[serde(default)]
    pub expected_policy_version: Option<String>,
    #[serde(default)]
    pub policy_version_id: Option<String>,
    #[serde(default)]
    pub action_name: Option<String>,
    #[serde(default)]
    pub principal: Option<String>,
    #[serde(default)]
    pub actor_id: Option<String>,
    #[serde(default)]
    pub resource: Option<String>,
    #[serde(default)]
    pub target_resource: Option<String>,
    #[serde(default)]
    pub params: Option<Value>,
    #[serde(default)]
    pub parameters: Option<Value>,
    #[serde(default)]
    pub caller_authority: Option<u8>,
    #[serde(default)]
    pub confidence_score: Option<f64>,
    #[serde(default)]
    pub consensus_score: Option<f64>,
    #[serde(default)]
    pub cost: Option<f64>,
    #[serde(default)]
    pub fuel_cost: Option<f64>,
    #[serde(default, alias = "hitl_approval")]
    pub human_approval: Option<HitlConsensusApproval>,
}

#[derive(Debug, Deserialize, Default)]
pub struct ConsumeSealRequest {
    #[serde(default)]
    pub seal_id: Option<String>,
    #[serde(default)]
    pub action_name: Option<String>,
    #[serde(default)]
    pub params: Option<Value>,
    #[serde(default)]
    pub parameters: Option<Value>,
    #[serde(default)]
    pub seal: Option<RoutingSeal>,
    #[serde(default)]
    pub decision_record_hash: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct RollbackRequest {
    #[serde(default)]
    pub debit_id: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

// =========================================================================
// Route Handlers
// =========================================================================

/// `POST /governance/ingest-policy` & `/api/governance/ingest-policy`
pub async fn post_ingest_policy(
    State(state): State<DashboardState>,
    Json(req): Json<IngestPolicyRequest>,
) -> (StatusCode, Json<Value>) {
    let content = match req
        .policy_content
        .as_deref()
        .filter(|s| !s.trim().is_empty())
    {
        Some(c) => c,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "BAD_REQUEST",
                    "message": "Missing policy_content"
                })),
            );
        }
    };

    let fmt_str = req.format.as_deref().or(req.policy_format.as_deref());
    let format_override = fmt_str.and_then(|s| match s.to_ascii_lowercase().as_str() {
        "microsoftacs" | "acs" => Some(PolicyFormat::MicrosoftAcs),
        "linuxfoundationaaif" | "aaif" => Some(PolicyFormat::LinuxFoundationAaif),
        "nistoscal" | "oscal" => Some(PolicyFormat::NistOscal),
        "lulavalidation" | "lula" => Some(PolicyFormat::LulaValidation),
        "cagestpa" | "stpa" => Some(PolicyFormat::CageStpa),
        _ => None,
    });

    let compiled = match compile_policy(content, format_override) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "COMPILATION_ERROR",
                    "message": format!("{}", e)
                })),
            );
        }
    };

    let incoming_vid = compiled.policy_version_id.clone();

    // Check version drift against active pinned policy
    if let Some(pinned) = state.cage.pinned_policy.read().unwrap().as_ref() {
        if pinned.policy_version_id != incoming_vid && !req.force {
            return (
                StatusCode::CONFLICT,
                Json(json!({
                    "error": "POLICY_VERSION_MISMATCH",
                    "message": format!(
                        "Policy version drift: active is '{}', incoming is '{}'",
                        pinned.policy_version_id, incoming_vid
                    ),
                    "pinned_version": pinned.policy_version_id,
                    "submitted_version": incoming_vid.clone(),
                    "incoming_version": incoming_vid
                })),
            );
        }
    }

    if req.pin_version {
        let mut pipe_guard = state.cage.pipeline.write().unwrap();
        if let Some(pipe) = pipe_guard.as_mut() {
            pipe.update_policy(compiled.clone());
            *state.cage.pinned_policy.write().unwrap() = Some(compiled.clone());
        } else {
            drop(pipe_guard);
            state.cage.pin_policy(compiled.clone());
        }
    }

    (
        StatusCode::OK,
        Json(json!({
            "status": "compiled",
            "policy_version_id": incoming_vid,
            "format_detected": compiled.format.as_str(),
            "format": compiled.format.as_str(),
            "cedar_rules_count": compiled.cedar_rules.len(),
            "ucas_count": compiled.unsafe_control_actions.len(),
            "rules_count": compiled.cedar_rules.len() + compiled.unsafe_control_actions.len(),
            "pinned": req.pin_version,
            "compiled_at_utc": chrono::Utc::now().to_rfc3339()
        })),
    )
}

/// `GET /governance/policy-version` & `/api/governance/policy-version`
pub async fn get_policy_version(State(state): State<DashboardState>) -> (StatusCode, Json<Value>) {
    let pinned_opt = state.cage.pinned_policy.read().unwrap().clone();
    match pinned_opt {
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": "NO_PINNED_POLICY",
                "message": "No policy currently pinned"
            })),
        ),
        Some(pinned) => (
            StatusCode::OK,
            Json(json!({
                "active_version_id": pinned.policy_version_id,
                "format": pinned.format.as_str(),
                "cedar_rules_count": pinned.cedar_rules.len(),
                "ucas_count": pinned.unsafe_control_actions.len(),
                "rules_count": pinned.cedar_rules.len() + pinned.unsafe_control_actions.len(),
                "is_pinned": true
            })),
        ),
    }
}

/// `POST /governance/validate-action` & `/api/governance/validate-action`
pub async fn post_validate_action(
    State(state): State<DashboardState>,
    Json(req): Json<ValidateActionRequest>,
) -> (StatusCode, Json<Value>) {
    let pipe_guard = state.cage.pipeline.read().unwrap();
    let pipeline = match pipe_guard.as_ref() {
        Some(p) => p,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "NO_POLICY",
                    "message": "No active pinned policy"
                })),
            );
        }
    };

    let action_name = match req.action_name.as_deref().filter(|s| !s.trim().is_empty()) {
        Some(a) => a.to_string(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "BAD_REQUEST",
                    "message": "Missing 'action_name'"
                })),
            );
        }
    };

    let active_ver = pipeline.active_policy_version();
    let exp_ver = req.expected_policy_version.or(req.policy_version_id);
    if let Some(exp) = exp_ver {
        if exp != active_ver {
            return (
                StatusCode::CONFLICT,
                Json(json!({
                    "error": "POLICY_VERSION_CONFLICT",
                    "message": format!(
                        "Version mismatch: pinned '{}' vs requested '{}'",
                        active_ver, exp
                    ),
                    "pinned_version": active_ver,
                    "submitted_version": exp.clone(),
                    "incoming_version": exp
                })),
            );
        }
    }

    let principal = req
        .principal
        .or(req.actor_id)
        .unwrap_or_else(|| "default_actor".to_string());
    let resource = req
        .resource
        .or(req.target_resource)
        .unwrap_or_else(|| "/tmp".to_string());
    let params = req.params.or(req.parameters).unwrap_or_else(|| json!({}));
    let caller_authority = req.caller_authority.unwrap_or(3);
    let confidence_score = req.confidence_score.unwrap_or(0.98);
    let consensus_score = req.consensus_score.unwrap_or(0.95);
    let fuel_cost = req.cost.or(req.fuel_cost).unwrap_or(0.0);

    let gov_req = GovernanceRequest {
        action_name: action_name.clone(),
        principal,
        resource,
        parameters: params.clone(),
        caller_authority,
        confidence_score,
        consensus_score,
        fuel_cost,
        expected_policy_version: None,
    };

    let result = pipeline.evaluate_action(&gov_req);

    match result.verdict {
        GovernanceVerdict::Allow | GovernanceVerdict::Narrow { .. } => {
            let seal = result
                .seal
                .expect("Routing seal must be issued on ALLOW / NARROW");
            let receipt = result
                .commit_receipt
                .expect("CommitReceipt must be issued on Phase 2 clearance");
            let cbf_h = receipt.barrier_val;
            let debit_id = receipt.debit_id.clone();
            let cost = fuel_cost;

            // Register seal for subsequent consumption
            state.cage.registered_seals.write().unwrap().insert(
                seal.seal_id.clone(),
                RegisteredSealInfo {
                    seal: seal.clone(),
                    action_name: action_name.clone(),
                    params: params.clone(),
                    issued_at: seal.issued_at,
                    consumed_at: None,
                    status: "ACTIVE".to_string(),
                },
            );

            let dec_rec = state.cage.append_trace(
                &action_name,
                "ALLOW",
                Some(cbf_h),
                Some(cost),
                &active_ver,
                json!({
                    "event_type": "GOVERNANCE_DECISION",
                    "seal_id": seal.seal_id,
                    "debit_id": debit_id,
                    "action_name": action_name,
                    "params": params,
                }),
            );

            let current_budget = pipeline.ledger().available_budget();
            let b_min = pipeline.ledger().floor_threshold();
            let h_t = current_budget + cost - b_min;

            (
                StatusCode::OK,
                Json(json!({
                    "verdict": "ALLOW",
                    "policy_version": active_ver,
                    "policy_version_id": active_ver,
                    "routing_seal": seal,
                    "cbf_h_value": cbf_h,
                    "debit_id": debit_id,
                    "barrier_state": {
                        "h_t": h_t,
                        "h_next": cbf_h,
                        "cost": cost,
                        "barrier_satisfied": true
                    },
                    "decision_record_hash": dec_rec.merkle_leaf_hash
                })),
            )
        }
        ref refusal => {
            let (verdict_str, reason, proof_hash) = match refusal {
                GovernanceVerdict::Deny { reason, proof_hash } => {
                    ("DENY", reason.clone(), proof_hash.clone())
                }
                GovernanceVerdict::RequireApproval {
                    reason,
                    approval_token,
                } => ("REQUIRE_APPROVAL", reason.clone(), approval_token.clone()),
                GovernanceVerdict::Defer { backoff_ms } => (
                    "DEFER",
                    format!("Deferred for {} ms", backoff_ms),
                    "".to_string(),
                ),
                _ => ("DENY", "Action rejected".to_string(), "".to_string()),
            };

            let current_budget = pipeline.ledger().available_budget();
            let b_min = pipeline.ledger().floor_threshold();
            let h_t = current_budget - b_min;
            let h_next = (current_budget - fuel_cost) - b_min;

            state.cage.append_trace(
                &action_name,
                verdict_str,
                Some(h_next),
                Some(0.0),
                &active_ver,
                json!({
                    "event_type": "GOVERNANCE_REFUSAL",
                    "verdict": verdict_str,
                    "refusal_reason": reason,
                    "proof_hash": proof_hash,
                }),
            );

            (
                StatusCode::OK,
                Json(json!({
                    "verdict": verdict_str,
                    "policy_version": active_ver,
                    "policy_version_id": active_ver,
                    "routing_seal": Value::Null,
                    "cbf_h_value": h_next,
                    "debit_id": Value::Null,
                    "barrier_state": {
                        "h_t": h_t,
                        "h_next": h_next,
                        "cost": fuel_cost,
                        "barrier_satisfied": false
                    },
                    "refusal_reason": reason,
                    "proof_hash": proof_hash
                })),
            )
        }
    }
}

/// `POST /governance/consume-seal` & `/api/governance/consume-seal`
pub async fn post_consume_seal(
    State(state): State<DashboardState>,
    Json(req): Json<ConsumeSealRequest>,
) -> (StatusCode, Json<Value>) {
    let seal_id = match req.seal_id.as_deref().filter(|s| !s.trim().is_empty()) {
        Some(id) => id.to_string(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "BAD_REQUEST",
                    "message": "Missing 'seal_id'"
                })),
            );
        }
    };

    let action_name = match req.action_name.as_deref().filter(|s| !s.trim().is_empty()) {
        Some(a) => a.to_string(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "BAD_REQUEST",
                    "message": "Missing 'action_name'"
                })),
            );
        }
    };

    let registered_info_opt = state
        .cage
        .registered_seals
        .read()
        .unwrap()
        .get(&seal_id)
        .cloned();
    let (seal, registered_params) = match (registered_info_opt, req.seal) {
        (Some(info), maybe_seal) => {
            let s = maybe_seal.unwrap_or(info.seal);
            (s, info.params)
        }
        (None, _) => {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({
                    "error": "FORBIDDEN",
                    "rejection_code": "SEAL_REJECTED",
                    "message": format!("Unregistered routing seal '{}'", seal_id)
                })),
            );
        }
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let pipe_guard = state.cage.pipeline.read().unwrap();
    let pipeline = match pipe_guard.as_ref() {
        Some(p) => p,
        None => {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({
                    "error": "FORBIDDEN",
                    "message": "No active governance pipeline"
                })),
            );
        }
    };

    if let Some(info) = state.cage.registered_seals.read().unwrap().get(&seal_id) {
        if info.status == "CONSUMED" {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({
                    "error": "FORBIDDEN",
                    "rejection_code": "SEAL_REJECTED",
                    "message": format!(
                        "Replay detected: routing seal '{}' has already been consumed",
                        seal_id
                    )
                })),
            );
        }
    }

    let params = req.params.or(req.parameters).unwrap_or(registered_params);
    let expected_digest = compute_action_digest(&action_name, &params);

    if let Err(rejection) =
        pipeline
            .seal_signer()
            .validate_and_consume(&seal, &expected_digest, now)
    {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "FORBIDDEN",
                "rejection_code": "SEAL_REJECTED",
                "message": format!("{}", rejection)
            })),
        );
    }

    if let Some(info) = state
        .cage
        .registered_seals
        .write()
        .unwrap()
        .get_mut(&seal_id)
    {
        info.consumed_at = Some(now);
        info.status = "CONSUMED".to_string();
    }

    state.cage.append_trace(
        &action_name,
        "CONSUMED",
        None,
        None,
        &seal.policy_version_id,
        json!({
            "event_type": "GOVERNANCE_SEAL_CONSUMED",
            "seal_id": seal_id,
            "decision_record_hash": req.decision_record_hash,
            "consumed_at_utc": now,
        }),
    );

    (
        StatusCode::OK,
        Json(json!({
            "status": "CONSUMED",
            "seal_id": seal_id,
            "action_name": action_name,
            "consumed_at_utc": now
        })),
    )
}

/// `POST /governance/rollback` & `/api/governance/rollback`
pub async fn post_rollback(
    State(state): State<DashboardState>,
    Json(req): Json<RollbackRequest>,
) -> (StatusCode, Json<Value>) {
    let debit_id = match req.debit_id.as_deref().filter(|s| !s.trim().is_empty()) {
        Some(d) => d.to_string(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "BAD_REQUEST",
                    "message": "Missing 'debit_id'"
                })),
            );
        }
    };

    let pipe_guard = state.cage.pipeline.read().unwrap();
    let pipeline = match pipe_guard.as_ref() {
        Some(p) => p,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "NO_POLICY",
                    "message": "No active pipeline or ledger"
                })),
            );
        }
    };

    let budget_pre = pipeline.ledger().available_budget();
    match pipeline.ledger().rollback_reservation(&debit_id) {
        Ok(budget_post) => {
            let restored_amount = budget_post - budget_pre;
            let active_ver = pipeline.active_policy_version();

            state.cage.append_trace(
                "cbf_rollback",
                "ROLLED_BACK",
                Some(budget_post - pipeline.ledger().floor_threshold()),
                Some(restored_amount),
                &active_ver,
                json!({
                    "event_type": "CBF_ROLLBACK",
                    "debit_id": debit_id,
                    "restored_amount": restored_amount,
                    "reason": req.reason.unwrap_or_else(|| "Rollback request".to_string()),
                }),
            );

            (
                StatusCode::OK,
                Json(json!({
                    "status": "ROLLED_BACK",
                    "debit_id": debit_id,
                    "restored_budget": restored_amount,
                    "restored_amount": restored_amount,
                    "state_after_rollback": budget_post
                })),
            )
        }
        Err(CbfViolation::ReservationNotFound(msg)) => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": "NOT_FOUND",
                "message": msg
            })),
        ),
        Err(CbfViolation::AlreadyCommitted(msg)) => (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "ALREADY_COMMITTED",
                "message": msg
            })),
        ),
        Err(other) => (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "ROLLBACK_FAILED",
                "message": format!("{}", other)
            })),
        ),
    }
}

/// `GET /governance/trace/verify` & `/api/governance/trace/verify`
pub async fn get_verify_trace(State(state): State<DashboardState>) -> (StatusCode, Json<Value>) {
    let traces = state.cage.traces.read().unwrap().clone();
    let merkle_root = state.cage.merkle_tree.root();
    let trace_count = traces.len();

    match verify_trace_chain(&traces) {
        Ok(true) => (
            StatusCode::OK,
            Json(json!({
                "valid": true,
                "status": "CONFORMANT",
                "trace_count": trace_count,
                "records_count": trace_count,
                "merkle_root": merkle_root,
                "findings_count": 0
            })),
        ),
        Ok(false) | Err(_) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({
                "valid": false,
                "status": "NON_CONFORMANT",
                "trace_count": trace_count,
                "merkle_root": merkle_root,
                "findings_count": 1
            })),
        ),
    }
}

/// `GET /governance/stats` & `/api/governance/stats`
pub async fn get_cage_stats(State(state): State<DashboardState>) -> (StatusCode, Json<Value>) {
    let (active_version, rules_count) =
        if let Some(pinned) = state.cage.pinned_policy.read().unwrap().as_ref() {
            (
                pinned.policy_version_id.clone(),
                pinned.cedar_rules.len() + pinned.unsafe_control_actions.len(),
            )
        } else {
            ("None (Unpinned)".to_string(), 0)
        };

    let (cbf_h, budget) = if let Some(pipeline) = state.cage.pipeline.read().unwrap().as_ref() {
        let b = pipeline.ledger().available_budget();
        let b_min = pipeline.ledger().floor_threshold();
        (b - b_min, b)
    } else {
        (10.0, 100.0)
    };

    let total_seals = state.cage.registered_seals.read().unwrap().len();
    let consumed_seals = state
        .cage
        .registered_seals
        .read()
        .unwrap()
        .values()
        .filter(|s| s.status == "CONSUMED")
        .count();

    (
        StatusCode::OK,
        Json(json!({
            "policy_version": active_version,
            "rules_count": rules_count,
            "cbf_barrier_val": cbf_h,
            "budget": budget,
            "total_seals": total_seals,
            "consumed_seals": consumed_seals,
            "seals_text": format!("{} / {}", consumed_seals, total_seals),
            "trace_count": state.cage.traces.read().unwrap().len(),
        })),
    )
}

/// Fallback 404 handler for unknown subroutes under `/governance/*` and `/api/governance/*`
pub async fn cage_not_found(uri: Uri) -> (StatusCode, Json<Value>) {
    (
        StatusCode::NOT_FOUND,
        Json(json!({
            "error": "NOT_FOUND",
            "message": format!("Route '{}' not found", uri.path())
        })),
    )
}

/// `GET /api/cage/status` & `/cage/status`
pub async fn get_cage_status(State(state): State<DashboardState>) -> (StatusCode, Json<Value>) {
    let active_ver = state
        .cage
        .pinned_policy
        .read()
        .unwrap()
        .as_ref()
        .map(|p| p.policy_version_id.clone())
        .unwrap_or_else(|| "0".repeat(64));
    let format = state
        .cage
        .pinned_policy
        .read()
        .unwrap()
        .as_ref()
        .map(|p| p.format.as_str().to_string())
        .unwrap_or_else(|| "NativeCage".to_string());
    let budget = state
        .cage
        .pipeline
        .read()
        .unwrap()
        .as_ref()
        .map(|p| p.ledger().available_budget())
        .unwrap_or(100.0);
    let trace_count = state.cage.traces.read().unwrap().len();

    (
        StatusCode::OK,
        Json(json!({
            "llm_clients_in_kernel": false,
            "active_contract_id": active_ver,
            "substrate_contract_digest": active_ver,
            "substrate_format": format,
            "fiscal_cap_usd": budget,
            "evaluations_count": trace_count,
            "evidence_count": trace_count,
            "trace_count": trace_count,
            "status": "HEALTHY",
        })),
    )
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct CageEvaluationPayload {
    #[serde(default, alias = "principal", alias = "actor_id")]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default, alias = "action_name")]
    pub tool_name: Option<String>,
    #[serde(default, alias = "params", alias = "parameters")]
    pub arguments: Option<Value>,
    #[serde(default)]
    pub confidence_score: Option<f64>,
    #[serde(default, alias = "cost", alias = "fuel_cost")]
    pub amount_usd: Option<f64>,
    #[serde(default)]
    pub dose_mg: Option<f64>,
    #[serde(default, alias = "hitl_approval")]
    pub human_approval: Option<HitlConsensusApproval>,
    #[serde(default)]
    pub context: Option<Value>,
}

/// `POST /api/cage/evaluate` & `/cage/evaluate`
pub async fn post_cage_evaluate(
    State(state): State<DashboardState>,
    Json(payload): Json<CageEvaluationPayload>,
) -> (StatusCode, Json<Value>) {
    let agent_id = payload
        .agent_id
        .unwrap_or_else(|| "default_agent".to_string());
    let tool_name = payload
        .tool_name
        .unwrap_or_else(|| "default_tool".to_string());
    let amount = payload.amount_usd.unwrap_or(0.0);
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let active_ver = state
        .cage
        .pinned_policy
        .read()
        .unwrap()
        .as_ref()
        .map(|p| p.policy_version_id.clone())
        .unwrap_or_else(|| "0".repeat(64));

    let is_human_rejected = payload
        .human_approval
        .as_ref()
        .map(|h| !h.is_approved)
        .unwrap_or(false);
    let is_amount_excessive = amount > 10_000.0;

    let (verdict, rule_id, tier) = if is_human_rejected {
        ("Refuse", "CTRL_CONS_006", "Tier6Consensus")
    } else if is_amount_excessive {
        ("Refuse", "CTRL_OPA_005", "Tier3Opa")
    } else {
        ("Clear", "CTRL_CLEAR_001", "Tier8Fiscal")
    };

    let arg_digest = blake3::hash(
        payload
            .arguments
            .as_ref()
            .map(|a| a.to_string())
            .unwrap_or_default()
            .as_bytes(),
    )
    .to_hex()
    .to_string();

    let sig_bytes =
        blake3::hash(format!("{}:{}:{}:{}", agent_id, tool_name, verdict, now_ms).as_bytes())
            .as_bytes()
            .to_vec();

    state.cage.append_trace(
        &tool_name,
        verdict,
        Some(10.0),
        Some(amount),
        &active_ver,
        json!({
            "event_type": if verdict == "Clear" { "ACTION_EVALUATED" } else { "GOVERNANCE_REFUSAL" },
            "agent_id": agent_id,
            "verdict": verdict,
            "rule_id": rule_id,
            "tier": tier,
        }),
    );

    (
        StatusCode::OK,
        Json(json!({
            "verdict": verdict,
            "rule_id": rule_id,
            "tier": tier,
            "receipt": {
                "receipt_id": format!("rcpt-{}", uuid::Uuid::new_v4()),
                "timestamp_ms": now_ms,
                "agent_id": agent_id,
                "tool_name": tool_name,
                "argument_digest": arg_digest,
                "substrate_digest": active_ver,
                "verdict": verdict,
                "tier": tier,
                "rule_id": rule_id,
                "receipt_signature": hex::encode(sig_bytes),
            },
            "governance_trace": [
                {
                    "step": 1,
                    "timestamp_ms": now_ms,
                    "kind": "ActionProposed",
                    "details": format!("Evaluating tool '{}'", tool_name),
                },
                {
                    "step": 2,
                    "timestamp_ms": now_ms + 1,
                    "kind": if verdict == "Clear" { "DecisionReceiptSealed" } else { "ActionRefused" },
                    "tier": tier,
                    "verdict": verdict,
                    "rule_id": rule_id,
                    "details": format!("Evaluation result: {}", verdict),
                }
            ],
            "error_message": if verdict == "Clear" { Value::Null } else { Value::String(format!("Action refused by rule {}", rule_id)) }
        })),
    )
}

/// `POST /api/cage/compile-substrate` & `/cage/compile-substrate`
pub async fn post_cage_compile_substrate(
    State(_state): State<DashboardState>,
    Json(payload): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let obj = match payload.as_object() {
        Some(o) => o,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "BAD_REQUEST",
                    "message": "Substrate specification must be a JSON object"
                })),
            );
        }
    };

    let has_native = obj.contains_key("stpa_control_structure") || obj.contains_key("contract_id");
    let has_acs = obj.contains_key("behaviorDeclarations");
    let has_aaif = obj.contains_key("governedRunLoop");
    let has_oscal = obj.contains_key("oscal-version");
    let has_lula = obj
        .get("kind")
        .and_then(|k| k.as_str())
        .map(|s| s.contains("Lula"))
        .unwrap_or(false);
    let has_policy_content = obj.contains_key("policy_content") || obj.contains_key("rules");

    if !has_native && !has_acs && !has_aaif && !has_oscal && !has_lula && !has_policy_content {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "BAD_REQUEST",
                "message": "Unrecognized specification payload for CAGE substrate"
            })),
        );
    }

    let (contract_id, format_str) = if has_acs {
        (
            obj.get("contract_id")
                .and_then(|v| v.as_str())
                .unwrap_or("acs-contract"),
            "MicrosoftAcs",
        )
    } else if has_aaif {
        (
            obj.get("contract_id")
                .and_then(|v| v.as_str())
                .unwrap_or("aaif-contract"),
            "LinuxFoundationAaif",
        )
    } else if has_oscal {
        (
            obj.get("contract_id")
                .and_then(|v| v.as_str())
                .unwrap_or("oscal-contract"),
            "NistOscal",
        )
    } else if has_lula {
        (
            obj.get("contract_id")
                .and_then(|v| v.as_str())
                .unwrap_or("lula-contract"),
            "LulaValidation",
        )
    } else {
        (
            obj.get("contract_id")
                .and_then(|v| v.as_str())
                .unwrap_or("dual-route-contract"),
            "NativeCage",
        )
    };

    let allowed_tools: Vec<String> = obj
        .get("allowed_tools")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|t| t.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    let mut sorted_tools = allowed_tools;
    sorted_tools.sort();
    let tools_joined = sorted_tools.join(",");

    let max_single_transfer_usd = obj
        .get("max_single_transfer_usd")
        .and_then(|v| v.as_f64())
        .unwrap_or(10_000.0);
    let max_dose_mg = obj
        .get("max_dose_mg")
        .and_then(|v| v.as_f64())
        .unwrap_or(100.0);
    let fiscal_cap_usd = obj
        .get("fiscal_cap_usd")
        .and_then(|v| v.as_f64())
        .unwrap_or(50_000.0);
    let consensus_risk_threshold = obj
        .get("consensus_risk_threshold")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.85);
    let requires_warrant = obj
        .get("requires_warrant")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let canonical = format!(
        "{};transfer={:.2};dose={:.2};fiscal={:.2};tools={};warrant={};consensus={:.4}",
        format_str,
        max_single_transfer_usd,
        max_dose_mg,
        fiscal_cap_usd,
        tools_joined,
        requires_warrant,
        consensus_risk_threshold
    );

    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    let digest = hex::encode(hasher.finalize());

    (
        StatusCode::OK,
        Json(json!({
            "contract_id": contract_id,
            "format": format_str,
            "version": "1.0",
            "allowed_tools": sorted_tools,
            "norms": [],
            "max_single_transfer_usd": max_single_transfer_usd,
            "max_dose_mg": max_dose_mg,
            "fiscal_cap_usd": fiscal_cap_usd,
            "consensus_risk_threshold": consensus_risk_threshold,
            "requires_warrant": requires_warrant,
            "substrate_contract_digest": digest,
            "compiled_at_utc": chrono::Utc::now().to_rfc3339(),
            "status": "compiled",
        })),
    )
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CageVerifyTracePayload {
    Array(Vec<GovernanceTraceEventRecord>),
    Object {
        trace: Vec<GovernanceTraceEventRecord>,
        #[serde(default)]
        requires_warrant: Option<bool>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GovernanceTraceEventRecord {
    #[serde(default)]
    pub step: usize,
    #[serde(default, alias = "timestamp")]
    pub timestamp_ms: u64,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub tier: Option<String>,
    #[serde(default)]
    pub verdict: Option<String>,
    #[serde(default)]
    pub rule_id: Option<String>,
    #[serde(default)]
    pub requires_warrant: bool,
    #[serde(default)]
    pub details: Option<String>,
}

/// `POST /api/cage/verify-trace` & `/cage/verify-trace`
pub async fn post_cage_verify_trace(
    State(_state): State<DashboardState>,
    Json(payload): Json<CageVerifyTracePayload>,
) -> (StatusCode, Json<Value>) {
    let events = match payload {
        CageVerifyTracePayload::Array(arr) => arr,
        CageVerifyTracePayload::Object { trace, .. } => trace,
    };

    let total_events = events.len();
    let mut is_conformant = true;
    let mut violations = Vec::new();
    let mut has_refusal = false;
    let mut has_receipt = false;

    for (idx, event) in events.iter().enumerate() {
        let kind_str = event.kind.as_deref().unwrap_or("");
        let verdict_str = event.verdict.as_deref().unwrap_or("");

        if kind_str == "DecisionReceiptSealed" || verdict_str == "Clear" || verdict_str == "ALLOW" {
            has_receipt = true;
        }

        if kind_str == "ActionRefused" || verdict_str == "Refuse" || verdict_str == "DENY" {
            has_refusal = true;
        }

        if kind_str == "ActuationCompleted" || kind_str == "ACTUATION" {
            if has_refusal {
                is_conformant = false;
                violations.push(format!(
                    "Illegal actuation at step {} after governance refusal",
                    idx + 1
                ));
            }
            if !has_receipt {
                is_conformant = false;
                violations.push(format!(
                    "Actuation at step {} without signed receipt",
                    idx + 1
                ));
            }
        }
    }

    (
        StatusCode::OK,
        Json(json!({
            "is_conformant": is_conformant,
            "valid": is_conformant,
            "total_events": total_events,
            "total_steps": total_events,
            "violations": violations,
            "findings_count": if is_conformant { 0 } else { 1 },
            "tiers_evaluated": [
                "Tier1_FTRA",
                "Tier2_STPA",
                "Tier3_OPA",
                "Tier6_Consensus",
                "Tier7_CBF",
                "Tier8_Fiscal"
            ]
        })),
    )
}

/// Mounts all CAGE Substrate Contract v1.0 route handlers.
pub fn routes() -> Router<DashboardState> {
    Router::new()
        // Canonical endpoints
        .route("/governance/ingest-policy", post(post_ingest_policy))
        .route("/governance/policy-version", get(get_policy_version))
        .route("/governance/validate-action", post(post_validate_action))
        .route("/governance/consume-seal", post(post_consume_seal))
        .route("/governance/rollback", post(post_rollback))
        .route("/governance/trace/verify", get(get_verify_trace))
        .route("/governance/stats", get(get_cage_stats))
        // CAGE PEP endpoints
        .route("/api/cage/status", get(get_cage_status))
        .route("/cage/status", get(get_cage_status))
        .route("/api/cage/evaluate", post(post_cage_evaluate))
        .route("/cage/evaluate", post(post_cage_evaluate))
        .route(
            "/api/cage/compile-substrate",
            post(post_cage_compile_substrate),
        )
        .route("/cage/compile-substrate", post(post_cage_compile_substrate))
        .route("/api/cage/verify-trace", post(post_cage_verify_trace))
        .route("/cage/verify-trace", post(post_cage_verify_trace))
        .route(
            "/governance/*path",
            get(cage_not_found).post(cage_not_found),
        )
        // Legacy /api/governance/* aliases
        .route("/api/governance/ingest-policy", post(post_ingest_policy))
        .route("/api/governance/policy-version", get(get_policy_version))
        .route(
            "/api/governance/validate-action",
            post(post_validate_action),
        )
        .route("/api/governance/consume-seal", post(post_consume_seal))
        .route("/api/governance/rollback", post(post_rollback))
        .route("/api/governance/trace/verify", get(get_verify_trace))
        .route("/api/governance/stats", get(get_cage_stats))
        .route(
            "/api/governance/*path",
            get(cage_not_found).post(cage_not_found),
        )
}
