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
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::DashboardState;

/// Default substrate secret key for CAGE routing seals HMAC signing.
pub const DEFAULT_CAGE_SUBSTRATE_SECRET: &[u8] = b"oshoosiclaw_cage_governance_secret_2026_test_key";

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
    let content = match req.policy_content.as_deref().filter(|s| !s.trim().is_empty()) {
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
pub async fn get_policy_version(
    State(state): State<DashboardState>,
) -> (StatusCode, Json<Value>) {
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
                GovernanceVerdict::Defer { backoff_ms } => {
                    ("DEFER", format!("Deferred for {} ms", backoff_ms), "".to_string())
                }
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

    let registered_info_opt = state.cage.registered_seals.read().unwrap().get(&seal_id).cloned();
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

    if let Err(rejection) = pipeline
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

    if let Some(info) = state.cage.registered_seals.write().unwrap().get_mut(&seal_id) {
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
pub async fn get_verify_trace(
    State(state): State<DashboardState>,
) -> (StatusCode, Json<Value>) {
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
pub async fn get_cage_stats(
    State(state): State<DashboardState>,
) -> (StatusCode, Json<Value>) {
    let (active_version, rules_count) = if let Some(pinned) = state.cage.pinned_policy.read().unwrap().as_ref() {
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
        .route("/governance/*path", get(cage_not_found).post(cage_not_found))
        // Legacy /api/governance/* aliases
        .route("/api/governance/ingest-policy", post(post_ingest_policy))
        .route("/api/governance/policy-version", get(get_policy_version))
        .route("/api/governance/validate-action", post(post_validate_action))
        .route("/api/governance/consume-seal", post(post_consume_seal))
        .route("/api/governance/rollback", post(post_rollback))
        .route("/api/governance/trace/verify", get(get_verify_trace))
        .route("/api/governance/stats", get(get_cage_stats))
        .route("/api/governance/*path", get(cage_not_found).post(cage_not_found))
}
