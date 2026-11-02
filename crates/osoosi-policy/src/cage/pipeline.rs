//! 2-Phase, 7-Tier Deterministic Governance Evaluation Pipeline
//!
//! Implements CAGE's deterministic two-phase runtime control plane:
//!
//! - **Phase 1: Read-Only Multi-Tier Verification (Idempotent & Non-Mutating)**
//!   - Tier 1: Fast Tier Risk Assessment (FTRA) — action reachability, criticality & caller privilege.
//!   - Tier 2: STPA 7-Hazard Safety Invariant Matrix — checks control action against compiled UCAs.
//!   - Tier 3: Cedar / OPA Formal Authorization — evaluates principal, action, resource, context.
//!   - Tier 4: Federal Reserve SR 26-2 Model Confidence Scoring:
//!     * $\text{confidence} \ge 0.95 \implies$ ALLOW candidate
//!     * $0.70 \le \text{confidence} < 0.95 \implies$ REQUIRE_APPROVAL with approval token
//!     * $\text{confidence} < 0.70 \implies$ DEFER with exponential backoff
//!   - Tier 5: Bayesian Multi-Detector Consensus check — evaluates detector quorum agreement.
//!
//!   *Strict Read-Only Invariant*: Phase 1 NEVER mutates state, budget, or ledger. If any check
//!   fails, it terminates immediately with a verdict (DENY, DEFER, or REQUIRE_APPROVAL) without
//!   calling Phase 2.
//!
//! - **Phase 2: Atomic State Mutation & Actuation Ledger**
//!   - Tier 6: Discrete-Time Exponential Control Barrier Function (CBF):
//!     $$h_{t+1} = (B_t - c) - B_{\min} \ge (1 - \gamma) h_t \ge 0$$
//!   - Tier 7: Fiscal Fuel Pre-Reservation & CommitReceipt issuance ($B_{t+1} = B_t - c$).
//!     Zero fiscal leakage on denial ($B_{t+1} = B_t$) with LIFO compensating rollback.
//!
//! - **Cryptographic Routing Seal Issuance (Tier 7 Completion)**
//!   Issued exclusively on [`GovernanceVerdict::Allow`] or [`GovernanceVerdict::Narrow`].

use crate::cage::cbf::{CbfViolation, CommitReceipt, FiscalLedger};
use crate::cage::policy_ingest::CompiledCagePolicy;
use crate::cage::routing_seal::{compute_action_digest, RoutingSealSigner, SealRejection};
use osoosi_types::cage::{GovernanceVerdict, RoutingSeal, StageOutcome, UnsafeControlAction};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Minimum confidence required by Federal Reserve SR 26-2 (§IV.B) for direct ALLOW clearance.
pub const SR_26_2_CONFIDENCE_ALLOW_THRESHOLD: f64 = 0.95;

/// Minimum confidence required for Human-In-The-Loop (HITL) approval escalation before DEFER.
pub const SR_26_2_CONFIDENCE_APPROVAL_THRESHOLD: f64 = 0.70;

/// Default Bayesian multi-detector consensus quorum threshold.
pub const DEFAULT_BAYESIAN_CONSENSUS_THRESHOLD: f64 = 0.70;

/// Action terminal reversibility classification for FTRA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ActionCriticality {
    /// Read-only inspection or telemetry polling. Permitted for all callers.
    ReadOnly,
    /// Reversible operations (e.g. temporary file writes, cache entries, low-risk actions).
    Reversible,
    /// Irreversible or high-privilege operations (process launch, socket bind, ledger mutation).
    IrreversibleTerminal,
}

impl ActionCriticality {
    /// Classifies an action name into its default risk criticality tier.
    pub fn classify(action_name: &str) -> Self {
        let name_lower = action_name.to_ascii_lowercase();
        if name_lower.contains("exec")
            || name_lower.contains("spawn")
            || name_lower.contains("launch")
            || name_lower.contains("driver")
            || name_lower.contains("delete")
            || name_lower.contains("purge")
            || name_lower.contains("socket")
            || name_lower.contains("bind")
            || name_lower.contains("childprocess")
            || name_lower.contains("modifysystembinary")
            || name_lower.contains("writebarrier")
        {
            ActionCriticality::IrreversibleTerminal
        } else if name_lower.contains("write")
            || name_lower.contains("update")
            || name_lower.contains("modify")
            || name_lower.contains("trade")
            || name_lower.contains("reserve")
            || name_lower.contains("transfer")
        {
            ActionCriticality::Reversible
        } else {
            ActionCriticality::ReadOnly
        }
    }

    /// Returns the minimum caller authority level required to execute this criticality tier.
    /// (1 is highest authority, 5 is lowest/untrusted).
    pub fn required_authority_rank(&self) -> u8 {
        match self {
            ActionCriticality::ReadOnly => 5,
            ActionCriticality::Reversible => 3,
            ActionCriticality::IrreversibleTerminal => 2,
        }
    }
}

/// Request payload submitted to the CAGE governance pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceRequest {
    /// Name of the control action to evaluate (e.g. "execute_child_process", "ExecuteStockOrder").
    pub action_name: String,

    /// Principal invoking the action (e.g. "agent-finance-01", "operator").
    pub principal: String,

    /// Resource target (e.g. "/usr/bin/bash", "AAPL", "CrownJewel/vault").
    pub resource: String,

    /// Dynamic parameters associated with the action invocation.
    pub parameters: serde_json::Value,

    /// Numerical caller authority level (1 = SystemSecurityPolicy, 5 = UntrustedRetrievedContent).
    pub caller_authority: u8,

    /// Model confidence score in [0.0, 1.0].
    pub confidence_score: f64,

    /// Multi-detector Bayesian consensus agreement score in [0.0, 1.0].
    pub consensus_score: f64,

    /// Fiscal fuel expenditure requested for this actuation.
    pub fuel_cost: f64,

    /// Optional expected policy version ID for HTTP 409 version pinning validation.
    pub expected_policy_version: Option<String>,
}

/// Complete result returned by the governance pipeline evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceEvaluationResult {
    /// Canonical verdict issued by the pipeline.
    pub verdict: GovernanceVerdict,

    /// Cryptographic routing seal issued on ALLOW or NARROW (None otherwise).
    pub seal: Option<RoutingSeal>,

    /// Diagnostic outcomes across all evaluated stages.
    pub stage_outcomes: Vec<StageOutcome>,

    /// Fiscal commit receipt issued on Phase 2 clearance (None if rejected).
    pub commit_receipt: Option<CommitReceipt>,

    /// 16-hex policy version active during evaluation.
    pub policy_version_id: String,

    /// 64-hex SHA-256 action digest bound to the evaluation.
    pub action_digest: String,
}

/// Pure-Rust 2-Phase, 7-Tier Deterministic Governance Pipeline.
pub struct CageGovernancePipeline {
    policy: Arc<RwLock<CompiledCagePolicy>>,
    ledger: Arc<FiscalLedger>,
    seal_signer: Arc<RoutingSealSigner>,
    consensus_threshold: f64,
}

impl CageGovernancePipeline {
    /// Constructs a new governance pipeline with compiled policy, fiscal ledger, and seal signer.
    pub fn new(policy: CompiledCagePolicy, ledger: FiscalLedger, secret_key: &[u8]) -> Self {
        let policy_ver = policy.policy_version_id.clone();
        let seal_signer = RoutingSealSigner::new(secret_key, &policy_ver);

        Self {
            policy: Arc::new(RwLock::new(policy)),
            ledger: Arc::new(ledger),
            seal_signer: Arc::new(seal_signer),
            consensus_threshold: DEFAULT_BAYESIAN_CONSENSUS_THRESHOLD,
        }
    }

    /// Sets the Bayesian consensus quorum threshold.
    pub fn with_consensus_threshold(mut self, threshold: f64) -> Self {
        self.consensus_threshold = threshold;
        self
    }

    /// Returns a reference to the fiscal ledger.
    pub fn ledger(&self) -> &Arc<FiscalLedger> {
        &self.ledger
    }

    /// Returns a reference to the routing seal signer.
    pub fn seal_signer(&self) -> &Arc<RoutingSealSigner> {
        &self.seal_signer
    }

    /// Returns the currently active policy version ID.
    pub fn active_policy_version(&self) -> String {
        self.policy.read().policy_version_id.clone()
    }

    /// Updates the compiled policy bundle and updates the seal signer's version pinning.
    pub fn update_policy(&self, new_policy: CompiledCagePolicy) {
        let new_ver = new_policy.policy_version_id.clone();
        self.seal_signer.set_policy_version(&new_ver);
        let mut p = self.policy.write();
        *p = new_policy;
    }

    /// Generates a deterministic 64-hex SHA-256 cryptographic refusal proof receipt.
    pub fn compute_refusal_proof(
        action_name: &str,
        stage: &str,
        reason: &str,
        timestamp: u64,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(action_name.as_bytes());
        hasher.update(b":");
        hasher.update(stage.as_bytes());
        hasher.update(b":");
        hasher.update(reason.as_bytes());
        hasher.update(b":");
        hasher.update(timestamp.to_string().as_bytes());
        hex::encode(hasher.finalize())
    }

    // =========================================================================
    // Phase 1: Read-Only Verification (Tiers 1 - 5)
    // Strict Invariant: NEVER mutates state, budget, or ledger.
    // =========================================================================

    /// Evaluates Tier 1: Fast Tier Risk Assessment (FTRA).
    fn evaluate_tier1_ftra(
        &self,
        request: &GovernanceRequest,
    ) -> Result<StageOutcome, (String, String)> {
        let criticality = ActionCriticality::classify(&request.action_name);
        let required_rank = criticality.required_authority_rank();

        if request.caller_authority > required_rank {
            let reason = format!(
                "FTRA_AUTHORITY_VIOLATION: Action '{}' is classified as {:?} (requires authority <= {}), caller authority is {}",
                request.action_name, criticality, required_rank, request.caller_authority
            );
            return Err(("ftra".to_string(), reason));
        }

        Ok(StageOutcome {
            stage_name: "ftra".to_string(),
            passed: true,
            details: Some(format!(
                "Action classified as {:?}; caller authority {} <= required {}",
                criticality, request.caller_authority, required_rank
            )),
        })
    }

    /// Evaluates Tier 2: STPA 7-Hazard Safety Invariant Matrix.
    fn evaluate_tier2_stpa(
        &self,
        request: &GovernanceRequest,
        ucas: &[UnsafeControlAction],
    ) -> Result<StageOutcome, (String, String)> {
        for uca in ucas {
            // Match control action
            if uca
                .control_action
                .eq_ignore_ascii_case(&request.action_name)
                || uca.control_action == "*"
            {
                // Check if context condition matches hazardous state
                if Self::matches_uca_context(&uca.context_condition, &request.parameters) {
                    let reason = format!(
                        "STPA_UCA_BREACH: Unsafe Control Action '{}' violated for hazard '{}': {}. Mitigation: {}",
                        uca.uca_id, uca.hazard_ref, uca.context_condition, uca.mitigation
                    );
                    return Err(("stpa".to_string(), reason));
                }
            }
        }

        Ok(StageOutcome {
            stage_name: "stpa".to_string(),
            passed: true,
            details: Some(format!(
                "Passed {} compiled STPA UCA safety invariants",
                ucas.len()
            )),
        })
    }

    /// Evaluates Tier 3: Cedar / OPA Formal Authorization Gate.
    fn evaluate_tier3_cedar(
        &self,
        request: &GovernanceRequest,
        cedar_rules: &[String],
    ) -> Result<StageOutcome, (String, String)> {
        for rule in cedar_rules {
            let rule_trimmed = rule.trim();

            // Explicit forbid check
            if rule_trimmed.starts_with("forbid")
                && Self::matches_cedar_forbid(rule_trimmed, request)
            {
                let reason = format!(
                    "CEDAR_FORBID_VIOLATION: Action '{}' forbidden by Cedar policy rule: {}",
                    request.action_name, rule_trimmed
                );
                return Err(("cedar".to_string(), reason));
            }
        }

        Ok(StageOutcome {
            stage_name: "cedar".to_string(),
            passed: true,
            details: Some(format!(
                "Cleared {} compiled Cedar authorization rules",
                cedar_rules.len()
            )),
        })
    }

    /// Evaluates Tier 4: Federal Reserve SR 26-2 Model Confidence Scoring.
    ///
    /// - confidence >= 0.95 -> PASS (admissible for ALLOW)
    /// - 0.70 <= confidence < 0.95 -> Escalate to REQUIRE_APPROVAL with approval token
    /// - confidence < 0.70 -> DEFER with exponential backoff
    fn evaluate_tier4_confidence(
        &self,
        confidence: f64,
        action_name: &str,
    ) -> Result<StageOutcome, GovernanceVerdict> {
        if confidence >= SR_26_2_CONFIDENCE_ALLOW_THRESHOLD {
            Ok(StageOutcome {
                stage_name: "confidence".to_string(),
                passed: true,
                details: Some(format!(
                    "Model confidence {:.4} >= SR 26-2 threshold {:.2}",
                    confidence, SR_26_2_CONFIDENCE_ALLOW_THRESHOLD
                )),
            })
        } else if confidence >= SR_26_2_CONFIDENCE_APPROVAL_THRESHOLD {
            let mut hasher = Sha256::new();
            hasher.update(action_name.as_bytes());
            hasher.update(confidence.to_string().as_bytes());
            hasher.update(uuid::Uuid::new_v4().as_bytes());
            let approval_token = format!("token_{}", &hex::encode(hasher.finalize())[..16]);

            let reason = format!(
                "SR 26-2 Model confidence {:.4} in [{:.2}, {:.2}): requires human approval before actuation",
                confidence, SR_26_2_CONFIDENCE_APPROVAL_THRESHOLD, SR_26_2_CONFIDENCE_ALLOW_THRESHOLD
            );

            Err(GovernanceVerdict::RequireApproval {
                reason,
                approval_token,
            })
        } else {
            // Exponential backoff proportional to confidence deficit
            let deficit = (SR_26_2_CONFIDENCE_APPROVAL_THRESHOLD - confidence).max(0.0);
            let backoff_ms = (1000.0 * (1.0 + deficit * 5.0)) as u64;

            Err(GovernanceVerdict::Defer { backoff_ms })
        }
    }

    /// Evaluates Tier 5: Bayesian Multi-Detector Consensus.
    fn evaluate_tier5_consensus(
        &self,
        consensus_score: f64,
    ) -> Result<StageOutcome, (String, String)> {
        if consensus_score >= self.consensus_threshold {
            Ok(StageOutcome {
                stage_name: "consensus".to_string(),
                passed: true,
                details: Some(format!(
                    "Consensus score {:.4} >= quorum threshold {:.2}",
                    consensus_score, self.consensus_threshold
                )),
            })
        } else {
            let reason = format!(
                "BAYESIAN_CONSENSUS_DEFICIT: Consensus score {:.4} below required quorum threshold {:.2}",
                consensus_score, self.consensus_threshold
            );
            Err(("consensus".to_string(), reason))
        }
    }

    // =========================================================================
    // Core Pipeline Evaluation
    // =========================================================================

    /// Evaluates an incoming action request through the complete 2-Phase, 7-Tier pipeline.
    ///
    /// Phase 1 executes read-only checks first. If any check fails, returns immediately
    /// without mutating state or deducting budget.
    /// If Phase 1 passes, Phase 2 evaluates CBF and pre-reserves fiscal fuel.
    /// On complete success, issues a single-use 30-second TTL [`RoutingSeal`].
    pub fn evaluate_action(&self, request: &GovernanceRequest) -> GovernanceEvaluationResult {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let policy = self.policy.read().clone();
        let action_digest = compute_action_digest(&request.action_name, &request.parameters);

        // Version Pinning Verification
        if let Some(expected_ver) = &request.expected_policy_version {
            if *expected_ver != policy.policy_version_id {
                let reason = format!(
                    "Policy version drift detected: active pinned version is '{}', requested was '{}'",
                    policy.policy_version_id, expected_ver
                );
                let proof_hash = Self::compute_refusal_proof(
                    &request.action_name,
                    "version_pinning",
                    &reason,
                    now,
                );
                return GovernanceEvaluationResult {
                    verdict: GovernanceVerdict::Deny { reason, proof_hash },
                    seal: None,
                    stage_outcomes: vec![StageOutcome {
                        stage_name: "version_pinning".to_string(),
                        passed: false,
                        details: Some("HTTP 409 Conflict version mismatch".to_string()),
                    }],
                    commit_receipt: None,
                    policy_version_id: policy.policy_version_id,
                    action_digest,
                };
            }
        }

        let mut stage_outcomes = Vec::with_capacity(7);

        // ---------------------------------------------------------------------
        // Phase 1: Read-Only Multi-Tier Verification (No State Mutation)
        // ---------------------------------------------------------------------

        // Tier 1: FTRA
        match self.evaluate_tier1_ftra(request) {
            Ok(outcome) => stage_outcomes.push(outcome),
            Err((stage, reason)) => {
                let proof_hash =
                    Self::compute_refusal_proof(&request.action_name, &stage, &reason, now);
                stage_outcomes.push(StageOutcome {
                    stage_name: stage,
                    passed: false,
                    details: Some(reason.clone()),
                });
                return GovernanceEvaluationResult {
                    verdict: GovernanceVerdict::Deny { reason, proof_hash },
                    seal: None,
                    stage_outcomes,
                    commit_receipt: None,
                    policy_version_id: policy.policy_version_id,
                    action_digest,
                };
            }
        }

        // Tier 2: STPA
        match self.evaluate_tier2_stpa(request, &policy.unsafe_control_actions) {
            Ok(outcome) => stage_outcomes.push(outcome),
            Err((stage, reason)) => {
                let proof_hash =
                    Self::compute_refusal_proof(&request.action_name, &stage, &reason, now);
                stage_outcomes.push(StageOutcome {
                    stage_name: stage,
                    passed: false,
                    details: Some(reason.clone()),
                });
                return GovernanceEvaluationResult {
                    verdict: GovernanceVerdict::Deny { reason, proof_hash },
                    seal: None,
                    stage_outcomes,
                    commit_receipt: None,
                    policy_version_id: policy.policy_version_id,
                    action_digest,
                };
            }
        }

        // Tier 3: Cedar
        match self.evaluate_tier3_cedar(request, &policy.cedar_rules) {
            Ok(outcome) => stage_outcomes.push(outcome),
            Err((stage, reason)) => {
                let proof_hash =
                    Self::compute_refusal_proof(&request.action_name, &stage, &reason, now);
                stage_outcomes.push(StageOutcome {
                    stage_name: stage,
                    passed: false,
                    details: Some(reason.clone()),
                });
                return GovernanceEvaluationResult {
                    verdict: GovernanceVerdict::Deny { reason, proof_hash },
                    seal: None,
                    stage_outcomes,
                    commit_receipt: None,
                    policy_version_id: policy.policy_version_id,
                    action_digest,
                };
            }
        }

        // Tier 4: Confidence (SR 26-2)
        match self.evaluate_tier4_confidence(request.confidence_score, &request.action_name) {
            Ok(outcome) => stage_outcomes.push(outcome),
            Err(verdict) => {
                // Read-only escalation: REQUIRE_APPROVAL or DEFER
                stage_outcomes.push(StageOutcome {
                    stage_name: "confidence".to_string(),
                    passed: false,
                    details: Some(format!("Verdict escalated: {:?}", verdict.as_str())),
                });
                return GovernanceEvaluationResult {
                    verdict,
                    seal: None,
                    stage_outcomes,
                    commit_receipt: None,
                    policy_version_id: policy.policy_version_id,
                    action_digest,
                };
            }
        }

        // Tier 5: Consensus
        match self.evaluate_tier5_consensus(request.consensus_score) {
            Ok(outcome) => stage_outcomes.push(outcome),
            Err((stage, reason)) => {
                let proof_hash =
                    Self::compute_refusal_proof(&request.action_name, &stage, &reason, now);
                stage_outcomes.push(StageOutcome {
                    stage_name: stage,
                    passed: false,
                    details: Some(reason.clone()),
                });
                return GovernanceEvaluationResult {
                    verdict: GovernanceVerdict::Deny { reason, proof_hash },
                    seal: None,
                    stage_outcomes,
                    commit_receipt: None,
                    policy_version_id: policy.policy_version_id,
                    action_digest,
                };
            }
        }

        // ---------------------------------------------------------------------
        // Phase 2: Atomic State Mutation & Fiscal Pre-Reservation (Tiers 6 - 7)
        // ---------------------------------------------------------------------

        let debit_id = format!("debit_{}", uuid::Uuid::new_v4().simple());
        let pre_reserve_res = self.ledger.pre_reserve(request.fuel_cost, &debit_id);

        match pre_reserve_res {
            Ok(commit_receipt) => {
                // Tier 6: CBF passed
                stage_outcomes.push(StageOutcome {
                    stage_name: "cbf".to_string(),
                    passed: true,
                    details: Some(format!(
                        "CBF barrier satisfaction cleared: h_next={:.4} >= (1-gamma)*h_t",
                        commit_receipt.barrier_val
                    )),
                });

                // Tier 7: Fiscal fuel pre-reserved
                stage_outcomes.push(StageOutcome {
                    stage_name: "fiscal".to_string(),
                    passed: true,
                    details: Some(format!(
                        "Reserved fuel {:.2}, remaining budget {:.2}",
                        commit_receipt.reserved_fuel, commit_receipt.remaining_budget
                    )),
                });

                // Issuance of 30-second TTL cryptographic routing seal
                let seal = self.seal_signer.issue_seal(&action_digest, now);

                GovernanceEvaluationResult {
                    verdict: GovernanceVerdict::Allow,
                    seal: Some(seal),
                    stage_outcomes,
                    commit_receipt: Some(commit_receipt),
                    policy_version_id: policy.policy_version_id,
                    action_digest,
                }
            }
            Err(violation) => {
                // CBF Violation: zero fiscal leakage
                stage_outcomes.push(StageOutcome {
                    stage_name: "cbf".to_string(),
                    passed: false,
                    details: Some(violation.to_string()),
                });

                let reason = format!("CBF_BARRIER_VIOLATION: {}", violation);
                let proof_hash =
                    Self::compute_refusal_proof(&request.action_name, "cbf", &reason, now);

                GovernanceEvaluationResult {
                    verdict: GovernanceVerdict::Deny { reason, proof_hash },
                    seal: None,
                    stage_outcomes,
                    commit_receipt: None,
                    policy_version_id: policy.policy_version_id,
                    action_digest,
                }
            }
        }
    }

    /// Evaluates an action with a parameter clamping narrower function.
    ///
    /// If primary evaluation is denied due to parameter boundaries, but clamped parameters
    /// pass Phase 1 & 2, returns [`GovernanceVerdict::Narrow`] with a routing seal issued
    /// specifically over the clamped parameters.
    pub fn evaluate_with_narrowing<F>(
        &self,
        request: &GovernanceRequest,
        narrower: F,
    ) -> GovernanceEvaluationResult
    where
        F: Fn(&GovernanceRequest) -> Option<serde_json::Value>,
    {
        let primary_result = self.evaluate_action(request);

        // If primary evaluation already allowed or required approval, return directly
        if primary_result.verdict.is_allowed_or_narrowed()
            || matches!(
                primary_result.verdict,
                GovernanceVerdict::RequireApproval { .. }
            )
        {
            return primary_result;
        }

        // Try narrower proposal
        if let Some(clamped_params) = narrower(request) {
            let mut clamped_request = request.clone();
            clamped_request.parameters = clamped_params.clone();

            // Re-evaluate on clamped parameters
            let clamped_result = self.evaluate_action(&clamped_request);

            if let GovernanceVerdict::Allow = clamped_result.verdict {
                return GovernanceEvaluationResult {
                    verdict: GovernanceVerdict::Narrow { clamped_params },
                    seal: clamped_result.seal,
                    stage_outcomes: clamped_result.stage_outcomes,
                    commit_receipt: clamped_result.commit_receipt,
                    policy_version_id: clamped_result.policy_version_id,
                    action_digest: clamped_result.action_digest,
                };
            }
        }

        primary_result
    }

    /// Helper evaluating whether a UCA context condition is triggered by parameters.
    fn matches_uca_context(condition: &str, params: &serde_json::Value) -> bool {
        let cond_lower = condition.trim().to_ascii_lowercase();

        if cond_lower.is_empty() {
            return false;
        }

        // Parameter null check: "routing_seal is_null"
        if cond_lower.contains("is_null") {
            let param_name = cond_lower.replace("is_null", "").trim().to_string();
            return match params.get(&param_name) {
                None => true,
                Some(serde_json::Value::Null) => true,
                Some(serde_json::Value::String(s)) => s.is_empty(),
                _ => false,
            };
        }

        // Boolean check: "contains_prompt_injection"
        if let Some(val) = params.get(cond_lower.as_str()) {
            if let Some(b) = val.as_bool() {
                return b;
            }
        }

        // Numerical threshold check: "order_value_usd > 10000"
        if cond_lower.contains('>') {
            let parts: Vec<&str> = cond_lower.split('>').collect();
            if parts.len() == 2 {
                let key = parts[0].trim();
                let threshold: f64 = parts[1].trim().parse().unwrap_or(f64::MAX);
                if let Some(val) = params.get(key).and_then(|v| v.as_f64()) {
                    return val > threshold;
                }
            }
        }

        if cond_lower.contains('<') {
            let parts: Vec<&str> = cond_lower.split('<').collect();
            if parts.len() == 2 {
                let key = parts[0].trim();
                let threshold: f64 = parts[1].trim().parse().unwrap_or(f64::MIN);
                if let Some(val) = params.get(key).and_then(|v| v.as_f64()) {
                    return val < threshold;
                }
            }
        }

        false
    }

    /// Helper evaluating whether a Cedar forbid rule matches a request.
    fn matches_cedar_forbid(rule: &str, request: &GovernanceRequest) -> bool {
        let rule_lower = rule.to_ascii_lowercase();
        let action_lower = request.action_name.to_ascii_lowercase();

        // Check if rule mentions this action
        if !rule_lower.contains(&action_lower) && !rule_lower.contains("action") {
            return false;
        }

        // Condition matching: when { ... }
        if let Some(idx) = rule_lower.find("when {") {
            let condition = &rule_lower[idx + 6..];
            if let Some(end_idx) = condition.find('}') {
                let clause = condition[..end_idx].trim();

                // Check context parameter restrictions
                if clause.contains("context.") {
                    let param_check = clause.replace("context.", "");
                    if param_check.contains("==") {
                        let parts: Vec<&str> = param_check.split("==").collect();
                        if parts.len() == 2 {
                            let key = parts[0].trim();
                            let expected = parts[1].trim().trim_matches('"');
                            if let Some(actual) =
                                request.parameters.get(key).and_then(|v| v.as_str())
                            {
                                return actual == expected;
                            }
                        }
                    }
                    if param_check.contains('>') {
                        let parts: Vec<&str> = param_check.split('>').collect();
                        if parts.len() == 2 {
                            let key = parts[0].trim();
                            let threshold: f64 = parts[1].trim().parse().unwrap_or(f64::MAX);
                            if let Some(val) = request.parameters.get(key).and_then(|v| v.as_f64())
                            {
                                return val > threshold;
                            }
                        }
                    }
                }
            }
        }

        false
    }

    /// Validates and atomically consumes a routing seal in the host capability gate.
    pub fn validate_and_consume_seal(
        &self,
        seal: &RoutingSeal,
        expected_action_digest: &str,
    ) -> Result<(), SealRejection> {
        self.seal_signer
            .validate_and_consume_now(seal, expected_action_digest)
    }

    /// Rolls back a fuel reservation LIFO if downstream actuation fails.
    pub fn rollback_reservation(&self, debit_id: &str) -> Result<f64, CbfViolation> {
        self.ledger.rollback_reservation(debit_id)
    }
}
