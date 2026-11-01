//! Bounded Agents: Delegation Security for Multi-Agent AI Systems (`arXiv:2608.15888`)
//!
//! Reference Implementation Port of `https://github.com/xmuruaga/bounded-agents`
//! (Agentic Principal Chain — APC) into OshoosiClaw (`osoosi-agent-anomaly`) and Cedar policies.
//!
//! Implements all formal constructs from Xabier Muruaga (2026), *Bounded Agents: Delegation
//! Security for Multi-Agent AI Systems* (`arXiv:2608.15888v1`):
//! 1. **Def. 4.1 & Thm. 4.6 (`ApcScope::meet`)**: Asymmetric meet-semilattice
//!    $\mathcal{S}_1 \sqcap \mathcal{S}_2 = (R_1 \cap R_2,\; A_1 \cap A_2,\; D_1 \cap D_2,\; X_1 \cup X_2)$
//!    guaranteeing monotonic blast-radius non-increase $\text{BR}(\mathcal{E}_k) \le \text{BR}(\mathcal{E}_{k-1})$.
//! 2. **Def. 4.2 & §5.4 (`AuthorizationEnvelope` & `PrincipalChain`)**: Multi-hop attenuation
//!    (2–8 hops) with HMAC-SHA256 integrity seals and `EnvelopeSealedError` anti-escalation.
//! 3. **Thm. 4.7 & Prop. 4.2 (`CompositionChecker`)**: Unordered pairwise ($k=2$)
//!    `DENY_COMPOSE(source_class, target_class)` + ordered resource-qualified $k$-tuple ($k \ge 2$)
//!    subsequence matching (`KTupleRestriction`), plus OshoosiClaw's **Cross-Session Principal
//!    Lineage Anti-Splitting Guard** closing the paper's 1/43 session-splitting boundary.
//! 4. **Def. 4.3 (`DelegationBudgetSpec` & `BudgetState`)**: 6 monotonic delegation budget
//!    dimensions (`cumulative_blast_radius`, `cumulative_irreversible`, `current_delegation_depth`,
//!    `peak_sensitivity`, `cross_domain_used`, `cumulative_cost`).
//! 5. **§5 (`ApcPolicyDecisionPoint`)**: Six conjunctive admissibility conditions
//!    $\text{Admissible}(a) \iff C_1 \wedge C_2 \wedge C_3 \wedge C_4 \wedge C_5 \wedge C_6$
//!    with zero scoring overrides, single-use action-hash `ApprovalToken`, fail-closed SHA-256
//!    hash-chained `EvidenceSink`, and pre-declared `IntentSpec` (`STRICT`/`WARN`/`AUDIT`).

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Mutex;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

fn compute_hmac_sha256_hex(key: &[u8], payload: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(payload);
    hex::encode(mac.finalize().into_bytes())
}

fn constant_time_eq_str(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// Action classification categories for composition checking (Paper §4.3).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ActionClass {
    ReadConfidential,
    ReadInternal,
    ReadPublic,
    ExternalTransmit,
    WriteSystem,
    ExecuteCode,
    DeleteResource,
    Custom(String),
}

impl ActionClass {
    pub fn as_str(&self) -> &str {
        match self {
            Self::ReadConfidential => "READ_CONFIDENTIAL",
            Self::ReadInternal => "READ_INTERNAL",
            Self::ReadPublic => "READ_PUBLIC",
            Self::ExternalTransmit => "EXTERNAL_transmit",
            Self::WriteSystem => "WRITE_SYSTEM",
            Self::ExecuteCode => "EXECUTE_CODE",
            Self::DeleteResource => "DELETE_RESOURCE",
            Self::Custom(s) => s.as_str(),
        }
    }
}

/// Pairwise unordered composition restriction ($k = 2$, Paper Def. 4.1).
/// Prohibits executing both `class_a` and `class_b` within the same session or lineage.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PairwiseRestriction {
    pub name: String,
    pub class_a: String,
    pub class_b: String,
}

impl PairwiseRestriction {
    pub fn new(
        name: impl Into<String>,
        class_a: impl Into<String>,
        class_b: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            class_a: class_a.into(),
            class_b: class_b.into(),
        }
    }
}

/// Ordered resource-qualified $k$-tuple composition restriction ($k \ge 2$, Paper Prop. 4.2).
/// Matches when the session history + candidate action contains the ordered subsequence
/// `[(class_1, resource_glob_1), ..., (class_k, resource_glob_k)]`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct KTupleStep {
    pub action_class: String,
    pub resource_pattern: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct KTupleRestriction {
    pub name: String,
    pub ordered_steps: Vec<KTupleStep>,
}

impl KTupleRestriction {
    pub fn new(name: impl Into<String>, ordered_steps: Vec<KTupleStep>) -> Self {
        Self {
            name: name.into(),
            ordered_steps,
        }
    }
}

/// Glob-style prefix/wildcard matching compatible with `apc/core.py::Scope.resource_matches`.
pub fn resource_pattern_matches(pattern: &str, resource: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return resource.starts_with(prefix);
    }
    pattern == resource
}

/// Asymmetric Meet-Semilattice Scope (`ApcScope`, Paper Def. 4.1 & Thm. 4.6).
///
/// $\mathcal{S}_1 \sqcap \mathcal{S}_2 = (R_1 \cap R_2,\; A_1 \cap A_2,\; D_1 \cap D_2,\; X_1 \cup X_2)$
/// Positive grants ($R, A, D$) intersect while negative composition restrictions ($X$) union.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApcScope {
    pub resources: BTreeSet<String>,
    pub actions: BTreeSet<String>,
    pub data_classifications: BTreeSet<String>,
    pub pairwise_restrictions: BTreeSet<PairwiseRestriction>,
    pub ktuple_restrictions: BTreeSet<KTupleRestriction>,
}

impl ApcScope {
    pub fn new(
        resources: impl IntoIterator<Item = impl Into<String>>,
        actions: impl IntoIterator<Item = impl Into<String>>,
        data_classifications: impl IntoIterator<Item = impl Into<String>>,
        pairwise_restrictions: impl IntoIterator<Item = PairwiseRestriction>,
        ktuple_restrictions: impl IntoIterator<Item = KTupleRestriction>,
    ) -> Self {
        Self {
            resources: resources.into_iter().map(Into::into).collect(),
            actions: actions.into_iter().map(Into::into).collect(),
            data_classifications: data_classifications.into_iter().map(Into::into).collect(),
            pairwise_restrictions: pairwise_restrictions.into_iter().collect(),
            ktuple_restrictions: ktuple_restrictions.into_iter().collect(),
        }
    }

    /// Computes the meet $\mathcal{S}_{\text{parent}} \sqcap \mathcal{S}_{\text{child}}$ (Def. 4.1).
    /// Resource patterns intersect with wildcard prefix awareness: if parent allows `docs/*` and
    /// child requests `docs/q3-financials`, `docs/q3-financials` is retained.
    pub fn meet(&self, child: &ApcScope) -> ApcScope {
        let mut narrowed_resources = BTreeSet::new();
        for c_res in &child.resources {
            if self.resources.iter().any(|p_res| {
                resource_pattern_matches(p_res, c_res) || (c_res.ends_with('*') && p_res == c_res)
            }) {
                narrowed_resources.insert(c_res.clone());
            }
        }
        for p_res in &self.resources {
            if child
                .resources
                .iter()
                .any(|c_res| resource_pattern_matches(c_res, p_res))
            {
                narrowed_resources.insert(p_res.clone());
            }
        }

        let narrowed_actions: BTreeSet<String> = if self.actions.contains("*") {
            child.actions.clone()
        } else if child.actions.contains("*") {
            self.actions.clone()
        } else {
            self.actions.intersection(&child.actions).cloned().collect()
        };

        let narrowed_classifications: BTreeSet<String> = self
            .data_classifications
            .intersection(&child.data_classifications)
            .cloned()
            .collect();

        let union_pairwise: BTreeSet<PairwiseRestriction> = self
            .pairwise_restrictions
            .union(&child.pairwise_restrictions)
            .cloned()
            .collect();

        let union_ktuple: BTreeSet<KTupleRestriction> = self
            .ktuple_restrictions
            .union(&child.ktuple_restrictions)
            .cloned()
            .collect();

        ApcScope {
            resources: narrowed_resources,
            actions: narrowed_actions,
            data_classifications: narrowed_classifications,
            pairwise_restrictions: union_pairwise,
            ktuple_restrictions: union_ktuple,
        }
    }

    pub fn allows_resource(&self, resource: &str) -> bool {
        self.resources
            .iter()
            .any(|pattern| resource_pattern_matches(pattern, resource))
    }

    pub fn allows_action(&self, action: &str) -> bool {
        self.actions.contains("*") || self.actions.contains(action)
    }

    pub fn allows_classification(&self, classification: &str) -> bool {
        self.data_classifications.contains("*")
            || self.data_classifications.contains(classification)
    }

    /// Combinatorial upper bound on blast radius $|R| \times |A| \times |D|$ (Paper Thm. 4.6).
    pub fn blast_radius(&self) -> usize {
        self.resources.len() * self.actions.len() * self.data_classifications.len()
    }
}

/// 6-Dimensional Monotonic Delegation Budget Specification (`DelegationBudgetSpec`, Paper Def. 4.3).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DelegationBudgetSpec {
    pub max_blast_radius: usize,
    pub max_irreversible_actions: usize,
    pub max_delegation_depth: usize,
    pub max_sensitivity_tier: u8,
    pub allow_cross_domain: bool,
    pub max_cumulative_cost: f64,
}

impl Default for DelegationBudgetSpec {
    fn default() -> Self {
        Self {
            max_blast_radius: 64,
            max_irreversible_actions: 3,
            max_delegation_depth: 5,
            max_sensitivity_tier: 3,
            allow_cross_domain: false,
            max_cumulative_cost: 10.0,
        }
    }
}

/// Live 6D Delegation Budget State (`BudgetState`, Paper Def. 4.3).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct BudgetState {
    pub cumulative_blast_radius: usize,
    pub cumulative_irreversible: usize,
    pub current_delegation_depth: usize,
    pub peak_sensitivity: u8,
    pub cross_domain_used: bool,
    pub cumulative_cost: f64,
}

impl BudgetState {
    #[allow(clippy::too_many_arguments)]
    pub fn check_and_record(
        &mut self,
        spec: &DelegationBudgetSpec,
        blast_delta: usize,
        is_irreversible: bool,
        delegation_depth: usize,
        sensitivity_tier: u8,
        is_cross_domain: bool,
        cost_delta: f64,
    ) -> Result<(), String> {
        let next_blast = self.cumulative_blast_radius.saturating_add(blast_delta);
        if next_blast > spec.max_blast_radius {
            return Err(format!(
                "C2_BUDGET_BLAST_RADIUS_EXCEEDED: {} > {}",
                next_blast, spec.max_blast_radius
            ));
        }
        let next_irrev = self.cumulative_irreversible + usize::from(is_irreversible);
        if next_irrev > spec.max_irreversible_actions {
            return Err(format!(
                "C2_BUDGET_IRREVERSIBLE_EXCEEDED: {} > {}",
                next_irrev, spec.max_irreversible_actions
            ));
        }
        if delegation_depth > spec.max_delegation_depth {
            return Err(format!(
                "C2_BUDGET_DEPTH_EXCEEDED: {} > {}",
                delegation_depth, spec.max_delegation_depth
            ));
        }
        let next_sens = self.peak_sensitivity.max(sensitivity_tier);
        if next_sens > spec.max_sensitivity_tier {
            return Err(format!(
                "C2_BUDGET_SENSITIVITY_EXCEEDED: {} > {}",
                next_sens, spec.max_sensitivity_tier
            ));
        }
        let next_cross = self.cross_domain_used || is_cross_domain;
        if next_cross && !spec.allow_cross_domain {
            return Err("C2_BUDGET_CROSS_DOMAIN_FORBIDDEN".to_string());
        }
        let next_cost = self.cumulative_cost + cost_delta;
        if next_cost > spec.max_cumulative_cost {
            return Err(format!(
                "C2_BUDGET_COST_EXCEEDED: {:.4} > {:.4}",
                next_cost, spec.max_cumulative_cost
            ));
        }

        self.cumulative_blast_radius = next_blast;
        self.cumulative_irreversible = next_irrev;
        self.current_delegation_depth = self.current_delegation_depth.max(delegation_depth);
        self.peak_sensitivity = next_sens;
        self.cross_domain_used = next_cross;
        self.cumulative_cost = next_cost;
        Ok(())
    }
}

/// Sealed Authorization Envelope (`AuthorizationEnvelope`, Paper Def. 4.2 & §5.4).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthorizationEnvelope {
    pub envelope_id: String,
    pub delegator_id: String,
    pub delegatee_id: String,
    pub root_principal_id: String,
    pub hop_index: usize,
    pub task_session_id: String,
    pub policy_version: String,
    pub effective_scope: ApcScope,
    pub budget_spec: DelegationBudgetSpec,
    pub issued_at_unix: i64,
    pub expires_at_unix: i64,
    pub sealed: bool,
    pub hmac_seal: String,
}

impl AuthorizationEnvelope {
    #[allow(clippy::too_many_arguments)]
    pub fn new_root(
        envelope_id: impl Into<String>,
        root_principal_id: impl Into<String>,
        delegatee_id: impl Into<String>,
        task_session_id: impl Into<String>,
        policy_version: impl Into<String>,
        scope: ApcScope,
        budget_spec: DelegationBudgetSpec,
        issued_at_unix: i64,
        expires_at_unix: i64,
        signing_key: &[u8],
    ) -> Self {
        let root_id = root_principal_id.into();
        let mut env = Self {
            envelope_id: envelope_id.into(),
            delegator_id: root_id.clone(),
            delegatee_id: delegatee_id.into(),
            root_principal_id: root_id,
            hop_index: 1,
            task_session_id: task_session_id.into(),
            policy_version: policy_version.into(),
            effective_scope: scope,
            budget_spec,
            issued_at_unix,
            expires_at_unix,
            sealed: true,
            hmac_seal: String::new(),
        };
        env.hmac_seal = env.compute_seal(signing_key);
        env
    }

    pub fn compute_seal(&self, signing_key: &[u8]) -> String {
        let canonical = format!(
            "{}|{}|{}|{}|{}|{}|{}|{:?}|{}|{}",
            self.envelope_id,
            self.delegator_id,
            self.delegatee_id,
            self.root_principal_id,
            self.hop_index,
            self.task_session_id,
            self.policy_version,
            self.effective_scope,
            self.issued_at_unix,
            self.expires_at_unix
        );
        compute_hmac_sha256_hex(signing_key, canonical.as_bytes())
    }

    pub fn verify_seal(&self, signing_key: &[u8]) -> bool {
        if !self.sealed {
            return false;
        }
        let expected = self.compute_seal(signing_key);
        constant_time_eq_str(&self.hmac_seal, &expected)
    }

    /// Attempt to mutate a sealed envelope in-place fails closed (`EnvelopeSealedError`).
    pub fn attempt_in_place_scope_mutation(&mut self, _new_scope: ApcScope) -> Result<(), String> {
        if self.sealed {
            return Err(
                "EnvelopeSealedError: Sealed AuthorizationEnvelope cannot be modified in place"
                    .to_string(),
            );
        }
        self.effective_scope = _new_scope;
        Ok(())
    }

    /// Delegate authority to the next hop via meet-semilattice narrowing $\mathcal{S}_{\text{parent}} \sqcap \mathcal{S}_{\text{child}}$.
    pub fn delegate_narrowed(
        &self,
        child_envelope_id: impl Into<String>,
        next_delegatee_id: impl Into<String>,
        requested_child_scope: &ApcScope,
        signing_key: &[u8],
    ) -> Result<AuthorizationEnvelope, String> {
        if !self.verify_seal(signing_key) {
            return Err("C1_PARENT_ENVELOPE_SEAL_INVALID".to_string());
        }
        let next_hop = self.hop_index + 1;
        if next_hop > self.budget_spec.max_delegation_depth {
            return Err(format!(
                "C2_DELEGATION_DEPTH_EXCEEDED: hop {} > max {}",
                next_hop, self.budget_spec.max_delegation_depth
            ));
        }
        let narrowed_scope = self.effective_scope.meet(requested_child_scope);
        let mut child = Self {
            envelope_id: child_envelope_id.into(),
            delegator_id: self.delegatee_id.clone(),
            delegatee_id: next_delegatee_id.into(),
            root_principal_id: self.root_principal_id.clone(),
            hop_index: next_hop,
            task_session_id: self.task_session_id.clone(),
            policy_version: self.policy_version.clone(),
            effective_scope: narrowed_scope,
            budget_spec: self.budget_spec.clone(),
            issued_at_unix: self.issued_at_unix,
            expires_at_unix: self.expires_at_unix,
            sealed: true,
            hmac_seal: String::new(),
        };
        child.hmac_seal = child.compute_seal(signing_key);
        Ok(child)
    }
}

/// Recorded action in session or lineage history for stateful composition checking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutedActionEvent {
    pub session_id: String,
    pub root_principal_id: String,
    pub actor_id: String,
    pub action: String,
    pub resource: String,
    pub action_classes: BTreeSet<String>,
}

/// Stateful Session & Cross-Session Principal Lineage Composition Checker (Thm. 4.7 & Prop. 4.2).
#[derive(Debug, Default)]
pub struct CompositionChecker {
    action_to_classes: HashMap<String, BTreeSet<String>>,
    session_history: Mutex<HashMap<String, Vec<ExecutedActionEvent>>>,
    /// Cross-Session Principal Lineage history (`root_principal_id -> Vec<ExecutedActionEvent>`)
    /// to block the paper's 1/43 cross-session action-splitting adaptive attack.
    principal_lineage_history: Mutex<HashMap<String, Vec<ExecutedActionEvent>>>,
    pub enforce_cross_session_lineage: bool,
}

impl CompositionChecker {
    pub fn new(enforce_cross_session_lineage: bool) -> Self {
        let mut checker = Self {
            action_to_classes: HashMap::new(),
            session_history: Mutex::new(HashMap::new()),
            principal_lineage_history: Mutex::new(HashMap::new()),
            enforce_cross_session_lineage,
        };
        checker.register_default_mappings();
        checker
    }

    pub fn register_default_mappings(&mut self) {
        self.map_action("read_confidential", ["READ_CONFIDENTIAL"]);
        self.map_action("read_secret", ["READ_CONFIDENTIAL"]);
        self.map_action("read_document", ["READ_CONFIDENTIAL"]);
        self.map_action("send_email", ["EXTERNAL_TRANSMIT"]);
        self.map_action("http_post_external", ["EXTERNAL_TRANSMIT"]);
        self.map_action("webhook_send", ["EXTERNAL_TRANSMIT"]);
        self.map_action("write_system_config", ["WRITE_SYSTEM"]);
        self.map_action("exec_shell", ["EXECUTE_CODE"]);
    }

    pub fn map_action(
        &mut self,
        action: impl Into<String>,
        classes: impl IntoIterator<Item = impl Into<String>>,
    ) {
        self.action_to_classes
            .insert(action.into(), classes.into_iter().map(Into::into).collect());
    }

    pub fn classes_for(&self, action: &str, resource: &str) -> BTreeSet<String> {
        let mut out = self
            .action_to_classes
            .get(action)
            .cloned()
            .unwrap_or_default();
        if (resource.starts_with("confidential/")
            || resource.contains("secret")
            || resource.contains("financial"))
            && action.starts_with("read")
        {
            out.insert("READ_CONFIDENTIAL".to_string());
        }
        if resource.starts_with("external/")
            || resource.starts_with("mailto:")
            || resource.starts_with("https://")
        {
            out.insert("EXTERNAL_TRANSMIT".to_string());
        }
        out
    }

    /// Evaluates pairwise ($k=2$) and ordered $k$-tuple ($k \ge 2$) composition restrictions
    /// over both `session_history` and (when enabled) `principal_lineage_history`.
    pub fn check_candidate(
        &self,
        scope: &ApcScope,
        session_id: &str,
        root_principal_id: &str,
        actor_id: &str,
        action: &str,
        resource: &str,
    ) -> Result<ExecutedActionEvent, String> {
        let candidate_classes = self.classes_for(action, resource);
        let candidate_event = ExecutedActionEvent {
            session_id: session_id.to_string(),
            root_principal_id: root_principal_id.to_string(),
            actor_id: actor_id.to_string(),
            action: action.to_string(),
            resource: resource.to_string(),
            action_classes: candidate_classes,
        };

        let session_guard = self.session_history.lock().unwrap();
        let sess_events = session_guard.get(session_id).cloned().unwrap_or_default();
        drop(session_guard);

        Self::verify_event_stream(scope, &sess_events, &candidate_event, "SESSION")?;

        if self.enforce_cross_session_lineage {
            let lineage_guard = self.principal_lineage_history.lock().unwrap();
            let lineage_events = lineage_guard
                .get(root_principal_id)
                .cloned()
                .unwrap_or_default();
            drop(lineage_guard);
            Self::verify_event_stream(
                scope,
                &lineage_events,
                &candidate_event,
                "CROSS_SESSION_LINEAGE",
            )?;
        }

        Ok(candidate_event)
    }

    pub fn commit_event(&self, event: ExecutedActionEvent) {
        self.session_history
            .lock()
            .unwrap()
            .entry(event.session_id.clone())
            .or_default()
            .push(event.clone());
        self.principal_lineage_history
            .lock()
            .unwrap()
            .entry(event.root_principal_id.clone())
            .or_default()
            .push(event);
    }

    fn verify_event_stream(
        scope: &ApcScope,
        prior_events: &[ExecutedActionEvent],
        candidate: &ExecutedActionEvent,
        stream_label: &str,
    ) -> Result<(), String> {
        let mut prior_classes = BTreeSet::new();
        for ev in prior_events {
            for c in &ev.action_classes {
                prior_classes.insert(c.as_str());
            }
        }

        // 1. Pairwise unordered restrictions (k = 2)
        for rule in &scope.pairwise_restrictions {
            let a_in_prior = prior_classes.contains(rule.class_a.as_str());
            let b_in_prior = prior_classes.contains(rule.class_b.as_str());
            let a_in_cand = candidate.action_classes.contains(&rule.class_a);
            let b_in_cand = candidate.action_classes.contains(&rule.class_b);

            if (a_in_prior && b_in_cand) || (b_in_prior && a_in_cand) || (a_in_cand && b_in_cand) {
                return Err(format!(
                    "C2_COMPOSITION_PAIRWISE_DENIED[{}]: rule '{}' prohibits combining {} and {}",
                    stream_label, rule.name, rule.class_a, rule.class_b
                ));
            }
        }

        // 2. Ordered resource-qualified k-tuple subsequence matching (Prop. 4.2)
        for krule in &scope.ktuple_restrictions {
            if krule.ordered_steps.is_empty() {
                continue;
            }
            let last_step = &krule.ordered_steps[krule.ordered_steps.len() - 1];
            let cand_matches_last = candidate.action_classes.contains(&last_step.action_class)
                && resource_pattern_matches(&last_step.resource_pattern, &candidate.resource);
            if !cand_matches_last {
                continue;
            }

            if krule.ordered_steps.len() == 1 {
                return Err(format!(
                    "C2_COMPOSITION_KTUPLE_DENIED[{}]: rule '{}' matched single step",
                    stream_label, krule.name
                ));
            }

            // Greedy subsequence scan over prior_events for steps[0..k-1]
            let target_prefix = &krule.ordered_steps[..krule.ordered_steps.len() - 1];
            let mut step_idx = 0usize;
            for ev in prior_events {
                let step = &target_prefix[step_idx];
                if ev.action_classes.contains(&step.action_class)
                    && resource_pattern_matches(&step.resource_pattern, &ev.resource)
                {
                    step_idx += 1;
                    if step_idx == target_prefix.len() {
                        return Err(format!(
                            "C2_COMPOSITION_KTUPLE_DENIED[{}]: rule '{}' matched {}-step ordered exfiltration chain",
                            stream_label,
                            krule.name,
                            krule.ordered_steps.len()
                        ));
                    }
                }
            }
        }

        Ok(())
    }
}

/// Condition 4 (`C4`): Single-Use Action-Hash Bound Approval Token (`apc/approval.py`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalToken {
    pub token_id: String,
    pub approver_id: String,
    pub expected_action_hash: String,
    pub expires_at_unix: i64,
    pub hmac_signature: String,
}

pub fn compute_action_hash(
    actor_id: &str,
    action: &str,
    resource: &str,
    task_session_id: &str,
    parameters_canonical: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(
        format!(
            "{}|{}|{}|{}|{}",
            actor_id, action, resource, task_session_id, parameters_canonical
        )
        .as_bytes(),
    );
    hex::encode(hasher.finalize())
}

impl ApprovalToken {
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        token_id: impl Into<String>,
        approver_id: impl Into<String>,
        actor_id: &str,
        action: &str,
        resource: &str,
        task_session_id: &str,
        parameters_canonical: &str,
        expires_at_unix: i64,
        signing_key: &[u8],
    ) -> Self {
        let token_id_s = token_id.into();
        let approver_s = approver_id.into();
        let action_hash = compute_action_hash(
            actor_id,
            action,
            resource,
            task_session_id,
            parameters_canonical,
        );
        let payload = format!(
            "{}|{}|{}|{}",
            token_id_s, approver_s, action_hash, expires_at_unix
        );
        let sig = compute_hmac_sha256_hex(signing_key, payload.as_bytes());
        Self {
            token_id: token_id_s,
            approver_id: approver_s,
            expected_action_hash: action_hash,
            expires_at_unix,
            hmac_signature: sig,
        }
    }
}

/// Condition 5 (`C5`): Fail-Closed SHA-256 Hash-Chained Evidence Sink (`apc/pdp.py`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRecord {
    pub sequence_no: usize,
    pub envelope_id: String,
    pub actor_id: String,
    pub action: String,
    pub resource: String,
    pub decision: String,
    pub prev_hash: String,
    pub record_hash: String,
}

#[derive(Debug)]
pub struct EvidenceSink {
    records: Mutex<Vec<EvidenceRecord>>,
    pub available: bool,
}

impl Default for EvidenceSink {
    fn default() -> Self {
        Self::new(true)
    }
}

impl EvidenceSink {
    pub fn new(available: bool) -> Self {
        Self {
            records: Mutex::new(Vec::new()),
            available,
        }
    }

    pub fn append_evidence(
        &self,
        envelope_id: &str,
        actor_id: &str,
        action: &str,
        resource: &str,
        decision: &str,
    ) -> Result<EvidenceRecord, String> {
        if !self.available {
            return Err(
                "C5_EVIDENCE_SINK_UNAVAILABLE: Fail-closed evidence requirement violated"
                    .to_string(),
            );
        }
        let mut guard = self.records.lock().unwrap();
        let seq = guard.len();
        let prev_hash = guard
            .last()
            .map(|r| r.record_hash.clone())
            .unwrap_or_else(|| "genesis".to_string());

        let mut hasher = Sha256::new();
        hasher.update(
            format!(
                "{}|{}|{}|{}|{}|{}|{}",
                seq, envelope_id, actor_id, action, resource, decision, prev_hash
            )
            .as_bytes(),
        );
        let record_hash = hex::encode(hasher.finalize());
        let record = EvidenceRecord {
            sequence_no: seq,
            envelope_id: envelope_id.to_string(),
            actor_id: actor_id.to_string(),
            action: action.to_string(),
            resource: resource.to_string(),
            decision: decision.to_string(),
            prev_hash,
            record_hash,
        };
        guard.push(record.clone());
        Ok(record)
    }

    pub fn verify_integrity(&self) -> bool {
        let guard = self.records.lock().unwrap();
        let mut expected_prev = "genesis".to_string();
        for (idx, rec) in guard.iter().enumerate() {
            if rec.sequence_no != idx || rec.prev_hash != expected_prev {
                return false;
            }
            let mut hasher = Sha256::new();
            hasher.update(
                format!(
                    "{}|{}|{}|{}|{}|{}|{}",
                    rec.sequence_no,
                    rec.envelope_id,
                    rec.actor_id,
                    rec.action,
                    rec.resource,
                    rec.decision,
                    rec.prev_hash
                )
                .as_bytes(),
            );
            let computed = hex::encode(hasher.finalize());
            if !constant_time_eq_str(&computed, &rec.record_hash) {
                return false;
            }
            expected_prev = rec.record_hash.clone();
        }
        true
    }

    pub fn len(&self) -> usize {
        self.records.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Condition 6 (`C6`): Pre-Declared Intent Enforcement Mode (`apc/intent.py`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntentEnforcementMode {
    Strict,
    Warn,
    Audit,
}

/// Pre-Declared Intent Specification (`IntentSpec`, Paper §5.3).
/// Enforces `action_resource_map` precedence over flat `intended_actions`/`intended_resources`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntentSpec {
    pub intent_id: String,
    pub intended_actions: BTreeSet<String>,
    pub intended_resources: BTreeSet<String>,
    pub action_resource_map: BTreeMap<String, BTreeSet<String>>,
    pub mode: IntentEnforcementMode,
}

impl IntentSpec {
    pub fn check_intent(&self, action: &str, resource: &str) -> Result<Option<String>, String> {
        let matched = if !self.action_resource_map.is_empty() {
            if let Some(allowed_res) = self.action_resource_map.get(action) {
                allowed_res
                    .iter()
                    .any(|pattern| resource_pattern_matches(pattern, resource))
            } else {
                false
            }
        } else {
            let act_ok =
                self.intended_actions.contains("*") || self.intended_actions.contains(action);
            let res_ok = self
                .intended_resources
                .iter()
                .any(|pattern| resource_pattern_matches(pattern, resource));
            act_ok && res_ok
        };

        if matched {
            return Ok(None);
        }

        let violation = format!(
            "C6_INTENT_MISMATCH: action '{}' on resource '{}' outside pre-declared intent '{}'",
            action, resource, self.intent_id
        );
        match self.mode {
            IntentEnforcementMode::Strict => Err(violation),
            IntentEnforcementMode::Warn | IntentEnforcementMode::Audit => Ok(Some(violation)),
        }
    }
}

/// Proposed agent tool call submitted to the APC Policy Decision Point (`ApcActionRequest`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApcActionRequest {
    pub actor_id: String,
    pub action: String,
    pub resource: String,
    pub data_classification: String,
    pub parameters_canonical: String,
    pub task_session_id: String,
    pub policy_version: String,
    pub now_unix: i64,
    pub requires_approval: bool,
    pub approval_token: Option<ApprovalToken>,
    pub is_irreversible: bool,
    pub sensitivity_tier: u8,
    pub is_cross_domain: bool,
    pub cost_delta: f64,
}

/// Decision returned by `ApcPolicyDecisionPoint::evaluate`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApcDecision {
    pub allowed: bool,
    pub satisfied_conditions: Vec<String>,
    pub failed_condition: Option<String>,
    pub reason: String,
    pub evidence_hash: Option<String>,
    pub intent_warning: Option<String>,
}

/// Agentic Principal Chain Policy Decision Point (`ApcPolicyDecisionPoint`, Paper §5).
///
/// Evaluates the six conjunctive admissibility conditions:
/// $\text{Admissible}(a) \iff C_1 \wedge C_2 \wedge C_3 \wedge C_4 \wedge C_5 \wedge C_6$
pub struct ApcPolicyDecisionPoint {
    signing_key: Vec<u8>,
    pub active_policy_version: String,
    pub composition_checker: CompositionChecker,
    pub evidence_sink: EvidenceSink,
    consumed_approval_tokens: Mutex<BTreeSet<String>>,
    budget_states: Mutex<HashMap<String, BudgetState>>,
}

impl ApcPolicyDecisionPoint {
    pub fn new(
        signing_key: impl Into<Vec<u8>>,
        active_policy_version: impl Into<String>,
        enforce_cross_session_lineage: bool,
    ) -> Self {
        Self {
            signing_key: signing_key.into(),
            active_policy_version: active_policy_version.into(),
            composition_checker: CompositionChecker::new(enforce_cross_session_lineage),
            evidence_sink: EvidenceSink::new(true),
            consumed_approval_tokens: Mutex::new(BTreeSet::new()),
            budget_states: Mutex::new(HashMap::new()),
        }
    }

    pub fn evaluate(
        &self,
        envelope: &AuthorizationEnvelope,
        intent: &IntentSpec,
        req: &ApcActionRequest,
    ) -> ApcDecision {
        let mut satisfied = Vec::with_capacity(6);

        // C1: Identity & Cryptographic Envelope Seal Binding
        if !envelope.verify_seal(&self.signing_key) {
            return self.deny(
                envelope,
                req,
                satisfied,
                "C1_IDENTITY",
                "Envelope HMAC seal verification failed",
            );
        }
        if envelope.delegatee_id != req.actor_id {
            return self.deny(
                envelope,
                req,
                satisfied,
                "C1_IDENTITY",
                &format!(
                    "Actor '{}' does not match envelope delegatee '{}'",
                    req.actor_id, envelope.delegatee_id
                ),
            );
        }
        satisfied.push("C1_IDENTITY".to_string());

        // C2: Scope + Stateful Composition + 6D Monotonic Budget
        if !envelope.effective_scope.allows_action(&req.action) {
            return self.deny(
                envelope,
                req,
                satisfied,
                "C2_SCOPE_ACTION",
                &format!("Action '{}' not in narrowed scope", req.action),
            );
        }
        if !envelope.effective_scope.allows_resource(&req.resource) {
            return self.deny(
                envelope,
                req,
                satisfied,
                "C2_SCOPE_RESOURCE",
                &format!("Resource '{}' not in narrowed scope", req.resource),
            );
        }
        if !envelope
            .effective_scope
            .allows_classification(&req.data_classification)
        {
            return self.deny(
                envelope,
                req,
                satisfied,
                "C2_SCOPE_CLASSIFICATION",
                &format!(
                    "Classification '{}' not in narrowed scope",
                    req.data_classification
                ),
            );
        }

        let candidate_event = match self.composition_checker.check_candidate(
            &envelope.effective_scope,
            &req.task_session_id,
            &envelope.root_principal_id,
            &req.actor_id,
            &req.action,
            &req.resource,
        ) {
            Ok(ev) => ev,
            Err(err) => return self.deny(envelope, req, satisfied, "C2_COMPOSITION", &err),
        };

        {
            let mut budgets = self.budget_states.lock().unwrap();
            let bstate = budgets
                .entry(envelope.root_principal_id.clone())
                .or_default();
            if let Err(budget_err) = bstate.check_and_record(
                &envelope.budget_spec,
                1,
                req.is_irreversible,
                envelope.hop_index,
                req.sensitivity_tier,
                req.is_cross_domain,
                req.cost_delta,
            ) {
                return self.deny(envelope, req, satisfied, "C2_BUDGET", &budget_err);
            }
        }
        satisfied.push("C2_SCOPE_COMPOSITION_BUDGET".to_string());

        // C3: Context Binding (Freshness, Session ID, Policy Version)
        if req.now_unix < envelope.issued_at_unix || req.now_unix > envelope.expires_at_unix {
            return self.deny(
                envelope,
                req,
                satisfied,
                "C3_CONTEXT_EXPIRY",
                "Action timestamp outside envelope validity window",
            );
        }
        if req.task_session_id != envelope.task_session_id {
            return self.deny(
                envelope,
                req,
                satisfied,
                "C3_CONTEXT_SESSION",
                "Cross-session envelope replay rejected",
            );
        }
        if req.policy_version != self.active_policy_version
            || envelope.policy_version != self.active_policy_version
        {
            return self.deny(
                envelope,
                req,
                satisfied,
                "C3_CONTEXT_POLICY_VERSION",
                "Stale policy version rejected",
            );
        }
        satisfied.push("C3_CONTEXT".to_string());

        // C4: Single-Use Action-Hash Bound Approval Token
        if req.requires_approval || req.is_irreversible {
            let Some(token) = &req.approval_token else {
                return self.deny(
                    envelope,
                    req,
                    satisfied,
                    "C4_APPROVAL_MISSING",
                    "High-consequence or irreversible action requires ApprovalToken",
                );
            };
            if req.now_unix > token.expires_at_unix {
                return self.deny(
                    envelope,
                    req,
                    satisfied,
                    "C4_APPROVAL_EXPIRED",
                    "ApprovalToken has expired",
                );
            }
            let expected_hash = compute_action_hash(
                &req.actor_id,
                &req.action,
                &req.resource,
                &req.task_session_id,
                &req.parameters_canonical,
            );
            if !constant_time_eq_str(&token.expected_action_hash, &expected_hash) {
                return self.deny(
                    envelope,
                    req,
                    satisfied,
                    "C4_APPROVAL_HASH_MISMATCH",
                    "ApprovalToken action hash does not match request parameters",
                );
            }
            let payload = format!(
                "{}|{}|{}|{}",
                token.token_id,
                token.approver_id,
                token.expected_action_hash,
                token.expires_at_unix
            );
            let expected_sig = compute_hmac_sha256_hex(&self.signing_key, payload.as_bytes());
            if !constant_time_eq_str(&token.hmac_signature, &expected_sig) {
                return self.deny(
                    envelope,
                    req,
                    satisfied,
                    "C4_APPROVAL_SIGNATURE_INVALID",
                    "ApprovalToken HMAC signature invalid",
                );
            }
            let mut used = self.consumed_approval_tokens.lock().unwrap();
            if !used.insert(token.token_id.clone()) {
                return self.deny(
                    envelope,
                    req,
                    satisfied,
                    "C4_APPROVAL_REPLAY",
                    "Single-use ApprovalToken already consumed",
                );
            }
        }
        satisfied.push("C4_APPROVAL".to_string());

        // C6: Pre-Declared Intent Alignment (evaluated before committing C5 evidence)
        let intent_warning = match intent.check_intent(&req.action, &req.resource) {
            Ok(warn_opt) => warn_opt,
            Err(intent_err) => {
                return self.deny(envelope, req, satisfied, "C6_INTENT", &intent_err);
            }
        };
        satisfied.push("C6_INTENT".to_string());

        // C5: Fail-Closed SHA-256 Hash-Chained Evidence Sink
        let evidence_rec = match self.evidence_sink.append_evidence(
            &envelope.envelope_id,
            &req.actor_id,
            &req.action,
            &req.resource,
            "ALLOW",
        ) {
            Ok(rec) => rec,
            Err(ev_err) => return self.deny(envelope, req, satisfied, "C5_EVIDENCE", &ev_err),
        };
        satisfied.push("C5_EVIDENCE".to_string());

        // Commit event to stateful session & lineage history only after all 6 conditions succeed
        self.composition_checker.commit_event(candidate_event);

        ApcDecision {
            allowed: true,
            satisfied_conditions: satisfied,
            failed_condition: None,
            reason: "ALLOW: All 6 conjunctive APC conditions satisfied (C1..C6)".to_string(),
            evidence_hash: Some(evidence_rec.record_hash),
            intent_warning,
        }
    }

    fn deny(
        &self,
        envelope: &AuthorizationEnvelope,
        req: &ApcActionRequest,
        satisfied: Vec<String>,
        failed_cond: &str,
        reason: &str,
    ) -> ApcDecision {
        let ev_hash = self
            .evidence_sink
            .append_evidence(
                &envelope.envelope_id,
                &req.actor_id,
                &req.action,
                &req.resource,
                &format!("DENY:{}", failed_cond),
            )
            .ok()
            .map(|r| r.record_hash);

        ApcDecision {
            allowed: false,
            satisfied_conditions: satisfied,
            failed_condition: Some(failed_cond.to_string()),
            reason: reason.to_string(),
            evidence_hash: ev_hash,
            intent_warning: None,
        }
    }
}

/// Cedar Policy Templates grounded from `arXiv:2608.15888` (`xmuruaga/bounded-agents`).
pub fn bounded_agents_apc_cedar_policies() -> &'static str {
    r#"// Bounded Agents: Agentic Principal Chain (APC) Cedar Policies (arXiv:2608.15888)
// Enforces C1..C6 conjunctive delegation security and cross-session composition invariants.

@id("arxiv-2608-15888-apc-c1-c3-envelope-seal-and-context")
forbid (
    principal,
    action,
    resource
)
when {
    !context.envelope_seal_verified ||
    context.actor_id != context.envelope_delegatee_id ||
    context.task_session_id != context.envelope_session_id ||
    context.policy_version != context.active_policy_version
};

@id("arxiv-2608-15888-apc-c2-pairwise-and-ktuple-exfiltration-guard")
forbid (
    principal,
    action,
    resource
)
when {
    context.composition_pairwise_violated ||
    context.composition_ktuple_violated ||
    context.cross_session_lineage_split_detected ||
    context.delegation_budget_exceeded
};

@id("arxiv-2608-15888-apc-c4-c5-c6-approval-evidence-intent")
forbid (
    principal,
    action,
    resource
)
when {
    (context.requires_approval && !context.approval_token_valid) ||
    !context.evidence_sink_healthy ||
    context.intent_strict_mismatch
};
"#
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_scope() -> ApcScope {
        ApcScope::new(
            ["docs/*", "external/email", "internal/*"],
            ["read_confidential", "send_email", "read_public"],
            ["CONFIDENTIAL", "PUBLIC"],
            [PairwiseRestriction::new(
                "no_confidential_exfil",
                "READ_CONFIDENTIAL",
                "EXTERNAL_TRANSMIT",
            )],
            [KTupleRestriction::new(
                "ordered_q3_exfil",
                vec![
                    KTupleStep {
                        action_class: "READ_CONFIDENTIAL".to_string(),
                        resource_pattern: "docs/q3-*".to_string(),
                    },
                    KTupleStep {
                        action_class: "EXTERNAL_TRANSMIT".to_string(),
                        resource_pattern: "external/*".to_string(),
                    },
                ],
            )],
        )
    }

    #[test]
    fn test_thm_4_6_asymmetric_meet_semilattice_and_monotonic_blast_radius() {
        let parent = sample_scope();
        let child_req = ApcScope::new(
            ["docs/q3-financials", "external/email", "ungranted/secret"],
            ["read_confidential", "send_email", "exec_shell"],
            ["CONFIDENTIAL"],
            [PairwiseRestriction::new(
                "no_code_exec_after_read",
                "READ_CONFIDENTIAL",
                "EXECUTE_CODE",
            )],
            [],
        );

        let narrowed = parent.meet(&child_req);
        assert!(narrowed.allows_resource("docs/q3-financials"));
        assert!(!narrowed.allows_resource("docs/q4-financials"));
        assert!(!narrowed.allows_resource("ungranted/secret"));
        assert!(narrowed.allows_action("read_confidential"));
        assert!(!narrowed.allows_action("exec_shell"));
        // Restrictions union (X1 U X2) while positive grants intersect
        assert_eq!(narrowed.pairwise_restrictions.len(), 2);
        assert_eq!(narrowed.ktuple_restrictions.len(), 1);
        assert!(narrowed.blast_radius() <= parent.blast_radius());
    }

    #[test]
    fn test_sealed_envelope_and_multi_hop_attenuation() {
        let key = b"oshoosi-apc-test-key-32-bytes!!!";
        let mut root_env = AuthorizationEnvelope::new_root(
            "env-hop-1",
            "user-alice",
            "orchestrator-agent",
            "sess-100",
            "v1.0",
            sample_scope(),
            DelegationBudgetSpec::default(),
            1_700_000_000,
            1_700_003_600,
            key,
        );

        assert!(root_env
            .attempt_in_place_scope_mutation(sample_scope())
            .is_err());

        let sub_scope = ApcScope::new(
            ["docs/q3-financials", "external/email"],
            ["read_confidential", "send_email"],
            ["CONFIDENTIAL", "PUBLIC"],
            [],
            [],
        );
        let hop2 = root_env
            .delegate_narrowed("env-hop-2", "worker-subagent", &sub_scope, key)
            .expect("hop 2 delegation must succeed");
        assert_eq!(hop2.hop_index, 2);
        assert_eq!(hop2.root_principal_id, "user-alice");
        assert!(hop2.verify_seal(key));
        assert!(hop2.effective_scope.blast_radius() <= root_env.effective_scope.blast_radius());
    }

    #[test]
    fn test_six_conjunctive_conditions_and_exfiltration_prevention() {
        let key = b"oshoosi-apc-test-key-32-bytes!!!";
        let pdp = ApcPolicyDecisionPoint::new(key.to_vec(), "v1.0", true);
        let env = AuthorizationEnvelope::new_root(
            "env-root",
            "principal-alice",
            "agent-worker-1",
            "sess-alpha",
            "v1.0",
            sample_scope(),
            DelegationBudgetSpec::default(),
            1_700_000_000,
            1_700_003_600,
            key,
        );
        let mut action_map = BTreeMap::new();
        action_map.insert(
            "read_confidential".to_string(),
            BTreeSet::from(["docs/*".to_string()]),
        );
        action_map.insert(
            "send_email".to_string(),
            BTreeSet::from(["external/email".to_string()]),
        );
        let intent = IntentSpec {
            intent_id: "intent-q3-summary".to_string(),
            intended_actions: BTreeSet::new(),
            intended_resources: BTreeSet::new(),
            action_resource_map: action_map,
            mode: IntentEnforcementMode::Strict,
        };

        // Step 1: Read confidential Q3 financials -> ALLOWED
        let req1 = ApcActionRequest {
            actor_id: "agent-worker-1".to_string(),
            action: "read_confidential".to_string(),
            resource: "docs/q3-financials".to_string(),
            data_classification: "CONFIDENTIAL".to_string(),
            parameters_canonical: "{}".to_string(),
            task_session_id: "sess-alpha".to_string(),
            policy_version: "v1.0".to_string(),
            now_unix: 1_700_000_100,
            requires_approval: false,
            approval_token: None,
            is_irreversible: false,
            sensitivity_tier: 2,
            is_cross_domain: false,
            cost_delta: 0.5,
        };
        let dec1 = pdp.evaluate(&env, &intent, &req1);
        assert!(dec1.allowed, "Step 1 read must be allowed: {:?}", dec1);

        // Step 2: Send external email in same session -> BLOCKED by C2 Composition
        let req2 = ApcActionRequest {
            action: "send_email".to_string(),
            resource: "external/email".to_string(),
            data_classification: "PUBLIC".to_string(),
            ..req1.clone()
        };
        let dec2 = pdp.evaluate(&env, &intent, &req2);
        assert!(!dec2.allowed);
        assert_eq!(dec2.failed_condition.as_deref(), Some("C2_COMPOSITION"));

        // Step 3: Adaptive attack — Cross-session splitting under same root principal ("principal-alice")
        let env_session_beta = AuthorizationEnvelope::new_root(
            "env-root-beta",
            "principal-alice",
            "agent-worker-2",
            "sess-beta",
            "v1.0",
            sample_scope(),
            DelegationBudgetSpec::default(),
            1_700_000_000,
            1_700_003_600,
            key,
        );
        let req_split = ApcActionRequest {
            actor_id: "agent-worker-2".to_string(),
            action: "send_email".to_string(),
            resource: "external/email".to_string(),
            data_classification: "PUBLIC".to_string(),
            task_session_id: "sess-beta".to_string(),
            ..req1
        };
        let dec_split = pdp.evaluate(&env_session_beta, &intent, &req_split);
        assert!(
            !dec_split.allowed,
            "Cross-session principal lineage guard must block adaptive session-splitting attack"
        );
        assert!(dec_split.reason.contains("CROSS_SESSION_LINEAGE"));
        assert!(pdp.evidence_sink.verify_integrity());
    }

    #[test]
    fn test_c4_single_use_approval_and_c5_fail_closed_evidence() {
        let key = b"oshoosi-apc-test-key-32-bytes!!!";
        let mut pdp = ApcPolicyDecisionPoint::new(key.to_vec(), "v1.0", true);
        let env = AuthorizationEnvelope::new_root(
            "env-c4",
            "principal-bob",
            "agent-ops",
            "sess-c4",
            "v1.0",
            sample_scope(),
            DelegationBudgetSpec::default(),
            1_700_000_000,
            1_700_003_600,
            key,
        );
        let intent = IntentSpec {
            intent_id: "intent-ops".to_string(),
            intended_actions: BTreeSet::from(["read_public".to_string()]),
            intended_resources: BTreeSet::from(["docs/*".to_string()]),
            action_resource_map: BTreeMap::new(),
            mode: IntentEnforcementMode::Strict,
        };
        let token = ApprovalToken::issue(
            "tok-001",
            "human-secops",
            "agent-ops",
            "read_public",
            "docs/readme",
            "sess-c4",
            "{\"fmt\":\"txt\"}",
            1_700_001_000,
            key,
        );
        let req = ApcActionRequest {
            actor_id: "agent-ops".to_string(),
            action: "read_public".to_string(),
            resource: "docs/readme".to_string(),
            data_classification: "PUBLIC".to_string(),
            parameters_canonical: "{\"fmt\":\"txt\"}".to_string(),
            task_session_id: "sess-c4".to_string(),
            policy_version: "v1.0".to_string(),
            now_unix: 1_700_000_200,
            requires_approval: true,
            approval_token: Some(token),
            is_irreversible: true,
            sensitivity_tier: 1,
            is_cross_domain: false,
            cost_delta: 0.1,
        };
        let first = pdp.evaluate(&env, &intent, &req);
        assert!(first.allowed);

        // Replay of the same ApprovalToken must be denied (C4_APPROVAL_REPLAY)
        let replay = pdp.evaluate(&env, &intent, &req);
        assert!(!replay.allowed);
        assert_eq!(
            replay.failed_condition.as_deref(),
            Some("C4_APPROVAL_REPLAY")
        );

        // Disable evidence sink -> must fail closed on C5_EVIDENCE
        pdp.evidence_sink.available = false;
        let mut req_no_approval = req.clone();
        req_no_approval.requires_approval = false;
        req_no_approval.is_irreversible = false;
        let c5_fail = pdp.evaluate(&env, &intent, &req_no_approval);
        assert!(!c5_fail.allowed);
        assert_eq!(c5_fail.failed_condition.as_deref(), Some("C5_EVIDENCE"));
    }

    #[test]
    fn test_cedar_policies_non_empty() {
        let policies = bounded_agents_apc_cedar_policies();
        assert!(policies.contains("arxiv-2608-15888-apc-c1-c3-envelope-seal-and-context"));
        assert!(policies.contains("arxiv-2608-15888-apc-c2-pairwise-and-ktuple-exfiltration-guard"));
        assert!(policies.contains("arxiv-2608-15888-apc-c4-c5-c6-approval-evidence-intent"));
    }
}
