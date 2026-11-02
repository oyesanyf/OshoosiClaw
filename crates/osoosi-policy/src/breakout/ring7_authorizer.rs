use super::*;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use hmac::{Hmac, Mac};
use osoosi_behavioral::{EmbeddingGemma2Engine, MatryoshkaDim};
use osoosi_types::{ArmRole, HostSecurityEvent, OctopusSecurityError};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

// ============================================================================
// 7. Ring 7: Capability & Effect Authorization Layer (`Ring7CapabilityEffectAuthorizer`)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionEgressBudgetState {
    pub requests_used: u32,
    pub max_requests: u32,
    pub bytes_used: usize,
    pub max_bytes: usize,
}

#[derive(Debug, Clone)]
pub struct CrownJewelProtectedAsset {
    pub asset_id: String,
    pub canonical_path: String,
    pub embedding_128d: Vec<f32>,
    pub concept_keywords: HashSet<String>,
}

pub struct Ring7CapabilityEffectAuthorizer {
    pub policy_version: String,
    pub workspace_allowlist: Arc<SignedWorkspaceInstructionAllowlist>,
    pub causal_graph: Arc<CausalSecurityGraph>,
    pub capability_cache: Arc<RevocationBoundCapabilityCache>,
    pub policy_store: Arc<ProtectedPolicyStore>,
    pub overload_controller: Arc<SafeTelemetryOverloadController>,
    pub integrity_recovery: Arc<ExternalIntegrityVerifierAndRecovery>,
    pub embedding_engine: EmbeddingGemma2Engine,
    pub temporal_evaluator: Arc<DogwoodTemporalPolicyEvaluator>,
    crown_jewels: DashMap<String, CrownJewelProtectedAsset>,
    egress_budgets: DashMap<String, SessionEgressBudgetState>,
    decision_counter: AtomicU64,
}

impl Default for Ring7CapabilityEffectAuthorizer {
    fn default() -> Self {
        Self::new()
    }
}

impl Ring7CapabilityEffectAuthorizer {
    pub fn new() -> Self {
        let auth = Self {
            policy_version: CEDAR_BREAKOUT_POLICY_VERSION.to_string(),
            workspace_allowlist: Arc::new(SignedWorkspaceInstructionAllowlist::default()),
            causal_graph: Arc::new(CausalSecurityGraph::default()),
            capability_cache: Arc::new(RevocationBoundCapabilityCache::default()),
            policy_store: Arc::new(ProtectedPolicyStore::default()),
            overload_controller: Arc::new(SafeTelemetryOverloadController::default()),
            integrity_recovery: Arc::new(ExternalIntegrityVerifierAndRecovery::default()),
            embedding_engine: EmbeddingGemma2Engine::new(MatryoshkaDim::Dim128),
            temporal_evaluator: Arc::new(DogwoodTemporalPolicyEvaluator::default()),
            crown_jewels: DashMap::new(),
            egress_budgets: DashMap::new(),
            decision_counter: AtomicU64::new(1),
        };
        auth.register_crown_jewel_asset(
            "crown-jewel-phaselock-kernel",
            "crates/edr-phaselock/src/lib.rs",
            "Proprietary OshoosiClaw Phaselock sub-linear zero-allocation ring buffer kernel consensus algorithm with secret prime modulus 2147483647 and HMAC epoch key derivation.",
        );
        auth
    }

    pub fn record_temporal_event(
        &self,
        session_id: &str,
        event_type: TemporalEventType,
        resource_path: Option<String>,
    ) {
        self.temporal_evaluator
            .record_event(session_id, event_type, resource_path);
    }

    pub fn record_temporal_declassification(&self, session_id: &str) {
        self.temporal_evaluator.record_declassification(session_id);
    }

    pub fn register_crown_jewel_asset(&self, asset_id: &str, canonical_path: &str, content: &str) {
        let emb = self.embedding_engine.embed_text(content);
        let keywords: HashSet<String> = content
            .split(|c: char| !c.is_alphanumeric() && c != '_' && c != '-')
            .map(|w| w.to_ascii_lowercase())
            .filter(|w| w.len() >= 5)
            .collect();
        let norm_path = canonical_path.replace('\\', "/").to_ascii_lowercase();
        self.crown_jewels.insert(
            norm_path.clone(),
            CrownJewelProtectedAsset {
                asset_id: asset_id.to_string(),
                canonical_path: norm_path,
                embedding_128d: emb,
                concept_keywords: keywords,
            },
        );
    }

    pub fn classify_file_path(&self, path: &str) -> DataClassification {
        let lower = path.replace('\\', "/").to_ascii_lowercase();
        if self.crown_jewels.contains_key(&lower)
            || lower.contains(".env")
            || lower.contains("id_rsa")
            || lower.contains("id_ed25519")
            || lower.contains("/.ssh/")
            || lower.contains("/.aws/")
            || lower.contains("lsass")
            || lower.contains("/etc/shadow")
            || lower.contains("ntds.dit")
            || lower.contains("crown_jewel")
            || lower.contains("secret_key")
            || lower.contains("phaselock")
        {
            DataClassification::CrownJewelSecret
        } else if lower.contains("config") || lower.contains("credentials") {
            DataClassification::Confidential
        } else {
            DataClassification::InternalWorkspace
        }
    }

    pub fn compute_covert_jitter_ms(&self, session_id: &str, resource_id: &str, turn: u32) -> u64 {
        let h = blake3::hash(format!("jitter:{}:{}:{}", session_id, resource_id, turn).as_bytes());
        let b = h.as_bytes();
        let raw = u16::from_le_bytes([b[0], b[1]]) as u64;
        50 + (raw % 201)
    }

    pub fn max_crown_jewel_semantic_similarity(&self, payload: &str) -> f64 {
        if payload.trim().is_empty() {
            return 0.0;
        }
        let emb = self.embedding_engine.embed_text(payload);
        let payload_words: HashSet<String> = payload
            .split(|c: char| !c.is_alphanumeric() && c != '_' && c != '-')
            .map(|w| w.to_ascii_lowercase())
            .filter(|w| w.len() >= 5)
            .collect();

        let mut max_score = 0.0_f64;
        for item in self.crown_jewels.iter() {
            let asset = item.value();
            let dot: f32 = emb
                .iter()
                .zip(asset.embedding_128d.iter())
                .map(|(a, b)| a * b)
                .sum();
            let cosine = (dot as f64).clamp(0.0, 1.0);
            let overlap = if asset.concept_keywords.is_empty() || payload_words.is_empty() {
                0.0
            } else {
                let shared = payload_words.intersection(&asset.concept_keywords).count();
                (shared as f64) / (asset.concept_keywords.len().clamp(1, 12) as f64)
            };
            let combined = (cosine * 0.65 + overlap.min(1.0) * 0.55).clamp(0.0, 1.0);
            if combined > max_score {
                max_score = combined;
            }
        }
        max_score
    }

    pub fn set_session_egress_budget(&self, session_id: &str, max_requests: u32, max_bytes: usize) {
        self.egress_budgets.insert(
            session_id.to_string(),
            SessionEgressBudgetState {
                requests_used: 0,
                max_requests,
                bytes_used: 0,
                max_bytes,
            },
        );
    }

    fn check_and_consume_egress_budget(&self, session_id: &str, payload_bytes: usize) -> bool {
        let Some(mut budget) = self.egress_budgets.get_mut(session_id) else {
            return false;
        };
        let next_req = budget.requests_used.saturating_add(1);
        let next_bytes = budget.bytes_used.saturating_add(payload_bytes);
        if next_req > budget.max_requests || next_bytes > budget.max_bytes {
            return true;
        }
        budget.requests_used = next_req;
        budget.bytes_used = next_bytes;
        false
    }

    pub fn evaluate_cedar_request(
        &self,
        principal: &CedarPrincipal,
        action: CedarAction,
        resource: &CedarResource,
        mut context: CedarContext,
        enforcement_stage: EnforcementStage,
    ) -> PolicyDecisionRecord {
        let taint_epoch = self.capability_cache.current_taint_epoch();
        let revocation_seq = self.capability_cache.current_revocation_seq();
        let active_policy_version = self.policy_store.active_version_label();
        context.taint_epoch = taint_epoch;
        context.revocation_seq = revocation_seq;
        context.policy_version = active_policy_version.clone();

        // Resolve live causal-graph state and workload mode BEFORE consulting the capability cache so a
        // cached permit can never mask a session termination, capability revocation, or overload
        // quarantine that happened without an epoch advance.
        let graph_state = self.causal_graph.resolve_state(
            Some(&principal.process_instance_key),
            None,
            &principal.session_id,
        );
        let workload_mode = self
            .overload_controller
            .workload_modes
            .get(&principal.session_id)
            .map(|m| *m.value());

        let mut hasher = blake3::Hasher::new();
        hasher.update(principal.session_id.as_bytes());
        hasher.update(b"|");
        hasher.update(principal.process_instance_key.as_bytes());
        hasher.update(b"|");
        hasher.update(&[principal.authority_level.rank()]);
        hasher.update(b"|");
        for cap in &principal.approved_capabilities {
            hasher.update(cap.as_bytes());
            hasher.update(b",");
        }
        hasher.update(b"|");
        hasher.update(resource.resource_type.as_bytes());
        hasher.update(b"|");
        hasher.update(&[resource.classification as u8]);
        hasher.update(b"|");
        hasher.update(&[
            resource.is_signed_and_allowlisted as u8,
            resource.is_approved_child_binary as u8,
            resource.is_task_scoped_destination as u8,
            resource.is_declassified_approved_sink as u8,
        ]);
        hasher.update(b"|");
        if let Some(ref svc) = resource.service_identity {
            hasher.update(svc.as_bytes());
        }
        hasher.update(b"|");
        if let Some(ref op) = resource.service_operation {
            hasher.update(op.as_bytes());
        }
        hasher.update(b"|");
        hasher.update(&[context.has_crown_jewel_taint as u8]);
        hasher.update(b"|");
        hasher.update(&[context.highest_data_classification as u8]);
        hasher.update(b"|");
        hasher.update(&context.taint_level.to_bits().to_le_bytes());
        hasher.update(b"|");
        hasher.update(&context.cumulative_salami_turns.to_le_bytes());
        hasher.update(b"|");
        hasher.update(&[
            context.has_approved_capability as u8,
            context.has_cryptographic_declassification as u8,
            context.upward_authority_promotion_attempted as u8,
            context.egress_budget_exceeded as u8,
        ]);
        hasher.update(b"|");
        hasher.update(&context.semantic_cosine_similarity.to_bits().to_le_bytes());
        hasher.update(b"|");
        hasher.update(&context.covert_jitter_applied_ms.to_le_bytes());
        hasher.update(b"|");
        hasher.update(&[
            graph_state.session_terminated as u8,
            graph_state.capabilities_revoked as u8,
            graph_state.has_crown_jewel_taint as u8,
        ]);
        hasher.update(b"|");
        hasher.update(&graph_state.taint_level.to_bits().to_le_bytes());
        hasher.update(b"|");
        hasher.update(&graph_state.cumulative_turns.to_le_bytes());
        hasher.update(b"|");
        if let Some(wm) = workload_mode {
            hasher.update(&[wm as u8]);
        } else {
            hasher.update(&[0xFF]);
        }
        let decision_input_fingerprint = hasher.finalize().to_hex().to_string();

        let cache_key = CapabilityCacheKey {
            principal_id: principal.principal_id.clone(),
            action,
            resource_id: resource.resource_id.clone(),
            policy_version: active_policy_version.clone(),
            taint_epoch,
            revocation_seq,
            decision_input_fingerprint,
        };

        if let Some(cached) = self.capability_cache.get_cached(&cache_key) {
            return cached;
        }

        let seq = self.decision_counter.fetch_add(1, Ordering::SeqCst);
        let mut d_hasher = blake3::Hasher::new();
        d_hasher.update(b"cedar-eval:");
        d_hasher.update(principal.principal_id.as_bytes());
        d_hasher.update(b":");
        d_hasher.update(action.cedar_id().as_bytes());
        d_hasher.update(b":");
        d_hasher.update(resource.resource_id.as_bytes());
        d_hasher.update(b":");
        d_hasher.update(context.causal_event_id.as_bytes());
        d_hasher.update(b":");
        d_hasher.update(&taint_epoch.to_le_bytes());
        d_hasher.update(b":");
        d_hasher.update(&revocation_seq.to_le_bytes());
        d_hasher.update(b":");
        d_hasher.update(&seq.to_le_bytes());
        let decision_hash = d_hasher.finalize();
        let policy_decision_id = format!("pdec-{:06}-{}", seq, &decision_hash.to_hex()[..14]);

        let mut matched_forbid = Vec::new();
        let mut matched_permit = Vec::new();

        if is_reserved_principal(&principal.principal_id) {
            let role_match = principal
                .authenticated_role
                .as_ref()
                .and_then(|r| validate_cedar_principal_role(&principal.principal_id, r).ok());
            if role_match.is_none() {
                matched_forbid.push(format!(
                    "CEDAR_PRINCIPAL_SPOOF_BLOCKED: principal '{}' is reserved and conflicts with authenticated role {:?}",
                    principal.principal_id, principal.authenticated_role
                ));
            }
        }

        if graph_state.session_terminated {
            matched_forbid.push("CEDAR-FORBID-SESSION-TERMINATED".to_string());
        }
        if graph_state.capabilities_revoked {
            matched_forbid.push("CEDAR-FORBID-CAPABILITIES-REVOKED".to_string());
        }

        if let Some(w_mode) = workload_mode {
            match w_mode {
                WorkloadDegradationMode::QuarantineAffectedWorkloadOnly => {
                    matched_forbid.push("CEDAR-FORBID-WORKLOAD-OVERLOAD-QUARANTINED".to_string());
                }
                WorkloadDegradationMode::StrictReadOnlyContainment
                    if matches!(
                        action,
                        CedarAction::ExternalWrite
                            | CedarAction::ChildProcessExec
                            | CedarAction::PrivilegedLocalControl
                    ) =>
                {
                    matched_forbid.push("CEDAR-FORBID-WORKLOAD-READONLY-DEGRADATION".to_string());
                }
                _ => {}
            }
        }

        let effective_crown_jewel_taint =
            context.has_crown_jewel_taint || graph_state.has_crown_jewel_taint;
        let effective_taint_level = context.taint_level.max(graph_state.taint_level);

        if action == CedarAction::ExternalWrite
            && effective_crown_jewel_taint
            && !context.has_cryptographic_declassification
        {
            matched_forbid.push(
                "CEDAR-FORBID-001: forbid(principal, action == Action::\"ExternalWrite\", resource) when { context.hasCrownJewelTaint }".to_string(),
            );
        }

        if action == CedarAction::PrivilegedLocalControl && !context.has_approved_capability {
            matched_forbid.push(
                "CEDAR-FORBID-002: forbid(principal, action == Action::\"PrivilegedLocalControl\", resource) unless { context.hasApprovedCapability }".to_string(),
            );
        }

        if matches!(
            action,
            CedarAction::ExternalWrite | CedarAction::ExternalNetworkConnect
        ) {
            if effective_crown_jewel_taint
                && !resource.is_declassified_approved_sink
                && !context.has_cryptographic_declassification
            {
                matched_forbid.push(
                    "CEDAR-FORBID-003A: Crown-Jewel tainted lineage forbidden from outbound network/write without cryptographic declassification".to_string(),
                );
            }
            if context.semantic_cosine_similarity >= 0.68
                && !context.has_cryptographic_declassification
            {
                matched_forbid.push(format!(
                    "CEDAR-FORBID-003B: Tier-2 semantic similarity {:.3} >= 0.68 against Crown-Jewel asset",
                    context.semantic_cosine_similarity
                ));
            }
            if context.egress_budget_exceeded {
                matched_forbid.push(
                    "CEDAR-FORBID-003C: Session outbound egress request/byte budget exceeded (covert channel rate limit)".to_string(),
                );
            }
            if !resource.is_task_scoped_destination {
                matched_forbid.push(
                    "CEDAR-FORBID-003D: Destination is outside the pinned task-scoped egress allowlist".to_string(),
                );
            }
            if effective_taint_level >= 0.70 && !context.has_cryptographic_declassification {
                matched_forbid.push(format!(
                    "CEDAR-FORBID-003E: Cumulative causal taint {:.2} >= 0.70 forbids external egress",
                    effective_taint_level
                ));
            }
        }

        if action == CedarAction::ChildProcessExec {
            if context.upward_authority_promotion_attempted {
                matched_forbid.push(
                    "CEDAR-FORBID-004A: Upward authority promotion from L4/L5 forbidden"
                        .to_string(),
                );
            }
            if !resource.is_approved_child_binary || !resource.is_signed_and_allowlisted {
                matched_forbid.push(
                    "CEDAR-FORBID-004B: Child process or build script is unsigned or not allowlisted for this task".to_string(),
                );
            }
            if effective_taint_level >= 0.75 {
                matched_forbid.push(format!(
                    "CEDAR-FORBID-004C: High causal taint {:.2} forbids spawning child processes",
                    effective_taint_level
                ));
            }
            // F05: Dogwood MFOTL past-only temporal evaluation:
            // Multi-turn payload fragmentation: UntrustedWebInput -> ScratchFileWrite -> SubprocessEnvOrArg
            if context.subprocess_env_or_arg_tainted
                || (context.has_untrusted_web_input && context.has_scratch_file_write)
            {
                if !context.has_cryptographic_declassification {
                    matched_forbid.push(
                        "CEDAR-FORBID-TEMPORAL-TAINT-FRAGMENTATION: CEDAR-FORBID-004D: Multi-turn payload fragmentation detected: untrusted web input flowed into scratch file and subsequently into subprocess execution within temporal window".to_string(),
                    );
                }
            } else {
                let now_sec = Utc::now().timestamp();
                let (violated, reason) = self.temporal_evaluator.evaluate_scratch_file_touch(
                    &principal.session_id,
                    &resource.resource_id,
                    now_sec,
                    Some(context.temporal_trace_window_seconds),
                );
                if violated {
                    if !context.has_cryptographic_declassification {
                        matched_forbid.push(
                            reason.unwrap_or_else(|| {
                                "CEDAR-FORBID-TEMPORAL-TAINT-FRAGMENTATION: CEDAR-FORBID-004D: Multi-turn payload fragmentation detected: untrusted web input flowed into scratch file and subsequently into subprocess execution within temporal window".to_string()
                            }),
                        );
                    }
                } else {
                    let (flow_violated, flow_reason) = self.temporal_evaluator.evaluate_taint_flow(
                        &principal.session_id,
                        now_sec,
                        Some(context.temporal_trace_window_seconds),
                    );
                    if flow_violated && !context.has_cryptographic_declassification {
                        matched_forbid.push(
                            flow_reason.unwrap_or_else(|| {
                                "CEDAR-FORBID-TEMPORAL-TAINT-FRAGMENTATION: CEDAR-FORBID-004D: Multi-turn payload fragmentation detected: untrusted web input flowed into scratch file and subsequently into subprocess execution within temporal window".to_string()
                            }),
                        );
                    }
                }
            }
        }

        if action == CedarAction::DynamicCodeExec
            && (!resource.is_signed_and_allowlisted
                || principal.authority_level.rank()
                    > AuthorityLevel::L3TrustedApplicationInstruction.rank())
        {
            matched_forbid.push(
                "CEDAR-FORBID-005: Unsigned or untrusted dynamic code/module load forbidden"
                    .to_string(),
            );
        }

        if action == CedarAction::SensitiveFileAccess {
            if principal.authority_level.rank() >= AuthorityLevel::L4WorkspaceConfiguration.rank()
                && resource.classification == DataClassification::CrownJewelSecret
            {
                matched_forbid.push(
                    "CEDAR-FORBID-006A: L4/L5 untrusted instruction cannot authorize Crown-Jewel secret access".to_string(),
                );
            }
            if !resource.is_task_scoped_destination {
                matched_forbid.push(
                    "CEDAR-FORBID-006B: Sensitive credential/system file outside task scope"
                        .to_string(),
                );
            }
        }

        if action == CedarAction::CrossSessionTransfer
            && (effective_crown_jewel_taint || effective_taint_level >= 0.50)
            && !context.has_cryptographic_declassification
        {
            matched_forbid.push(
                "CEDAR-FORBID-007: Cross-session transfer of tainted/Crown-Jewel data forbidden without supervisor ZK declassification".to_string(),
            );
        }

        if matched_forbid.is_empty() {
            match action {
                CedarAction::ChildProcessExec
                    if resource.is_approved_child_binary && resource.is_signed_and_allowlisted =>
                {
                    matched_permit.push("CEDAR-PERMIT-CHILD-EXEC-SCOPED".to_string());
                }
                CedarAction::SensitiveFileAccess if resource.is_task_scoped_destination => {
                    matched_permit.push("CEDAR-PERMIT-SCOPED-FILE-READ".to_string());
                }
                CedarAction::ExternalNetworkConnect if resource.is_task_scoped_destination => {
                    matched_permit.push("CEDAR-PERMIT-SCOPED-NETWORK-CONNECT".to_string());
                }
                CedarAction::ExternalWrite
                    if resource.is_task_scoped_destination
                        && (!effective_crown_jewel_taint
                            || context.has_cryptographic_declassification) =>
                {
                    matched_permit.push("CEDAR-PERMIT-SCOPED-EXTERNAL-WRITE".to_string());
                }
                CedarAction::PrivilegedLocalControl if context.has_approved_capability => {
                    matched_permit.push("CEDAR-PERMIT-APPROVED-LOCAL-CONTROL".to_string());
                }
                CedarAction::DynamicCodeExec if resource.is_signed_and_allowlisted => {
                    matched_permit.push("CEDAR-PERMIT-SIGNED-MODULE-LOAD".to_string());
                }
                CedarAction::CrossSessionTransfer
                    if (!effective_crown_jewel_taint && effective_taint_level < 0.50)
                        || context.has_cryptographic_declassification =>
                {
                    matched_permit.push("CEDAR-PERMIT-CLEAN-OR-DECLASSIFIED-TRANSFER".to_string());
                }
                _ => {}
            }
        }

        let allowed = matched_forbid.is_empty() && !matched_permit.is_empty();
        let reason = if allowed {
            format!(
                "PERMIT [{}]: Authorized by {}",
                action.cedar_id(),
                matched_permit.join(", ")
            )
        } else if !matched_forbid.is_empty() {
            format!(
                "DENY_FORBID [{}]: Blocked by {}",
                action.cedar_id(),
                matched_forbid.join("; ")
            )
        } else {
            format!(
                "DENY_DEFAULT [{}]: No Cedar permit rule matched for resource '{}'",
                action.cedar_id(),
                resource.resource_id
            )
        };

        let record = PolicyDecisionRecord {
            allowed,
            policy_decision_id,
            causal_event_id: context.causal_event_id,
            policy_version: active_policy_version,
            action,
            enforcement_stage,
            matched_forbid_policies: matched_forbid,
            matched_permit_policies: matched_permit,
            reason,
            taint_epoch_at_decision: taint_epoch,
            revocation_seq_at_decision: revocation_seq,
            covert_jitter_ms: context.covert_jitter_applied_ms,
            evaluated_at: Utc::now(),
        };

        if allowed && action != CedarAction::SensitiveFileAccess {
            self.capability_cache.put_cached(cache_key, record.clone());
        }
        record
    }

    #[allow(clippy::result_large_err)] // Public capability guard API returns PolicyDecisionRecord by value to prevent heap allocation on security fast-path
    pub fn execute_guarded_sensitive_read<F, R>(
        &self,
        principal: &CedarPrincipal,
        file_path: &str,
        is_task_scoped: bool,
        read_fn: F,
    ) -> Result<(R, PolicyDecisionRecord), PolicyDecisionRecord>
    where
        F: FnOnce() -> R,
    {
        self.capability_cache
            .in_flight_sensitive_reads
            .fetch_add(1, Ordering::SeqCst);
        let _write_guard = self.capability_cache.taint_transition_barrier.write();

        let classification = self.classify_file_path(file_path);
        let resource = CedarResource {
            resource_id: file_path.to_string(),
            resource_type: "File".to_string(),
            classification,
            is_signed_and_allowlisted: true,
            is_approved_child_binary: false,
            is_task_scoped_destination: is_task_scoped,
            is_declassified_approved_sink: false,
            service_identity: None,
            service_operation: None,
        };

        let pre_state = self.causal_graph.resolve_state(
            Some(&principal.process_instance_key),
            None,
            &principal.session_id,
        );
        let ctx = CedarContext {
            policy_version: self.policy_store.active_version_label(),
            causal_event_id: pre_state.last_causal_event_id.clone(),
            has_crown_jewel_taint: pre_state.has_crown_jewel_taint,
            highest_data_classification: pre_state.highest_classification.max(classification),
            taint_level: pre_state.taint_level,
            cumulative_salami_turns: pre_state.cumulative_turns,
            has_approved_capability: false,
            has_cryptographic_declassification: false,
            upward_authority_promotion_attempted: false,
            egress_budget_exceeded: false,
            semantic_cosine_similarity: 0.0,
            covert_jitter_applied_ms: 0,
            taint_epoch: self.capability_cache.current_taint_epoch(),
            revocation_seq: self.capability_cache.current_revocation_seq(),
            has_untrusted_web_input: false,
            has_scratch_file_write: false,
            subprocess_env_or_arg_tainted: false,
            temporal_trace_window_seconds: 7200,
        };

        let decision = self.evaluate_cedar_request(
            principal,
            CedarAction::SensitiveFileAccess,
            &resource,
            ctx,
            EnforcementStage::PreExecutionPrevented,
        );

        if !decision.allowed {
            self.capability_cache
                .in_flight_sensitive_reads
                .fetch_sub(1, Ordering::SeqCst);
            return Err(decision);
        }

        if classification >= DataClassification::Confidential {
            self.capability_cache.advance_taint_and_revocation();
        }
        let step_taint = match classification {
            DataClassification::CrownJewelSecret => 0.95,
            DataClassification::Confidential => 0.55,
            DataClassification::InternalWorkspace => 0.10,
            DataClassification::Public => 0.0,
        };
        let updated_node = self.causal_graph.record_causal_step(
            &principal.process_instance_key,
            &principal.session_id,
            step_taint,
            classification,
            0.0,
        );

        let output = read_fn();
        self.capability_cache
            .in_flight_sensitive_reads
            .fetch_sub(1, Ordering::SeqCst);

        let mut final_decision = decision;
        final_decision.causal_event_id = updated_node.last_causal_event_id;
        final_decision.taint_epoch_at_decision = self.capability_cache.current_taint_epoch();
        final_decision.revocation_seq_at_decision = self.capability_cache.current_revocation_seq();
        Ok((output, final_decision))
    }

    pub fn execute_guarded_external_write<F, R>(
        &self,
        principal: &CedarPrincipal,
        destination_url: &str,
        payload: &str,
        is_task_scoped_destination: bool,
        declassification_receipt_id: Option<&str>,
        effect_fn: F,
    ) -> GuardedEffectOutcome<R>
    where
        F: FnOnce() -> R,
    {
        let pre_state = self.causal_graph.resolve_state(
            Some(&principal.process_instance_key),
            None,
            &principal.session_id,
        );
        let has_valid_declassification = declassification_receipt_id
            .map(|rid| {
                self.causal_graph.verify_declassification_receipt(
                    rid,
                    &principal.session_id,
                    payload,
                )
            })
            .unwrap_or(false);

        let budget_exceeded =
            self.check_and_consume_egress_budget(&principal.session_id, payload.len());
        let sem_sim = self.max_crown_jewel_semantic_similarity(payload);
        let jitter_ms = self.compute_covert_jitter_ms(
            &principal.session_id,
            destination_url,
            pre_state.cumulative_turns,
        );

        let resource = CedarResource {
            resource_id: destination_url.to_string(),
            resource_type: "ExternalEndpoint".to_string(),
            classification: pre_state.highest_classification,
            is_signed_and_allowlisted: true,
            is_approved_child_binary: false,
            is_task_scoped_destination,
            is_declassified_approved_sink: has_valid_declassification,
            service_identity: Some("ExternalSaaS".to_string()),
            service_operation: Some("PublishWrite".to_string()),
        };

        let ctx = CedarContext {
            policy_version: self.policy_store.active_version_label(),
            causal_event_id: pre_state.last_causal_event_id.clone(),
            has_crown_jewel_taint: pre_state.has_crown_jewel_taint,
            highest_data_classification: pre_state.highest_classification,
            taint_level: pre_state.taint_level,
            cumulative_salami_turns: pre_state.cumulative_turns,
            has_approved_capability: principal
                .approved_capabilities
                .iter()
                .any(|c| c == "ExternalWrite"),
            has_cryptographic_declassification: has_valid_declassification,
            upward_authority_promotion_attempted: false,
            egress_budget_exceeded: budget_exceeded,
            semantic_cosine_similarity: sem_sim,
            covert_jitter_applied_ms: jitter_ms,
            taint_epoch: self.capability_cache.current_taint_epoch(),
            revocation_seq: self.capability_cache.current_revocation_seq(),
            has_untrusted_web_input: false,
            has_scratch_file_write: false,
            subprocess_env_or_arg_tainted: false,
            temporal_trace_window_seconds: 7200,
        };

        let decision = self.evaluate_cedar_request(
            principal,
            CedarAction::ExternalWrite,
            &resource,
            ctx,
            EnforcementStage::PreExecutionPrevented,
        );

        if !decision.allowed {
            return GuardedEffectOutcome::DeniedPreExecution {
                policy_decision_id: decision.policy_decision_id,
                causal_event_id: decision.causal_event_id,
                reason: decision.reason,
            };
        }

        let _read_guard = self.capability_cache.taint_transition_barrier.read();
        let current_taint_epoch = self.capability_cache.current_taint_epoch();
        let current_revocation_seq = self.capability_cache.current_revocation_seq();
        let in_flight = self.capability_cache.in_flight_sensitive_reads();
        let latest_state = self.causal_graph.resolve_state(
            Some(&principal.process_instance_key),
            None,
            &principal.session_id,
        );

        if in_flight > 0
            || current_taint_epoch != decision.taint_epoch_at_decision
            || current_revocation_seq != decision.revocation_seq_at_decision
            || (latest_state.has_crown_jewel_taint && !has_valid_declassification)
            || latest_state.capabilities_revoked
            || latest_state.session_terminated
        {
            return GuardedEffectOutcome::DeniedByConcurrentRevocation {
                policy_decision_id: decision.policy_decision_id,
                causal_event_id: latest_state.last_causal_event_id,
                decision_taint_epoch: decision.taint_epoch_at_decision,
                current_taint_epoch,
                decision_revocation_seq: decision.revocation_seq_at_decision,
                current_revocation_seq,
                reason: "DENY_CONCURRENT_REVOCATION_BARRIER: Taint epoch / revocation_seq advanced or Crown-Jewel read occurred before ExternalWrite commit".to_string(),
            };
        }

        let output = effect_fn();
        GuardedEffectOutcome::Committed {
            output,
            policy_decision_id: decision.policy_decision_id,
            causal_event_id: decision.causal_event_id,
        }
    }

    pub fn evaluate_os_event(&self, event: &HostSecurityEvent) -> PolicyDecisionRecord {
        let get_str = |keys: &[&str]| -> String {
            for k in keys {
                if let Some(s) = event.data.get(*k).and_then(|v| v.as_str()) {
                    if !s.trim().is_empty() {
                        return s.trim().to_string();
                    }
                }
            }
            String::new()
        };
        let get_u32 = |keys: &[&str]| -> u32 {
            for k in keys {
                if let Some(v) = event.data.get(*k) {
                    if let Some(n) = v.as_u64() {
                        return n as u32;
                    }
                    if let Some(s) = v.as_str() {
                        if let Ok(n) = s.parse::<u32>() {
                            return n;
                        }
                    }
                }
            }
            0
        };

        let pid = get_u32(&["ProcessId", "process_id", "pid", "SourceProcessId"]);
        let parent_pid = get_u32(&[
            "ParentProcessId",
            "parent_process_id",
            "ppid",
            "ClientProcessId",
        ]);
        let start_time_100ns = event
            .data
            .get("ProcessStartTime100ns")
            .and_then(|v| v.as_u64())
            .unwrap_or_else(|| event.timestamp.timestamp_nanos_opt().unwrap_or(1000) as u64);

        let image = get_str(&["Image", "image", "ProcessName", "SourceImage"]);
        let image_loaded = get_str(&["ImageLoaded", "image_loaded", "ModulePath"]);
        let cmdline = get_str(&["CommandLine", "command_line", "Payload"]);
        let target_file = get_str(&["TargetFilename", "target_filename", "FilePath", "Path"]);
        let dest_ip = get_str(&["DestinationIp", "destination_ip", "DestAddress"]);
        let dest_host = get_str(&["DestinationHostname", "destination_hostname", "QueryName"]);
        let dest_port = get_u32(&["DestinationPort", "destination_port", "DestPort"]) as u16;
        let pipe_name = get_str(&["PipeName", "pipe_name", "IpcTarget"]);
        let http_method = get_str(&["HttpMethod", "http_method", "Operation"]);
        let fallback_session_id = {
            let s = get_str(&["SessionId", "session_id", "AgentSessionId"]);
            if s.is_empty() {
                "os-default-session".to_string()
            } else {
                s
            }
        };

        let requested_authority = match event.data.get("AuthorityLevel").and_then(|v| v.as_u64()) {
            Some(1) => AuthorityLevel::L1SystemSecurityPolicy,
            Some(2) => AuthorityLevel::L2AuthorizedUserObjective,
            Some(3) => AuthorityLevel::L3TrustedApplicationInstruction,
            Some(4) => AuthorityLevel::L4WorkspaceConfiguration,
            Some(5) => AuthorityLevel::L5UntrustedRetrievedContent,
            _ => AuthorityLevel::L2AuthorizedUserObjective,
        };

        // P1.2 Confused-Deputy Broker Attribution: if the process is an OS/developer broker
        // (`WmiPrvSE.exe`, `svchost.exe`, `conhost.exe`, `git-remote-https.exe`, `ssh.exe`),
        // bind it to the requesting client process/session!
        let node_state = if CausalSecurityGraph::is_broker_process_image(&image) && parent_pid > 0 {
            let (broker_state, _) = self.causal_graph.attribute_broker_operation(
                pid.max(1),
                start_time_100ns,
                &image,
                parent_pid,
                &fallback_session_id,
            );
            broker_state
        } else {
            let parent_instance_key = event
                .data
                .get("ParentInstanceKey")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .or_else(|| {
                    if parent_pid > 0 {
                        self.causal_graph
                            .pid_to_latest_instance
                            .get(&parent_pid)
                            .map(|r| r.value().clone())
                    } else {
                        None
                    }
                });
            let image_blake3 = blake3::hash(format!("{}:{}", image, cmdline).as_bytes())
                .to_hex()
                .to_string();
            let proc_identity = ProcessInstanceIdentity::new(
                pid.max(1),
                start_time_100ns,
                image_blake3,
                parent_instance_key,
                event
                    .data
                    .get("JobObjectId")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                fallback_session_id.clone(),
            );
            self.causal_graph
                .register_process_instance(proc_identity, requested_authority)
        };

        let session_id = node_state.origin_session_id.clone();
        let proc_key = node_state.node_key.clone();

        let is_signed = event
            .data
            .get("Signed")
            .and_then(|v| v.as_bool())
            .or_else(|| {
                event
                    .data
                    .get("Signed")
                    .and_then(|v| v.as_str())
                    .map(|s| s.eq_ignore_ascii_case("true"))
            })
            .unwrap_or(true);

        // P0.1 / P0.3: Never use `PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES`
        // to block third-party developer `.dll`/`.pyd` builds in approved workspace/toolchain directories.
        // Instead, distinguish legitimate developer/toolchain libraries from untrusted temp/download drops
        // and enforce pre-effect restrictions on subsequent sensitive resource access and outbound connections.
        let (action, resource, stage, sem_sim, jitter_ms) = match event.event_id {
            7 => {
                let mod_lower = image_loaded.replace('\\', "/").to_ascii_lowercase();
                let is_developer_workspace_lib = (mod_lower.contains("/target/debug/")
                    || mod_lower.contains("/target/release/")
                    || mod_lower.contains("/site-packages/")
                    || mod_lower.contains("/node_modules/"))
                    && !mod_lower.contains("untrusted")
                    && !mod_lower.contains("evil");
                let is_untrusted_mod = (!is_signed && !is_developer_workspace_lib)
                    || mod_lower.contains("/temp/")
                    || mod_lower.contains("/tmp/")
                    || mod_lower.contains("/downloads/")
                    || mod_lower.contains("untrusted")
                    || mod_lower.contains("evil")
                    || mod_lower.contains(" unsigned");
                if is_untrusted_mod {
                    self.causal_graph
                        .revoke_node_capabilities(&proc_key, &session_id);
                    self.capability_cache.advance_taint_and_revocation();
                }
                let enforce_stage = if event
                    .data
                    .get("PreEffectCodePolicyEnforced")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
                {
                    EnforcementStage::PreExecutionPrevented
                } else {
                    EnforcementStage::PostNotificationContained
                };
                (
                    CedarAction::DynamicCodeExec,
                    CedarResource {
                        resource_id: if image_loaded.is_empty() {
                            image.clone()
                        } else {
                            image_loaded
                        },
                        resource_type: "DynamicModule".to_string(),
                        classification: DataClassification::InternalWorkspace,
                        is_signed_and_allowlisted: !is_untrusted_mod,
                        is_approved_child_binary: !is_untrusted_mod,
                        is_task_scoped_destination: !is_untrusted_mod,
                        is_declassified_approved_sink: false,
                        service_identity: None,
                        service_operation: Some("ImageLoad".to_string()),
                    },
                    enforce_stage,
                    0.0,
                    0,
                )
            }
            8 | 10 => {
                self.causal_graph
                    .revoke_node_capabilities(&proc_key, &session_id);
                self.capability_cache.advance_taint_and_revocation();
                (
                    CedarAction::DynamicCodeExec,
                    CedarResource {
                        resource_id: format!("mem-access:{}:{}", image, event.event_id),
                        resource_type: "ProcessMemory".to_string(),
                        classification: DataClassification::CrownJewelSecret,
                        is_signed_and_allowlisted: false,
                        is_approved_child_binary: false,
                        is_task_scoped_destination: false,
                        is_declassified_approved_sink: false,
                        service_identity: None,
                        service_operation: Some("ProcessMemoryInjection".to_string()),
                    },
                    EnforcementStage::PreExecutionPrevented,
                    0.0,
                    0,
                )
            }
            17 | 18 => {
                let target_pipe = if pipe_name.is_empty() {
                    r"\\.\pipe\unknown".to_string()
                } else {
                    pipe_name
                };
                let cls = LoopbackIpcAuthorizer::classify_target(&target_pipe, "CONNECT");
                (
                    cls.mapped_cedar_action,
                    CedarResource {
                        resource_id: target_pipe,
                        resource_type: "NamedPipe".to_string(),
                        classification: DataClassification::CrownJewelSecret,
                        is_signed_and_allowlisted: false,
                        is_approved_child_binary: false,
                        is_task_scoped_destination: !cls.requires_privileged_capability,
                        is_declassified_approved_sink: false,
                        service_identity: Some(format!("{:?}", cls.service_identity)),
                        service_operation: Some(format!("{:?}", cls.service_operation)),
                    },
                    EnforcementStage::PreExecutionPrevented,
                    0.0,
                    0,
                )
            }
            3 | 5156 => {
                let target_endpoint = if !dest_host.is_empty() {
                    LoopbackIpcAuthorizer::build_network_target(&dest_host, dest_port)
                } else if !dest_ip.is_empty() {
                    LoopbackIpcAuthorizer::build_network_target(&dest_ip, dest_port.max(80))
                } else {
                    cmdline.clone()
                };
                let cls = LoopbackIpcAuthorizer::classify_target(&target_endpoint, &http_method);
                let is_canonical_approved_remote = target_endpoint
                    .to_ascii_lowercase()
                    .contains("github.com/oyesanyf/oshoosiclaw")
                    || (cls.is_local_or_ipc && !cls.requires_privileged_capability);
                let sim = self.max_crown_jewel_semantic_similarity(&cmdline);
                let jitter = self.compute_covert_jitter_ms(
                    &session_id,
                    &target_endpoint,
                    node_state.cumulative_turns,
                );
                (
                    cls.mapped_cedar_action,
                    CedarResource {
                        resource_id: target_endpoint,
                        resource_type: "NetworkEndpoint".to_string(),
                        classification: node_state.highest_classification,
                        is_signed_and_allowlisted: is_signed,
                        is_approved_child_binary: true,
                        is_task_scoped_destination: is_canonical_approved_remote
                            || event
                                .data
                                .get("TaskScopedDestination")
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false),
                        is_declassified_approved_sink: false,
                        service_identity: Some(format!("{:?}", cls.service_identity)),
                        service_operation: Some(format!("{:?}", cls.service_operation)),
                    },
                    EnforcementStage::PreExecutionPrevented,
                    sim,
                    jitter,
                )
            }
            11 | 4663 => {
                let path = if target_file.is_empty() {
                    cmdline.clone()
                } else {
                    target_file
                };
                let classification = self.classify_file_path(&path);
                let is_scoped = event
                    .data
                    .get("TaskScopedDestination")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(classification != DataClassification::CrownJewelSecret);
                if is_scoped && classification == DataClassification::CrownJewelSecret {
                    self.capability_cache.advance_taint_and_revocation();
                    self.causal_graph.record_causal_step(
                        &proc_key,
                        &session_id,
                        0.95,
                        classification,
                        0.0,
                    );
                }
                (
                    CedarAction::SensitiveFileAccess,
                    CedarResource {
                        resource_id: path,
                        resource_type: "File".to_string(),
                        classification,
                        is_signed_and_allowlisted: is_signed,
                        is_approved_child_binary: false,
                        is_task_scoped_destination: is_scoped,
                        is_declassified_approved_sink: false,
                        service_identity: None,
                        service_operation: Some("FileAccess".to_string()),
                    },
                    EnforcementStage::PreExecutionPrevented,
                    0.0,
                    0,
                )
            }
            _ => {
                let combined_lower = format!("{} {}", image, cmdline).to_ascii_lowercase();
                let suspicious_child = combined_lower.contains(" -enc ")
                    || combined_lower.contains("-encodedcommand")
                    || combined_lower.contains("downloadstring")
                    || combined_lower.contains("invoke-expression")
                    || combined_lower.contains("curl ")
                    || combined_lower.contains("wget ")
                    || combined_lower.contains("nc -e")
                    || combined_lower.contains("/dev/tcp/")
                    || combined_lower.contains("webhook.site")
                    || combined_lower.contains("requestbin")
                    || combined_lower.contains("mimikatz")
                    || combined_lower.contains("procdump")
                    || combined_lower.contains("lsass")
                    || combined_lower.contains("keymgr.dll")
                    || combined_lower.contains("comsvcs.dll")
                    || !is_signed;

                (
                    CedarAction::ChildProcessExec,
                    CedarResource {
                        resource_id: if image.is_empty() {
                            cmdline.clone()
                        } else {
                            image
                        },
                        resource_type: "ChildProcess".to_string(),
                        classification: node_state.highest_classification,
                        is_signed_and_allowlisted: !suspicious_child && is_signed,
                        is_approved_child_binary: !suspicious_child,
                        is_task_scoped_destination: !suspicious_child,
                        is_declassified_approved_sink: false,
                        service_identity: None,
                        service_operation: Some("ProcessCreate".to_string()),
                    },
                    EnforcementStage::PreExecutionPrevented,
                    0.0,
                    0,
                )
            }
        };

        let latest_state = self
            .causal_graph
            .resolve_state(Some(&proc_key), Some(pid), &session_id);

        let principal = CedarPrincipal {
            principal_id: format!("agent-proc-{}", proc_key),
            session_id: session_id.clone(),
            process_instance_key: proc_key,
            authority_level: latest_state.authority_level,
            approved_capabilities: Vec::new(),
            authenticated_role: None,
        };

        let context = CedarContext {
            policy_version: self.policy_store.active_version_label(),
            causal_event_id: latest_state.last_causal_event_id,
            has_crown_jewel_taint: latest_state.has_crown_jewel_taint,
            highest_data_classification: latest_state.highest_classification,
            taint_level: latest_state.taint_level,
            cumulative_salami_turns: latest_state.cumulative_turns,
            has_approved_capability: event
                .data
                .get("HasApprovedCapability")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            has_cryptographic_declassification: false,
            upward_authority_promotion_attempted: false,
            egress_budget_exceeded: false,
            semantic_cosine_similarity: sem_sim,
            covert_jitter_applied_ms: jitter_ms,
            taint_epoch: self.capability_cache.current_taint_epoch(),
            revocation_seq: self.capability_cache.current_revocation_seq(),
            has_untrusted_web_input: event
                .data
                .get("HasUntrustedWebInput")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            has_scratch_file_write: event
                .data
                .get("HasScratchFileWrite")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            subprocess_env_or_arg_tainted: event
                .data
                .get("SubprocessEnvOrArgTainted")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            temporal_trace_window_seconds: event
                .data
                .get("TemporalTraceWindowSeconds")
                .and_then(|v| v.as_u64())
                .unwrap_or(7200),
        };

        self.evaluate_cedar_request(&principal, action, &resource, context, stage)
    }

    pub fn get_status_snapshot(&self) -> serde_json::Value {
        let (merkle_root, _) = self.workspace_allowlist.compute_merkle_root();
        serde_json::json!({
            "policy_version": self.policy_store.active_version_label(),
            "policy_version_num": self.policy_store.active_version_num(),
            "workspace_merkle_root_blake3": merkle_root,
            "taint_epoch": self.capability_cache.current_taint_epoch(),
            "revocation_seq": self.capability_cache.current_revocation_seq(),
            "in_flight_sensitive_reads": self.capability_cache.in_flight_sensitive_reads(),
            "registered_crown_jewel_assets": self.crown_jewels.len(),
            "status": "unified capability enforcement under implementation and verification",
        })
    }
}

static GLOBAL_RING7_AUTHORIZER: OnceLock<Arc<Ring7CapabilityEffectAuthorizer>> = OnceLock::new();

pub fn global_ring7_authorizer() -> Arc<Ring7CapabilityEffectAuthorizer> {
    GLOBAL_RING7_AUTHORIZER
        .get_or_init(|| Arc::new(Ring7CapabilityEffectAuthorizer::new()))
        .clone()
}

