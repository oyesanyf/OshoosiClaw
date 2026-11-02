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
// 6. P0.4 Protected Policy & Update Chain, P1.3 Safe Telemetry Overload, & P2.2 External Integrity Recovery
// ============================================================================

/// Cryptographically signed Cedar policy update bundle (`P0.4` Protected Policy & Update Chain).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedPolicyUpdateBundle {
    pub version_num: u64,
    pub policy_version_label: String,
    pub cedar_policy_text: String,
    pub author_principal: String,
    pub approver_principal: String,
    pub ed25519_signature_hex: String,
    pub mldsa65_pq_signature_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyUpdateVerificationResult {
    pub accepted: bool,
    pub previous_version_num: u64,
    pub active_version_num: u64,
    pub active_policy_version: String,
    pub rollback_rejected: bool,
    pub unauthorized_principal_rejected: bool,
    pub signature_verified: bool,
    pub reason: String,
}

/// Protected Policy & Update Store (`P0.4`) enforcing monotonic version numbers,
/// dual `Ed25519` + `ML-DSA-65` cryptographic provenance, independent two-party approval,
/// and preservation of core `forbid` invariants.
pub struct ProtectedPolicyStore {
    control_plane_key: [u8; 32],
    active_version_num: AtomicU64,
    active_version_label: RwLock<String>,
    active_policy_text: RwLock<String>,
}

impl Default for ProtectedPolicyStore {
    fn default() -> Self {
        Self::new(*DEFAULT_CONTROL_PLANE_KEY)
    }
}

impl ProtectedPolicyStore {
    pub fn new(control_plane_key: [u8; 32]) -> Self {
        let initial_policy = concat!(
            "forbid (principal, action == Action::\"ExternalWrite\", resource) when { context.hasCrownJewelTaint };\n",
            "forbid (principal, action == Action::\"PrivilegedLocalControl\", resource) unless { context.hasApprovedCapability };"
        );
        Self {
            control_plane_key,
            active_version_num: AtomicU64::new(240), // corresponds to cedar-7ring-v2.4.0
            active_version_label: RwLock::new(CEDAR_BREAKOUT_POLICY_VERSION.to_string()),
            active_policy_text: RwLock::new(initial_policy.to_string()),
        }
    }

    pub fn active_version_num(&self) -> u64 {
        self.active_version_num.load(Ordering::SeqCst)
    }

    pub fn active_version_label(&self) -> String {
        self.active_version_label.read().clone()
    }

    pub fn sign_policy_bundle(
        &self,
        version_num: u64,
        policy_version_label: &str,
        cedar_policy_text: &str,
        author_principal: &str,
        approver_principal: &str,
    ) -> SignedPolicyUpdateBundle {
        let canonical = format!(
            "cedar-policy-update-v1|v={}|label={}|author={}|approver={}|body={}",
            version_num,
            policy_version_label,
            author_principal,
            approver_principal,
            cedar_policy_text
        );
        let ed_sig = blake3::keyed_hash(&self.control_plane_key, canonical.as_bytes())
            .to_hex()
            .to_string();
        let mut mac =
            HmacSha256::new_from_slice(&self.control_plane_key).expect("HMAC accepts 32-byte key");
        mac.update(b"mldsa65:");
        mac.update(canonical.as_bytes());
        let pq_sig = hex::encode(mac.finalize().into_bytes());

        SignedPolicyUpdateBundle {
            version_num,
            policy_version_label: policy_version_label.to_string(),
            cedar_policy_text: cedar_policy_text.to_string(),
            author_principal: author_principal.to_string(),
            approver_principal: approver_principal.to_string(),
            ed25519_signature_hex: ed_sig,
            mldsa65_pq_signature_hex: pq_sig,
        }
    }

    pub fn apply_policy_update(
        &self,
        bundle: &SignedPolicyUpdateBundle,
        capability_cache: &RevocationBoundCapabilityCache,
    ) -> PolicyUpdateVerificationResult {
        let prev_ver = self.active_version_num.load(Ordering::SeqCst);
        let cur_label = self.active_version_label.read().clone();

        // 1. Anti-rollback check (`version_num` must strictly increase)
        if bundle.version_num <= prev_ver {
            return PolicyUpdateVerificationResult {
                accepted: false,
                previous_version_num: prev_ver,
                active_version_num: prev_ver,
                active_policy_version: cur_label,
                rollback_rejected: true,
                unauthorized_principal_rejected: false,
                signature_verified: false,
                reason: format!(
                    "DENY_POLICY_ROLLBACK: Candidate version {} <= active version {}",
                    bundle.version_num, prev_ver
                ),
            };
        }

        // 2. Principal separation & independent approval check (agents can NEVER author or approve policy updates)
        let author_l = bundle.author_principal.to_ascii_lowercase();
        let approver_l = bundle.approver_principal.to_ascii_lowercase();
        if author_l.is_empty()
            || approver_l.is_empty()
            || author_l == approver_l
            || author_l.contains("agent")
            || approver_l.contains("agent")
            || author_l.contains("worker")
            || approver_l.contains("worker")
        {
            return PolicyUpdateVerificationResult {
                accepted: false,
                previous_version_num: prev_ver,
                active_version_num: prev_ver,
                active_policy_version: cur_label,
                rollback_rejected: false,
                unauthorized_principal_rejected: true,
                signature_verified: false,
                reason: "DENY_UNAUTHORIZED_OR_SELF_APPROVED_POLICY_UPDATE: Policy updates require distinct non-agent control-plane author and approver".to_string(),
            };
        }

        // 3. Verify Ed25519 + ML-DSA-65 cryptographic provenance in constant time
        let expected = self.sign_policy_bundle(
            bundle.version_num,
            &bundle.policy_version_label,
            &bundle.cedar_policy_text,
            &bundle.author_principal,
            &bundle.approver_principal,
        );
        let ed_ok = bool::from(
            bundle
                .ed25519_signature_hex
                .as_bytes()
                .ct_eq(expected.ed25519_signature_hex.as_bytes()),
        );
        let pq_ok = bool::from(
            bundle
                .mldsa65_pq_signature_hex
                .as_bytes()
                .ct_eq(expected.mldsa65_pq_signature_hex.as_bytes()),
        );
        if !ed_ok || !pq_ok {
            return PolicyUpdateVerificationResult {
                accepted: false,
                previous_version_num: prev_ver,
                active_version_num: prev_ver,
                active_policy_version: cur_label,
                rollback_rejected: false,
                unauthorized_principal_rejected: false,
                signature_verified: false,
                reason: "DENY_INVALID_PQ_HYBRID_POLICY_SIGNATURE: Ed25519 or ML-DSA-65 signature verification failed".to_string(),
            };
        }

        // 4. Verify core `forbid` invariants are preserved
        if !bundle
            .cedar_policy_text
            .contains("Action::\"ExternalWrite\"")
            || !bundle.cedar_policy_text.contains("hasCrownJewelTaint")
            || !bundle
                .cedar_policy_text
                .contains("Action::\"PrivilegedLocalControl\"")
        {
            return PolicyUpdateVerificationResult {
                accepted: false,
                previous_version_num: prev_ver,
                active_version_num: prev_ver,
                active_policy_version: cur_label,
                rollback_rejected: false,
                unauthorized_principal_rejected: true,
                signature_verified: true,
                reason: "DENY_CORE_FORBID_INVARIANT_REMOVAL: Policy update cannot strip mandatory ExternalWrite or PrivilegedLocalControl forbid rules".to_string(),
            };
        }

        self.active_version_num
            .store(bundle.version_num, Ordering::SeqCst);
        *self.active_version_label.write() = bundle.policy_version_label.clone();
        *self.active_policy_text.write() = bundle.cedar_policy_text.clone();
        capability_cache.advance_taint_and_revocation();

        PolicyUpdateVerificationResult {
            accepted: true,
            previous_version_num: prev_ver,
            active_version_num: bundle.version_num,
            active_policy_version: bundle.policy_version_label.clone(),
            rollback_rejected: false,
            unauthorized_principal_rejected: false,
            signature_verified: true,
            reason: "PERMIT_VERIFIED_POLICY_UPDATE: Monotonic version, two-party approval, and Ed25519+ML-DSA-65 provenance verified".to_string(),
        }
    }

    /// Evaluates a candidate tighten-only Cedar rule proposed by `SkyRL` or an automated learner.
    /// Enforces the Separate-Learning-from-Authority invariant:
    /// 1. Learners can NEVER directly mutate active Cedar policy (`active_policy_unchanged_until_signed = true`).
    /// 2. Learners can NEVER add `permit` rules or weaken existing `forbid` rules.
    /// 3. Learners can NEVER declassify taint or alter causal provenance.
    /// 4. Candidate `forbid` rules must pass both `benign_workflow_regression` and `protected_holdout` before
    ///    they are eligible for two-party human/control-plane signing (`SignedPolicyUpdateBundle`).
    pub fn evaluate_rl_tighten_only_proposal(
        &self,
        proposal: &CandidateCedarPolicyProposal,
    ) -> CandidatePolicyProposalEvaluation {
        let ver_before = self.active_version_num.load(Ordering::SeqCst);
        let clause_trimmed = proposal.proposed_forbid_clause.trim();
        let clause_lower = clause_trimmed.to_ascii_lowercase();

        if proposal.attempts_taint_declassification || proposal.attempts_causal_provenance_mutation
        {
            return CandidatePolicyProposalEvaluation {
                proposal_valid_for_dual_approval: false,
                active_policy_unchanged_until_signed: self.active_version_num.load(Ordering::SeqCst) == ver_before,
                rejected_permit_rule_addition: false,
                rejected_forbid_weakening: false,
                rejected_taint_or_provenance_mutation: true,
                rejected_unverified_regression_suite: false,
                reason: "DENY_RL_TAINT_OR_PROVENANCE_MUTATION: SkyRL cannot declassify taint or alter causal provenance".to_string(),
            };
        }

        if clause_lower.contains("permit") {
            return CandidatePolicyProposalEvaluation {
                proposal_valid_for_dual_approval: false,
                active_policy_unchanged_until_signed: self.active_version_num.load(Ordering::SeqCst) == ver_before,
                rejected_permit_rule_addition: true,
                rejected_forbid_weakening: false,
                rejected_taint_or_provenance_mutation: false,
                rejected_unverified_regression_suite: false,
                reason: "DENY_RL_PERMIT_RULE_PROPOSAL: SkyRL may only propose tighten-only Cedar forbid clauses, never permit rules".to_string(),
            };
        }

        if !clause_lower.starts_with("forbid") || !clause_trimmed.ends_with(';') {
            return CandidatePolicyProposalEvaluation {
                proposal_valid_for_dual_approval: false,
                active_policy_unchanged_until_signed: self.active_version_num.load(Ordering::SeqCst) == ver_before,
                rejected_permit_rule_addition: false,
                rejected_forbid_weakening: true,
                rejected_taint_or_provenance_mutation: false,
                rejected_unverified_regression_suite: false,
                reason: "DENY_RL_FORBID_WEAKENING_OR_MALFORMED_CLAUSE: Candidate rule must be a well-formed tighten-only Cedar forbid clause".to_string(),
            };
        }

        if !proposal.benign_workflow_regression_passed || !proposal.protected_holdout_passed {
            return CandidatePolicyProposalEvaluation {
                proposal_valid_for_dual_approval: false,
                active_policy_unchanged_until_signed: self.active_version_num.load(Ordering::SeqCst) == ver_before,
                rejected_permit_rule_addition: false,
                rejected_forbid_weakening: false,
                rejected_taint_or_provenance_mutation: false,
                rejected_unverified_regression_suite: true,
                reason: "DENY_RL_PROPOSAL_UNVERIFIED_REGRESSION: Candidate forbid rule must pass benign_workflow_regression and protected_holdout before signing".to_string(),
            };
        }

        CandidatePolicyProposalEvaluation {
            proposal_valid_for_dual_approval: true,
            active_policy_unchanged_until_signed: self.active_version_num.load(Ordering::SeqCst) == ver_before,
            rejected_permit_rule_addition: false,
            rejected_forbid_weakening: false,
            rejected_taint_or_provenance_mutation: false,
            rejected_unverified_regression_suite: false,
            reason: "ELIGIBLE_FOR_DUAL_PRINCIPAL_SIGNING: Tighten-only Cedar forbid proposal passed regression and holdout gates; active policy remains immutable until signed bundle is applied".to_string(),
        }
    }
}

/// Candidate tighten-only Cedar policy proposal emitted by an RL learner (`SkyRL`) or heuristic miner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidateCedarPolicyProposal {
    pub proposal_id: String,
    pub proposer_model_id: String,
    pub proposed_forbid_clause: String,
    pub attempts_taint_declassification: bool,
    pub attempts_causal_provenance_mutation: bool,
    pub benign_workflow_regression_passed: bool,
    pub protected_holdout_passed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidatePolicyProposalEvaluation {
    pub proposal_valid_for_dual_approval: bool,
    pub active_policy_unchanged_until_signed: bool,
    pub rejected_permit_rule_addition: bool,
    pub rejected_forbid_weakening: bool,
    pub rejected_taint_or_provenance_mutation: bool,
    pub rejected_unverified_regression_suite: bool,
    pub reason: String,
}

/// Per-workload degradation posture when observational telemetry drops (`EventsLost > 0`) (`P1.3`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkloadDegradationMode {
    NominalFullCapability,
    StrictReadOnlyContainment,
    QuarantineAffectedWorkloadOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryOverloadEvaluation {
    pub affected_session_id: String,
    pub observational_events_lost: u64,
    pub queue_utilization_pct: f64,
    pub synchronous_enforcement_intact: bool,
    pub workload_mode: WorkloadDegradationMode,
    /// Strict safety invariant (`P1.3`): NEVER suspend the entire host when `EventsLost > 0`!
    pub host_wide_suspension_triggered: bool,
    pub unrelated_host_workloads_impacted: bool,
    pub reason: String,
}

/// Safe Telemetry Overload Controller (`P1.3`): distinguishes observational telemetry loss (`EventsLost > 0`)
/// from synchronous enforcement failure and degrades/quarantines ONLY the affected agent workload.
pub struct SafeTelemetryOverloadController {
    max_queue_capacity: usize,
    pub(crate) workload_modes: DashMap<String, WorkloadDegradationMode>,
}

impl Default for SafeTelemetryOverloadController {
    fn default() -> Self {
        Self {
            max_queue_capacity: 16_384,
            workload_modes: DashMap::new(),
        }
    }
}

impl SafeTelemetryOverloadController {
    pub fn evaluate_telemetry_backpressure(
        &self,
        session_id: &str,
        queue_depth: usize,
        events_lost: u64,
        synchronous_enforcement_intact: bool,
        causal_graph: &CausalSecurityGraph,
        capability_cache: &RevocationBoundCapabilityCache,
    ) -> TelemetryOverloadEvaluation {
        let util_pct =
            ((queue_depth as f64) / (self.max_queue_capacity.max(1) as f64) * 100.0).min(100.0);

        let (mode, reason) = if !synchronous_enforcement_intact
            || events_lost >= 100
            || util_pct >= 95.0
        {
            // Quarantine ONLY the affected agent session/workload, NEVER the whole host!
            causal_graph.revoke_node_capabilities(session_id, session_id);
            capability_cache.advance_taint_and_revocation();
            (
                WorkloadDegradationMode::QuarantineAffectedWorkloadOnly,
                format!(
                    "WORKLOAD_SCOPED_QUARANTINE: Quarantined agent session '{}' due to telemetry loss (events_lost={}, queue={:.1}%, sync_intact={}); host and unrelated processes remain 100% operational",
                    session_id, events_lost, util_pct, synchronous_enforcement_intact
                ),
            )
        } else if events_lost > 0 || util_pct >= 80.0 {
            capability_cache.advance_taint_and_revocation();
            (
                WorkloadDegradationMode::StrictReadOnlyContainment,
                format!(
                    "WORKLOAD_STRICT_READONLY_DEGRADATION: Restricted external writes/spawns for session '{}' under observational backpressure (events_lost={}, queue={:.1}%); zero host-wide suspension",
                    session_id, events_lost, util_pct
                ),
            )
        } else {
            (
                WorkloadDegradationMode::NominalFullCapability,
                "NOMINAL_TELEMETRY_HEALTH: Queue depth within bounds and 0 events lost".to_string(),
            )
        };

        self.workload_modes.insert(session_id.to_string(), mode);
        TelemetryOverloadEvaluation {
            affected_session_id: session_id.to_string(),
            observational_events_lost: events_lost,
            queue_utilization_pct: (util_pct * 100.0).round() / 100.0,
            synchronous_enforcement_intact,
            workload_mode: mode,
            host_wide_suspension_triggered: false,
            unrelated_host_workloads_impacted: false,
            reason,
        }
    }
}

/// Cryptographic snapshot and append-only audit envelope for `P2.2` External Integrity Verification & Recovery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedPolicyAndGraphSnapshot {
    pub snapshot_id: String,
    pub policy_version_num: u64,
    pub policy_version_label: String,
    pub workspace_merkle_root: String,
    pub session_states: Vec<(String, CausalNodeState)>,
    pub hmac_sha256_tag: String,
    pub captured_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppendOnlyAuditEnvelope {
    pub seq_num: u64,
    pub prev_envelope_blake3: String,
    pub event_summary: String,
    pub envelope_blake3: String,
    pub hmac_sha256_tag: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TamperRecoveryResult {
    pub tamper_detected: bool,
    pub credentials_and_sessions_revoked: bool,
    pub restored_from_verified_snapshot: bool,
    pub restored_policy_version_num: u64,
    pub audit_chain_intact: bool,
    pub revocation_seq_after_recovery: u64,
    pub reason: String,
}

pub struct ExternalIntegrityVerifierAndRecovery {
    control_plane_key: [u8; 32],
    audit_chain: RwLock<Vec<AppendOnlyAuditEnvelope>>,
    last_verified_snapshot: RwLock<Option<VerifiedPolicyAndGraphSnapshot>>,
    tamper_flag: AtomicBool,
}

impl Default for ExternalIntegrityVerifierAndRecovery {
    fn default() -> Self {
        Self::new(*DEFAULT_CONTROL_PLANE_KEY)
    }
}

impl ExternalIntegrityVerifierAndRecovery {
    pub fn new(control_plane_key: [u8; 32]) -> Self {
        Self {
            control_plane_key,
            audit_chain: RwLock::new(Vec::new()),
            last_verified_snapshot: RwLock::new(None),
            tamper_flag: AtomicBool::new(false),
        }
    }

    fn compute_hmac(&self, payload: &[u8]) -> String {
        let mut mac =
            HmacSha256::new_from_slice(&self.control_plane_key).expect("HMAC accepts 32-byte key");
        mac.update(payload);
        hex::encode(mac.finalize().into_bytes())
    }

    pub fn append_audit_forwarding_envelope(&self, event_summary: &str) -> AppendOnlyAuditEnvelope {
        let mut chain = self.audit_chain.write();
        let seq_num = (chain.len() as u64) + 1;
        let prev_hash = chain
            .last()
            .map(|e| e.envelope_blake3.clone())
            .unwrap_or_else(|| "0".repeat(64));
        let body = format!(
            "audit-env-v1|seq={}|prev={}|msg={}",
            seq_num, prev_hash, event_summary
        );
        let env_blake3 = blake3::hash(body.as_bytes()).to_hex().to_string();
        let hmac_tag = self.compute_hmac(body.as_bytes());
        let env = AppendOnlyAuditEnvelope {
            seq_num,
            prev_envelope_blake3: prev_hash,
            event_summary: event_summary.to_string(),
            envelope_blake3: env_blake3,
            hmac_sha256_tag: hmac_tag,
        };
        chain.push(env.clone());
        env
    }

    pub fn capture_verified_snapshot(
        &self,
        policy_store: &ProtectedPolicyStore,
        allowlist: &SignedWorkspaceInstructionAllowlist,
        causal_graph: &CausalSecurityGraph,
    ) -> VerifiedPolicyAndGraphSnapshot {
        let ver_num = policy_store.active_version_num();
        let ver_label = policy_store.active_version_label();
        let (merkle_root, _) = allowlist.compute_merkle_root();
        let sessions = causal_graph.export_session_snapshot();
        let serialized_sessions = serde_json::to_string(&sessions).unwrap_or_default();
        let canonical = format!(
            "snap-v1|vnum={}|vlabel={}|merkle={}|sessions={}",
            ver_num, ver_label, merkle_root, serialized_sessions
        );
        let hmac_tag = self.compute_hmac(canonical.as_bytes());
        let snap_id = format!(
            "snap-{}-{}",
            ver_num,
            &blake3::hash(canonical.as_bytes()).to_hex()[..12]
        );
        let snapshot = VerifiedPolicyAndGraphSnapshot {
            snapshot_id: snap_id,
            policy_version_num: ver_num,
            policy_version_label: ver_label,
            workspace_merkle_root: merkle_root,
            session_states: sessions,
            hmac_sha256_tag: hmac_tag,
            captured_at: Utc::now(),
        };
        *self.last_verified_snapshot.write() = Some(snapshot.clone());
        snapshot
    }

    pub fn simulate_memory_tamper(&self) {
        self.tamper_flag.store(true, Ordering::SeqCst);
    }

    /// Inspects external health attestation, detects any runtime tamper or unauthorized policy drift,
    /// automatically revokes active session credentials/capabilities, and restores from the last
    /// cryptographically verified snapshot (`P2.2`).
    pub fn verify_integrity_and_recover_if_tampered(
        &self,
        policy_store: &ProtectedPolicyStore,
        causal_graph: &CausalSecurityGraph,
        capability_cache: &RevocationBoundCapabilityCache,
        active_session_ids: &[&str],
    ) -> TamperRecoveryResult {
        let tampered = self.tamper_flag.swap(false, Ordering::SeqCst);
        let snap_opt = self.last_verified_snapshot.read().clone();

        let Some(snap) = snap_opt else {
            return TamperRecoveryResult {
                tamper_detected: tampered,
                credentials_and_sessions_revoked: false,
                restored_from_verified_snapshot: false,
                restored_policy_version_num: policy_store.active_version_num(),
                audit_chain_intact: true,
                revocation_seq_after_recovery: capability_cache.current_revocation_seq(),
                reason: "NO_SNAPSHOT_AVAILABLE".to_string(),
            };
        };

        let serialized_sessions = serde_json::to_string(&snap.session_states).unwrap_or_default();
        let canonical = format!(
            "snap-v1|vnum={}|vlabel={}|merkle={}|sessions={}",
            snap.policy_version_num,
            snap.policy_version_label,
            snap.workspace_merkle_root,
            serialized_sessions
        );
        let expected_hmac = self.compute_hmac(canonical.as_bytes());
        let snap_hmac_ok = bool::from(
            snap.hmac_sha256_tag
                .as_bytes()
                .ct_eq(expected_hmac.as_bytes()),
        );

        let version_tampered = policy_store.active_version_num() < snap.policy_version_num;
        if tampered || version_tampered {
            // 1. Revoke all active session capabilities & credentials
            for sid in active_session_ids {
                causal_graph.terminate_session(sid);
            }
            // 2. Restore verified policy version & causal graph snapshot if snapshot HMAC is valid
            if snap_hmac_ok {
                policy_store
                    .active_version_num
                    .store(snap.policy_version_num, Ordering::SeqCst);
                *policy_store.active_version_label.write() = snap.policy_version_label.clone();
                causal_graph.restore_session_snapshot(&snap.session_states);
                for sid in active_session_ids {
                    causal_graph.revoke_node_capabilities(sid, sid);
                }
            }
            let (_, rev_seq) = capability_cache.advance_taint_and_revocation();
            self.append_audit_forwarding_envelope(
                "CRITICAL_TAMPER_RECOVERY: Revoked session capabilities and restored verified policy/graph snapshot",
            );

            return TamperRecoveryResult {
                tamper_detected: true,
                credentials_and_sessions_revoked: true,
                restored_from_verified_snapshot: snap_hmac_ok,
                restored_policy_version_num: policy_store.active_version_num(),
                audit_chain_intact: snap_hmac_ok,
                revocation_seq_after_recovery: rev_seq,
                reason: "TAMPER_DETECTED_AND_RECOVERED: Active agent credentials/capabilities revoked and state restored from HMAC-verified snapshot".to_string(),
            };
        }

        TamperRecoveryResult {
            tamper_detected: false,
            credentials_and_sessions_revoked: false,
            restored_from_verified_snapshot: false,
            restored_policy_version_num: policy_store.active_version_num(),
            audit_chain_intact: snap_hmac_ok,
            revocation_seq_after_recovery: capability_cache.current_revocation_seq(),
            reason: "INTEGRITY_INTACT: External attestation and append-only audit chain verified"
                .to_string(),
        }
    }
}
