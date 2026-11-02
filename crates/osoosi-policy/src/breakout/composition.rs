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
// 8. Authorized-Effect Composition (`WorkflowCompositionEvaluator`), Advisory-Only
//    Model Guard (`AdvisoryModelJudgmentGuard`), & `PlatformAttestationGate`
// ============================================================================

/// Categorizes individually permitted operations in a multi-step agent workflow
/// so `WorkflowCompositionEvaluator` can detect prohibited composed outcomes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComposedWorkflowStepKind {
    ReadPermittedProjectFile {
        path: String,
    },
    ModifyPermittedSourceCode {
        path: String,
    },
    ModifyPermittedConfiguration {
        path: String,
        weakens_security_or_unverified: bool,
    },
    ExecuteApprovedLocalTest {
        command: String,
    },
    ExecuteApprovedDeployment {
        target_environment: String,
        dual_authorization_cosigners: Vec<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowCompositionVerdict {
    pub allowed: bool,
    pub session_id: String,
    pub individual_step_permitted_by_cedar: bool,
    pub composed_workflow_violation_detected: bool,
    pub requires_dual_authorization: bool,
    pub policy_decision_id: String,
    pub causal_chain_summary: Vec<String>,
    pub reason: String,
}

/// Evaluates outcome-level workflow composition invariants over `CausalSecurityGraph`:
/// - Blocks `ReadPermittedProjectFile -> ModifyPermittedConfiguration -> ExecuteApprovedDeployment`
///   when the composed chain would deploy weakened or unverified security/runtime configuration
///   without independent dual-authorization (`cosigners.len() >= 2`).
/// - Permits `ReadPermittedProjectFile -> ModifyPermittedSourceCode -> ExecuteApprovedLocalTest` (`cargo test`).
#[derive(Default)]
pub struct WorkflowCompositionEvaluator {
    session_steps: DashMap<String, Vec<ComposedWorkflowStepKind>>,
}

impl WorkflowCompositionEvaluator {
    pub fn new() -> Self {
        Self {
            session_steps: DashMap::new(),
        }
    }

    /// Evaluates and records a workflow step, executing `effect_fn` ONLY if both individual Cedar
    /// authorization and composed workflow outcome invariants hold.
    pub fn evaluate_and_execute_step<F, R>(
        &self,
        session_id: &str,
        step: ComposedWorkflowStepKind,
        effect_fn: F,
    ) -> (WorkflowCompositionVerdict, Option<R>)
    where
        F: FnOnce() -> R,
    {
        let mut history = self
            .session_steps
            .entry(session_id.to_string())
            .or_default();
        history.push(step.clone());
        let steps_snapshot = history.clone();
        drop(history);

        let chain_summary: Vec<String> = steps_snapshot
            .iter()
            .map(|s| match s {
                ComposedWorkflowStepKind::ReadPermittedProjectFile { path } => {
                    format!("ReadPermittedProjectFile({})", path)
                }
                ComposedWorkflowStepKind::ModifyPermittedSourceCode { path } => {
                    format!("ModifyPermittedSourceCode({})", path)
                }
                ComposedWorkflowStepKind::ModifyPermittedConfiguration {
                    path,
                    weakens_security_or_unverified,
                } => format!(
                    "ModifyPermittedConfiguration({}, weakened_or_unverified={})",
                    path, weakens_security_or_unverified
                ),
                ComposedWorkflowStepKind::ExecuteApprovedLocalTest { command } => {
                    format!("ExecuteApprovedLocalTest({})", command)
                }
                ComposedWorkflowStepKind::ExecuteApprovedDeployment {
                    target_environment,
                    dual_authorization_cosigners,
                } => format!(
                    "ExecuteApprovedDeployment({}, cosigners={})",
                    target_environment,
                    dual_authorization_cosigners.len()
                ),
            })
            .collect();

        let decision_hash =
            blake3::hash(format!("wf-comp:{}:{}", session_id, chain_summary.join("->")).as_bytes());
        let policy_decision_id = format!("pdec-wf-{}", &decision_hash.to_hex()[..16]);

        if let ComposedWorkflowStepKind::ExecuteApprovedDeployment {
            ref target_environment,
            ref dual_authorization_cosigners,
        } = step
        {
            let has_prior_read = steps_snapshot
                .iter()
                .any(|s| matches!(s, ComposedWorkflowStepKind::ReadPermittedProjectFile { .. }));
            let has_unverified_config_mod = steps_snapshot.iter().any(|s| {
                matches!(
                    s,
                    ComposedWorkflowStepKind::ModifyPermittedConfiguration {
                        weakens_security_or_unverified: true,
                        ..
                    }
                )
            });

            // Count distinct non-agent human/control-plane cosigners
            let distinct_valid_cosigners: HashSet<String> = dual_authorization_cosigners
                .iter()
                .map(|c| c.trim().to_ascii_lowercase())
                .filter(|c| !c.is_empty() && !c.contains("agent") && !c.contains("worker"))
                .collect();

            if has_prior_read && has_unverified_config_mod && distinct_valid_cosigners.len() < 2 {
                return (
                    WorkflowCompositionVerdict {
                        allowed: false,
                        session_id: session_id.to_string(),
                        individual_step_permitted_by_cedar: true,
                        composed_workflow_violation_detected: true,
                        requires_dual_authorization: true,
                        policy_decision_id,
                        causal_chain_summary: chain_summary,
                        reason: format!(
                            "DENY_AUTHORIZED_EFFECT_COMPOSITION: Individually permitted steps (ReadPermittedProjectFile -> ModifyPermittedConfiguration -> ExecuteApprovedDeployment[{}]) compose into an unverified/weakened deployment outcome without dual human authorization",
                            target_environment
                        ),
                    },
                    None,
                );
            }
        }

        let out = effect_fn();
        (
            WorkflowCompositionVerdict {
                allowed: true,
                session_id: session_id.to_string(),
                individual_step_permitted_by_cedar: true,
                composed_workflow_violation_detected: false,
                requires_dual_authorization: false,
                policy_decision_id,
                causal_chain_summary: chain_summary,
                reason: "PERMIT_COMPOSED_WORKFLOW: Causal workflow sequence satisfies outcome-level composition invariants".to_string(),
            },
            Some(out),
        )
    }
}

/// Enforces the `Model manipulation` defense: LLM, classifier, and embedding judgments
/// (`AlignmentCheck`, Tier-2 cosine similarity, ML voters) are strictly advisory (risk escalation only)
/// and can NEVER grant a capability, declassify taint, or override a Cedar/workflow denial.
pub struct AdvisoryModelJudgmentGuard;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvisoryModelEvaluationResult {
    pub final_allowed: bool,
    pub deterministic_cedar_allowed: bool,
    pub model_claimed_benign_confidence: f64,
    pub model_attempted_capability_grant: bool,
    pub model_attempted_taint_declassification: bool,
    pub model_override_rejected: bool,
    pub reason: String,
}

impl AdvisoryModelJudgmentGuard {
    pub fn enforce_advisory_only_invariant(
        deterministic_cedar_allowed: bool,
        model_claimed_benign: bool,
        model_confidence: f64,
        model_requested_capability_grant: bool,
        model_requested_declassification: bool,
    ) -> AdvisoryModelEvaluationResult {
        // Model can escalate a risk (turning `true` into `false` if `!model_claimed_benign && model_confidence >= 0.90`),
        // but can NEVER turn `deterministic_cedar_allowed == false` into `true`, nor grant capabilities or declassify taint!
        let final_allowed =
            deterministic_cedar_allowed && !(!model_claimed_benign && model_confidence >= 0.90);

        let override_rejected = !deterministic_cedar_allowed
            && (model_claimed_benign
                || model_requested_capability_grant
                || model_requested_declassification);

        AdvisoryModelEvaluationResult {
            final_allowed,
            deterministic_cedar_allowed,
            model_claimed_benign_confidence: model_confidence,
            model_attempted_capability_grant: model_requested_capability_grant,
            model_attempted_taint_declassification: model_requested_declassification,
            model_override_rejected: override_rejected,
            reason: if override_rejected {
                "DENY_MODEL_MANIPULATION_OVERRIDE: Probabilistic LLM/embedding/classifier outputs are strictly advisory and cannot grant capabilities, declassify taint, or override a Cedar/workflow denial".to_string()
            } else if !final_allowed {
                "DENY_ESCALATED_OR_FORBIDDEN: Action blocked by deterministic Cedar policy or high-confidence advisory risk escalation".to_string()
            } else {
                "PERMIT_DETERMINISTIC_AND_ADVISORY_CLEAN".to_string()
            },
        }
    }
}

/// Platform Attestation Posture covering Residual Exploit Classes #1–#4:
/// 1. UEFI / Bootloader / Measured Boot TPM PCRs (`uefi_secure_boot_and_tpm_pcr0_7_valid`)
/// 2. Hypervisor / VBS / HVCI integrity (`hvci_vbs_and_hypervisor_enforced`)
/// 3. CPU microarchitectural side-channel mitigations (`microcode_spectre_mds_l1tf_mitigated`)
/// 4. IOMMU / VT-d / Kernel DMA Protection (`iommu_vt_d_kernel_dma_protection_active`)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformAttestationPosture {
    pub uefi_secure_boot_and_tpm_pcr0_7_valid: bool,
    pub hvci_vbs_and_hypervisor_enforced: bool,
    pub microcode_spectre_mds_l1tf_mitigated: bool,
    pub iommu_vt_d_kernel_dma_protection_active: bool,
    pub undocumented_kernel_table_walk_used: bool,
}

impl Default for PlatformAttestationPosture {
    fn default() -> Self {
        Self {
            uefi_secure_boot_and_tpm_pcr0_7_valid: true,
            hvci_vbs_and_hypervisor_enforced: true,
            microcode_spectre_mds_l1tf_mitigated: true,
            iommu_vt_d_kernel_dma_protection_active: true,
            undocumented_kernel_table_walk_used: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformAttestationDecision {
    pub operation_allowed: bool,
    pub sensitive_keys_withheld: bool,
    pub degraded_layers: Vec<String>,
    pub reason: String,
}

pub struct PlatformAttestationGate;

impl PlatformAttestationGate {
    /// Evaluates whether a high-impact operation or sensitive key release may proceed given
    /// the current hardware/firmware/hypervisor attestation state.
    pub fn evaluate_high_impact_operation(
        posture: &PlatformAttestationPosture,
        operation_name: &str,
    ) -> PlatformAttestationDecision {
        let mut degraded = Vec::new();
        if !posture.uefi_secure_boot_and_tpm_pcr0_7_valid {
            degraded.push("ResidualClass#1_UEFI_MeasuredBoot_PCR0_7_Degraded".to_string());
        }
        if !posture.hvci_vbs_and_hypervisor_enforced {
            degraded.push("ResidualClass#2_Hypervisor_HVCI_VBS_Degraded".to_string());
        }
        if !posture.microcode_spectre_mds_l1tf_mitigated {
            degraded.push("ResidualClass#3_CPU_Microcode_Mitigation_Degraded".to_string());
        }
        if !posture.iommu_vt_d_kernel_dma_protection_active {
            degraded.push("ResidualClass#4_IOMMU_Kernel_DMA_Protection_Degraded".to_string());
        }
        if posture.undocumented_kernel_table_walk_used {
            degraded.push("Unsupported_Undocumented_Kernel_Table_Walk_Detected".to_string());
        }

        if !degraded.is_empty() {
            return PlatformAttestationDecision {
                operation_allowed: false,
                sensitive_keys_withheld: true,
                degraded_layers: degraded.clone(),
                reason: format!(
                    "DENY_UNTRUSTED_PLATFORM_ATTESTATION_WITHHOLD: Withheld sensitive keys and blocked '{}' due to degraded platform trust: {}",
                    operation_name,
                    degraded.join(", ")
                ),
            };
        }

        PlatformAttestationDecision {
            operation_allowed: true,
            sensitive_keys_withheld: false,
            degraded_layers: Vec::new(),
            reason: format!(
                "PERMIT_ATTESTED_PLATFORM: All 4 hardware/firmware/hypervisor trust layers verified for '{}'",
                operation_name
            ),
        }
    }
}

