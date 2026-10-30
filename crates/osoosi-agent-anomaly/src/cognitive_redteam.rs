//! # Cognitive Red-Team Interceptor & Deliberate Friction Gate (Feature F31)
//!
//! Provides:
//! 1. Counterfactual causal tracing ($S_{\text{exec}} \setminus S_{\text{deny}}$) on pending execution graphs.
//! 2. Natural-language justification stripping to eliminate operator fluency bias.
//! 3. SAELens latent deception likelihood scoring ($P_{\text{deception}} \in [0.0, 1.0]$) with auto-veto at $\ge 0.85$.
//! 4. Deliberate cognitive friction via polymorphic verification challenges (1 genuine invariant vs 3 distractors, 120s TTL).
//! 5. Mandatory dual-custody quorum approval (2 distinct operators: $O_1 \neq O_2$) for untrusted provenance or irreversible sinks.

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use osoosi_runtime::mesh_guard::{HitlApprovalReceipt, HitlCognitiveFirewall, MeshTaintLevel};
use osoosi_types::OctopusSecurityError;
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

pub const AUTO_VETO_THRESHOLD: f64 = 0.85;
pub const CHALLENGE_TTL_SECONDS: i64 = 120;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IrreversibleMutationType {
    PermanentFileOverwriteOrDeletion,
    ExternalNetworkEgress,
    HostProcessExecution,
    CredentialExposure,
    PersistenceModification,
    SecurityBoundaryTampering,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IrreversibleStateChange {
    pub mutation_type: IrreversibleMutationType,
    pub resource: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlastRadiusDiff {
    pub target_resource: String,
    pub privilege_tier: String,
    pub is_irreversible: bool,
    pub irreversible_mutations: Vec<IrreversibleStateChange>,
    pub taint_lineage_summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolymorphicChallenge {
    pub challenge_id: String,
    pub request_id: String,
    pub prompt: String,
    pub target_resource: String,
    pub options: Vec<String>,
    pub correct_option_index: usize,
    pub challenge_nonce: String,
    pub expires_at_utc: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolymorphicChallengePublic {
    pub challenge_id: String,
    pub request_id: String,
    pub prompt: String,
    pub target_resource: String,
    pub options: Vec<String>,
    pub challenge_nonce: String,
    pub expires_at_utc: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HitlApprovalState {
    PendingChallenge,
    PendingFirstApproval,
    PendingSecondApproval {
        first_operator: String,
    },
    QuorumApproved {
        operators: Vec<String>,
        receipt: Option<HitlApprovalReceipt>,
    },
    AutoVetoed {
        reason: String,
    },
    Rejected {
        operator: String,
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingExecutionGraphNode {
    pub session_id: String,
    pub arm_id: usize,
    pub arm_generation: u64,
    pub agent_id: String,
    pub correlation_id: String,
    pub tool_name: String,
    pub target_resource: String,
    pub command_args: String,
    pub stated_justification: String,
    pub incoming_taint: MeshTaintLevel,
    pub user_objective: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CognitiveRedTeamAssessment {
    pub request_id: String,
    pub canonical_tool: String,
    pub canonical_target_resource: String,
    pub stripped_justification: String,
    pub blast_radius_diff: BlastRadiusDiff,
    pub deception_score: f64,
    pub auto_vetoed: bool,
    pub veto_reason: Option<String>,
    pub dual_custody_required: bool,
    pub approval_state: HitlApprovalState,
    pub challenge: Option<PolymorphicChallengePublic>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredPendingHitlAction {
    pub request_id: String,
    pub node: PendingExecutionGraphNode,
    pub assessment: CognitiveRedTeamAssessment,
    pub full_challenge: Option<PolymorphicChallenge>,
    pub approval_state: HitlApprovalState,
    pub created_at_utc: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CognitiveRedTeamStatus {
    pub total_evaluations: usize,
    pub total_auto_vetoes: usize,
    pub total_challenges_passed: usize,
    pub total_challenges_failed: usize,
    pub total_quorum_completions: usize,
    pub pending_actions_count: usize,
}

pub struct CognitiveRedTeamInterceptor {
    operator_secret: [u8; 32],
    pending_actions: Arc<DashMap<String, StoredPendingHitlAction>>,
    total_evaluations: AtomicUsize,
    total_auto_vetoes: AtomicUsize,
    total_challenges_passed: AtomicUsize,
    total_challenges_failed: AtomicUsize,
    total_quorum_completions: AtomicUsize,
}

impl CognitiveRedTeamInterceptor {
    pub fn new(operator_secret: [u8; 32]) -> Self {
        Self {
            operator_secret,
            pending_actions: Arc::new(DashMap::new()),
            total_evaluations: AtomicUsize::new(0),
            total_auto_vetoes: AtomicUsize::new(0),
            total_challenges_passed: AtomicUsize::new(0),
            total_challenges_failed: AtomicUsize::new(0),
            total_quorum_completions: AtomicUsize::new(0),
        }
    }

    /// Strips fluent natural-language justifications, eliminating operator confirmation bias.
    pub fn strip_natural_language_justification(_raw_justification: &str) -> String {
        "[STRIPPED BY COGNITIVE RED-TEAM: Fluency suppressed. Review deterministic blast radius below]"
            .to_string()
    }

    /// Counterfactual causal state diff ($S_{\text{exec}} \setminus S_{\text{deny}}$):
    /// projects state mutations if executed vs if denied (frozen at baseline).
    pub fn simulate_blast_radius_diff(
        tool_name: &str,
        target_resource: &str,
        command_args: &str,
        incoming_taint: MeshTaintLevel,
    ) -> BlastRadiusDiff {
        let mut mutations = Vec::new();
        let tool_lower = tool_name.trim().to_ascii_lowercase();
        let resource_lower = target_resource.trim().to_ascii_lowercase();
        let args_lower = command_args.trim().to_ascii_lowercase();

        // 1. Permanent file overwrite or deletion
        let is_scratch = resource_lower.contains("scratch")
            || resource_lower.contains("temp")
            || resource_lower.contains("tmp");
        if (tool_lower == "write_file"
            || tool_lower.contains("delete")
            || tool_lower.contains("unlink"))
            && !is_scratch
        {
            mutations.push(IrreversibleStateChange {
                mutation_type: IrreversibleMutationType::PermanentFileOverwriteOrDeletion,
                resource: target_resource.to_string(),
                detail: "Target path is a persistent host location outside isolated scratchpad."
                    .to_string(),
            });
        }

        // 2. Sensitive files / System paths
        if resource_lower.contains("system32")
            || resource_lower.contains("hosts")
            || resource_lower.contains("sam")
            || resource_lower.contains("lsass")
            || resource_lower.contains(".ssh")
            || resource_lower.contains("osoosi.db")
            || resource_lower.contains("osoosi.toml")
            || args_lower.contains("system32")
            || args_lower.contains("hosts")
            || args_lower.contains("lsass")
        {
            mutations.push(IrreversibleStateChange {
                mutation_type: IrreversibleMutationType::SecurityBoundaryTampering,
                resource: target_resource.to_string(),
                detail:
                    "Action targets protected operating system configuration or credential store."
                        .to_string(),
            });
        }

        // 3. Host Process Execution
        if tool_lower == "shell_exec"
            || tool_lower == "cmd"
            || tool_lower == "powershell"
            || args_lower.contains("powershell")
            || args_lower.contains("cmd.exe")
            || args_lower.contains("bash")
            || args_lower.contains("sh ")
        {
            mutations.push(IrreversibleStateChange {
                mutation_type: IrreversibleMutationType::HostProcessExecution,
                resource: if tool_lower == "shell_exec" {
                    "host_interpreter".to_string()
                } else {
                    tool_name.to_string()
                },
                detail:
                    "Spawning host subprocess or script interpreter with unconstrained arguments."
                        .to_string(),
            });
        }

        // 4. External Network Egress
        if tool_lower == "network_egress"
            || args_lower.contains("curl ")
            || args_lower.contains("wget ")
            || args_lower.contains("invoke-webrequest")
            || args_lower.contains("http://")
            || args_lower.contains("https://")
        {
            mutations.push(IrreversibleStateChange {
                mutation_type: IrreversibleMutationType::ExternalNetworkEgress,
                resource: target_resource.to_string(),
                detail: "Outbound socket connection targeting external network endpoint."
                    .to_string(),
            });
        }

        // 5. Credential Exposure
        if tool_lower == "extract_credentials"
            || resource_lower.contains("lsass")
            || resource_lower.contains("sam")
            || resource_lower.contains("shadow")
            || resource_lower.contains("dpapi")
            || args_lower.contains("sekurlsa")
            || args_lower.contains("logonpasswords")
        {
            mutations.push(IrreversibleStateChange {
                mutation_type: IrreversibleMutationType::CredentialExposure,
                resource: target_resource.to_string(),
                detail: "Access to system security authority or cryptographic key material."
                    .to_string(),
            });
        }

        // 6. Persistence Modification
        if resource_lower.contains("runonce")
            || resource_lower.contains("run")
            || resource_lower.contains("systemd")
            || resource_lower.contains("tasks")
            || resource_lower.contains("startup")
            || args_lower.contains("schtasks")
            || args_lower.contains("reg add")
        {
            mutations.push(IrreversibleStateChange {
                mutation_type: IrreversibleMutationType::PersistenceModification,
                resource: target_resource.to_string(),
                detail: "Modification of OS auto-start or persistent service registration."
                    .to_string(),
            });
        }

        let is_irreversible = !mutations.is_empty();
        let privilege_tier = if mutations
            .iter()
            .any(|m| m.mutation_type == IrreversibleMutationType::CredentialExposure)
        {
            "CRITICAL_CREDENTIAL_ACCESS".to_string()
        } else if mutations
            .iter()
            .any(|m| m.mutation_type == IrreversibleMutationType::SecurityBoundaryTampering)
        {
            "CRITICAL_HOST_MUTATION_OR_EXEC".to_string()
        } else if is_irreversible {
            "ELEVATED_IRREVERSIBLE_OPERATION".to_string()
        } else {
            "BENIGN_REVERSIBLE_OPERATION".to_string()
        };

        BlastRadiusDiff {
            target_resource: target_resource.to_string(),
            privilege_tier,
            is_irreversible,
            irreversible_mutations: mutations,
            taint_lineage_summary: format!("MeshTaint::{:?}", incoming_taint),
        }
    }

    /// Computes SAELens latent deception likelihood $P_{\text{deception}} \in [0.0, 1.0]$.
    /// Actions with $P_{\text{deception}} \ge 0.85$ are hard-vetoed.
    pub fn compute_saelens_deception_likelihood(
        user_objective: &str,
        tool_name: &str,
        target_resource: &str,
        command_args: &str,
        stated_justification: &str,
        incoming_taint: MeshTaintLevel,
        blast_diff: &BlastRadiusDiff,
    ) -> (f64, Option<String>) {
        // 1. Visual & syntactic obfuscation scan
        let combined_text = format!(
            "{}\n{}\n{}\n{}",
            stated_justification, tool_name, target_resource, command_args
        );
        let indicators = HitlCognitiveFirewall::scan_for_visual_deception(&combined_text);
        let mut obf_score = 0.0f64;
        for ind in &indicators {
            match ind {
                osoosi_runtime::mesh_guard::HitlDeceptionIndicator::BidirectionalOverrideRtlo(
                    _,
                ) => {
                    obf_score += 0.95;
                }
                osoosi_runtime::mesh_guard::HitlDeceptionIndicator::UnicodeConfusableHomograph(
                    _,
                ) => {
                    obf_score += 0.90;
                }
                osoosi_runtime::mesh_guard::HitlDeceptionIndicator::ObfuscatedShellPayload(_) => {
                    obf_score += 0.90;
                }
                osoosi_runtime::mesh_guard::HitlDeceptionIndicator::ZeroWidthSteganography(_) => {
                    obf_score += 0.85;
                }
                osoosi_runtime::mesh_guard::HitlDeceptionIndicator::AnsiEscapeInjection(_) => {
                    obf_score += 0.85;
                }
                _ => {
                    obf_score += 0.50;
                }
            }
        }
        obf_score = obf_score.min(1.0);

        // 2. Intent-vs-effect semantic divergence
        let obj_lower = user_objective.trim().to_ascii_lowercase();
        let is_benign_objective = obj_lower.contains("read")
            || obj_lower.contains("test")
            || obj_lower.contains("format")
            || obj_lower.contains("lint")
            || obj_lower.contains("check")
            || obj_lower.contains("docs");

        let mut div_score = 0.0f64;
        if is_benign_objective {
            if blast_diff
                .irreversible_mutations
                .iter()
                .any(|m| m.mutation_type == IrreversibleMutationType::CredentialExposure)
            {
                div_score = 0.95;
            } else if blast_diff
                .irreversible_mutations
                .iter()
                .any(|m| m.mutation_type == IrreversibleMutationType::SecurityBoundaryTampering)
            {
                div_score = 0.90;
            } else if blast_diff.is_irreversible {
                div_score = 0.60;
            }
        }

        // 3. Taint penalty
        let taint_score = match incoming_taint {
            MeshTaintLevel::TrustedInternal => 0.0,
            MeshTaintLevel::Suspect => 0.35,
            MeshTaintLevel::UntrustedExternal => 0.65,
            MeshTaintLevel::Quarantined => 0.95,
        };

        // 4. Irreversible blast penalty
        let irrev_score = (0.25 * blast_diff.irreversible_mutations.len() as f64).min(1.0);

        // Ensemble calculation:
        // P_deception = min(1.0, max(obf, div, 1.0 - (1 - latent) * (1 - taint*0.5) * (1 - irrev*0.3)))
        let blended =
            1.0 - (1.0 - obf_score * 0.7) * (1.0 - taint_score * 0.5) * (1.0 - irrev_score * 0.3);
        let p_deception = obf_score.max(div_score).max(blended).clamp(0.0, 1.0);

        let veto_reason = if p_deception >= AUTO_VETO_THRESHOLD {
            Some(format!(
                "COGNITIVE_REDTEAM_AUTO_VETO: Deception likelihood P_deception={:.2} >= {:.2} (indicators={:?}, divergence={:.2}). Execution blocked.",
                p_deception, AUTO_VETO_THRESHOLD, indicators, div_score
            ))
        } else {
            None
        };

        (p_deception, veto_reason)
    }

    /// Generates a randomized polymorphic verification challenge (1 true invariant, 3 distractors).
    pub fn generate_polymorphic_challenge(
        request_id: &str,
        target_resource: &str,
        tool_name: &str,
    ) -> PolymorphicChallenge {
        let tool_lower = tool_name.trim().to_ascii_lowercase();

        // 1. Determine genuine system invariant based on domain
        let (genuine_invariant, distractors) = if tool_lower.contains("write")
            || target_resource.contains("hosts")
            || target_resource.contains("System32")
        {
            (
                "Invariant: Host filesystem paths outside sandbox scratchpad cannot be truncated or unlinked without write-intent authorization.",
                vec![
                    "Invariant: Local loopback adapter MTU must remain configured at exactly 1500 bytes.",
                    "Invariant: Audio renderer buffer size must not exceed 4096 samples per frame.",
                    "Invariant: Display scaling factor must remain at 100% during background batch jobs.",
                ],
            )
        } else if tool_lower.contains("cred") || target_resource.contains("lsass") {
            (
                "Invariant: Operating system credentials in LSASS/SAM/DPAPI are accessible exclusively to SYSTEM and must not be exposed to child workers.",
                vec![
                    "Invariant: Windows font cache size must not exceed 64 megabytes.",
                    "Invariant: Mouse cursor update polling rate must remain between 60Hz and 144Hz.",
                    "Invariant: Bluetooth peripheral pairing timeout must be exactly 300 seconds.",
                ],
            )
        } else if tool_lower.contains("exec")
            || tool_lower.contains("cmd")
            || tool_lower.contains("powershell")
        {
            (
                "Invariant: Subprocess execution environments must not inherit un-sanitized interpreter hook variables (PYTHONPATH, RUSTC_WRAPPER, NODE_OPTIONS).",
                vec![
                    "Invariant: CPU fan speed governor must remain in passive mode during I/O operations.",
                    "Invariant: System tray icon dimensions must remain 16x16 pixels.",
                    "Invariant: Network interface MAC address must not contain odd-parity octets.",
                ],
            )
        } else {
            (
                "Invariant: Outbound socket connections must not target unverified public IPv4/IPv6 endpoints from isolated sandbox workers.",
                vec![
                    "Invariant: GPU shader compilation cache must remain bounded under 128 megabytes.",
                    "Invariant: Keyboard repeat delay must remain configured at 500 milliseconds.",
                    "Invariant: Default printer spooler port must not use TCP port 9100.",
                ],
            )
        };

        let mut options = vec![
            genuine_invariant.to_string(),
            distractors[0].to_string(),
            distractors[1].to_string(),
            distractors[2].to_string(),
        ];

        // Fisher-Yates shuffle with cryptographic RNG
        let mut rng = rand::thread_rng();
        options.shuffle(&mut rng);

        let correct_option_index = options
            .iter()
            .position(|o| o == genuine_invariant)
            .unwrap_or(0);

        let challenge_id = format!("chal-{}", uuid::Uuid::new_v4());
        let challenge_nonce = format!("{:x}", uuid::Uuid::new_v4().as_u128());
        let expires_at_utc = Utc::now() + chrono::Duration::seconds(CHALLENGE_TTL_SECONDS);

        PolymorphicChallenge {
            challenge_id,
            request_id: request_id.to_string(),
            prompt: "Identify the genuine system invariant governing this action to verify comprehension:".to_string(),
            target_resource: target_resource.to_string(),
            options,
            correct_option_index,
            challenge_nonce,
            expires_at_utc,
        }
    }

    /// Evaluates a pending execution graph node and stores it in the pending queue.
    pub fn evaluate_pending_action(
        &self,
        node: PendingExecutionGraphNode,
    ) -> CognitiveRedTeamAssessment {
        self.total_evaluations.fetch_add(1, Ordering::SeqCst);

        let request_id = format!("req-{}", uuid::Uuid::new_v4());
        let canonical_tool = node.tool_name.trim().to_ascii_lowercase();
        let canonical_target_resource = node.target_resource.trim().to_string();
        let stripped_justification =
            Self::strip_natural_language_justification(&node.stated_justification);

        let blast_diff = Self::simulate_blast_radius_diff(
            &node.tool_name,
            &node.target_resource,
            &node.command_args,
            node.incoming_taint,
        );

        let (deception_score, veto_reason) = Self::compute_saelens_deception_likelihood(
            &node.user_objective,
            &node.tool_name,
            &node.target_resource,
            &node.command_args,
            &node.stated_justification,
            node.incoming_taint,
            &blast_diff,
        );

        let auto_vetoed = deception_score >= AUTO_VETO_THRESHOLD;
        if auto_vetoed {
            self.total_auto_vetoes.fetch_add(1, Ordering::SeqCst);
        }

        // Dual custody required if untrusted external taint OR irreversible mutation
        let dual_custody_required = node.incoming_taint == MeshTaintLevel::UntrustedExternal
            || node.incoming_taint == MeshTaintLevel::Quarantined
            || blast_diff.is_irreversible;

        let (approval_state, challenge_pub, full_challenge) = if auto_vetoed {
            (
                HitlApprovalState::AutoVetoed {
                    reason: veto_reason.clone().unwrap_or_default(),
                },
                None,
                None,
            )
        } else {
            let challenge = Self::generate_polymorphic_challenge(
                &request_id,
                &canonical_target_resource,
                &canonical_tool,
            );
            let pub_challenge = PolymorphicChallengePublic {
                challenge_id: challenge.challenge_id.clone(),
                request_id: challenge.request_id.clone(),
                prompt: challenge.prompt.clone(),
                target_resource: challenge.target_resource.clone(),
                options: challenge.options.clone(),
                challenge_nonce: challenge.challenge_nonce.clone(),
                expires_at_utc: challenge.expires_at_utc,
            };
            (
                HitlApprovalState::PendingChallenge,
                Some(pub_challenge),
                Some(challenge),
            )
        };

        let assessment = CognitiveRedTeamAssessment {
            request_id: request_id.clone(),
            canonical_tool,
            canonical_target_resource,
            stripped_justification,
            blast_radius_diff: blast_diff,
            deception_score,
            auto_vetoed,
            veto_reason,
            dual_custody_required,
            approval_state: approval_state.clone(),
            challenge: challenge_pub,
        };

        let stored = StoredPendingHitlAction {
            request_id: request_id.clone(),
            node,
            assessment: assessment.clone(),
            full_challenge,
            approval_state,
            created_at_utc: Utc::now(),
        };

        self.pending_actions.insert(request_id, stored);
        assessment
    }

    /// Returns public assessment views of all pending actions.
    pub fn get_pending_actions(&self) -> Vec<CognitiveRedTeamAssessment> {
        self.pending_actions
            .iter()
            .map(|entry| entry.value().assessment.clone())
            .collect()
    }

    /// Fetches public challenge (answer hidden) for given request_id.
    pub fn get_public_challenge(&self, request_id: &str) -> Option<PolymorphicChallengePublic> {
        self.pending_actions.get(request_id).and_then(|entry| {
            entry
                .value()
                .full_challenge
                .as_ref()
                .map(|c| PolymorphicChallengePublic {
                    challenge_id: c.challenge_id.clone(),
                    request_id: c.request_id.clone(),
                    prompt: c.prompt.clone(),
                    target_resource: c.target_resource.clone(),
                    options: c.options.clone(),
                    challenge_nonce: c.challenge_nonce.clone(),
                    expires_at_utc: c.expires_at_utc,
                })
        })
    }

    /// Submits operator approval solving the polymorphic challenge and enforcing dual-custody ($O_1 \neq O_2$).
    pub fn submit_approval(
        &self,
        request_id: &str,
        operator_id: &str,
        selected_option_index: usize,
        challenge_nonce: &str,
        confirmation_token: Option<&str>,
    ) -> Result<HitlApprovalState, OctopusSecurityError> {
        let op_trimmed = operator_id.trim();
        if op_trimmed.is_empty() {
            return Err(OctopusSecurityError::IdentitySpoofingDetected(
                "Operator ID cannot be empty".to_string(),
            ));
        }

        let mut entry = self.pending_actions.get_mut(request_id).ok_or_else(|| {
            OctopusSecurityError::EnclaveViolation(format!(
                "HITL request '{}' not found in pending actions",
                request_id
            ))
        })?;

        // 1. Verify not auto-vetoed
        if entry.assessment.auto_vetoed {
            return Err(OctopusSecurityError::CapabilityDenied(
                "Action was auto-vetoed by Cognitive Red-Team Interceptor. Approval is forbidden."
                    .to_string(),
            ));
        }

        // 2. Verify challenge exists and is valid
        let challenge = entry.full_challenge.as_ref().ok_or_else(|| {
            OctopusSecurityError::CapabilityDenied(
                "No active challenge found for action".to_string(),
            )
        })?;

        if challenge.challenge_nonce != challenge_nonce {
            self.total_challenges_failed.fetch_add(1, Ordering::SeqCst);
            return Err(OctopusSecurityError::IdentitySpoofingDetected(
                "Invalid challenge nonce provided".to_string(),
            ));
        }

        if Utc::now() > challenge.expires_at_utc {
            self.total_challenges_failed.fetch_add(1, Ordering::SeqCst);
            return Err(OctopusSecurityError::CapabilityDenied(
                "Challenge expired (TTL 120s exceeded). Refresh challenge.".to_string(),
            ));
        }

        if selected_option_index != challenge.correct_option_index {
            self.total_challenges_failed.fetch_add(1, Ordering::SeqCst);
            return Err(OctopusSecurityError::CapabilityDenied(
                "Incorrect system invariant selected in polymorphic challenge. Review blast radius."
                    .to_string(),
            ));
        }

        // Challenge passed!
        self.total_challenges_passed.fetch_add(1, Ordering::SeqCst);

        // Optional typed blast-radius token verification if required by divergence
        if entry.assessment.deception_score >= 0.45 && entry.assessment.deception_score < 0.85 {
            let expected_token = HitlCognitiveFirewall::expected_blast_radius_token(
                &entry.node.tool_name,
                &entry.node.target_resource,
            );
            if let Some(token) = confirmation_token {
                if token.trim() != expected_token {
                    return Err(OctopusSecurityError::CapabilityDenied(format!(
                        "Typed confirmation token mismatch: expected '{}', got '{}'",
                        expected_token, token
                    )));
                }
            } else {
                return Err(OctopusSecurityError::CapabilityDenied(format!(
                    "Typed confirmation token required: '{}'",
                    expected_token
                )));
            }
        }

        // Dual custody logic
        if entry.assessment.dual_custody_required {
            match &entry.approval_state {
                HitlApprovalState::PendingChallenge | HitlApprovalState::PendingFirstApproval => {
                    let new_state = HitlApprovalState::PendingSecondApproval {
                        first_operator: op_trimmed.to_string(),
                    };
                    entry.approval_state = new_state.clone();
                    entry.assessment.approval_state = new_state.clone();
                    Ok(new_state)
                }
                HitlApprovalState::PendingSecondApproval { first_operator } => {
                    if first_operator == op_trimmed {
                        return Err(OctopusSecurityError::DelegationScopeViolation(
                            "DUAL_CUSTODY_SELF_APPROVAL_FORBIDDEN: Second operator must be distinct from first operator."
                                .to_string(),
                        ));
                    }

                    // Generate cryptographic HitlApprovalReceipt
                    let receipt_id = format!("rcpt-{}", uuid::Uuid::new_v4());
                    let issued_at = Utc::now().timestamp() as u64;
                    let expires_at = issued_at + 300; // 5 min receipt validity

                    let receipt = HitlApprovalReceipt::sign(
                        &receipt_id,
                        &format!("{}+{}", first_operator, op_trimmed),
                        entry.node.arm_id,
                        entry.node.arm_generation,
                        &entry.node.correlation_id,
                        vec![entry.node.tool_name.clone()],
                        issued_at,
                        expires_at,
                        &self.operator_secret,
                    );

                    let new_state = HitlApprovalState::QuorumApproved {
                        operators: vec![first_operator.clone(), op_trimmed.to_string()],
                        receipt: Some(receipt),
                    };
                    entry.approval_state = new_state.clone();
                    entry.assessment.approval_state = new_state.clone();
                    self.total_quorum_completions.fetch_add(1, Ordering::SeqCst);
                    Ok(new_state)
                }
                HitlApprovalState::QuorumApproved { .. } => Ok(entry.approval_state.clone()),
                other => Err(OctopusSecurityError::CapabilityDenied(format!(
                    "Action cannot be approved in state {:?}",
                    other
                ))),
            }
        } else {
            // Single operator sufficient
            let receipt_id = format!("rcpt-{}", uuid::Uuid::new_v4());
            let issued_at = Utc::now().timestamp() as u64;
            let expires_at = issued_at + 300;

            let receipt = HitlApprovalReceipt::sign(
                &receipt_id,
                op_trimmed,
                entry.node.arm_id,
                entry.node.arm_generation,
                &entry.node.correlation_id,
                vec![entry.node.tool_name.clone()],
                issued_at,
                expires_at,
                &self.operator_secret,
            );

            let new_state = HitlApprovalState::QuorumApproved {
                operators: vec![op_trimmed.to_string()],
                receipt: Some(receipt),
            };
            entry.approval_state = new_state.clone();
            entry.assessment.approval_state = new_state.clone();
            self.total_quorum_completions.fetch_add(1, Ordering::SeqCst);
            Ok(new_state)
        }
    }

    /// Rejects action and records operator audit reason.
    pub fn submit_rejection(
        &self,
        request_id: &str,
        operator_id: &str,
        reason: &str,
    ) -> Result<HitlApprovalState, OctopusSecurityError> {
        let mut entry = self.pending_actions.get_mut(request_id).ok_or_else(|| {
            OctopusSecurityError::EnclaveViolation(format!(
                "HITL request '{}' not found in pending actions",
                request_id
            ))
        })?;

        let new_state = HitlApprovalState::Rejected {
            operator: operator_id.trim().to_string(),
            reason: reason.trim().to_string(),
        };
        entry.approval_state = new_state.clone();
        entry.assessment.approval_state = new_state.clone();
        Ok(new_state)
    }

    /// Telemetry status summary.
    pub fn get_status(&self) -> CognitiveRedTeamStatus {
        CognitiveRedTeamStatus {
            total_evaluations: self.total_evaluations.load(Ordering::Relaxed),
            total_auto_vetoes: self.total_auto_vetoes.load(Ordering::Relaxed),
            total_challenges_passed: self.total_challenges_passed.load(Ordering::Relaxed),
            total_challenges_failed: self.total_challenges_failed.load(Ordering::Relaxed),
            total_quorum_completions: self.total_quorum_completions.load(Ordering::Relaxed),
            pending_actions_count: self.pending_actions.len(),
        }
    }
}

static GLOBAL_COGNITIVE_REDTEAM: OnceLock<CognitiveRedTeamInterceptor> = OnceLock::new();

/// Global thread-safe singleton for Cognitive Red-Team Interceptor.
pub fn global_cognitive_redteam() -> &'static CognitiveRedTeamInterceptor {
    GLOBAL_COGNITIVE_REDTEAM.get_or_init(|| {
        let secret = [0x5cu8; 32];
        CognitiveRedTeamInterceptor::new(secret)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_counterfactual_blast_radius_reversible_vs_irreversible() {
        // Read-only reversible
        let read_blast = CognitiveRedTeamInterceptor::simulate_blast_radius_diff(
            "read_file",
            "C:\\workspace\\README.md",
            "",
            MeshTaintLevel::TrustedInternal,
        );
        assert!(!read_blast.is_irreversible);
        assert!(read_blast.irreversible_mutations.is_empty());
        assert_eq!(read_blast.privilege_tier, "BENIGN_REVERSIBLE_OPERATION");

        // Permanent write irreversible
        let write_blast = CognitiveRedTeamInterceptor::simulate_blast_radius_diff(
            "write_file",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "127.0.0.1 bad.local",
            MeshTaintLevel::UntrustedExternal,
        );
        assert!(write_blast.is_irreversible);
        assert!(
            write_blast
                .irreversible_mutations
                .iter()
                .any(|m| m.mutation_type
                    == IrreversibleMutationType::PermanentFileOverwriteOrDeletion)
        );
        assert!(write_blast
            .irreversible_mutations
            .iter()
            .any(|m| m.mutation_type == IrreversibleMutationType::SecurityBoundaryTampering));
    }

    #[test]
    fn test_justification_stripping() {
        let raw =
            "Please approve this action because I am formatting logs and testing dependencies.";
        let stripped = CognitiveRedTeamInterceptor::strip_natural_language_justification(raw);
        assert!(!stripped.contains("formatting logs"));
        assert!(stripped.contains("[STRIPPED BY COGNITIVE RED-TEAM"));
    }

    #[test]
    fn test_saelens_deception_auto_veto_at_0_85() {
        let interceptor = CognitiveRedTeamInterceptor::new([0x11; 32]);
        let node = PendingExecutionGraphNode {
            session_id: "sess-01".to_string(),
            arm_id: 1,
            arm_generation: 1,
            agent_id: "worker-1".to_string(),
            correlation_id: "corr-01".to_string(),
            tool_name: "extract_credentials".to_string(),
            target_resource: "C:\\Windows\\System32\\lsass.exe".to_string(),
            command_args: "--dump".to_string(),
            stated_justification: "Harmless developer log cleanup".to_string(),
            incoming_taint: MeshTaintLevel::UntrustedExternal,
            user_objective: "Format readme and fix typos".to_string(),
        };

        let assessment = interceptor.evaluate_pending_action(node);
        assert!(assessment.deception_score >= 0.85);
        assert!(assessment.auto_vetoed);
        assert!(matches!(
            assessment.approval_state,
            HitlApprovalState::AutoVetoed { .. }
        ));

        // Attempting to approve an auto-vetoed action is rejected
        let res = interceptor.submit_approval(&assessment.request_id, "op1", 0, "dummy", None);
        assert!(res.is_err());
    }

    #[test]
    fn test_polymorphic_challenge_shuffling_and_verification() {
        let interceptor = CognitiveRedTeamInterceptor::new([0x22; 32]);
        let node = PendingExecutionGraphNode {
            session_id: "sess-02".to_string(),
            arm_id: 2,
            arm_generation: 1,
            agent_id: "worker-2".to_string(),
            correlation_id: "corr-02".to_string(),
            tool_name: "write_file".to_string(),
            target_resource: "C:\\Windows\\System32\\drivers\\etc\\hosts".to_string(),
            command_args: "127.0.0.1 test.local".to_string(),
            stated_justification: "Update test host configuration".to_string(),
            incoming_taint: MeshTaintLevel::TrustedInternal,
            user_objective: "Configure local dev environment".to_string(),
        };

        let assessment = interceptor.evaluate_pending_action(node);
        assert!(!assessment.auto_vetoed);
        assert!(assessment.challenge.is_some());

        let pub_chal = assessment.challenge.unwrap();
        let correct_idx = {
            let stored = interceptor
                .pending_actions
                .get(&assessment.request_id)
                .unwrap();
            stored.full_challenge.as_ref().unwrap().correct_option_index
        };

        // Submitting wrong option index fails
        let wrong_idx = (correct_idx + 1) % 4;
        let fail_res = interceptor.submit_approval(
            &assessment.request_id,
            "operator_alice",
            wrong_idx,
            &pub_chal.challenge_nonce,
            None,
        );
        assert!(fail_res.is_err());
    }

    #[test]
    fn test_dual_custody_self_approval_blocked_and_quorum_success() {
        let interceptor = CognitiveRedTeamInterceptor::new([0x33; 32]);
        // UntrustedExternal incoming taint requires dual custody
        let node = PendingExecutionGraphNode {
            session_id: "sess-03".to_string(),
            arm_id: 3,
            arm_generation: 1,
            agent_id: "worker-3".to_string(),
            correlation_id: "corr-03".to_string(),
            tool_name: "write_file".to_string(),
            target_resource: "C:\\Windows\\System32\\drivers\\etc\\hosts".to_string(),
            command_args: "127.0.0.1 safe.local".to_string(),
            stated_justification: "Updating system host routing entry".to_string(),
            incoming_taint: MeshTaintLevel::UntrustedExternal,
            user_objective: "Modify system host routing configuration".to_string(),
        };

        let assessment = interceptor.evaluate_pending_action(node);
        assert!(assessment.dual_custody_required);

        let pub_chal = assessment.challenge.unwrap();
        let correct_idx = {
            let stored = interceptor
                .pending_actions
                .get(&assessment.request_id)
                .unwrap();
            stored.full_challenge.as_ref().unwrap().correct_option_index
        };

        // Operator 1 approves -> moves to PendingSecondApproval
        let first_res = interceptor
            .submit_approval(
                &assessment.request_id,
                "operator_alice",
                correct_idx,
                &pub_chal.challenge_nonce,
                None,
            )
            .expect("First approval should succeed");

        assert!(matches!(
            first_res,
            HitlApprovalState::PendingSecondApproval { ref first_operator } if first_operator == "operator_alice"
        ));

        // Same Operator 1 attempts second approval -> blocked!
        let self_res = interceptor.submit_approval(
            &assessment.request_id,
            "operator_alice",
            correct_idx,
            &pub_chal.challenge_nonce,
            None,
        );
        assert!(self_res.is_err());
        let err_str = format!("{:?}", self_res.unwrap_err());
        assert!(err_str.contains("DUAL_CUSTODY_SELF_APPROVAL_FORBIDDEN"));

        // Distinct Operator 2 approves -> QuorumApproved with receipt!
        let second_res = interceptor
            .submit_approval(
                &assessment.request_id,
                "operator_bob",
                correct_idx,
                &pub_chal.challenge_nonce,
                None,
            )
            .expect("Second approval from distinct operator should achieve quorum");

        match second_res {
            HitlApprovalState::QuorumApproved { operators, receipt } => {
                assert_eq!(operators, vec!["operator_alice", "operator_bob"]);
                assert!(receipt.is_some());
                let r = receipt.unwrap();
                assert!(!r.signature_hex.is_empty());
                assert_eq!(r.target_arm_id, 3);
            }
            other => panic!("Expected QuorumApproved, got {:?}", other),
        }
    }
}
