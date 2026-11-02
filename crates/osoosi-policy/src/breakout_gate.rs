//! # 7-Ring Continuous Cedar Reference Monitor, Causal Provenance Graph, & Capability-Based Effect Gate
//!
//! Provides the unified policy & capability enforcement core shared by `osoosi-policy` (`PolicyEngine::evaluate`
//! and `PolicyEngine::scan_event`) and `osoosi-agent-anomaly` (`BreakoutDefenseCoordinator`,
//! `RuntimeAlignmentScanner`, and `Ring7CapabilityEffectAuthorizer`).
//!
//! ## Subsystem Architecture & Invariants:
//! - **Ring 7 Direct Binary Byte Hashing**: Authorizer hashes raw binary bytes directly (`sha256`, `blake3`, cryptographic hash)
//!   rather than inspecting mutable metadata, preventing TOCTOU file tampering.
//! - **5-Level Immutable Authority Lattice (L1-L5)**: Agent genesis pins immutable capability envelope at creation.
//! - **Prohibition of Dynamic Dilation**: Runtime attempts to dilate or escalate capabilities fail closed (`deny`), ensuring
//!   child envelopes are strictly confined within parent limits.
//!
//! Decomposed into cohesive submodules under `crate::breakout::*`.
//! Re-exports all symbols with 100% backwards compatibility.

#[path = "breakout/mod.rs"]
pub mod breakout;
pub use breakout::*;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    #[test]
    fn test_loopback_host_classification_is_mathematical_including_bracketed_ipv6() {
        for host in [
            "localhost",
            "api.localhost",
            "127.0.0.1",
            "127.45.6.7",
            "0.0.0.0",
            "::1",
            "[::1]",
            "::",
            "[::ffff:127.0.0.1]",
            "::ffff:7f00:1",
        ] {
            assert!(
                LoopbackIpcAuthorizer::is_loopback_or_unspecified_host(host),
                "{host} must classify as loopback/unspecified"
            );
        }
        for host in [
            "github.com",
            "128.0.0.1",
            "[2001:db8::1]",
            "127.example.com",
            "localhost.evil.com",
        ] {
            assert!(
                !LoopbackIpcAuthorizer::is_loopback_or_unspecified_host(host),
                "{host} must not classify as loopback"
            );
        }

        // IPv6-bracketed Chrome DevTools endpoint must be recognized as privileged local control.
        let cdp_v6 =
            LoopbackIpcAuthorizer::classify_target("http://[::1]:9333/devtools/browser/123", "GET");
        assert!(cdp_v6.is_local_or_ipc);
        assert!(cdp_v6.requires_privileged_capability);
        assert_eq!(
            cdp_v6.mapped_cedar_action,
            CedarAction::PrivilegedLocalControl
        );
    }

    #[test]
    fn test_cached_permit_cannot_bypass_context_dependent_forbid() {
        let auth = Ring7CapabilityEffectAuthorizer::new();
        let principal = CedarPrincipal {
            principal_id: "agent-cache-regression".to_string(),
            session_id: "sess-cache-regression".to_string(),
            process_instance_key: "proc:7100:1:agent:sess-cache-regression".to_string(),
            authority_level: AuthorityLevel::L2AuthorizedUserObjective,
            approved_capabilities: vec!["ExternalWrite".to_string()],
            authenticated_role: None,
        };
        auth.set_session_egress_budget(&principal.session_id, 1, 1024);

        let first = auth.execute_guarded_external_write(
            &principal,
            "https://github.com/oyesanyf/OshoosiClaw",
            "ping",
            true,
            None,
            || (),
        );
        assert!(matches!(first, GuardedEffectOutcome::Committed { .. }));

        // Same principal/action/resource: the earlier permit is cached, but the exhausted egress budget
        // changes the decision inputs, so the request must be evaluated afresh and denied.
        let effects = std::sync::atomic::AtomicUsize::new(0);
        let second = auth.execute_guarded_external_write(
            &principal,
            "https://github.com/oyesanyf/OshoosiClaw",
            "covert-bit",
            true,
            None,
            || {
                effects.fetch_add(1, Ordering::SeqCst);
            },
        );
        assert!(
            matches!(second, GuardedEffectOutcome::DeniedPreExecution { .. }),
            "cached permit replayed past CEDAR-FORBID-003C egress budget: {second:?}"
        );
        assert_eq!(effects.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_authority_hierarchy_and_signed_workspace_allowlist() {
        assert!(AuthorityLevel::L1SystemSecurityPolicy
            .outranks(&AuthorityLevel::L2AuthorizedUserObjective));
        assert!(AuthorityLevel::L2AuthorizedUserObjective
            .outranks(&AuthorityLevel::L4WorkspaceConfiguration));
        assert!(!AuthorityLevel::L4WorkspaceConfiguration.can_override_higher_policy());
        assert!(!AuthorityLevel::L5UntrustedRetrievedContent.can_authorize_privileged_action());

        let allowlist =
            SignedWorkspaceInstructionAllowlist::new(*b"test-control-plane-key-32-bytes!");
        let content = b"# AGENTS.md\nAlways run cargo test before shipping.";
        let sig = allowlist.sign_and_register_workspace_file(
            ".agents/AGENTS.md",
            content,
            "control-plane-key-v1",
        );
        let verified = allowlist.verify_workspace_instruction(
            ".agents/AGENTS.md",
            content,
            AuthorityLevel::L4WorkspaceConfiguration,
        );
        assert!(verified.allowed);
        assert!(verified.cryptographic_signature_valid);
        assert_eq!(
            sig.assigned_authority,
            AuthorityLevel::L4WorkspaceConfiguration
        );
        assert_eq!(
            verified.effective_authority,
            AuthorityLevel::L4WorkspaceConfiguration
        );

        // Attempting upward promotion from L4 to L2 must be blocked
        let promoted = allowlist.verify_workspace_instruction(
            ".agents/AGENTS.md",
            content,
            AuthorityLevel::L2AuthorizedUserObjective,
        );
        assert!(!promoted.allowed);
        assert!(promoted.upward_promotion_blocked);

        // Machine-wide CRYPTPROTECT_LOCAL_MACHINE key storage must be rejected
        let machine_wide = allowlist
            .verify_key_isolation_policy("OsoosiEDRService", "DPAPI:CRYPTPROTECT_LOCAL_MACHINE");
        assert!(!machine_wide.allowed);
        assert!(machine_wide.cryptprotect_local_machine_rejected);
    }

    #[test]
    fn test_rl_separate_learning_from_authority_invariant() {
        let store = ProtectedPolicyStore::default();
        let initial_ver = store.active_version_num();

        // 1. RL attempting to add a `permit` rule must be rejected
        let permit_prop = CandidateCedarPolicyProposal {
            proposal_id: "prop-permit-1".to_string(),
            proposer_model_id: "skyrl-ppo-v2".to_string(),
            proposed_forbid_clause:
                "permit (principal, action == Action::\"ExternalWrite\", resource);".to_string(),
            attempts_taint_declassification: false,
            attempts_causal_provenance_mutation: false,
            benign_workflow_regression_passed: true,
            protected_holdout_passed: true,
        };
        let eval_permit = store.evaluate_rl_tighten_only_proposal(&permit_prop);
        assert!(!eval_permit.proposal_valid_for_dual_approval);
        assert!(eval_permit.rejected_permit_rule_addition);
        assert!(eval_permit.active_policy_unchanged_until_signed);
        assert_eq!(store.active_version_num(), initial_ver);

        // 2. RL attempting taint declassification must be rejected
        let taint_prop = CandidateCedarPolicyProposal {
            proposal_id: "prop-taint-2".to_string(),
            proposer_model_id: "skyrl-ppo-v2".to_string(),
            proposed_forbid_clause:
                "forbid (principal, action == Action::\"ExternalWrite\", resource);".to_string(),
            attempts_taint_declassification: true,
            attempts_causal_provenance_mutation: false,
            benign_workflow_regression_passed: true,
            protected_holdout_passed: true,
        };
        let eval_taint = store.evaluate_rl_tighten_only_proposal(&taint_prop);
        assert!(!eval_taint.proposal_valid_for_dual_approval);
        assert!(eval_taint.rejected_taint_or_provenance_mutation);

        // 3. Valid tighten-only forbid proposal that passed regression & holdout is eligible for dual-signing,
        //    yet NEVER mutates active policy until a dual-principal SignedPolicyUpdateBundle is applied
        let valid_forbid = CandidateCedarPolicyProposal {
            proposal_id: "prop-forbid-3".to_string(),
            proposer_model_id: "skyrl-ppo-v2".to_string(),
            proposed_forbid_clause: "forbid (principal, action == Action::\"DynamicCodeExec\", resource) when { context.taintLevel > 50 };".to_string(),
            attempts_taint_declassification: false,
            attempts_causal_provenance_mutation: false,
            benign_workflow_regression_passed: true,
            protected_holdout_passed: true,
        };
        let eval_valid = store.evaluate_rl_tighten_only_proposal(&valid_forbid);
        assert!(eval_valid.proposal_valid_for_dual_approval);
        assert!(eval_valid.active_policy_unchanged_until_signed);
        assert_eq!(store.active_version_num(), initial_ver);
    }

    #[test]
    fn test_dogwood_mfotl_temporal_taint_flow_forbid() {
        let evaluator = DogwoodTemporalPolicyEvaluator::new(7200);
        let session = "sess-temporal-test-1";

        // Step 1: UntrustedWebInput
        evaluator.record_event(
            session,
            TemporalEventType::UntrustedWebInput,
            Some("https://attacker.example.com/payload.js".to_string()),
        );

        // Subprocess at this point is not yet fragmented
        let (forbid, _) =
            evaluator.evaluate_taint_flow(session, chrono::Utc::now().timestamp(), None);
        assert!(!forbid, "Should not forbid before scratch file write");

        // Step 2: ScratchFileWrite
        evaluator.record_event(
            session,
            TemporalEventType::ScratchFileWrite,
            Some("/tmp/scratch_stage1.sh".to_string()),
        );

        // Step 3: SubprocessEnvOrArg referencing scratch file
        evaluator.record_event(
            session,
            TemporalEventType::SubprocessEnvOrArg,
            Some("/tmp/scratch_stage1.sh".to_string()),
        );

        // Evaluation must now trigger forbid
        let (forbid, reason) =
            evaluator.evaluate_taint_flow(session, chrono::Utc::now().timestamp(), None);
        assert!(
            forbid,
            "Dogwood MFOTL must forbid multi-turn temporal taint chain"
        );
        assert!(reason
            .unwrap()
            .contains("CEDAR-FORBID-TEMPORAL-TAINT-FRAGMENTATION"));
    }

    #[test]
    fn test_dogwood_mfotl_supervisor_declassification_clears_forbid() {
        let evaluator = DogwoodTemporalPolicyEvaluator::new(7200);
        let session = "sess-temporal-declass-test";
        let now = chrono::Utc::now().timestamp();

        evaluator.record_atom(TemporalTraceAtom {
            timestamp_utc: now - 100,
            event_type: TemporalEventType::UntrustedWebInput,
            session_id: session.to_string(),
            resource_path: Some("https://partner-api.com/data".to_string()),
        });
        evaluator.record_atom(TemporalTraceAtom {
            timestamp_utc: now - 80,
            event_type: TemporalEventType::ScratchFileWrite,
            session_id: session.to_string(),
            resource_path: Some("/tmp/parsed_data.json".to_string()),
        });
        evaluator.record_atom(TemporalTraceAtom {
            timestamp_utc: now - 60,
            event_type: TemporalEventType::SubprocessEnvOrArg,
            session_id: session.to_string(),
            resource_path: Some("/tmp/parsed_data.json".to_string()),
        });

        // Without declassification, it is forbidden
        let (forbid_before, _) = evaluator.evaluate_taint_flow(session, now, None);
        assert!(forbid_before);

        // Record supervisor cryptographic declassification
        evaluator.record_declassification(session);

        // After supervisor declassification, forbid is cleared
        let (forbid_after, reason) =
            evaluator.evaluate_taint_flow(session, chrono::Utc::now().timestamp(), None);
        assert!(
            !forbid_after,
            "Supervisor declassification must clear temporal taint forbid"
        );
        assert!(reason.is_none());
    }

    #[test]
    fn test_dogwood_mfotl_sliding_window_expiry() {
        let evaluator = DogwoodTemporalPolicyEvaluator::new(7200);
        let session = "sess-temporal-expiry-test";
        let now = chrono::Utc::now().timestamp();
        let three_hours_ago = now - 10800; // outside 2h (7200s) window

        evaluator.record_atom(TemporalTraceAtom {
            timestamp_utc: three_hours_ago,
            event_type: TemporalEventType::UntrustedWebInput,
            session_id: session.to_string(),
            resource_path: Some("https://old-input.com".to_string()),
        });
        evaluator.record_atom(TemporalTraceAtom {
            timestamp_utc: three_hours_ago + 10,
            event_type: TemporalEventType::ScratchFileWrite,
            session_id: session.to_string(),
            resource_path: Some("/tmp/old_scratch.txt".to_string()),
        });
        evaluator.record_atom(TemporalTraceAtom {
            timestamp_utc: now,
            event_type: TemporalEventType::SubprocessEnvOrArg,
            session_id: session.to_string(),
            resource_path: Some("/tmp/old_scratch.txt".to_string()),
        });

        // Out-of-window web input should not trigger the temporal taint chain
        let (forbid, _) = evaluator.evaluate_taint_flow(session, now, None);
        assert!(
            !forbid,
            "Events outside sliding window (2h) must expire and not trigger forbid"
        );
    }

    #[test]
    fn test_ring7_authorizer_child_process_exec_blocked_on_taint_fragmentation() {
        let authorizer = Ring7CapabilityEffectAuthorizer::new();
        let principal = CedarPrincipal {
            principal_id: "agent-coder-1".to_string(),
            session_id: "sess-r7-temporal".to_string(),
            process_instance_key: "proc-1".to_string(),
            authority_level: AuthorityLevel::L3TrustedApplicationInstruction,
            approved_capabilities: vec!["process_spawn".to_string()],
            authenticated_role: None,
        };
        let resource = CedarResource {
            resource_id: "proc_child_1".to_string(),
            resource_type: "ChildProcess".to_string(),
            classification: DataClassification::InternalWorkspace,
            is_signed_and_allowlisted: false,
            is_approved_child_binary: true,
            is_task_scoped_destination: true,
            is_declassified_approved_sink: false,
            service_identity: None,
            service_operation: None,
        };

        let context = CedarContext {
            has_untrusted_web_input: true,
            has_scratch_file_write: true,
            subprocess_env_or_arg_tainted: true,
            ..Default::default()
        };

        let decision = authorizer.evaluate_cedar_request(
            &principal,
            CedarAction::ChildProcessExec,
            &resource,
            context,
            EnforcementStage::PreExecutionPrevented,
        );

        assert!(
            !decision.allowed,
            "ChildProcessExec must be forbidden on temporal taint fragmentation"
        );
        assert!(
            decision
                .matched_forbid_policies
                .iter()
                .any(|p| p.contains("CEDAR-FORBID-TEMPORAL-TAINT-FRAGMENTATION")),
            "Matched policies: {:?}",
            decision.matched_forbid_policies
        );
    }
}
