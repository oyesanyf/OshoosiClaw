---
name: agent-breakout-prevention
description: Design, verify, and audit OshoosiClaw's 7-Ring Continuous Cedar Reference Monitor, 5-Level Immutable Authority Lattice (L1-L5), Persistent Causal Security Graph, OS-Enforced Capability Isolation (Windows AppContainer/Job Objects & Linux seccomp/Landlock/cgroups), 3-Boundary Self-Protection, 9-Family Residual-Risk Verification Suite, and 6-Capability Adversarial & Usability Regression Harness.
---

# Agent Breakout Prevention & Continuous Cedar Reference Monitor Skill

Use this skill when implementing, auditing, or extending agentic containment, prompt-injection / goal-hijack defenses, causal taint propagation, or adversarial breakout testing in OshoosiClaw (`OpenỌ̀ṣọ́ọ̀sì`).

## 1. Core Architectural Principle: Separate Reasoning from Authority

Models may **propose** actions, summarize untrusted content, and emit advisory risk scores, but models **never hold ambient authority**. Every privileged effect is mediated by a deterministic, non-bypassable OS & Cedar Reference Monitor across 7 defense rings:

1. **Ring 1 — Immutable 5-Level Authority Hierarchy & Signed Workspace Instructions (`crates/osoosi-policy/src/breakout_gate.rs`)**:
   - Strict ordering: `L1SystemSecurityPolicy (1) > L2AuthorizedUserObjective (2) > L3TrustedApplicationInstruction (3) > L4WorkspaceConfiguration (4) > L5UntrustedRetrievedContent (5)`.
   - Workspace files (`CLAUDE.md`, `.cursorrules`, `.agents/AGENTS.md`, `.githooks`, `build.rs`) are verified via `SignedWorkspaceInstructionAllowlist` using keyed `HMAC-BLAKE3` + `HMAC-SHA256` (`subtle::ConstantTimeEq`) + `Ed25519/ML-DSA-65` hybrid attestation.
   - **Zero Upward Authority Promotion**: Even validly signed `L4WorkspaceConfiguration` files can never override `L1` or `L2` policy.
   - **Per-User / Hardware-Bound Key Scope (`P0.2`)**: Signing keys must never use machine-wide `CRYPTPROTECT_LOCAL_MACHINE` scope.

2. **Ring 2 — Continuous Lifecycle Cedar Authorization (`PolicyEngine::evaluate` & `scan_event`)**:
   - Evaluates `CedarPrincipal`, `CedarAction` (`ChildProcessExec`, `SensitiveFileAccess`, `ExternalNetworkConnect`, `ExternalWrite`, `PrivilegedLocalControl`, `DynamicCodeExec`, `CrossSessionTransfer`), `CedarResource`, and `CedarContext`.
   - Emits deterministic `(policy_decision_id, causal_event_id, policy_version)` and distinguishes `PreExecutionPrevented`, `PostNotificationContained`, and `PostExecutionDetected`.
   - **Fail-Closed Voter Invariant**: Compromised (`weight < 0.0`) or timed-out voters (`ReaVoter`, `OpenJevVoter`) can never turn a Cedar `forbid` into permission; voter multipliers are clamped to `[0.50, 2.50]`.

3. **Ring 3 — Persistent Causal Security Graph & Workflow Composition (`CausalSecurityGraph`, `WorkflowCompositionEvaluator`)**:
   - Tracks composite `ProcessInstanceIdentity` (`boot_id_guid`, `pid`, `creation_time_100ns`, `process_start_key`, `exe_sha256`, `parent_instance_key`) to defeat PID reuse.
   - Propagates monotonic taint and `DataClassification` (`Public < InternalWorkspace < SensitiveCredential < CrownJewelSecret`) across child/grandchild processes, intermediate files, system brokers (`WmiPrvSE.exe`, `svchost.exe`, `conhost.exe`, `git-remote-https.exe`, `ssh.exe`), and cross-session transfers.
   - Blocks composed workflows (`SensitiveFileAccess -> Transform -> ExternalWrite`) unless accompanied by a verified `<ZK_PII:...>` or `<ZK_CROWN_JEWEL_REDACTED:...>` supervisor HMAC receipt (`DeclassificationReceipt`).

4. **Ring 4 — Loopback & Local IPC Service-Identity Authorizer (`LoopbackIpcAuthorizer`)**:
   - Inspects destination port, URL path, HTTP method, and named pipes/Unix sockets so `127.0.0.1` is never treated as blanket-benign.
   - Permits read-only local Ollama inference (`/api/generate`, `/api/chat`, `/api/embeddings` on `:11434`) while blocking unapproved Chrome DevTools (`:9222`), Docker Engine (`:2375`, `//./pipe/docker_engine`, `/var/run/docker.sock`), and Ollama model deletion/mutation.

5. **Ring 5 — Concurrency Seqlock & Revocation-Bound Capability Cache (`RevocationBoundCapabilityCache`)**:
   - Keyed by `(principal_id, action, resource_id, policy_version, taint_epoch, revocation_seq)` and synchronized via a `parking_lot::RwLock` barrier so `0` in-flight `ExternalWrite` operations ever commit after a concurrent `SensitiveFileAccess` or revocation begins.

6. **Ring 6 — 3-Boundary Control-Plane Self-Protection (`ProtectedPolicyStore`, `SafeTelemetryOverloadController`, `ExternalIntegrityVerifierAndRecovery`)**:
   - `P0.4`: Dual `Ed25519 + ML-DSA-65` signatures, monotonic anti-rollback version numbers, and independent two-party non-agent approval (`author_principal != approver_principal`).
   - **Separate Learning from Authority (`CandidateCedarPolicyProposal`)**: RL (`SkyRL`) may only propose tighten-only `forbid` clauses and cannot mutate active Cedar policy, add `permit` rules, weaken `forbid` rules, declassify taint, or alter causal provenance without passing `benign_workflow_regression` + `protected_holdout` and dual-principal signing.
   - `P1.3`: When `EventsLost > 0`, high-risk capability grants (`ExternalWrite`, `ChildProcessExec`, `PrivilegedLocalControl`, `DynamicCodeExec`) freeze automatically while keeping local developer reads responsive.
   - `P2.2`: Out-of-process integrity heartbeat and deterministic snapshot recovery.

7. **Ring 7 — OS-Enforced Capability Isolation (`Ring7CapabilityEffectAuthorizer`, `OsConfinementVerifier`)**:
   - Windows: AppContainer low-privilege token + Job Object (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, `JOB_OBJECT_LIMIT_ACTIVE_PROCESS`, UI clipboard/desktop restrictions) + `CREATE_SUSPENDED` pre-resume verification + WFP/NDF outbound filter.
   - Linux: Non-root `UID 65532:65532`, `--cap-drop=ALL`, `PR_SET_NO_NEW_PRIVS`, read-only rootfs, `docker/seccomp-oshoosi.json`, Landlock V3, and cgroups v2.

## 2. Verification & Adversarial Regression Commands

- **Rust Unit & Proof Suite Verification**:
  ```powershell
  cargo test --no-run -p osoosi-policy --lib
  cargo test --no-run -p osoosi-agent-anomaly --lib
  powershell -ExecutionPolicy Bypass -File scripts/sign_debug_test_binaries.ps1
  cargo test -p osoosi-policy --lib
  cargo test -p osoosi-agent-anomaly --lib breakout_prevention
  ```
- **6-Capability Adversarial & Usability Regression Harness**:
  ```powershell
  python tests/strix_llm_adversarial_tester.py --skip-strix --suite adr_bench
  python tests/strix_llm_adversarial_tester.py --skip-strix --suite rampart
  python tests/strix_llm_adversarial_tester.py --skip-strix --suite agentdojo
  python tests/strix_llm_adversarial_tester.py --skip-strix --suite pyrit
  python tests/strix_llm_adversarial_tester.py --skip-strix --suite host_enforcement_verification
  python tests/strix_llm_adversarial_tester.py --skip-strix --suite benign_workflow_regression
  ```
