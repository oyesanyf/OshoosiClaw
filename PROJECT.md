# Project: 7-Ring Continuous Cedar Lifecycle & Effect-Based Authorization Architecture

## Architecture
OshoosiClaw (OpenỌ̀ṣọ́ọ̀sì) is upgraded from isolated heuristic rings to a unified **7-Ring Continuous Cedar Lifecycle & Effect-Based Authorization Architecture** with a persistent causal security graph, non-promotable authority hierarchy, capability-based egress gating, service-identity loopback authorization, and operating-system-enforced process isolation.

```
+---------------------------------------------------------------------------------------------------------+
|                                  Level 1: SystemSecurityPolicy (Immutable)                              |
|                                Level 2: AuthorizedUserObjective (User Task)                             |
|                               Level 3: TrustedApplicationInstruction (App)                              |
|                          Level 4: WorkspaceConfiguration (.cursorrules, CLAUDE.md)                      |
|                         Level 5: UntrustedRetrievedContent (Web, HAR, Tool Output)                      |
+---------------------------------------------------------------------------------------------------------+
                                                     |
                                                     v
+---------------------------------------------------------------------------------------------------------+
|                         Ring 7: Capability & Effect Authorization Layer (Cedar)                         |
|  - Downstream OS Effect Gate: PolicyEngine::evaluate(session_id, pid, effect)                           |
|  - Explicit Cedar `forbid` rules: Crown-Jewel taint -> forbid ExternalWrite; forbid PrivilegedControl  |
|  - Revocation-Bound Capability Cache: (principal_id, action, resource_id, policy_ver, taint, rev_seq)   |
|  - Fail-Closed Voter Invariant: ReaVoter/OpenJevVoter are evidence-only; can NEVER override Cedar forbid|
+---------------------------------------------------------------------------------------------------------+
         |                                           |                                           |
         v                                           v                                           v
+-----------------------------+     +-----------------------------+     +-----------------------------+
|    Persistent Causal Graph  |     |  Capability Egress & DLP   |     |  OS-Enforced Confinement    |
| - SQLite: process_instances |     | - EgressEvaluationContext   |     | - Win32 Job Object          |
|   files, events, edges      |     | - Pre-inspection revocation |     | - TokenIsAppContainer       |
| - ProcessInstanceIdentity   |     | - Tier-2 Ollama embeddings  |     | - SECURITY_CAPABILITIES     |
|   (pid, start_time, digest, |     | - 50-250ms egress jitter    |     | - Pre-spawn mitigation      |
|    parent, job, session)    |     | - Per-session request quota |     | - Linux eBPF LSM / Landlock |
| - Monotonic transitive taint|     | - Service-identity loopback |     | - Side-effect oracles       |
| - ZK-PII declassification   |     |   (CDP, Ollama, Docker)     |     |   (0 bytes transmitted)     |
+-----------------------------+     +-----------------------------+     +-----------------------------+
```

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | 5-Level Immutable Authority Hierarchy | Strict non-elevation (L1 System to L5 Untrusted). L4 cannot override L1/L2. Unsigned/tampered workspace files taint at Turn 0. | M2 | R1 |
| 2 | Keyed Merkle Workspace Attestation | Keyed `Ed25519` + `ML-DSA-65` / `HMAC-BLAKE3` authentication over `.cursorrules`, `CLAUDE.md`, `.githooks`, `AGENTS.md`. | M3 | R1, Follow-up |
| 3 | ReaVoter ImageLoaded & Benign Removal | Inspect Sysmon Event 7 `ImageLoaded`. Remove permanent benign process exemption for `cargo`, `python`, `node` on dynamic loads/taint. | M1 | R2, Follow-up |
| 4 | Fix `rea.rs:7169` `chunk_hashes.len()` | Ensure clean compilation of `osoosi-core` by referencing `chunk_hashes.len()`. | M1 | Follow-up |
| 5 | Continuous Downstream OS Effect Gate | Wire `PolicyEngine::evaluate` to downstream OS effects (`ChildProcessExec`, `SensitiveFileAccess`, etc.) correlated via process ancestry. | M2 | R2, R6 |
| 6 | Cryptographic Traceability IDs | Issue `policy_decision_id` + `causal_event_id` + `policy_version` for every authorized effect. | M2 | Follow-up |
| 7 | Revocation-Bound Capability Cache | Keyed by `(principal_id, action, resource_id, policy_version, taint_epoch, revocation_seq)` with instant invalidation. | M2 | Follow-up |
| 8 | Capability-Based Egress Authorization | Evaluate 5-element tuple before payload inspection. Reading Crown-Jewel automatically revokes external write/publish capabilities. | M3 | R3 |
| 9 | Canonical Git Push Exemption | Permit legitimate `git push` to `https://github.com/oyesanyf/OshoosiClaw.git` and workspace `cargo build`/`test` (0% false positives). | M3 | Follow-up, Usability |
| 10 | Tier-2 Local Ollama Embeddings & DLP | Cosine similarity ($\ge 0.82$) against registered Crown-Jewels + 32-byte lexical shingles. | M3 | R3 |
| 11 | Cryptographic Egress Jitter & Quota | 50–250ms stochastic delay + per-session external request quota for tainted sessions. | M3 | R3 |
| 12 | Persistent Causal Security Graph in SQLite | Schema for `causal_process_instances`, `causal_files`, `causal_events`, `causal_edges`, `capability_cache` in `database/osoosi.db`. | M1 | R4 |
| 13 | Non-Detachable `ProcessInstanceIdentity` | `(pid, start_time_100ns, image_digest_blake3, parent_instance_id, job_object_id, origin_session_id)` to prevent context escape. | M1 | Follow-up |
| 14 | Monotonic Transitive Taint Propagation | $\text{taint\_level}_t \ge \text{taint\_level}_{t-1}$ across 20+ filler turns, subprocesses, and intermediate files. | M3 | R4, R5 |
| 15 | Trusted Declassification & Scoped Reset | Verified `<ZK_PII:...>` scrubbing with `ML-DSA-65` PQC proof and scoped task reset rules for usability. | M1 | R4, Usability |
| 16 | Atomic Concurrency Synchronization | Seqlock / `RwLock` taint-transition barrier + pre-commit capability re-validation (race test: read vs write). | M3 | Follow-up |
| 17 | Service-Identity Loopback & IPC Gating | Eliminate blanket loopback trust. Gating for CDP (9222/any port), Ollama (`/api/create`, `/api/pull`, `/api/delete`), Docker socket/pipe. | M3 | R5 |
| 18 | Ring 7 Capability & Effect Layer | Dedicated Ring 7 in `ContainmentRingId` and `PolicyEngine` evaluating Cedar policies. | M2 | R6 |
| 19 | Explicit Cedar `forbid` Precedence | `forbid ExternalWrite when context.hasCrownJewelTaint`, `forbid PrivilegedLocalControl unless context.hasApprovedCapability`. | M2 | Follow-up |
| 20 | Fail-Closed Voter Consensus Invariant | `ReaVoter`/`OpenJevVoter` can never override Cedar `forbid` or turn denial to permit. Offline/compromised voters fail closed. | M2 | R6 |
| 21 | Windows AppContainer + Job Object Verification | Verify `IsProcessInJob == TRUE`, `TokenIsAppContainer == TRUE`, `SECURITY_CAPABILITIES` / SID, restricted tokens before `ResumeThread`. | M4 | R2, Follow-up |
| 22 | Developer-Compatible Pre-Effect Confinement (P0.1) | Enforce pre-effect gates via AppContainer + WFP + application control (no blanket BLOCK_NON_MICROSOFT_BINARIES that breaks dev dll/pyd) and Linux eBPF LSM. | M4 | Follow-up, P0.1 |
| 22a| Service-Identity Key Isolation (P0.2) | Never use `CRYPTPROTECT_LOCAL_MACHINE`; use dedicated service-isolated non-exportable keys so untrusted agents never possess signing authority. | M1 | Follow-up, P0.2 |
| 22b| Protected Policy Chain & Anti-Rollback (P0.4) | Signed provenance, monotonic `policy_version`, anti-rollback verification, and independent approval for Cedar policy/capability updates. | M2 | Follow-up, P0.4 |
| 22c| Confused-Deputy Broker Attribution (P1.2) | Attribute broker-mediated effects (`WmiPrvSE.exe`, `svchost.exe`, `git-remote-https.exe`, `ssh.exe`) to originating agent session. | M1 | Follow-up, P1.2 |
| 22d| Safe Telemetry Overload Handling (P1.3) | Never suspend host when `EventsLost > 0`; quarantine ONLY affected agent workload when confidence lost, preserving host availability. | M4 | Follow-up, P1.3 |
| 22e| Platform Trust & External Recovery (P1.1, P2.2) | Supported platform protections (Secure Boot/HVCI), verifiable health signals, credential revocation, trusted recovery. | M4 | Follow-up, P2.2 |
| 23 | Linux eBPF LSM / Landlock Confinement | eBPF LSM socket and process ancestry gating + Landlock filesystem restriction. | M4 | R2 |
| 24 | Breakout Prevention & Gauntlet Simulation Endpoints | `GET /api/agent-anomalies/breakout-prevention-report` and `POST /api/agent-anomalies/simulate-breakout-gauntlet` exposing 7-row matrix, 9-family residual-risk suite, and live simulation of every breakout vector & EDR flaw. | M5 | R7, Follow-up |
| 25 | 6-Part Adversarial Rust Test Suite | `crates/osoosi-agent-anomaly/tests/seven_ring_breakout_prevention.rs` verifying all 6 breakout scenarios pre-execution. | M6 / Test Track | R7 |
| 26 | Side-Effect Oracles | Prove prohibited actions did not occur (0 bytes transmitted on socket, file unmodified, child process not resumed). | M6 / Test Track | Follow-up |
| 27 | Strix LLM Adversarial Tester Integration | Python harness in `tests/strix_llm_adversarial_tester.py` verifying multi-turn breakout prevention & live daemon health. | M6 / Test Track | R7 |
| 28 | WikiSkill Reusable Skill Persistence | Compile experience into `.agents/skills/agent-breakout-prevention/SKILL.md`. | M6 / Test Track | User Req |
| 29 | Defensible Claim Wording & Docs/Diagrams | README.md architecture diagrams, credit documentation, and exact defensible wording. | M6 | Follow-up, Lifecycle |
| 30 | Full-Lifecycle Packaging & WDSI Submission | Rebuild Windows MSI, Linux packages (.deb/.rpm/.tar.gz), Docker container, WDSI submission, and clean Git tree. | M6 | Lifecycle Invariant |
| 31 | 9-Family Residual-Risk Verification Suite | Covers Workflow composition, Policy integrity, Model manipulation, Platform attestation, Administrator abuse, Supply-chain integrity, Resource exhaustion, Covert-channel assessment, Recovery across 12 residual exploit classes. | M5, M6 | Follow-up |
| 32 | 5-Stage Autonomous Testing Sequence Adapters | Modular adapters (ADR-Bench, RAMPART regression loop, AgentDojo, PyRIT, Host Enforcement Verification) classifying outcomes into `PREVENTED`, `DETECTED_AFTER_EXECUTION`, `ESCAPED_CONTAINMENT`, `INCONCLUSIVE`. | M6 / Test Track | Follow-up |
| 33 | 6 Production Refinements & 4 Central Measurements | 6-field evidence schema, RAMPART regression framework, out-of-band observer fault injection, immutable regression artifacts (`logs/regression_artifacts/` & `adversarial_regression_cases`), benign workflow regression, 4 measurements in WebUI (`#adversarial-tests-view`). | M5, M6 | Follow-up |
| 34 | Learning-Authority Boundary & Corpus Splits | Strict separation of SkyRL learning from Cedar authority; bounded voter weights `[0.50, 2.50]`, tighten-only Cedar proposals with dual authorization; 60/20/20 corpus split (training, validation, protected_holdout) with holdout 100% prevention gate. | M2, M5, M6 | Follow-up |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | Persistent Causal Security Graph & Core Integrity Fixes | SQLite schema in `database/osoosi.db`, `ProcessInstanceIdentity`, transitive graph persistence, trusted ZK-PII declassification, `rea.rs:7169` compile fix, and `ReaVoter` Event 7 `ImageLoaded` support. | none | IN_PROGRESS |
| M2 | 5-Level Authority Hierarchy, Ring 7 Effect Gate & Cedar Policies | `AuthorityLevel` L1–L5, `PolicyEngine::evaluate` downstream OS effect interception, `policy_decision_id` + `causal_event_id`, Revocation-Bound Capability Cache, Cedar `forbid` policies, fail-closed voter consensus. | M1 | PLANNED |
| M3 | Capability-Based Egress, Merkle Attestation, Monotonic Taint & Loopback Gating | Pre-inspection egress revocation, canonical git push exemption, keyed Merkle workspace verification, monotonic taint, Tier-2 local embeddings, jitter/budget, service-identity loopback gating (CDP, Ollama, Docker). | M1, M2 | PLANNED |
| M4 | Operating-System Enforced Confinement Verification | Windows AppContainer + Job Object (`TokenIsAppContainer`, `SECURITY_CAPABILITIES`, `IsProcessInJob == TRUE`), pre-spawn mitigation policies, `ImageLoad` notification capability revocation, Linux eBPF LSM/Landlock. | M2 | PLANNED |
| M5 | REST Prevention Telemetry & Dashboard Integration | `GET /api/agent-anomalies/breakout-prevention-report` exposing the 7-row matrix with 4 measurable outcomes, prevention rate 100%, usability rate 100%, exact defensible wording. | M2, M3, M4 | PLANNED |
| M6 | Final Milestone: Full Verification, E2E Adversarial Proofs, WikiSkill, Packages & Solo Ship | Pass 100% E2E test suite (Tiers 1–4) & Tier 5 Adversarial Hardening (`seven_ring_breakout_prevention.rs`, `strix_llm_adversarial_tester.py`, `verify_port_3030_e2e.py`), compile WikiSkill, build all packages, submit to WDSI, ship solo PR. | M1–M5, Test Track | PLANNED |

## Interface Contracts

### M1 (CausalSecurityGraph) <-> M2 (Ring 7 Cedar PolicyEngine)
- `CausalSecurityGraph::get_process_identity(pid: u32) -> Option<ProcessInstanceIdentity>`
- `CausalSecurityGraph::record_effect(decision_id: &str, event_id: &str, effect: &DownstreamOsEffect) -> Result<()>`
- `CausalSecurityGraph::get_session_taint(session_id: &str) -> (bool, f32, DataClassification)`
- `CausalSecurityGraph::declassify_node(node_id: &str, zk_proof: &ZkBftQuarantineProof) -> Result<()>`

### M2 (PolicyEngine & CapabilityCache) <-> M3 (Egress & AlignmentScanner)
- `PolicyEngine::evaluate_downstream_effect(session_id: &str, pid: u32, effect: DownstreamOsEffect) -> AuthorizationDecision`
- `RevocationBoundCapabilityCache::check_and_acquire(key: &CapabilityCacheKey) -> CacheLookupResult`
- `RevocationBoundCapabilityCache::invalidate_all(reason: &str)`
- `EgressEvaluationContext::evaluate_capability(&self) -> EgressAuthorizationVerdict`

### M2 / M3 <-> M4 (OS Confinement CanaryCage)
- `CanaryCage::spawn_sandboxed_worker(cmd: &Command, profile: &AppContainerProfile) -> Result<SandboxedProcessHandle>`
- `SandboxedProcessHandle::verify_confinement(&self) -> ConfinementVerificationReport` (asserts `IsProcessInJob`, `TokenIsAppContainer`, `SECURITY_CAPABILITIES`)
- `CanaryCage::handle_image_load_notification(pid: u32, image_loaded: &Path) -> Result<()>`

### M5 (REST API) <-> M6 (Adversarial Suite & Verification)
- `GET /api/agent-anomalies/breakout-prevention-report -> BreakoutPreventionReportResponse`:
  - `prevention_rate: 1.0` (100%)
  - `legitimate_usability_pass_rate: 1.0` (100%)
  - `coverage_matrix: [7 rows x 4 outcomes]`
  - `defensible_statement: String`

## Code Layout
- `crates/osoosi-core/src/rea.rs` & `crates/osoosi-core/src/causal_graph.rs`: Causal graph persistence, rusqlite storage, `ReaVoter` fixes.
- `crates/osoosi-policy/src/engine.rs`, `crates/osoosi-policy/src/authority.rs`, `crates/osoosi-policy/src/capability_cache.rs`: Authority hierarchy, Ring 7 Cedar effect gate, capability cache, fail-closed voter consensus.
- `crates/osoosi-agent-anomaly/src/alignment_scanner.rs`, `crates/osoosi-agent-anomaly/src/breakout_defense.rs`, `crates/osoosi-agent-anomaly/src/file_lineage.rs`: Merkle workspace attestation, monotonic taint, loopback gating.
- `crates/osoosi-dp/src/lib.rs`: CrownJewel Tier-2 Ollama embeddings, lexical shingles, egress capability revocation.
- `crates/osoosi-runtime/src/canary_cage.rs` & `crates/osoosi-sandbox/`: AppContainer + Job Object gating, pre-spawn mitigation.
- `crates/osoosi-dashboard/src/routes/` & `crates/osoosi-dashboard/src/lib.rs`: Telemetry and breakout prevention report route.
- `crates/osoosi-agent-anomaly/tests/seven_ring_breakout_prevention.rs`: Rust adversarial prevention suite.
- `tests/strix_llm_adversarial_tester.py`: Python end-to-end multi-turn adversarial test harness.
- `.agents/skills/agent-breakout-prevention/SKILL.md`: Persistent WikiSkill compilation.
- `scripts/build_and_submit.ps1` & `scripts/solo_pr_ship.ps1`: Release compilation, Authenticode signing, WDSI submission, and Git PR shipping.
