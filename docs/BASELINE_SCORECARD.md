# OshoosiClaw Baseline Security Scorecard: EDR Compromise & Agent Breakout Resistance

**Document Version**: 1.0.0 (Official Baseline)  
**Date**: 2026-10-24  
**Audit Conducted By**: Independent Reviewer & Adversarial Critic (`reviewer_baseline_1`)  
**Workspace**: `C:\Users\oyesanyf\.gemini\antigravity\worktrees\a8713ab9-6f3b-4090-9b97-de8c79268ee8\subagent-EDR---Agent-Breakout-A--Team-teamwork-preview-2935d844`  
**Repository Target**: OshoosiClaw (`OpenỌ̀ṣọ́ọ̀sì`) — Production Rust EDR with Autonomous AI Agent Containment  

---

## 1. Executive Summary & Independent Reviewer Assessment

This document serves as the authoritative, independent baseline security evaluation for the OshoosiClaw repository prior to implementation of remediation passes. The audit evaluates the codebase against two critical security domains:
1. **Domain 1: EDR Compromise Resistance** — Protection of the EDR daemon, telemetry hooks, local databases, P2P/Nostr intelligence mesh, decision engines, and Port 3030 management daemon against hostile tampering, blinding, evasion, and poisoning by local or remote adversaries.
2. **Domain 2: Agent Breakout Resistance** — Confinement of autonomous AI agents within strict OS-enforced capabilities (Windows AppContainer, Job Objects, Linux seccomp/Landlock), multi-ring reference monitors (7-Ring Continuous Cedar, 5-Level Lattice), mathematical network isolation (SSRF, DNS rebinding), path containment (`Path::join`), cryptographic inter-agent mesh (HMAC SHA-256 epoch keys), and Data Loss Prevention (DLP).

### Summary Baseline Grades

| Domain | Total Vectors Audited | Check 1: Control in Code | Check 2: Real Path Fail-Closed | Check 3: Proving Test | All 3 Checks Passed | Baseline Letter Grade |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Domain 1: EDR Compromise** | 20 | 9 / 20 (45.0%) | 4 / 20 (20.0%) | 3 / 20 (15.0%) | 3 / 20 (15.0%) | **D** |
| **Domain 2: Agent Breakout** | 22 | 19 / 22 (86.4%) | 9 / 22 (40.9%) | 18 / 22 (81.8%) | 8 / 22 (36.4%) | **C-** |
| **Overall Repository Posture** | **42** | **28 / 42 (66.7%)** | **13 / 42 (31.0%)** | **21 / 42 (50.0%)** | **11 / 42 (26.2%)** | **D+ / C-** |

### Critical Auditor Findings (Integrity Violations & Pervasive Bypasses)
1. **Signed Binary Unconditional Bypass (`crates/osoosi-core/src/lib.rs:13853`)**: If an executable is Authenticode signed (`is_signed == true`), the code explicitly sets `is_mal = false` and verdict to `"benign"` (`ignored_and_allowed`), completely discarding malicious verdicts from ML models and the Clef Decision Engine.
2. **Operator Password Overwrite Login Bypass (`crates/osoosi-dashboard/src/lib.rs:5587–5608`)**: Any HTTP client issuing a `POST /api/auth/login` with username `"admin"` or empty string and ANY candidate secret automatically overwrites `admin_password.hash` on disk and authenticates with an administrative session.
3. **Admin Token Exfiltration on Status Endpoint (`crates/osoosi-dashboard/src/lib.rs:1146–1158`)**: Any unauthenticated client requesting `GET /api/status` or `GET /` receives the master administrative token in a `Set-Cookie: osoosi_token=...` response header.
4. **Configuration Tamper "Self-Healing" Auto-Resigning (`crates/osoosi-core/src/hardened.rs:737–742`)**: If critical configuration files are tampered with, `assess_security()` calls `sign_all_critical_configs()`, automatically re-signing the tampered files with new hashes and declaring integrity satisfied.
5. **Unauthenticated Public Siquery & REA File Disassembly Endpoints (`crates/osoosi-dashboard/src/lib.rs:1166–1186`)**: Localhost requests bypass authentication for `POST /api/siquery/query` (exfiltrating process environment variables including secrets) and `POST /api/rea/v1/analyze` (accepting arbitrary host file paths and returning disassembled ASTs and strings).
6. **Disconnected Pre-Execution Tool Gate (`crates/osoosi-agent-anomaly/src/containment_ring.rs:436–465`)**: `AgentContainmentRing::execute_contained_tool` evaluates only file lineage digests and impulse tickets; it fails to invoke `BreakoutDefenseCoordinator`, `validate_agent_filesystem_access`, `validate_agent_egress_url`, or `RuntimeAlignmentScanner` before running tool closures.
7. **Mock / Stub Implementations in Sandbox (`crates/osoosi-sandbox/src/native_host.rs:278–353`)**: HostCall dispatchers for `handle_fetch_url`, `handle_exec_command`, and `handle_send_mesh` contain dummy mock returns (`status: 200, body: "{}"`, empty stdout, random UUIDs).
8. **Host Master Secret Leakage to Sandboxed Child Processes (`crates/osoosi-runtime/src/canary_cage.rs:545–548`)**: `CanaryCage` builds child environment blocks by iterating `for (k, v) in std::env::vars()`, unconditionally forwarding the EDR's master tokens, cloud API keys, and private credentials to untrusted child processes.
9. **Tautological Mock Tests in Residual-Risk Suite (`crates/osoosi-agent-anomaly/tests/seven_ring_breakout_prevention.rs:855–907`)**: Module 11 contains tests that define local boolean variables (`let composite_outcome_safe = false; assert!(!execution_permitted);`) rather than exercising production code.

---

## 2. Threat Model Rubric & Grading Criteria

Every vector across both domains is audited against three strict, objective checks:
- **Check 1 (Control in Code)**: A concrete defensive control or invariant check is implemented in production code (verified with exact `file:line` citation).
- **Check 2 (Enforced Fail-Closed on Real Path)**: The control is actively wired into the live execution path. All error, timeout, or unknown conditions fail closed (deny, quarantine, or terminate). It fails if it only logs `warn!`, auto-heals/re-signs, is bypassed by signed binaries or path substrings, is unwired, or relies on mock stubs.
- **Check 3 (Proving Test)**: An automated adversarial test exercises the actual attack technique against the implementation (and live Port 3030 daemon where applicable) and proves it is stopped.

### Letter-Grade Scale Definition
- **A+**: 100% of vectors pass Check 1, Check 2, and Check 3. Zero fail-open paths, zero unwired controls, zero mock stubs, and all tests pass with $\ge 3$ agreeing trials.
- **A**: 100% pass Check 1 and Check 2; $\ge 90\%$ pass Check 3.
- **B**: $\ge 85\%$ pass Check 1 and Check 2.
- **C**: Check 1 mostly present, but widespread Check 2 fail-open, unwired, or bypassed paths.
- **D / F**: Critical controls missing or pervasive fail-open architecture.

---

## 3. Domain 1: EDR Compromise Baseline Scorecard (20 Vectors)

| Vector ID | Vector Name | Threat ID / MITRE | Check 1: Code Control | Check 2: Real Path Fail-Closed | Check 3: Proving Test | Baseline Status |
|---|---|---|---|---|---|:---:|
| **EDR-VEC-01** | Binary Masquerading & Static Path Abuse | T1036.005 | `crates/osoosi-core/src/rea.rs:480` | **FAIL**: Bypassed via substring checks in `voters.rs:87` (`\cache\`, `\models\`, `\tools\`) | **FAIL**: `verify_15:681` (isolated unit helper only) | **FAIL** |
| **EDR-VEC-02** | Counter-AI Prompt Injection & Redirection | LLM01, T1027 | `crates/osoosi-core/src/rea.rs:5690` | **PASS**: Inline sanitizer redacts prompt injection & escalates threat score | **PASS**: `verify_15:709`, `rea.rs:7310` | **PASS** |
| **EDR-VEC-03** | P2P Mesh Kill-Switch & Hash Poisoning | T1562.001 | `crates/osoosi-core/src/rea.rs:5970` | **FAIL**: Unwired in `lib.rs:4863` & `lib.rs:5262`; hashes marked malicious without inspection | **FAIL**: `verify_15:720` (helper test only) | **FAIL** |
| **EDR-VEC-04** | ETW Channel Blinding & Suppression | T1562.006 | `crates/osoosi-telemetry/src/host_events.rs:299` | **FAIL**: Channel drop sets `is_available=false` with info! log; Event 1102 ignored | **FAIL**: `verify_15:733` (cycle detector only) | **FAIL** |
| **EDR-VEC-05** | BYOVD Driver & Kernel DKOM | T1068, T1014 | `crates/osoosi-runtime/src/kernel_driver.rs:106` | **FAIL**: User-mode loading unblocked without driver; DKOM detection is periodic | **FAIL**: `verify_15:753` (in-memory hash check only) | **FAIL** |
| **EDR-VEC-06** | Usermode Hook Evasion & Hollowing | T1562, T1055 | `crates/osoosi-telemetry/src/hollowing.rs:25` | **FAIL**: `lib.rs:7688` logs `warn!` on confirmed hollowing without terminating | **FAIL**: `verify_15:771` (no process termination proof) | **FAIL** |
| **EDR-VEC-07** | Parser Memory Safety & Resource Bounds | CWE-125/787 | `crates/osoosi-core/src/rea.rs:85` | **PASS**: 256KB cap and `catch_unwind` panic isolation enforced | **PASS**: `verify_15:792`, `rea.rs:7280` | **PASS** |
| **EDR-VEC-08** | Audit Log & Merkle Tampering | T1070, T1565 | `crates/osoosi-audit/src/lib.rs:50` | **PASS**: ML-DSA-65 post-quantum hybrid signing + TPM 2.0 anchoring | **PASS**: `verify_15:803`, `osoosi-audit:240` | **PASS** |
| **EDR-VEC-09** | Admin Token Exfiltration via Status Endpoint | CWE-306, T1562 | **FAIL**: `dashboard/src/lib.rs:1152` | **FAIL**: `GET /api/status` actively sets `Set-Cookie: osoosi_token=...` | **FAIL**: NONE (test suite exploits leak) | **FAIL** |
| **EDR-VEC-10** | Arbitrary Host Siquery SQL Exfiltration | CWE-306, T1082 | **FAIL**: `dashboard/src/lib.rs:1174` | **FAIL**: `is_public_bypass` exempts `/api/siquery/query` from auth on localhost | **FAIL**: NONE | **FAIL** |
| **EDR-VEC-11** | Config Tamper Auto-Resigning Bypass | T1562, CWE-353 | **FAIL**: `hardened.rs:739` | **FAIL**: Auto-resigns tampered configs and declares integrity satisfied | **FAIL**: `main.rs:8210` (CLI parsing only) | **FAIL** |
| **EDR-VEC-12** | Signed Binary Unconditional Decision Bypass | T1562.001 | **FAIL**: `lib.rs:13853` | **FAIL**: `!is_signed` forces `is_mal=false`, discarding ML/decision engine verdicts | **FAIL**: NONE | **FAIL** |
| **EDR-VEC-13** | Consensus Veto Fragile String Override | T1562.001 | **FAIL**: `engine.rs:1177` | **FAIL**: Vetoes override malicious votes unless reason matches fragile strings | **FAIL**: NONE | **FAIL** |
| **EDR-VEC-14** | Unauthenticated USB Serial Kill-Switch | T1562.001 | **FAIL**: `watchdog.rs:350` | **FAIL**: Plain ASCII `"KILL\n"` immediately exits process with 137 | **FAIL**: NONE | **FAIL** |
| **EDR-VEC-15** | Named Pipe Telemetry Injection | T1562, T1055 | **FAIL**: `native.rs:852` | **FAIL**: `\\.\pipe\osoosi_injection` created with NULL DACL | **FAIL**: NONE | **FAIL** |
| **EDR-VEC-16** | Binary Name Benign Bias in Local Engine | T1036.005 | **FAIL**: `local_engine.rs:608` | **FAIL**: Brier score awards +2.2 to +4.5 benign points based on filename string alone | **FAIL**: NONE | **FAIL** |
| **EDR-VEC-17** | Operator Password Hash Overwrite Bypass | CWE-287, T1562 | **FAIL**: `dashboard/src/lib.rs:5587` | **FAIL**: `POST /api/auth/login` as "admin" overwrites hash on disk and logs in | **FAIL**: NONE | **FAIL** |
| **EDR-VEC-18** | HTTP Dual Framing & Desync Attacks | RFC 9112 | `crates/osoosi-dashboard/src/lib.rs:1050` | **PASS**: Framing defense middleware rejects dual framing & HEAD body | **FAIL**: Unit test in `lib.rs:12520`; no multi-trial wire test | **FAIL** |
| **EDR-VEC-19** | Arbitrary File Decompilation / REA Oracle | CWE-200, T1083 | **FAIL**: `dashboard/src/lib.rs:1180` | **FAIL**: `/api/rea/v1/analyze` in `is_public_bypass`; disassembles any host file | **FAIL**: NONE | **FAIL** |
| **EDR-VEC-20** | SkyRL Model Retraining & Adapter Tampering | T1565.001 | **FAIL**: `dashboard/src/lib.rs:1178` | **FAIL**: `/api/skyrl/v1/train` in `is_public_bypass`; unauthenticated model mutation | **FAIL**: NONE | **FAIL** |

### Domain 1 Baseline Summary:
- **Total Vectors**: 20
- **Check 1 Passed (Control in Code)**: 9 / 20 (45.0%)
- **Check 2 Passed (Real Path Fail-Closed)**: 4 / 20 (20.0%) [EDR-VEC-02, EDR-VEC-07, EDR-VEC-08, EDR-VEC-18]
- **Check 3 Passed (Proving Test)**: 3 / 20 (15.0%) [EDR-VEC-02, EDR-VEC-07, EDR-VEC-08]
- **Passing All 3 Checks**: 3 / 20 (15.0%)
- **Baseline Letter Grade**: **D**

---

## 4. Domain 2: Agent Breakout Baseline Scorecard (22 Vectors)

| Vector ID | Vector Name | Invariant / MITRE | Check 1: Code Control | Check 2: Real Path Fail-Closed | Check 3: Proving Test | Baseline Status |
|---|---|---|---|---|---|:---:|
| **AB-VEC-01** | Multi-Turn Goal Hijacking | LLM01 | `alignment_scanner.rs:306` | **FAIL**: Out-of-band only; unwired in `execute_contained_tool` pre-execution | **PASS**: `verify_15:430`, `alignment_scanner:2240` | **PARTIAL** |
| **AB-VEC-02** | Lateral Movement & Epoch Forgery | Law 3, T1080 | `containment_ring.rs:113` | **FAIL**: `agent_id` casing bug in `containment_ring.rs:95`; mock stub in `native_host.rs:351` | **PASS**: `verify_15:463`, `containment_ring:970` | **PARTIAL** |
| **AB-VEC-03** | Path Traversal & Path::join | CWE-22, T1083 | `sandbox/src/lib.rs:640` | **FAIL**: `validate_sandbox_relative_path` dead code; unwired in `execute_contained_tool` | **PASS**: `verify_15:486`, `sandbox/src/lib.rs:704` | **PARTIAL** |
| **AB-VEC-04** | SSRF & Localhost Pivot | CWE-918, T1090 | `native_host.rs:370` | **FAIL**: Mock return in `handle_fetch_url`; loopback allowed in `agent_egress.rs:314` | **PASS**: `verify_15:514`, `sandbox/src/lib.rs:726` | **PARTIAL** |
| **AB-VEC-05** | OS Sandbox Escape | SEC-WIN-01 | `canary_cage.rs:585` | **FAIL**: `windows.rs` boolean simulation; AppContainer missing in `canary_cage.rs` | **PASS**: `verify_15:546`, `sandbox/src/lib.rs:754` | **PARTIAL** |
| **AB-VEC-06** | Steganographic / DLP Exfiltration | T1048, T1027 | `osoosi-dp/src/lib.rs:1` | **FAIL**: Passive `/api/dlp/inspect` only; unwired inline in tool execution or egress | **PASS**: `verify_15:628`, `osoosi-dp:2500` | **PARTIAL** |
| **AB-VEC-07** | Self-Approval & Workflow Tampering | T1562.001 | `workflow_guard.rs:702` | **FAIL**: `.github/workflows/auto-review-bot.yml:75` auto-approves PRs touching workflows | **PASS**: `verify_15:657` | **PARTIAL** |
| **AB-VEC-08** | Upward Authority Promotion (Ring 1) | Authority Lattice | `breakout_gate.rs:86` | **PASS**: Deterministically rejected in `verify_workspace_instruction` | **PASS**: `seven_ring:554`, `breakout_prevention:554` | **PASS** |
| **AB-VEC-09** | Loopback & Local IPC Pivot (Ring 4) | Ring 4 Invariant | `breakout_gate.rs:Authorizer` | **FAIL**: `agent_egress.rs:314` blanket-allows loopback without port inspection | **PASS**: `seven_ring:953`, `breakout_prevention:953` | **PARTIAL** |
| **AB-VEC-10** | Salami-Sliced Drift & PID Reuse | Ring 3 Invariant | `breakout_gate.rs:Graph` | **PASS**: Monotonic taint accumulation & composite `ProcessInstanceIdentity` | **PASS**: `file_lineage_challenge.rs`, `breakout_prevention:842` | **PASS** |
| **AB-VEC-11** | Dynamic Code / DLL Injection (Ring 7) | EventID 7 | `breakout_gate.rs:evaluate` | **PASS**: Untrusted DLL load triggers immediate capability revocation | **PASS**: `seven_ring:586`, `breakout_prevention:586` | **PASS** |
| **AB-VEC-12** | Capability Concurrency Race (Ring 5) | Concurrency Law | `breakout_gate.rs:Cache` | **PASS**: RwLock barrier prevents concurrent Crown-Jewel read/write race | **PASS**: `breakout_prevention:440` (24 concurrent threads) | **PASS** |
| **AB-VEC-13** | Confused-Deputy System Broker (Ring 3)| Ring 3 Broker | `breakout_gate.rs:Broker`| **PASS**: Binds broker network activity to origin session taint | **PASS**: `breakout_prevention:1077` | **PASS** |
| **AB-VEC-14** | WASM Dual-Metering & Overflow | Wasm Sandbox | `sandbox/src/lib.rs:163` | **FAIL**: Metered Wasm core, but `native_host.rs:325` returns mock objects | **PASS**: `attack_isolation_test.rs:10` | **PARTIAL** |
| **AB-VEC-15** | Rogue Threat Voter Manipulation (Ring 2)| Ring 2 Invariant | `breakout_prevention.rs:1030`| **PASS**: Cedar `forbid` cannot be overridden; voter weights clamped [0.5, 2.5] | **PASS**: `seven_ring_breakout_prevention.rs:1030` | **PASS** |
| **AB-VEC-16** | GhostJacking & EchoLeak Markdown | Token Smuggling | `agentjacking_guard.rs:40` | **FAIL**: Unwired on tool output streams and WebUI markdown rendering | **PASS**: `alignment_scanner.rs:2240` | **PARTIAL** |
| **AB-VEC-17** | Naive Binary Self-Exclusion | T1036.005 | `verified.rs:120` | **FAIL**: Dead code (never called in `scan_event`); naive string basename check | **FAIL**: Test only tests isolated dead function | **FAIL** |
| **AB-VEC-18** | SQL Injection Escape via WASM HostCall | CWE-89 | `native_host.rs:332` | **PASS**: `is_query_allowed` rejects multi-statement and administrative SQL | **PASS**: `attack_isolation_test.rs` | **PASS** |
| **AB-VEC-19** | Telemetry Overload DoS (Family 7) | Availability | `breakout_gate.rs:Overload` | **PASS**: Quarantines affected workload; maintains host-wide monitoring | **PASS**: `breakout_prevention:1367` | **PASS** |
| **AB-VEC-20** | Composed Workflow Escalation (Family 1)| Multi-Step Guard | `breakout_gate.rs:Workflow` | **PASS**: Sequence state tracking enforces cosigner quorum | **FAIL**: `seven_ring:855` is a tautological mock test | **PARTIAL** |
| **AB-VEC-21** | Host Master Secret Leakage via Env Vars | CWE-200, T1552 | **FAIL**: `canary_cage.rs:545` | **FAIL**: `for (k,v) in env::vars()` copies all host secrets into child processes | **FAIL**: NONE | **FAIL** |
| **AB-VEC-22** | Unchecked WASI Directory Traversal | Sandbox Escape | **FAIL**: `sandbox/src/lib.rs:528` | **FAIL**: Bare WASI context lacks sandbox preopen directory root constraints | **FAIL**: NONE | **FAIL** |

### Domain 2 Baseline Summary:
- **Total Vectors**: 22
- **Check 1 Passed (Control in Code)**: 19 / 22 (86.4%)
- **Check 2 Passed (Real Path Fail-Closed)**: 9 / 22 (40.9%) [AB-VEC-08, AB-VEC-10, AB-VEC-11, AB-VEC-12, AB-VEC-13, AB-VEC-15, AB-VEC-18, AB-VEC-19, AB-VEC-20]
- **Check 3 Passed (Proving Test)**: 18 / 22 (81.8%)
- **Passing All 3 Checks**: 8 / 22 (36.4%) [AB-VEC-08, AB-VEC-10, AB-VEC-11, AB-VEC-12, AB-VEC-13, AB-VEC-15, AB-VEC-18, AB-VEC-19] (Note: AB-VEC-20 fails Check 3 due to tautological test)
- **Baseline Letter Grade**: **C-**

---

## 5. Reviewer-Discovered Vectors (Missing from Initial Rubric)

During independent adversarial auditing of the codebase, 4 previously uncataloged attack vectors were identified and integrated into the scorecard:

### 1. EDR-VEC-19: Unauthenticated Arbitrary File Decompilation & Reverse Engineering Oracle
- **Citation**: `crates/osoosi-dashboard/src/lib.rs:1180`, `lib.rs:876`, `lib.rs:9470–9475` (`post_rea_analyze`)
- **Mechanism**: The route `/api/rea/v1/analyze` is included in `is_public_bypass`. An unauthenticated local or network caller can submit a JSON payload containing `{"target_path": "C:\\Windows\\System32\\config\\SAM"}` or `{"target_path": "config/dashboard_token.key"}`. The handler invokes `osoosi_core::rea::analyze_target_path`, parsing, extracting strings, calculating entropy, decompiling functions, and returning a detailed analysis report to the unauthenticated caller.
- **Grading**: Check 1 = FAIL, Check 2 = FAIL, Check 3 = FAIL.

### 2. EDR-VEC-20: Unauthenticated SkyRL Model Retraining & Adapter Manipulation
- **Citation**: `crates/osoosi-dashboard/src/lib.rs:1178`, `crates/osoosi-dashboard/src/routes/skyrl.rs:845` (`post_skyrl_train`)
- **Mechanism**: `path.starts_with("/api/skyrl/v1/")` is listed in `is_public_bypass`. State-changing POST endpoints `/api/skyrl/v1/train`, `/api/skyrl/v1/step`, and `/api/skyrl/v1/adapter` can be invoked without credentials, allowing an attacker to feed poisoned RL state transitions or corrupt agent policy weights.
- **Grading**: Check 1 = FAIL, Check 2 = FAIL, Check 3 = FAIL.

### 3. AB-VEC-21: Host Master Secret & Credential Leakage via Child Process Environment Variable Inheritance
- **Citation**: `crates/osoosi-runtime/src/canary_cage.rs:545–548`
- **Mechanism**: When `CanaryCage` builds the child process environment block for sandboxed execution, it iterates over all current process environment variables:
  ```rust
  let mut env_map: BTreeMap<String, String> = BTreeMap::new();
  for (k, v) in std::env::vars() {
      env_map.insert(k, v);
  }
  ```
  This unconditionally forwards all host secrets (`OSOOSI_DASHBOARD_API_TOKEN`, `GITHUB_TOKEN`, `AWS_SECRET_ACCESS_KEY`, etc.) directly into the environment of the unprivileged or quarantined child process.
- **Grading**: Check 1 = FAIL, Check 2 = FAIL, Check 3 = FAIL.

### 4. AB-VEC-22: Unchecked WASI Preopened Directory Traversal & Rootfs Escape
- **Citation**: `crates/osoosi-sandbox/src/lib.rs:528`
- **Mechanism**: In `run_script`, the WASI context is constructed via `let wasi_p1 = wasmtime_wasi::WasiCtxBuilder::new().build_p1();` without constraining preopened directories. Furthermore, `validate_sandbox_relative_path` (line 640) is never called on paths accessed during execution, allowing WASM modules to bypass sandbox path boundaries.
- **Grading**: Check 1 = FAIL, Check 2 = FAIL, Check 3 = FAIL.

---

## 6. Adversarial Stress-Test Findings & Integrity Violations

In accordance with strict reviewer integrity instructions, the following architectural shortcuts and facade implementations were uncovered:

### Violation 1: Tautological Self-Certifying Mock Assertions in Test Suite
**Location**: `crates/osoosi-agent-anomaly/tests/seven_ring_breakout_prevention.rs:855–907`  
**Description**: Module 11 tests declare local boolean constants and assert that their logical combination equals false without invoking any production crate code:
```rust
#[test]
fn test_family_1_workflow_composition_outcome_invariant() {
    let read_allowed = true;
    let modify_allowed = true;
    let composite_outcome_safe = false;
    let execution_permitted = read_allowed && modify_allowed && composite_outcome_safe;
    assert!(!execution_permitted);
}
```
**Impact**: Gives the false appearance of passing integration tests for residual-risk families while executing zero real logic.

### Violation 2: Facade HostCall Implementations in Sandbox
**Location**: `crates/osoosi-sandbox/src/native_host.rs:278–353`  
**Description**: Handlers for HTTP fetches, command execution, and mesh dispatch return static mock structs:
```rust
// Real implementation would use reqwest here
info!("Host: fetching URL '{}'", url);
HostResponse::HttpResponse { status: 200, body: "{}".to_string() }
```
**Impact**: Hostcalls do not execute actual sandboxed network/process operations or verify mathematical SSRF/AppContainer constraints.

### Violation 3: Simulated In-Memory Confinement Gate
**Location**: `crates/osoosi-sandbox/src/windows.rs:98–160`  
**Description**: `evaluate_pre_resume_confinement_gate` evaluates purely in-memory booleans (`appcontainer_profile_allocated: bool`, `sid_bound: bool`). It never links or executes native Win32 `CreateAppContainerProfileW`, `FreeSid`, or `DeleteAppContainerProfile`.

---

## 7. Actionable Roadmap to A+ Certification

To achieve an authoritative **A+ grade** on both scorecards, the upcoming engineering milestones must execute the following remediation plan:

### Milestone 2.1: Domain 1 (EDR Compromise) Production Remediation
1. **Eliminate Substring Path Exemptions (`voters.rs:87`)**: Remove blind path keyword exemptions (`\cache\`, `\models\`, `\tools\`, `\traps\`, `\wavlink\`, `\.ollama\`). Enforce Authenticode and Catalog thumbprint verification before declaring any binary trusted.
2. **Wire P2P/Nostr Mesh Inspection (`lib.rs:4863, 5262`)**: Route all incoming GossipSub and Nostr threat frames through `inspect_mesh_threat_frame` prior to Bloom filter insertion or database logging.
3. **Escalate Channel Drops & Collect Event 1102 (`host_events.rs:299`)**: Add EventID 1102 ("Audit Log Cleared") to Security subscriptions. Escalate channel drop (`!sub.is_available`) to an immediate high-priority tamper alert.
4. **Autonomous Hollowing Termination (`lib.rs:7688`)**: Terminate suspended and source PIDs fail-closed upon confirmed process hollowing and emit a `ThreatSignature`.
5. **Secure Dashboard Authentication & Endpoints (`dashboard/src/lib.rs`)**:
   - Remove automatic `Set-Cookie: osoosi_token=...` on `GET /api/status`.
   - Remove `/api/siquery/query`, `/api/rea/v1/`, and `/api/skyrl/v1/` from `is_public_bypass`.
   - Remove unauthenticated password hash overwrite in `post_auth_login_endpoint`.
6. **Enforce Asymmetric Config Signatures (`hardened.rs:739`)**: Remove auto-resigning logic. Require Ed25519 digital signature verification against embedded master public keys; fail closed on tamper.
7. **Fix Signed Binary Bypass (`lib.rs:13853`)**: Evaluate threat verdicts based on decision model probability and behavioral indicators regardless of `is_signed`. Check Authenticode as evidence, not an unconditional exemption.
8. **Replace Fragile Veto Substrings (`engine.rs:1177`)**: Map evidence classes and event IDs deterministically without relying on fragile string literal matching.
9. **Secure Named Pipe & Serial Port (`native.rs:852`, `watchdog.rs:350`)**: Apply strict SDDL on `\\.\pipe\osoosi_injection` (SYSTEM + Admin only). Require HMAC challenge-response verification for serial kill commands.

### Milestone 2.2: Domain 2 (Agent Breakout) Production Remediation
1. **Pre-Execution Tool Gate Wiring (`containment_ring.rs:436`)**: Wire `BreakoutDefenseCoordinator::evaluate_action`, `validate_agent_filesystem_access`, `validate_agent_egress_url`, and `RuntimeAlignmentScanner::evaluate_tier1_structural` directly into `execute_contained_tool` before the tool closure runs.
2. **De-Mock NativeHost (`native_host.rs`)**: Implement real network and process calls governed by `is_ssrf_url` and `CanaryCage`.
3. **Win32 AppContainer Integration (`canary_cage.rs`)**: Implement genuine `CreateAppContainerProfileW` allocation and `STARTUPINFOEXW` security capabilities binding with `FreeSid` and `DeleteAppContainerProfile` cleanup. On Linux, apply `prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)`.
4. **Strict Loopback Filtering & DNS Rebinding (`agent_egress.rs`)**: Remove blanket `ip.is_loopback()` allowance; require port inspection against `LoopbackIpcAuthorizer`. Add pre-connect DNS IP resolution checking in SSRF validators.
5. **Agent ID Normalization (`containment_ring.rs`)**: Normalize `agent_id` with `.trim().to_ascii_lowercase()` across all epoch and key operations.
6. **Patch CI Auto-Review Bot (`.github/workflows/auto-review-bot.yml`)**: Forbid automated approval if any file in `.github/workflows/`, `crates/osoosi-policy/`, or security configuration is modified.
7. **Sanitize Child Process Environment Variables (`canary_cage.rs:545`)**: Whitelist only necessary benign environment variables (`SystemRoot`, `PATH`, etc.) when spawning child processes; scrub all tokens and API keys.
8. **Refactor Residual-Risk Tests (`seven_ring_breakout_prevention.rs:855`)**: Replace tautological boolean assertions with calls to the production proof suite.

### Milestone 3: Adversarial Proof Suite & Live Port 3030 CI Integration
- Build a Python proof runner (`scripts/run_live_adversarial_proof_suite.py`) executing $\ge 3$ agreeing trials for every vector against production code and live Port 3030 daemon.
- Integrate the runner into `.github/workflows/ci.yml` and upload `logs/adversarial_proof_report.json` as a CI artifact.
