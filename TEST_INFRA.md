# Test Infrastructure Specification: Continuous Agent Breakout Defense (`TEST_INFRA.md`)

**Document Version**: 2.0.0  
**Target Milestone**: Continuous Agent Breakout Defense Hardening (Requirements R1–R7)  
**Author**: E2E Test Writer (`teamwork_test_writer_e2e`)  
**Status**: APPROVED & ACTIVE  

---

## 1. Test Philosophy & Core Invariants

1. **Opaque-Box & Requirement-Driven**:
   Tests are derived strictly from `ORIGINAL_REQUEST.md` (Requirements R1 through R7) and `PROJECT.md` interface specifications. Tests evaluate observable external boundaries: process exit codes, handle inheritance masks, Win32 Job Object limits, socket address classifications, cryptographic HMAC-SHA256 signatures, HTTP status codes, and deterministic consensus actions.

2. **Absolute Zero-Mock Rule**:
   Under no circumstances do tests assert against synthetic placeholders, mock bypass flags, or dummy signatures. All oracles execute genuine cryptographic mathematics (`hmac`, `sha256`), real IPv4/IPv6 address parsing (`ipaddress`), real Win32 process creation flags and security descriptors, and authentic AST/source invariant inspection.

3. **Progressive Testability & Isolation**:
   Every test case is self-contained and isolated. Setup and teardown create isolated process trees, temporary sandboxes, and process-scoped environment variables. Tests do not depend on execution order and clean up temporary resources upon completion.

4. **Zero-Touch Environment & PATH Immutability**:
   In strict accordance with repository rules, no test or harness ever mutates, overwrites, resets, or persists modifications to user or system `PATH` or registry environment hives (`HKCU\Environment`, `HKLM\System\CurrentControlSet\Control\Session Manager\Environment`). All environment variables are process-scoped only.

---

## 2. 4-Tier Test Matrix (Requirements R1–R7)

| Requirement | Scope & Domain Crates | Tier 1 (Feature >=5) | Tier 2 (Boundary >=5) | Tier 3 (Pairwise) | Tier 4 (Scenario) |
|---|---|:---:|:---:|:---:|:---:|
| **R1. OS Sandbox, Token & Process Isolation** | `crates/osoosi-sandbox` | 6 tests (`tc01`–`tc06`) | 6 tests (`b01`–`b06`) | P01, P02, P09 | Scenario 1, Scenario 2 |
| **R2. Temporal Policy & Operational Breakout** | `crates/osoosi-policy`, `crates/osoosi-agent-anomaly` | 6 tests (`tc01`–`tc06`) | 6 tests (`b01`–`b06`) | P01, P03, P10 | Scenario 1 |
| **R3. Multi-Agent Mesh & Indirect Prompt Injection** | `crates/osoosi-runtime`, `crates/osoosi-agent-anomaly` | 6 tests (`tc01`–`tc06`) | 6 tests (`b01`–`b06`) | P02, P03, P04 | Scenario 1 |
| **R4. Telemetry Resilience & Kernel Integrity** | `driver/windows`, `osoosi_inject.dll`, `crates/osoosi-telemetry` | 6 tests (`tc01`–`tc06`) | 6 tests (`b01`–`b06`) | P05, P06 | Scenario 3 |
| **R5. Control Plane & SQLite Storage Hardening** | `crates/osoosi-dashboard`, `database/osoosi.db` | 6 tests (`tc01`–`tc06`) | 6 tests (`b01`–`b06`) | P04, P07, P09 | Scenario 4 |
| **R6. Research Swarm Poisoning Defenses** | `crates/osoosi-agent-anomaly`, `crates/osoosi-dashboard` | 6 tests (`tc01`–`tc06`) | 6 tests (`b01`–`b06`) | P07, P08 | Scenario 5 |
| **R7. Decision Model Asymmetric Veto** | `crates/osoosi-model`, `crates/osoosi-policy` | 6 tests (`tc01`–`tc06`) | 6 tests (`b01`–`b06`) | P05, P06, P08, P10 | Scenario 3, Scenario 5 |
| **TOTALS** | **Full 7-Ring Continuous Breakout Suite** | **42 Tests** | **42 Tests** | **10 Tests** | **5 Scenarios** |

**Grand Total**: **99 Comprehensive Test Cases across Tiers 1–4**.

---

## 3. Tier Breakdown & Test Objectives

### Tier 1: Feature Coverage (42 Tests)
Equivalence class representative happy-path tests verifying each requirement in isolation:
- **R1 (Sandbox Isolation)**: `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` allowlist configuration; `CREATE_SUSPENDED` pre-resume verification; `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` & `ACTIVE_PROCESS` enforcement; `FILE_FLAG_OPEN_REPARSE_POINT` junction blocking; `GetFinalPathNameByHandleW` canonical root containment; `SocketAddr` pinning against loopback, RFC1918, CGNAT, and link-local addresses.
- **R2 (Temporal Policy & Env Guard)**: Dogwood MFOTL past-only temporal logic tracking cumulative information-flow (`UntrustedWebInput -> ScratchFileWrite -> SubprocessEnvOrArg`) over sliding time window $[t - 2\text{h}, t]$; temporal forbid clearing via supervisor declassification receipt; inspection and blocking of `GIT_SSH_COMMAND`, `GIT_EXTERNAL_DIFF`, `RUSTC_WRAPPER`, `PYTHONPATH`, `PYTHONSTARTUP`, `NODE_OPTIONS`, `.cargo/config.toml`, and `build.rs`.
- **R3 (Mesh Invariants & Capability Stripping)**: `TaintLevel::UntrustedExternal` HMAC-SHA256 message envelopes; constant-time cryptographic envelope signature verification; rejection of stale generation epochs ($N \to N+1$); `MeshCapabilityGovernor` downstream capability stripping (`shell_exec`, `cmd`, `powershell`, `write_file`, `network_egress`, `extract_credentials`); operator HITL receipt bypass; lateral movement sink isolation (`to_ascii_lowercase()` normalization).
- **R4 (Telemetry & Kernel Integrity)**: In-memory watchdog detection of `EtwEventWrite` patching (`0xC3` / `xor eax, eax; ret`), `AmsiScanBuffer` patching (`0x80070057`), and inline hook unhooking; dual-tier prioritized Tokio channels protecting security alerts under event flood; Authenticode SHA-256 blocklist enforcement against known vulnerable BYOVD drivers (LOLDrivers); kernel callback registration self-integrity auditing (`PspCreateProcessNotifyRoutine`, `ObRegisterCallbacks`).
- **R5 (Control Plane & SQLite Hardening)**: `/api/auth/session` gating behind elevated admin secret proof; rejection of unauthenticated sessions; strict `Origin: http://127.0.0.1:3030` and `Sec-Fetch-Site: same-origin` enforcement; Protected Win32 NTFS DACLs (`D:P(A;;GA;;;SY)(A;;GA;;;BA)`) on `database/osoosi.db*` and `osoosi.toml*`; TPM 2.0 NCrypt hardware-keyed HMAC-SHA256 row integrity tags for `ui_settings_kv` and `research_registry_meta`.
- **R6 (Research Swarm Poisoning Defenses)**: In-memory declarative indicator string replay with zero host process execution; canary benign-corpus evaluation enforcing exactly 0 false positives before rule promotion; candidate rule rejection on false positives; operator approval gating prior to active blocking mode; anti-eviction protection for verified/pinned rules; malformed and overly broad rule rejection.
- **R7 (Decision Model Asymmetric Veto)**: Deterministic cryptographic and kernel behavioral invariant violations unconditionally commanding `ResponseAction::Isolate` (confidence = 1.0); asymmetric veto overriding static PE ML and NSRL whitelist vetoes; benign consensus preservation; Byzantine voter weight clamping to $[0.50, 2.50]$; contention-free concurrency lock hygiene without DashMap deadlocks or async lock starvation.

### Tier 2: Boundary & Corner Cases (42 Tests)
Extreme limits, empty inputs, max buffer sizes, illegal tokens, unicode homoglyphs, and timing window edges:
- **R1**: Empty and whitespace-only paths; null-byte injection (`path\x00extra`); percent-encoded traversal sequences (`%2e%2e`, `%2f`, `%5c`, `%00`); NTFS Alternate Data Streams (`file:stream`, `C:`); IPv4-mapped IPv6 literals (`::ffff:127.0.0.1`); port 0 and port 65536+ rejection with boundary ports 1 and 65535 support.
- **R2**: Empty environment dictionary; sliding window exact edge at $t - 7200.0\text{s}$ vs $t - 7201.0\text{s}$; CRLF embedded newlines in environment values; mixed-case environment variable normalization (`git_ssh_command`); zero-duration supervisor declassifications; high-throughput 5,000 variable environment blocks evaluating in < 50ms.
- **R3**: 0-byte, truncated, and 63-byte invalid HMAC signatures; maximum generation epoch ($2^{63}-1$) with regressing epoch rejection; mixed-case lateral sink normalization (`aCcOuNtInGLeDgErWrItE`); empty capability sets; single-bit flipped HMAC signatures; unknown / unclassified agent roles failing closed.
- **R4**: 0-byte driver hashes; 1024-character maximum path/hash buffer limits; single-byte `0xC3` prologue patches; null callback pointer (`0x0`) DKOM tamper detection; 5,000 event pure benign flood shedding; 100% saturated critical security alert bursts.
- **R5**: Missing/None Origin headers versus empty Origin; subdomain-spoofed origins (`http://127.0.0.1:3030.evil.com`); 0-byte row payload TPM HMAC tags; 1 MiB large SQLite row payloads; permissive ACE detection (`Everyone`, `Authenticated Users`); constant-time secret comparison preventing timing side-channel leaks.
- **R6**: Empty rule indicator string; wildcard regex-bomb / ReDoS resilience; empty benign corpus boundaries; priority 9999 eviction rejection on pinned rules; duplicate rule registration idempotency; unicode homoglyph resilience.
- **R7**: Negative infinity (-999.0) voter weights clamped to 0.50; positive infinity (+999.0) voter weights clamped to 2.50; empty voter lists; simultaneous ML veto AND NSRL whitelist veto overridden by deterministic guard; threshold boundary between confidence 0.8499 (Alert) and 0.8500 (Isolate); zero-confidence benign consensus.

### Tier 3: Cross-Feature Pairwise Interactions (10 Tests)
Interaction tests between intersecting perimeters:
- **P01 (R1 x R2)**: AppContainer child process spawn with tainted environment block injection.
- **P02 (R1 x R3)**: DNS rebinding / SSRF SocketAddr pinning on untrusted mesh ingress URL payload.
- **P03 (R2 x R3)**: Dogwood MFOTL cumulative taint tracking into Mesh Capability Governor tool stripping.
- **P04 (R3 x R5)**: Untrusted mesh envelope attempting unauthorized control plane session authentication.
- **P05 (R4 x R7)**: High-frequency telemetry event flood during deterministic LSASS tamper asymmetric veto.
- **P06 (R4 x R7)**: Known vulnerable BYOVD driver load attempt overriding NSRL whitelist veto.
- **P07 (R5 x R6)**: Cross-origin CSRF request attempting unauthorized research swarm rule promotion.
- **P08 (R6 x R7)**: In-memory declarative rule canary verification integrating into voter consensus.
- **P09 (R1 x R5)**: Scratch sandbox NTFS junction traversal targeting protected SQLite database.
- **P10 (R2 x R7)**: Build script (`build.rs`) configuration tampering triggering deterministic asymmetric isolate.

### Tier 4: Real-World Application Scenarios (5 Multi-Step Scenarios)
1. **Scenario 1: Multi-Turn Salami-Sliced Prompt Injection & Git Hook RCE Breakout (R1, R2, R3)**
   - External retrieval ingest -> HMAC envelope tagging -> scratchpad script write -> inter-arm task forwarding -> `MeshCapabilityGovernor` capability stripping -> Dogwood MFOTL temporal forbid -> `ExecutionEnvironmentGuard` blocks `GIT_SSH_COMMAND` -> suspended AppContainer child process terminated before `ResumeThread`.
2. **Scenario 2: TOCTOU NTFS Junction Switch & Suspended Worker Handle Theft (R1, R5)**
   - Adversarial tool creates rapid NTFS junction pointing to `database/osoosi.db` -> concurrent child process spawn attempting elevated handle inheritance -> `open_confined` reparse point verification detects `FILE_ATTRIBUTE_REPARSE_POINT` -> `GetFinalPathNameByHandleW` detects path escape -> `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` allowlist rejects leaked handles -> suspended worker terminated with `TerminateProcess`, profile rolled back via `DeleteAppContainerProfile`.
3. **Scenario 3: BYOVD Vulnerable Driver Escalation During ETW Blinding & Telemetry Flooding (R4, R7)**
   - Malware patches `EtwEventWrite` (0xC3) and `AmsiScanBuffer` (0x80070057) -> telemetry flood of 10,000 benign events -> concurrent drop of vulnerable signed driver (`GDRV.SYS`) -> watchdog detects byte patching -> priority channels preserve security alerts -> driver pre-initialization callback blocks known SHA-256 hash -> consensus engine enforces deterministic asymmetric veto commanding `ResponseAction::Isolate` (confidence = 1.0), overriding ML and NSRL vetoes.
4. **Scenario 4: Cross-Origin CSRF & SQLite NTFS DACL Out-of-Band Tampering (R5, R6)**
   - Malicious website issues background AJAX requests to `/api/auth/session` with `Origin: http://evil-site.com` -> control plane middleware rejects with 403 Forbidden -> attacker attempts direct filesystem modification of `database/osoosi.db` from standard user token -> Protected NTFS DACL (`D:P(A;;GA;;;SY)(A;;GA;;;BA)`) denies write access -> attacker attempts to forge SQLite row payloads -> TPM 2.0 NCrypt hardware-keyed HMAC-SHA256 row integrity tag verification detects mismatch and rejects forged rows.
5. **Scenario 5: Poisoned Research Swarm Rule Eviction & Host Code Execution Bypass (R6, R7)**
   - Compromised research repo publishes rule matching clean developer tools (`cargo.exe`, `cl.exe`) with malicious install scripts -> Arm 3 evaluates declarative indicator strings strictly in-memory without host execution -> canary benign corpus evaluation detects false positives (`fp > 0`) and rejects rule promotion -> attacker attempts priority 9999 eviction of existing pinned rules -> anti-eviction guard denies eviction -> unapproved rules restricted from active blocking mode -> consensus engine asymmetric veto prevents degradation of deterministic invariants.

---

## 4. Test Execution & Reporting Instructions

### Unified E2E Test Suite Runner
```powershell
python scripts/run_breakout_defense_e2e.py
```

### Granular Per-Tier Execution
```powershell
# Tier 1 Feature Coverage Only (42 tests)
python scripts/run_breakout_defense_e2e.py --tier1-only

# Tier 2 Boundary & Corner Cases Only (42 tests)
python scripts/run_breakout_defense_e2e.py --tier2-only

# Tier 3 Pairwise Interactions Only (10 tests)
python scripts/run_breakout_defense_e2e.py --tier3-only

# Tier 4 Real-World Application Scenarios Only (5 tests)
python scripts/run_breakout_defense_e2e.py --tier4-only
```

### JSON Reporting
```powershell
python scripts/run_breakout_defense_e2e.py --json
```
Execution results are automatically recorded in machine-readable JSON format at:
`logs/breakout_defense_e2e_report.json`

---

## 5. Verification Commands for Rust Crates & Drivers

In tandem with the opaque-box test runner, underlying crate interfaces are verified via Cargo:
```powershell
# Verify Rust unit and proof tests for policy and anomaly engines
cargo test -p osoosi-policy --lib
cargo test -p osoosi-agent-anomaly --lib breakout_prevention
cargo test -p osoosi-sandbox --test attack_isolation_test
```
