# Project: OshoosiClaw High-Performance Zero-Trust Agent Defense & EDR (R1-R5)

## Architecture
OpenỌ̀ṣọ́ọ̀sì (`OshoosiClaw`) is engineered into a high-performance, continuously adaptive, zero-trust Agent Defense and EDR platform that delivers near-zero measurable overhead under representative production workloads while maximizing prevention, detection, and containment of agent breakout, sandbox escape, privilege escalation, tool-chain abuse, policy bypass, telemetry evasion, and coordinated multi-agent compromise.

```
+-----------------------------------------------------------------------------------------------------------------------+
|                                  Pre-Execution Security & Unified Confinement (M1 / R1)                               |
| - Offline Workspace Dependency Resolution (rhai workspace crate fix & CARGO_TARGET_DIR MASM line limit guard)         |
| - Tier-1 In-Process Wasmtime: Wired MemoryLimiter (64 MiB cap), fuel metering, single confined scratch directory     |
| - Tier-2 Win32 Confinement: CREATE_SUSPENDED, IsProcessInJob, AppContainer SID, create_deelevated_token               |
| - Egress Security: DNS-pinned network egress & Google Safe Browsing v4 integration to eliminate TOCTOU rebinding      |
+-----------------------------------------------------------------------------------------------------------------------+
                                                           |
                                                           v
+-----------------------------------------------------------------------------------------------------------------------+
|                             Continuous Breakout Defense & Per-File DLP Precision (M2 / R2)                            |
| - 7-Ring Continuous Cedar Reference Monitor (L1-L5 authority lattice, causal event cevt-... / pdec-... correlation)   |
| - Deny-overrides precedence & instant authorization cache invalidation on taint/revocation/policy transition         |
| - Per-submission browser/HAR DLP resolution: allow benign (covergeneral.docx) & auto-release stale destination blocks |
| - High-precision sensitive file containment (10-MB-Test.xlsx) via 4-voter quorum & native Rust WFP (FwpmFilterAdd0)   |
+-----------------------------------------------------------------------------------------------------------------------+
                                                           |
                                                           v
+-----------------------------------------------------------------------------------------------------------------------+
|                                Peer-to-Peer Mesh, BFT Consensus & RL Separation (M3 / R3)                             |
| - LibP2P GossipSub (15 topics), pure-Rust ML-DSA-65 / Ed25519 hybrid signatures & hardware TPM 2.0 PCR attestation   |
| - BFT Consensus (2/3 quorum, PoS weighting, PoW difficulty) & Byzantine anti-kill-switch fraud proofs                |
| - Strict RL separation: learned policies strictly advisory; cannot declassify taint or override Cedar denials        |
+-----------------------------------------------------------------------------------------------------------------------+
                                                           |
                                                           v
+-----------------------------------------------------------------------------------------------------------------------+
|                               Profiling-Driven Performance & Async Lock Safety (M4 / R4)                              |
| - Tier-1 Wasmtime warm invocation optimization (< 1 ms): precompiled Module cache & shared Linker                    |
| - Async Tokio lock hygiene: eliminate blocking_write()/blocking_read() calls on Tokio RwLock in async/Rayon contexts  |
| - DashMap nested lock contention elimination; WebUI 0-diff parity verification                                        |
+-----------------------------------------------------------------------------------------------------------------------+
                                                           |
                                                           v
+-----------------------------------------------------------------------------------------------------------------------+
|                               Adversarial Proof, Benchmarking & Packaging Delivery (M5 / R5)                          |
| - Multi-tier E2E testing (Tiers 1-4) & adversarial hardening (Tier 5); 43/43 A+ vectors verified across 129 trials   |
| - Empirical Benchmark Report: docs/PERFORMANCE_AND_SECURITY_BENCHMARK.md (latencies, CPU%, RSS, 0 dropped events)    |
| - Unified Packaging: Windows MSI (SDK signtool.exe + WDSI submission), Linux deb/rpm/tar.gz, hardened Docker         |
| - Solo PR shipping via scripts/solo_pr_ship.ps1 & cross-repo sync to D:\harfile\AgentOctopus                          |
+-----------------------------------------------------------------------------------------------------------------------+
```

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | Cargo Offline Dependency Resolution | Add `rhai` dependency in root `Cargo.toml` `[workspace.dependencies]` to unblock offline cargo index resolution. | M1 | Survey 1, Survey 2 |
| 2 | Tier-1 Wasmtime Memory Limiter | Wire `MemoryLimiter` into `Store` via `store.limiter(...)` and configure 64 MiB linear memory limit. | M1 | R1, Survey 1 |
| 3 | Tier-1 Wasmtime Confined Scratch Dir | Preopen single confined scratch directory (`workspace_dir`) in `WasiCtxBuilder`. | M1 | R1, Survey 1 |
| 4 | Host Operation Fuel Metering | Deduct execution fuel via `caller.consume_fuel(...)` during host function calls (`host_scan_file`, `host_fetch_url`, etc.). | M1 | R1, Survey 1 |
| 5 | Capability Checking & Revocation | Check and consume `store.capabilities` in host function dispatch to eliminate capability reuse. | M1 | R1, Survey 1 |
| 6 | Tier-2 Win32 Process Confinement | Implement `create_deelevated_token` and route process spawning through AppContainer + Job Object with `IsProcessInJob`. | M1 | R1, Survey 1 |
| 7 | DNS-Pinned Network Egress | Implement DNS pinning in `handle_fetch_url` to eliminate DNS rebinding TOCTOU vulnerabilities. | M1 | R1, Survey 1 |
| 8 | Auto-Release Stale Destination Blocks | When a submission is allowed (`event.allowed == true`, e.g. `covergeneral.docx`), release active WFP host blocks. | M2 | R2, Survey 2 |
| 9 | Large File DLP Streaming (16 MB) | Expand `MAX_STREAM_BYTES` in `har_dlp.rs` to 16 MB so 10-MB test files (`10-MB-Test.xlsx`) are completely inspected. | M2 | R2, Survey 2 |
| 10 | Per-Submission File Selection Precision | Tighten candidate sorting in `har_dlp.rs` using exact timestamp and form-data metadata binding. | M2 | R2, Survey 2 |
| 11 | 4-Voter Quorum & Native WFP Containment | Verify `OpenJEV-Voter`, `REA-Voter`, `RedactX`, `GoogleSafeBrowsing` 4-voter quorum and native `FwpmFilterAdd0` WFP containment. | M2 | R2, Survey 2 |
| 12 | P2P Mesh GossipSub & Hybrid PQC | Verify 15-topic GossipSub and NIST FIPS 204 `ML-DSA-65` + `Ed25519` dual signatures with secure secret zeroization. | M3 | R3, Survey 3 |
| 13 | Hardware TPM 2.0 PCR Attestation | Verify composite PCR quote validation [0, 7, 16], OEM EK silicon certificate validation, and anti-replay nonces (300s TTL). | M3 | R3, Survey 3 |
| 14 | BFT Consensus & Anti-Kill-Switch Veto | Enforce 2/3 quorum, PoS stake exponentiation, PoW vote difficulty, `ByzantineKillSwitchFraudProof`, and stake slashing. | M3 | R3, Survey 3 |
| 15 | Strict RL Separation from Deterministic Deny | Enforce Cedar invariants: `DENY_RL_TAINT_OR_PROVENANCE_MUTATION`, `DENY_RL_PERMIT_RULE_PROPOSAL`, `DENY_MODEL_MANIPULATION_OVERRIDE`. | M3 | R3, Survey 3 |
| 16 | Tier-1 Wasmtime Warm Invocation (< 1 ms) | Implement precompiled `Module` cache (`DashMap<[u8; 32], Module>`) and shared `Linker` in `osoosi-sandbox`. | M4 | R4, Survey 1 |
| 17 | Epoch Timer Task Contention Fix | Eliminate per-execution `tokio::spawn` timer tasks that trigger engine-wide epoch cancellation. | M4 | R4, Survey 1 |
| 18 | Tokio Async Lock Safety Refactoring | Refactor `blocking_write()` and `blocking_read()` call sites on `tokio::sync::RwLock` across `maintenance.rs`, `malware.rs`, `analyzer.rs`, `adaptive.rs`. | M4 | R4, Survey 1 |
| 19 | DashMap Nested Lock Hygiene | Eliminate nested lock acquisitions on `DashMap` in `containment_ring.rs` and `agent_egress.rs`. | M4 | R4, Survey 1 |
| 20 | WebUI 0-Diff Parity Maintenance | Maintain 100% byte-for-byte SHA256 equality between `dashboard/src` and `dashboard/dist` (15/15 tests passing). | M4 | R4, Survey 3 |
| 21 | Comprehensive Benchmark Report Authoring | Compile and publish `docs/PERFORMANCE_AND_SECURITY_BENCHMARK.md` recording latencies, CPU%, RSS, and 0 dropped events. | M5 | R5, Survey 3 |
| 22 | 43 A+ Adversarial Vectors Multi-Trial Proof | Execute and verify 43 vectors across Domain 1 & Domain 2 with 100% agreement over 129 trials. | M5 | R5, Survey 3 |
| 23 | E2E Testing Suite (Tiers 1-4) & Hardening (Tier 5) | Design and execute comprehensive 4-tier opaque-box E2E test suite followed by Tier 5 adversarial coverage hardening. | M5 | R5, Survey 3 |
| 24 | Full-Lifecycle Packaging & Submission | Rebuild Windows MSI (SDK `signtool.exe` + WDSI submission), Linux packages (`.deb`, `.rpm`, `.tar.gz`), and hardened Docker image. | M5 | R5, Governance |
| 25 | Solo PR Shipping & Cross-Repo Sync | Execute `scripts/solo_pr_ship.ps1` for clean branch merge and synchronize updates to `D:\harfile\AgentOctopus`. | M5 | Governance |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | Pre-Execution Security & Unified Confinement | Features 1–7: Rhai dependency fix, wired MemoryLimiter (64 MiB), scratch dir, fuel metering, capability enforcement, Win32 AppContainer + Job Object + de-elevated token, DNS pinning. | none | DONE (PR #216, commit 8e44e2f0; 28/28 sandbox & 132/132 agent-anomaly tests pass, 0 warnings) |
| M2 | Continuous Breakout Defense & DLP Precision | Features 8–11: Stale block auto-release on benign upload, 16MB stream buffer in `har_dlp.rs`, per-submission candidate binding, 4-voter quorum + WFP verification. | M1 | DONE (26/26 DLP tests, 77/77 policy tests, 132/132 agent-anomaly tests, 15/15 WebUI parity tests pass) |
| M3 | P2P Mesh, BFT Containment & RL Separation | Features 12–15: P2P GossipSub, ML-DSA-65/Ed25519, TPM 2.0 quote validation, BFT consensus, Byzantine kill-switch fraud proofs, strict Cedar RL separation. | M1 | PLANNED |
| M4 | Profiling-Driven Performance & Lock Safety | Features 16–20: Wasmtime module cache (<1ms warm invocation), epoch timer fix, Tokio async lock safety refactoring, DashMap lock hygiene, WebUI 0-diff parity. | M1, M2 | PLANNED |
| M5 | Adversarial Proof, Benchmarking & Packaging Delivery | Features 21–25: Benchmark report `PERFORMANCE_AND_SECURITY_BENCHMARK.md`, 43 A+ vector validation, 100% E2E test pass + Tier 5 hardening, Windows/Linux/Docker packaging, WDSI submission, AgentOctopus sync, Solo PR ship. | M1, M2, M3, M4 | PLANNED |

## Interface Contracts

### M1: Wasmtime & Win32 Sandbox Interface
- `SandboxConfig`:
  - `memory_limit_bytes`: `u64` (default `64 * 1024 * 1024` = 64 MiB)
  - `workspace_dir`: `Option<PathBuf>` (preopened as single confined scratch directory in WASI P1)
- `create_deelevated_token(source_token: HANDLE) -> Result<HANDLE, Win32Error>`:
  - Creates restricted token with `DisableSids`, restricted SIDs, and `TokenIntegrityLevel = Medium/Low`.
- `execute_confined_windows_process(program: &str, args: &[&str], profile_name: &str, policy: &WindowsConfinementPolicy) -> Result<ConfinementTransitionOutcome, String>`:
  - Creates process with `CREATE_SUSPENDED (0x00000004)`, assigns to Job Object, sets AppContainer token, asserts `IsProcessInJob == TRUE`, resumes thread.

### M2: DLP Event & Auto-Release Interface
- `post_dlp_browser_event(event: DlpBrowserEvent) -> Response`:
  - If `event.allowed == true`: queries active destination block for `event.destination_host`. If blocked, calls `osoosi_core::wfp::unblock_destination_native(ip)` to release stale block.
- `resolve_local_uploaded_file(candidate: Option<&str>, destination_sink: &str) -> Option<ResolvedDlpFile>`:
  - Streams up to `16 * 1024 * 1024` bytes (16 MiB), parses Office OpenXML Deflate streams, and matches submission metadata.

### M3: BFT Consensus & RL Policy Separation
- `breakout_gate::CedarAuthorizer`:
  - `DENY_RL_TAINT_OR_PROVENANCE_MUTATION`: rejects any request to alter taint state via RL policy.
  - `DENY_MODEL_MANIPULATION_OVERRIDE`: if Cedar evaluation denies, model recommendation cannot override.

### M4: Precompiled WASM Module Cache
- `ModuleCache`:
  - `get_or_compile(engine: &Engine, wasm_bytes: &[u8]) -> Result<Module, wasmtime::Error>`
  - Key: `blake3::hash(wasm_bytes)`
  - Target: warm invocation < 1 ms.

## Code Layout
- `crates/osoosi-sandbox/src/`:
  - `lib.rs`: Wasmtime engine, module cache, `Store` initialization with `store.limiter`.
  - `memory_limiter.rs`: `MemoryLimiter` enforcing 64 MiB cap.
  - `native_host.rs`: Hostcall dispatch with capability consumption, fuel deduction, DNS pinning.
  - `windows.rs`: `create_deelevated_token`, Win32 AppContainer and Job Object process spawning.
- `crates/osoosi-dashboard/src/routes/`:
  - `dlp.rs`: `post_dlp_browser_event` with stale block auto-release.
  - `har_dlp.rs`: `MAX_STREAM_BYTES` 16 MiB streaming and metadata binding.
  - `dlp_containment.rs`: 4-voter quorum and WFP containment.
- `crates/osoosi-core/src/`:
  - `wfp.rs`: Native `FwpmFilterAdd0` and `FwpmFilterDeleteById0`.
  - `orchestrator/maintenance.rs`: Async lock refactoring (eliminate `blocking_write` in Rayon).
- `docs/`:
  - `PERFORMANCE_AND_SECURITY_BENCHMARK.md`: Full empirical benchmark report.
- `scripts/`:
  - `build_and_submit.ps1`: Primary release build, signing, WDSI submission, and packaging script.
  - `solo_pr_ship.ps1`: Automated Git branch and PR merge script.
