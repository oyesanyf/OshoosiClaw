# Project: OpenỌ̀ṣọ́ọ̀sì (`OshoosiClaw`) Performance & Zero-Trust Defense Hardening

## Architecture
OpenỌ̀ṣọ́ọ̀sì (`OshoosiClaw`) is a high-performance, continuously adaptive zero-trust Agent Defense and EDR platform.
- **Control Plane**: `osoosi-types`, `osoosi-agent-anomaly`, `osoosi-policy` (5-level authority hierarchy, Cedar/Dogwood reference monitor, persistent causal security graph, revocation-bound capability cache, command-line tokenization).
- **Execution Sandboxing**:
  - **Tier 1 (In-Process Wasmtime Sandbox)**: `osoosi-sandbox` (`wasm_tier1.rs`, `open_confined.rs`) with fuel metering, 64 MiB linear memory limit, zero ambient WASI authority, handle-locked scratchpad.
  - **Tier 2 (Native Win32 De-Elevated Confinement)**: `osoosi-sandbox` (`executable_identity.rs`, `token_posture.rs`, `windows.rs`, `tiered_executor.rs`) with handle read-locking `FILE_SHARE_READ`, PE verification, AppContainer SID profile, `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, `IsProcessInJob == TRUE`, de-elevated token, sorted minimal Unicode environment.
- **DLP & Data Protection**: `osoosi-dp`, `osoosi-dashboard` (`har_dlp.rs`, `dlp.rs`, `dlp_containment.rs`), `osoosi-core` (`wfp.rs`, `rea.rs`) with per-submission `.lnk` recency resolution, streaming OOXML extraction, 4-voter quorum (`OpenJEV`, `REA`, `RedactX`, `GoogleSafeBrowsing`), native Rust WFP `FwpmFilterAdd0` blocking, and bidirectional auto-release.
- **P2P Mesh & Consensus**: `osoosi-wire`, `osoosi-core` (`byzantine.rs`) with hybrid PQC (`ML-KEM-768` + `ML-DSA-65`), TPM 2.0 attestation, 2/3 BFT consensus, anti-kill-switch fail-closed enforcement, and strict SkyRL tighten-only proposal separation.
- **Performance & Telemetry**: `osoosi-telemetry`, `osoosi-model`, `osoosi-behavioral`, `osoosi-core` with bounded channels, lock contention elimination (no `blocking_read()`/`blocking_write()` on Tokio async locks), YARA-X scanning, eBPF CO-RE schemas.

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | Tier-2 Handle-Locked Executable Identity | Port `executable_identity.rs` (`FILE_SHARE_READ`, PE verification, kernel tuple SHA-256 caching, interpreter marker check) | M1 | R1, Survey |
| 2 | Tier-2 AppContainer Pipeline Integration | Unify `ExecutableIdentityVerifier`, AppContainer SID spawning with sorted Unicode environment, and `MeasuredActuationSample` in `tiered_executor.rs` | M1 | R1, Survey |
| 3 | DLP Auto-Release Parity in `dlp.rs` | Call `restore_browser_destination_blocks_for_host` in `post_dlp_browser_event` (on clean upload) and `post_dlp_release` | M2 | R2, Survey |
| 4 | Per-Submission DLP Accuracy Verification | Verify `covergeneral.docx` allow & unblock vs `10-MB-Test.xlsx` 4-voter quorum + WFP block | M2 | R2, Survey |
| 5 | Bounded Task Queue in `adaptive.rs` | Replace `unbounded_channel::<DeferredTask>()` with bounded channel (`4096`) | M3 | R4, Survey |
| 6 | Lock Hygiene & Async Safety | Convert `sys` in `adaptive.rs` to `parking_lot::Mutex<System>`, eliminate `blocking_write()`, optimize lock scopes in `maintenance.rs` and `voters.rs` | M3 | R4, Survey |
| 7 | Full-Stack Adversarial & Benchmarking Delivery | Execute `seven_ring_breakout_prevention.rs`, `webui_parity.test.mjs`, update `PERFORMANCE_AND_SECURITY_BENCHMARK.md`, verify `AgentOctopus` sync | M4 | R3, R5, Survey |
| 8 | Unified Build, WDAC Sign & Microsoft Submission | Execute `scripts/build_and_submit.ps1` with native Windows SDK `signtool.exe`, submit to WDSI, ship cleanly via `scripts/solo_pr_ship.ps1` | M4 | R5, Governance |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| 1 | M1: Tier-2 Executable Identity & Confinement Parity | `crates/osoosi-sandbox/src/executable_identity.rs`, `tiered_executor.rs`, `lib.rs` | none | DONE |
| 2 | M2: Per-File DLP Precision & Auto-Release Parity | `crates/osoosi-dashboard/src/routes/dlp.rs`, `har_dlp.rs`, `dlp_containment.rs` | none | IN_PROGRESS |
| 3 | M3: Performance Optimization & Lock Hygiene | `crates/osoosi-core/src/adaptive.rs`, `maintenance.rs`, `voters.rs` | none | PLANNED |
| 4 | M4: Full Adversarial Proof, Benchmark & Microsoft Delivery | Adversarial suites, `PERFORMANCE_AND_SECURITY_BENCHMARK.md`, `AgentOctopus` sync, `build_and_submit.ps1` | M1, M2, M3 | PLANNED |

## Code Layout
- `crates/osoosi-sandbox/src/executable_identity.rs`: Handle read-locking, PE verification, SHA-256 caching by kernel file tuple, interpreter marker detection.
- `crates/osoosi-sandbox/src/tiered_executor.rs`: Tiered execution dispatcher routing Tier 1 Wasm vs Tier 2 Win32 AppContainer.
- `crates/osoosi-dashboard/src/routes/dlp.rs`: DLP REST API handlers, auto-release coordination.
- `crates/osoosi-dashboard/src/routes/har_dlp.rs`: Real-time autonomous HAR-to-DLP collector and candidate file resolution.
- `crates/osoosi-core/src/adaptive.rs`: Host adaptive telemetry and task scheduler.
- `crates/osoosi-core/src/orchestrator/maintenance.rs`: Background model maintenance and weight updates.
- `crates/osoosi-core/src/voters.rs`: Behavioral and YARA threat voters.
- `docs/PERFORMANCE_AND_SECURITY_BENCHMARK.md`: Verified latency, throughput, and adversarial prevention documentation.
- `scripts/build_and_submit.ps1`: Canonical unified release build, WDAC signing, WDSI submission, and PR shipping script.

## Interface Contracts
### `osoosi-sandbox::executable_identity` ↔ `tiered_executor`
- `ExecutableIdentityVerifier::new(allowed_stems: &[&str]) -> Self`
- `verifier.verify_and_lock(path: &Path) -> Result<LockedExecutableIdentity, OctopusSecurityError>`
- `LockedExecutableIdentity`: retains open read-locked handle (`FILE_SHARE_READ`) until child process is created via `CreateProcessW`, preventing disk TOCTOU replacement.

### `osoosi-dashboard::routes::dlp` ↔ `osoosi-dashboard::routes::har_dlp`
- `engine.restore_browser_destination_blocks_for_host(host: &str, reason: &str) -> Vec<String>`
- Invoked when clean file upload is processed (`event.allowed == true`) and when an event is released (`post_dlp_release`).
