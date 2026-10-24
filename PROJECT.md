# Project: OshoosiClaw Production Hardening (B to A-)

## Architecture
OshoosiClaw is upgraded from heuristic, path-based trust to a hardened cryptographic-only security architecture with discrete-argv process execution, fast hermetic testing, modular crate structure (<= 2,500 lines per file), live multi-trial CI verification on port 3030, and non-blocking async request pipelines.

```
+---------------------------------------------------------------------------------------------------------+
|                                    Cryptographic Binary Trust Layer (R1)                                |
|  - Real WinVerifyTrust (Authenticode) + CatRoot Catalog Hash Lookup + Protected BLAKE3 Hash Inventory    |
|  - Zero path-prefix, PATH-derived, or substring-based trust (Fail-Closed on user-writable paths)        |
+---------------------------------------------------------------------------------------------------------+
                                                     |
                                                     v
+---------------------------------------------------------------------------------------------------------+
|                                   Core EDR & Modular Orchestrator (R4)                                  |
|  - crates/osoosi-core/src/rea/ (8 submodules, all <= 1,500 lines)                                       |
|  - crates/osoosi-core/src/orchestrator/ (8 submodules, all <= 2,300 lines) + slim lib.rs (~1,400 lines)  |
|  - Argument-Safe Process Execution (R2): Discrete argv only (no cmd /C, sh -c, powershell -Command)     |
|  - Host-Independent Masquerade & Zero Test-Only Stems (R6): CANONICAL_PROTECTED_BINARY_NAMES            |
+---------------------------------------------------------------------------------------------------------+
          |                                          |                                          |
          v                                          v                                          v
+----------------------------+     +----------------------------+     +----------------------------+
|  Async Request Paths (R7)  |     |  Deterministic Suite (R3)  |     |  Live Multi-Trial CI (R5)  |
| - Fast response (< 500ms)  |     | - Opt-in FHE feature gate  |     | - Daemon on port 3030      |
| - Async background purges  |     | - Core lib test < 35s      |     | - 6-Vector breakout suite  |
| - Progress on /status      |     | - Hermetic test fixtures   |     | - 15-Vector gauntlet       |
| - Non-blocking file I/O    |     | - CRT-mixing fix (LNK4098) |     | - T >= 3 trials per vector |
+----------------------------+     +----------------------------+     +----------------------------+
```

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | Starting State Verification & PR #1 | Commit verified uncommitted changes: `causal_graph.rs` `DeclassifiedInto` edge filter, `lib.rs` cleanup `spawn_blocking`, WebUI watchdog mojibake fix & timeout 60s, maintain 0-diff WebUI parity. | M0 | Survey |
| 2 | Decommission 14 Path/Prefix/Name Trust Sites | Eliminate `get_dynamic_trusted_dir_prefixes`, `is_canonical_trusted_binary_dir`, `is_consensus_finding_vetoed_or_benign`, `scanner_skip_path`, etc. | M1 | R1, Survey |
| 3 | Unified Cryptographic Binary Trust Pipeline | Enforce Authenticode (`WinVerifyTrust`), Windows Catalog (`CatRoot`), and protected BLAKE3 hash inventory. Fail closed on user-writable paths. | M1 | R1 |
| 4 | Host-Independent Masquerade Detection | Replace dynamic host PATH/folder scanning with deterministic `CANONICAL_PROTECTED_BINARY_NAMES` catalog. | M1 | R6 |
| 5 | Remove Test-Only Stems from Production Code | Replace broken `"libfoo"` check in `disk_cleanup.rs` with dynamic Cargo workspace package stem discovery. | M1 | R6 |
| 6 | Argument-Safe Process Execution | Replace all `cmd /C`, `sh -c`, `powershell -Command` string invocations in `disk_cleanup.rs`, `openshell.rs`, `cli/main.rs` with native `std::fs` and discrete argv. | M2 | R2 |
| 7 | Process Execution CI Check Script | Add repository scanner script to CI preventing any future single-string shell executions. | M2 | R2 |
| 8 | Non-Blocking `/api/system/cleanup` & Background Purge | Fast in-memory trim returns < 500ms (SLA < 5s); background task runs filesystem/SQLite purge with progress on `GET /api/disk-cleanup/status`. | M2 | R7 |
| 9 | Async Handler Audit & File I/O Non-Blocking | Audit all Axum handlers; replace blocking `std::fs::read` on large files with `tokio::fs` or chunked reading. | M2 | R7 |
| 10 | Gated Slow FHE Tests Behind Opt-In Feature | Add `fhe` feature in `crates/osoosi-core/Cargo.toml`; gate 3 slow tests in `fhe_coordinator.rs` behind `#[cfg(feature = "fhe")]`, reducing test time from 132s to < 35s. | M3 | R3 |
| 11 | CRT-Mixing Source Fix for LNK4098 | Patch `esaxx-rs` to eliminate `.static_crt(true)`; resolve `LIBCMT` vs `MSVCRT` conflict without `/IGNORE:4098`; remove `#![allow(linker_messages)]`. | M3 | R6 |
| 12 | Hermetic Test Fixtures Across Workspaces | Ensure all unit tests run independent of host file layout, user, PATH, or network on both Windows and Linux (WSL). | M3 | R3 |
| 13 | Modular Decomposition of `crates/osoosi-core/src/rea.rs` | Split monolithic 8,557-line `rea.rs` into 8 cohesive submodules in `crates/osoosi-core/src/rea/` (max 1,500 lines per file). | M4 | R4 |
| 14 | Modular Decomposition of `crates/osoosi-core/src/lib.rs` | Split monolithic 15,146-line `lib.rs` into 8 `orchestrator/` submodules (max 2,300 lines per file) + slim `lib.rs` (~1,400 lines). | M4 | R4 |
| 15 | Public API Backward Compatibility | Re-export all public symbols via `pub use` so dependent crates compile with zero breaking changes. | M4 | R4 |
| 16 | Multi-Trial Live CI Verification Runner | Implement `scripts/run_live_multi_trial_suite.py` running $T \ge 3$ trials per vector, reporting `NonReproducibleTransient` on inconsistency, and failing closed. | M5 | R5 |
| 17 | CI Live Verification Workflow on Port 3030 | Add `live-verification` job in `.github/workflows/ci.yml` compiling daemon, starting on port 3030, and running 6-vector breakout suite + 15-vector gauntlet. | M5 | R5 |
| 18 | Final Verification, Full Packaging & Solo PR | Rebuild Windows MSI, Linux deb/rpm/tar.gz, Docker image; submit to Microsoft WDSI; update README & mermaid diagrams; solo PR ship. | M6 | Governance, R1-R7 |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M0 | Ship Verified Starting State & PR #1 | Commit 6 verified starting files; ship PR via `scripts/solo_pr_ship.ps1`. | none | IN_PROGRESS |
| M1 | Cryptographic Binary Trust (R1) & Host-Independent Masquerade & Remove Test Stems (R6) | Eliminate 14 path-based trust sites; implement unified cryptographic trust pipeline; deterministic protected names; dynamic Cargo stem discovery; tests. | M0 | PLANNED |
| M2 | Argument-Safe Execution (R2) & Async Request Hygiene (R7) | Discrete argv execution (eliminate `cmd /C`, `sh -c`); non-blocking `/api/system/cleanup` (< 500ms); audit Axum handlers; CI shell check. | M1 | PLANNED |
| M3 | Fast Hermetic Test Suite (R3) & CRT Mixing LNK4098 Fix (R6) | Opt-in `fhe` cargo feature (< 120s suite); patch `esaxx-rs` to remove `.static_crt(true)`; remove `#![allow(linker_messages)]`; hermetic fixtures. | M1 | PLANNED |
| M4 | Modular Decomposition of rea.rs and lib.rs (R4) | Split `rea.rs` into `rea/` (8 submodules, all <= 1,500 lines); split `lib.rs` into `orchestrator/` (8 submodules, all <= 2,300 lines) + slim `lib.rs`; re-exports. | M1, M2, M3 | PLANNED |
| M5 | Live Multi-Trial CI Verification on Port 3030 (R5) | Multi-trial test runner ($T \ge 3$ trials, `NonReproducibleTransient` fail-closed); GitHub Actions `live-verification` job. | M2, M3, M4 | PLANNED |
| M6 | Final Verification, Documentation & Diagrams, Release Packaging & Microsoft Submission | Full verification, update README.md and mermaid diagrams, build MSI/Linux/Docker, WDSI submission, ship final PR. | M1-M5 | PLANNED |

## Interface Contracts

### M1: Cryptographic Binary Trust
- `verify_binary_cryptographic_trust(path: &Path) -> BinaryTrustVerdict`:
  - Returns `BinaryTrustVerdict::Trusted(TrustSource::ProtectedHashInventory | TrustSource::Authenticode | TrustSource::WindowsCatalog)`
  - Returns `BinaryTrustVerdict::Untrusted(TrustRejectionReason)`
- `CANONICAL_PROTECTED_BINARY_NAMES: &[&'static str]`: Static, versioned slice of protected OS and developer binary stems.

### M2: Async Cleanup & Disk Management
- `POST /api/system/cleanup` -> `Json(DiskCleanupJobResponse { job_id, status: "scheduled", immediate_freed_bytes })` (Returns in < 500ms).
- `GET /api/disk-cleanup/status` -> `Json(DiskCleanupJobProgress { job_id, is_active, phase, files_pruned, bytes_freed, error: Option<String> })`.

### M3: FHE Feature Flag
- In `crates/osoosi-core/Cargo.toml`: `fhe = ["dep:tfhe"]` (optional, default disabled).
- Tests requiring homomorphic operations annotated with `#[cfg(feature = "fhe")]`.

### M4: Modular Core Architecture
- `crates/osoosi-core/src/rea/`: `types.rs`, `path_security.rs`, `prompt_injection.rs`, `inspectors/`, `engine.rs`, `inventory.rs`, `voters.rs`, `tests.rs`.
- `crates/osoosi-core/src/orchestrator/`: `init.rs`, `event_pipeline.rs`, `mesh.rs`, `maintenance.rs`, `remediation.rs`, `query.rs`, `types.rs`, `tests.rs`.
- `crates/osoosi-core/src/lib.rs`: Public re-exports `pub use orchestrator::EdrOrchestrator;`, `pub use rea::*;`.

## Code Layout
- `crates/osoosi-core/src/rea/`: Decomposed submodules of `rea.rs` (max <= 1,500 lines).
- `crates/osoosi-core/src/orchestrator/`: Decomposed submodules of `lib.rs` (max <= 2,300 lines).
- `crates/osoosi-core/src/lib.rs`: High-level crate root & public re-exports (~1,400 lines).
- `scripts/run_live_multi_trial_suite.py`: Multi-trial test runner for port 3030 daemon.
- `scripts/check_no_shell_exec.py`: CI linter script ensuring 0 shell-string executions.
- `.github/workflows/ci.yml`: Updated CI pipeline with `live-verification` job.
