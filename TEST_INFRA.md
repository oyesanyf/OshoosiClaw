# E2E Test Infra: OshoosiClaw High-Performance Zero-Trust Defense

## Test Philosophy
- **Opaque-Box & Requirement-Driven**: Tests are derived strictly from `ORIGINAL_REQUEST.md` (R1-R5) and user-facing specifications, never implementation internals.
- **Methodology**: Systematic 4-tier testing: Category-Partition, Boundary Value Analysis (BVA), Pairwise Combinatorial Testing, and Real-World Workload Testing.
- **Progressive Testability**: Verification does not rely on components more complex than the unit under test. Tier 1 gives pass/fail signal from the earliest milestones.
- **Adversarial Hardening**: Upon passing Tiers 1-4, Phase 2 executes Tier 5 white-box adversarial testing with Challenger agents.

## Feature Inventory & Test Matrix
| # | Feature | Requirement Source | Tier 1 (>=5) | Tier 2 (>=5) | Tier 3 (Pairwise) | Tier 4 (App Scenario) |
|---|---------|-------------------|:------------:|:------------:|:-----------------:|:---------------------:|
| 1 | Tier-1 Wasmtime Confinement (64MiB limit, fuel, scratch dir) | R1 §1 | 5 | 5 | ✓ | S1 |
| 2 | Hostcall Capability Revocation & Fuel Metering | R1 §1 | 5 | 5 | ✓ | S1 |
| 3 | Tier-2 Win32 Confinement (AppContainer, Job Object, Token De-elevation) | R1 §2 | 5 | 5 | ✓ | S2 |
| 4 | DNS-Pinned Egress & Google Safe Browsing v4 | R1 §2 | 5 | 5 | ✓ | S2 |
| 5 | 7-Ring Cedar Reference Monitor & Authority Lattice (L1-L5) | R2 §1 | 5 | 5 | ✓ | S3 |
| 6 | Causal Security Graph (`cevt-...` / `pdec-...` correlation) | R2 §1 | 5 | 5 | ✓ | S3 |
| 7 | Deny-Overrides Precedence & Cache Invalidation | R2 §1 | 5 | 5 | ✓ | S3 |
| 8 | Per-Submission DLP: Benign Auto-Release (`covergeneral.docx`) | R2 §2 | 5 | 5 | ✓ | S4 |
| 9 | Per-Submission DLP: Sensitive 4-Voter Quorum (`10-MB-Test.xlsx`) | R2 §2 | 5 | 5 | ✓ | S4 |
| 10 | Native Rust WFP Containment (`FwpmFilterAdd0`) | R2 §2 | 5 | 5 | ✓ | S4 |
| 11 | LibP2P GossipSub (15 topics) & ML-DSA-65/Ed25519 Signatures | R3 §1 | 5 | 5 | ✓ | S5 |
| 12 | Hardware TPM 2.0 PCR Attestation & OEM Chain Verification | R3 §1 | 5 | 5 | ✓ | S5 |
| 13 | BFT Consensus Quorum & Anti-Kill-Switch Byzantine Defense | R3 §2 | 5 | 5 | ✓ | S5 |
| 14 | Deterministic Deny Precedence Over Adaptive RL (Cedar Invariants) | R3 §3 | 5 | 5 | ✓ | S5 |
| 15 | Tier-1 Warm Invocation Optimization (< 1 ms) | R4 §1 | 5 | 5 | ✓ | S1, S6 |
| 16 | Tokio Async Lock Safety & Contention-Free Event Processing | R4 §2 | 5 | 5 | ✓ | S6 |
| 17 | WebUI 0-Diff Parity Invariant (`webui_parity.test.mjs`) | R4 §3 | 5 | 5 | ✓ | S6 |
| 18 | Multi-Trial Adversarial Verification (43 A+ Vectors) | R5 §1 | 5 | 5 | ✓ | S7 |

## Test Architecture
- **Runner**: Node.js & PowerShell test harnesses invoking CLI endpoints, REST APIs, and cargo test suites:
  - Unit/Integration: `cargo test -- -p <crate>` (configured with `CARGO_TARGET_DIR`)
  - WebUI Parity: `node --test dashboard/tests/webui_parity.test.mjs`
  - Multi-Node Mesh Benchmark: `python scripts/run_multi_node_mesh_benchmark.py --fast`
  - Adversarial Proof Suite: `python scripts/run_live_adversarial_proof_suite.py`
  - E2E Validation Harness: `scripts/run_e2e_suite.py` (executes Tiers 1-4)
- **Format**: Structured JSON output with per-tier pass/fail counters and latency percentiles.

## Real-World Application Scenarios (Tier 4)
| # | Scenario | Features Exercised | Expected Outcome |
|---|----------|--------------------|------------------|
| S1 | Untrusted WASM Agent Execution | F1, F2, F15 | Linear memory capped at 64MiB; fuel exhausted on infinite loops; warm start < 1ms. |
| S2 | High-Integrity Host Command Confinement | F3, F4 | Spawns in suspended state, bound to AppContainer SID + Job Object, de-elevated token; network egress DNS-pinned. |
| S3 | Multi-Turn Agent Goal Hijacking Resistance | F5, F6, F7 | Taint accumulated in causal graph; Cedar forbid overrides voter weight; cache invalidated upon taint transition. |
| S4 | Browser DLP Document Upload Precision | F8, F9, F10 | Benign `covergeneral.docx` upload allowed and clears stale destination block; `10-MB-Test.xlsx` triggers 4-voter quorum and WFP block. |
| S5 | Byzantine Mesh Threat Injection | F11, F12, F13, F14 | Rogue peer kill-switch detected; `ByzantineKillSwitchFraudProof` issued; rogue peer stake slashed by 100.0; RL cannot override Cedar denial. |
| S6 | Sustained Event Saturation & Lock Contention | F15, F16, F17 | Zero Tokio `blocking_write` deadlocks under 5,000 req/sec; zero memory leaks; WebUI remains 0-diff. |
| S7 | Full 43-Vector Adversarial Regression Gauntlet | F18 | 43/43 vectors pass with 100% agreement over 129 trials; zero transients. |

## Coverage Thresholds
- **Tier 1 (Feature Coverage)**: >= 5 test cases per feature (18 features * 5 = 90 test cases minimum)
- **Tier 2 (Boundary & Corner)**: >= 5 test cases per feature (18 features * 5 = 90 test cases minimum)
- **Tier 3 (Cross-Feature Combinations)**: >= 18 pairwise interaction test cases
- **Tier 4 (Real-World Scenarios)**: >= 7 full end-to-end workload scenarios
- **Total Minimum Test Cases**: ~205 test cases across Tiers 1–4.
