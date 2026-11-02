# E2E Test Infra: Google Cybernetic Agent Governance Engine (CAGE) Native Substrate

## Test Philosophy
- **Opaque-Box & Requirement-Driven**: Tests derive directly from `ORIGINAL_REQUEST.md` and CAGE Substrate Contract v1.0 specifications. Tests interact exclusively through public APIs, CLI commands, HTTP endpoints on port 3030, and serialized policy files, without internal module mocking.
- **Progressive Testability**: Verification does not depend on features more complex than what is under test. Tier 1 tests provide clear pass/fail signals with only early milestones in place.
- **Negative & Adversarial Testing**: Extensive coverage of invalid, malformed, expired, replay, and budget-exhausting inputs verifying fail-closed invariants and 64-character hex receipts.
- **Methodology**: Systematic 4-Tier approach combining Category-Partition, Boundary Value Analysis (BVA), Pairwise Combinatorial Testing, and Real-World Workload Testing, followed by Tier 5 Adversarial Coverage Hardening.

---

## Feature Inventory & Test Mapping
| # | Feature | Source (Requirement) | Tier 1 (Coverage) | Tier 2 (Boundary) | Tier 3 (Cross-Feature) | Tier 4 (Real-World) |
|---|---------|----------------------|:-----------------:|:-----------------:|:----------------------:|:-------------------:|
| F1 | Multi-Format Auto-Detection (ACS, AAIF, OSCAL, Lula, STPA) | ORIGINAL_REQUEST §R1 | 5 | 5 | ✓ | ✓ |
| F2 | Cedar & STPA UCA Policy Compilation | ORIGINAL_REQUEST §R1 | 5 | 5 | ✓ | ✓ |
| F3 | Deterministic 16-Hex Version Pinning & 409 Conflict | ORIGINAL_REQUEST §R1 | 5 | 5 | ✓ | ✓ |
| F4 | Phase 1 Read-Only Multi-Tier Gating (FTRA, STPA, Cedar, SR 26-2) | ORIGINAL_REQUEST §R2 | 5 | 5 | ✓ | ✓ |
| F5 | Phase 2 Discrete-Time Exponential CBF & Fiscal Ledger | ORIGINAL_REQUEST §R2 | 5 | 5 | ✓ | ✓ |
| F6 | Canonical Verdicts & 30s TTL Cryptographic Routing Seals | ORIGINAL_REQUEST §R2 | 5 | 5 | ✓ | ✓ |
| F7 | Pure-Rust 34-State BFS Formal Model (NoDirectBind) | ORIGINAL_REQUEST §R3 | 5 | 5 | ✓ | ✓ |
| F8 | Stream Invariant Verifier (5 Invariants, 64-hex Receipts) | ORIGINAL_REQUEST §R3 | 5 | 5 | ✓ | ✓ |
| F9 | Host Capability Gate Routing Seal Enforcement | ORIGINAL_REQUEST §R4 | 5 | 5 | ✓ | ✓ |
| F10 | RFC 8785 JCS Canonical JSON Formatting | ORIGINAL_REQUEST §R5 | 5 | 5 | ✓ | ✓ |
| F11 | `cage-audit/3.0` & `GOVERNANCE_TRACE` Merkle Anchoring | ORIGINAL_REQUEST §R5 | 5 | 5 | ✓ | ✓ |
| F12 | SQLite CAGE State Persistence (`cage_policies`, `cage_routing_seals`) | ORIGINAL_REQUEST §R5 | 5 | 5 | ✓ | ✓ |
| F13 | Substrate Contract v1.0 REST API on Port 3030 | ORIGINAL_REQUEST §R6 | 5 | 5 | ✓ | ✓ |
| F14 | WebUI Governance Substrate Card & 0-Diff Parity | ORIGINAL_REQUEST §R6 | 5 | 5 | ✓ | ✓ |
| F15 | Consolidated CI/CD Governance Workflows | ORIGINAL_REQUEST §R7 | 5 | 5 | ✓ | ✓ |

---

## Test Architecture
- **Location**: `tests/e2e_cage_governance/` and crate integration test suites (`crates/osoosi-policy/tests/`, `crates/osoosi-sandbox/tests/`, etc.).
- **Invocation**:
  - Full suite: `cargo test --test e2e_cage_governance`
  - Policy ingestion & CBF: `cargo test -p osoosi-policy --test cage_tests`
  - Host capability seal: `cargo test -p osoosi-sandbox --test host_capability_cage_tests`
  - WebUI Parity: `node --test dashboard/tests/webui_parity.test.mjs`
  - Model verification: `cargo run -p osoosi-policy --bin verify_cage_bfs`
- **Output & Pass/Fail Semantics**: All tests exit with code 0 on pass. Errors fail closed with structured failure diagnostics.

---

## Real-World Application Scenarios (Tier 4)
| # | Scenario | Features Exercised | Complexity |
|---|----------|--------------------|------------|
| 1 | Multi-Format Ingestion Pipeline: Ingest ACS policy, pin version, detect conflict on duplicate mismatch, verify 409 Conflict | F1, F2, F3, F12, F13 | High |
| 2 | Autonomous Financial Agent Loop: Phase 1 risk check, Phase 2 CBF fuel budget consumption ($B_t$), seal issuance, actuation execution, audit trace anchor | F4, F5, F6, F9, F11, F12 | Critical |
| 3 | Actuation Refusal & Fiscal Rollback: Injected unsafe parameters trigger CBF denial, assert zero fiscal budget leakage ($B_{t+1}=B_t$) and 64-hex refusal receipt | F5, F6, F8, F11 | High |
| 4 | Replay & Seal Expiration Attack Defense: Attempt actuation with expired seal (>30s TTL) or replayed seal, assert immediate fail-closed rejection | F6, F9, F11, F13 | Critical |
| 5 | Formal Model Space Verification: Execute 34-state BFS engine, assert 34 gated states vs 17 ungated counterexample states | F7, F15 | High |
| 6 | End-to-End REST Governance Daemon Lifecycle: POST ingest-policy, GET policy-version, POST validate-action, POST consume-seal, GET trace/verify | F3, F6, F9, F11, F13 | Critical |
| 7 | WebUI Live Observability & 0-Diff Parity: Load dashboard, render `#cage-governance-card`, verify live CBF indicator update and byte-level parity | F14 | Medium |
| 8 | Multi-Arm Lateral Containment with CAGE Gate: High-risk tool invocation blocked without active seal, passed with valid seal | F4, F6, F9, F11 | High |

---

## Coverage Thresholds
- **Tier 1 (Feature Coverage)**: ≥5 test cases per feature (15 × 5 = 75 tests)
- **Tier 2 (Boundary & Corner Cases)**: ≥5 test cases per feature (15 × 5 = 75 tests)
- **Tier 3 (Cross-Feature Combinations)**: ≥15 pairwise interaction tests
- **Tier 4 (Real-World Scenarios)**: 8 comprehensive application scenarios
- **Total Minimum Target**: ≥173 test cases
- **Acceptance Gate**: 100% pass across all tests with zero flaky runs.
