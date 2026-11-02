# Project: Google Cybernetic Agent Governance Engine (CAGE) Native Substrate Integration

## Architecture
OshoosiClaw integrates Google's Cybernetic Agent Governance Engine (CAGE) as a native production cybernetic governance substrate. It provides deterministic two-phase policy enforcement, discrete-time exponential Control Barrier Functions (CBF), single-use 30-second TTL cryptographic routing seals, formal 34-state BFS verification of `NoDirectBind`, stream invariant auditing, REST API/WebUI observability, and automated CI/CD governance gates.

```
External Policy Formats
[Microsoft ACS, Linux Foundation AAIF, NIST OSCAL 1.1.x, Lula, Native CAGE STPA]
                                 │
                                 ▼
         [ Multi-Format Policy Auto-Detection & Compiler ]
         (Deterministic 16-hex SHA-256 Version Pinning, 409 Conflict)
                                 │
                                 ▼
   ┌──────────────────────────────────────────────────────────────────┐
   │       2-Phase, 7-Tier Deterministic Governance Pipeline          │
   │                                                                  │
   │  [ Phase 1: Read-Only Verification (No State Mutation) ]         │
   │  - Tier 1: Fast Tier Risk Assessment (FTRA)                      │
   │  - Tier 2: STPA 7-Hazard Safety Invariant Matrix                 │
   │  - Tier 3: Cedar / OPA Formal Authorization                      │
   │  - Tier 4: SR 26-2 Model Confidence Scoring (>=0.95/0.70)        │
   │  - Tier 5: Bayesian Multi-Detector Consensus Check               │
   │                                                                  │
   │  [ Phase 2: Atomic State Mutation & Actuation Ledger ]           │
   │  - Tier 6: Discrete-Time Exponential Control Barrier Function:   │
   │            h_{t+1} = (B_t - c) - B_min >= (1 - gamma)*h_t >= 0   │
   │            (Zero fiscal leakage on denial, fuel pre-reservation) │
   │  - Tier 7: Cryptographic Routing Seal Issuance (30s TTL, single) │
   └──────────────────────────────────┬───────────────────────────────┘
                                      │ Verdict: ALLOW / NARROW / REQUIRE_APPROVAL / DEFER / DENY
                                      ▼
                        ┌───────────────────────────┐
                        │ Cryptographic Routing Seal │
                        └─────────────┬─────────────┘
                                      │
            ┌─────────────────────────┴─────────────────────────┐
            ▼                                                   ▼
┌───────────────────────────────┐               ┌───────────────────────────────┐
│ Host Capability Gate (Sandbox)│               │ Cryptographic Audit Trail     │
│ - validate_and_consume_seal() │               │ - RFC 8785 JCS Canonical JSON │
│ - Enforces NoDirectBind       │               │ - cage-audit/3.0 Hash Chaining│
│ - Single-use 30-second TTL    │               │ - MerkleAuditTree Anchoring   │
│ - High-risk actuation gate    │               │ - SQLite State Persistence    │
└───────────────────────────────┘               └───────────────────────────────┘
            │                                                   │
            ▼                                                   ▼
[ Wasm/Host Actuation Execution ]               [ REST API / WebUI Observability ]
                                                (Port 3030 endpoints & WebUI Card)
```

---

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | Multi-Format Policy Auto-Detection | Auto-detect ACS (`behaviorDeclarations`), AAIF (`governedRunLoop`), OSCAL 1.1.x (`oscal-version`), Lula (`kind: LulaValidation`), and native CAGE STPA YAML/JSON | M1 | Survey Spec & R1 |
| 2 | Cedar & STPA UCA Policy Compilation | Compile external format ASTs into native Cedar authorization rules and STPA Unsafe Control Actions (UCAs) | M1 | Survey Spec & R1 |
| 3 | Deterministic 16-Char Hex Version Pinning | Derive 16-hex lowercase SHA-256 version ID via RFC 8785 JCS canonicalization; enforce HTTP 409 Conflict on version mismatch | M1 | Survey Spec & R1 |
| 4 | Phase 1 Read-Only Governance Pipeline | Non-mutating verification: FTRA, STPA 7-hazards, Cedar/OPA, SR 26-2 confidence scoring, and Bayesian consensus | M2 | Survey Spec & R2 |
| 5 | Phase 2 Discrete-Time Exponential CBF | Exponential barrier: $h_{t+1} = (B_t - c) - B_{\min} \ge (1-\gamma)h_t \ge 0$, fiscal pre-reservation, zero budget leakage on denial, LIFO rollback | M2 | Survey Spec & R2 |
| 6 | Canonical Verdicts & Routing Seal Issuance | Output `ALLOW`, `NARROW`, `REQUIRE_APPROVAL`, `DEFER`, `DENY`; issue 30-second TTL single-use cryptographic routing seal on approved actions | M2 | Survey Spec & R2 |
| 7 | Pure-Rust 34-State BFS Formal Model | Exhaustive BFS model proving `NoDirectBind` theorem (34 gated reachable states, 1 EXECUTED state, 0 direct-bind violations vs 17 ungated counterexample states) | M3 | Survey Spec & R3 |
| 8 | Stream Invariant Verifier | Enforce 5 CAGE stream invariants (`no_direct_bind`, `cbf_barrier`, `seal`, `cbf_rollback`, `refusal_evidence`) with 64-hex SHA-256 digests | M3 | Survey Spec & R3 |
| 9 | Host Capability Gate Routing Seal Enforcement | Validate and atomically consume 30-second single-use routing seal in `host_capability_gate.rs` before high-risk actuation (`NoDirectBind`) | M4 | Survey Core & R4 |
| 10 | RFC 8785 JCS Canonical JSON Formatter | Zero-dependency RFC 8785 JSON Canonicalization Scheme implementation for deterministic hashing | M5 | Survey Core & R5 |
| 11 | Audit Trail & Merkle Tree Anchoring | Emit hash-chained `cage-audit/3.0` & `GOVERNANCE_TRACE` records anchored into `MerkleAuditTree` | M5 | Survey Core & R5 |
| 12 | SQLite CAGE State Persistence | Create and manage `cage_policies`, `cage_routing_seals`, and `cage_governance_traces` in `MemoryStore` | M5 | Survey UI & R5 |
| 13 | Substrate Contract v1.0 REST API | Dedicated `routes/cage.rs` submodule on port 3030: `/governance/ingest-policy`, `/governance/policy-version`, `/governance/validate-action`, `/governance/consume-seal`, `/governance/rollback`, `/governance/trace/verify` + `/api/governance/*` | M6 | Survey UI & R6 |
| 14 | WebUI Governance Substrate Card & Parity | Interactive `#cage-governance-card` in `dashboard/src/` and `dashboard/dist/` with 0-diff parity | M6 | Survey UI & R6 |
| 15 | Consolidated CI/CD Governance Workflow | `.github/workflows/cage-governance-gate.yml` consolidating TLC model check, policy drift check, compliance audit stream, and license guard | M7 | Sentinel R7 Directive |
| 16 | E2E Test Suite Execution & Adversarial Hardening | Execute 4-tier requirement-driven E2E test suite + Tier 5 adversarial coverage hardening | M8 | Dual Track & R8 |
| 17 | Production Release Build, Signing & Solo PR Ship | Authenticode sign all binaries via Windows SDK `signtool.exe`, package `OshoosiClaw.msi`, WDSI submission, and ship via `solo_pr_ship.ps1` | M9 | User Rules & R8 |

---

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | Multi-Format Policy Ingestion & Version Pinning | Features 1–3: ACS, AAIF, OSCAL, Lula, CAGE STPA auto-detection, Cedar/UCA compiler, 16-hex version pinning, 409 conflict | none | DONE (Gate PASS) |
| M2 | Deterministic 2-Phase Governance & CBF Pipeline | Features 4–6: Phase 1 read-only checks, Phase 2 exponential CBF & fiscal fuel pre-reservation, canonical verdicts, 30s TTL routing seal | M1 | DONE (Gate PASS) |
| M3 | Formal BFS State Model & Stream Invariant Verifier | Features 7–8: Pure-Rust 34-state BFS model proving NoDirectBind (34 vs 17 states), 5 stream invariants with 64-hex lowercase receipts | M1, M2 | DONE (Gate PASS) |
| M4 | Host Capability Gate Routing Seal Enforcement | Feature 9: `host_capability_gate.rs` integration, single-use 30s TTL seal validation & consumption, NoDirectBind enforcement | M2 | DONE (Gate PASS) |
| M5 | Audit Trail & SQLite State Persistence | Features 10–12: Pure-Rust RFC 8785 JCS, `cage-audit/3.0` & `GOVERNANCE_TRACE` hash chaining, Merkle tree anchoring, SQLite tables | M2 | DONE (Gate PASS) |
| M6 | Substrate REST API & WebUI Observability | Features 13–14: Dedicated `routes/cage.rs` on port 3030, all contract endpoints + aliases, `#cage-governance-card` with 0-diff WebUI parity | M1, M2, M4, M5 | DONE (Gate PASS) |
| M7 | CI/CD Governance & Verification Workflows | Feature 15: `.github/workflows/cage-governance-gate.yml` (tlc-model-check, policy-compile-drift, compliance-audit-stream, license-guard) | M1, M3, M5 | DONE (Gate PASS) |
| M8 | Final Milestone: E2E Test Suite Pass (Tiers 1-4) & Adversarial Coverage Hardening (Tier 5) | Feature 16: Pass 100% of E2E requirement test suite across Tiers 1-4, followed by Tier 5 Challenger adversarial hardening | M1–M7, TEST_READY.md | DONE (Gate PASS) |
| M9 | Production Packaging, Authenticode Signing & Solo PR Shipping | Feature 17: Build release binaries, Windows SDK `signtool.exe` signing, `OshoosiClaw.msi`, WDSI submission, and `solo_pr_ship.ps1` | M8 | DONE (Gate PASS) |

---

## Interface Contracts

### 1. Shared Types (`crates/osoosi-types/src/cage.rs`)
```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GovernanceVerdict {
    Allow,
    Narrow { clamped_params: serde_json::Value },
    RequireApproval { reason: String, approval_token: String },
    Defer { backoff_ms: u64 },
    Deny { reason: String, proof_hash: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutingSeal {
    pub seal_id: String,
    pub policy_version_id: String, // 16-hex
    pub action_digest: String,     // 64-hex SHA-256
    pub issued_at: u64,           // Unix epoch seconds
    pub expires_at: u64,          // issued_at + 30s
    pub signature: String,        // HMAC-SHA256 hex
}
```

### 2. Multi-Format Policy Compiler (`crates/osoosi-policy/src/cage/policy_ingest.rs`)
```rust
pub enum PolicyFormat {
    MicrosoftAcs,
    LinuxFoundationAaif,
    NistOscal,
    LulaValidation,
    CageStpa,
}

pub struct CompiledCagePolicy {
    pub policy_version_id: String, // 16-hex
    pub format: PolicyFormat,
    pub raw_content: String,
    pub cedar_rules: Vec<String>,
    pub unsafe_control_actions: Vec<UnsafeControlAction>,
    pub cbf_gamma: f64,
    pub cbf_b_min: f64,
}
```

### 3. Control Barrier Function (`crates/osoosi-policy/src/cage/cbf.rs`)
```rust
pub struct ControlBarrierFunction {
    pub gamma: f64,
    pub b_min: f64,
}

impl ControlBarrierFunction {
    /// h_{t+1} = (B_t - cost) - B_min >= (1 - gamma) * h_t >= 0
    pub fn evaluate_step(&self, current_budget: f64, cost: f64, current_h: f64) -> Result<f64, CbfViolation>;
}
```

### 4. Routing Seal Verifier (`crates/osoosi-sandbox/src/host_capability_gate.rs`)
```rust
pub trait RoutingSealVerifier: Send + Sync {
    /// Validates seal signature, policy version, action digest, TTL (30s), and consumes single-use nonce
    fn validate_and_consume(&self, seal: &RoutingSeal, expected_action_digest: &str) -> Result<(), SealRejection>;
}
```

---

## Code Layout
- `crates/osoosi-types/src/cage.rs`: Shared types (`RoutingSeal`, `GovernanceVerdict`, `StageOutcome`, `CbfParameters`).
- `crates/osoosi-policy/src/cage/`:
  - `mod.rs`: Public API re-exports for the CAGE governance substrate.
  - `policy_ingest.rs`: Multi-format parser, auto-detector, Cedar/UCA compiler, 16-hex version generator.
  - `pipeline.rs`: 2-Phase 7-tier deterministic governance pipeline.
  - `cbf.rs`: Discrete-time exponential Control Barrier Function & fiscal ledger.
  - `routing_seal.rs`: 30-second TTL single-use cryptographic seal generator & verifier.
  - `formal_model.rs`: Pure-Rust 34-state BFS model proving `NoDirectBind`.
  - `stream_verifier.rs`: 5-stream invariant verifier with 64-hex receipts.
- `crates/osoosi-policy/src/breakout/`:
  - Submodules decomposing `breakout_gate.rs` with 100% public re-export compatibility.
- `crates/osoosi-sandbox/src/host_capability_gate.rs`: Routing seal enforcement (`NoDirectBind`).
- `crates/osoosi-audit/src/canonical_json.rs`: RFC 8785 JCS canonical formatting.
- `crates/osoosi-memory/src/lib.rs`: Tables `cage_policies`, `cage_routing_seals`, `cage_governance_traces`.
- `crates/osoosi-dashboard/src/routes/cage.rs`: REST handlers for CAGE Substrate Contract v1.0.
- `dashboard/src/` & `dashboard/dist/`: `#cage-governance-card` with 0-diff parity.
- `.github/workflows/cage-governance-gate.yml`: Consolidated CI/CD governance gate.
- `tests/e2e_cage_governance/`: Opaque-box E2E test suite across Tiers 1-4.
