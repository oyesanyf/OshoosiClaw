# Project: OpenỌ̀ṣọ́ọ̀sì (`OshoosiClaw`) — EDR Voter Consensus Routing, RAPTOR Pentest, Security Remediation & Multi-Platform Packaging

## Architecture
OpenỌ̀ṣọ́ọ̀sì (`OshoosiClaw`) combines a 7-Ring Continuous Cedar Reference Monitor, Universal REA (Reverse Engineer Anything) voting across all 8 detectors, multi-voter Bayesian consensus pipeline, RAPTOR autonomous penetration testing, GitHub Actions CI health, and automated multi-platform release packaging.

```
Candidate Telemetry Across All 8 Detectors
[Process/ETW, Malware/YARA, HAR/Net, DLP, Agent/Align, CVE/SCA, Memory/Shield, P2P/Mesh]
                                    │
                                    ▼
       [ Universal REA Voter: global_rea_engine().cast_consensus_vote(...) ]
       (BLAKE3 seal, binary/evidence deconstruction, universal_coverage_snapshot)
                                    │
                                    ▼
   ┌──────────────────────────────────────────────────────────────┐
   │         Multi-Voter Decision Consensus Pipeline             │
   │  ┌─────────────────────────┐  ┌───────────────────────────┐  │
   │  │   ReaVoter / OpenJev    │  │ Clef Decision Model Voter │  │
   │  │    (Structural/PE/DLP)  │  │  (SystemOne, Strands SLM) │  │
   │  └─────────────────────────┘  └───────────────────────────┘  │
   │  ┌─────────────────────────┐  ┌───────────────────────────┐  │
   │  │ Behavioral Process      │  │ Threat Voters (Static,    │  │
   │  │ Lineage Voter           │  │  Entropy, Heuristic,      │  │
   │  │ (ProcessTreeEmbedder,   │  │  AMSI, ETW, Memory)       │  │
   │  │ CoLog, CausalGraph)     │  │                           │  │
   │  └─────────────────────────┘  └───────────────────────────┘  │
   └──────────────────────────────┬───────────────────────────────┘
                                  │ Consensus Adjudication
                                  ▼
               ┌──────────────────────────────────────┐
               │ Ring 7 Cedar Capability/Effect Gate  │
               └──────────────────┬───────────────────┘
                                  │
                   ┌──────────────┴──────────────┐
                   ▼                             ▼
         [ Automated Containment ]        [ Audit & Mesh ]
         (Process Kill, WFP Block,        (OpenLineage, SQLite,
          AppContainer Severing)           Nostr/GossipSub Broadcast)
```

---

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | Event 9995 5-Sigma Voter Routing | Route frozen forensic snapshot events through REA and voter consensus before containment | M1 | Survey 1, R2 |
| 2 | Sysmon Event 10 Shield Routing | Route process access violations through REA and voter consensus instead of immediate block | M1 | Survey 1, R2 |
| 3 | Behavioral Anomaly Autotomy Routing | Route `AgentAnomalyDetector` findings through voter consensus before branch severing | M1 | Survey 1, R2 |
| 4 | `already_multi_voter` String Check Fix | Eliminate `aad-` and `dlp_` bypasses in `query.rs:1438` to enforce full voter quorum | M1 | Survey 1, R2 |
| 5 | `BehavioralProcessLineageVoter` Implementation | Unified `ThreatVoter` combining `ProcessTreeEmbedder` (Candle 128d), `CoLogFilter`, `DynamicAgentClassifier`, and `CausalSecurityGraph` | M1 | Survey 1, R2 |
| 6 | `ClefDecisionVoter` Implementation | Active `ThreatVoter` wrapping `ClefDecisionEngine` (SystemOne OpenJEV, Strands Decider, Cloudflare, local fallback) | M1 | Survey 1, R2 |
| 7 | Universal REA Voting Across 8 Detectors | `[REA-Voter]` actively votes across Process/ETW, Malware/YARA, HAR/Net, DLP, Agent/Align, CVE/SCA, Memory/Shield, P2P/Mesh; verify `universal_coverage_snapshot()` | M1 | User Mandate, R2 |
| 8 | Voter Registration & Classification | Register new voters in `post_init_voters` and map in `classify_vote` with `EvidenceClass::Behavior` | M1 | Survey 1, R2 |
| 9 | Voter Routing & Consensus Tests | Verify voter consensus routing, active behavioral voting, and 8-detector REA coverage via unit/integration tests and `edr_tester.py` | M1 | Survey 1, R2 |
| 10 | RAPTOR Scan Execution | Run RAPTOR penetration test (`raptor_scan_project` / `Invoke-RaptorScan.ps1`) with Ollama `foundation-sec-8b` | M2 | Survey 2, R3 |
| 11 | Security Audit Validation Engine | Apply 5-phase validation protocol (TP vs FP) across Critical, High, Medium, Low, Informational tiers | M2 | Survey 2, R3 |
| 12 | Findings Ledger & Schema Validation | Record findings in `findings.json` and validate with `validate-findings.cjs` and `validate-coverage-ledger.cjs` | M2 | Survey 2, R3 |
| 13 | Critical & High Severity Remediation | Surgical fixes at trusted decision points for confirmed RCE, containment defeat, or auth bypass | M3 | Survey 2, R4 |
| 14 | Medium & Low Severity Remediation | Refactor unhandled panics (`?`/defensive match), constant-time comparisons, and parameterized commands | M3 | Survey 2, R4 |
| 15 | Informational Remediation & Hygiene | Structured prompt envelopes, sanitized error logging, and defense-in-depth annotations | M3 | Survey 2, R4 |
| 16 | GitHub Actions Workflow Remediation | Inspect `gh run view 40791535914` and `40791492405`, fix failing workflows in `.github/workflows/` ensuring 100% green CI | M3 | User Directive, R4 |
| 17 | Full-Stack Regression Verification | Run cargo check, clippy, cargo test, WebUI parity, and `verify_port_3030_e2e.py` | M3 | Survey 2, R4 |
| 18 | Cross-Repository Synchronization | Synchronize security controls, containment logic, and rules to `D:\harfile\AgentOctopus` | M3 | Survey 2, R4 |
| 19 | Windows MSI Build, Signing & WDSI Submission | WiX v5 MSI with permanent append-only PATH, native SDK `signtool.exe` signing, and WDSI submission | M4 | Survey 3, R5 |
| 20 | Linux Packaging & Provenance | Verify `.deb`, `.rpm`, `.tar.gz`, stripped ELF, OpenPGP signatures, and DSSE provenance in `deploy/linux/` | M4 | Survey 3, R5 |
| 21 | macOS Universal Release Archive | Package `oshoosiclaw-1.2.0-darwin-universal.tar.gz` with `launchd` plist, `install.sh`, and GPG/DSSE attestations in `deploy/macos/` | M4 | Survey 3, R5 |

---

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | REA & Decision Voter Consensus Routing with Behavioral Engine Voter | Features 1–9: Bypass elimination, `BehavioralProcessLineageVoter`, `ClefDecisionVoter`, universal 8-detector REA voting, `universal_coverage_snapshot()`, `query.rs` refactor, consensus integration tests | none | IN_PROGRESS |
| M2 | RAPTOR Penetration Testing & Security Audit Validation | Features 10–12: Pre-flight checks, RAPTOR scan across 39 crates, 5-phase audit validation, `findings.json` ledger | M1 | PLANNED |
| M3 | Comprehensive Vulnerability Remediation, CI Workflow Fix & Code Commit | Features 13–18: 100% remediation of confirmed findings across all severity levels, fix failing GitHub Actions workflows in `.github/workflows/`, zero regressions, AgentOctopus sync, PR ship | M2 | PLANNED |
| M4 | Multi-Platform Release Artifact Packaging | Features 19–21: Windows MSI signing/WDSI submission, Linux package verification, macOS universal archive & launchd daemon, release sync | M3 | PLANNED |

---

## Interface Contracts

### `ThreatVoter` Trait (`crates/osoosi-policy/src/engine.rs`)
```rust
#[async_trait::async_trait]
pub trait ThreatVoter: Send + Sync {
    fn name(&self) -> String;
    async fn vote(&self, event: &HostSecurityEvent) -> Option<VoteResult>;
}

pub struct VoteResult {
    pub confidence: f32,
    pub reason: String,
    pub weight: f32, // Positive = malicious, Negative = certified benign veto
}
```

### Universal 8-Detector REA Voting Contract
```rust
// Casts recorded vote with BLAKE3 seal across all 8 detectors:
// 1. Process/ETW/CLI
// 2. Malware/YARA
// 3. HAR/Network
// 4. DLP
// 5. Agent/Alignment
// 6. CVE/SCA
// 7. Siquery / Memory / Shield
// 8. P2P / Nostr Mesh
pub fn cast_consensus_vote(...) -> Option<VoteResult>;
pub fn universal_coverage_snapshot() -> CoverageSnapshot; // All 8 detectors > 0
```

---

## Code Layout
- `crates/osoosi-core/src/voters.rs` (or `rea/voters.rs`): `BehavioralProcessLineageVoter`, `ClefDecisionVoter`, `ReaVoter`, `OpenJevVoter`.
- `crates/osoosi-core/src/rea/`: `global_rea_engine().cast_consensus_vote(...)` across all 8 detectors.
- `crates/osoosi-core/src/orchestrator/event_pipeline.rs`: Telemetry ingestion, containment gating, consensus adjudication.
- `crates/osoosi-core/src/orchestrator/query.rs`: `adjudicate_threat_signature_with_rea_and_voters` and multi-voter routing.
- `crates/osoosi-core/src/orchestrator/init.rs`: `post_init_voters` registration into `PolicyEngine`.
- `crates/osoosi-agent-anomaly/src/detector.rs`: Anomaly detection and non-premature autotomy emission.
- `crates/osoosi-policy/src/engine.rs`: `PolicyEngine`, `classify_vote`, consensus aggregation.
- `scripts/Invoke-RaptorScan.ps1`: Automated RAPTOR pentest execution script.
- `~/.security-audit-skill/OshoosiClaw/run-4/`: Security audit findings ledger and coverage matrix.
- `.github/workflows/*.yml`: CI and release workflows.
- `scripts/build_and_submit.ps1`: Windows release build, WiX v5 packaging, SDK `signtool.exe` signing, and WDSI submission.
- `packaging/linux/build_packages.sh`: Linux `.deb`, `.rpm`, `.tar.gz`, and standalone ELF build.
- `packaging/macos/build_packages.sh`: macOS portable archive packaging script.
- `deploy/windows/`, `deploy/linux/`, `deploy/macos/`: Distribution directories with GPG signatures and DSSE in-toto provenance.
- `D:\harfile\AgentOctopus`: Cross-repository synchronized codebase.
