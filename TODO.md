# OpenỌ̀ṣọ́ọ̀sì (OshoosiClaw) — Open-Source Governance & Incubation Roadmap

This document outlines the 4-part open-source security, code quality, foundation incubation, and community review roadmap to graduate OpenỌ̀ṣọ́ọ̀sì into a recognized, world-class enterprise open-source security foundation standard.

---

## 1. Automated Security and Best Practices

### OpenSSF Scorecard & Supply-Chain Integrity
- [x] **OpenSSF Scorecard Workflow**: Deployed official OpenSSF Scorecard GitHub Action (`.github/workflows/scorecard.yml`) with pinned full-length commit SHAs and least-privilege `read-all` + `security-events: write` permissions.
- [x] **Automated Dependency Updates**: Configured Dependabot (`.github/dependabot.yml`) for weekly `cargo` and `github-actions` updates, satisfying OpenSSF `Dependency-Update-Tool` 10/10 criteria.
- [x] **Branch Protection & Code Review**: Enforce signed commits, branch protection rules on `main`, and pull request reviews.
- [ ] **OpenSSF Best Practices Badge**: Register repository on [bestpractices.dev](https://bestpractices.dev/) and complete all criteria to achieve the OpenSSF Passing and Silver Badges:
  - Documented vulnerability reporting process (`SECURITY.md`).
  - Automated continuous integration testing on all commits and PRs.
  - [x] Published cryptographic hash manifests (`SHA256SUMS.txt.asc`), SLSA v1.0 DSSE `.intoto.jsonl` provenance, GPG-signed Linux packages (`.deb`, `.rpm`, `.tar.gz`), and Authenticode-signed Windows `OshoosiClaw.msi` (`v1.2.0`).

---

## 2. Automated Code Quality and Static Analysis

### Multi-Engine Code Health & Maintainability
- [ ] **SonarCloud Continuous Quality Gate**:
  - Set up SonarCloud project integration at [sonarcloud.io](https://sonarcloud.io/).
  - Automate analysis across Rust (`cargo clippy`), TypeScript/JavaScript (`dashboard/`), and Python (`scripts/`).
  - Target: **Zero Code Smells, Zero Security Hotspots, and Maintainability Rating A**.
- [ ] **DeepSource / CodeFactor Integration**:
  - Configure automated style, complexity, and performance audits on every pull request.
  - Track cognitive complexity of consensus and Dempster-Shafer fusion algorithms.
- [x] **Hermetic Fuzzing & Gauntlets**:
  - Deployed ClusterFuzzLite continuous fuzzing (`.github/workflows/cifuzz.yml`, `fuzz/`) and 6-phase `/security-audit` schema verification (`validate-findings.cjs`, `validate-coverage-ledger.cjs`).

---

## 3. Foundation Incubation and Governance

### Cloud Native Computing Foundation (CNCF) Sandbox
- [x] **Maintainers & Governance**: Published [MAINTAINERS.md](MAINTAINERS.md) documenting core maintainers, review criteria, consensus protocols, and Emeritus guidelines.
- [x] **Open Governance & Code of Conduct**: Standardized project governance rules, security disclosures, and non-discriminatory participation.
- [ ] **CNCF Sandbox Application**:
  - Align license terms and intellectual property under standard open-source foundations (Apache 2.0 / MIT dual-license).
  - Submit official CNCF Sandbox application via GitHub issue on [cncf/sandbox](https://github.com/cncf/sandbox).
  - Present OpenỌ̀ṣọ́ọ̀sì decentralized endpoint telemetry and eBPF/WFP host defense to CNCF Security Technical Advisory Group (TAG-Security).

### Apache Software Foundation (ASF) Incubator
- [ ] **ASF Incubation Champion & Mentors**:
  - Identify ASF Member Champion and 3 IPMC (Incubator Project Management Committee) Mentors.
- [ ] **Formal ASF Proposal**:
  - Draft formal proposal following the ASF Incubator template: rationale, initial committers, scope, alignment with the Apache Way.
  - Submit proposal to `general@incubator.apache.org` with subject `[PROPOSAL] OpenOsoosi Incubation`.
  - Conduct IPMC discussion and call for vote (`[VOTE]` thread).

---

## 4. Community Peer Review and Usability

### Community Feedback & Peer Audit
- [ ] **Hacker News Launch (`Show HN`)**:
  - Title: *"Show HN: OpenỌ̀ṣọ́ọ̀sì – Autonomous, P2P Rust EDR with ML-KEM-768, Two-Tier Merkle & 101-Table Siquery (Windows & Linux)"*
  - Emphasize local model inference, zero telemetry exfiltration, 100/100 multi-sensor fusion, and self-hosted air-gapped capabilities.
- [ ] **Technical Subreddit Presentations**:
  - `r/rust`: Architecture deep-dive on safe concurrency, DashMap lock hygiene, two-tier BLAKE3 Merkle chains, NSRL/ASLR Merkle verification, and Windows SDK `signtool.exe` + Linux eBPF integration.
  - `r/netsec`: Technical analysis of Byzantine fault-tolerant mesh consensus, pre-operation kernel driver / eBPF LSM blocking, and adversarial evasion benchmarking.
  - `r/opensource`: Open-source endpoint security governance, reproducible builds, and CNCF/ASF incubation journey.
  - `r/programming` & `r/python`: Siquery-RS 101-table relational engine, OpenJev non-autoregressive decision model, and automated Microsoft Security Intelligence (WDSI) pipeline.
- [ ] **Product Hunt Maker Launch**:
  - Create interactive product demo highlighting the zero-config Windows Service installer (`OshoosiClaw.msi`), Linux `.deb`/`.rpm` packages, live WebUI dashboard, and 100/100 supervisor posture.


---

## 5. `.env` Secret Seal Reliability & Non-Invasive Shadow Vault Architecture

### Root-Cause Diagnosis: Why `.env` Seal Fails to Revert & Interferes with Applications
Audited across [`crates/osoosi-core/src/protected_env_backup.rs`](crates/osoosi-core/src/protected_env_backup.rs), [`crates/osoosi-dashboard/src/routes/env_gateway.rs`](crates/osoosi-dashboard/src/routes/env_gateway.rs), and [`crates/osoosi-core/src/orchestrator/init.rs`](crates/osoosi-core/src/orchestrator/init.rs):

1. **Silent Write Failures Followed by Destructive Vault Shredding (`remove_backup`)**:
   - In `ProtectedEnvBackupVault::auto_revert`, file restoration discards write errors (`let _ = Self::write_file_atomic(&p, &clean_bytes);`). If an IDE, Node/Python server, or Docker container holds a file lock on `.env` when clicking **Revert**, `write_file_atomic` fails silently while `auto_revert` returns `Ok(())`.
   - Immediately afterward, `post_env_gateway_revert`, `post_env_gateway_config`, and `post_env_gateway_toggle` unconditionally call `ProtectedEnvBackupVault::remove_backup(vp, true)`, zero-shredding `.vault` and `.dpapi` files even when `.env` on disk still contains `OSHOOSI_STANDIN_*` tokens.
2. **DACL / Privilege Mismatch (`os error 5`) Swallowed as `Ok(())`**:
   - When a vault is created by the elevated Windows Service (`NT AUTHORITY\SYSTEM`) with a restricted NTFS DACL (`D:P(A;;GA;;;SY)(A;;GA;;;BA)`), and a revert is triggered from a non-elevated CLI or process, `auto_revert_all_active_vaults` catches `ErrorKind::PermissionDenied` (`os error 5`), prints a warning, and returns `Ok(())`—leaving the vault un-reverted while reporting success.
3. **Background Watcher Re-Sealing Unsealed Files (`unseal-file` Race)**:
   - Unsealing a single file via `post_env_gateway_unseal_file` calls `revert_single_file` to restore that `.env` file on disk, **but does not add the file to an exclusion list**.
   - Within 2–10 seconds, either the dashboard watcher loop (`post_env_gateway_watch`) or the 10-second daemon discovery loop (`spawn_periodic_env_discovery`) scans the workspace, sees plaintext secrets in `.env` while `seal_enabled == true`, and **immediately re-seals the file back to `OSHOOSI_STANDIN_*`**.
4. **In-Place Disk Mutation Breaks External Apps (`dotenv`, Vite, Next.js, Python, Docker)**:
   - Because `seal_and_protect_with_policy` rewrites `.env` **in place on disk** with `OSHOOSI_STANDIN_<16-hex>` tokens, any external application, test runner, or container that reads `.env` directly from the filesystem (rather than routing through `osoosi env run` or the localhost `:19420` gateway) receives literal `OSHOOSI_STANDIN_*` strings instead of real API keys—causing `401 Unauthorized` failures across external tools.
5. **Orphaned Stand-In Tokens When `.vault` Is Missing**:
   - If a `.env` file already had `OSHOOSI_STANDIN_*` tokens from an earlier session whose `.vault` was deleted or overwritten, `seal_and_protect_with_policy` skips `OSHOOSI_STANDIN_*` values during sealing (`if val_trimmed.starts_with(STANDIN_PREFIX) { continue; }`), saving the stand-in token itself as the "original" baseline in the new vault.

### 4-Part Remediation Roadmap
- [ ] **1. Non-Invasive "Shadow Vault" Mode by Default (Zero `.env` Disk Mutation)**:
  - Introduce a `SealDiskMode` setting (`ShadowVaultOnly` vs. `InPlaceStandIn`) defaulting to **`ShadowVaultOnly` (`in_place_disk_replacement: false`)**:
    - **Shadow Vault (Default)**: Encrypts and backs up all `.env` secrets into the hardware-bound `.vault` / `.dpapi` enclave and enforces secret redaction in OshoosiClaw agent processes, logs, and LLM prompts, **without modifying `.env` files on disk**. External apps (`npm`, `cargo`, `pytest`, Docker, IDEs) continue reading `.env` with zero interference.
    - **Process-Scoped Stand-In Injection**: Inject `OSHOOSI_STANDIN_*` tokens only into untrusted child processes spawned by the agent sandbox (`Command::env`), never into the user's on-disk `.env` unless the user explicitly opts into strict `InPlaceStandIn` mode.
- [ ] **2. Verified Atomic Revert Gate (Never Shred Vault Before Verifying `.env` Restoration)**:
  - Refactor `ProtectedEnvBackupVault::auto_revert` and `write_file_atomic`:
    - Propagate every `io::Error` (including Windows `ERROR_SHARING_VIOLATION` `os error 32` and `ERROR_ACCESS_DENIED` `os error 5`) instead of ignoring with `let _ =`.
    - Add a 5-attempt exponential backoff retry (`50ms -> 800ms`) in `write_file_atomic` when another process briefly locks `.env`.
    - After writing restored bytes, **re-read the `.env` file from disk**, verify its SHA-256 matches the restored content and that zero `OSHOOSI_STANDIN_` tokens remain, and **only then** allow `remove_backup(vp, true)` to delete the `.vault`. If any file fails restoration, keep `.vault` intact and surface the exact locked file path in the WebUI.
- [ ] **3. Persistent Per-File Exclusion on `unseal-file`**:
  - Add `excluded_files: Vec<String>` to `EnvSealConfig` (`env_seal_config.json`).
  - When a user clicks **Unseal File** (`post_env_gateway_unseal_file`), canonically add that `.env` path to `excluded_files` so neither the 2-second watcher nor the 10-second orchestrator discovery loop re-seals it until the user explicitly clicks **Seal File** again.
- [ ] **4. Cross-Vault Stand-In Dictionary & `WM_SETTINGCHANGE` Broadcast**:
  - Maintain an encrypted append-only stand-in lookup ledger (`standin_recovery.vault`) mapping `OSHOOSI_STANDIN_<hash> -> original_ciphertext` so that even if a `.env` file was re-sealed while already containing stand-in tokens, `revert` can still recover the original secret from the ledger.
  - On Windows (`#[cfg(windows)]`), after reverting user registry environment variables (`HKCU\Environment`), broadcast `WM_SETTINGCHANGE` (`"Environment"`) with a 100ms timeout so running shells and IDEs pick up the reverted environment without requiring a logoff.
