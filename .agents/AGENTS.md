# Project Rules & User Preferences

## Git Push Guardrails
- **Restricted Remotes:** NEVER run `git push` inside `IDE/vscode` or target any Microsoft/upstream third-party remote.
- **Canonical Repository:** ALL code pushes must strictly target `https://github.com/oyesanyf/OshoosiClaw.git`.

- **Zero-Wait Incremental Commits ("NO COMMIT SHOULD WAIT, WE MAY LOSE CODE CHANGE"):** Never leave verified code waiting uncommitted in the working tree across subtasks. Both lead agents and subagents must commit and ship incremental checkpoints immediately via `powershell -ExecutionPolicy Bypass -File scripts/solo_pr_ship.ps1 -Title "..."` and verify `git status -s` is clean before ending any turn.

- **Mandatory PR & GitHub Actions Workflow Remediation ("ALWAY FIX PR AND WORKFLOW ISSUES"):** Always check open Pull Requests and GitHub Actions workflow runs when shipping code. If any Pull Request is stuck or any GitHub Actions workflow (`.github/workflows/*.yml`) fails, immediately inspect the failed job logs, fix the broken workflow or check, and ensure the PR merges cleanly into `main`.
- **Multi-Developer Code Review & Branch Protection Policy:** GitHub Branch Protection enforces at least one approval (`required_approving_review_count = 1`) on `main`. As more developers join, any repository collaborator or peer developer can review and approve pull requests—`oyesanyf` does not personally have to approve every PR (`require at least one approve, it does not have to be me always, it can be another developer`). For automated release builds and maintainer PRs, `.githooks/post-commit` (`core.hooksPath = .githooks`) and `scripts/solo_pr_ship.ps1` ship commits via a temporary `pr/solo-<timestamp>` branch, verified by `.github/workflows/auto-review-bot.yml`, where approval from any peer developer or the bot satisfies Branch Protection and OpenSSF Scorecard `Code-Review` / `CI-Tests` checks. Step 8 of `scripts/build_and_submit.ps1` also invokes `scripts/solo_pr_ship.ps1`.

## Mandatory Automated Microsoft Submission on Every Build
- **User Preference:** "Each time the code is built, remember to send to Microsoft."
- **Trigger:** Whenever code is built, packaged, or released.
- **Enforcement:** Code artifacts MUST always be Authenticode signed (SHA-256 + RFC 3161 timestamp) and submitted to Microsoft Security Intelligence (WDSI) via `python scripts/submit_to_wdsi.py --all --no-launch` (orchestrated by `scripts/build_and_submit.ps1`).
- **Standard Command:** Use `powershell -ExecutionPolicy Bypass -File scripts/build_and_submit.ps1` as the canonical command to build, sign, package, and submit to Microsoft in one go.
- **Mandatory GitHub Release MSI Sync on Every Build:** Every time `OshoosiClaw.msi` is built and signed, it MUST also be uploaded to the latest GitHub Release (`https://github.com/oyesanyf/OshoosiClaw/releases/latest`) along with its updated `.intoto.jsonl`, `.sig`, and `.asc` attestations via `python scripts/update_github_release_msi.py` (automatically invoked by `scripts/build_and_submit.ps1`).

## Mandatory Full-Lifecycle Completion: Build All Packages, Fix Security, & Update Docs/Diagrams
- **User Requirement:** "remember to always build packages fix security update docs and diagrams"
- **1. Build All Release Packages (Windows, Linux, & Docker):** Whenever code, WebUI, or configuration changes are finalized, always build and verify all distribution targets:
  - **Windows:** `OshoosiClaw.msi` and signed release binaries via `scripts/build_and_submit.ps1`.
  - **Linux (WSL):** Compile `/root/osoosi-linux-target/release/osoosi`, package `.deb`, `.rpm`, and `.tar.gz` via `packaging/linux/build_packages.sh`, copy to `deploy/linux/`, and sync GPG-signed/DSSE-attested assets via `python scripts/update_github_release_msi.py`.
  - **Docker:** Build and verify the hardened multi-stage container (`docker build -t ghcr.io/oyesanyf/oshoosiclaw:1.2.0 .`) with digest-pinned base images, non-root `UID 65532:65532`, `0` SUID/SGID files, `--read-only` rootfs, `--cap-drop=ALL`, and `docker/seccomp-oshoosi.json`.
- **2. Proactive Security Audit & Zero Regressions:** Every change must be verified against authentication bypasses (`HttpOnly; SameSite=Strict` cookies, constant-time token comparison), async lock panics (never call `blocking_read()`/`blocking_write()` inside async Tokio tasks), and container/OS confinement invariants.
- **3. Documentation & Mermaid Diagrams Sync:** Every feature, security fix, or packaging update must update `README.md`, relevant security reports, and `mermaid` architecture diagrams before shipping the PR.

## Strict Invariant: PATH & Environment Variable Protection
- **User Requirement:** "my path must never ever be over wrote"
- **Zero-Overwrite Rule:** Under NO circumstance may any script, installer definition, registry operation, or code modification overwrite, replace, or truncate the user or system `PATH` or any environment variable.
- **WiX / MSI Invariant:** In all WiX manifests (`.wxs`), any `<Environment>` tag targeting `PATH` MUST have `Permanent="yes"` and `Part="last"`. Never use `Permanent="no"`, which generates destructive `-` deletion flags in the Windows Installer `Environment` table.
- **Scripting & Registry Invariant:** Never set `Path` in PowerShell without reading, preserving, and appending to the existing `Path` string.
- **Runtime Invariant:** The EDR engine and background daemons must never write to persistent Windows Registry environment hives (`HKLM` or `HKCU`).

## Strict Invariant: Production Code Only (No Mocks, No Naive Shortcuts)
- **User Requirement:** "dont ever make up mock code write actual code"
- **Zero-Mock Rule:** Under NO circumstance may any agent, subagent, or feature generate dummy placeholders, mock signatures, or synthetic shortcuts in place of genuine production functionality.
- **No Lazy Path Exclusions:** Never resolve false positives by adding blind directory or path string exclusions. Accuracy matters: always resolve root causes via genuine signature verification, Windows Catalog lookups, and decision model consensus.
- **Decision Model Integration:** All candidate detections and automated responses MUST be evaluated by the production decision models (Clef Decision Engine, Strands Decider, Threat Voters) rather than raw isolated heuristics.

## Windows WDAC / Device Guard Primary `signtool.exe` Invariant
- **Primary Signer Rule:** Always use the native Windows 10 SDK `signtool.exe` (`SHA-256` digest + DigiCert RFC 3161 timestamp) as the primary Authenticode signer for all `.exe`, `.dll`, and `.msi` artifacts. Never rely on `osslsigncode` as the primary signer on Windows, as Windows Device Guard / WDAC rejects non-standard PE signature tables.
- **Complete Binary Coverage & Verification:** Every build must sign both primary artifacts and all companion binaries in `target/release/` (`osoosi.exe`, `osoosi_inject.dll`, `osoosi-auditor.exe`, `otx-taxii-rs.exe`, `bulk_trainer.exe`, `test-peer.exe`) and assert `(Get-AuthenticodeSignature <path>).SignerCertificate -ne $null`.

## EDR Operational Evaluation & Full-Stack Telemetry Invariants
- **Monitor Mode vs. Enforce Mode Awareness:** When evaluating live attacks (`edr_tester.py`, Atomic Red Team, `rfc_hunt_swarm.py`), always check whether the daemon is running in **Monitor Mode** (`Action: Logged and Alerted`) or **Enforce Mode** (`Blocked / Quarantined / Process Terminated`). In Monitor Mode, verify detection efficacy via `Consensus Threat Identified` logs, SQLite `threats` / `consensus_findings` persistence, and P2P/Nostr mesh broadcasts.
- **Daemon Working-Directory Database Resolution:** Before querying SQLite during live monitoring, check the running `osoosi.exe` working directory (`Get-CimInstance Win32_Process`), as `database/osoosi.db` resolves relative to the process CWD (e.g., `target/release/database/osoosi.db` when launched from `target/release`).
- **DashMap Lock Hygiene:** Never call `.iter()` or `.get()` on a `DashMap` while holding a mutable `.entry()` or `.get_mut()` guard on the same map in the same task; always explicitly `drop(entry)` before iterating.
- **WebUI Parity Invariant:** Every modification to `dashboard/src/` (`index.html`, `app.js`, `styles.css`) must maintain `0 diff` parity with `dashboard/dist/`.

## Execution Blueprints (Flash Engine Constraints)
- **Trigger:** Applies ONLY when running high-speed/Flash models (e.g., Gemini Flash variants).
- **Exclusion:** Full-scale reasoning engines and simple/trivial single-line queries proceed normally without blueprints.

---

### Blueprint 1: Sandbox & Verify (Coding & Architecture)
1. **SANDBOX:** State implementation plan, required crates/dependencies, and 3 specific edge cases (e.g., Rust OOM/memory safety, TS disposable leaks, async deadlocks).
2. **VERIFY:** Detail how the design explicitly handles each identified edge case.
3. **OUTPUT:** Final code implementation with strict typing and error handling.

### Blueprint 2: Deconstruct & Solve (Math & Logic)
1. **EXTRACT:** List all raw data, variables, and constraints from the prompt.
2. **RULE:** State the exact formula or logic rule required.
3. **WORK:** Show step-by-step transformations.
4. **ANSWER:** Conclude with the final computed result (do not state the answer in the first line).

### Blueprint 3: Self-Correction (Debugging & Error Logs)
1. **TRACE:** Follow execution flow line-by-line to the point of failure.
2. **ISOLATE:** State the exact cause of the crash or syntax error.
3. **REFACTOR:** Provide the fixed code block highlighting the patch.

### Blueprint 4: Retrieve & Struct (Q&A & Technical Research)
1. **RETRIEVE:** Cite specific context sources, files, logs, or external docs referenced.
2. **CONTEXT:** Summarize key verified facts and remaining open variables.
3. **ANSWER:** Present a concise, scannable response using bullet points or tables.
## Cross-Repository Synchronization (`D:\harfile\AgentOctopus`) — Disabled
- **User Preference:** "no need to be sync agent octupus anymore"
- **Rule:** Do NOT synchronize changes to `D:\harfile\AgentOctopus`. Keep all development, packaging, and git pushes strictly scoped to `https://github.com/oyesanyf/OshoosiClaw.git`.

## Awesome Lists Community Traction Protocol (4 Verticals)
- **Vertical 1 (Direct EDR & Detection Engineering):** `shadawck/awesome-endpoint-detection-and-response`, `infosecB/awesome-detection-engineering`, `0x4D31/awesome-threat-detection`, `threat-hunting/awesome_Threat-Hunting`.
- **Vertical 2 (Blue Team, DFIR, Forensics & Reverse Engineering):** `fabacab/awesome-cybersecurity-blueteam`, `A-poc/BlueTeam-Tools`, `sbilly/awesome-security`, `meirwah/awesome-incident-response`, `cugu/awesome-forensics`, `dsopas/awesome-reverse-engineering`.
- **Vertical 3 (Rust & eBPF Systems Directories):** `rust-unofficial/awesome-rust`, `osirislab/awesome-rust-security`, `0xflotus/awesome-rust-security`, `qmonnet/awesome-ebpf`, `zoidbergwill/awesome-ebpf`, `aya-rs/awesome-aya`.
- **Vertical 4 (Specialized YARA Signature, Agentic AI Security & OpenClaw Lists):** `InQuest/awesome-yara`, `pedramamini/awesome-yara`, `corca-ai/awesome-ai-security`, `requie/awesome-ai-cybersecurity`, `machinae/awesome-claws`.
- **Automation Script:** Use `python scripts/submit_awesome_lists.py` (or `powershell -ExecutionPolicy Bypass -File scripts/submit_awesome_lists.ps1`) to inspect targets, generate category-tailored descriptions, and automate forked PR submissions across all four verticals.
