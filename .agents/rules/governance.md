---
description: Enforce Gemini 3.1 Pro lead governance with Gemini 3.7 Flash multi-pass execution
trigger: always_on
model: gemini-3.1-pro
---

# Architecture & Governance Protocol

1. **Model Roles & Hierarchy**:
   - **Lead Architect (Gemini 3.1 Pro)**: Manage high-level reasoning, architecture decomposition, test strategies, and final verification.
   - **Worker Subagent (Gemini 3.7 Flash)**: Delegate all code editing, script generation, and terminal runs using the `invoke_subagent` tool. Set the `Model` argument to `flash` and give it a descriptive `Role` (e.g., 'Worker Subagent'). 

2. **Mandatory Iterative Loop**:
   - For all complex, low-level, or kernel-space engineering tasks, do not accept single-shot solutions.
   - **Pass 1 (Decomposition)**: Pro breaks down the task into precise functional boundaries and test criteria.
   - **Pass 2 (Execution)**: The Flash subagent implements the patch and runs validation commands.
   - **Pass 3 (Review & Iteration)**: Pro verifies the diffs; if any checks or edge cases fail, return the feedback to the Flash subagent (using `send_message`) for iteration until green.

3. **Mandatory Automated Microsoft Submission & Primary `signtool.exe` WDAC Signing**:
   - **User Preference**: "Each time the code is built, remember to send to Microsoft."
   - Every build of release binaries or installer packages MUST automatically code-sign all target and companion binaries with native Windows SDK `signtool.exe` (SHA-256 + DigiCert RFC 3161 timestamp), verify `SignerCertificate != null` so Windows Device Guard / WDAC never blocks execution, and submit them to Microsoft Security Intelligence (WDSI).
   - Use `scripts/build_and_submit.ps1` as the canonical unified release build command, which automatically compiles `osoosi-cli`, re-signs configs, generates the MSI installer, signs all binaries, invokes `python scripts/submit_to_wdsi.py --all --no-launch`, and uploads the signed MSI and SLSA provenance to GitHub Releases via `python scripts/update_github_release_msi.py`.
   - **Mandatory GitHub Release MSI Sync on Every Build:** Every time `OshoosiClaw.msi` is built and signed, it MUST also be uploaded to the latest GitHub Release (`https://github.com/oyesanyf/OshoosiClaw/releases/latest`) along with its updated `.intoto.jsonl`, `.sig`, and `.asc` attestations via `python scripts/update_github_release_msi.py` (automatically invoked by `scripts/build_and_submit.ps1`).
   - Never release or produce an unsubmitted binary artifact.

4. **Strict Invariant: Zero Environment Overwrites (PATH Immutability)**:
   - **User Preference:** "my path must never ever be over wrote"
   - Every installer package, build script, and code modification must preserve all existing user and system environment variables.
   - WiX environment components for `PATH` must strictly be `Permanent="yes"`.

5. **Multi-Developer Code Review & Branch Protection Policy**:
   - GitHub Branch Protection enforces at least one approval (`required_approving_review_count = 1`) on `main`.
   - As more developers join, any repository collaborator or peer developer can review and approve pull requests—`oyesanyf` does not personally have to approve every PR (`require at least one approve, it does not have to be me always, it can be another developer`).
   - For automated commits and maintainer PRs, `.githooks/post-commit` (configured via `core.hooksPath = .githooks`) and `scripts/solo_pr_ship.ps1` move commits to a temporary `pr/solo-<timestamp>` branch, open a PR verified by `.github/workflows/auto-review-bot.yml`, and approval from any peer developer or the bot satisfies Branch Protection and OpenSSF Scorecard `Code-Review` and `CI-Tests` checks.

6. **Mandatory Full-Lifecycle Deliverable Gate (Packages + Security + Docs & Diagrams)**:
   - **User Preference**: "remember to always build packages fix security update docs and diagrams"
   - Every completed task must:
     1. **Build & Sync All Packages**: Rebuild Windows (`OshoosiClaw.msi`), Linux (`.deb`, `.rpm`, `.tar.gz` via WSL `packaging/linux/build_packages.sh`), and the hardened Docker image (`ghcr.io/oyesanyf/oshoosiclaw:1.2.0`), and sync signed release assets to GitHub Releases.
     2. **Verify Security Invariants**: Audit for zero auth regressions, zero token leaks, zero async `blocking_read()`/`blocking_write()` panics, and strict non-root (`65532:65532`) read-only container confinement.
     3. **Update Documentation & Diagrams**: Update `README.md` and `mermaid` architecture diagrams to reflect all new capabilities, security hardening, and packaging workflows.

7. **Strict Invariant: Zero-Wait Incremental Commits, Mandatory Security Remediation During Solo Process, & Nightly Scheduled RAPTOR Audits**:
   - **User Preferences**: `"NO COMMIT SHOULD WAIT , WE MAY LOSE CODE CHANGE"`, `"ALWAY FIX PR AND WORKFLOW ISSUES"`, and `"DURING THE SOLO PROCESS ALL SECURITY ISSUES MUST BE FIXED"`.
   - Commit and ship incremental checkpoints immediately via `scripts/solo_pr_ship.ps1` rather than batching uncommitted changes across long runs; verify `git status -s` is empty at the end of every turn.
   - Continuously check open Pull Requests and GitHub Actions workflow runs; immediately diagnose and fix any failing GitHub Actions workflow, CI check, or blocked PR until merged and green.
   - **Mandatory Solo-Process Security Fix Gate**: During every solo PR ship cycle (`scripts/solo_pr_ship.ps1`), all RAPTOR Security Audit (`SAST + Post-Quantum Crypto + SCA`) findings and security vulnerabilities MUST be inspected and fixed before merge; never allow a RAPTOR run to pass with `0` SARIF files parsed.
   - **Nightly Scheduled Execution**: RAPTOR runs automatically every night at `02:30` both via GitHub Actions cron (`30 2 * * *` in `.github/workflows/raptor-security.yml`) and via the local Windows Scheduled Task `OshoosiClaw-Nightly-Raptor-Security-Audit` (`scripts/run_nightly_raptor_audit.ps1`).

## Cross-Repository Synchronization (`D:\harfile\AgentOctopus`) — Disabled
- **User Preference:** "no need to be sync agent octupus anymore"
- **Rule:** Do NOT synchronize changes to `D:\harfile\AgentOctopus`. Keep all development, packaging, and git pushes strictly scoped to `https://github.com/oyesanyf/OshoosiClaw.git`.

## Awesome Lists Community Traction Protocol � Disabled (Strictly Forbidden)
- **User Preference:** "STOP CREATING ALL THESE AWESOME LISTS TOO MAY AND THEY ARE SHOW UP AS REPO IN MY REPO"
- **Strict Rule:** NEVER fork, clone, or create any `awesome-*` list repositories (or `BlueTeam-Tools`, `reverse-engineering`, etc.) under `oyesanyf`, and NEVER run automated awesome-list PR scripts. Keep the `oyesanyf` GitHub account completely free of third-party awesome-list forks.