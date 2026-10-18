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

5. **Solo-Developer Auto-Review Bot & Post-Commit PR Workflow**:
   - Because `oyesanyf` is the solo developer and repository administrator, GitHub forbids developers from approving their own pull requests.
   - All commits on `main` automatically trigger `.githooks/post-commit` (configured via `core.hooksPath = .githooks`), which invokes `scripts/solo_pr_ship.ps1`.
   - The workflow moves the commit to a temporary `pr/solo-<timestamp>` branch, opens a GitHub PR, triggers `github-actions[bot]` via `.github/workflows/auto-review-bot.yml` to verify identity and security invariants, submits an official `APPROVED` review, and squash-merges into `main`.
   - This satisfies GitHub Branch Protection requirements and maintains 10/10 on OpenSSF Scorecard `Code-Review` and `CI-Tests` checks.

6. **Mandatory Full-Lifecycle Deliverable Gate (Packages + Security + Docs & Diagrams)**:
   - **User Preference**: "remember to always build packages fix security update docs and diagrams"
   - Every completed task must:
     1. **Build & Sync All Packages**: Rebuild Windows (`OshoosiClaw.msi`), Linux (`.deb`, `.rpm`, `.tar.gz` via WSL `packaging/linux/build_packages.sh`), and the hardened Docker image (`ghcr.io/oyesanyf/oshoosiclaw:1.2.0`), and sync signed release assets to GitHub Releases.
     2. **Verify Security Invariants**: Audit for zero auth regressions, zero token leaks, zero async `blocking_read()`/`blocking_write()` panics, and strict non-root (`65532:65532`) read-only container confinement.
     3. **Update Documentation & Diagrams**: Update `README.md` and `mermaid` architecture diagrams to reflect all new capabilities, security hardening, and packaging workflows.
