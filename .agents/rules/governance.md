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

7. **Strict Invariant: Zero-Wait Incremental Commits & PR/Workflow Health**:
   - **User Preferences**: `"NO COMMIT SHOULD WAIT , WE MAY LOSE CODE CHANGE"` and `"ALWAY FIX PR AND WORKFLOW ISSUES"`.
   - Commit and ship incremental checkpoints immediately via `scripts/solo_pr_ship.ps1` rather than batching uncommitted changes across long runs; verify `git status -s` is empty at the end of every turn.
   - Continuously check open Pull Requests and GitHub Actions workflow runs; immediately diagnose and fix any failing GitHub Actions workflow, CI check, or blocked PR until merged and green.

## Mandatory Cross-Repository Synchronization (`D:\harfile\AgentOctopus`)
- **User Preference:** "alway update agentoctopus when you update here"
- **Rule:** Whenever security controls, containment rings, breakout defenses, CIS Benchmark rules, DLP logic, console suppression, or documentation are updated in `D:\harfile\OshoosiClaw`, always synchronize the corresponding changes to `D:\harfile\AgentOctopus` (`https://github.com/oyesanyf/AgentOctopus.git`), verify zero compiler warnings, commit, and push so both repositories remain in lockstep.
