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

3. **Mandatory Automated Microsoft Submission on Build**:
   - **User Preference**: "Each time the code is built, remember to send to Microsoft."
   - Every build of release binaries or installer packages MUST automatically code-sign all target binaries with Authenticode (SHA-256 + DigiCert RFC 3161 timestamp) and submit them to Microsoft Security Intelligence (WDSI).
   - Use `scripts/build_and_submit.ps1` as the canonical unified release build command, which automatically compiles `osoosi-cli`, re-signs configs, generates the MSI installer, signs all binaries, and invokes `python scripts/submit_to_wdsi.py --all --no-launch`.
   - Never release or produce an unsubmitted binary artifact.
