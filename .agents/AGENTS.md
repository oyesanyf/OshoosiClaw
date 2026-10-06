# Project Rules & User Preferences

## Git Push Guardrails
- **Restricted Remotes:** NEVER run `git push` inside `IDE/vscode` or target any Microsoft/upstream third-party remote.
- **Canonical Repository:** ALL code pushes must strictly target `https://github.com/oyesanyf/OshoosiClaw.git`.

## Mandatory Automated Microsoft Submission on Every Build
- **User Preference:** "Each time the code is built, remember to send to Microsoft."
- **Trigger:** Whenever code is built, packaged, or released.
- **Enforcement:** Code artifacts MUST always be Authenticode signed (SHA-256 + RFC 3161 timestamp) and submitted to Microsoft Security Intelligence (WDSI) via `python scripts/submit_to_wdsi.py --all --no-launch` (orchestrated by `scripts/build_and_submit.ps1`).
- **Standard Command:** Use `powershell -ExecutionPolicy Bypass -File scripts/build_and_submit.ps1` as the canonical command to build, sign, package, and submit to Microsoft in one go.

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