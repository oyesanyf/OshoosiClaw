---
name: "🌱 Good First Issue (Starter Task)"
about: "Template for creating or proposing a beginner-friendly starter issue"
title: "[GFI]: "
labels: ["good first issue", "help wanted", "onboarding"]
assignees: ""
---

### 🎯 Issue Summary
A clear and concise description of the starter task and why it is well-suited for a new contributor.

### 📦 Target Crate / Subsystem
- [ ] `crates/osoosi-cli` (CLI commands, argument parsing, shell formatting)
- [ ] `crates/osoosi-dashboard` (WebUI, REST endpoints, HTML/CSS/JS)
- [ ] `crates/osoosi-core` (Telemetry event filtering, configuration, helpers)
- [ ] `crates/osoosi-agent-anomaly` (Siquery SQL virtual tables, metrics)
- [ ] `crates/osoosi-types` (Data models, serde serialization, display traits)
- [ ] `tools/` or `scripts/` (Python automation, verification tools, test helpers)
- [ ] Documentation / Examples (`docs/`, `README.md`, `ARCHITECTURE.md`)

### 📍 Exact File & Line Pointers
- File: `crates/.../src/...rs` (Lines `...`–`...`)
- Test file: `tests/...` or `crates/.../tests/...`

### 🔍 Current Behavior / Problem Description
Describe what the code currently does or what is missing.

### 💡 Proposed Solution & Expected Behavior
Step-by-step guidance on how to implement the change cleanly.

### 🧪 Step-by-Step Verification Commands
Provide the exact commands the contributor can run to verify their fix locally:

```bash
# 1. Compile target
cargo check -p <crate-name>

# 2. Run target unit test
cargo test -p <crate-name> <test_name>

# 3. Verify repository hygiene
make verify-onboarding
```

### 📋 Invariant Checklist
- [ ] **Zero-Touch PATH**: No modifications to persistent environment variables.
- [ ] **Production Code Only**: No mock signatures or dummy constants.
- [ ] **Async Safety**: No `blocking_read()` / `blocking_write()` in async tasks.
- [ ] **Tests Passing**: New or updated unit test added.

### 💬 Mentorship & Review
First-time contributor PRs are prioritized and reviewed within 24–48 hours! Feel free to ask clarifying questions directly in this issue.
