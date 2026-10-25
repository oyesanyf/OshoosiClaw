# 🌱 OpenỌ̀ṣọ́ọ̀sì (OshoosiClaw) — Curated Good First Issues Catalog

Welcome, prospective contributor! This catalog contains **12 well-scoped, self-contained starter tasks** (`GFI-01` through `GFI-12`) designed to give you a smooth, rewarding onboarding experience in OshoosiClaw.

Every ticket includes:
- **Exact File & Line Pointers**: Where the logic lives in the repository.
- **Problem & Solution Definition**: Exactly what needs to be changed.
- **Passing Verification Command**: Test command you can run locally to prove your fix works.
- **Safety Invariant Checklist**: Ensures your PR adheres to core repository standards.

---

## 📑 Issue Index

| ID | Title | Subsystem / Language | Estimated Effort |
| :--- | :--- | :--- | :---: |
| [`GFI-01`](#gfi-01-add---json-output-flag-to-osoosi-cli-query) | Add `--json` Output Flag to `osoosi-cli query` | CLI / Rust | 1–2 hours |
| [`GFI-02`](#gfi-02-implement-stdfmtdisplay-for-priority-in-osoosi-types) | Implement `std::fmt::Display` for `Priority` in `osoosi-types` | Domain Models / Rust | 30 mins |
| [`GFI-03`](#gfi-03-implement-high-contrast-focus-ring-for-keyboard-accessibility) | Implement High-Contrast Focus Ring for Keyboard Accessibility | WebUI / CSS | 45 mins |
| [`GFI-04`](#gfi-04-add-virtual-column-size_pretty-in-siquery-processes-table) | Add Virtual Column `size_pretty` in Siquery `processes` Table | Telemetry SQL / Rust | 1–2 hours |
| [`GFI-05`](#gfi-05-add-descriptive-error-diagnostics-for-appcontainer-sid-lookup) | Add Descriptive Error Diagnostics for AppContainer SID Lookup | Sandboxing / Rust | 1 hour |
| [`GFI-06`](#gfi-06-implement-configurable-log-file-rotation-retention-policy) | Implement Configurable Log File Rotation Retention Policy | Daemon Core / Rust | 1–2 hours |
| [`GFI-07`](#gfi-07-case-insensitive-suffix-normalization-in-binary-trust-probes) | Case-Insensitive Suffix Normalization in Binary Trust Probes | Cryptographic Trust / Rust | 45 mins |
| [`GFI-08`](#gfi-08-add-x-content-type-options-nosniff-header-to-webui-responses) | Add `X-Content-Type-Options: nosniff` Header to WebUI Responses | Axum Server / Rust | 30 mins |
| [`GFI-09`](#gfi-09-add-validation-for-nonce-uniqueness-in-capability-tickets) | Add Validation for Nonce Uniqueness in Capability Tickets | Policy Monitor / Rust | 1 hour |
| [`GFI-10`](#gfi-10-add---dry-run-and-diagnostics-to-securebert-onnx-exporter) | Add `--dry-run` and Diagnostics to SecureBERT ONNX Exporter | Tooling / Python | 1 hour |
| [`GFI-11`](#gfi-11-machine-guid-sanitization-helper-for-anonymized-triage-dumps) | Machine GUID Sanitization Helper for Anonymized Triage Dumps | Host Forensics / Rust | 1–2 hours |
| [`GFI-12`](#gfi-12-automated-verification-test-for-starter-issue-pointers) | Automated Verification Test for Starter Issue Pointers | Tooling / Python | 45 mins |

---

### GFI-01: Add `--json` Output Flag to `osoosi-cli query`
- **File**: [`crates/osoosi-cli/src/main.rs`](../crates/osoosi-cli/src/main.rs#L180-L240)
- **Subsystem**: CLI / Rust
- **Problem**: When running `osoosi-cli query "SELECT pid, name FROM processes LIMIT 5;"`, the CLI outputs tabular plain-text. Programmatic automation scripts (e.g., CI runners and SIEM forwarders) require structured JSON format.
- **Solution**:
  1. Add an optional `--json` flag to the `Query` subcommand struct in `crates/osoosi-cli/src/main.rs`.
  2. If `--json` is specified, serialize the resulting `Vec<SiqueryRow>` using `serde_json::to_string_pretty(&rows)`.
  3. Print the serialized JSON to stdout and exit with code 0.
- **Verification Command**:
  ```bash
  cargo check -p osoosi-cli
  cargo test -p osoosi-cli
  ```
- **Invariants**: Keep existing default tabular output intact when `--json` is absent.

---

### GFI-02: Implement `std::fmt::Display` for `Priority` in `osoosi-types`
- **File**: [`crates/osoosi-types/src/threat.rs`](../crates/osoosi-types/src/threat.rs#L40-L75)
- **Subsystem**: Domain Types / Rust
- **Problem**: The `Priority` enum (`Low`, `Normal`, `High`, `Critical`) derives `Debug`, `Serialize`, and `Deserialize`, but lacks an explicit `Display` implementation, requiring verbose `format!("{:?}", priority)` calls in logging macros.
- **Solution**:
  1. Implement `std::fmt::Display for Priority` in `crates/osoosi-types/src/threat.rs`.
  2. Map `Low => "LOW"`, `Normal => "NORMAL"`, `High => "HIGH"`, `Critical => "CRITICAL"`.
  3. Add a unit test verifying `priority.to_string()`.
- **Verification Command**:
  ```bash
  cargo test -p osoosi-types test_priority_display
  ```
- **Invariants**: Zero breaking changes to `serde` serialization.

---

### GFI-03: Implement High-Contrast Focus Ring for Keyboard Accessibility
- **File**: [`dashboard/src/style.css`](../dashboard/src/style.css#L50-L90)
- **Subsystem**: WebUI / CSS
- **Problem**: Interactive buttons and selects currently rely on browser default focus outlines, which can be difficult to discern against the dark theme palette (`#0f172a`).
- **Solution**:
  1. Add a global `:focus-visible` rule in `dashboard/src/style.css`:
     ```css
     :focus-visible {
       outline: 2px solid #38bdf8;
       outline-offset: 2px;
     }
     ```
  2. Ensure `.btn-secondary:focus-visible` and `select:focus-visible` render clearly.
  3. Mirror the changes to `dashboard/dist/style.css` to maintain 0-diff parity.
- **Verification Command**:
  ```bash
  node dashboard/tests/webui_parity.test.mjs
  ```
- **Invariants**: `dashboard/src/style.css` and `dashboard/dist/style.css` must remain 100% identical in SHA-256 hash.

---

### GFI-04: Add Virtual Column `size_pretty` in Siquery `processes` Table
- **File**: [`crates/osoosi-agent-anomaly/src/siquery.rs`](../crates/osoosi-agent-anomaly/src/siquery.rs#L250-L320)
- **Subsystem**: Telemetry SQL / Rust
- **Problem**: The `processes` virtual table returns memory size exclusively in raw bytes (`memory_bytes INTEGER`). Analysts writing ad-hoc SQL queries often want a formatted human-readable string (e.g., `45.2 MB`).
- **Solution**:
  1. Add a helper function `format_memory_size(bytes: u64) -> String` producing `B`, `KB`, `MB`, or `GB`.
  2. Add a `size_pretty TEXT` column to the `processes` schema and row builder in `siquery.rs`.
  3. Write a unit test asserting `SELECT size_pretty FROM processes LIMIT 1;` succeeds.
- **Verification Command**:
  ```bash
  cargo test -p osoosi-agent-anomaly test_siquery_processes_virtual_table
  ```
- **Invariants**: Retain the existing `memory_bytes` integer column for mathematical SQL comparisons (`WHERE memory_bytes > 100000000`).

---

### GFI-05: Add Descriptive Error Diagnostics for AppContainer SID Lookup
- **File**: [`crates/osoosi-sandbox/src/open_confined.rs`](../crates/osoosi-sandbox/src/open_confined.rs#L80-L130)
- **Subsystem**: Sandboxing / Rust
- **Problem**: When `DeriveAppContainerSidFromAppContainerName` encounters an invalid profile name or OS restriction on older Windows builds, error reporting logs a raw hex code without actionable diagnostic context.
- **Solution**:
  1. Wrap the Win32 error in a descriptive `anyhow::Context` detailing the attempted profile name and recommending Windows 10/11 version prerequisites.
  2. Ensure the fail-closed error path cleanly frees any partially allocated handles via RAII.
- **Verification Command**:
  ```bash
  cargo check -p osoosi-sandbox
  cargo test -p osoosi-sandbox
  ```
- **Invariants**: Must fail closed; never execute an uncontained process fallback.

---

### GFI-06: Implement Configurable Log File Rotation Retention Policy
- **File**: [`crates/osoosi-core/src/log_retention.rs`](../crates/osoosi-core/src/log_retention.rs#L30-L85)
- **Subsystem**: Daemon Core / Rust
- **Problem**: Log retention currently defaults to a fixed 14-day window. Resource-constrained environments need to specify retention days in `config/osoosi.toml`.
- **Solution**:
  1. Read optional `retention_days` from `LoggingConfig` in `crates/osoosi-core/src/log_retention.rs`.
  2. If `retention_days` is unset, default safely to 14 days.
  3. Add a unit test verifying retention cutoff calculation for varying days.
- **Verification Command**:
  ```bash
  cargo test -p osoosi-core test_log_retention
  ```
- **Invariants**: Safe log rotation even when file is held open (Windows sharing violation handling).

---

### GFI-07: Case-Insensitive Suffix Normalization in Binary Trust Probes
- **File**: [`crates/osoosi-trust/src/lib.rs`](../crates/osoosi-trust/src/lib.rs#L85-L130)
- **Subsystem**: Cryptographic Trust / Rust
- **Problem**: When checking whether a path is an executable candidate (`.exe`, `.dll`, `.sys`), casing variations (e.g., `.EXE` or `.Dll`) on case-insensitive filesystems should be normalized efficiently.
- **Solution**:
  1. Extract extension and convert to ASCII lowercase (`to_ascii_lowercase()`) prior to matching.
  2. Add unit tests covering mixed-case file paths.
- **Verification Command**:
  ```bash
  cargo test -p osoosi-trust test_binary_trust_path_normalization
  ```
- **Invariants**: Do NOT bypass digital signature verification or catalog lookups based solely on extension.

---

### GFI-08: Add `X-Content-Type-Options: nosniff` Header to WebUI Responses
- **File**: [`crates/osoosi-dashboard/src/lib.rs`](../crates/osoosi-dashboard/src/lib.rs#L75-L120)
- **Subsystem**: Axum Server / Rust
- **Problem**: WebUI HTTP responses on `127.0.0.1:3030` should enforce modern browser security headers against MIME confusion attacks.
- **Solution**:
  1. Add an Axum middleware layer in `crates/osoosi-dashboard/src/lib.rs` appending `X-Content-Type-Options: nosniff` to all HTTP responses.
  2. Verify headers using a quick curl or integration test.
- **Verification Command**:
  ```bash
  cargo test -p osoosi-dashboard
  ```
- **Invariants**: Must not break SSE event streaming or WebSockets.

---

### GFI-09: Add Validation for Nonce Uniqueness in Capability Tickets
- **File**: [`crates/osoosi-policy/src/breakout_gate.rs`](../crates/osoosi-policy/src/breakout_gate.rs#L110-L160)
- **Subsystem**: Policy Monitor / Rust
- **Problem**: `DiracDeltaCapabilityTicket` uses single-use impulses. Adding a small in-memory LRU or set of recent nonces prevents replay attacks within the same session epoch.
- **Solution**:
  1. Add a bounded `seen_nonces` check in `CapabilityGate` before ticket consumption.
  2. Reject tickets with duplicate nonces with `Veto: DuplicateNonceReplay`.
  3. Add unit test asserting duplicate nonce returns error.
- **Verification Command**:
  ```bash
  cargo test -p osoosi-policy test_capability_ticket_nonce_replay
  ```
- **Invariants**: Single-use impulse semantics must strictly hold.

---

### GFI-10: Add `--dry-run` and Diagnostics to SecureBERT ONNX Exporter
- **File**: [`scripts/export_securebert_onnx.py`](../scripts/export_securebert_onnx.py)
- **Subsystem**: Tooling / Python
- **Problem**: `export_securebert_onnx.py` attempts external model downloads immediately upon execution without a `--dry-run` flag or target directory validation, making offline testing difficult.
- **Solution**:
  1. Add standard `argparse` with `--dry-run`, `--model-id`, and `--output-dir` arguments.
  2. In `--dry-run` mode, print the target output path and model architecture details without downloading or exporting weights.
  3. Validate write permissions on the target directory before initiating model download.
- **Verification Command**:
  ```bash
  python scripts/export_securebert_onnx.py --help
  ```
- **Invariants**: Preserve default export directory `models/behavioral` when arguments are omitted.

---

### GFI-11: Machine GUID Sanitization Helper for Anonymized Triage Dumps
- **File**: [`crates/osoosi-forensics/src/stream.rs`](../crates/osoosi-forensics/src/stream.rs#L90-L140)
- **Subsystem**: Host Forensics / Rust
- **Problem**: When exporting forensic triage bundles for peer research or bug reports, host Machine GUIDs and MAC addresses should be pseudorandomly blinded via BLAKE3 key derivation.
- **Solution**:
  1. Implement `anonymize_machine_id(guid: &str, salt: &[u8]) -> String` using BLAKE3 keyed hash.
  2. Unit test verifying that the output is deterministic for a given salt but obscures the raw hardware ID.
- **Verification Command**:
  ```bash
  cargo test -p osoosi-forensics test_machine_id_anonymization
  ```
- **Invariants**: Output must produce valid format string without crashing on empty GUIDs.

---

### GFI-12: Automated Verification Test for Starter Issue Pointers
- **File**: [`scripts/seed_good_first_issues.py`](../scripts/seed_good_first_issues.py)
- **Subsystem**: Tooling / Python
- **Problem**: Starter issue documentation can drift if file paths or line ranges change across refactorings.
- **Solution**:
  1. Create `scripts/seed_good_first_issues.py` to parse `docs/GOOD_FIRST_ISSUES.md`.
  2. Verify that every referenced file exists on disk and contains the referenced structures.
  3. Provide `--verify` and `--export-json` CLI options.
- **Verification Command**:
  ```bash
  python scripts/seed_good_first_issues.py --verify
  ```
- **Invariants**: Must return exit code 0 when all pointers are valid.

---

## 🚀 How to Claim an Issue

1. Open a comment on the corresponding GitHub issue saying: *"I would like to work on this issue!"*
2. Fork the repository and create a branch: `git checkout -b feature/gfi-01-json-output`.
3. Follow the steps in [`CONTRIBUTING.md`](../CONTRIBUTING.md) to build and verify your fix.
4. Submit a Pull Request targeting `main`. Our maintainers will review your PR within 24–48 hours!
