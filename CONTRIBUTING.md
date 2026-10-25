# Contributing to OpenỌ̀ṣọ́ọ̀sì (OshoosiClaw)

Thank you for your interest in contributing to **OpenỌ̀ṣọ́ọ̀sì (OshoosiClaw)**! We welcome contributions from developers, security researchers, reverse engineers, and system architects.

This document provides technical instructions, coding standards, and architectural invariants for contributing to the repository.

---

## 📜 Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md). Please read it before contributing.

> [!IMPORTANT]
> **Zero-Touch PATH Protection Protocol**  
> Under NO circumstance may any script, installer definition (`.wxs`), code change, or test overwrite, reset, or truncate user or system environment variables (`PATH`, `HKCU\Environment`, `HKLM`). All environment operations must be strictly process-scoped or append-only (`Permanent="yes"` in WiX manifests).

> [!IMPORTANT]
> **Production Code Only (Zero-Mock Invariant)**  
> Never fabricate dummy placeholders, mock security rules, or fake detection responses. All detection signatures, catalog lookups, and response actions must route through authentic decision models (Clef Decision Engine, Strands Decider, Byzantine Quorum).

---

## 🚀 Development Setup

### Prerequisites

- **Rust 1.75+** (MSRV) — Install via [rustup.rs](https://rustup.rs)
- **Python 3.11+** — For AI defense swarm, SkyRL, and test harnesses
- **Git** — Version control
- **Windows**: Visual Studio Build Tools 2022 (C++ workload) + Windows 10/11 SDK (`signtool.exe`)
- **Linux (WSL / Ubuntu)**: `build-essential`, `llvm`, `clang`, `libelf-dev` (for eBPF probes)

### Setting Up Your Environment

You can build and test using standard `make` or native `cargo` / `powershell` commands:

```bash
# Clone the repository
git clone https://github.com/oyesanyf/OshoosiClaw.git
cd OshoosiClaw

# Single-command build and test via Makefile
make check
make test
make verify-onboarding

# Alternatively via cargo & Python directly:
cargo build --all-features
cargo test --all-features
cargo clippy --all-features -- -D warnings
cargo fmt --all -- --check
python scripts/verify_repo_clarity_and_languages.py
python scripts/validate_readme.py
```

> [!TIP]
> **Fast Pre-Flight Verification**  
> Running `make verify-onboarding` verifies both Linguist language composition (Rust + Python $\ge 90\%$) and onboarding documentation clarity before opening a PR.

---

## 🎯 Finding Your First Task (Good First Issues)

New to OshoosiClaw? We maintain a curated catalog of bite-sized, self-contained starter tasks designed specifically for new contributors:

👉 **[docs/GOOD_FIRST_ISSUES.md](docs/GOOD_FIRST_ISSUES.md)** — Contains 12 well-specified issues (`GFI-01` through `GFI-12`) across Rust, Python, and WebUI domains with exact `file:line` pointers, problem definitions, expected behavior, and verification commands.

You can also browse open issues on GitHub tagged with the [`good first issue`](https://github.com/oyesanyf/OshoosiClaw/labels/good%20first%20issue) label.

---

## 🤝 Contributor Pathway & Recognition

We deeply value our open-source contributors and are committed to creating a welcoming, transparent, and rewarding engineering community:

1. **Priority First-PR Review Commitment**:
   - First-time contributors receive expedited code review from maintainers within **24–48 hours**.
   - If your PR needs adjustments, maintainers provide actionable, constructive guidance rather than blunt rejections.

2. **Public Release-Notes Credit**:
   - Every contributor whose pull request is merged is credited by GitHub handle and full name (if desired) in the official GitHub Release notes for that milestone.
   - Significant contributions are featured in the repository's `#about` and `#acknowledgments` sections.

3. **2–3 PR Pathway to Triage & Architecture**:
   - After **2 to 3 successfully merged PRs** demonstrating adherence to safety invariants and testing rigor:
     - You will be invited to participate directly in quarterly architectural planning sessions.
     - You will be granted GitHub repository **Triage** permissions (labeling, prioritizing, and assigning issues).
     - You will be eligible for repository co-maintainership and peer review delegation.

---

## 🏛️ Workspace Architecture & Crate Map

OshoosiClaw is structured as a high-assurance multi-crate Rust workspace complemented by Python research tools:

| Functional Domain | Crates | Purpose |
| :--- | :--- | :--- |
| **Core & Daemon Engine** | `osoosi-core`, `osoosi-runtime`, `osoosi-cli`, `osoosi-types` | Central daemon supervisor, process lifecycle, event dispatcher, CLI commands, shared core types. |
| **Telemetry & Host Forensics** | `osoosi-telemetry`, `osoosi-memory`, `osoosi-forensics`, `osoosi-dns`, `osoosi-inject`, `osoosi-hexpatch` | ETW/eBPF host sensors, memory analysis, process injection defenses, live binary hexpatching. |
| **Reverse Engineering & Forensics** | `osoosi-behavioral`, `rea` | Autonomous binary/bytecode forensics, PE/ELF/WASM decompiler, YARA-X rules, behavioral anomaly detection. |
| **Policy & Sandboxing** | `osoosi-policy`, `osoosi-sandbox`, `osoosi-agent-anomaly`, `agent-thermostat` | Cedar PARC & Dogwood MFOTL engines, Win32 Job Object CanaryCage, Agentic AI anomaly scanner, agent throttling. |
| **AI Models & Active Defense** | `osoosi-model`, `compression-prompt`, `edr-phaselock`, `tools/defense_swarm` | ONNX runtime, SecureBERT, prompt compression, Phaselock defense, SkyRL RL co-evolution. |
| **Zero-Process Quantum & Shield** | `silicon-shield`, `zero-genesis-capacity`, `zero-algebraic-kernel`, `zero-vacuum-lensing`, `zero-divine-equilibrium` | Zero-process algebraic kernel, hardware silicon shield, thermodynamic equilibrium defense models. |
| **Cryptography, Mesh & Wire** | `osoosi-audit`, `osoosi-wire`, `osoosi-trust`, `osoosi-relay`, `osoosi-dp`, `test-peer` | BLAKE3 Merkle logchains, TPM 2.0 silicon signers, ML-KEM-768 PQC, differential privacy, Nostr relay, TFHE mesh. |
| **Threat Intelligence & Feeds** | `osoosi-owasp-hunting`, `osoosi-vcdb`, `otx-taxii-rs`, `osoosi-exporter`, `osoosi-auditor` | OWASP hunting feed sync, Verizon VCDB breach replay, AlienVault OTX/TAXII client, telemetry exporter, auditor CLI. |
| **WebUI & API Dashboard** | `osoosi-dashboard` | Embedded Axum HTTP/SSE server, continuous HAR web traffic sensor, zero-dependency WebUI on `127.0.0.1:3030`. |

---

## 🎨 Code Conventions & Rust Standards

### Rust Style Guidelines

- Follow standard `rustfmt` formatting (enforced via `cargo fmt --all -- --check`).
- All public functions, structs, and traits must include doc comments (`///`).
- Logging must use `tracing` macros (`info!`, `warn!`, `error!`, `debug!`) — never raw `println!`.
- Error handling: prefer `anyhow::Result` for application logic and `thiserror` for library crates.
- Async concurrency: use `Arc<T>` with `tokio::sync::RwLock` or `parking_lot::RwLock` where appropriate; **never** invoke `blocking_read()` or `blocking_write()` inside Tokio async tasks.
- DashMap hygiene: explicitly drop mutable `.entry()` or `.get_mut()` guards before invoking iterator methods (`.iter()`, `.len()`).

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```text
type(scope): concise description

feat(mesh): add GossipSub Byzantine peer equivocation defense
fix(telemetry): resolve ETW event subscription race condition
docs(community): standardize issue and pull request templates
refactor(dashboard): extract domain routes into dedicated modules
```

---

## 🔄 Contribution Workflow & Shipping

### Branch Protection & Review Policy

> [!NOTE]
> **Collaborator Code Review Policy**  
> GitHub Branch Protection enforces at least one approval (`required_approving_review_count = 1`) on `main`. Any repository collaborator or peer developer can review and approve pull requests.

For maintainers and automated release builds, the repository includes an automated solo PR shipping mechanism:

```powershell
# Commit and ship increments with zero wait:
powershell -ExecutionPolicy Bypass -File scripts/solo_pr_ship.ps1 -Title "feat(mesh): expand GossipSub benchmarks"
```

### Pre-Submission Checklist

Before opening a pull request, ensure:
1. `cargo check --all-targets` compiles with 0 errors.
2. `cargo test --all-features` passes.
3. `python scripts/verify_repo_clarity_and_languages.py` exits with code `0`.
4. `python scripts/verify_port_3030_e2e.py` passes if modifying backend endpoints or WebUI assets.
5. `dashboard/tests/webui_parity.test.mjs` confirms 0-diff SHA-256 parity between `dashboard/src/` and `dashboard/dist/`.
6. `git status -s` is 100% clean.

---

## 🔒 Security Vulnerability Reporting

> [!WARNING]
> **Do NOT open public GitHub issues for security vulnerabilities.**  
> Report vulnerabilities confidentially via [GitHub Private Security Advisories](https://github.com/oyesanyf/OshoosiClaw/security/advisories/new) or consult our [Security Policy](SECURITY.md).

---

## 📜 License

By contributing to OshoosiClaw, you agree that your contributions are licensed under the [MIT License](LICENSE).
