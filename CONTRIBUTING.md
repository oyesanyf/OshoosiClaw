# Contributing to OshoosiClaw

Thank you for your interest in contributing to **OshoosiClaw**! This document provides guidelines and instructions for contributing.

## 🏹 Code of Conduct

By participating in this project, you agree to uphold a respectful and inclusive environment. We follow the [Contributor Covenant](https://www.contributor-covenant.org/).

## 🚀 Getting Started

### Prerequisites

- **Rust 1.75+** — Install via [rustup](https://rustup.rs)
- **Git** — Version control
- **Visual Studio Build Tools 2022** (Windows only)

### Setting Up Your Development Environment

```powershell
# Fork the repository on GitHub, then:
git clone https://github.com/YOUR_USERNAME/OshoosiClaw.git
cd OshoosiClaw

# Build everything
cargo build --all-features

# Run tests
cargo test --all-features

# Run linting
cargo clippy --all-features -- -D warnings

# Format code
cargo fmt --all -- --check
```

## 📝 How to Contribute

### Reporting Bugs

1. Check if the issue already exists in [GitHub Issues](https://github.com/oyesanyf/OshoosiClaw/issues)
2. Create a new issue with:
   - **Title**: Clear, descriptive summary
   - **Steps to Reproduce**: Exact commands/actions
   - **Expected Behavior**: What should happen
   - **Actual Behavior**: What actually happens
   - **Environment**: OS, Rust version, Sysmon version
   - **Logs**: Relevant output from `logs/osoosi.log`

### Suggesting Features

Open a [Feature Request](https://github.com/oyesanyf/OshoosiClaw/issues/new?template=feature_request.md) with:
- **Problem Statement**: What security gap does this address?
- **Proposed Solution**: How should it work?
- **MITRE ATT&CK Mapping**: Which technique(s) does this detect/prevent?

### Submitting Code

1. **Fork** the repository
2. **Create a feature branch**: `git checkout -b feature/your-feature-name`
3. **Write code** following our conventions (below)
4. **Write tests** for all new functionality
5. **Run CI locally**: `cargo build --all-features && cargo test --all-features && cargo clippy`
6. **Commit** with clear messages: `feat(core): add memory forensics via HollowsHunter`
7. **Push** and open a **Pull Request**

## 🎨 Code Conventions

### Rust Style

- Follow `rustfmt` defaults (run `cargo fmt`)
- All public items must have `///` doc comments
- Use `tracing` macros (`info!`, `warn!`, `error!`, `debug!`) for logging
- Prefer `anyhow::Result` for error handling
- Use `Arc<T>` for shared ownership, `tokio::sync::Mutex` for async locking
- Place `#[cfg(target_os = "...")]` blocks for platform-specific code

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
type(scope): description

feat(core): add HollowsHunter memory scanning
fix(telemetry): resolve Sysmon event parsing for ID 25
docs(readme): update architecture diagram
refactor(policy): split NSRL download into streaming module
```

### Crate Guidelines

| When adding... | Put it in... |
|:---------------|:-------------|
| New detection logic | `osoosi-core/src/` |
| New data types/schemas | `osoosi-types/src/` |
| OS-level telemetry | `osoosi-telemetry/src/` |
| ML models/scanning | `osoosi-model/src/` |
| P2P mesh features | `osoosi-wire/src/` |
| CLI commands | `osoosi-cli/src/main.rs` |

## 🔒 Security

If you discover a security vulnerability, **DO NOT** open a public issue. See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## 📜 License

By contributing, you agree that your contributions will be licensed under the MIT License.
