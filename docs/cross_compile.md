# OshoosiClaw — Cross-Compilation Guide

> **TL;DR** — Install `cross`, then run one command per target. No linker pain.

---

## Prerequisites

### 1. Install `cross`
```bash
cargo install cross --git https://github.com/cross-rs/cross
```
`cross` wraps every build in a pre-configured Docker container. You never touch a linker manually.

### 2. Docker (required for `cross`)
- Windows: [Docker Desktop](https://www.docker.com/products/docker-desktop/)
- WSL2: `sudo apt install docker.io && sudo service docker start`

---

## Build Commands

### Native Windows (x86_64 MSVC) — current default
```powershell
cargo build --release
# Binary: target/x86_64-pc-windows-msvc/release/osoosi.exe
```

### Linux Static Binary (recommended for server/WSL deployment)
Produces a **zero-dependency** binary — runs on any Linux without installing anything.
```bash
cross build --release --target x86_64-unknown-linux-musl
# Binary: target/x86_64-unknown-linux-musl/release/osoosi
```

### Linux ARM64 Static Binary (Raspberry Pi, AWS Graviton, cloud ARM)
```bash
cross build --release --target aarch64-unknown-linux-musl
# Binary: target/aarch64-unknown-linux-musl/release/osoosi
```

### Windows GNU (from WSL/Linux, no MSVC needed)
```bash
cross build --release --target x86_64-pc-windows-gnu
# Binary: target/x86_64-pc-windows-gnu/release/osoosi.exe
```

### macOS (requires GitHub Actions or an osxcross SDK — see below)
```bash
cross build --release --target x86_64-apple-darwin     # Intel Mac
cross build --release --target aarch64-apple-darwin    # Apple Silicon
```

---

## What Works on Each Platform

| Feature | Windows | Linux | macOS |
|---|---|---|---|
| Sysmon telemetry | ✅ native EventLog | ✅ via auditd/journald | ✅ via Unified Log |
| Windows Update COM | ✅ | ❌ (gated by `#[cfg]`) | ❌ |
| Registry operations | ✅ winreg | ❌ (gated) | ❌ |
| File watcher | ✅ ReadDirectoryChanges | ✅ inotify | ✅ kqueue |
| YARA-X scanning | ✅ | ✅ | ✅ |
| ONNX / AI models | ✅ | ✅ | ✅ |
| P2P mesh (libp2p) | ✅ | ✅ | ✅ |
| SQLite memory store | ✅ | ✅ | ✅ |
| Defender exclusions | ✅ registry | ❌ | ❌ |

All Windows-only features are already gated by `#[cfg(target_os = "windows")]` — the Linux/macOS builds simply exclude them and compile cleanly.

---

## Linux Telemetry Stubs

On Linux, the agent uses `auditd`/`journald`-based telemetry in place of Sysmon. This is already scaffolded in the code — look for `#[cfg(target_os = "linux")]` blocks in:
- `crates/osoosi-telemetry/src/sysmon.rs`
- `crates/osoosi-repair/src/discovery.rs`
- `crates/osoosi-repair/src/lib.rs`

---

## GitHub Actions CI (Recommended for macOS)

Apple's SDK cannot legally be shipped in Docker, so macOS builds run on Apple-hosted runners:

```yaml
# .github/workflows/release.yml
name: Release
on:
  push:
    tags: ['v*']
jobs:
  build-windows:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      - run: cargo build --release
      - uses: actions/upload-artifact@v4
        with:
          name: osoosi-windows
          path: target/release/osoosi.exe

  build-linux:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: cargo install cross --git https://github.com/cross-rs/cross
      - run: cross build --release --target x86_64-unknown-linux-musl
      - uses: actions/upload-artifact@v4
        with:
          name: osoosi-linux-x64
          path: target/x86_64-unknown-linux-musl/release/osoosi

  build-macos:
    runs-on: macos-latest
    steps:
      - uses: actions/checkout@v4
      - run: rustup target add aarch64-apple-darwin x86_64-apple-darwin
      - run: cargo build --release --target aarch64-apple-darwin
      - run: cargo build --release --target x86_64-apple-darwin
      - uses: actions/upload-artifact@v4
        with:
          name: osoosi-macos
          path: |
            target/aarch64-apple-darwin/release/osoosi
            target/x86_64-apple-darwin/release/osoosi
```

---

## Verifying the Build

### Windows (check no Linux stubs leaked):
```powershell
cargo check --target x86_64-pc-windows-msvc
```

### Linux (check no Windows APIs leaked):
```powershell
# From Windows, using cross:
cross check --target x86_64-unknown-linux-musl
```
