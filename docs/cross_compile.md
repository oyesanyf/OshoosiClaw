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

| Feature | Windows (`x86_64-pc-windows-msvc`) | Linux (`x86_64-unknown-linux-gnu`) | macOS (`apple-darwin`) |
|---|---|---|---|
| Kernel Pre-Exec Blocking | ✅ Ring-0 Driver (`PsSetCreateProcessNotifyRoutineEx`) | ✅ eBPF LSM (`bprm_check_security` + `blocked_paths`/`blocked_hashes`) | ⚠️ Endpoint Security (ESF) |
| Runtime Telemetry | ✅ Native Sysmon ETW (Events 1–25) | ✅ CO-RE eBPF (`sched_process_exec`, `exit`, `connect`, `mprotect` $W\oplus X$, `ptrace`) + `auditd` | ✅ Unified Log |
| Binary Allowlist & Page Integrity | ✅ NSRL 4 KB Merkle + Authenticode + Windows Catalog | ✅ NSRL 4 KB Merkle + Linux `fs-verity` (`FS_IOC_MEASURE_VERITY`) + ELF64 `.asc`/`.sig` | ✅ NSRL 4 KB Merkle |
| ASLR Code-Segment Merkle | ✅ PE `.text` (`IMAGE_REL_BASED_DIR64`) relocation normalization | ✅ ELF64 PIE/PIC `PT_LOAD` (`PF_X`) relocation normalization + `/proc/<pid>/maps` | ✅ Mach-O `__TEXT` |
| Process Memory VAD Forensics | ✅ Velociraptor VQL + Win32 `VirtualQueryEx` | ✅ Native `/proc/<pid>/maps` + `/proc/<pid>/mem` (`rwxp` & `/memfd:` detection) | ✅ Velociraptor |
| Service Lifecycle | ✅ Native Win32 SCM (`OsoosiEDR`) | ✅ Native `systemd` (`osoosi-edr.service`) + `setsid()` daemon | ✅ `launchd` |
| OS Sandboxing | ✅ AppContainer + Job Objects + Restricted Tokens | ✅ Landlock V3 + seccomp-bpf + cgroups v2 + namespaces | ✅ Seatbelt |
| Siquery 101-Table SQL Engine | ✅ All 101 tables populated | ✅ All 101 tables populated (`/proc`, `/sys`, `/etc`, Merkle, AI) | ✅ Cross-platform tables |
| Hierarchical BLAKE3 Merkle | ✅ Per-Arm, Per-Tarpit, Per-Ring + Ed25519 Rollup | ✅ Per-Arm, Per-Tarpit, Per-Ring + Ed25519 Rollup | ✅ Full parity |
| Native Installer Packages | ✅ Signed `OshoosiClaw.msi` (WiX v5) | ✅ Signed `.deb`, `.rpm`, `.tar.gz` (`packaging/linux/build_packages.sh`) | ✅ `.tar.gz` |

---

## Native Linux Build & Packaging (`v1.2.0`)

On Linux or WSL2 Ubuntu (`x86_64-unknown-linux-gnu`), build the release binary, CO-RE eBPF probe, and `.deb` / `.rpm` / `.tar.gz` packages:

```bash
# 1. Compile the CO-RE eBPF probe (optional if using pre-compiled ebpf/osoosi_probe.bpf.o)
clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -Iebpf/include -c ebpf/src/osoosi_probe.bpf.c -o ebpf/osoosi_probe.bpf.o

# 2. Build the native Linux release binary
cargo build --release -p osoosi-cli --bin osoosi

# 3. Package .deb, .rpm, .tar.gz, and standalone binary
bash packaging/linux/build_packages.sh target/release/osoosi 1.2.0
```

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
