---
name: rea
description: Autonomous Reverse Engineer Anything (REA) workflow and engine for inspecting native binaries (PE/ELF/Mach-O), Rust cargo-auditable binaries, Go BuildInfo binaries, WASM artifacts, EVM bytecode, .NET CIL assemblies, JavaScript/Electron/ASAR apps, SQLite databases, network captures (HAR/PCAP), Android/Flutter APKs, and firmware with evidence-backed findings, reconstructed code, and auto-generated YARA signatures.
---

# Autonomous REA: Reverse Engineer Anything

REA (`Reverse Engineer Anything`, inspired by `morluto/rea`) connects OpenỌ̀ṣọ́ọ̀sì agents, the CLI (`osoosi rea`), and the WebUI (`#rea`) to an **autonomous, local reverse-engineering engine** across binaries, applications, bytecode, databases, network captures, and runtime behavior.

## Core Principles

1. **Autonomous Operation (`AutonomousReaEngine`)**:
   - REA runs continuously and autonomously in the background (`autonomous_enabled = true`), sweeping active non-whitelisted processes, newly flagged/quarantined artifacts, companion binaries, and local SQLite/manifest snapshots without waiting for human intervention.
   - Every autonomous investigation produces:
     - **Evidence-Backed Observations (`ReaEvidence`)**: Exact file offsets, virtual addresses, section names, SHA-256/BLAKE3 digests, and confidence scores.
     - **Explicit Limitations (`ReaLimitation`)**: Transparent disclosure when stripped symbols, missing external providers (`ghidra`, `rizin`, `hopper`, `ida`), or packed sections bound static visibility.
     - **Reconstructed Code (`reconstructed_code`)**: Decompiled C/Rust pseudocode for native binaries, WAT (`(module ...)`) for WebAssembly, Solidity interface/dispatchers for EVM bytecode, and IPC security contracts for Electron/ASAR apps.
     - **Autonomous Defense Synthesis (`auto_yara_rule`)**: Multi-token YARA rules and Clef Decision Engine signals automatically synthesized from unique binary imports, section hashes, and dispatch selectors.
2. **Bounded Output & Process Cleanup Ownership**:
   - External provider invocations (`rea`, `npx rea-agents`, `rizin`, `radare2`, `ghidraRun`, `objdump`, `dumpbin`, `jadx`, `binwalk`, `tshark`) enforce a strict **4 MiB combined stdout/stderr cap** and guarantee child process termination on timeout or cancellation.

## Supported Targets

| Target Kind | What Autonomous REA Returns | Built-In / Provider Support |
|---|---|---|
| `native` | PE/ELF/Mach-O sections, segments, imports, exports, symbols, security mitigations (`ASLR`, `DEP/NX`, `CFG`, `PIE`, `RELRO`), call targets, C pseudocode | Built-in static PE/ELF/Mach-O parser + optional `ghidra` / `rizin` / `objdump` / `rea-agents` |
| `rust` | Embedded `.dep-v0` (`cargo-auditable`) crate names, versions, dependency edges, `rustc` compiler version, panic strategy | Built-in ELF/PE/Mach-O inspection |
| `go` | Embedded `\xff Go buildinf:` compiler version, main module, dependency modules, replacements, build flags | Built-in ELF/PE/Mach-O inspection (no Go installation required) |
| `wasm` | `\0asm` validation, LEB128 section inventory, exact import/export WAT signatures, reconstructed WAT skeleton | Built-in WASM binary parser |
| `evm` | `PUSH4` 4-byte selector dispatch table, byte offsets, inferred arguments, `view`/`payable`/`non-payable` mutability, Solidity interface | Built-in EVM bytecode disassembler |
| `dotnet` | `BSJB` CLR metadata root, runtime version, `#~`/`#Strings`/`#US`/`#GUID`/`#Blob` streams, P/Invoke native dependencies, CIL stats | Built-in static PE/.NET parser |
| `electron` | `.asar` archive header & file table, `package.json`, `BrowserWindow` flags (`nodeIntegration`, `contextIsolation`, `sandbox`), `contextBridge`/`ipcMain` channels, `.node` addons | Built-in ASAR & JS/Electron static analyzer |
| `sqlite` | Read-only snapshot of tables, columns, indexes, views, triggers, and WAL state | Built-in SQLite schema inspector |
| `har` | HTTP Archive (`.har`) and `.pcap` endpoints, methods, status codes, TLS SNI, and exposed payload schemas | Built-in HAR/PCAP analyzer |
| `firmware` | SquashFS, CramFS, U-Boot `uImage`, Flattened Device Tree (`DTB`), Gzip/XZ/Zstd streams, and Android/Flutter (`classes.dex`, `libapp.so`, `libflutter.so`) | Built-in magic region scanner + optional `binwalk` / `jadx` |

## CLI Usage

```powershell
# Autonomous target inspection (auto-detects format)
osoosi rea analyze <path> --json

# Explicit target inspection
osoosi rea analyze target/release/osoosi.exe --target rust --json

# Autonomous multi-target sweep
osoosi rea sweep --json

# Inspect raw EVM bytecode
osoosi rea evm 0x6080604052348015600f57600080fd5b506004361060285760003560e01c8063a9059cbb14602d57 --json

# Check local reverse-engineering providers
osoosi rea providers --json
```

## Dashboard REST API & WebUI (`#rea`)

- `GET /api/rea/v1/status` — Returns engine status, `autonomous_enabled`, `total_autonomous_sweeps`, detected providers, and recent evidence-backed investigations.
- `POST /api/rea/v1/analyze` — Runs immediate REA analysis on `target_path`, `raw_hex`, or preset (`self_binary`, `sample_evm`, `sample_wasm`).
- `POST /api/rea/v1/autonomous` — Triggers an immediate autonomous sweep across active processes/binaries or toggles autonomous mode.
