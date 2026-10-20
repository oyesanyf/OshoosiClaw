---
name: rea
description: Autonomous Reverse Engineer Anything (REA) workflow and engine for inspecting native binaries (PE/ELF/Mach-O), Rust cargo-auditable binaries, Go BuildInfo binaries, WASM artifacts, EVM bytecode, .NET CIL assemblies, JavaScript/Electron/ASAR apps, SQLite databases, network captures (HAR/PCAP), Android/Flutter APKs, and firmware with evidence-backed findings, reconstructed code, and auto-generated YARA signatures.
---

# Autonomous REA: Reverse Engineer Anything

REA (`Reverse Engineer Anything`, inspired by `morluto/rea`) connects OpenỌ̀ṣọ́ọ̀sì agents, the CLI (`osoosi rea`), and the WebUI (`#rea`) to an **autonomous, local reverse-engineering engine** across binaries, applications, bytecode, databases, network captures, and runtime behavior.

## Core Principles

1. **Two-Tier Classification Pipeline (Google Magika ONNX + Structural Compiler Provenance)**:
   - **Tier 1 (Envelope & MIME Detection)**: Every target is first inspected with Google Magika (`identify_with_magika` in `crates/osoosi-core/src/rea.rs`) and magic-byte verification to determine the outer container envelope (`pebin`, `elf`, `macho`, `wasm`, `sqlite`, `pcap`, `json`, `apk`, `dex`, `shell`, `powershell`) and record `metadata["magika"]` + `google_magika` evidence.
   - **Tier 2 (Structural PE/ELF/Mach-O Provenance)**: For PE binaries, `goblin::pe::PE::parse` inspects the Optional Header's CLR Runtime Header DataDirectory (`IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR`, index 14). If `DataDirectory[14]` is zero, the PE is unequivocally native (`rust_binary`, `go_binary`, or `native_binary`) and never misclassified as `.NET` even if `.rdata` contains `"BSJB"` string literals.
2. **256 MiB Full-Binary Read Capacity (`REA_MAX_FILE_READ_BYTES`)**:
   - `analyze_target_path` reads up to **256 MiB** (`268,435,456` bytes) so large Rust/Go/Electron binaries (`osoosi.exe` ~82–128 MiB) are analyzed in full without truncating trailing `.dep-v0` or `.rdata` sections.
3. **Autonomous Operation (`AutonomousReaEngine`)**:
   - REA runs continuously and autonomously in the background (`spawn_autonomous_rea_daemon`) and triggers immediately on live malware/quarantine detections (`spawn_autonomous_rea_for_threat`), persisting findings, reconstructed code, and multi-token YARA rules (`yara/rea_auto_rules.yar`).
4. **Bounded Output & Process Cleanup Ownership**:
   - External provider invocations (`rea`, `npx rea-agents`, `rizin`, `radare2`, `ghidraRun`, `objdump`, `dumpbin`, `jadx`, `binwalk`, `tshark`) enforce a strict **4 MiB combined stdout/stderr cap** and guarantee child process termination on timeout or cancellation.

## Supported Targets

| Target Kind | What Autonomous REA Returns | Built-In / Provider Support |
|---|---|---|
| `native` | PE/ELF/Mach-O sections, segments, imports, exports, symbols, security mitigations (`ASLR`, `DEP/NX`, `CFG`, `PIE`, `RELRO`), call targets, C pseudocode | Built-in static PE/ELF/Mach-O parser + Google Magika + optional `ghidra` / `rizin` / `objdump` |
| `rust` | Embedded `.dep-v0` (`cargo-auditable`) crate names, versions, dependency edges, `rustc` compiler version, panic strategy | Built-in ELF/PE/Mach-O inspection |
| `go` | Embedded `\xff Go buildinf:` compiler version, main module, dependency modules, replacements, build flags | Built-in ELF/PE/Mach-O inspection (no Go installation required) |
| `wasm` | `\0asm` validation, LEB128 section inventory, exact import/export WAT signatures, reconstructed WAT skeleton | Built-in WASM binary parser |
| `evm` | `PUSH4` 4-byte selector dispatch table, byte offsets, inferred arguments, `view`/`payable`/`non-payable` mutability, Solidity interface | Built-in EVM bytecode disassembler |
| `dotnet` | PE CLR DataDirectory[14] + ECMA-335 `BSJB` CLR metadata root, runtime version, `#~`/`#Strings`/`#US`/`#GUID`/`#Blob` streams, P/Invoke native dependencies | Built-in static PE/.NET parser |
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
