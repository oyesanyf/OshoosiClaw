#![allow(unused_imports)]
//! REA: Reverse Engineer Anything — Autonomous Multi-Format Binary, Bytecode, Archive & Runtime Inspector.
//!
//! Implements native, zero-mock, evidence-backed reverse engineering across:
//! - Native PE / ELF / Mach-O binaries (`goblin` + `pelite` + `pe_inspector`)
//! - Rust binaries (`.dep-v0` `cargo-auditable` zlib JSON + crate registry symbols + `rustc` metadata)
//! - Go binaries (`\xff Go buildinf:` magic + embedded module/dependency/build tables)
//! - WebAssembly (`.wasm`) modules (LEB128 section headers, Type/Import/Export AST, WAT skeleton)
//! - EVM smart contract bytecode (`PUSH4 <selector> EQ PUSH1/PUSH2 <offset> JUMPI` dispatchers + Solidity reconstruction)
//! - .NET CIL assemblies (`BSJB` CLR metadata root, stream headers `#~`, `#Strings`, `#US`, `#GUID`, `#Blob`, P/Invoke)
//! - JavaScript / Electron & Chromium `.asar` archives (16-byte pickle header + JSON virtual FS + `BrowserWindow` flags + IPC channels)
//! - SQLite 3 databases (`SQLite format 3\0` header + read-only `sqlite_master` & `PRAGMA table_info` schema extraction)
//! - Network captures (`.har` HTTP Archive JSON & `.pcap` / `.pcapng` packet headers + endpoint extraction)
//! - Firmware images & Android/Flutter APKs (SquashFS, U-Boot uImage, DTB, Gzip, XZ, Zstd, DEX, `libapp.so`, `libflutter.so`)
//!
//! Includes the **Autonomous REA Engine (`AutonomousReaEngine`)**, which continuously discovers,
//! reverse-engineers, reconstructs pseudocode, and synthesizes multi-token YARA rules for host artifacts.

use anyhow::{anyhow, Result};

pub mod engine;
pub mod entrypoint;
pub mod inspectors;
pub mod path_security;
pub mod prompt_injection;
pub mod types;
pub mod voters;

#[cfg(test)]
mod tests;

pub use engine::*;
pub use entrypoint::*;
pub use inspectors::*;
pub use path_security::*;
pub use prompt_injection::*;
pub use types::*;
pub use voters::*;
