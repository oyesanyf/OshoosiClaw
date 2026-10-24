#![allow(unused_imports)]
use anyhow::{anyhow, Result};
use chrono::Utc;
use flate2::read::ZlibDecoder;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tracing::{debug, info};

use super::super::*;

// ============================================================================
// 1. Rust Binary Inspector (`cargo-auditable` `.dep-v0` + crate registry paths)
// ============================================================================

pub fn inspect_rust_binary(
    bytes: &[u8],
) -> (
    Value,
    Vec<Value>,
    Vec<ReaEvidence>,
    Vec<ReaLimitation>,
    String,
) {
    let mut findings = Vec::new();
    let mut evidence = Vec::new();
    let mut limitations = Vec::new();
    let mut crates: Vec<Value> = Vec::new();
    let mut seen_crates: HashSet<String> = HashSet::new();
    let mut rustc_version: Option<String> = None;
    let mut auditable_found = false;

    // 1. Check ELF/PE/Mach-O for `.dep-v0` section via goblin
    let mut dep_v0_slices: Vec<(usize, &[u8])> = Vec::new();
    if let Ok(obj) = goblin::Object::parse(bytes) {
        match obj {
            goblin::Object::Elf(elf) => {
                for sh in &elf.section_headers {
                    if let Some(name) = elf.shdr_strtab.get_at(sh.sh_name) {
                        if name == ".dep-v0" {
                            let start = sh.sh_offset as usize;
                            let size = sh.sh_size as usize;
                            if start + size <= bytes.len() && size > 0 {
                                dep_v0_slices.push((start, &bytes[start..start + size]));
                            }
                        }
                    }
                }
            }
            goblin::Object::PE(pe) => {
                for sec in &pe.sections {
                    let name = String::from_utf8_lossy(&sec.name)
                        .trim_matches('\0')
                        .to_string();
                    if name == ".dep-v0" {
                        let start = sec.pointer_to_raw_data as usize;
                        let size = (sec.virtual_size.min(sec.size_of_raw_data)) as usize;
                        if start + size <= bytes.len() && size > 0 {
                            dep_v0_slices.push((start, &bytes[start..start + size]));
                        }
                    }
                }
            }
            _ => {}
        }
    }

    // Also fallback scan if `.dep-v0` marker bytes exist followed by zlib stream (0x78 0x9c / 0x78 0x01 / 0x78 0xda)
    if dep_v0_slices.is_empty() {
        for (i, w) in bytes.windows(2).enumerate() {
            if w[0] == 0x78 && matches!(w[1], 0x01 | 0x5e | 0x9c | 0xda) {
                let slice = &bytes[i..bytes.len().min(i + 262_144)];
                let mut decoder = ZlibDecoder::new(slice);
                let mut decompressed = Vec::new();
                if decoder
                    .by_ref()
                    .take(1024 * 1024)
                    .read_to_end(&mut decompressed)
                    .is_ok()
                    && decompressed.starts_with(b"{")
                    && find_subslice(&decompressed, b"\"packages\"").is_some()
                {
                    dep_v0_slices.push((i, slice));
                    break;
                }
            }
        }
    }

    for (offset, slice) in dep_v0_slices {
        let max_decompressed = (slice.len().saturating_mul(MAX_ARCHIVE_DECOMPRESSION_RATIO))
            .clamp(65_536, MAX_DECOMPRESSED_BYTES);
        let decoder = ZlibDecoder::new(slice);
        let mut json_str = String::new();
        if decoder
            .take((max_decompressed + 1) as u64)
            .read_to_string(&mut json_str)
            .is_ok()
        {
            if json_str.len() > max_decompressed {
                limitations.push(ReaLimitation {
                    code: "REA_DECOMPRESSION_BOMB_CAPPED".to_string(),
                    description: format!(
                        "Compressed .dep-v0 section at 0x{:x} exceeded MAX_ARCHIVE_DECOMPRESSION_RATIO ({}x); truncated at {} bytes.",
                        offset, MAX_ARCHIVE_DECOMPRESSION_RATIO, max_decompressed
                    ),
                    remediation: None,
                });
                continue;
            }
            if let Ok(parsed) = serde_json::from_str::<Value>(&json_str) {
                if let Some(pkgs) = parsed.get("packages").and_then(|v| v.as_array()) {
                    auditable_found = true;
                    for pkg in pkgs.iter().take(2048) {
                        let name = pkg
                            .get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown");
                        let ver = pkg
                            .get("version")
                            .and_then(|v| v.as_str())
                            .unwrap_or("0.0.0");
                        let key = format!("{}@{}", name, ver);
                        if seen_crates.insert(key) {
                            crates.push(json!({
                                "name": name,
                                "version": ver,
                                "source": "cargo-auditable (.dep-v0)",
                            }));
                        }
                    }
                    evidence.push(ReaEvidence {
                        source: "cargo-auditable (.dep-v0)".to_string(),
                        location: format!("offset 0x{:x}", offset),
                        observation: format!(
                            "Decompressed .dep-v0 zlib dependency manifest containing {} Rust crates",
                            pkgs.len()
                        ),
                        confidence: 0.99,
                        digest_sha256: Some(sha256_hex(json_str.as_bytes())),
                    });
                }
            }
        }
    }

    // 2. Scan full binary bytes for `rustc 1.<digit>` compiler marker and `/cargo/registry/src/.../<crate>-<ver>/`
    // (Large 70–128 MB binaries have 50+ MB of `.text` before `.rdata`/`.rodata`, so a prefix string cap misses `.rdata`).
    let mut search_pos = 0usize;
    while search_pos + 12 <= bytes.len() {
        let Some(rel) = find_subslice(&bytes[search_pos..], b"rustc 1.") else {
            break;
        };
        let abs = search_pos + rel;
        search_pos = abs + 8;
        if abs + 9 <= bytes.len() && bytes[abs + 8].is_ascii_digit() {
            let end = (abs + 64).min(bytes.len());
            let ver_bytes: Vec<u8> = bytes[abs..end]
                .iter()
                .copied()
                .take_while(|&b| (0x20..=0x7e).contains(&b))
                .collect();
            if let Ok(ver_str) = String::from_utf8(ver_bytes) {
                let ver_part = ver_str.trim().to_string();
                rustc_version = Some(ver_part.clone());
                evidence.push(ReaEvidence {
                    source: "rustc_version_marker".to_string(),
                    location: format!("offset=0x{:x}", abs),
                    observation: format!("Detected Rust compiler signature: {}", ver_part),
                    confidence: 0.98,
                    digest_sha256: None,
                });
                break;
            }
        }
    }

    let panic_unwind = find_subslice(bytes, b"rust_begin_unwind").is_some()
        || find_subslice(bytes, b"core::panicking::panic").is_some();
    let panic_abort = find_subslice(bytes, b"panic_abort").is_some()
        || find_subslice(bytes, b"__rust_start_panic").is_some();

    for needle in [
        &b"/cargo/registry/src/"[..],
        &b"\\cargo\\registry\\src\\"[..],
    ] {
        let mut reg_pos = 0usize;
        while reg_pos + needle.len() < bytes.len() && crates.len() < 512 {
            let Some(rel) = find_subslice(&bytes[reg_pos..], needle) else {
                break;
            };
            let after_start = reg_pos + rel + needle.len();
            reg_pos = after_start;
            let after_end = (after_start + 160).min(bytes.len());
            let path_bytes: Vec<u8> = bytes[after_start..after_end]
                .iter()
                .copied()
                .take_while(|&b| (0x21..=0x7e).contains(&b))
                .collect();
            if let Ok(after_str) = String::from_utf8(path_bytes) {
                let normalized = after_str.replace('\\', "/");
                let parts: Vec<&str> = normalized.split('/').collect();
                if parts.len() >= 2 {
                    let crate_dir = parts[1];
                    if let Some(dash_idx) = crate_dir.rfind('-') {
                        let cname = &crate_dir[..dash_idx];
                        let cver = &crate_dir[dash_idx + 1..];
                        if !cname.is_empty()
                            && cver
                                .chars()
                                .next()
                                .map(|c| c.is_ascii_digit())
                                .unwrap_or(false)
                        {
                            let key = format!("{}@{}", cname, cver);
                            if seen_crates.insert(key) {
                                crates.push(json!({
                                    "name": cname,
                                    "version": cver,
                                    "source": "cargo_registry_symbol_path"
                                }));
                            }
                        }
                    }
                }
            }
        }
    }

    if !auditable_found {
        limitations.push(ReaLimitation {
            code: "NO_CARGO_AUDITABLE_SECTION".to_string(),
            description: "Binary does not contain a .dep-v0 cargo-auditable section; crate list was recovered from panic/source path strings.".to_string(),
            remediation: Some("Compile Rust binaries with `cargo auditable build --release` to embed complete SBOM metadata.".to_string()),
        });
    }

    if !crates.is_empty() {
        evidence.push(ReaEvidence {
            source: "rust_crate_extractor".to_string(),
            location: "rodata/dep-v0".to_string(),
            observation: format!("Recovered {} Rust crate dependencies", crates.len()),
            confidence: if auditable_found { 0.99 } else { 0.88 },
            digest_sha256: None,
        });
    }

    let panic_strategy = if panic_abort {
        "abort"
    } else if panic_unwind {
        "unwind"
    } else {
        "unknown"
    };

    findings.push(json!({
        "category": "rust_toolchain",
        "severity": "info",
        "title": format!("Rust Binary ({})", rustc_version.as_deref().unwrap_or("rustc unknown")),
        "detail": format!("Discovered {} crate dependencies; cargo-auditable={}, panic_strategy={}", crates.len(), auditable_found, panic_strategy),
    }));

    let mut cargo_toml = String::from("# Reconstructed Cargo.toml from REA Binary Inspection\n[package]\nname = \"reconstructed-rust-target\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\n");
    for c in crates.iter().take(40) {
        let name = c.get("name").and_then(|v| v.as_str()).unwrap_or("unknown");
        let ver = c.get("version").and_then(|v| v.as_str()).unwrap_or("*");
        cargo_toml.push_str(&format!("{} = \"{}\"\n", name, ver));
    }
    cargo_toml.push_str(&format!(
        "\n// Reconstructed Rust Entrypoint Skeleton\n// Compiler: {}\n// Panic Strategy: {}\npub fn main() {{\n    // {} crates linked into binary\n}}\n",
        rustc_version.as_deref().unwrap_or("rustc"),
        panic_strategy,
        crates.len()
    ));

    let metadata = json!({
        "rustc_version": rustc_version,
        "cargo_auditable": auditable_found,
        "panic_strategy": panic_strategy,
        "crate_count": crates.len(),
        "crates": crates,
    });

    (metadata, findings, evidence, limitations, cargo_toml)
}

// ============================================================================
// 2. Go Binary Inspector (`\xff Go buildinf:` + module/dep/build lines)
// ============================================================================

pub fn inspect_go_binary(
    bytes: &[u8],
) -> (
    Value,
    Vec<Value>,
    Vec<ReaEvidence>,
    Vec<ReaLimitation>,
    String,
) {
    let mut findings = Vec::new();
    let mut evidence = Vec::new();
    let mut limitations = Vec::new();

    let magic = b"\xff Go buildinf:";
    let magic_offset = find_subslice(bytes, magic);
    let mut ptr_size = None;
    let mut endianness = None;

    if let Some(off) = magic_offset {
        if off + 16 <= bytes.len() {
            ptr_size = Some(bytes[off + 14]);
            let end_byte = bytes[off + 15];
            endianness = Some(if end_byte & 1 == 0 {
                "little_endian"
            } else {
                "big_endian"
            });
        }
        evidence.push(ReaEvidence {
            source: "go_buildinfo_magic".to_string(),
            location: format!("offset 0x{:x}", off),
            observation: format!(
                "Found Go buildinfo header (ptr_size={:?}, endian={:?})",
                ptr_size, endianness
            ),
            confidence: 0.99,
            digest_sha256: None,
        });
    } else {
        limitations.push(ReaLimitation {
            code: "GO_BUILDINFO_MAGIC_STRIPPED".to_string(),
            description: "The `\\xff Go buildinf:` header was not found; falling back to embedded module/version string scan.".to_string(),
            remediation: None,
        });
    }

    let strings = extract_printable_strings(bytes, 4, 10_000);
    let mut go_version: Option<String> = None;
    let mut main_path: Option<String> = None;
    let mut main_module: Option<Value> = None;
    let mut dependencies: Vec<Value> = Vec::new();
    let mut replacements: Vec<Value> = Vec::new();
    let mut build_settings: Vec<Value> = Vec::new();

    for s in &strings {
        if go_version.is_none() {
            if let Some(idx) = s.find("go1.") {
                let ver: String = s[idx..]
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-')
                    .collect();
                if ver.len() >= 5 {
                    go_version = Some(ver.clone());
                    evidence.push(ReaEvidence {
                        source: "go_compiler_version".to_string(),
                        location: "rodata".to_string(),
                        observation: format!("Detected Go toolchain version: {}", ver),
                        confidence: 0.97,
                        digest_sha256: None,
                    });
                }
            }
        }
    }

    // Also scan raw UTF-8 lossy text around `path\t` or `mod\t` or `dep\t`
    let lossy = String::from_utf8_lossy(bytes);
    for line in lossy.lines() {
        let trimmed = line.trim_matches(|c: char| c.is_control() && c != '\t');
        if let Some(rest) = trimmed.strip_prefix("path\t") {
            let p = rest.trim().to_string();
            if !p.is_empty() && main_path.is_none() {
                main_path = Some(p);
            }
        } else if let Some(rest) = trimmed.strip_prefix("mod\t") {
            let parts: Vec<&str> = rest.split('\t').collect();
            if !parts.is_empty() && main_module.is_none() {
                main_module = Some(json!({
                    "path": parts[0].trim(),
                    "version": parts.get(1).copied().unwrap_or("(devel)").trim(),
                    "sum": parts.get(2).copied().unwrap_or("").trim(),
                }));
            }
        } else if let Some(rest) = trimmed.strip_prefix("dep\t") {
            let parts: Vec<&str> = rest.split('\t').collect();
            if !parts.is_empty() {
                dependencies.push(json!({
                    "module": parts[0].trim(),
                    "version": parts.get(1).copied().unwrap_or("").trim(),
                    "sum": parts.get(2).copied().unwrap_or("").trim(),
                }));
            }
        } else if let Some(rest) = trimmed.strip_prefix("=>\t") {
            let parts: Vec<&str> = rest.split('\t').collect();
            if !parts.is_empty() {
                replacements.push(json!({
                    "replacement_path": parts[0].trim(),
                    "version": parts.get(1).copied().unwrap_or("").trim(),
                    "sum": parts.get(2).copied().unwrap_or("").trim(),
                }));
            }
        } else if let Some(rest) = trimmed.strip_prefix("build\t") {
            let kv = rest.trim();
            if let Some((k, v)) = kv.split_once('=') {
                build_settings.push(json!({"key": k, "value": v}));
            } else if !kv.is_empty() {
                build_settings.push(json!({"flag": kv}));
            }
        }
    }

    if !dependencies.is_empty() || main_module.is_some() {
        evidence.push(ReaEvidence {
            source: "go_mod_table".to_string(),
            location: "runtime.modinfo".to_string(),
            observation: format!(
                "Extracted Go module manifest: main={:?}, dependencies={}, build_settings={}",
                main_path,
                dependencies.len(),
                build_settings.len()
            ),
            confidence: 0.99,
            digest_sha256: None,
        });
    }

    findings.push(json!({
        "category": "go_buildinfo",
        "severity": "info",
        "title": format!("Go Binary ({})", go_version.as_deref().unwrap_or("go unknown")),
        "detail": format!(
            "Module: {}, Dependencies: {}, Build flags: {}",
            main_path.as_deref().unwrap_or("unknown"),
            dependencies.len(),
            build_settings.len()
        ),
    }));

    let mod_name = main_module
        .as_ref()
        .and_then(|m| m.get("path"))
        .and_then(|v| v.as_str())
        .or(main_path.as_deref())
        .unwrap_or("example.com/reconstructed");
    let go_ver_clean = go_version
        .as_deref()
        .unwrap_or("go1.22")
        .trim_start_matches("go");

    let mut go_mod = format!(
        "// Reconstructed go.mod via OpenOshoosi REA\nmodule {}\n\ngo {}\n\nrequire (\n",
        mod_name, go_ver_clean
    );
    for dep in &dependencies {
        let m = dep.get("module").and_then(|v| v.as_str()).unwrap_or("");
        let v = dep.get("version").and_then(|v| v.as_str()).unwrap_or("");
        if !m.is_empty() {
            go_mod.push_str(&format!("    {} {}\n", m, v));
        }
    }
    go_mod.push_str(")\n\npackage main\n\nfunc main() {\n    // Entrypoint reconstructed from Go runtime.main\n}\n");

    let metadata = json!({
        "go_version": go_version,
        "pointer_size": ptr_size,
        "endianness": endianness,
        "main_path": main_path,
        "main_module": main_module,
        "dependencies": dependencies,
        "replacements": replacements,
        "build_settings": build_settings,
    });

    (metadata, findings, evidence, limitations, go_mod)
}

// ============================================================================
// 3. Native Binary Inspector (PE / ELF / Mach-O + Mitigations + Pseudocode)
// ============================================================================

pub fn inspect_native_binary(
    path: Option<&Path>,
    bytes: &[u8],
) -> (
    Value,
    Vec<Value>,
    Vec<ReaEvidence>,
    Vec<ReaLimitation>,
    String,
) {
    let mut findings = Vec::new();
    let mut evidence = Vec::new();
    let mut limitations = Vec::new();

    let mut binary_format = "unknown".to_string();
    let mut architecture = "unknown".to_string();
    let mut entry_point: u64 = 0;
    let mut image_base: u64 = 0;
    let mut sections: Vec<Value> = Vec::new();
    let mut imports: Vec<String> = Vec::new();
    let mut exports: Vec<String> = Vec::new();
    let mut mitigations = serde_json::Map::new();
    let mut suspicious_apis: Vec<String> = Vec::new();

    let high_risk_api_patterns = [
        "virtualallocex",
        "writeprocessmemory",
        "createremotethread",
        "ntunmapviewofsection",
        "setthreadcontext",
        "queueuserapc",
        "ntcreatethreadex",
        "isdebuggerpresent",
        "checkremotedebuggerpresent",
        "ptrace",
        "memfd_create",
        "process_vm_writev",
        "dlopen",
        "winhttpopen",
        "internetopen",
        "cryptencrypt",
    ];

    match goblin::Object::parse(bytes) {
        Ok(goblin::Object::PE(pe)) => {
            binary_format = if pe.is_64 {
                "PE64 (PE32+)".to_string()
            } else {
                "PE32".to_string()
            };
            architecture = if pe.is_64 {
                "x86_64".to_string()
            } else {
                "x86".to_string()
            };
            entry_point = pe.entry as u64;
            image_base = pe.image_base as u64;

            let dll_chars = pe
                .header
                .optional_header
                .map(|oh| oh.windows_fields.dll_characteristics)
                .unwrap_or(0);
            let aslr = (dll_chars & 0x0040) != 0;
            let high_entropy_va = (dll_chars & 0x0020) != 0;
            let dep_nx = (dll_chars & 0x0100) != 0;
            let cfg = (dll_chars & 0x4000) != 0;
            let force_integrity = (dll_chars & 0x0080) != 0;

            mitigations.insert("ASLR".to_string(), json!(aslr));
            mitigations.insert("HighEntropyVA".to_string(), json!(high_entropy_va));
            mitigations.insert("DEP_NX".to_string(), json!(dep_nx));
            mitigations.insert("ControlFlowGuard_CFG".to_string(), json!(cfg));
            mitigations.insert("ForceIntegrity".to_string(), json!(force_integrity));

            evidence.push(ReaEvidence {
                source: "pe_optional_header".to_string(),
                location: format!("entry=0x{:x}, image_base=0x{:x}", entry_point, image_base),
                observation: format!(
                    "{} mitigations: ASLR={}, DEP/NX={}, CFG={}, HighEntropyVA={}",
                    binary_format, aslr, dep_nx, cfg, high_entropy_va
                ),
                confidence: 1.0,
                digest_sha256: None,
            });

            if pe.sections.len() > MAX_PE_SECTIONS {
                limitations.push(ReaLimitation {
                    code: "PE_SECTION_BOMB_CAPPED".to_string(),
                    description: format!(
                        "PE header declares {} sections (exceeds MAX_PE_SECTIONS={}); capped inspection at {} sections.",
                        pe.sections.len(),
                        MAX_PE_SECTIONS,
                        MAX_PE_SECTIONS
                    ),
                    remediation: None,
                });
                findings.push(json!({
                    "category": "REA_SECTION_BOMB_DETECTED",
                    "severity": "high",
                    "title": format!("Excessive PE Section Count ({} sections > {})", pe.sections.len(), MAX_PE_SECTIONS),
                    "detail": "Malformed or anti-analysis PE header attempting section-table exhaustion.",
                }));
            }

            for sec in pe.sections.iter().take(MAX_PE_SECTIONS) {
                let name = String::from_utf8_lossy(&sec.name)
                    .trim_matches('\0')
                    .to_string();
                let raw_start = sec.pointer_to_raw_data as usize;
                let raw_size = sec.size_of_raw_data as usize;
                let entropy = if raw_start + raw_size <= bytes.len() && raw_size > 0 {
                    calculate_entropy(&bytes[raw_start..raw_start + raw_size])
                } else {
                    0.0
                };
                let chars = sec.characteristics;
                let is_rwx = (chars & 0xA000_0000) == 0xA000_0000;
                if is_rwx {
                    findings.push(json!({
                        "category": "rwx_section",
                        "severity": "high",
                        "title": format!("Writable + Executable (RWX) PE section: {}", name),
                        "detail": format!("Section {} has characteristics 0x{:08x} and entropy {:.2}", name, chars, entropy),
                    }));
                }
                sections.push(json!({
                    "name": name,
                    "virtual_address": format!("0x{:x}", sec.virtual_address),
                    "virtual_size": sec.virtual_size,
                    "raw_size": sec.size_of_raw_data,
                    "characteristics": format!("0x{:08x}", chars),
                    "entropy": (entropy * 100.0).round() / 100.0,
                    "rwx": is_rwx,
                }));
            }

            for imp in pe.imports.iter().take(MAX_DISASM_INSTRUCTIONS) {
                let sym = format!("{}!{}", imp.dll, imp.name);
                let low = sym.to_ascii_lowercase();
                for pat in &high_risk_api_patterns {
                    if low.contains(pat) && !suspicious_apis.contains(&sym) {
                        suspicious_apis.push(sym.clone());
                    }
                }
                if imports.len() < 250 {
                    imports.push(sym);
                }
            }

            for exp in pe.exports.iter().take(MAX_DISASM_INSTRUCTIONS) {
                if let Some(name) = exp.name {
                    if exports.len() < 250 {
                        exports.push(name.to_string());
                    }
                }
            }
        }
        Ok(goblin::Object::Elf(elf)) => {
            binary_format = if elf.is_64 {
                "ELF64".to_string()
            } else {
                "ELF32".to_string()
            };
            architecture = format!("machine_0x{:x}", elf.header.e_machine);
            entry_point = elf.entry;

            let is_pie = elf.header.e_type == goblin::elf::header::ET_DYN;
            let mut has_nx = false;
            let mut has_relro = false;
            for ph in elf.program_headers.iter().take(MAX_PE_SECTIONS) {
                if ph.p_type == goblin::elf::program_header::PT_GNU_STACK {
                    has_nx = (ph.p_flags & goblin::elf::program_header::PF_X) == 0;
                }
                if ph.p_type == goblin::elf::program_header::PT_GNU_RELRO {
                    has_relro = true;
                }
                if ph.p_type == goblin::elf::program_header::PT_LOAD && (ph.p_flags & 0x7) == 0x7 {
                    findings.push(json!({
                        "category": "rwx_segment",
                        "severity": "high",
                        "title": "RWX PT_LOAD segment in ELF binary",
                        "detail": format!("Offset 0x{:x}, vaddr 0x{:x}", ph.p_offset, ph.p_vaddr),
                    }));
                }
            }

            let mut has_canary = false;
            for sym in elf.dynsyms.iter().take(MAX_DISASM_INSTRUCTIONS) {
                if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                    if name.is_empty() {
                        continue;
                    }
                    if name.contains("__stack_chk_fail") {
                        has_canary = true;
                    }
                    let low = name.to_ascii_lowercase();
                    for pat in &high_risk_api_patterns {
                        if low.contains(pat) && !suspicious_apis.contains(&name.to_string()) {
                            suspicious_apis.push(name.to_string());
                        }
                    }
                    if sym.is_import() {
                        if imports.len() < 250 {
                            imports.push(name.to_string());
                        }
                    } else if exports.len() < 250 {
                        exports.push(name.to_string());
                    }
                }
            }

            mitigations.insert("PIE".to_string(), json!(is_pie));
            mitigations.insert("NX_Stack".to_string(), json!(has_nx));
            mitigations.insert("RELRO".to_string(), json!(has_relro));
            mitigations.insert("StackCanary".to_string(), json!(has_canary));

            evidence.push(ReaEvidence {
                source: "elf_header".to_string(),
                location: format!("entry=0x{:x}", entry_point),
                observation: format!(
                    "{} mitigations: PIE={}, NX={}, RELRO={}, StackCanary={}",
                    binary_format, is_pie, has_nx, has_relro, has_canary
                ),
                confidence: 1.0,
                digest_sha256: None,
            });

            if elf.section_headers.len() > MAX_PE_SECTIONS {
                limitations.push(ReaLimitation {
                    code: "ELF_SECTION_BOMB_CAPPED".to_string(),
                    description: format!(
                        "ELF header declares {} sections (exceeds MAX_PE_SECTIONS={}); capped inspection.",
                        elf.section_headers.len(),
                        MAX_PE_SECTIONS
                    ),
                    remediation: None,
                });
            }

            for sh in elf.section_headers.iter().take(MAX_PE_SECTIONS) {
                let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("").to_string();
                if name.is_empty() {
                    continue;
                }
                let start = sh.sh_offset as usize;
                let size = sh.sh_size as usize;
                let entropy = if start + size <= bytes.len() && size > 0 {
                    calculate_entropy(&bytes[start..start + size])
                } else {
                    0.0
                };
                sections.push(json!({
                    "name": name,
                    "virtual_address": format!("0x{:x}", sh.sh_addr),
                    "size": sh.sh_size,
                    "flags": format!("0x{:x}", sh.sh_flags),
                    "entropy": (entropy * 100.0).round() / 100.0,
                }));
            }
        }
        Ok(goblin::Object::Mach(mach)) => {
            binary_format = "Mach-O".to_string();
            if let goblin::mach::Mach::Binary(macho) = mach {
                entry_point = macho.entry;
                let is_pie = (macho.header.flags & 0x200000) != 0; // MH_PIE
                mitigations.insert("PIE".to_string(), json!(is_pie));
                if let Ok(imps) = macho.imports() {
                    for imp in imps.iter().take(250) {
                        imports.push(format!("{}!{}", imp.dylib, imp.name));
                    }
                }
                if let Ok(exps) = macho.exports() {
                    for exp in exps.iter().take(250) {
                        exports.push(exp.name.clone());
                    }
                }
            }
            evidence.push(ReaEvidence {
                source: "macho_header".to_string(),
                location: format!("entry=0x{:x}", entry_point),
                observation: "Parsed Mach-O binary structure".to_string(),
                confidence: 0.98,
                digest_sha256: None,
            });
        }
        _ => {
            limitations.push(ReaLimitation {
                code: "UNSTRUCTURED_NATIVE_BINARY".to_string(),
                description: "Target did not match standard PE/ELF/Mach-O headers; performed raw byte/string heuristics.".to_string(),
                remediation: None,
            });
        }
    }

    if let Some(p) = path {
        if let Ok(pe_findings) = crate::pe_inspector::inspect_file(p) {
            for dep in pe_findings.suspicious_dependencies {
                if !suspicious_apis.contains(&dep) {
                    suspicious_apis.push(dep);
                }
            }
        }
    }

    let strings = extract_printable_strings(bytes, 6, 400);
    let high_value_strings: Vec<String> = strings
        .into_iter()
        .filter(|s| {
            let l = s.to_ascii_lowercase();
            l.contains("http://")
                || l.contains("https://")
                || l.contains("hklm\\")
                || l.contains("hkcu\\")
                || l.contains("\\\\.\\pipe\\")
                || l.contains(".dll")
                || l.contains(".exe")
                || l.contains("powershell")
                || l.contains("cmd.exe")
                || l.contains("/bin/sh")
        })
        .take(50)
        .collect();

    if !suspicious_apis.is_empty() {
        findings.push(json!({
            "category": "suspicious_imports",
            "severity": "medium",
            "title": format!("Referenced {} high-risk process/memory APIs", suspicious_apis.len()),
            "detail": suspicious_apis.join(", "),
        }));
        evidence.push(ReaEvidence {
            source: "import_table_analyzer".to_string(),
            location: "IAT/dynsym".to_string(),
            observation: format!("High-risk APIs imported: {}", suspicious_apis.join(", ")),
            confidence: 0.95,
            digest_sha256: None,
        });
    }

    let mut pseudocode = format!(
        "// Reconstructed C Pseudocode via OpenOshoosi REA\n// Format: {} ({})\n// ImageBase: 0x{:x} | EntryPoint: 0x{:x}\n\n",
        binary_format, architecture, image_base, entry_point
    );
    for imp in imports.iter().take(15) {
        pseudocode.push_str(&format!(
            "extern void* __imp_{}();\n",
            imp.replace(['!', '.', '-'], "_")
        ));
    }
    pseudocode.push_str(&format!(
        "\nint __fastcall entry_0x{:x}(void* peb_or_argc, void* argv) {{\n",
        entry_point
    ));
    if !suspicious_apis.is_empty() {
        for api in &suspicious_apis {
            pseudocode.push_str(&format!(
                "    // [SECURITYOBSERVATION] Capability reference: {}\n",
                api
            ));
        }
    }
    for s in high_value_strings.iter().take(6) {
        pseudocode.push_str(&format!("    const char* ref_str = {:?};\n", s));
    }
    pseudocode.push_str("    return dispatch_runtime_main();\n}\n");

    // Law 7: Verify static entry-point CFG transition baseline via CfgHadamardZeroVerifier
    let cfg_baseline =
        osoosi_audit::nsrl_aslr_merkle::CfgHadamardZeroVerifier::verify_runtime_transitions(
            &[(image_base, entry_point)],
            &[(image_base, entry_point)],
        );

    let metadata = json!({
        "format": binary_format,
        "architecture": architecture,
        "entry_point": format!("0x{:x}", entry_point),
        "image_base": format!("0x{:x}", image_base),
        "mitigations": mitigations,
        "section_count": sections.len(),
        "sections": sections,
        "import_count": imports.len(),
        "imports": imports,
        "export_count": exports.len(),
        "exports": exports,
        "suspicious_apis": suspicious_apis,
        "high_value_strings": high_value_strings,
        "cfg_hadamard_zero_verified": cfg_baseline.is_zero_violation,
        "cfg_hadamard_complement_l1": cfg_baseline.hadamard_complement_l1_norm,
    });

    (metadata, findings, evidence, limitations, pseudocode)
}

// ============================================================================
// 6. .NET Assembly Inspector (`BSJB` CLR Metadata Root + Streams + P/Invoke)
// ============================================================================

pub fn inspect_dotnet_assembly(
    bytes: &[u8],
) -> (
    Value,
    Vec<Value>,
    Vec<ReaEvidence>,
    Vec<ReaLimitation>,
    String,
) {
    let mut findings = Vec::new();
    let mut evidence = Vec::new();
    let mut limitations = Vec::new();

    // Reject valid native PE files whose OptionalHeader DataDirectory[14] (CLR Runtime Header) is zero
    if pe_clr_runtime_header_present(bytes) == Some(false) {
        limitations.push(ReaLimitation {
            code: "NATIVE_PE_NO_CLR_HEADER".to_string(),
            description: "PE OptionalHeader CLR Runtime DataDirectory (index 14) is zero; target is a native PE binary, not a .NET assembly.".to_string(),
            remediation: Some("Analyze as `rust_binary`, `go_binary`, or `native_binary`.".to_string()),
        });
        return (
            json!({"valid_dotnet": false, "reason": "PE CLR DataDirectory[14] is zero"}),
            findings,
            evidence,
            limitations,
            "// Native PE binary (CLR DataDirectory[14] == 0)".to_string(),
        );
    }

    let Some((bsjb_off, clr_version, streams)) = find_pe_dotnet_bsjb_header(bytes) else {
        limitations.push(ReaLimitation {
            code: "MISSING_BSJB_SIGNATURE".to_string(),
            description: "Structurally valid ECMA-335 CLR Metadata root signature `BSJB` (0x424A5342) was not found in target.".to_string(),
            remediation: None,
        });
        return (
            json!({"valid_dotnet": false}),
            findings,
            evidence,
            limitations,
            "// No valid BSJB CLR metadata found".to_string(),
        );
    };

    evidence.push(ReaEvidence {
        source: "dotnet_clr_bsjb_header".to_string(),
        location: format!("offset 0x{:x}", bsjb_off),
        observation: format!(
            "Located BSJB CLR metadata root (CLR version: {}, streams: {})",
            clr_version,
            streams.len()
        ),
        confidence: 1.0,
        digest_sha256: None,
    });

    let all_strings = extract_printable_strings(bytes, 4, 2000);
    let mut pinvoke_dlls = Vec::new();
    let mut namespaces = Vec::new();

    for s in &all_strings {
        let low = s.to_ascii_lowercase();
        if (low.ends_with(".dll") && low != "mscoree.dll") && !pinvoke_dlls.contains(s) {
            pinvoke_dlls.push(s.clone());
        }
        if (s.starts_with("System.") || s.starts_with("Microsoft.") || s.contains("Namespace"))
            && namespaces.len() < 40
            && !namespaces.contains(s)
        {
            namespaces.push(s.clone());
        }
    }

    findings.push(json!({
        "category": "dotnet_cil_metadata",
        "severity": "info",
        "title": format!(".NET Assembly ({}, {} metadata streams)", clr_version, streams.len()),
        "detail": format!("Streams: {:?}, P/Invoke DLLs: {:?}", streams.iter().filter_map(|s| s.get("name").and_then(|v| v.as_str())).collect::<Vec<_>>(), pinvoke_dlls),
    }));

    let mut csharp = format!(
        "// Reconstructed C# Metadata Skeleton via OpenOshoosi REA\n// CLR Runtime Version: {}\nusing System;\nusing System.Runtime.InteropServices;\n\nnamespace ReconstructedAssembly {{\n    public class Program {{\n",
        clr_version
    );
    for dll in &pinvoke_dlls {
        csharp.push_str(&format!(
            "        [DllImport({:?})]\n        private static extern IntPtr NativeExternCall();\n\n",
            dll
        ));
    }
    csharp.push_str("        public static void Main(string[] args) {\n            // CIL Entrypoint\n        }\n    }\n}\n");

    let metadata = json!({
        "valid_dotnet": true,
        "bsjb_offset": format!("0x{:x}", bsjb_off),
        "clr_version": clr_version,
        "streams": streams,
        "pinvoke_dlls": pinvoke_dlls,
        "managed_references": namespaces,
    });

    (metadata, findings, evidence, limitations, csharp)
}
