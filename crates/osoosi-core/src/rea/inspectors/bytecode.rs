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
// 4. WebAssembly (`.wasm`) Artifact Inspector (LEB128 + WAT Skeleton)
// ============================================================================

fn read_leb128_u32(bytes: &[u8], pos: &mut usize) -> Option<u32> {
    let mut result = 0u32;
    let mut shift = 0u32;
    for _ in 0..5 {
        if *pos >= bytes.len() {
            return None;
        }
        let byte = bytes[*pos];
        *pos += 1;
        result |= ((byte & 0x7F) as u32) << shift;
        if (byte & 0x80) == 0 {
            return Some(result);
        }
        shift += 7;
    }
    None
}

fn read_wasm_name(bytes: &[u8], pos: &mut usize) -> Option<String> {
    let len = read_leb128_u32(bytes, pos)? as usize;
    if *pos + len > bytes.len() {
        return None;
    }
    let s = String::from_utf8_lossy(&bytes[*pos..*pos + len]).to_string();
    *pos += len;
    Some(s)
}

fn wasm_valtype_str(b: u8) -> &'static str {
    match b {
        0x7F => "i32",
        0x7E => "i64",
        0x7D => "f32",
        0x7C => "f64",
        0x7B => "v128",
        0x70 => "funcref",
        0x6F => "externref",
        _ => "any",
    }
}

pub fn inspect_wasm_artifact(
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

    if bytes.len() < 8 || &bytes[0..4] != b"\0asm" {
        limitations.push(ReaLimitation {
            code: "INVALID_WASM_MAGIC".to_string(),
            description: "File does not start with WebAssembly `\\0asm` magic bytes.".to_string(),
            remediation: None,
        });
        return (
            json!({"valid_wasm": false}),
            findings,
            evidence,
            limitations,
            "(module ;; invalid wasm header)".to_string(),
        );
    }

    let version = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    evidence.push(ReaEvidence {
        source: "wasm_binary_header".to_string(),
        location: "offset 0x0..0x8".to_string(),
        observation: format!(
            "Validated WebAssembly binary magic `\\0asm` version {}",
            version
        ),
        confidence: 1.0,
        digest_sha256: None,
    });

    let mut pos = 8usize;
    let mut sections = Vec::new();
    let mut func_types: Vec<String> = Vec::new();
    let mut imports: Vec<Value> = Vec::new();
    let mut defined_func_type_indices: Vec<u32> = Vec::new();
    let mut exports: Vec<Value> = Vec::new();
    let mut custom_sections: Vec<String> = Vec::new();
    let mut function_body_count = 0u32;

    while pos < bytes.len() {
        let sec_id = bytes[pos];
        pos += 1;
        let Some(sec_len) = read_leb128_u32(bytes, &mut pos) else {
            break;
        };
        let sec_len = sec_len as usize;
        if pos + sec_len > bytes.len() {
            limitations.push(ReaLimitation {
                code: "TRUNCATED_WASM_SECTION".to_string(),
                description: format!(
                    "Section id {} declared length {} exceeding buffer.",
                    sec_id, sec_len
                ),
                remediation: None,
            });
            break;
        }
        let sec_start = pos;
        let sec_end = pos + sec_len;
        let sec_name = match sec_id {
            0 => "Custom",
            1 => "Type",
            2 => "Import",
            3 => "Function",
            4 => "Table",
            5 => "Memory",
            6 => "Global",
            7 => "Export",
            8 => "Start",
            9 => "Element",
            10 => "Code",
            11 => "Data",
            12 => "DataCount",
            _ => "Unknown",
        };
        sections.push(json!({
            "id": sec_id,
            "name": sec_name,
            "offset": format!("0x{:x}", sec_start),
            "size": sec_len,
        }));

        let mut cur = sec_start;
        match sec_id {
            0 => {
                if let Some(cname) = read_wasm_name(bytes, &mut cur) {
                    custom_sections.push(cname);
                }
            }
            1 => {
                // Type section
                if let Some(count) = read_leb128_u32(bytes, &mut cur) {
                    for _ in 0..count.min(1024) {
                        if cur >= sec_end || bytes[cur] != 0x60 {
                            break;
                        }
                        cur += 1;
                        let Some(p_count) = read_leb128_u32(bytes, &mut cur) else {
                            break;
                        };
                        let mut params = Vec::new();
                        for _ in 0..p_count.min(128) {
                            if cur < sec_end {
                                params.push(wasm_valtype_str(bytes[cur]));
                                cur += 1;
                            }
                        }
                        let Some(r_count) = read_leb128_u32(bytes, &mut cur) else {
                            break;
                        };
                        let mut results = Vec::new();
                        for _ in 0..r_count.min(128) {
                            if cur < sec_end {
                                results.push(wasm_valtype_str(bytes[cur]));
                                cur += 1;
                            }
                        }
                        let sig = format!(
                            "(func (param {}) (result {}))",
                            params.join(" "),
                            results.join(" ")
                        );
                        func_types.push(sig);
                    }
                }
            }
            2 => {
                // Import section
                if let Some(count) = read_leb128_u32(bytes, &mut cur) {
                    for _ in 0..count.min(1024) {
                        let Some(module) = read_wasm_name(bytes, &mut cur) else {
                            break;
                        };
                        let Some(field) = read_wasm_name(bytes, &mut cur) else {
                            break;
                        };
                        if cur >= sec_end {
                            break;
                        }
                        let kind_byte = bytes[cur];
                        cur += 1;
                        let mut type_index_opt: Option<u32> = None;
                        let kind = match kind_byte {
                            0x00 => {
                                type_index_opt =
                                    Some(read_leb128_u32(bytes, &mut cur).unwrap_or(0));
                                "func"
                            }
                            0x01 => {
                                cur = (cur + 3).min(sec_end);
                                "table"
                            }
                            0x02 => {
                                if cur < sec_end {
                                    let flags = bytes[cur];
                                    cur += 1;
                                    let _ = read_leb128_u32(bytes, &mut cur);
                                    if (flags & 1) != 0 {
                                        let _ = read_leb128_u32(bytes, &mut cur);
                                    }
                                }
                                "memory"
                            }
                            0x03 => {
                                cur = (cur + 2).min(sec_end);
                                "global"
                            }
                            _ => "unknown",
                        };
                        let mut imp_obj = json!({
                            "module": module,
                            "name": field,
                            "kind": kind,
                        });
                        if let Some(t_idx) = type_index_opt {
                            imp_obj["type_index"] = json!(t_idx);
                        }
                        imports.push(imp_obj);
                    }
                }
            }
            3 => {
                // Function section (maps defined functions to their Type section indices)
                if let Some(count) = read_leb128_u32(bytes, &mut cur) {
                    for _ in 0..count.min(1024) {
                        if cur >= sec_end {
                            break;
                        }
                        if let Some(t_idx) = read_leb128_u32(bytes, &mut cur) {
                            defined_func_type_indices.push(t_idx);
                        } else {
                            break;
                        }
                    }
                }
            }
            7 => {
                // Export section
                if let Some(count) = read_leb128_u32(bytes, &mut cur) {
                    for _ in 0..count.min(1024) {
                        let Some(name) = read_wasm_name(bytes, &mut cur) else {
                            break;
                        };
                        if cur >= sec_end {
                            break;
                        }
                        let kind_byte = bytes[cur];
                        cur += 1;
                        let idx = read_leb128_u32(bytes, &mut cur).unwrap_or(0);
                        let kind = match kind_byte {
                            0x00 => "func",
                            0x01 => "table",
                            0x02 => "memory",
                            0x03 => "global",
                            _ => "unknown",
                        };
                        exports.push(json!({
                            "name": name,
                            "kind": kind,
                            "index": idx,
                        }));
                    }
                }
            }
            10 => {
                // Code section
                if let Some(count) = read_leb128_u32(bytes, &mut cur) {
                    if count as usize > MAX_DISASM_INSTRUCTIONS {
                        limitations.push(ReaLimitation {
                            code: "WASM_CODE_BODY_COUNT_CAPPED".to_string(),
                            description: format!(
                                "WASM Code section claims {} function bodies (exceeds MAX_DISASM_INSTRUCTIONS={}); capped.",
                                count, MAX_DISASM_INSTRUCTIONS
                            ),
                            remediation: None,
                        });
                    }
                    function_body_count = count.min(MAX_DISASM_INSTRUCTIONS as u32);
                }
            }
            _ => {}
        }

        pos = sec_end;
        if sections.len() >= MAX_PE_SECTIONS {
            limitations.push(ReaLimitation {
                code: "WASM_SECTION_BOMB_CAPPED".to_string(),
                description: format!(
                    "WASM module exceeded MAX_PE_SECTIONS ({}) sections; capped.",
                    MAX_PE_SECTIONS
                ),
                remediation: None,
            });
            break;
        }
    }

    evidence.push(ReaEvidence {
        source: "wasm_section_parser".to_string(),
        location: format!("{} sections", sections.len()),
        observation: format!(
            "Parsed {} types, {} imports, {} exports, {} code bodies",
            func_types.len(),
            imports.len(),
            exports.len(),
            function_body_count
        ),
        confidence: 1.0,
        digest_sha256: None,
    });

    findings.push(json!({
        "category": "wasm_module",
        "severity": "info",
        "title": format!("WebAssembly v{} Module ({} exports, {} imports)", version, exports.len(), imports.len()),
        "detail": format!("Sections: {}, Function bodies: {}", sections.len(), function_body_count),
    }));

    let mut wat = format!(
        "(module ;; Reconstructed by OpenOshoosi REA (WASM v{})\n",
        version
    );
    for (idx, t) in func_types.iter().enumerate() {
        wat.push_str(&format!("  (type $t{} {})\n", idx, t));
    }
    let mut imported_func_count = 0usize;
    for imp in &imports {
        let m = imp.get("module").and_then(|v| v.as_str()).unwrap_or("env");
        let n = imp.get("name").and_then(|v| v.as_str()).unwrap_or("fn");
        let k = imp.get("kind").and_then(|v| v.as_str()).unwrap_or("func");
        if k == "func" {
            let t_idx = imp.get("type_index").and_then(|v| v.as_u64()).unwrap_or(0);
            wat.push_str(&format!(
                "  (import \"{}\" \"{}\" (func $f{} (type $t{})))\n",
                m, n, imported_func_count, t_idx
            ));
            imported_func_count += 1;
        } else {
            wat.push_str(&format!("  (import \"{}\" \"{}\" ({}))\n", m, n, k));
        }
    }
    let defined_total = defined_func_type_indices
        .len()
        .max(function_body_count as usize)
        .min(256);
    for def_i in 0..defined_total {
        let func_idx = imported_func_count + def_i;
        let t_idx = defined_func_type_indices.get(def_i).copied().unwrap_or(0);
        wat.push_str(&format!(
            "  (func $f{} (type $t{}) ;; defined function body #{}\n    unreachable\n  )\n",
            func_idx, t_idx, def_i
        ));
    }
    for exp in &exports {
        let n = exp.get("name").and_then(|v| v.as_str()).unwrap_or("export");
        let k = exp.get("kind").and_then(|v| v.as_str()).unwrap_or("func");
        let idx = exp.get("index").and_then(|v| v.as_u64()).unwrap_or(0);
        wat.push_str(&format!("  (export \"{}\" ({} {}))\n", n, k, idx));
    }
    wat.push_str(")\n");

    let metadata = json!({
        "valid_wasm": true,
        "version": version,
        "sections": sections,
        "type_signatures": func_types,
        "imports": imports,
        "defined_function_types": defined_func_type_indices,
        "exports": exports,
        "custom_sections": custom_sections,
        "function_body_count": function_body_count,
    });

    (metadata, findings, evidence, limitations, wat)
}


// ============================================================================
// 5. EVM Smart Contract Bytecode Inspector (Dispatch Table + Selectors + Solidity)
// ============================================================================

/// Known 4-byte Solidity function selector lookup table.
pub fn lookup_evm_selector(selector_hex: &str) -> Option<&'static str> {
    match selector_hex.to_ascii_lowercase().as_str() {
        "a9059cbb" => Some("transfer(address,uint256)"),
        "095ea7b3" => Some("approve(address,uint256)"),
        "70a08231" => Some("balanceOf(address)"),
        "23b872dd" => Some("transferFrom(address,address,uint256)"),
        "18160ddd" => Some("totalSupply()"),
        "06fdde03" => Some("name()"),
        "95d89b41" => Some("symbol()"),
        "313ce567" => Some("decimals()"),
        "dd62ed3e" => Some("allowance(address,address)"),
        "8da5cb5b" => Some("owner()"),
        "f2fde38b" => Some("transferOwnership(address)"),
        "715018a6" => Some("renounceOwnership()"),
        "3ccfd60b" => Some("withdraw()"),
        "d0e30db0" => Some("deposit()"),
        "40c10f19" => Some("mint(address,uint256)"),
        "42966c68" => Some("burn(uint256)"),
        "5c975abb" => Some("paused()"),
        "8456cb59" => Some("pause()"),
        "3f4ba83a" => Some("unpause()"),
        "42842e0e" => Some("safeTransferFrom(address,address,uint256)"),
        "6352211e" => Some("ownerOf(uint256)"),
        "01ffc9a7" => Some("supportsInterface(bytes4)"),
        _ => None,
    }
}

pub fn inspect_evm_bytecode(
    raw_or_hex: &[u8],
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

    // Decode hex if input is ASCII hex string
    let bytecode: Vec<u8> = if let Ok(s) = std::str::from_utf8(raw_or_hex) {
        let trimmed = s.trim();
        let hex_clean: String = trimmed
            .strip_prefix("0x")
            .or_else(|| trimmed.strip_prefix("0X"))
            .unwrap_or(trimmed)
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        if !hex_clean.is_empty()
            && hex_clean.len().is_multiple_of(2)
            && hex_clean.bytes().all(|b| b.is_ascii_hexdigit())
        {
            hex::decode(&hex_clean).unwrap_or_else(|_| raw_or_hex.to_vec())
        } else {
            raw_or_hex.to_vec()
        }
    } else {
        raw_or_hex.to_vec()
    };

    let mut selectors: Vec<Value> = Vec::new();
    let mut seen_selectors: HashSet<String> = HashSet::new();
    let mut has_sstore = false;
    let mut has_sload = false;
    let mut has_callvalue = false;
    let mut has_delegatecall = false;
    let mut has_selfdestruct = false;
    let mut has_create2 = false;
    let mut opcode_count = 0usize;

    let mut pc = 0usize;
    while pc < bytecode.len() && opcode_count < MAX_DISASM_INSTRUCTIONS {
        let op = bytecode[pc];
        opcode_count += 1;
        match op {
            0x34 => has_callvalue = true,    // CALLVALUE
            0x54 => has_sload = true,        // SLOAD
            0x55 => has_sstore = true,       // SSTORE
            0xf4 => has_delegatecall = true, // DELEGATECALL
            0xf5 => has_create2 = true,      // CREATE2
            0xff => has_selfdestruct = true, // SELFDESTRUCT
            0x63 => {
                // PUSH4 <4-byte selector>
                if pc + 5 <= bytecode.len() {
                    let sel_bytes = &bytecode[pc + 1..pc + 5];
                    let sel_hex = hex::encode(sel_bytes);
                    // Look ahead up to 8 bytes for EQ (0x14) and PUSH1 (0x60) / PUSH2 (0x61) + JUMPI (0x57)
                    let lookahead_end = (pc + 14).min(bytecode.len());
                    let window = &bytecode[pc + 5..lookahead_end];
                    let mut eq_pos = None;
                    for (idx, &b) in window.iter().enumerate() {
                        if b == 0x14 {
                            eq_pos = Some(idx);
                            break;
                        }
                    }
                    if let Some(eq_idx) = eq_pos {
                        let after_eq = &window[eq_idx + 1..];
                        let mut target_offset: Option<u32> = None;
                        if after_eq.len() >= 3 && after_eq[0] == 0x60 && after_eq[2] == 0x57 {
                            target_offset = Some(after_eq[1] as u32);
                        } else if after_eq.len() >= 4 && after_eq[0] == 0x61 && after_eq[3] == 0x57
                        {
                            target_offset =
                                Some(u16::from_be_bytes([after_eq[1], after_eq[2]]) as u32);
                        } else if after_eq.contains(&0x57) {
                            target_offset = Some(0);
                        }

                        if let Some(dest) = target_offset {
                            if seen_selectors.insert(sel_hex.clone()) {
                                let sig = lookup_evm_selector(&sel_hex);
                                selectors.push(json!({
                                    "selector": format!("0x{}", sel_hex),
                                    "signature": sig.unwrap_or("unknown_selector(bytes)"),
                                    "jump_target": format!("0x{:04x}", dest),
                                    "pc_offset": format!("0x{:04x}", pc),
                                }));
                                evidence.push(ReaEvidence {
                                    source: "evm_dispatcher_disassembler".to_string(),
                                    location: format!("pc 0x{:04x} -> jumpdest 0x{:04x}", pc, dest),
                                    observation: format!(
                                        "PUSH4 0x{} ({}) EQ JUMPI dispatch entry",
                                        sel_hex,
                                        sig.unwrap_or("unresolved")
                                    ),
                                    confidence: 0.99,
                                    digest_sha256: None,
                                });
                            }
                        }
                    }
                }
                pc += 5;
                continue;
            }
            0x60..=0x7f => {
                let push_len = (op - 0x5f) as usize;
                pc += 1 + push_len;
                continue;
            }
            _ => {}
        }
        pc += 1;
    }

    if has_delegatecall {
        findings.push(json!({
            "category": "evm_delegatecall",
            "severity": "high",
            "title": "DELEGATECALL (0xf4) detected in EVM bytecode",
            "detail": "Contract can execute external code in its own storage context (proxy or potential storage collision risk).",
        }));
    }
    if has_selfdestruct {
        findings.push(json!({
            "category": "evm_selfdestruct",
            "severity": "high",
            "title": "SELFDESTRUCT (0xff) opcode present",
            "detail": "Contract contains SELFDESTRUCT opcode capable of destroying contract state/forwarding balance.",
        }));
    }
    findings.push(json!({
        "category": "evm_dispatch_summary",
        "severity": "info",
        "title": format!("Disassembled {} EVM instructions and {} dispatch selectors", opcode_count, selectors.len()),
        "detail": format!("SSTORE={}, SLOAD={}, CALLVALUE={}, DELEGATECALL={}, SELFDESTRUCT={}", has_sstore, has_sload, has_callvalue, has_delegatecall, has_selfdestruct),
    }));

    if selectors.iter().any(|s| {
        s.get("signature")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .starts_with("unknown")
    }) {
        limitations.push(ReaLimitation {
            code: "UNRESOLVED_4BYTE_SELECTORS".to_string(),
            description: "One or more 4-byte function selectors are custom and not in the offline canonical ABI table.".to_string(),
            remediation: Some("Supply the contract ABI JSON or query an offline 4byte signature database.".to_string()),
        });
    }

    let mut sol = String::from("// SPDX-License-Identifier: UNLICENSED\n// Reconstructed Solidity Dispatcher via OpenOshoosi REA\npragma solidity ^0.8.20;\n\ncontract ReconstructedEvmContract {\n");
    if has_sload || has_sstore {
        sol.push_str("    mapping(uint256 => uint256) private _storage;\n\n");
    }
    for sel in &selectors {
        let s_hex = sel
            .get("selector")
            .and_then(|v| v.as_str())
            .unwrap_or("0x00000000");
        let sig = sel
            .get("signature")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown()");
        let dest = sel
            .get("jump_target")
            .and_then(|v| v.as_str())
            .unwrap_or("0x00");
        let mutability = if has_sstore {
            if has_callvalue {
                "external payable"
            } else {
                "external"
            }
        } else {
            "external view"
        };
        sol.push_str(&format!(
            "    // Selector: {} -> JUMPDEST {}\n    function {} {} {{\n        // Dispatched from {}\n    }}\n\n",
            s_hex, dest, sig, mutability, dest
        ));
    }
    sol.push_str("}\n");

    let metadata = json!({
        "bytecode_length": bytecode.len(),
        "opcode_count": opcode_count,
        "selector_count": selectors.len(),
        "selectors": selectors,
        "state_mutability": {
            "sstore": has_sstore,
            "sload": has_sload,
            "callvalue_payable": has_callvalue,
            "delegatecall": has_delegatecall,
            "selfdestruct": has_selfdestruct,
            "create2": has_create2,
        }
    });

    (metadata, findings, evidence, limitations, sol)
}


// ============================================================================
// 7. JavaScript / Electron & ASAR Archive Inspector
// ============================================================================

fn walk_asar_files(node: &Value, prefix: &str, out: &mut Vec<(String, u64, u64)>) {
    walk_asar_files_bounded(node, prefix, out, 0);
}

fn walk_asar_files_bounded(
    node: &Value,
    prefix: &str,
    out: &mut Vec<(String, u64, u64)>,
    depth: usize,
) {
    if depth > 16 || out.len() >= 1024 {
        return;
    }
    if let Some(files) = node.get("files").and_then(|v| v.as_object()) {
        for (name, child) in files {
            if out.len() >= 1024 {
                break;
            }
            let path = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{}/{}", prefix, name)
            };
            if child.get("files").is_some() {
                walk_asar_files_bounded(child, &path, out, depth + 1);
            } else {
                let size = child.get("size").and_then(|v| v.as_u64()).unwrap_or(0);
                let offset = child
                    .get("offset")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<u64>().ok())
                    .or_else(|| child.get("offset").and_then(|v| v.as_u64()))
                    .unwrap_or(0);
                out.push((path, offset, size));
            }
        }
    }
}

pub fn inspect_javascript_electron(
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
    let limitations = Vec::new();

    let mut asar_entries: Vec<Value> = Vec::new();
    let mut package_json_val: Option<Value> = None;
    let mut js_sources: Vec<String> = Vec::new();

    // 1. Check if directory
    if let Some(p) = path {
        if p.is_dir() {
            let pkg_path = p.join("package.json");
            if pkg_path.is_file() {
                if let Ok(content) = std::fs::read_to_string(&pkg_path) {
                    package_json_val = serde_json::from_str(&content).ok();
                }
            }
            for entry in walkdir::WalkDir::new(p)
                .max_depth(3)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                if entry.path().is_file() {
                    if let Some(ext) = entry.path().extension().and_then(|e| e.to_str()) {
                        if matches!(ext, "js" | "mjs" | "cjs") && js_sources.len() < 16 {
                            if let Ok(s) = std::fs::read_to_string(entry.path()) {
                                js_sources.push(s);
                            }
                        }
                    }
                }
            }
        }
    }

    // 2. Check if ASAR archive (`04 00 00 00` pickle header)
    if bytes.len() >= 16 && bytes[0..4] == [0x04, 0x00, 0x00, 0x00] {
        let header_size = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
        let json_len = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]) as usize;
        let json_start = 16usize;
        if json_start + json_len <= bytes.len() {
            let json_slice = &bytes[json_start..json_start + json_len];
            let json_str = String::from_utf8_lossy(json_slice)
                .trim_matches('\0')
                .to_string();
            if let Ok(ast) = serde_json::from_str::<Value>(&json_str) {
                let mut file_tuples = Vec::new();
                walk_asar_files(&ast, "", &mut file_tuples);
                let data_base = 8 + header_size;

                evidence.push(ReaEvidence {
                    source: "chromium_asar_header".to_string(),
                    location: format!(
                        "offset 0x0..0x{:x} (data_base=0x{:x})",
                        json_start + json_len,
                        data_base
                    ),
                    observation: format!(
                        "Parsed ASAR archive header containing {} virtual files",
                        file_tuples.len()
                    ),
                    confidence: 1.0,
                    digest_sha256: Some(sha256_hex(json_slice)),
                });

                for (fpath, foff, fsize) in file_tuples {
                    asar_entries.push(json!({
                        "path": fpath,
                        "offset": foff,
                        "size": fsize,
                    }));
                    let abs_start = data_base.saturating_add(foff as usize);
                    let abs_end = abs_start.saturating_add(fsize as usize);
                    if abs_end <= bytes.len() && fsize <= 512 * 1024 {
                        if fpath == "package.json" || fpath.ends_with("/package.json") {
                            if package_json_val.is_none() {
                                package_json_val =
                                    serde_json::from_slice(&bytes[abs_start..abs_end]).ok();
                            }
                        } else if fpath.ends_with(".js") && js_sources.len() < 16 {
                            js_sources.push(
                                String::from_utf8_lossy(&bytes[abs_start..abs_end]).to_string(),
                            );
                        }
                    }
                }
            }
        }
    } else if !bytes.is_empty() {
        let text = String::from_utf8_lossy(bytes).to_string();
        if package_json_val.is_none() && text.trim_start().starts_with('{') {
            package_json_val = serde_json::from_str(&text).ok();
        }
        js_sources.push(text);
    }

    let combined_js = js_sources.join("\n");
    let mut ipc_channels: Vec<String> = Vec::new();
    let mut native_addons: Vec<String> = Vec::new();

    // Scan for ipcMain.handle('channel'), ipcMain.on('channel'), ipcRenderer.invoke('channel'), contextBridge.exposeInMainWorld('api')
    let ipc_markers = [
        "ipcMain.handle(",
        "ipcMain.on(",
        "ipcRenderer.invoke(",
        "ipcRenderer.send(",
        "contextBridge.exposeInMainWorld(",
    ];
    for marker in &ipc_markers {
        let mut search_slice = combined_js.as_str();
        while let Some(idx) = search_slice.find(marker) {
            let after = &search_slice[idx + marker.len()..];
            let trimmed = after.trim_start();
            if let Some(quote) = trimmed.chars().next() {
                if quote == '\'' || quote == '"' || quote == '`' {
                    let rest = &trimmed[1..];
                    if let Some(end_q) = rest.find(quote) {
                        let chan = format!("{}{}", marker.trim_end_matches('('), &rest[..end_q]);
                        if !ipc_channels.contains(&chan) {
                            ipc_channels.push(chan);
                        }
                    }
                }
            }
            search_slice = after;
        }
    }

    for entry in &asar_entries {
        if let Some(p) = entry.get("path").and_then(|v| v.as_str()) {
            if p.ends_with(".node") && !native_addons.contains(&p.to_string()) {
                native_addons.push(p.to_string());
            }
        }
    }

    let node_integration_true = combined_js.contains("nodeIntegration: true")
        || combined_js.contains("nodeIntegration:true");
    let context_isolation_false = combined_js.contains("contextIsolation: false")
        || combined_js.contains("contextIsolation:false");
    let sandbox_false =
        combined_js.contains("sandbox: false") || combined_js.contains("sandbox:false");
    let web_security_false =
        combined_js.contains("webSecurity: false") || combined_js.contains("webSecurity:false");

    if node_integration_true || context_isolation_false || web_security_false {
        findings.push(json!({
            "category": "electron_webpreferences_risk",
            "severity": "high",
            "title": "Insecure Electron BrowserWindow webPreferences detected",
            "detail": format!(
                "nodeIntegration={}, contextIsolation_disabled={}, sandbox_disabled={}, webSecurity_disabled={}",
                node_integration_true, context_isolation_false, sandbox_false, web_security_false
            ),
        }));
        evidence.push(ReaEvidence {
            source: "electron_security_scanner".to_string(),
            location: "BrowserWindow.webPreferences".to_string(),
            observation: format!(
                "Electron security flags: nodeIntegration={}, contextIsolation_disabled={}, webSecurity_disabled={}",
                node_integration_true, context_isolation_false, web_security_false
            ),
            confidence: 0.96,
            digest_sha256: None,
        });
    }

    if !ipc_channels.is_empty() {
        evidence.push(ReaEvidence {
            source: "electron_ipc_extractor".to_string(),
            location: "main/preload JS".to_string(),
            observation: format!(
                "Discovered {} Electron IPC channels: {}",
                ipc_channels.len(),
                ipc_channels.join(", ")
            ),
            confidence: 0.97,
            digest_sha256: None,
        });
    }

    let reconstructed = format!(
        "// Reconstructed Electron / JS Security & IPC Surface via OpenOshoosi REA\n// ASAR Files: {} | IPC Channels: {} | Native .node Addons: {}\nconst securityPosture = {{\n  nodeIntegrationEnabled: {},\n  contextIsolationDisabled: {},\n  sandboxDisabled: {},\n  webSecurityDisabled: {},\n  ipcChannels: {:?}\n}};\n",
        asar_entries.len(),
        ipc_channels.len(),
        native_addons.len(),
        node_integration_true,
        context_isolation_false,
        sandbox_false,
        web_security_false,
        ipc_channels
    );

    let metadata = json!({
        "asar_file_count": asar_entries.len(),
        "asar_files": asar_entries,
        "package_json": package_json_val,
        "electron_security_flags": {
            "node_integration_enabled": node_integration_true,
            "context_isolation_disabled": context_isolation_false,
            "sandbox_disabled": sandbox_false,
            "web_security_disabled": web_security_false,
        },
        "ipc_channels": ipc_channels,
        "native_addons": native_addons,
    });

    (metadata, findings, evidence, limitations, reconstructed)
}

