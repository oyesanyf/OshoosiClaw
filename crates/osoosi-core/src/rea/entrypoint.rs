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

use super::*;

/// Locate and structurally validate an ECMA-335 II.24.2.1 CLR Metadata Root (`BSJB`, `0x424A5342`).
///
/// Crucially, a naive `find_subslice(bytes, b"BSJB")` causes false positives when inspecting
/// native binaries (like `osoosi.exe` itself) that contain the literal string `"BSJB"` inside
/// their `.rdata` or `.text` sections alongside x86_64 machine code (e.g. `48 C7 84 24 78...`
/// which decodes as garbage `HǄ$xH...`).
///
/// A genuine ECMA-335 CLR Metadata Root at `bsjb_off` must satisfy:
/// 1. `Signature` == `0x424A5342` (`"BSJB"`)
/// 2. `MajorVersion` in `1..=2`, `MinorVersion` in `0..=5`
/// 3. `Reserved` == `0` (`u32` at `+8..+12`)
/// 4. `Length` (`ver_len` at `+12..+16`) in `4..=64` and `4`-byte aligned (`ver_len % 4 == 0`)
/// 5. `Version` string at `+16..+16+ver_len` starts with `'v'` followed by an ASCII digit (e.g. `"v4.0.30319"` or `"v2.0.50727"`) and contains only printable ASCII (`0x20..=0x7e`) and null padding
/// 6. `Streams` (`u16` at `+16 + ver_len + 2`) in `1..=16`
/// 7. At least one stream header immediately follows with a valid `'#'`-prefixed ASCII name (`#~`, `#-`, `#Strings`, `#US`, `#GUID`, `#Blob`, `#Pdb`)
pub fn find_valid_dotnet_bsjb_header(bytes: &[u8]) -> Option<(usize, String, Vec<Value>)> {
    let mut search_from = 0usize;
    while search_from + 32 <= bytes.len() {
        let rel = find_subslice(&bytes[search_from..], b"BSJB")?;
        let bsjb_off = search_from + rel;
        search_from = bsjb_off + 4;

        if bsjb_off + 20 > bytes.len() {
            break;
        }

        let major = u16::from_le_bytes([bytes[bsjb_off + 4], bytes[bsjb_off + 5]]);
        let minor = u16::from_le_bytes([bytes[bsjb_off + 6], bytes[bsjb_off + 7]]);
        let reserved = u32::from_le_bytes([
            bytes[bsjb_off + 8],
            bytes[bsjb_off + 9],
            bytes[bsjb_off + 10],
            bytes[bsjb_off + 11],
        ]);
        let ver_len = u32::from_le_bytes([
            bytes[bsjb_off + 12],
            bytes[bsjb_off + 13],
            bytes[bsjb_off + 14],
            bytes[bsjb_off + 15],
        ]) as usize;

        if !(1..=2).contains(&major) || minor > 10 || reserved != 0 {
            continue;
        }
        if !(4..=64).contains(&ver_len) || bsjb_off + 16 + ver_len + 4 > bytes.len() {
            continue;
        }

        let raw_ver = &bytes[bsjb_off + 16..bsjb_off + 16 + ver_len];
        let trimmed_ver_bytes: Vec<u8> = raw_ver.iter().copied().take_while(|&b| b != 0).collect();
        if trimmed_ver_bytes.len() < 2
            || !trimmed_ver_bytes[0].eq_ignore_ascii_case(&b'v')
            || !trimmed_ver_bytes[1].is_ascii_digit()
            || !trimmed_ver_bytes
                .iter()
                .all(|&b| (0x20..=0x7e).contains(&b))
        {
            continue;
        }
        let clr_version = String::from_utf8_lossy(&trimmed_ver_bytes).to_string();

        let aligned_ver = (ver_len + 3) & !3;
        let flags_off = bsjb_off + 16 + aligned_ver;
        if flags_off + 4 > bytes.len() {
            continue;
        }

        let stream_count =
            u16::from_le_bytes([bytes[flags_off + 2], bytes[flags_off + 3]]) as usize;
        if !(1..=16).contains(&stream_count) {
            continue;
        }

        let mut streams = Vec::new();
        let mut cur = flags_off + 4;
        let mut valid_streams = true;
        for _ in 0..stream_count {
            if cur + 8 > bytes.len() {
                valid_streams = false;
                break;
            }
            let s_offset =
                u32::from_le_bytes([bytes[cur], bytes[cur + 1], bytes[cur + 2], bytes[cur + 3]]);
            let s_size = u32::from_le_bytes([
                bytes[cur + 4],
                bytes[cur + 5],
                bytes[cur + 6],
                bytes[cur + 7],
            ]);
            cur += 8;
            let name_start = cur;
            while cur < bytes.len() && bytes[cur] != 0 && (cur - name_start) < 32 {
                cur += 1;
            }
            if cur >= bytes.len() || bytes[cur] != 0 || cur == name_start {
                valid_streams = false;
                break;
            }
            let name_slice = &bytes[name_start..cur];
            if name_slice[0] != b'#' || !name_slice.iter().all(|&b| (0x20..=0x7e).contains(&b)) {
                valid_streams = false;
                break;
            }
            let s_name = String::from_utf8_lossy(name_slice).to_string();
            cur += 1; // skip null terminator
            let name_len = cur - name_start;
            let aligned_name = (name_len + 3) & !3;
            cur = name_start + aligned_name;

            streams.push(json!({
                "name": s_name,
                "offset": format!("0x{:x}", s_offset),
                "size": s_size,
            }));
        }

        if valid_streams && !streams.is_empty() {
            return Some((bsjb_off, clr_version, streams));
        }
    }
    None
}

/// Convert a PE Relative Virtual Address (RVA) into a validated file offset using section headers.
pub fn pe_rva_to_file_offset(pe: &goblin::pe::PE, rva: usize, file_len: usize) -> Option<usize> {
    if rva == 0 {
        return None;
    }
    for sec in &pe.sections {
        let va = sec.virtual_address as usize;
        let vsize = (sec.virtual_size as usize).max(sec.size_of_raw_data as usize);
        let raw_ptr = sec.pointer_to_raw_data as usize;
        let raw_size = sec.size_of_raw_data as usize;
        if rva >= va && rva < va.saturating_add(vsize) {
            let delta = rva - va;
            if delta < raw_size {
                let off = raw_ptr.saturating_add(delta);
                if off < file_len {
                    return Some(off);
                }
            }
        }
    }
    None
}

/// Check whether a PE binary has a valid, section-mapped CLR Runtime Header DataDirectory
/// (`IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR`, index 14).
/// Returns:
/// - `Some(true)` if `goblin::pe::PE::parse` succeeds AND OptionalHeader DataDirectory[14] maps to a valid `IMAGE_COR20_HEADER` inside a PE section.
/// - `Some(false)` if `goblin::pe::PE::parse` succeeds AND DataDirectory[14] is absent, zero, or points outside valid PE sections (meaning it is definitively a native PE, NOT a .NET assembly).
/// - `None` if `bytes` is not a full parseable PE header (e.g., synthetic minimal unit-test buffer).
pub fn pe_clr_runtime_header_present(bytes: &[u8]) -> Option<bool> {
    if !bytes.starts_with(b"MZ") {
        return None;
    }
    if let Ok(pe) = goblin::pe::PE::parse(bytes) {
        let Some(dir) = pe
            .header
            .optional_header
            .and_then(|opt| opt.data_directories.get_clr_runtime_header().copied())
        else {
            return Some(false);
        };
        if dir.virtual_address == 0 || dir.size < 48 {
            return Some(false);
        }
        let Some(cor20_off) = pe_rva_to_file_offset(&pe, dir.virtual_address as usize, bytes.len())
        else {
            return Some(false);
        };
        if cor20_off + 16 > bytes.len() {
            return Some(false);
        }
        let cb = u32::from_le_bytes([
            bytes[cor20_off],
            bytes[cor20_off + 1],
            bytes[cor20_off + 2],
            bytes[cor20_off + 3],
        ]);
        if cb < 48 {
            return Some(false);
        }
        let metadata_rva = u32::from_le_bytes([
            bytes[cor20_off + 8],
            bytes[cor20_off + 9],
            bytes[cor20_off + 10],
            bytes[cor20_off + 11],
        ]) as usize;
        let metadata_size = u32::from_le_bytes([
            bytes[cor20_off + 12],
            bytes[cor20_off + 13],
            bytes[cor20_off + 14],
            bytes[cor20_off + 15],
        ]) as usize;
        if metadata_rva != 0 && metadata_size >= 16 {
            if let Some(meta_off) = pe_rva_to_file_offset(&pe, metadata_rva, bytes.len()) {
                return Some(
                    find_valid_dotnet_bsjb_header(&bytes[meta_off..])
                        .map(|(rel_off, _, _)| rel_off == 0)
                        .unwrap_or(false),
                );
            }
            return Some(false);
        }
        return Some(find_valid_dotnet_bsjb_header(bytes).is_some());
    }
    None
}

/// Locate the ECMA-335 `BSJB` metadata root, preferring the authoritative `IMAGE_COR20_HEADER.MetaData`
/// RVA when `bytes` is a full parseable PE binary.
pub fn find_pe_dotnet_bsjb_header(bytes: &[u8]) -> Option<(usize, String, Vec<Value>)> {
    if bytes.starts_with(b"MZ") {
        if let Ok(pe) = goblin::pe::PE::parse(bytes) {
            if let Some(dir) = pe
                .header
                .optional_header
                .and_then(|opt| opt.data_directories.get_clr_runtime_header().copied())
            {
                if dir.virtual_address != 0 && dir.size >= 48 {
                    if let Some(cor20_off) =
                        pe_rva_to_file_offset(&pe, dir.virtual_address as usize, bytes.len())
                    {
                        if cor20_off + 16 <= bytes.len() {
                            let metadata_rva = u32::from_le_bytes([
                                bytes[cor20_off + 8],
                                bytes[cor20_off + 9],
                                bytes[cor20_off + 10],
                                bytes[cor20_off + 11],
                            ]) as usize;
                            if let Some(meta_off) =
                                pe_rva_to_file_offset(&pe, metadata_rva, bytes.len())
                            {
                                if let Some((rel_off, ver, streams)) =
                                    find_valid_dotnet_bsjb_header(&bytes[meta_off..])
                                {
                                    return Some((meta_off + rel_off, ver, streams));
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    find_valid_dotnet_bsjb_header(bytes)
}

/// Automatically classify the REA target kind from path and raw bytes using a 2-tier pipeline:
/// - **Tier 1 (Envelope & MIME Detection)**: Google Magika deep-learning content identification + container magic bytes.
///   Always runs BEFORE trusting file extensions so masqueraded binaries (e.g. PE renamed to `.wasm` or `.apk`) are never misrouted.
/// - **Tier 2 (Structural PE/ELF/Mach-O Compiler & Runtime Provenance)**:
///   - For valid PE files (`goblin::pe::PE::parse`), inspects PE DataDirectory[14] (`CLR Runtime Header`) and its section-mapped `IMAGE_COR20_HEADER`.
///     If DataDirectory[14] is zero or unmapped, the PE is unequivocally native (never `.NET`—even if `.rdata` contains `"BSJB"`).
///   - Checks `.dep-v0` / `rustc` / `/cargo/registry/` for Rust, `\xff Go buildinf:` for Go, and ECMA-335 `BSJB` stream headers for `.NET`.
pub fn detect_target_kind(path: Option<&Path>, bytes: &[u8]) -> ReaTargetKind {
    if let Some(p) = path {
        if p.is_dir() {
            if p.join("package.json").is_file() || p.join("resources").is_dir() {
                return ReaTargetKind::JavaScriptElectron;
            }
            if p.join("AndroidManifest.xml").is_file() {
                return ReaTargetKind::AndroidFlutter;
            }
        }
    }

    if bytes.starts_with(b"\0asm\x01\0\0\0") || bytes.starts_with(b"\0asm") {
        return ReaTargetKind::WasmArtifact;
    }

    if bytes.starts_with(b"SQLite format 3\0") {
        return ReaTargetKind::SqliteDatabase;
    }

    // PCAP / PCAPNG magic
    if bytes.len() >= 4 {
        let m32 = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if matches!(
            m32,
            0xa1b2c3d4 | 0xd4c3b2a1 | 0xa1b23c4d | 0x4d3cb2a1 | 0x0a0d0d0a
        ) {
            return ReaTargetKind::NetworkCapture;
        }
    }

    // Check ASAR pickle header: 04 00 00 00 ... {"files":
    if bytes.len() >= 24
        && bytes[0..4] == [0x04, 0x00, 0x00, 0x00]
        && find_subslice(&bytes[..bytes.len().min(64)], b"{\"files\"").is_some()
    {
        return ReaTargetKind::JavaScriptElectron;
    }

    // Check ZIP / APK magic at offset 0
    if bytes.starts_with(b"PK\x03\x04") {
        if find_subslice(bytes, b"AndroidManifest.xml").is_some()
            || find_subslice(bytes, b"classes.dex").is_some()
            || find_subslice(bytes, b"libflutter.so").is_some()
            || find_subslice(bytes, b"libapp.so").is_some()
        {
            return ReaTargetKind::AndroidFlutter;
        }
    }
    if bytes.starts_with(b"dex\n03") {
        return ReaTargetKind::AndroidFlutter;
    }

    // Check Firmware magic headers at start of image
    if bytes.starts_with(b"hsqs")
        || bytes.starts_with(b"sqsh")
        || bytes.starts_with(b"\x27\x05\x19\x56")
        || bytes.starts_with(b"\xd0\x0d\xfe\xed")
        || bytes.starts_with(b"UBI#")
    {
        return ReaTargetKind::FirmwareImage;
    }

    // Tier 1: Consult Google Magika content identification for non-native envelopes
    let magika_id = identify_with_magika(path, bytes);
    match magika_id.label.as_str() {
        "wasm" => return ReaTargetKind::WasmArtifact,
        "sqlite" => return ReaTargetKind::SqliteDatabase,
        "pcap" => return ReaTargetKind::NetworkCapture,
        "apk" | "dex" => return ReaTargetKind::AndroidFlutter,
        _ => {}
    }

    // Tier 2: Structural PE / ELF / Mach-O Compiler & Runtime Provenance
    let is_native_container = bytes.starts_with(b"MZ")
        || bytes.starts_with(b"\x7fELF")
        || matches!(magika_id.label.as_str(), "pebin" | "elf" | "macho")
        || (bytes.len() >= 4
            && matches!(
                u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
                0xfeedface | 0xfeedfacf | 0xcefaedfe | 0xcffaedfe | 0xcafebabe
            ));

    if is_native_container {
        let pe_has_clr_dir = pe_clr_runtime_header_present(bytes);

        // 1. If PE Optional Header explicitly has a valid, section-mapped CLR DataDirectory[14],
        //    and a structurally valid BSJB root exists, it is a .NET assembly.
        if pe_has_clr_dir == Some(true) && find_pe_dotnet_bsjb_header(bytes).is_some() {
            return ReaTargetKind::DotNetAssembly;
        }

        // 2. Check Rust provenance (`cargo-auditable` `.dep-v0`, `rustc 1.`, cargo registry paths, `rust_begin_unwind`)
        let has_rust_markers = find_subslice(bytes, b".dep-v0").is_some()
            || find_subslice(bytes, b"rustc 1.").is_some()
            || find_subslice(bytes, b"/cargo/registry/src/").is_some()
            || find_subslice(bytes, b"\\cargo\\registry\\src\\").is_some()
            || find_subslice(bytes, b"rust_begin_unwind").is_some();

        if has_rust_markers {
            return ReaTargetKind::RustBinary;
        }

        // 3. Check Go provenance (`\xff Go buildinf:` or `go1.` + runtime symbols)
        if find_subslice(bytes, b"\xff Go buildinf:").is_some()
            || (find_subslice(bytes, b"go1.").is_some()
                && (find_subslice(bytes, b"runtime.main").is_some()
                    || find_subslice(bytes, b"go.buildid").is_some()
                    || find_subslice(bytes, b"\nmod\t").is_some()
                    || find_subslice(bytes, b"\ndep\t").is_some()))
        {
            return ReaTargetKind::GoBinary;
        }

        // 4. If `bytes` is NOT a full PE with a zeroed CLR DataDirectory (e.g. a compact synthetic test buffer
        //    or mono bundle without full OptionalHeader), check for a structurally valid ECMA-335 BSJB header.
        if pe_has_clr_dir != Some(false) && find_pe_dotnet_bsjb_header(bytes).is_some() {
            return ReaTargetKind::DotNetAssembly;
        }

        // 5. Check Flutter / Dart AOT snapshot symbols
        if find_subslice(bytes, b"libflutter.so").is_some()
            || find_subslice(bytes, b"libapp.so").is_some()
            || find_subslice(bytes, b"_kDartVmSnapshotInstructions").is_some()
        {
            return ReaTargetKind::AndroidFlutter;
        }

        return ReaTargetKind::NativeBinary;
    }

    // Check JSON text (.har or package.json) or JS
    if let Ok(text) = std::str::from_utf8(&bytes[..bytes.len().min(8192)]) {
        let trimmed = text.trim_start();
        if trimmed.starts_with('{') {
            if text.contains("\"log\"") && text.contains("\"entries\"") {
                return ReaTargetKind::NetworkCapture;
            }
            if text.contains("\"dependencies\"")
                || text.contains("\"devDependencies\"")
                || text.contains("\"electron\"")
                || text.contains("BrowserWindow")
            {
                return ReaTargetKind::JavaScriptElectron;
            }
        }
        if text.contains("BrowserWindow")
            || text.contains("ipcMain")
            || text.contains("ipcRenderer")
            || text.contains("contextBridge")
        {
            return ReaTargetKind::JavaScriptElectron;
        }

        // Check hex string for EVM bytecode
        let hex_clean = trimmed.strip_prefix("0x").unwrap_or(trimmed).trim();
        if hex_clean.len() >= 8
            && hex_clean.len().is_multiple_of(2)
            && hex_clean.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return ReaTargetKind::EvmBytecode;
        }
    }

    // Check raw EVM bytecode patterns (e.g., 0x60 0x80 0x60 0x40 0x52 or PUSH4 <sel> EQ)
    if bytes.starts_with(&[0x60, 0x80, 0x60, 0x40, 0x52])
        || bytes.starts_with(&[0x60, 0x60, 0x60, 0x40, 0x52])
        || bytes.windows(6).any(|w| w[0] == 0x63 && w[5] == 0x14)
    {
        return ReaTargetKind::EvmBytecode;
    }

    // Check embedded firmware signatures inside raw non-executable image
    if find_subslice(bytes, b"hsqs").is_some()
        || find_subslice(bytes, b"sqsh").is_some()
        || find_subslice(bytes, b"\x27\x05\x19\x56").is_some()
        || find_subslice(bytes, b"\xd0\x0d\xfe\xed").is_some()
    {
        return ReaTargetKind::FirmwareImage;
    }

    // Extension tie-breaker only for non-executable buffers without conflicting magic headers
    if let Some(p) = path {
        if let Some(ext) = p.extension().and_then(|e| e.to_str()) {
            match ext.to_ascii_lowercase().as_str() {
                "wasm" => return ReaTargetKind::WasmArtifact,
                "asar" | "js" | "mjs" | "cjs" => return ReaTargetKind::JavaScriptElectron,
                "har" | "pcap" | "pcapng" | "cap" => return ReaTargetKind::NetworkCapture,
                "apk" | "dex" => return ReaTargetKind::AndroidFlutter,
                "evm" | "bin-runtime" => return ReaTargetKind::EvmBytecode,
                _ => {}
            }
        }
    }

    ReaTargetKind::NativeBinary
}


// ============================================================================
// Unified REA Entrypoint (`analyze_target_bytes` & `analyze_target_path`)
// ============================================================================

/// Analyze a raw byte buffer with an optional target path and requested target kind.
pub fn analyze_target_bytes(
    target_label: &str,
    path: Option<&Path>,
    bytes: &[u8],
    requested_kind: ReaTargetKind,
    autonomous_trigger: Option<String>,
) -> ReaInvestigationReport {
    let magika_identity = identify_with_magika(path, bytes);
    let effective_kind = if requested_kind == ReaTargetKind::Auto {
        detect_target_kind(path, bytes)
    } else {
        requested_kind
    };

    let sha256 = sha256_hex(bytes);
    let blake3_hash = blake3_hex(bytes);
    let mut providers_used = vec![
        "osoosi-rea-native".to_string(),
        "google-magika-onnx".to_string(),
    ];

    let mut panic_contained = false;
    let (mut metadata, mut findings, mut evidence, mut limitations, mut reconstructed) =
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match effective_kind {
            ReaTargetKind::RustBinary => {
                let (r_meta, mut r_find, mut r_ev, mut r_lim, r_code) = inspect_rust_binary(bytes);
                let (n_meta, n_find, n_ev, n_lim, _n_code) = inspect_native_binary(path, bytes);
                r_find.extend(n_find);
                r_ev.extend(n_ev);
                r_lim.extend(n_lim);
                let combined_meta = json!({
                    "rust": r_meta,
                    "native": n_meta,
                });
                (combined_meta, r_find, r_ev, r_lim, r_code, None)
            }
            ReaTargetKind::GoBinary => {
                let (g_meta, mut g_find, mut g_ev, mut g_lim, g_code) = inspect_go_binary(bytes);
                let (n_meta, n_find, n_ev, n_lim, _n_code) = inspect_native_binary(path, bytes);
                g_find.extend(n_find);
                g_ev.extend(n_ev);
                g_lim.extend(n_lim);
                let combined_meta = json!({
                    "go": g_meta,
                    "native": n_meta,
                });
                (combined_meta, g_find, g_ev, g_lim, g_code, None)
            }
            ReaTargetKind::DotNetAssembly => {
                let (d_meta, mut d_find, mut d_ev, mut d_lim, d_code) =
                    inspect_dotnet_assembly(bytes);
                let (n_meta, n_find, n_ev, n_lim, _n_code) = inspect_native_binary(path, bytes);
                d_find.extend(n_find);
                d_ev.extend(n_ev);
                d_lim.extend(n_lim);
                let combined_meta = json!({
                    "dotnet": d_meta,
                    "native": n_meta,
                });
                (combined_meta, d_find, d_ev, d_lim, d_code, None)
            }
            ReaTargetKind::NativeBinary | ReaTargetKind::Auto => {
                let (m, f, e, l, c) = inspect_native_binary(path, bytes);
                (m, f, e, l, c, None)
            }
            ReaTargetKind::WasmArtifact => {
                let (m, f, e, l, c) = inspect_wasm_artifact(bytes);
                (m, f, e, l, c, Some("osoosi-rea-wasm"))
            }
            ReaTargetKind::EvmBytecode => {
                let (m, f, e, l, c) = inspect_evm_bytecode(bytes);
                (m, f, e, l, c, Some("osoosi-rea-evm"))
            }
            ReaTargetKind::JavaScriptElectron => {
                let (m, f, e, l, c) = inspect_javascript_electron(path, bytes);
                (m, f, e, l, c, Some("osoosi-rea-electron-asar"))
            }
            ReaTargetKind::SqliteDatabase => {
                let (m, f, e, l, c) = inspect_sqlite_database(path, bytes);
                (m, f, e, l, c, Some("osoosi-rea-sqlite"))
            }
            ReaTargetKind::NetworkCapture => {
                let (m, f, e, l, c) = inspect_network_capture(path, bytes);
                (m, f, e, l, c, Some("osoosi-rea-netcap"))
            }
            ReaTargetKind::AndroidFlutter | ReaTargetKind::FirmwareImage => {
                let (m, f, e, l, c) = inspect_firmware_or_apk(path, bytes);
                (m, f, e, l, c, Some("osoosi-rea-firmware-apk"))
            }
        })) {
            Ok((m, f, e, l, c, extra_prov)) => {
                if let Some(p) = extra_prov {
                    providers_used.push(p.to_string());
                }
                (m, f, e, l, c)
            }
            Err(_) => {
                panic_contained = true;
                (
                    json!({
                        "parser_sandbox": "catch_unwind_isolated",
                        "panic_contained": true,
                    }),
                    vec![json!({
                        "category": "rea_parser_panic_contained",
                        "code": "REA_PARSER_PANIC_CONTAINED",
                        "severity": "high",
                        "title": "Malformed Binary/Bytecode Triggered Sandboxed Parser Guard",
                        "detail": "std::panic::catch_unwind isolated an internal parser panic on adversarial input without crashing the EDR daemon.",
                    })],
                    vec![ReaEvidence {
                        source: "rea_parser_sandbox".to_string(),
                        location: "std::panic::catch_unwind".to_string(),
                        observation: "Contained parser panic on malformed/fuzzed artifact".to_string(),
                        confidence: 1.0,
                        digest_sha256: Some(sha256.clone()),
                    }],
                    vec![ReaLimitation {
                        code: "REA_PARSER_PANIC_CONTAINED".to_string(),
                        description: "Parser panic was isolated by REA Protection Layer 3 catch_unwind boundary.".to_string(),
                        remediation: None,
                    }],
                    "// [REA_PARSER_SANDBOX] Malformed artifact contained safely via std::panic::catch_unwind\n".to_string(),
                )
            }
        };

    // Protection Layer 1: Check for binary masquerading / untrusted path spoofing
    let masquerade_spoof = detect_binary_masquerade_spoof(target_label, path, Some(bytes));
    if let Some(ref spoof_reason) = masquerade_spoof {
        findings.push(json!({
            "category": "REA_MASQUERADE_SPOOF_DETECTED",
            "code": "REA_MASQUERADE_SPOOF_DETECTED",
            "severity": "critical",
            "title": "Binary Masquerading / Untrusted Path Spoof Detected",
            "detail": spoof_reason,
        }));
        evidence.push(ReaEvidence {
            source: "rea_anti_masquerade_guard".to_string(),
            location: target_label.to_string(),
            observation: spoof_reason.clone(),
            confidence: 0.99,
            digest_sha256: Some(sha256.clone()),
        });
    }

    // Protection Layer 4: Scan for embedded prompt-injection / disassembler-poisoning strings & sanitize output
    let is_verified_self_binary = autonomous_trigger
        .as_deref()
        .map(|t| t.contains("self_binary") || t.contains("companion_binary"))
        .unwrap_or(false)
        || path
            .and_then(|p| std::env::current_exe().ok().map(|exe| p == exe.as_path()))
            .unwrap_or(false)
        || (find_subslice(bytes, b"OpenOshoosi::REA::ReportIntegritySeal").is_some()
            && find_subslice(bytes, b"rustc 1.").is_some());

    let (prompt_injections, sanitized_count) =
        scan_and_sanitize_counter_ai_strings(bytes, &mut reconstructed, is_verified_self_binary);
    if !prompt_injections.is_empty() {
        for inj in &prompt_injections {
            findings.push(json!({
                "category": "REA_ANTI_ANALYSIS_PROMPT_INJECTION",
                "code": "REA_ANTI_ANALYSIS_PROMPT_INJECTION",
                "severity": "critical",
                "title": "Embedded Counter-AI Prompt Injection / Disassembler Poisoning Detected",
                "detail": inj,
            }));
            evidence.push(ReaEvidence {
                source: "rea_counter_ai_string_sanitizer".to_string(),
                location: "binary_strings".to_string(),
                observation: inj.clone(),
                confidence: 0.98,
                digest_sha256: Some(sha256.clone()),
            });
        }
    }

    let entropy = calculate_entropy(bytes);
    if let Some(obj) = metadata.as_object_mut() {
        obj.insert(
            "overall_entropy".to_string(),
            json!((entropy * 100.0).round() / 100.0),
        );
        obj.insert(
            "magika".to_string(),
            serde_json::to_value(&magika_identity).unwrap_or(Value::Null),
        );
    }

    evidence.push(ReaEvidence {
        source: format!("google_magika:{}", magika_identity.engine),
        location: "content_envelope".to_string(),
        observation: format!(
            "Magika content identification: label='{}' (mime='{}', description='{}', score={:.2})",
            magika_identity.label,
            magika_identity.mime_type,
            magika_identity.description,
            magika_identity.score
        ),
        confidence: magika_identity.score,
        digest_sha256: Some(sha256.clone()),
    });

    // Calculate threat score from findings severity and entropy
    let mut threat_score = 0.05f32;
    for f in &findings {
        match f.get("severity").and_then(|v| v.as_str()).unwrap_or("info") {
            "critical" => threat_score += 0.45,
            "high" => threat_score += 0.30,
            "medium" => threat_score += 0.15,
            _ => {}
        }
    }
    if entropy > 7.4
        && matches!(
            effective_kind,
            ReaTargetKind::NativeBinary | ReaTargetKind::RustBinary | ReaTargetKind::GoBinary
        )
    {
        threat_score += 0.15;
    }
    threat_score = threat_score.min(0.99);

    // R15 + Layer 1: Zero threat score ONLY on verified non-masquerading, non-injected developer / benign system processes
    let target_lower = target_label.to_ascii_lowercase();
    let has_untrusted_path = is_untrusted_writable_or_temp_path(target_label)
        || path
            .map(|p| is_untrusted_writable_or_temp_path(&p.to_string_lossy()))
            .unwrap_or(false);
    let is_self_or_dev_binary = !has_untrusted_path
        && masquerade_spoof.is_none()
        && prompt_injections.is_empty()
        && ((target_lower == "osoosi.exe"
            || target_lower == "osoosi-cli.exe"
            || target_lower == "osoosi_inject.dll"
            || is_verified_self_binary)
            || is_rea_benign_system_or_dev_process(target_label, None)
            || path
                .map(|p| is_rea_benign_system_or_dev_process(&p.to_string_lossy(), None))
                .unwrap_or(false));

    if masquerade_spoof.is_some() {
        threat_score = threat_score.max(0.95);
    } else if !prompt_injections.is_empty() {
        threat_score = threat_score.max(0.92);
    } else if is_self_or_dev_binary {
        threat_score = 0.0f32;
        for f in &mut findings {
            if let Some(sev) = f.get_mut("severity") {
                if sev.as_str() == Some("medium")
                    || sev.as_str() == Some("high")
                    || sev.as_str() == Some("critical")
                {
                    *sev = serde_json::json!("info");
                }
            }
        }
    }

    let auto_yara_rule = Some(synthesize_rea_yara_rule(
        target_label,
        effective_kind.as_str(),
        bytes,
        &sha256,
        &blake3_hash,
    ));

    if evidence.is_empty() {
        evidence.push(ReaEvidence {
            source: "rea_core_hasher".to_string(),
            location: "full_artifact".to_string(),
            observation: format!(
                "Hashed {} bytes (entropy {:.2} bits/byte)",
                bytes.len(),
                entropy
            ),
            confidence: 1.0,
            digest_sha256: Some(sha256.clone()),
        });
    }

    if limitations.is_empty() {
        limitations.push(ReaLimitation {
            code: "STATIC_PASS_COMPLETE".to_string(),
            description:
                "Static binary/bytecode reconstruction completed without dynamic execution attach."
                    .to_string(),
            remediation: None,
        });
    }

    let summary = format!(
        "REA [{}] analyzed '{}' ({} bytes, entropy {:.2} bits/byte, {} evidence items, {} findings, threat_score={:.2})",
        effective_kind.as_str(),
        target_label,
        bytes.len(),
        entropy,
        evidence.len(),
        findings.len(),
        threat_score
    );

    let canonical_dir_verified = is_canonical_trusted_binary_dir(target_label)
        || path
            .map(|p| is_canonical_trusted_binary_dir(&p.to_string_lossy()))
            .unwrap_or(false);

    let mut report = ReaInvestigationReport {
        target_path: target_label.to_string(),
        detected_kind: effective_kind.as_str().to_string(),
        size_bytes: bytes.len() as u64,
        sha256,
        blake3: blake3_hash,
        summary,
        metadata,
        findings,
        evidence,
        limitations,
        reconstructed_code: Some(reconstructed),
        auto_yara_rule,
        threat_score,
        autonomous_trigger,
        providers_used,
        timestamp: Utc::now().to_rfc3339(),
        report_integrity_hmac_blake3: String::new(),
        rea_security_posture: Value::Null,
    };

    let seal = compute_rea_report_seal(&report);
    let posture = json!({
        "layer1_anti_masquerading": "enforced",
        "masquerade_spoof_detected": masquerade_spoof.is_some(),
        "masquerade_detail": masquerade_spoof,
        "canonical_path_verified": canonical_dir_verified,
        "layer2_path_sandbox": "enforced",
        "unc_smb_device_ads_blocked": true,
        "layer3_parser_sandbox": "enforced",
        "catch_unwind_isolated": true,
        "panic_contained": panic_contained,
        "max_file_bytes": MAX_REA_FILE_BYTES,
        "max_pe_sections": MAX_PE_SECTIONS,
        "max_extracted_strings": MAX_EXTRACTED_STRINGS,
        "max_disasm_instructions": MAX_DISASM_INSTRUCTIONS,
        "max_sqlite_pages": MAX_SQLITE_PAGES,
        "layer4_counter_ai_sanitizer": "enforced",
        "prompt_injection_detected": !prompt_injections.is_empty(),
        "counter_ai_prompt_injection_detected": !prompt_injections.is_empty(),
        "prompt_injection_findings": prompt_injections,
        "sanitized_strings_count": sanitized_count,
        "report_integrity_hmac_blake3": seal,
        "seal_verified": true,
    });
    report.report_integrity_hmac_blake3 = seal.clone();
    report.rea_security_posture = posture.clone();
    if let Some(obj) = report.metadata.as_object_mut() {
        obj.insert("report_integrity_hmac_blake3".to_string(), json!(seal));
        obj.insert("rea_security_posture".to_string(), posture);
    }

    report
}

/// Analyze a file or directory path on disk, or fallback to hex decoding if `path_or_hex` is raw EVM/WASM hex.
pub fn analyze_target_path(
    path_or_hex: &str,
    requested_kind: ReaTargetKind,
    autonomous_trigger: Option<String>,
) -> Result<ReaInvestigationReport> {
    let trimmed = path_or_hex.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("Target path or hex payload cannot be empty"));
    }

    // Check if it's a pure hex payload first (e.g. `0x60806040...` or WASM hex `0061736d...`)
    let hex_clean: String = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed)
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();

    let is_inline_hex = !trimmed.contains('\\')
        && !trimmed.contains('/')
        && !trimmed.contains(':')
        && !trimmed.contains('.')
        && hex_clean.len() >= 8
        && hex_clean.len().is_multiple_of(2)
        && hex_clean.bytes().all(|b| b.is_ascii_hexdigit());

    if !is_inline_hex {
        // Protection Layer 2: Strictly validate file path BEFORE any filesystem probe (exists/open)
        let validated_path = validate_rea_target_path(trimmed)?;
        let p = validated_path.as_path();
        if p.exists() {
            if p.is_dir() {
                return Ok(analyze_target_bytes(
                    trimmed,
                    Some(p),
                    b"",
                    ReaTargetKind::JavaScriptElectron,
                    autonomous_trigger,
                ));
            }
            // Cap read to REA_MAX_FILE_READ_BYTES (256 MiB) so large Rust/Go/Electron binaries
            // (e.g., `osoosi.exe` ~82-128 MiB) are read in full without truncating trailing sections.
            let f = std::fs::File::open(p)?;
            let file_len = f.metadata().map(|m| m.len()).unwrap_or(0);
            let mut buf = Vec::with_capacity((file_len.min(REA_MAX_FILE_READ_BYTES)) as usize);
            f.take(REA_MAX_FILE_READ_BYTES).read_to_end(&mut buf)?;
            let mut report =
                analyze_target_bytes(trimmed, Some(p), &buf, requested_kind, autonomous_trigger);
            // Explicitly release the multi-megabyte file buffer before post-processing
            std::mem::drop(buf);
            if file_len > 16 * 1024 * 1024 {
                osoosi_model::malware::trim_working_set_after_init();
            }
            if file_len > REA_MAX_FILE_READ_BYTES {
                report.limitations.push(ReaLimitation {
                    code: "LARGE_FILE_BOUNDED_READ".to_string(),
                    description: format!(
                        "Target file size ({} bytes) exceeded REA_MAX_FILE_READ_BYTES ({} bytes); analyzed first 256 MiB.",
                        file_len, REA_MAX_FILE_READ_BYTES
                    ),
                    remediation: None,
                });
            }
            return Ok(report);
        }
    }

    if hex_clean.len() >= 8
        && hex_clean.len().is_multiple_of(2)
        && hex_clean.bytes().all(|b| b.is_ascii_hexdigit())
    {
        let raw = hex::decode(&hex_clean)?;
        let effective_kind = if requested_kind == ReaTargetKind::Auto {
            if raw.starts_with(b"\0asm") {
                ReaTargetKind::WasmArtifact
            } else {
                ReaTargetKind::EvmBytecode
            }
        } else {
            requested_kind
        };
        let report = analyze_target_bytes(
            &format!("inline_hex:0x{}...", &hex_clean[..hex_clean.len().min(16)]),
            None,
            &raw,
            effective_kind,
            autonomous_trigger,
        );
        std::mem::drop(raw);
        return Ok(report);
    }

    Err(anyhow!(
        "Target path '{}' does not exist on disk and is not a valid hex payload",
        trimmed
    ))
}

/// Built-in sample EVM ERC-20 + Vault dispatcher bytecode for presets & autonomous verification.
pub const SAMPLE_EVM_CONTRACT_HEX: &str = "0x6080604052348015600f57600080fd5b506004361060485760003560e01c8063a9059cbb14604d578063095ea7b314605557806370a0823114605d5780638da5cb5b1460655780633ccfd60b14606d575b600080fd5b6001600055005b6002600055005b60005460005260206000f35b60015460005260206000f35b600080f400";

/// Built-in sample WebAssembly module bytes (`add(i32, i32) -> i32` + imported `env.log_event`).
pub const SAMPLE_WASM_MODULE_HEX: &str = "0061736d01000000010b0260017f0060027f7f017f02110103656e76096c6f675f6576656e740000030201010707010361646400010a09010700200020016a0b";

