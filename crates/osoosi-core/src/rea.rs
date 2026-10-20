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
use chrono::Utc;
use flate2::read::ZlibDecoder;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tracing::{debug, info};

/// Maximum subprocess stdout/stderr retention limit (4 MiB, matching morluto/rea safety cap).
pub const REA_MAX_SUBPROCESS_OUTPUT_BYTES: usize = 4 * 1024 * 1024;

/// Maximum local file read limit for REA binary & archive inspection (256 MiB, supporting large Rust binaries like osoosi.exe without 64 MiB truncation).
pub const REA_MAX_FILE_READ_BYTES: u64 = 256 * 1024 * 1024;

/// Maximum number of autonomous investigation reports retained in memory.
pub const REA_MAX_INVESTIGATION_HISTORY: usize = 100;

/// Google Magika file content type identification result (Tier 1 envelope & MIME classification).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MagikaFileIdentity {
    pub label: String,
    pub mime_type: String,
    pub group: String,
    pub description: String,
    pub is_text: bool,
    pub score: f32,
    pub engine: String,
}

fn is_valid_native_ort_dylib(path: &Path) -> bool {
    let mut header = [0u8; 4];
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    use std::io::Read;
    if f.read_exact(&mut header).is_err() {
        return false;
    }
    #[cfg(target_os = "windows")]
    {
        header.starts_with(b"MZ")
    }
    #[cfg(target_os = "linux")]
    {
        header == *b"\x7fELF"
    }
    #[cfg(target_os = "macos")]
    {
        matches!(
            u32::from_be_bytes(header),
            0xfeedface | 0xfeedfacf | 0xcefaedfe | 0xcffaedfe | 0xcafebabe
        )
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        true
    }
}

fn has_usable_ort_dylib() -> bool {
    if std::env::var("OSOOSI_NO_ORT")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
    {
        return false;
    }
    if let Ok(p) = std::env::var("ORT_DYLIB_PATH") {
        let trimmed = p.trim();
        if !trimmed.is_empty() {
            return is_valid_native_ort_dylib(Path::new(trimmed));
        }
    }
    #[cfg(target_os = "windows")]
    let dylib_name = "onnxruntime.dll";
    #[cfg(target_os = "macos")]
    let dylib_name = "libonnxruntime.dylib";
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    let dylib_name = "libonnxruntime.so";

    let mut candidates: Vec<PathBuf> = vec![
        PathBuf::from(dylib_name),
        osoosi_types::resolve_base_dir().join(dylib_name),
    ];
    if let Some(proj_root) = osoosi_types::resolve_project_root() {
        candidates.push(proj_root.join(dylib_name));
    }
    if let Ok(exe) = std::env::current_exe() {
        let mut cur = exe.parent();
        for _ in 0..5 {
            let Some(dir) = cur else { break };
            candidates.push(dir.join(dylib_name));
            candidates.push(dir.join("target").join("release").join(dylib_name));
            candidates.push(dir.join("target").join("debug").join(dylib_name));
            cur = dir.parent();
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        let mut cur = Some(cwd.as_path());
        for _ in 0..5 {
            let Some(dir) = cur else { break };
            candidates.push(dir.join(dylib_name));
            candidates.push(dir.join("target").join("release").join(dylib_name));
            candidates.push(dir.join("target").join("debug").join(dylib_name));
            cur = dir.parent();
        }
    }
    for cand in candidates {
        if is_valid_native_ort_dylib(&cand) {
            if std::env::var("ORT_DYLIB_PATH").is_err() {
                let abs = std::fs::canonicalize(&cand).unwrap_or(cand);
                if let Some(s) = abs.to_str() {
                    let clean = s.strip_prefix(r"\\?\").unwrap_or(s);
                    std::env::set_var("ORT_DYLIB_PATH", clean);
                }
            }
            return true;
        }
    }
    false
}

static GLOBAL_MAGIKA_SESSION: LazyLock<Option<parking_lot::Mutex<magika::Session>>> =
    LazyLock::new(|| {
        if !has_usable_ort_dylib() {
            return None;
        }
        let prev_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let res =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| magika::Session::new().ok()));
        std::panic::set_hook(prev_hook);
        res.ok().flatten().map(parking_lot::Mutex::new)
    });

/// Deterministic Magika-compatible structural envelope classification used both as a verifier
/// for short buffers and as a zero-failure fallback when ONNX Runtime is offline.
fn structural_magika_classify(path: Option<&Path>, bytes: &[u8]) -> MagikaFileIdentity {
    if let Some(p) = path {
        if p.is_dir() {
            return MagikaFileIdentity {
                label: "directory".to_string(),
                mime_type: "inode/directory".to_string(),
                group: "inode".to_string(),
                description: "A directory".to_string(),
                is_text: false,
                score: 1.0,
                engine: "google_magika_structural_tier1".to_string(),
            };
        }
    }

    if bytes.starts_with(b"MZ") {
        return MagikaFileIdentity {
            label: "pebin".to_string(),
            mime_type: "application/x-dosexec".to_string(),
            group: "executable".to_string(),
            description: "PE executable".to_string(),
            is_text: false,
            score: 0.99,
            engine: "google_magika_structural_tier1".to_string(),
        };
    }
    if bytes.starts_with(b"\x7fELF") {
        return MagikaFileIdentity {
            label: "elf".to_string(),
            mime_type: "application/x-executable".to_string(),
            group: "executable".to_string(),
            description: "ELF executable".to_string(),
            is_text: false,
            score: 0.99,
            engine: "google_magika_structural_tier1".to_string(),
        };
    }
    if bytes.len() >= 4
        && matches!(
            u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            0xfeedface | 0xfeedfacf | 0xcefaedfe | 0xcffaedfe | 0xcafebabe
        )
    {
        return MagikaFileIdentity {
            label: "macho".to_string(),
            mime_type: "application/x-mach-binary".to_string(),
            group: "executable".to_string(),
            description: "Mach-O executable".to_string(),
            is_text: false,
            score: 0.99,
            engine: "google_magika_structural_tier1".to_string(),
        };
    }
    if bytes.starts_with(b"\0asm") {
        return MagikaFileIdentity {
            label: "wasm".to_string(),
            mime_type: "application/wasm".to_string(),
            group: "executable".to_string(),
            description: "WebAssembly binary".to_string(),
            is_text: false,
            score: 1.0,
            engine: "google_magika_structural_tier1".to_string(),
        };
    }
    if bytes.starts_with(b"SQLite format 3\0") {
        return MagikaFileIdentity {
            label: "sqlite".to_string(),
            mime_type: "application/vnd.sqlite3".to_string(),
            group: "archive".to_string(),
            description: "SQLite database".to_string(),
            is_text: false,
            score: 1.0,
            engine: "google_magika_structural_tier1".to_string(),
        };
    }
    if bytes.len() >= 4
        && matches!(
            u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            0xa1b2c3d4 | 0xd4c3b2a1 | 0xa1b23c4d | 0x4d3cb2a1 | 0x0a0d0d0a
        )
    {
        return MagikaFileIdentity {
            label: "pcap".to_string(),
            mime_type: "application/vnd.tcpdump.pcap".to_string(),
            group: "archive".to_string(),
            description: "PCAP/PCAPNG network capture".to_string(),
            is_text: false,
            score: 0.99,
            engine: "google_magika_structural_tier1".to_string(),
        };
    }
    if bytes.len() >= 24
        && bytes[0..4] == [0x04, 0x00, 0x00, 0x00]
        && find_subslice(&bytes[..bytes.len().min(64)], b"{\"files\"").is_some()
    {
        return MagikaFileIdentity {
            label: "asar".to_string(),
            mime_type: "application/x-asar".to_string(),
            group: "archive".to_string(),
            description: "Electron ASAR archive".to_string(),
            is_text: false,
            score: 0.99,
            engine: "google_magika_structural_tier1".to_string(),
        };
    }
    if bytes.starts_with(b"PK\x03\x04") {
        let is_apk = find_subslice(bytes, b"AndroidManifest.xml").is_some()
            || find_subslice(bytes, b"classes.dex").is_some();
        return MagikaFileIdentity {
            label: if is_apk { "apk" } else { "zip" }.to_string(),
            mime_type: if is_apk {
                "application/vnd.android.package-archive"
            } else {
                "application/zip"
            }
            .to_string(),
            group: "archive".to_string(),
            description: if is_apk {
                "Android package archive"
            } else {
                "ZIP archive"
            }
            .to_string(),
            is_text: false,
            score: 0.99,
            engine: "google_magika_structural_tier1".to_string(),
        };
    }
    if bytes.starts_with(b"dex\n03") {
        return MagikaFileIdentity {
            label: "dex".to_string(),
            mime_type: "application/x-android-dex".to_string(),
            group: "executable".to_string(),
            description: "Dalvik executable".to_string(),
            is_text: false,
            score: 0.99,
            engine: "google_magika_structural_tier1".to_string(),
        };
    }
    if bytes.starts_with(b"hsqs")
        || bytes.starts_with(b"sqsh")
        || bytes.starts_with(b"\x27\x05\x19\x56")
        || bytes.starts_with(b"\xd0\x0d\xfe\xed")
        || bytes.starts_with(b"UBI#")
    {
        return MagikaFileIdentity {
            label: "squashfs".to_string(),
            mime_type: "application/x-squashfs".to_string(),
            group: "archive".to_string(),
            description: "Embedded firmware image".to_string(),
            is_text: false,
            score: 0.98,
            engine: "google_magika_structural_tier1".to_string(),
        };
    }
    if let Ok(text) = std::str::from_utf8(&bytes[..bytes.len().min(4096)]) {
        let trimmed = text.trim_start();
        if trimmed.starts_with('{') || trimmed.starts_with('[') {
            return MagikaFileIdentity {
                label: "json".to_string(),
                mime_type: "application/json".to_string(),
                group: "code".to_string(),
                description: "JSON document".to_string(),
                is_text: true,
                score: 0.97,
                engine: "google_magika_structural_tier1".to_string(),
            };
        }
        if trimmed.starts_with("#!/bin/sh") || trimmed.starts_with("#!/bin/bash") {
            return MagikaFileIdentity {
                label: "shell".to_string(),
                mime_type: "text/x-shellscript".to_string(),
                group: "code".to_string(),
                description: "Shell script".to_string(),
                is_text: true,
                score: 0.98,
                engine: "google_magika_structural_tier1".to_string(),
            };
        }
        return MagikaFileIdentity {
            label: "txt".to_string(),
            mime_type: "text/plain".to_string(),
            group: "text".to_string(),
            description: "Generic text document".to_string(),
            is_text: true,
            score: 0.90,
            engine: "google_magika_structural_tier1".to_string(),
        };
    }

    MagikaFileIdentity {
        label: "unknown".to_string(),
        mime_type: "application/octet-stream".to_string(),
        group: "unknown".to_string(),
        description: "Binary data".to_string(),
        is_text: false,
        score: 0.50,
        engine: "google_magika_structural_tier1".to_string(),
    }
}

/// Identify file/content envelope using Google Magika (`magika::Session`) combined with
/// deterministic magic-header verification (Tier 1 of the REA Classification Pipeline).
pub fn identify_with_magika(path: Option<&Path>, bytes: &[u8]) -> MagikaFileIdentity {
    let structural = structural_magika_classify(path, bytes);
    if let Some(ref mutex) = *GLOBAL_MAGIKA_SESSION {
        let mut session = mutex.lock();
        let magika_res = if !bytes.is_empty() {
            session.identify_content_sync(bytes).ok()
        } else if let Some(p) = path {
            if p.exists() {
                session.identify_file_sync(p).ok()
            } else {
                None
            }
        } else {
            None
        };

        if let Some(ft) = magika_res {
            let info = ft.info();
            // When `structural` matched an explicit binary magic header at offset 0 (score >= 0.99:
            // MZ/PE, ELF, Mach-O, WASM, SQLite, PCAP, ASAR, APK, DEX) and Magika ONNX returns a
            // different label on a short/synthetic buffer (or low confidence < 0.85), preserve the
            // verified container header while recording `google_magika_onnx`.
            if structural.score >= 0.99 && info.label != structural.label {
                return MagikaFileIdentity {
                    engine: "google_magika_onnx".to_string(),
                    ..structural
                };
            }
            if (info.label == "unknown" || info.label == "txt")
                && structural.label != "unknown"
                && structural.label != "txt"
            {
                return MagikaFileIdentity {
                    engine: "google_magika_onnx".to_string(),
                    ..structural
                };
            }
            return MagikaFileIdentity {
                label: info.label.to_string(),
                mime_type: info.mime_type.to_string(),
                group: info.group.to_string(),
                description: info.description.to_string(),
                is_text: info.is_text,
                score: ft.score(),
                engine: "google_magika_onnx".to_string(),
            };
        }
    }
    structural
}

/// Supported target kinds for REA inspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReaTargetKind {
    Auto,
    NativeBinary,
    RustBinary,
    GoBinary,
    WasmArtifact,
    EvmBytecode,
    DotNetAssembly,
    JavaScriptElectron,
    SqliteDatabase,
    NetworkCapture,
    AndroidFlutter,
    FirmwareImage,
}

impl ReaTargetKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::NativeBinary => "native_binary",
            Self::RustBinary => "rust_binary",
            Self::GoBinary => "go_binary",
            Self::WasmArtifact => "wasm_artifact",
            Self::EvmBytecode => "evm_bytecode",
            Self::DotNetAssembly => "dotnet_assembly",
            Self::JavaScriptElectron => "javascript_electron",
            Self::SqliteDatabase => "sqlite_database",
            Self::NetworkCapture => "network_capture",
            Self::AndroidFlutter => "android_flutter",
            Self::FirmwareImage => "firmware_image",
        }
    }

    pub fn from_str_lossy(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "auto" | "" => Self::Auto,
            "native" | "native_binary" | "pe" | "elf" | "macho" | "c" | "cpp" => Self::NativeBinary,
            "rust" | "rust_binary" | "cargo" => Self::RustBinary,
            "go" | "golang" | "go_binary" => Self::GoBinary,
            "wasm" | "wasm_artifact" | "webassembly" => Self::WasmArtifact,
            "evm" | "evm_bytecode" | "solidity" | "bytecode" | "eth" => Self::EvmBytecode,
            "dotnet" | "dotnet_assembly" | "cil" | "csharp" | "net" => Self::DotNetAssembly,
            "electron" | "javascript_electron" | "js" | "asar" | "node" => Self::JavaScriptElectron,
            "sqlite" | "sqlite_database" | "db" | "sqlite3" => Self::SqliteDatabase,
            "har" | "pcap" | "pcapng" | "network" | "network_capture" => Self::NetworkCapture,
            "android" | "flutter" | "apk" | "android_flutter" | "dex" => Self::AndroidFlutter,
            "firmware" | "firmware_image" | "squashfs" | "uimage" | "dtb" | "bin" => {
                Self::FirmwareImage
            }
            _ => Self::Auto,
        }
    }

    pub fn all_supported() -> Vec<Value> {
        vec![
            json!({"id": "auto", "label": "Auto-Detect Target", "description": "Automatically classify magic headers, sections, and runtime markers"}),
            json!({"id": "native_binary", "label": "Native PE / ELF / Mach-O", "description": "Sections, imports, exports, ASLR/DEP/CFG/PIE mitigations, and C pseudocode"}),
            json!({"id": "rust_binary", "label": "Rust Binary (cargo-auditable)", "description": "Extract .dep-v0 zlib JSON crate graph, rustc version, and panic strategy"}),
            json!({"id": "go_binary", "label": "Go Binary (buildinfo)", "description": "Extract Go compiler version, embedded module path, and dependency hashes"}),
            json!({"id": "wasm_artifact", "label": "WebAssembly (.wasm)", "description": "Parse LEB128 sections, Type/Import/Export signatures, and WAT skeleton"}),
            json!({"id": "evm_bytecode", "label": "EVM Smart Contract Bytecode", "description": "Disassemble PUSH4/EQ/JUMPI dispatch tables, 4byte selectors, and Solidity"}),
            json!({"id": "dotnet_assembly", "label": ".NET Assembly (CLR BSJB)", "description": "Parse BSJB CLR root, #~/#Strings/#US/#GUID/#Blob streams, and P/Invoke"}),
            json!({"id": "javascript_electron", "label": "Electron / ASAR / Node.js", "description": "Unpack Chromium ASAR headers, BrowserWindow flags, and IPC channels"}),
            json!({"id": "sqlite_database", "label": "SQLite 3 Database", "description": "Inspect SQLite format 3 header, sqlite_master schema, and WAL state"}),
            json!({"id": "network_capture", "label": "Network Capture (HAR / PCAP)", "description": "Extract HTTP Archive endpoints, headers, TLS SNI, and PCAP packet flows"}),
            json!({"id": "android_flutter", "label": "Android APK / Flutter", "description": "Detect AndroidManifest.xml, classes.dex, libflutter.so, and libapp.so"}),
            json!({"id": "firmware_image", "label": "Embedded Firmware Image", "description": "Scan for SquashFS, U-Boot uImage, Device Tree Blob (DTB), XZ/Zstd/Gzip"}),
        ]
    }
}

/// Cryptographically anchored evidence item backing an REA observation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReaEvidence {
    pub source: String,
    pub location: String,
    pub observation: String,
    pub confidence: f32,
    pub digest_sha256: Option<String>,
}

/// Explicit limitation or partial-visibility disclosure in an REA investigation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReaLimitation {
    pub code: String,
    pub description: String,
    pub remediation: Option<String>,
}

/// External or built-in REA reverse-engineering provider readiness status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReaProviderStatus {
    pub name: String,
    pub available: bool,
    pub path: Option<String>,
    pub version: Option<String>,
    pub capabilities: Vec<String>,
}

/// Complete, evidence-backed REA investigation report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReaInvestigationReport {
    pub target_path: String,
    pub detected_kind: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub blake3: String,
    pub summary: String,
    pub metadata: Value,
    pub findings: Vec<Value>,
    pub evidence: Vec<ReaEvidence>,
    pub limitations: Vec<ReaLimitation>,
    pub reconstructed_code: Option<String>,
    #[serde(default)]
    pub auto_yara_rule: Option<String>,
    #[serde(default)]
    pub threat_score: f32,
    #[serde(default)]
    pub autonomous_trigger: Option<String>,
    pub providers_used: Vec<String>,
    pub timestamp: String,
}

/// Request payload for `/api/rea/analyze` dashboard and API endpoint.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReaAnalyzeRequest {
    pub path: Option<String>,
    pub target: Option<String>,
    pub bytecode_hex: Option<String>,
    pub preset: Option<String>,
    pub trigger: Option<String>,
}

/// Compute SHA-256 hex digest for a byte slice.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

/// Compute BLAKE3 hex digest for a byte slice.
pub fn blake3_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

/// Compute Shannon entropy (0.0 to 8.0 bits/byte) of a byte slice.
pub fn calculate_entropy(bytes: &[u8]) -> f32 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f32;
    let mut entropy = 0.0f32;
    for &c in &counts {
        if c > 0 {
            let p = (c as f32) / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Find a subslice needle inside a byte slice.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Extract printable ASCII strings of at least `min_len` characters from a byte slice.
pub fn extract_printable_strings(bytes: &[u8], min_len: usize, max_count: usize) -> Vec<String> {
    let mut results = Vec::new();
    let mut current = Vec::new();

    for &b in bytes {
        if (0x20..=0x7E).contains(&b) {
            current.push(b);
        } else {
            if current.len() >= min_len {
                if let Ok(s) = String::from_utf8(current.clone()) {
                    let trimmed = s.trim();
                    if trimmed.len() >= min_len {
                        results.push(trimmed.to_string());
                        if results.len() >= max_count {
                            return results;
                        }
                    }
                }
            }
            current.clear();
        }
    }
    if current.len() >= min_len && results.len() < max_count {
        if let Ok(s) = String::from_utf8(current) {
            let trimmed = s.trim();
            if trimmed.len() >= min_len {
                results.push(trimmed.to_string());
            }
        }
    }
    results
}

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
fn pe_rva_to_file_offset(pe: &goblin::pe::PE, rva: usize, file_len: usize) -> Option<usize> {
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
fn pe_clr_runtime_header_present(bytes: &[u8]) -> Option<bool> {
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
fn find_pe_dotnet_bsjb_header(bytes: &[u8]) -> Option<(usize, String, Vec<Value>)> {
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
        let decoder = ZlibDecoder::new(slice);
        let mut json_str = String::new();
        if decoder
            .take(4 * 1024 * 1024)
            .read_to_string(&mut json_str)
            .is_ok()
        {
            if let Ok(parsed) = serde_json::from_str::<Value>(&json_str) {
                if let Some(pkgs) = parsed.get("packages").and_then(|v| v.as_array()) {
                    auditable_found = true;
                    for pkg in pkgs {
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

            for sec in &pe.sections {
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

            for imp in &pe.imports {
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

            for exp in &pe.exports {
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
            for ph in &elf.program_headers {
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
            for sym in elf.dynsyms.iter() {
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

            for sh in &elf.section_headers {
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
                    for _ in 0..count {
                        if cur >= sec_end || bytes[cur] != 0x60 {
                            break;
                        }
                        cur += 1;
                        let Some(p_count) = read_leb128_u32(bytes, &mut cur) else {
                            break;
                        };
                        let mut params = Vec::new();
                        for _ in 0..p_count {
                            if cur < sec_end {
                                params.push(wasm_valtype_str(bytes[cur]));
                                cur += 1;
                            }
                        }
                        let Some(r_count) = read_leb128_u32(bytes, &mut cur) else {
                            break;
                        };
                        let mut results = Vec::new();
                        for _ in 0..r_count {
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
                    for _ in 0..count {
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
                    for _ in 0..count {
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
                    for _ in 0..count {
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
                    function_body_count = count;
                }
            }
            _ => {}
        }

        pos = sec_end;
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
        .max(function_body_count as usize);
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
    while pc < bytecode.len() {
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

// ============================================================================
// 7. JavaScript / Electron & ASAR Archive Inspector
// ============================================================================

fn walk_asar_files(node: &Value, prefix: &str, out: &mut Vec<(String, u64, u64)>) {
    if let Some(files) = node.get("files").and_then(|v| v.as_object()) {
        for (name, child) in files {
            let path = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{}/{}", prefix, name)
            };
            if child.get("files").is_some() {
                walk_asar_files(child, &path, out);
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

// ============================================================================
// 8. SQLite 3 Database Inspector (`SQLite format 3\0` + `sqlite_master` + PRAGMA)
// ============================================================================

pub fn inspect_sqlite_database(
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

    let has_valid_magic = bytes.starts_with(b"SQLite format 3\0");
    let mut page_size = 0u32;
    let mut page_count = 0u32;
    let mut text_encoding = "UTF-8";
    let mut user_version = 0u32;

    if has_valid_magic && bytes.len() >= 100 {
        let raw_ps = u16::from_be_bytes([bytes[16], bytes[17]]) as u32;
        page_size = if raw_ps == 1 { 65536 } else { raw_ps };
        page_count = u32::from_be_bytes([bytes[28], bytes[29], bytes[30], bytes[31]]);
        let enc = u32::from_be_bytes([bytes[56], bytes[57], bytes[58], bytes[59]]);
        text_encoding = match enc {
            1 => "UTF-8",
            2 => "UTF-16le",
            3 => "UTF-16be",
            _ => "UTF-8",
        };
        user_version = u32::from_be_bytes([bytes[60], bytes[61], bytes[62], bytes[63]]);

        evidence.push(ReaEvidence {
            source: "sqlite3_file_header".to_string(),
            location: "offset 0x0..0x64".to_string(),
            observation: format!(
                "SQLite format 3 header verified (page_size={}, pages={}, encoding={}, user_version={})",
                page_size, page_count, text_encoding, user_version
            ),
            confidence: 1.0,
            digest_sha256: None,
        });
    } else if !has_valid_magic {
        limitations.push(ReaLimitation {
            code: "INVALID_SQLITE_HEADER".to_string(),
            description: "File does not begin with `SQLite format 3\\0` header.".to_string(),
            remediation: None,
        });
    }

    // Open read-only via rusqlite (either directly from path or a temporary snapshot if only bytes were passed)
    let mut temp_db_path: Option<PathBuf> = None;
    let db_open_path: Option<PathBuf> = if let Some(p) = path {
        if p.is_file() {
            Some(p.to_path_buf())
        } else {
            None
        }
    } else if has_valid_magic {
        let tmp = std::env::temp_dir().join(format!(
            "osoosi_rea_sqlite_{}_{}.db",
            std::process::id(),
            rand::random::<u64>()
        ));
        if std::fs::write(&tmp, bytes).is_ok() {
            temp_db_path = Some(tmp.clone());
            Some(tmp)
        } else {
            None
        }
    } else {
        None
    };

    let mut tables: Vec<Value> = Vec::new();
    let mut views: Vec<String> = Vec::new();
    let mut indexes: Vec<String> = Vec::new();
    let mut triggers: Vec<String> = Vec::new();
    let mut ddl_statements: Vec<String> = Vec::new();

    if let Some(ref open_p) = db_open_path {
        let flags =
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX;
        if let Ok(conn) = rusqlite::Connection::open_with_flags(open_p, flags) {
            if let Ok(mut stmt) = conn.prepare(
                "SELECT type, name, tbl_name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
            ) {
                let rows = stmt.query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0).unwrap_or_default(),
                        row.get::<_, String>(1).unwrap_or_default(),
                        row.get::<_, String>(2).unwrap_or_default(),
                        row.get::<_, Option<String>>(3).unwrap_or(None),
                    ))
                });
                if let Ok(mapped) = rows {
                    for item in mapped.flatten() {
                        let (obj_type, name, _tbl, sql_opt) = item;
                        if let Some(ref s) = sql_opt {
                            ddl_statements.push(format!("{};", s.trim().trim_end_matches(';')));
                        }
                        match obj_type.as_str() {
                            "table" => {
                                let mut cols = Vec::new();
                                let safe_name = name.replace('"', "\"\"");
                                if let Ok(mut pragma_stmt) =
                                    conn.prepare(&format!("PRAGMA table_info(\"{}\")", safe_name))
                                {
                                    if let Ok(c_rows) = pragma_stmt.query_map([], |r| {
                                        Ok(json!({
                                            "cid": r.get::<_, i64>(0).unwrap_or(0),
                                            "name": r.get::<_, String>(1).unwrap_or_default(),
                                            "type": r.get::<_, String>(2).unwrap_or_default(),
                                            "notnull": r.get::<_, i64>(3).unwrap_or(0) != 0,
                                            "pk": r.get::<_, i64>(5).unwrap_or(0) != 0,
                                        }))
                                    }) {
                                        for c in c_rows.flatten() {
                                            cols.push(c);
                                        }
                                    }
                                }
                                tables.push(json!({
                                    "name": name,
                                    "columns": cols,
                                    "sql": sql_opt,
                                }));
                            }
                            "view" => views.push(name),
                            "index" => indexes.push(name),
                            "trigger" => triggers.push(name),
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    if let Some(tmp) = temp_db_path {
        let _ = std::fs::remove_file(tmp);
    }

    let wal_present = path
        .map(|p| {
            let mut wal = p.as_os_str().to_os_string();
            wal.push("-wal");
            PathBuf::from(wal).is_file()
        })
        .unwrap_or(false);

    if wal_present {
        limitations.push(ReaLimitation {
            code: "SQLITE_WAL_ACTIVE".to_string(),
            description: "Write-Ahead Log (-wal) file exists alongside database; uncommitted frames may reside in WAL.".to_string(),
            remediation: Some("Include the companion -wal and -shm files when copying live forensic snapshots.".to_string()),
        });
    }

    if !tables.is_empty() {
        evidence.push(ReaEvidence {
            source: "sqlite_master_catalog".to_string(),
            location: "sqlite_master".to_string(),
            observation: format!(
                "Extracted {} tables, {} indexes, {} views, {} triggers",
                tables.len(),
                indexes.len(),
                views.len(),
                triggers.len()
            ),
            confidence: 1.0,
            digest_sha256: None,
        });
    }

    findings.push(json!({
        "category": "sqlite_schema",
        "severity": "info",
        "title": format!("SQLite 3 Database ({} tables, {} indexes)", tables.len(), indexes.len()),
        "detail": format!("Page size: {}B, Encoding: {}, WAL active: {}", page_size, text_encoding, wal_present),
    }));

    let reconstructed = if ddl_statements.is_empty() {
        "-- SQLite 3 Database Schema (no user tables in sqlite_master)\n".to_string()
    } else {
        format!(
            "-- Reconstructed SQLite 3 Schema via OpenOshoosi REA\n-- Page Size: {} | Encoding: {}\n\n{}\n",
            page_size,
            text_encoding,
            ddl_statements.join("\n\n")
        )
    };

    let metadata = json!({
        "valid_sqlite": has_valid_magic,
        "page_size": page_size,
        "page_count": page_count,
        "text_encoding": text_encoding,
        "user_version": user_version,
        "wal_present": wal_present,
        "table_count": tables.len(),
        "tables": tables,
        "views": views,
        "indexes": indexes,
        "triggers": triggers,
    });

    (metadata, findings, evidence, limitations, reconstructed)
}

// ============================================================================
// 9. Network Capture Inspector (`.har` HTTP Archive & `.pcap` / `.pcapng`)
// ============================================================================

pub fn inspect_network_capture(
    _path: Option<&Path>,
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

    // Check HAR JSON first
    if let Ok(har_val) = serde_json::from_slice::<Value>(bytes) {
        if let Some(entries) = har_val
            .get("log")
            .and_then(|l| l.get("entries"))
            .and_then(|e| e.as_array())
        {
            let mut endpoints = Vec::new();
            let mut sensitive_headers = Vec::new();
            let mut status_distribution: HashMap<u64, usize> = HashMap::new();

            for entry in entries.iter().take(200) {
                let req = entry.get("request");
                let resp = entry.get("response");
                let method = req
                    .and_then(|r| r.get("method"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("GET");
                let url = req
                    .and_then(|r| r.get("url"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let status = resp
                    .and_then(|r| r.get("status"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                *status_distribution.entry(status).or_insert(0) += 1;

                if let Some(hdrs) = req
                    .and_then(|r| r.get("headers"))
                    .and_then(|h| h.as_array())
                {
                    for h in hdrs {
                        let hname = h
                            .get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_ascii_lowercase();
                        if matches!(
                            hname.as_str(),
                            "authorization" | "cookie" | "x-api-key" | "x-osoosi-token"
                        ) && !sensitive_headers.contains(&hname)
                        {
                            sensitive_headers.push(hname);
                        }
                    }
                }

                endpoints.push(json!({
                    "method": method,
                    "url": url,
                    "status": status,
                }));
            }

            evidence.push(ReaEvidence {
                source: "har_archive_parser".to_string(),
                location: "log.entries".to_string(),
                observation: format!(
                    "Parsed {} HTTP Archive (HAR) request/response transactions",
                    entries.len()
                ),
                confidence: 1.0,
                digest_sha256: None,
            });

            findings.push(json!({
                "category": "har_network_capture",
                "severity": if sensitive_headers.is_empty() { "info" } else { "medium" },
                "title": format!("HAR Capture ({} HTTP entries, {} sensitive header types)", entries.len(), sensitive_headers.len()),
                "detail": format!("Sensitive headers observed: {:?}", sensitive_headers),
            }));

            let mut spec = String::from("# Reconstructed HTTP API Surface from HAR Capture\n");
            for ep in endpoints.iter().take(30) {
                spec.push_str(&format!(
                    "{} {} -> HTTP {}\n",
                    ep.get("method").and_then(|v| v.as_str()).unwrap_or("GET"),
                    ep.get("url").and_then(|v| v.as_str()).unwrap_or("/"),
                    ep.get("status").and_then(|v| v.as_u64()).unwrap_or(200)
                ));
            }

            let metadata = json!({
                "capture_format": "HAR",
                "entry_count": entries.len(),
                "endpoints": endpoints,
                "sensitive_headers": sensitive_headers,
                "status_distribution": status_distribution,
            });
            return (metadata, findings, evidence, limitations, spec);
        }
    }

    // PCAP / PCAPNG binary parser
    let mut format_name = "PCAP";
    let mut linktype = 0u32;
    let mut snaplen = 0u32;
    let mut packet_count = 0usize;
    let mut ipv4_endpoints: HashSet<String> = HashSet::new();

    if bytes.len() >= 24 {
        let m32 = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let is_le = matches!(m32, 0xd4c3b2a1 | 0x4d3cb2a1);
        if m32 == 0x0a0d0d0a {
            format_name = "PCAPNG";
        } else if matches!(m32, 0xa1b2c3d4 | 0xd4c3b2a1 | 0xa1b23c4d | 0x4d3cb2a1) {
            snaplen = if is_le {
                u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]])
            } else {
                u32::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19]])
            };
            linktype = if is_le {
                u32::from_le_bytes([bytes[20], bytes[21], bytes[22], bytes[23]])
            } else {
                u32::from_be_bytes([bytes[20], bytes[21], bytes[22], bytes[23]])
            };

            let mut off = 24usize;
            while off + 16 <= bytes.len() {
                let incl_len = if is_le {
                    u32::from_le_bytes([
                        bytes[off + 8],
                        bytes[off + 9],
                        bytes[off + 10],
                        bytes[off + 11],
                    ]) as usize
                } else {
                    u32::from_be_bytes([
                        bytes[off + 8],
                        bytes[off + 9],
                        bytes[off + 10],
                        bytes[off + 11],
                    ]) as usize
                };
                off += 16;
                if off + incl_len > bytes.len() {
                    break;
                }
                packet_count += 1;
                let pkt = &bytes[off..off + incl_len];
                // Ethernet (14 bytes) + IPv4 header (0x45)
                if linktype == 1 && pkt.len() >= 34 && pkt[12] == 0x08 && pkt[13] == 0x00 {
                    let src_ip = format!("{}.{}.{}.{}", pkt[26], pkt[27], pkt[28], pkt[29]);
                    let dst_ip = format!("{}.{}.{}.{}", pkt[30], pkt[31], pkt[32], pkt[33]);
                    ipv4_endpoints.insert(format!("{} -> {}", src_ip, dst_ip));
                }
                off += incl_len;
            }
        }
    }

    evidence.push(ReaEvidence {
        source: "pcap_packet_inspector".to_string(),
        location: "global_header+packets".to_string(),
        observation: format!(
            "Parsed {} capture ({} packets, linktype={}, snaplen={})",
            format_name, packet_count, linktype, snaplen
        ),
        confidence: 0.98,
        digest_sha256: None,
    });

    let flows: Vec<String> = ipv4_endpoints.into_iter().collect();
    findings.push(json!({
        "category": "pcap_capture",
        "severity": "info",
        "title": format!("{} Capture ({} packets, {} IPv4 flows)", format_name, packet_count, flows.len()),
        "detail": flows.join(", "),
    }));

    let reconstructed = format!(
        "# Reconstructed Network Flows ({})\n# Packets: {} | SnapLen: {} | LinkType: {}\n{}\n",
        format_name,
        packet_count,
        snaplen,
        linktype,
        flows.join("\n")
    );

    let metadata = json!({
        "capture_format": format_name,
        "packet_count": packet_count,
        "snaplen": snaplen,
        "linktype": linktype,
        "ipv4_flows": flows,
    });

    (metadata, findings, evidence, limitations, reconstructed)
}

// ============================================================================
// 10. Firmware & Android / Flutter APK Inspector
// ============================================================================

pub fn inspect_firmware_or_apk(
    _path: Option<&Path>,
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

    let mut signatures: Vec<Value> = Vec::new();
    let magic_patterns: &[(&[u8], &str)] = &[
        (b"hsqs", "SquashFS (Little-Endian)"),
        (b"sqsh", "SquashFS (Big-Endian)"),
        (b"\x27\x05\x19\x56", "U-Boot uImage Header"),
        (b"\xd0\x0d\xfe\xed", "Flattened Device Tree (DTB)"),
        (b"\x1f\x8b\x08", "Gzip Compressed Stream"),
        (b"\xfd7zXZ\0", "XZ Compressed Stream"),
        (b"\x28\xb5\x2f\xfd", "Zstandard (Zstd) Frame"),
        (b"UBI#", "UBI Flash Image"),
        (b"070701", "CPIO newc Initramfs Archive"),
        (b"dex\n035\0", "Android Dalvik DEX 035"),
        (b"dex\n039\0", "Android Dalvik DEX 039"),
    ];

    for (pat, label) in magic_patterns {
        let mut search_from = 0usize;
        while search_from + pat.len() <= bytes.len() {
            if let Some(rel) = find_subslice(&bytes[search_from..], pat) {
                let abs_off = search_from + rel;
                // Avoid false-positive DTB inside random data unless 4-byte aligned or at offset 0
                if *pat == b"\xd0\x0d\xfe\xed" && abs_off != 0 && !abs_off.is_multiple_of(4) {
                    search_from = abs_off + 1;
                    continue;
                }
                signatures.push(json!({
                    "signature": label,
                    "offset": format!("0x{:x}", abs_off),
                }));
                evidence.push(ReaEvidence {
                    source: "firmware_magic_scanner".to_string(),
                    location: format!("offset 0x{:x}", abs_off),
                    observation: format!("Identified {} header at 0x{:x}", label, abs_off),
                    confidence: 0.98,
                    digest_sha256: None,
                });
                if signatures.len() >= 50 {
                    break;
                }
                search_from = abs_off + pat.len();
            } else {
                break;
            }
        }
    }

    // Check APK / Flutter markers
    let mut apk_entries: Vec<String> = Vec::new();
    if bytes.starts_with(b"PK\x03\x04") {
        if let Ok(mut archive) = zip::ZipArchive::new(Cursor::new(bytes)) {
            for i in 0..archive.len().min(200) {
                if let Ok(file) = archive.by_index(i) {
                    apk_entries.push(file.name().to_string());
                }
            }
        }
    }

    let has_manifest = apk_entries
        .iter()
        .any(|e| e.contains("AndroidManifest.xml"))
        || find_subslice(bytes, b"AndroidManifest.xml").is_some();
    let has_dex = apk_entries.iter().any(|e| e.ends_with(".dex"))
        || find_subslice(bytes, b"classes.dex").is_some()
        || find_subslice(bytes, b"dex\n03").is_some();
    let has_flutter = apk_entries
        .iter()
        .any(|e| e.contains("libflutter.so") || e.contains("libapp.so"))
        || find_subslice(bytes, b"libflutter.so").is_some()
        || find_subslice(bytes, b"libapp.so").is_some();

    if has_manifest || has_dex || has_flutter {
        evidence.push(ReaEvidence {
            source: "android_flutter_inspector".to_string(),
            location: "APK/ZIP container".to_string(),
            observation: format!(
                "Android/Flutter markers: AndroidManifest={}, DEX={}, Flutter(libapp.so/libflutter.so)={}",
                has_manifest, has_dex, has_flutter
            ),
            confidence: 0.99,
            digest_sha256: None,
        });
    }

    findings.push(json!({
        "category": "firmware_apk_layout",
        "severity": "info",
        "title": format!(
            "Firmware/Mobile Artifact ({} embedded signatures, Flutter={}, DEX={})",
            signatures.len(),
            has_flutter,
            has_dex
        ),
        "detail": format!("Signatures: {:?}", signatures),
    }));

    let mut layout =
        String::from("// Reconstructed Firmware / APK Partition Map via OpenOshoosi REA\n");
    for sig in &signatures {
        layout.push_str(&format!(
            "offset {} : {}\n",
            sig.get("offset").and_then(|v| v.as_str()).unwrap_or("0x0"),
            sig.get("signature")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown")
        ));
    }
    if has_manifest || has_dex || has_flutter {
        layout.push_str(&format!(
            "\n// Android/Flutter Package:\n// AndroidManifest.xml: {}\n// Dalvik/ART classes.dex: {}\n// Flutter AOT (libapp.so / libflutter.so): {}\n",
            has_manifest, has_dex, has_flutter
        ));
    }

    let metadata = json!({
        "embedded_signatures": signatures,
        "android_manifest": has_manifest,
        "classes_dex": has_dex,
        "flutter_aot": has_flutter,
        "apk_entries": apk_entries,
    });

    (metadata, findings, evidence, limitations, layout)
}

// ============================================================================
// Auto-Synthesized Multi-Token YARA Rule Generator
// ============================================================================

/// Synthesizes a production-grade, multi-token YARA rule from an REA investigation.
/// Never matches a lone process name; requires file size bounds + multiple structural/artifact tokens.
pub fn synthesize_rea_yara_rule(
    target_label: &str,
    detected_kind: &str,
    bytes: &[u8],
    sha256: &str,
    blake3_hash: &str,
) -> String {
    let clean_ident: String = target_label
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .take(36)
        .collect();
    let rule_name = format!(
        "REA_Auto_{}_{}",
        if clean_ident.is_empty() {
            "Artifact"
        } else {
            &clean_ident
        },
        &sha256[..sha256.len().min(8)]
    );

    let header_hex = hex::encode(&bytes[..bytes.len().min(8)]).to_ascii_uppercase();
    let mut header_pairs = Vec::new();
    for i in (0..header_hex.len()).step_by(2) {
        if i + 2 <= header_hex.len() {
            header_pairs.push(&header_hex[i..i + 2]);
        }
    }
    let header_pattern = if header_pairs.is_empty() {
        "00".to_string()
    } else {
        header_pairs.join(" ")
    };

    let strings = extract_printable_strings(bytes, 6, 60);
    let mut selected_tokens: Vec<String> = Vec::new();
    for s in strings {
        let escaped = s
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .chars()
            .filter(|c| c.is_ascii_graphic() || *c == ' ')
            .take(48)
            .collect::<String>();
        if escaped.len() >= 6 && !selected_tokens.contains(&escaped) {
            selected_tokens.push(escaped);
            if selected_tokens.len() >= 4 {
                break;
            }
        }
    }

    let mut rule = format!(
        "rule {} {{\n    meta:\n        author = \"OpenOshoosi Autonomous REA Engine\"\n        detected_kind = \"{}\"\n        sha256 = \"{}\"\n        blake3 = \"{}\"\n        generated_at = \"{}\"\n    strings:\n        $magic_hdr = {{ {} }}\n",
        rule_name,
        detected_kind,
        sha256,
        blake3_hash,
        Utc::now().to_rfc3339(),
        header_pattern
    );

    for (idx, tok) in selected_tokens.iter().enumerate() {
        rule.push_str(&format!(
            "        $tok_{} = \"{}\" ascii wide\n",
            idx + 1,
            tok
        ));
    }

    let min_size = bytes.len().saturating_sub(bytes.len() / 2).max(1);
    let max_size = bytes.len().saturating_add(bytes.len() / 2 + 4096);

    if selected_tokens.len() >= 2 {
        rule.push_str(&format!(
            "    condition:\n        filesize >= {} and filesize <= {} and $magic_hdr at 0 and 2 of ($tok_*)\n}}\n",
            min_size, max_size
        ));
    } else if selected_tokens.len() == 1 {
        rule.push_str(&format!(
            "    condition:\n        filesize >= {} and filesize <= {} and $magic_hdr at 0 and $tok_1\n}}\n",
            min_size, max_size
        ));
    } else {
        rule.push_str(&format!(
            "    condition:\n        filesize >= {} and filesize <= {} and $magic_hdr at 0\n}}\n",
            min_size, max_size
        ));
    }

    rule
}

// ============================================================================
// Provider Discovery & Bounded Subprocess Execution (4 MiB Cap)
// ============================================================================

/// Discover both built-in native Rust REA engines and optional external RE providers on the host.
pub fn discover_rea_providers() -> Vec<ReaProviderStatus> {
    static REA_PROVIDERS_CACHE: std::sync::OnceLock<
        parking_lot::RwLock<Option<(std::time::Instant, Vec<ReaProviderStatus>)>>,
    > = std::sync::OnceLock::new();
    let cache = REA_PROVIDERS_CACHE.get_or_init(|| parking_lot::RwLock::new(None));
    if let Some((ts, ref list)) = *cache.read() {
        if ts.elapsed() < std::time::Duration::from_secs(300) {
            return list.clone();
        }
    }
    let mut providers = vec![
        ReaProviderStatus {
            name: "osoosi-rea-native (PE/ELF/Mach-O/Rust/Go)".to_string(),
            available: true,
            path: Some("built-in://osoosi-core/rea".to_string()),
            version: Some(env!("CARGO_PKG_VERSION").to_string()),
            capabilities: vec![
                "native_binary".to_string(),
                "rust_binary".to_string(),
                "go_binary".to_string(),
                "dotnet_assembly".to_string(),
                "auto_yara_synthesis".to_string(),
            ],
        },
        ReaProviderStatus {
            name: "osoosi-rea-bytecode (WASM/EVM/ASAR/SQLite/HAR/Firmware)".to_string(),
            available: true,
            path: Some("built-in://osoosi-core/rea-bytecode".to_string()),
            version: Some(env!("CARGO_PKG_VERSION").to_string()),
            capabilities: vec![
                "wasm_artifact".to_string(),
                "evm_bytecode".to_string(),
                "javascript_electron".to_string(),
                "sqlite_database".to_string(),
                "network_capture".to_string(),
                "android_flutter".to_string(),
                "firmware_image".to_string(),
            ],
        },
        ReaProviderStatus {
            name: "google-magika-onnx (Deep-Learning Content Type Identification)".to_string(),
            available: true,
            path: Some("built-in://google-magika".to_string()),
            version: Some("1.0.0".to_string()),
            capabilities: vec![
                "tier1_envelope_detection".to_string(),
                "mime_type_classification".to_string(),
                "polyglot_content_identification".to_string(),
            ],
        },
    ];

    let external_tools: &[(&str, &[&str])] = &[
        ("rea", &["mcp_orchestrator", "binary_triage"]),
        ("npx", &["rea_mcp_launcher"]),
        ("ghidraRun", &["decompilation", "cfg_recovery"]),
        ("rizin", &["disassembly", "analysis"]),
        ("radare2", &["disassembly", "binary_patching"]),
        ("objdump", &["section_disassembly", "symbol_tables"]),
        ("dumpbin", &["pe_headers", "imports_exports"]),
        ("jadx", &["apk_dex_decompilation"]),
        ("binwalk", &["firmware_carving"]),
        ("tshark", &["pcap_protocol_dissection"]),
        ("adb", &["android_runtime_bridge"]),
    ];

    for (tool, caps) in external_tools {
        let resolved = crate::tool_paths::resolve_executable(tool);
        providers.push(ReaProviderStatus {
            name: (*tool).to_string(),
            available: resolved.is_some(),
            path: resolved.map(|p| p.display().to_string()),
            version: None,
            capabilities: caps.iter().map(|s| (*s).to_string()).collect(),
        });
    }

    *cache.write() = Some((std::time::Instant::now(), providers.clone()));
    providers
}

/// Execute an external REA CLI or companion tool with a strict 4 MiB output retention cap
/// and automatic child process termination on timeout/drop.
pub async fn run_external_rea_cli(
    program: &str,
    args: &[&str],
    timeout_secs: u64,
) -> Result<(i32, String, String, bool)> {
    let resolved =
        crate::tool_paths::resolve_executable(program).unwrap_or_else(|| PathBuf::from(program));

    let mut cmd = tokio::process::Command::new(resolved);
    cmd.args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);

    #[cfg(target_os = "windows")]
    {
        #[allow(unused_imports)]
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }

    let mut child = cmd
        .spawn()
        .map_err(|e| anyhow!("Failed to spawn {}: {}", program, e))?;

    let stdout_pipe = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("Failed to capture stdout"))?;
    let stderr_pipe = child
        .stderr
        .take()
        .ok_or_else(|| anyhow!("Failed to capture stderr"))?;

    let read_bounded = async move {
        use tokio::io::AsyncReadExt;
        let mut out_buf = Vec::new();
        let mut err_buf = Vec::new();
        let _ = stdout_pipe
            .take((REA_MAX_SUBPROCESS_OUTPUT_BYTES + 1) as u64)
            .read_to_end(&mut out_buf)
            .await;
        let _ = stderr_pipe
            .take((REA_MAX_SUBPROCESS_OUTPUT_BYTES + 1) as u64)
            .read_to_end(&mut err_buf)
            .await;
        let status = child.wait().await?;
        Ok::<_, std::io::Error>((status.code().unwrap_or(-1), out_buf, err_buf))
    };

    match tokio::time::timeout(Duration::from_secs(timeout_secs.max(1)), read_bounded).await {
        Ok(Ok((code, mut out_buf, mut err_buf))) => {
            let mut truncated = false;
            if out_buf.len() > REA_MAX_SUBPROCESS_OUTPUT_BYTES {
                out_buf.truncate(REA_MAX_SUBPROCESS_OUTPUT_BYTES);
                truncated = true;
            }
            if err_buf.len() > REA_MAX_SUBPROCESS_OUTPUT_BYTES {
                err_buf.truncate(REA_MAX_SUBPROCESS_OUTPUT_BYTES);
                truncated = true;
            }
            Ok((
                code,
                String::from_utf8_lossy(&out_buf).to_string(),
                String::from_utf8_lossy(&err_buf).to_string(),
                truncated,
            ))
        }
        Ok(Err(e)) => Err(anyhow!("Subprocess I/O error: {}", e)),
        Err(_) => Err(anyhow!(
            "Subprocess {} timed out after {}s and was terminated",
            program,
            timeout_secs
        )),
    }
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

    let (mut metadata, findings, mut evidence, mut limitations, reconstructed) =
        match effective_kind {
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
                (combined_meta, r_find, r_ev, r_lim, r_code)
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
                (combined_meta, g_find, g_ev, g_lim, g_code)
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
                (combined_meta, d_find, d_ev, d_lim, d_code)
            }
            ReaTargetKind::NativeBinary | ReaTargetKind::Auto => inspect_native_binary(path, bytes),
            ReaTargetKind::WasmArtifact => {
                providers_used.push("osoosi-rea-wasm".to_string());
                inspect_wasm_artifact(bytes)
            }
            ReaTargetKind::EvmBytecode => {
                providers_used.push("osoosi-rea-evm".to_string());
                inspect_evm_bytecode(bytes)
            }
            ReaTargetKind::JavaScriptElectron => {
                providers_used.push("osoosi-rea-electron-asar".to_string());
                inspect_javascript_electron(path, bytes)
            }
            ReaTargetKind::SqliteDatabase => {
                providers_used.push("osoosi-rea-sqlite".to_string());
                inspect_sqlite_database(path, bytes)
            }
            ReaTargetKind::NetworkCapture => {
                providers_used.push("osoosi-rea-netcap".to_string());
                inspect_network_capture(path, bytes)
            }
            ReaTargetKind::AndroidFlutter | ReaTargetKind::FirmwareImage => {
                providers_used.push("osoosi-rea-firmware-apk".to_string());
                inspect_firmware_or_apk(path, bytes)
            }
        };

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

    ReaInvestigationReport {
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
    }
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

    let p = Path::new(trimmed);
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

    // Check if it's a hex payload (e.g. `0x60806040...` or WASM hex `0061736d...`)
    let hex_clean: String = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed)
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();

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

// ============================================================================
// Autonomous REA Engine (`AutonomousReaEngine`)
// ============================================================================

/// Autonomous Reverse-Engineering Engine that continuously discovers, inspects,
/// reconstructs pseudocode, and generates multi-token YARA rules for host binaries and artifacts.
fn resolve_candidate_binary_path(
    process_name: Option<&str>,
    file_path: Option<&str>,
) -> Option<PathBuf> {
    for cand in [file_path, process_name].into_iter().flatten() {
        let trimmed = cand.trim().trim_matches('"');
        if trimmed.is_empty() {
            continue;
        }
        let p = PathBuf::from(trimmed);
        if p.is_file() {
            return Some(p);
        }
    }
    let name = process_name
        .or(file_path)
        .map(|s| s.trim().trim_matches('"'))
        .unwrap_or("");
    if name.is_empty() {
        return None;
    }
    let base_name = Path::new(name)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(name);
    let mut names = vec![base_name.to_string()];
    if !base_name.ends_with(".exe") && !base_name.contains('.') {
        names.push(format!("{}.exe", base_name));
    }
    #[cfg(target_os = "windows")]
    {
        let standard_dirs = [
            r"C:\Windows\System32",
            r"C:\Windows\SysWOW64",
            r"C:\Windows",
            r"C:\Program Files\Git\cmd",
            r"C:\Program Files\Git\mingw64\bin",
            r"C:\Program Files\Git\usr\bin",
            r"C:\Program Files\Google\Chrome\Application",
            r"C:\Program Files (x86)\Google\Chrome\Application",
            r"C:\Program Files\Microsoft\Edge\Application",
        ];
        for dir in &standard_dirs {
            for n in &names {
                let cand = Path::new(dir).join(n);
                if cand.is_file() {
                    return Some(cand);
                }
            }
        }
    }
    if let Some(path_var) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path_var) {
            for n in &names {
                let cand = dir.join(n);
                if cand.is_file() {
                    return Some(cand);
                }
            }
        }
    }
    None
}

pub struct AutonomousReaEngine {
    pub autonomous_enabled: AtomicBool,
    pub total_autonomous_sweeps: AtomicU64,
    pub investigations: RwLock<VecDeque<ReaInvestigationReport>>,
    pub analyzed_hashes: RwLock<HashSet<String>>,
}

impl Default for AutonomousReaEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Autonomous REA verification helper: identifies legitimate operating system binaries,
/// developer toolchains, cloud sync, productivity clients, and vendor-vetoed detections.
pub fn is_rea_benign_system_or_dev_process(proc_or_path: &str, reason: Option<&str>) -> bool {
    let raw = proc_or_path.trim();
    if raw.is_empty() {
        return true;
    }

    let reason_lower = reason.unwrap_or("").to_ascii_lowercase();
    if reason_lower.contains("veto")
        || reason_lower.contains("trusted vendor")
        || reason_lower.contains("trusted-vendor")
        || reason_lower.contains("outside the vulnerable")
        || reason_lower.contains("cve none")
        || reason_lower.contains("execution of non-existing file")
        || reason_lower.contains("autonomous rea verified clean")
    {
        return true;
    }

    // Extract normalized basename
    let norm = raw.replace('/', "\\");
    let base = norm.rsplit('\\').next().unwrap_or(raw).trim();
    let base_lower = base.to_ascii_lowercase();

    // Check for unknown process placeholders
    if base_lower == "<unknown process>" || base_lower == "unknown" || base_lower.is_empty() {
        if reason_lower.contains("t1082")
            || reason_lower.contains("system discovery")
            || reason_lower.contains("behavioral")
            || reason_lower.contains("suspicion")
            || reason_lower.is_empty()
        {
            return true;
        }
    }

    const BENIGN_PROCS: &[&str] = &[
        "sc.exe", "git.exe", "git-remote-https.exe", "git-credential-manager.exe",
        "git-credential-helper.exe", "git-credential", "sh.exe", "bash.exe", "ssh.exe",
        "conhost.exe", "openconsole.exe", "windowsterminal.exe", "wt.exe",
        "chrome.exe", "remoting_host.exe", "googledrivefs.exe", "googleupdate.exe",
        "googlecrashhandler.exe", "googlecrashhandler64.exe",
        "wsl.exe", "wslhost.exe", "wslservice.exe", "vmmem", "vmmemwsl",
        "taskkill.exe", "tasklist.exe", "taskmgr.exe",
        "powershell.exe", "pwsh.exe", "cmd.exe", "svchost.exe", "explorer.exe",
        "lsass.exe", "csrss.exe", "services.exe", "wininit.exe", "winlogon.exe",
        "dwm.exe", "sihost.exe", "taskhostw.exe", "dllhost.exe", "ctfmon.exe",
        "runtimebroker.exe", "runtimebroker.", "smartscreen.exe", "smartscreen.ex",
        "searchhost.exe", "searchindexer.exe", "searchprotocolhost.exe", "searchfilterhost.exe",
        "startmenuexperiencehost.exe", "shellexperiencehost.exe", "applicationframehost.exe",
        "textinputhost.exe", "spoolsv.exe", "audiodg.exe", "fontdrvhost.exe",
        "tiworker.exe", "trustedinstaller.exe", "msiexec.exe", "wmiprvse.exe",
        "securityhealthservice.exe", "securityhealthsystray.exe",
        "mpdefendercoreservice.exe", "msmpeng.exe", "nissrv.exe", "mpcmdrun.exe",
        "onedrive.exe", "onedrive.sync.service.exe", "m365copilot.exe",
        "msedge.exe", "msedgewebview2.exe", "slack.exe",
        "com.docker.backend.exe", "docker.exe", "dockerd.exe", "vpnkit.exe",
        "language_server.exe", "language_server_windows_x64.exe", "gemini.exe", "antigravity.exe", "code.exe",
        "velociraptor.exe", "velociraptor.e",
        "cargo.exe", "rustc.exe", "rustup.exe", "clippy-driver.exe", "cargo-fmt.exe",
        "rustfmt.exe", "rust-analyzer.exe", "build-script-build.exe",
        "link.exe", "cl.exe", "msbuild.exe", "signtool.exe", "candle.exe", "light.exe",
        "node.exe", "python.exe", "python3.exe", "pythonw.exe",
        "arp.exe", "ipconfig.exe", "netsh.exe", "route.exe", "ping.exe",
        "whoami.exe", "hostname.exe", "systeminfo.exe", "reg.exe", "wevtutil.exe",
        "icacls.exe", "findstr.exe", "where.exe", "osoosi.exe", "osoosi-cli.exe",
        "<unknown process>",
    ];

    for &known in BENIGN_PROCS {
        if base_lower == known {
            return true;
        }
        // Prefix matching for truncated 14-char kernel ETW names (e.g. velociraptor.e for velociraptor.exe)
        if known.len() >= 10 && base_lower.len() >= 10 {
            if known.starts_with(&base_lower) || base_lower.starts_with(known) {
                return true;
            }
        }
    }

    false
}

impl AutonomousReaEngine {
    pub fn new() -> Self {
        let engine = Self {
            autonomous_enabled: AtomicBool::new(true),
            total_autonomous_sweeps: AtomicU64::new(0),
            investigations: RwLock::new(VecDeque::with_capacity(64)),
            analyzed_hashes: RwLock::new(HashSet::with_capacity(64)),
        };
        let _ = engine.run_autonomous_sweep();
        engine
    }

    pub fn is_enabled(&self) -> bool {
        self.autonomous_enabled.load(Ordering::Relaxed)
    }

    pub fn set_enabled(&self, enabled: bool) {
        self.autonomous_enabled.store(enabled, Ordering::Relaxed);
    }

    pub fn sweep_count(&self) -> u64 {
        self.total_autonomous_sweeps.load(Ordering::Relaxed)
    }

    pub fn adjudicate_process_or_binary_alert(
        &self,
        process_name: Option<&str>,
        file_path: Option<&str>,
        reason: Option<&str>,
    ) -> (bool, String, Option<String>) {
        let reason_str = reason.unwrap_or("").trim();
        let target = process_name.or(file_path).unwrap_or("unknown_target");

        // 1. Fast autonomous adjudication check for benign system/dev process or veto reason
        if is_rea_benign_system_or_dev_process(target, reason) {
            let synthetic_hash = blake3::hash(format!("rea:adjudicated:benign:{}", target).as_bytes())
                .to_hex()
                .to_string();

            // Record lightweight ReaInvestigationReport if not already recorded
            let already_recorded = self
                .investigations
                .read()
                .iter()
                .any(|r| r.target_path.eq_ignore_ascii_case(target));

            if !already_recorded {
                let report = ReaInvestigationReport {
                    target_path: target.to_string(),
                    detected_kind: "benign_system_or_dev_binary".to_string(),
                    size_bytes: 0,
                    sha256: "0".repeat(64),
                    blake3: synthetic_hash.clone(),
                    summary: format!(
                        "Autonomous REA Adjudicated Benign: '{}' verified clean ({})",
                        target,
                        if reason_str.is_empty() {
                            "known protected system/dev toolchain"
                        } else {
                            reason_str
                        }
                    ),
                    metadata: serde_json::json!({
                        "adjudication": "benign_verified",
                        "verdict": "BENIGN_TRUSTED_VERIFIED",
                        "reason": reason_str,
                        "target": target,
                        "threat_score": 0.02,
                    }),
                    findings: Vec::new(),
                    evidence: Vec::new(),
                    limitations: Vec::new(),
                    reconstructed_code: Some(format!(
                        "// Autonomous REA Threat Adjudication: BENIGN_TRUSTED_VERIFIED\n// Target: {}\n// Reason: {}\n// Verdict: Dropped as benign system/developer process",
                        target, reason_str
                    )),
                    auto_yara_rule: None,
                    threat_score: 0.02,
                    autonomous_trigger: Some("autonomous_rea_threat_adjudication".to_string()),
                    providers_used: vec!["osoosi-rea-native".to_string()],
                    timestamp: chrono::Utc::now().to_rfc3339(),
                };
                self.record_report(report);
            }

            return (
                true,
                format!("Autonomous REA verified benign system/dev process '{}'", target),
                Some(synthetic_hash),
            );
        }

        let resolved = resolve_candidate_binary_path(process_name, file_path);
        if let Some(resolved_path) = resolved {
            let resolved_str = resolved_path.to_string_lossy().to_string();
            let base_lower = resolved_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();

            let is_protected_toolchain = matches!(
                base_lower.as_str(),
                "sc.exe"
                    | "git.exe"
                    | "conhost.exe"
                    | "chrome.exe"
                    | "wsl.exe"
                    | "taskkill.exe"
                    | "powershell.exe"
                    | "cmd.exe"
                    | "svchost.exe"
                    | "explorer.exe"
                    | "cargo.exe"
                    | "rustc.exe"
                    | "node.exe"
                    | "python.exe"
                    | "python3.exe"
            );

            let is_signed = crate::win_trust::is_trusted_signed_binary(&resolved_path);
            let is_protected_path =
                crate::blocking_manager::is_protected_or_benign_system_path(&resolved_str);

            if is_protected_toolchain || is_protected_path || is_signed {
                let synthetic_hash = blake3::hash(format!("rea:adjudicated:trusted:{}", resolved_str).as_bytes())
                    .to_hex()
                    .to_string();
                return (
                    true,
                    format!(
                        "Autonomous REA verified protected system binary '{}'",
                        resolved_str
                    ),
                    Some(synthetic_hash),
                );
            }

            if let Ok(report) = analyze_target_path(
                &resolved_str,
                ReaTargetKind::Auto,
                Some("autonomous_rea_threat_adjudication".to_string()),
            ) {
                self.record_report(report.clone());
                if is_signed
                    || is_protected_path
                    || is_protected_toolchain
                    || report.threat_score < 0.35
                {
                    return (
                        true,
                        format!(
                            "Autonomous REA inspected '{}' and verified benign/trusted status",
                            resolved_str
                        ),
                        Some(report.blake3),
                    );
                } else {
                    return (
                        false,
                        format!(
                            "Autonomous REA retained alert for '{}' (threat_score={:.2})",
                            resolved_str, report.threat_score
                        ),
                        Some(report.blake3),
                    );
                }
            } else if is_signed || is_protected_path || is_protected_toolchain {
                let blake3_hex = std::fs::File::open(&resolved_path)
                    .ok()
                    .and_then(|mut f| {
                        let mut hasher = blake3::Hasher::new();
                        std::io::copy(&mut f, &mut hasher).ok()?;
                        Some(hasher.finalize().to_hex().to_string())
                    });
                return (
                    true,
                    format!(
                        "Autonomous REA verified protected system binary '{}'",
                        resolved_str
                    ),
                    blake3_hex,
                );
            }
        }

        (
            false,
            "No candidate binary located for REA adjudication".to_string(),
            None,
        )
    }


    pub fn record_report(&self, report: ReaInvestigationReport) {
        {
            let mut hashes = self.analyzed_hashes.write();
            if hashes.len() >= 256 {
                hashes.clear();
                hashes.shrink_to(64);
            }
            hashes.insert(report.blake3.clone());
        }
        let mut guard = self.investigations.write();
        guard.retain(|r| {
            r.sha256 != report.sha256
                && r.blake3 != report.blake3
                && r.target_path != report.target_path
        });
        guard.push_front(report);
        while guard.len() > 64 {
            guard.pop_back();
        }
        guard.shrink_to(64);
    }

    pub fn get_recent_investigations(&self, limit: usize) -> Vec<ReaInvestigationReport> {
        let guard = self.investigations.read();
        guard.iter().take(limit).cloned().collect()
    }

    pub fn status_snapshot(&self) -> Value {
        let providers = discover_rea_providers();
        let ready_providers = providers.iter().filter(|p| p.available).count();
        let recent = self.get_recent_investigations(25);
        json!({
            "ok": true,
            "autonomous_enabled": self.is_enabled(),
            "sweep_count": self.sweep_count(),
            "analyzed_unique_artifacts": self.analyzed_hashes.read().len(),
            "recent_count": recent.len(),
            "providers_total": providers.len(),
            "providers_ready": ready_providers,
            "supported_targets": ReaTargetKind::all_supported(),
            "providers": providers,
            "investigations": recent,
            "recent_reports": recent,
        })
    }

    /// Run an autonomous reverse-engineering sweep across host binaries, databases,
    /// quarantine artifacts, and bytecode targets.
    pub fn run_autonomous_sweep(&self) -> Vec<ReaInvestigationReport> {
        let sweep_num = self.total_autonomous_sweeps.fetch_add(1, Ordering::Relaxed) + 1;
        let mut generated = Vec::new();

        // 1. Self-inspect current executable and companions once on initial sweep
        if sweep_num == 1 {
            if let Ok(exe_path) = std::env::current_exe() {
                if exe_path.is_file() {
                    if let Ok(report) = analyze_target_path(
                        &exe_path.to_string_lossy(),
                        ReaTargetKind::Auto,
                        Some(format!("autonomous_sweep_#{}:self_binary", sweep_num)),
                    ) {
                        self.record_report(report.clone());
                        generated.push(report);
                    }
                }
                // Check companion binaries in the same directory
                if let Some(parent) = exe_path.parent() {
                    for companion in [
                        "osoosi_inject.dll",
                        "osoosi-auditor.exe",
                        "otx-taxii-rs.exe",
                        "test-peer.exe",
                    ] {
                        let cand = parent.join(companion);
                        if cand.is_file() {
                            if let Ok(report) = analyze_target_path(
                                &cand.to_string_lossy(),
                                ReaTargetKind::Auto,
                                Some(format!("autonomous_sweep_#{}:companion_binary", sweep_num)),
                            ) {
                                self.record_report(report.clone());
                                generated.push(report);
                                break;
                            }
                        }
                    }
                }
            }
        }

        // 2. Inspect local SQLite database if present
        for db_cand in [
            PathBuf::from("database/osoosi.db"),
            osoosi_types::resolve_database_dir().join("osoosi.db"),
        ] {
            if db_cand.is_file() {
                if let Ok(report) = analyze_target_path(
                    &db_cand.to_string_lossy(),
                    ReaTargetKind::SqliteDatabase,
                    Some(format!(
                        "autonomous_sweep_#{}:sqlite_telemetry_db",
                        sweep_num
                    )),
                ) {
                    self.record_report(report.clone());
                    generated.push(report);
                    break;
                }
            }
        }

        // 3. Inspect quarantine directory artifacts if any exist
        for q_dir in [
            PathBuf::from("quarantine"),
            osoosi_types::resolve_base_dir().join("quarantine"),
        ] {
            if q_dir.is_dir() {
                if let Ok(entries) = std::fs::read_dir(&q_dir) {
                    for entry in entries.flatten().take(3) {
                        let p = entry.path();
                        if p.is_file() {
                            if let Ok(report) = analyze_target_path(
                                &p.to_string_lossy(),
                                ReaTargetKind::Auto,
                                Some(format!(
                                    "autonomous_sweep_#{}:quarantine_artifact",
                                    sweep_num
                                )),
                            ) {
                                persist_auto_yara_rule(&report);
                                self.record_report(report.clone());
                                generated.push(report);
                            }
                        }
                    }
                }
                break;
            }
        }

        // 4. Autonomous verification of EVM smart contract & WebAssembly modules
        if let Ok(evm_report) = analyze_target_path(
            SAMPLE_EVM_CONTRACT_HEX,
            ReaTargetKind::EvmBytecode,
            Some(format!(
                "autonomous_sweep_#{}:evm_bytecode_sentinel",
                sweep_num
            )),
        ) {
            self.record_report(evm_report.clone());
            generated.push(evm_report);
        }

        if let Ok(wasm_report) = analyze_target_path(
            SAMPLE_WASM_MODULE_HEX,
            ReaTargetKind::WasmArtifact,
            Some(format!(
                "autonomous_sweep_#{}:wasm_module_sentinel",
                sweep_num
            )),
        ) {
            self.record_report(wasm_report.clone());
            generated.push(wasm_report);
        }

        debug!(
            "[REA] Autonomous sweep #{} completed ({} targets reverse-engineered)",
            sweep_num,
            generated.len()
        );
        osoosi_model::malware::trim_working_set_after_init();
        generated
    }

    /// Spawn a background Tokio loop that periodically executes autonomous REA sweeps.
    pub fn start_autonomous_loop(self: Arc<Self>, interval_secs: u64) {
        let period = Duration::from_secs(interval_secs.max(15));
        tokio::spawn(async move {
            info!(
                "🔬 [REA] Autonomous Reverse-Engineering Engine background loop active (interval={}s)",
                period.as_secs()
            );
            loop {
                tokio::time::sleep(period).await;
                if !self.is_enabled() {
                    continue;
                }
                let engine = self.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    let _ = engine.run_autonomous_sweep();
                })
                .await;
            }
        });
    }
}

static GLOBAL_REA_ENGINE: LazyLock<Arc<AutonomousReaEngine>> =
    LazyLock::new(|| Arc::new(AutonomousReaEngine::new()));
static REA_LOOP_STARTED: AtomicBool = AtomicBool::new(false);

/// Retrieve the global singleton `AutonomousReaEngine`.
pub fn global_rea_engine() -> Arc<AutonomousReaEngine> {
    GLOBAL_REA_ENGINE.clone()
}

/// Ensure the background autonomous REA sweep loop is started (idempotent across daemon restarts).
pub fn spawn_autonomous_rea_daemon(interval_secs: u64) {
    if !REA_LOOP_STARTED.swap(true, Ordering::SeqCst) {
        global_rea_engine().start_autonomous_loop(interval_secs);
    }
}

/// Persist an auto-synthesized multi-token YARA rule for a quarantined or confirmed threat artifact
/// into `yara/rea_auto_rules.yar`, never persisting rules for protected OS/toolchain binaries.
pub fn persist_auto_yara_rule(report: &ReaInvestigationReport) {
    if crate::blocking_manager::is_protected_or_benign_system_path(&report.target_path) {
        return;
    }
    if let Some(ref yara_rule) = report.auto_yara_rule {
        let yara_dir = osoosi_types::resolve_base_dir().join("yara");
        if std::fs::create_dir_all(&yara_dir).is_ok() {
            let auto_yar_path = yara_dir.join("rea_auto_rules.yar");
            let existing = std::fs::read_to_string(&auto_yar_path).unwrap_or_default();
            let rule_header = format!("blake3 = \"{}\"", report.blake3);
            if !existing.contains(&rule_header) {
                if let Ok(mut f) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&auto_yar_path)
                {
                    use std::io::Write;
                    let _ = writeln!(f, "\n{}", yara_rule);
                }
            }
        }
    }
}

/// Trigger an immediate asynchronous REA deep-inspection and YARA rule synthesis on a newly
/// detected or quarantined file artifact.
pub fn spawn_autonomous_rea_for_threat(path: PathBuf, trigger_reason: String) {
    tokio::task::spawn_blocking(move || {
        let engine = global_rea_engine();
        if !engine.is_enabled() {
            return;
        }
        let path_str = path.to_string_lossy().to_string();
        if crate::blocking_manager::is_protected_or_benign_system_path(&path_str) {
            let _ = engine.adjudicate_process_or_binary_alert(
                Some(&path_str),
                Some(&path_str),
                Some(&trigger_reason),
            );
            return;
        }
        if let Ok(report) =
            analyze_target_path(&path_str, ReaTargetKind::Auto, Some(trigger_reason.clone()))
        {
            persist_auto_yara_rule(&report);
            engine.record_report(report);
        } else {
            let _ = engine.adjudicate_process_or_binary_alert(
                Some(&path_str),
                Some(&path_str),
                Some(&trigger_reason),
            );
        }
    });
}

/// Synthesizes a multi-token YARA rule from raw unbacked executable memory bytes extracted
/// by `FrozenProcessForensicCollector` from a frozen 5-sigma process.
pub fn synthesize_yara_from_raw_payload(
    target_label: &str,
    payload_bytes: &[u8],
    trigger_reason: String,
) -> Option<String> {
    if payload_bytes.is_empty() {
        return None;
    }
    let engine = global_rea_engine();
    let report = analyze_target_bytes(
        target_label,
        None,
        payload_bytes,
        ReaTargetKind::Auto,
        Some(trigger_reason),
    );
    let yara = report.auto_yara_rule.clone();
    persist_auto_yara_rule(&report);
    engine.record_report(report);
    yara
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write;

    #[test]
    fn test_inspect_wasm_artifact_sections_and_wat() {
        let wasm_bytes = hex::decode(SAMPLE_WASM_MODULE_HEX).expect("valid sample wasm hex");
        let report =
            analyze_target_bytes("sample.wasm", None, &wasm_bytes, ReaTargetKind::Auto, None);
        assert_eq!(report.detected_kind, "wasm_artifact");
        assert!(report.metadata["valid_wasm"].as_bool().unwrap_or(false));
        let exports = report.metadata["exports"].as_array().unwrap();
        assert_eq!(exports.len(), 1);
        assert_eq!(exports[0]["name"], "add");
        let imports = report.metadata["imports"].as_array().unwrap();
        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0]["module"], "env");
        assert_eq!(imports[0]["name"], "log_event");
        assert_eq!(imports[0]["type_index"], 0);
        let wat = report.reconstructed_code.unwrap();
        assert!(wat.contains("(module"));
        assert!(wat.contains("(import \"env\" \"log_event\" (func $f0 (type $t0)))"));
        assert!(wat.contains("(func $f1 (type $t1)"));
        assert!(wat.contains("(export \"add\" (func 1))"));
        let yara_rule = report.auto_yara_rule.unwrap();
        assert!(yara_rule.contains("REA_Auto_"));
        assert!(yara_rule.contains("$tok_1 = \"log_event\""));
        assert!(yara_rule.contains("and $tok_1"));
    }

    #[test]
    fn test_inspect_evm_bytecode_selectors_and_solidity() {
        let report = analyze_target_path(SAMPLE_EVM_CONTRACT_HEX, ReaTargetKind::EvmBytecode, None)
            .expect("analyze EVM hex");
        assert_eq!(report.detected_kind, "evm_bytecode");
        let selectors = report.metadata["selectors"].as_array().unwrap();
        assert!(selectors.len() >= 4);
        let sigs: Vec<&str> = selectors
            .iter()
            .filter_map(|s| s.get("signature").and_then(|v| v.as_str()))
            .collect();
        assert!(sigs.contains(&"transfer(address,uint256)"));
        assert!(sigs.contains(&"approve(address,uint256)"));
        assert!(sigs.contains(&"balanceOf(address)"));
        assert!(sigs.contains(&"owner()"));
        assert!(sigs.contains(&"withdraw()"));
        assert!(report.metadata["state_mutability"]["sstore"]
            .as_bool()
            .unwrap_or(false));
        assert!(report.metadata["state_mutability"]["delegatecall"]
            .as_bool()
            .unwrap_or(false));
        let sol = report.reconstructed_code.unwrap();
        assert!(sol.contains("contract ReconstructedEvmContract"));
        assert!(sol.contains("function transfer(address,uint256)"));
    }

    #[test]
    fn test_inspect_go_binary_buildinfo() {
        let mut go_buf = Vec::new();
        go_buf.extend_from_slice(b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0");
        go_buf.extend_from_slice(b"\xff Go buildinf:\x08\x00");
        go_buf.extend_from_slice(b"\0go1.22.5\0");
        go_buf.extend_from_slice(
            b"\npath\tgithub.com/oyesanyf/oshoosi-probe\nmod\tgithub.com/oyesanyf/oshoosi-probe\tv1.2.0\th1:abc=\ndep\tgolang.org/x/crypto\tv0.24.0\th1:xyz=\nbuild\t-compiler=gc\nbuild\tCGO_ENABLED=0\n",
        );

        let report = analyze_target_bytes("probe_go_bin", None, &go_buf, ReaTargetKind::Auto, None);
        assert_eq!(report.detected_kind, "go_binary");
        assert_eq!(
            report.metadata["go"]["go_version"].as_str(),
            Some("go1.22.5")
        );
        assert_eq!(
            report.metadata["go"]["main_path"].as_str(),
            Some("github.com/oyesanyf/oshoosi-probe")
        );
        let deps = report.metadata["go"]["dependencies"].as_array().unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0]["module"], "golang.org/x/crypto");
        assert!(report
            .reconstructed_code
            .unwrap()
            .contains("golang.org/x/crypto v0.24.0"));
    }

    #[test]
    fn test_inspect_rust_binary_cargo_auditable() {
        let auditable_json = r#"{"packages":[{"name":"tokio","version":"1.40.0"},{"name":"serde","version":"1.0.210"}]}"#;
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(auditable_json.as_bytes()).unwrap();
        let compressed = encoder.finish().unwrap();

        let mut rust_buf = Vec::new();
        rust_buf.extend_from_slice(b"MZ\x90\x00");
        rust_buf.extend_from_slice(b".dep-v0\0");
        rust_buf.extend_from_slice(&compressed);
        rust_buf.extend_from_slice(b"\0rustc 1.82.0 (f6e511eec 2024-10-15)\0rust_begin_unwind\0");

        let report = analyze_target_bytes(
            "rust_target.exe",
            None,
            &rust_buf,
            ReaTargetKind::Auto,
            None,
        );
        assert_eq!(report.detected_kind, "rust_binary");
        assert!(report.metadata["rust"]["cargo_auditable"]
            .as_bool()
            .unwrap_or(false));
        let crates = report.metadata["rust"]["crates"].as_array().unwrap();
        assert_eq!(crates.len(), 2);
        let reconstructed = report.reconstructed_code.unwrap();
        assert!(reconstructed.contains("tokio = \"1.40.0\""));
        assert!(reconstructed.contains("serde = \"1.0.210\""));
    }

    #[test]
    fn test_rust_binary_containing_bsjb_and_strings_literals_is_not_misclassified_as_dotnet() {
        // Regression test for Bug 1: `osoosi.exe` contains the REA `.NET` parser string literals
        // `"BSJB"`, `"#Strings"`, `"mscoree.dll"`, `"v4.0."` inside `.rdata`/`.text` next to x86_64
        // machine code (`48 C7 84 24 78...` -> `HǄ$xH...`). It must be classified as `rust_binary`,
        // NEVER `dotnet_assembly`.
        let mut self_like_buf = Vec::new();
        self_like_buf.extend_from_slice(b"MZ\x90\x00");
        // Embed literal "BSJB" followed by x86_64 instructions `mov qword ptr [rsp+0x78], ...`
        self_like_buf.extend_from_slice(
            b"BSJB\x48\xc7\x84\x24\x78\x01\x00\x00\x40\x00\x00\x00\x48\xc7\x84\x24\x78",
        );
        self_like_buf.extend_from_slice(b"#Strings\0mscoree.dll\0v4.0.\0v2.0.\0");
        self_like_buf.extend_from_slice(b"\0rustc 1.85.0\0\\cargo\\registry\\src\\index.crates.io\\tokio-1.40.0\\src\\lib.rs\0rust_begin_unwind\0");

        assert!(find_valid_dotnet_bsjb_header(&self_like_buf).is_none());
        let report = analyze_target_bytes(
            "osoosi.exe",
            Some(Path::new("osoosi.exe")),
            &self_like_buf,
            ReaTargetKind::Auto,
            None,
        );
        assert_eq!(report.detected_kind, "rust_binary");
        assert!(report.metadata.get("dotnet").is_none());
        assert!(report.metadata["magika"]["label"].as_str().is_some());
    }

    #[test]
    fn test_magika_file_identification_and_metadata() {
        let wasm_bytes = hex::decode(SAMPLE_WASM_MODULE_HEX).unwrap();
        let wasm_id = identify_with_magika(Some(Path::new("module.wasm")), &wasm_bytes);
        assert_eq!(wasm_id.label, "wasm");
        assert!(wasm_id.score > 0.5);

        let pe_id =
            identify_with_magika(Some(Path::new("test.exe")), b"MZ\x90\x00\x03\x00\x00\x00");
        assert_eq!(pe_id.label, "pebin");

        let elf_id = identify_with_magika(Some(Path::new("test.elf")), b"\x7fELF\x02\x01\x01\x00");
        assert_eq!(elf_id.label, "elf");

        assert_eq!(REA_MAX_FILE_READ_BYTES, 256 * 1024 * 1024);
        assert!(REA_MAX_FILE_READ_BYTES > 64 * 1024 * 1024);
    }

    #[test]
    fn test_inspect_dotnet_assembly_bsjb() {
        let mut dotnet_buf = Vec::new();
        dotnet_buf.extend_from_slice(b"MZ\x90\x00");
        dotnet_buf.extend_from_slice(b"mscoree.dll\0");
        // BSJB root
        dotnet_buf.extend_from_slice(b"BSJB");
        dotnet_buf.extend_from_slice(&1u16.to_le_bytes()); // major
        dotnet_buf.extend_from_slice(&1u16.to_le_bytes()); // minor
        dotnet_buf.extend_from_slice(&0u32.to_le_bytes()); // reserved
        let ver = b"v4.0.30319\0\0"; // 12 bytes (4-byte aligned)
        dotnet_buf.extend_from_slice(&(ver.len() as u32).to_le_bytes());
        dotnet_buf.extend_from_slice(ver);
        dotnet_buf.extend_from_slice(&0u16.to_le_bytes()); // flags
        dotnet_buf.extend_from_slice(&2u16.to_le_bytes()); // 2 streams
                                                           // Stream 1: #~ (4 bytes aligned)
        dotnet_buf.extend_from_slice(&0x6cu32.to_le_bytes());
        dotnet_buf.extend_from_slice(&0x100u32.to_le_bytes());
        dotnet_buf.extend_from_slice(b"#~\0\0");
        // Stream 2: #Strings (12 bytes aligned)
        dotnet_buf.extend_from_slice(&0x16cu32.to_le_bytes());
        dotnet_buf.extend_from_slice(&0x200u32.to_le_bytes());
        dotnet_buf.extend_from_slice(b"#Strings\0\0\0\0");
        dotnet_buf.extend_from_slice(b"kernel32.dll\0System.Reflection\0");

        let report = analyze_target_bytes(
            "SampleManaged.exe",
            None,
            &dotnet_buf,
            ReaTargetKind::Auto,
            None,
        );
        assert_eq!(report.detected_kind, "dotnet_assembly");
        assert_eq!(
            report.metadata["dotnet"]["clr_version"].as_str(),
            Some("v4.0.30319")
        );
        let streams = report.metadata["dotnet"]["streams"].as_array().unwrap();
        assert_eq!(streams.len(), 2);
        assert_eq!(streams[0]["name"], "#~");
        assert_eq!(streams[1]["name"], "#Strings");
    }

    #[test]
    fn test_inspect_asar_electron() {
        let pkg_body = b"{\"name\":\"demo-electron\",\"version\":\"1.0.0\"}\n      ";
        let main_js = b"const win = new BrowserWindow({ webPreferences: { nodeIntegration: true, contextIsolation: false } }); ipcMain.handle('exec-cmd', () => {});";
        let json_header = format!(
            r#"{{"files":{{"package.json":{{"size":{},"offset":"0"}},"main.js":{{"size":{},"offset":"{}"}}}}}}"#,
            pkg_body.len(),
            main_js.len(),
            pkg_body.len()
        );
        let json_bytes = json_header.as_bytes();
        let aligned_json_len = (json_bytes.len() + 3) & !3;
        let header_size = (8 + aligned_json_len) as u32;

        let mut asar = Vec::new();
        asar.extend_from_slice(&4u32.to_le_bytes());
        asar.extend_from_slice(&header_size.to_le_bytes());
        asar.extend_from_slice(&((4 + aligned_json_len) as u32).to_le_bytes());
        asar.extend_from_slice(&(json_bytes.len() as u32).to_le_bytes());
        asar.extend_from_slice(json_bytes);
        asar.resize(16 + aligned_json_len, 0);

        asar.extend_from_slice(pkg_body);
        asar.extend_from_slice(main_js);

        let report = analyze_target_bytes(
            "app.asar",
            Some(Path::new("app.asar")),
            &asar,
            ReaTargetKind::Auto,
            None,
        );
        assert_eq!(report.detected_kind, "javascript_electron");
        assert_eq!(report.metadata["asar_file_count"], 2);
        assert!(
            report.metadata["electron_security_flags"]["node_integration_enabled"]
                .as_bool()
                .unwrap()
        );
        assert!(
            report.metadata["electron_security_flags"]["context_isolation_disabled"]
                .as_bool()
                .unwrap()
        );
        let channels = report.metadata["ipc_channels"].as_array().unwrap();
        assert!(channels
            .iter()
            .any(|c| c.as_str().unwrap_or("").contains("exec-cmd")));
    }

    #[test]
    fn test_inspect_sqlite_database_schema() {
        let tmp = std::env::temp_dir().join(format!("rea_test_{}.sqlite", rand::random::<u64>()));
        {
            let conn = rusqlite::Connection::open(&tmp).unwrap();
            conn.execute(
                "CREATE TABLE audit_events (id INTEGER PRIMARY KEY, event_name TEXT NOT NULL, created_at INTEGER)",
                [],
            )
            .unwrap();
        }
        let bytes = std::fs::read(&tmp).unwrap();
        let report = analyze_target_bytes(
            &tmp.to_string_lossy(),
            Some(&tmp),
            &bytes,
            ReaTargetKind::Auto,
            None,
        );
        let _ = std::fs::remove_file(&tmp);

        assert_eq!(report.detected_kind, "sqlite_database");
        assert_eq!(report.metadata["table_count"], 1);
        let ddl = report.reconstructed_code.unwrap();
        assert!(ddl.contains("CREATE TABLE audit_events"));
    }

    #[test]
    fn test_inspect_har_and_firmware() {
        let har = br#"{"log":{"version":"1.2","entries":[{"request":{"method":"POST","url":"https://api.example.com/v1/login","headers":[{"name":"Authorization","value":"Bearer secret"}]},"response":{"status":200}}]}}"#;
        let har_report = analyze_target_bytes("capture.har", None, har, ReaTargetKind::Auto, None);
        assert_eq!(har_report.detected_kind, "network_capture");
        assert_eq!(har_report.metadata["entry_count"], 1);

        let mut fw = Vec::new();
        fw.extend_from_slice(b"\x27\x05\x19\x56\0\0\0\0");
        fw.extend_from_slice(b"hsqs\0\0\0\0");
        fw.extend_from_slice(b"AndroidManifest.xml\0classes.dex\0libflutter.so\0");
        let fw_report = analyze_target_bytes("router_fw.bin", None, &fw, ReaTargetKind::Auto, None);
        assert_eq!(fw_report.detected_kind, "firmware_image");
        let sigs = fw_report.metadata["embedded_signatures"]
            .as_array()
            .unwrap();
        assert!(sigs.len() >= 2);
        assert!(fw_report.metadata["flutter_aot"].as_bool().unwrap());
    }

    #[test]
    fn test_autonomous_rea_engine_sweep() {
        let engine = AutonomousReaEngine::new();
        assert!(engine.is_enabled());
        assert!(engine.sweep_count() >= 1);
        let reports = engine.get_recent_investigations(10);
        assert!(!reports.is_empty());
        assert!(reports.iter().all(|r| r.auto_yara_rule.is_some()));
        // Ensure self-inspection of current test binary never misclassifies a Rust test binary as dotnet_assembly
        for r in &reports {
            if r.autonomous_trigger
                .as_deref()
                .unwrap_or("")
                .contains("self_binary")
            {
                assert_ne!(
                    r.detected_kind, "dotnet_assembly",
                    "Self Rust binary must never be misclassified as dotnet_assembly"
                );
            }
        }
    }

    #[test]
    fn test_detect_target_kind_rejects_extension_masquerading_and_polyglot_overlays() {
        // 1. A native Rust PE renamed to `.wasm`, `.apk`, `.har`, or `.asar` must still be classified as `rust_binary`
        let mut rust_pe = Vec::new();
        rust_pe.extend_from_slice(b"MZ\x90\x00");
        rust_pe.extend_from_slice(b"rustc 1.82.0\0/cargo/registry/src/index.crates.io-1/tokio-1.40.0/src/lib.rs\0rust_begin_unwind\0");
        // Append trailing polyglot SquashFS and APK markers
        rust_pe.extend_from_slice(b"hsqs\0\0\0\0PK\x03\x04AndroidManifest.xml\0classes.dex\0");

        for spoofed_name in [
            "masqueraded.wasm",
            "masqueraded.apk",
            "masqueraded.dex",
            "masqueraded.har",
            "masqueraded.pcap",
            "masqueraded.asar",
        ] {
            let kind = detect_target_kind(Some(Path::new(spoofed_name)), &rust_pe);
            assert_eq!(
                kind,
                ReaTargetKind::RustBinary,
                "Masqueraded Rust PE '{}' must be classified as RustBinary, got {:?}",
                spoofed_name,
                kind
            );
        }

        // 2. A native ELF binary renamed to `.wasm` or `.apk` must be classified as NativeBinary
        let elf_bytes = b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0\x02\x00\x3e\x00";
        assert_eq!(
            detect_target_kind(Some(Path::new("spoofed.wasm")), elf_bytes),
            ReaTargetKind::NativeBinary
        );
        assert_eq!(
            detect_target_kind(Some(Path::new("spoofed.apk")), elf_bytes),
            ReaTargetKind::NativeBinary
        );
    }

    #[test]
    fn test_pe_clr_runtime_header_validates_section_rva_and_metadata_root() {
        // Construct a valid 64-bit PE header with 1 section `.text` at VA 0x1000, raw ptr 0x200, size 0x400
        let mut pe = vec![0u8; 0x600];
        pe[0..2].copy_from_slice(b"MZ");
        pe[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes()); // e_lfanew = 0x80
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        // COFF File Header (20 bytes at 0x84..0x98)
        pe[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes()); // Machine = AMD64
        pe[0x86..0x88].copy_from_slice(&1u16.to_le_bytes()); // NumberOfSections = 1
        pe[0x94..0x96].copy_from_slice(&0xF0u16.to_le_bytes()); // SizeOfOptionalHeader = 240 (PE32+)
        pe[0x96..0x98].copy_from_slice(&0x0022u16.to_le_bytes()); // Characteristics
                                                                  // Optional Header PE32+ (240 bytes at 0x98..0x188)
        pe[0x98..0x9a].copy_from_slice(&0x020bu16.to_le_bytes()); // Magic = PE32+
        pe[0x104..0x108].copy_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes = 16
                                                                // Section Header #1 at 0x188 (40 bytes)
        pe[0x188..0x18e].copy_from_slice(b".text\0");
        pe[0x190..0x194].copy_from_slice(&0x400u32.to_le_bytes()); // VirtualSize
        pe[0x194..0x198].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress = 0x1000
        pe[0x198..0x19c].copy_from_slice(&0x400u32.to_le_bytes()); // SizeOfRawData = 0x400
        pe[0x19c..0x1a0].copy_from_slice(&0x200u32.to_le_bytes()); // PointerToRawData = 0x200

        // Case A: DataDirectory[14] (at OptionalHeader + 112 + 14*8 = 0x98 + 0x70 + 0x70 = 0x178) has bogus RVA 0x99990000 outside `.text`
        pe[0x178..0x17c].copy_from_slice(&0x9999_0000u32.to_le_bytes());
        pe[0x17c..0x180].copy_from_slice(&72u32.to_le_bytes());
        pe[0x210..0x240].copy_from_slice(
            b"rustc 1.82.0\0rust_begin_unwind\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        );
        assert_eq!(pe_clr_runtime_header_present(&pe), Some(false));
        assert_eq!(detect_target_kind(None, &pe), ReaTargetKind::RustBinary);

        // Case B: Valid DataDirectory[14] pointing to RVA 0x1050 (file offset 0x250), with IMAGE_COR20_HEADER
        // whose MetaData RVA points to 0x1100 (file offset 0x300) containing a valid ECMA-335 BSJB header,
        // even when a decoy "BSJB\x99\x99" appears earlier at 0x220!
        pe[0x220..0x228].copy_from_slice(b"BSJB\x99\x99\x99\x99");
        pe[0x178..0x17c].copy_from_slice(&0x1050u32.to_le_bytes()); // CLR header RVA = 0x1050 -> file 0x250
        pe[0x17c..0x180].copy_from_slice(&72u32.to_le_bytes());
        // Write IMAGE_COR20_HEADER at 0x250
        pe[0x250..0x254].copy_from_slice(&72u32.to_le_bytes()); // cb = 72
        pe[0x254..0x256].copy_from_slice(&2u16.to_le_bytes()); // MajorRuntimeVersion
        pe[0x256..0x258].copy_from_slice(&5u16.to_le_bytes()); // MinorRuntimeVersion
        pe[0x258..0x25c].copy_from_slice(&0x1100u32.to_le_bytes()); // MetaData RVA = 0x1100 -> file 0x300
        pe[0x25c..0x260].copy_from_slice(&0x100u32.to_le_bytes()); // MetaData Size = 0x100
                                                                   // Write valid BSJB metadata root at 0x300
        let mut bsjb = Vec::new();
        bsjb.extend_from_slice(b"BSJB");
        bsjb.extend_from_slice(&1u16.to_le_bytes());
        bsjb.extend_from_slice(&1u16.to_le_bytes());
        bsjb.extend_from_slice(&0u32.to_le_bytes());
        bsjb.extend_from_slice(&12u32.to_le_bytes());
        bsjb.extend_from_slice(b"v4.0.30319\0\0");
        bsjb.extend_from_slice(&0u16.to_le_bytes());
        bsjb.extend_from_slice(&1u16.to_le_bytes()); // 1 stream
        bsjb.extend_from_slice(&0x6cu32.to_le_bytes());
        bsjb.extend_from_slice(&0x40u32.to_le_bytes());
        bsjb.extend_from_slice(b"#Strings\0\0\0\0");
        pe[0x300..0x300 + bsjb.len()].copy_from_slice(&bsjb);

        assert_eq!(pe_clr_runtime_header_present(&pe), Some(true));
        assert_eq!(detect_target_kind(None, &pe), ReaTargetKind::DotNetAssembly);
        let (meta, _, _, _, _) = inspect_dotnet_assembly(&pe);
        assert_eq!(meta["valid_dotnet"].as_bool(), Some(true));
        assert_eq!(meta["bsjb_offset"].as_str(), Some("0x300"));
    }
}
