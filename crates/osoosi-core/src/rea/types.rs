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

/// Maximum subprocess stdout/stderr retention limit (4 MiB, matching morluto/rea safety cap).
pub const REA_MAX_SUBPROCESS_OUTPUT_BYTES: usize = 4 * 1024 * 1024;

/// Maximum local file read limit for REA binary & archive inspection (256 MiB, supporting large Rust binaries like osoosi.exe without 64 MiB truncation).
pub const REA_MAX_FILE_READ_BYTES: u64 = 256 * 1024 * 1024;

/// Hard resource bounds for REA binary, bytecode, database, and archive parsers (Protection Layer 3).
pub const MAX_REA_FILE_BYTES: u64 = REA_MAX_FILE_READ_BYTES;
pub const MAX_PE_SECTIONS: usize = 96;
pub const MAX_EXTRACTED_STRINGS: usize = 2048;
pub const MAX_SINGLE_STRING_BYTES: usize = 4096;
pub const MAX_DISASM_INSTRUCTIONS: usize = 16_384;
pub const MAX_SQLITE_PAGES: u32 = 262_144;
pub const MAX_ARCHIVE_DECOMPRESSION_RATIO: usize = 32;
pub const MAX_DECOMPRESSED_BYTES: usize = 16 * 1024 * 1024;

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
    #[serde(default)]
    pub report_integrity_hmac_blake3: String,
    #[serde(default)]
    pub rea_security_posture: Value,
}

/// Errors produced during REA dynamic sandboxed detonation or binary probing.
#[derive(Debug, thiserror::Error)]
pub enum ReaError {
    #[error("Target binary does not exist on disk: {0}")]
    NotFound(String),
    #[error("REA sandbox path violation: {0}")]
    SandboxPathViolation(String),
    #[error("Immune benign process: {0}")]
    ImmuneBenign(String),
    #[error("Canary cage execution error: {0}")]
    CageError(String),
    #[error("IO error during detonation probe: {0}")]
    Io(#[from] std::io::Error),
    #[error("General REA error: {0}")]
    General(String),
}

/// Dynamic sandbox detonation report emitted by `run_caged_rea_detonation_probe`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReaDetonationReport {
    pub binary_path: String,
    pub session_id: String,
    pub exit_code: Option<i32>,
    pub duration_ms: u64,
    pub canary_triggered: bool,
    pub threat_score: f32,
    pub verdict: String,
    pub mitre_attack_ids: Vec<String>,
    pub findings: Vec<Value>,
    pub evidence: Vec<ReaEvidence>,
    pub alert: Option<osoosi_runtime::canary_cage::CanaryAlert>,
    pub metadata: Value,
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

/// Derive a deterministic 32-byte key for tamper-evident REA report sealing (Protection Layer 4).
fn rea_report_seal_key() -> [u8; 32] {
    blake3::derive_key(
        "OpenOshoosi::REA::ReportIntegritySeal::v2",
        b"OSA-REA-HMAC-BLAKE3-TAMPER-EVIDENT-SEAL-2026",
    )
}

/// Compute a keyed BLAKE3 HMAC integrity seal over a `ReaInvestigationReport`.
pub fn compute_rea_report_seal(report: &ReaInvestigationReport) -> String {
    let key = rea_report_seal_key();
    let mut hasher = blake3::Hasher::new_keyed(&key);
    hasher.update(b"REA_REPORT_SEAL_V2|");
    hasher.update(report.target_path.as_bytes());
    hasher.update(b"|");
    hasher.update(report.detected_kind.as_bytes());
    hasher.update(b"|");
    hasher.update(&report.size_bytes.to_le_bytes());
    hasher.update(b"|");
    hasher.update(report.sha256.as_bytes());
    hasher.update(b"|");
    hasher.update(report.blake3.as_bytes());
    hasher.update(b"|");
    hasher.update(format!("{:.4}", report.threat_score).as_bytes());
    hasher.update(b"|");
    hasher.update(&(report.findings.len() as u64).to_le_bytes());
    hasher.update(b"|");
    hasher.update(&(report.evidence.len() as u64).to_le_bytes());
    format!("hmac-blake3:{}", hasher.finalize().to_hex())
}

/// Constant-time verification of a `ReaInvestigationReport` tamper-evident seal.
pub fn verify_rea_report_seal(report: &ReaInvestigationReport) -> bool {
    let expected = compute_rea_report_seal(report);
    let actual = report.report_integrity_hmac_blake3.as_bytes();
    let exp_bytes = expected.as_bytes();
    if actual.len() != exp_bytes.len() || actual.is_empty() {
        return false;
    }
    let mut diff = 0u8;
    for (&a, &b) in actual.iter().zip(exp_bytes.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

/// Verdict returned by `AutonomousReaEngine::inspect_and_vet_mesh_frame` when inspecting
/// outbound or inbound P2P / GossipSub / Nostr mesh threat frames.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReaMeshInspectionVerdict {
    pub allowed: bool,
    pub vetoed: bool,
    pub veto_reason: Option<String>,
    pub fraud_proof: Option<osoosi_wire::ByzantineKillSwitchFraudProof>,
    pub prompt_injection_detected: bool,
    pub masquerade_detected: bool,
    pub rea_seal_blake3: String,
    pub threat_score_adjustment: f64,
    pub summary: String,
}

/// Result of REA + OpenJEV deep forensic inspection of an HTTP Archive (`.har`) entry or archive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReaHarAnalysisResult {
    pub url: String,
    pub method: String,
    pub status: u16,
    pub artifact_class: String,
    pub rea_voter_decision: String,
    pub rea_voter_reason: String,
    pub openjev_voter_decision: String,
    pub openjev_voter_reason: String,
    pub prompt_injection_detected: bool,
    pub embedded_binary_detected: bool,
    pub smuggling_or_ssrf_detected: bool,
    pub threat_score: f32,
    pub findings: Vec<Value>,
    pub rea_seal_blake3: String,
}

/// Result of routing a candidate detector alert through `AutonomousReaEngine::evaluate_detector_candidate`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReaDetectorEvaluation {
    pub detector_name: String,
    pub target: String,
    pub benign_veto: bool,
    pub masquerade_escalated: bool,
    pub prompt_injection_escalated: bool,
    pub adjusted_score: f64,
    pub rea_threat_score: f32,
    pub verdict: String,
    pub explanation: String,
    pub rea_seal_blake3: String,
    pub auto_yara_synthesized: bool,
}

/// Structured consensus vote cast by `ReaVoter` / `AutonomousReaEngine::cast_consensus_vote`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReaConsensusVote {
    pub voter_name: String,
    pub target: String,
    pub detector_source: String,
    pub decision: String,
    pub weight: f64,
    pub confidence: f64,
    pub benign_veto: bool,
    pub masquerade_escalated: bool,
    pub prompt_injection_detected: bool,
    pub reason: String,
    pub rea_seal_blake3: String,
    pub timestamp: String,
}

pub type ReaVoteResult = ReaConsensusVote;
