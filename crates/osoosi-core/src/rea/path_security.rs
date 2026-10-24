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

// ============================================================================
// Protection Layer 2: Path Traversal, UNC/SMB NTLMv2 Leak, Device Namespace, & ADS Guard
// ============================================================================

/// Validate a file/directory path before REA opens or probes it on disk.
///
/// Strictly rejects:
/// - Null bytes or ASCII control characters (`< 0x20`)
/// - Percent-encoded traversal (`%2e`, `%2f`, `%5c`, `%00`)
/// - Windows Device namespaces (`\\.\`, `\\?\`, `GLOBALROOT`, `\Device\`, `\??\`)
/// - UNC / SMB network shares (`\\server\share`, `//server/share`, `smb://`, `file:////`) to prevent NTLMv2 hash relay
/// - NTFS Alternate Data Streams (`:` anywhere except index 1 of `[A-Za-z]:`)
/// - Parent directory traversal (`..`)
/// - Reserved DOS/Windows device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1`..`COM9`, `LPT1`..`LPT9`)
/// - Symlink escapes (`is_symlink()`)
pub fn validate_rea_target_path(raw_path: &str) -> Result<PathBuf> {
    let trimmed = raw_path.trim().trim_matches('"');
    if trimmed.is_empty() {
        return Err(anyhow!(
            "REA_SANDBOX_PATH_VIOLATION: target path cannot be empty"
        ));
    }

    if trimmed.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(anyhow!(
            "REA_SANDBOX_PATH_VIOLATION: null byte or control character in path"
        ));
    }

    let lower = trimmed.to_ascii_lowercase();
    if lower.contains("%2e")
        || lower.contains("%2f")
        || lower.contains("%5c")
        || lower.contains("%00")
    {
        return Err(anyhow!(
            "REA_SANDBOX_PATH_VIOLATION: percent-encoded path traversal blocked"
        ));
    }

    if lower.starts_with(r"\\.\")
        || lower.starts_with(r"\\?\")
        || lower.starts_with("//./")
        || lower.starts_with("//?/")
        || lower.contains("globalroot")
        || lower.starts_with(r"\device\")
        || lower.starts_with(r"\??\")
    {
        return Err(anyhow!(
            "REA_SANDBOX_PATH_VIOLATION: Windows device namespace path blocked ('{}')",
            trimmed
        ));
    }

    if trimmed.starts_with(r"\\")
        || trimmed.starts_with("//")
        || lower.starts_with("smb://")
        || lower.starts_with("file://")
        || lower.starts_with("dav://")
        || lower.starts_with("http://")
        || lower.starts_with("https://")
    {
        return Err(anyhow!(
            "REA_SANDBOX_PATH_VIOLATION: UNC/SMB/remote network path blocked to prevent NTLMv2 credential leak ('{}')",
            trimmed
        ));
    }

    // Reject NTFS Alternate Data Streams (any ':' not at index 1 after an ASCII drive letter)
    for (idx, ch) in trimmed.char_indices() {
        if ch == ':' {
            let valid_drive_colon = idx == 1 && trimmed.as_bytes()[0].is_ascii_alphabetic();
            if !valid_drive_colon {
                return Err(anyhow!(
                    "REA_SANDBOX_PATH_VIOLATION: NTFS Alternate Data Stream (ADS) or illegal colon blocked ('{}')",
                    trimmed
                ));
            }
        }
    }

    // Reject parent directory traversal (`..`) in raw segments and Path components
    for seg in trimmed.split(['\\', '/']) {
        if seg == ".." {
            return Err(anyhow!(
                "REA_SANDBOX_PATH_VIOLATION: parent directory traversal ('..') blocked ('{}')",
                trimmed
            ));
        }
        let stem = seg
            .split('.')
            .next()
            .unwrap_or(seg)
            .trim_end_matches([' ', '.'])
            .to_ascii_lowercase();
        if matches!(
            stem.as_str(),
            "con"
                | "prn"
                | "aux"
                | "nul"
                | "conin$"
                | "conout$"
                | "com1"
                | "com2"
                | "com3"
                | "com4"
                | "com5"
                | "com6"
                | "com7"
                | "com8"
                | "com9"
                | "lpt1"
                | "lpt2"
                | "lpt3"
                | "lpt4"
                | "lpt5"
                | "lpt6"
                | "lpt7"
                | "lpt8"
                | "lpt9"
        ) {
            return Err(anyhow!(
                "REA_SANDBOX_PATH_VIOLATION: reserved DOS/Windows device name '{}' blocked",
                seg
            ));
        }
    }

    let path_buf = PathBuf::from(trimmed);
    for comp in path_buf.components() {
        if matches!(comp, std::path::Component::ParentDir) {
            return Err(anyhow!(
                "REA_SANDBOX_PATH_VIOLATION: parent directory component ('..') blocked"
            ));
        }
    }

    if let Ok(sym_meta) = std::fs::symlink_metadata(&path_buf) {
        if sym_meta.file_type().is_symlink() {
            return Err(anyhow!(
                "REA_SANDBOX_PATH_VIOLATION: symlink or reparse-point escape blocked ('{}')",
                trimmed
            ));
        }
    }

    Ok(path_buf)
}

/// Inspect a local filesystem path after enforcing Protection Layer 2 (`validate_rea_target_path`).
pub fn inspect_path(path: &str) -> Result<ReaInvestigationReport> {
    let validated = validate_rea_target_path(path)?;
    analyze_target_path(
        &validated.to_string_lossy(),
        ReaTargetKind::Auto,
        Some("rea_inspect_path_sandboxed".to_string()),
    )
}

// ============================================================================
// Protection Layer 1: Anti-Masquerading & Cryptographic Path/Signature Pinning
// ============================================================================

/// Returns `true` if `path_str` is inside a writable, temporary, or user-download directory
/// where system or developer toolchain binaries (`svchost.exe`, `cl.exe`, `powershell.exe`, `osoosi.exe`)
/// must NEVER be trusted as benign.
pub fn is_untrusted_writable_or_temp_path(path_str: &str) -> bool {
    let raw = path_str.trim().trim_matches('"');
    if !raw.contains('\\') && !raw.contains('/') {
        return false;
    }
    let norm = raw.replace('/', "\\").to_ascii_lowercase();
    let unix_norm = raw.replace('\\', "/").to_ascii_lowercase();

    let untrusted_markers = [
        r"\temp\",
        r"\tmp\",
        r"\appdata\local\temp",
        r"\downloads\",
        r"\users\public\",
        r"\programdata\temp",
        r"\windows\temp",
        r"\windows\tasks",
        r"\recycler\",
        r"\$recycle.bin\",
        r"\perflogs\",
        r"\desktop\",
        r"\target\debug\",
        r"\target\release\",
        r"\target\",
        r"\node_modules\",
        r"\.venv\",
        r"\venv\",
    ];
    for marker in &untrusted_markers {
        if norm.contains(marker) || norm.ends_with(marker.trim_end_matches('\\')) {
            return true;
        }
    }

    let unix_markers = [
        "/tmp/",
        "/var/tmp/",
        "/dev/shm/",
        "/downloads/",
        "/users/public/",
        "/desktop/",
        "/target/",
        "/node_modules/",
        "/.venv/",
        "/venv/",
    ];
    for marker in &unix_markers {
        if unix_norm.contains(marker) || unix_norm.starts_with(marker) {
            return true;
        }
    }

    if let Ok(sys_temp) = std::env::var("TEMP").or_else(|_| std::env::var("TMP")) {
        let st = sys_temp.replace('/', "\\").to_ascii_lowercase();
        if !st.is_empty()
            && (norm.starts_with(&st) || norm.contains(&format!("\\{}\\", st.trim_matches('\\'))))
        {
            return true;
        }
    }

    let sys_temp = std::env::temp_dir()
        .to_string_lossy()
        .replace('/', "\\")
        .to_ascii_lowercase();
    if !sys_temp.is_empty() && norm.starts_with(&sys_temp) {
        return true;
    }

    false
}

/// Returns `true` only if `path_str` points to an existing file that is cryptographically trusted
/// (Authenticode, Windows Catalog, or BLAKE3 protected hash inventory).
///
/// NOTE: Directory-prefix, PATH-derived, and substring trust heuristics have been decommissioned.
pub fn is_canonical_trusted_binary_dir(path_str: &str) -> bool {
    let raw = path_str.trim().trim_matches('"');
    if raw.is_empty() || is_untrusted_writable_or_temp_path(raw) {
        return false;
    }
    let p = Path::new(raw);
    verify_dynamic_binary_trust(p)
}

// ============================================================================
// Protection Layer 1: Canonical Masquerade Protection & Host-Independent Names
// ============================================================================

/// Canonical, immutable, versioned reference list of protected Windows, Linux,
/// and developer toolchain binary names.
///
/// Guaranteed to be protected on ANY host, whether running on a full developer
/// workstation, a headless Linux container, or a minimal CI runner with empty PATH.
pub static CANONICAL_PROTECTED_BINARY_NAMES: &[&str] = &[
    // Core Windows System Services & Daemons
    "svchost.exe",
    "lsass.exe",
    "csrss.exe",
    "smss.exe",
    "services.exe",
    "explorer.exe",
    "winlogon.exe",
    "taskhostw.exe",
    "runtimebroker.exe",
    "sihost.exe",
    "dwm.exe",
    "conhost.exe",
    "spoolsv.exe",
    "wininit.exe",
    "msmpeng.exe",
    "nissrv.exe",
    "securityhealthservice.exe",
    "searchindexer.exe",
    "audiodg.exe",
    "fontdrvhost.exe",
    // Windows Administrative & Diagnostic Executables (frequently abused LOTL)
    "rundll32.exe",
    "regsvr32.exe",
    "msiexec.exe",
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "certutil.exe",
    "schtasks.exe",
    "sc.exe",
    "net.exe",
    "net1.exe",
    "nltest.exe",
    "whoami.exe",
    "fltmc.exe",
    "vssadmin.exe",
    "bcdedit.exe",
    "wbadmin.exe",
    "robocopy.exe",
    "xcopy.exe",
    "icacls.exe",
    "takeown.exe",
    "attrib.exe",
    "mshta.exe",
    "bitsadmin.exe",
    "curl.exe",
    "tar.exe",
    "wsl.exe",
    "wslhost.exe",
    // Core Windows Dynamic Link Libraries
    "ntdll.dll",
    "kernel32.dll",
    "kernelbase.dll",
    "user32.dll",
    "gdi32.dll",
    "advapi32.dll",
    "shell32.dll",
    "ole32.dll",
    "oleaut32.dll",
    "ws2_32.dll",
    "crypt32.dll",
    "wintrust.dll",
    "sechost.dll",
    "rpcrt4.dll",
    "shlwapi.dll",
    "bcrypt.dll",
    "ncrypt.dll",
    "amsi.dll",
    "clbcatq.dll",
    "version.dll",
    // Developer Toolchains, Compilers & Linkers
    "cl.exe",
    "link.exe",
    "lib.exe",
    "ml64.exe",
    "rc.exe",
    "nmake.exe",
    "msbuild.exe",
    "csc.exe",
    "vbc.exe",
    "cvtres.exe",
    "cargo.exe",
    "rustc.exe",
    "rustup.exe",
    "rustdoc.exe",
    "rust-lld.exe",
    "lld-link.exe",
    "lld.exe",
    "clang.exe",
    "clang++.exe",
    "gcc.exe",
    "g++.exe",
    "ld.exe",
    "cmake.exe",
    "ninja.exe",
    "git.exe",
    "git-remote-https.exe",
    "ssh.exe",
    "scp.exe",
    "sftp.exe",
    "gpg.exe",
    "python.exe",
    "pythonw.exe",
    "pip.exe",
    "node.exe",
    "npm.exe",
    "npx.exe",
    "yarn.exe",
    "deno.exe",
    "bun.exe",
    "go.exe",
    "javac.exe",
    "java.exe",
    "dotnet.exe",
    // OshoosiClaw Production & Security Binaries
    "osoosi.exe",
    "osoosi-cli.exe",
    "osoosi-auditor.exe",
    "osoosi-relay.exe",
    "osoosi_inject.dll",
    "otx-taxii-rs.exe",
    "bulk_trainer.exe",
    "test-peer.exe",
    // Unix / Linux Core Binaries & Daemons
    "systemd",
    "init",
    "bash",
    "sh",
    "zsh",
    "sudo",
    "su",
    "sshd",
    "login",
    "passwd",
    "iptables",
    "nftables",
    "systemctl",
    "journalctl",
    "crond",
    "cron",
    "dockerd",
    "docker",
    "containerd",
    "runc",
    "auditd",
];

static CANONICAL_PROTECTED_NAMES_SET: std::sync::OnceLock<dashmap::DashSet<String>> =
    std::sync::OnceLock::new();

/// Returns the concurrent set of canonical protected binary names, augmented dynamically
/// with the current process executable name.
pub fn get_canonical_protected_binary_names() -> &'static dashmap::DashSet<String> {
    CANONICAL_PROTECTED_NAMES_SET.get_or_init(|| {
        let set = dashmap::DashSet::new();
        for name in CANONICAL_PROTECTED_BINARY_NAMES {
            set.insert(name.to_ascii_lowercase());
        }
        if let Ok(cur_exe) = std::env::current_exe() {
            if let Some(name) = cur_exe.file_name().and_then(|n| n.to_str()) {
                set.insert(name.to_ascii_lowercase());
            }
        }
        set
    })
}

/// Backwards-compatible alias for existing callers.
pub fn get_dynamic_masquerade_protected_names() -> &'static dashmap::DashSet<String> {
    get_canonical_protected_binary_names()
}

/// Check if a binary or process name is canonically protected against masquerading.
pub fn is_canonical_protected_binary_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    get_canonical_protected_binary_names().contains(&lower)
}

/// Detect whether a target binary or process is masquerading as a protected OS or developer binary
/// from an untrusted directory or with a non-PE/corrupted header.
pub fn detect_binary_masquerade_spoof(
    target_label: &str,
    path: Option<&Path>,
    bytes: Option<&[u8]>,
) -> Option<String> {
    let effective_str = path
        .map(|p| p.to_string_lossy().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| target_label.to_string());
    let raw = effective_str.trim().trim_matches('"');
    if raw.is_empty() {
        return None;
    }

    let norm = raw.replace('/', "\\");
    let base = norm.rsplit('\\').next().unwrap_or(raw).trim();
    let base_lower = base.to_ascii_lowercase();

    let is_protected_name = is_canonical_protected_binary_name(base);
    let has_dir_sep = raw.contains('\\') || raw.contains('/');

    if is_protected_name && has_dir_sep {
        if is_untrusted_writable_or_temp_path(raw) {
            return Some(format!(
                "REA_MASQUERADE_SPOOF_DETECTED: Protected binary '{}' is executing from untrusted writable/temp path '{}'",
                base_lower, raw
            ));
        }

        // All protected system and developer binaries must possess valid cryptographic verification
        let p = Path::new(raw);
        let is_trusted = if p.is_file() {
            verify_dynamic_binary_trust(p)
        } else {
            cfg!(not(target_os = "windows"))
                && (raw.starts_with(r"C:\Windows\")
                    || raw.starts_with(r"c:\windows\")
                    || raw.starts_with(r"C:\Program Files\")
                    || raw.starts_with(r"c:\program files\"))
        };
        if !is_trusted {
            return Some(format!(
                "REA_MASQUERADE_SPOOF_DETECTED: Protected binary '{}' at '{}' lacks valid cryptographic signature or hash inventory verification",
                base_lower, raw
            ));
        }
    }

    // Check header integrity if bytes are provided or if file exists on disk
    if is_protected_name && (base_lower.ends_with(".exe") || base_lower.ends_with(".dll")) {
        if let Some(buf) = bytes {
            if !buf.is_empty() && !buf.starts_with(b"MZ") && !buf.starts_with(b"\x7fELF") {
                return Some(format!(
                    "REA_MASQUERADE_SPOOF_DETECTED: Protected binary '{}' has non-executable payload header (expected PE 'MZ' or ELF magic)",
                    base_lower
                ));
            }
        } else if has_dir_sep {
            let p = Path::new(raw);
            if p.is_file() {
                if let Ok(mut f) = std::fs::File::open(p) {
                    let mut hdr = [0u8; 4];
                    if f.read(&mut hdr).unwrap_or(0) >= 2
                        && !hdr.starts_with(b"MZ")
                        && !hdr.starts_with(b"\x7fELF")
                    {
                        return Some(format!(
                            "REA_MASQUERADE_SPOOF_DETECTED: On-disk file '{}' masquerading as '{}' lacks PE/ELF executable header",
                            raw, base_lower
                        ));
                    }
                }
            }
        }
    }

    None
}

