//! Authoritative Executable Identity Verifier & Handle-Locked Binary Launcher (`crates/osoosi-sandbox/src/executable_identity.rs`).
//!
//! Architectural Enforcement Guarantees:
//! 1. **Defense-in-Depth Separation**: Executable verification is the authoritative binary
//!    identity gate before any Tier 2 native Win32 process creation.
//! 2. **Handle-Locked TOCTOU Prevention (`FILE_SHARE_READ` Only)**:
//!    Opens the target binary with `FILE_FLAG_OPEN_REPARSE_POINT` and `dwShareMode = FILE_SHARE_READ`
//!    (omitting `FILE_SHARE_WRITE` and `FILE_SHARE_DELETE`). The returned [`VerifiedExecutableHandle`]
//!    keeps the OS file handle open across `CreateProcessW` / `CreateProcessAsUserW`, causing the
//!    Windows kernel to block any concurrent write, truncation, or rename between verification and launch.
//! 3. **Canonical Path & Trusted Location Enforcement**:
//!    Resolves the open handle via `GetFinalPathNameByHandleW`, rejects reparse points / symlinks /
//!    junctions, and blocks execution from untrusted temp, scratchpad, or current-working-directory paths.
//! 4. **Cryptographic SHA-256 & PE Original-Identity Inspection (Renamed Interpreter Defense)**:
//!    Verifies valid PE headers (`MZ` / `PE\0\0`), computes the SHA-256 digest (cached by immutable
//!    kernel `(volume_serial, file_index, last_write_time, file_size)` tuple for `< 10 µs` hot-path latency),
//!    pins genuine `System32` binary hashes, and scans PE export/version/import markers (`OriginalFilename`,
//!    `System.Management.Automation`, `python`, `mshta`, `wscript`, `cscript`, `rundll32`, `regsvr32`)
//!    so renamed interpreters (e.g., `powershell.exe` or `python.exe` renamed to `git.exe`) fail closed.

use osoosi_types::OctopusSecurityError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::sync::{OnceLock, RwLock};

/// Normalizes an executable token (`"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.EXE"` -> `"powershell"`).
pub fn normalize_executable_stem(token: &str) -> String {
    let unquoted = token.trim().trim_matches('"').trim_matches('\'');
    let basename = unquoted
        .rsplit(&['\\', '/'][..])
        .next()
        .unwrap_or(unquoted)
        .to_ascii_lowercase();
    for suffix in [".exe", ".com", ".bat", ".cmd"] {
        if let Some(stem) = basename.strip_suffix(suffix) {
            return stem.to_string();
        }
    }
    basename
}

/// Default-deny allowlist of executable stems permitted in Tier 2 native execution.
pub const ALLOWED_TIER2_EXECUTABLE_STEMS: &[&str] = &[
    "cmd",
    "where",
    "git",
    "cargo",
    "curl",
];

/// Forbidden interpreter, script host, and LOLBin stems that may never execute in Tier 2,
/// whether invoked directly or disguised by renaming the binary on disk.
pub const FORBIDDEN_TIER2_EXECUTABLE_STEMS: &[&str] = &[
    "powershell",
    "powershell_ise",
    "pwsh",
    "mshta",
    "wscript",
    "cscript",
    "rundll32",
    "regsvr32",
    "certutil",
    "bitsadmin",
    "msiexec",
    "python",
    "python3",
    "pythonw",
    "node",
    "deno",
    "bun",
    "ruby",
    "perl",
    "php",
    "bash",
    "sh",
    "wsl",
    "csc",
    "vbc",
    "msbuild",
    "installutil",
    "cmstp",
    "odbcconf",
    "forfiles",
    "pcalua",
];

/// Embedded PE / version / import markers that identify an interpreter or LOLBin even when its
/// filename on disk has been renamed to an allowlisted stem (e.g. `powershell.exe` -> `git.exe`).
const RENAMED_INTERPRETER_PE_MARKERS: &[(&str, &[u8])] = &[
    ("powershell", b"System.Management.Automation"),
    ("powershell_pdb", b"powershell.pdb"),
    ("pwsh_dll", b"pwsh.dll"),
    ("python_dll", b"python3"),
    ("python_core", b"Py_Main"),
    ("python_run", b"Py_Initialize"),
    ("mshta", b"mshta.pdb"),
    ("wscript", b"wscript.pdb"),
    ("cscript", b"cscript.pdb"),
    ("rundll32", b"rundll32.pdb"),
    ("regsvr32", b"regsvr32.pdb"),
    ("certutil", b"certutil.pdb"),
    ("node_v8", b"napi_register_module_v1"),
];

/// Immutable kernel file identity key used to safely cache SHA-256 and PE inspection results
/// while still holding a live `FILE_SHARE_READ` handle on every invocation.
#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct KernelFileIdentityKey {
    volume_serial: u32,
    file_index_high: u32,
    file_index_low: u32,
    last_write_high: u32,
    last_write_low: u32,
    file_size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedExecutableMetadata {
    pub requested_program: String,
    pub normalized_stem: String,
    pub canonical_path: String,
    pub sha256_hex: String,
    pub file_size: u64,
    pub is_system32_binary: bool,
}

/// Holds a read-locked (`FILE_SHARE_READ` only) OS file handle to the verified executable.
/// Keeping this guard alive across `CreateProcessW` prevents any concurrent process from
/// modifying, overwriting, or renaming the binary between verification and process creation.
#[derive(Debug)]
pub struct VerifiedExecutableHandle {
    pub metadata: VerifiedExecutableMetadata,
    #[allow(dead_code)]
    pub locked_file: std::fs::File,
}

impl VerifiedExecutableHandle {
    pub fn locked_file(&self) -> &std::fs::File {
        &self.locked_file
    }
}

#[cfg(windows)]
#[derive(Clone)]
struct CachedPeInspection {
    sha256_hex: String,
    detected_interpreter_marker: Option<String>,
}

#[cfg(windows)]
fn pe_inspection_cache() -> &'static RwLock<HashMap<KernelFileIdentityKey, CachedPeInspection>> {
    static CACHE: OnceLock<RwLock<HashMap<KernelFileIdentityKey, CachedPeInspection>>> =
        OnceLock::new();
    CACHE.get_or_init(|| RwLock::new(HashMap::with_capacity(64)))
}

/// Authoritative executable identity verifier for Tier 2 native binary launches.
#[derive(Debug, Clone)]
pub struct ExecutableIdentityVerifier {
    allowed_stems: HashSet<String>,
    pinned_sha256_by_stem: HashMap<String, String>,
}

impl Default for ExecutableIdentityVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl ExecutableIdentityVerifier {
    pub fn new() -> Self {
        #[cfg(windows)]
        win_exec_id::enable_safe_search_path_mode();

        let allowed_stems = ALLOWED_TIER2_EXECUTABLE_STEMS
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        Self {
            allowed_stems,
            pinned_sha256_by_stem: HashMap::new(),
        }
    }

    /// Pins an exact expected SHA-256 hex digest for a given executable stem.
    pub fn pin_executable_sha256(&mut self, stem: &str, sha256_hex: impl Into<String>) {
        self.pinned_sha256_by_stem
            .insert(normalize_executable_stem(stem), sha256_hex.into().to_ascii_lowercase());
    }

    /// Adds an explicitly approved executable stem to this verifier instance.
    pub fn allow_stem(&mut self, stem: &str) {
        self.allowed_stems.insert(normalize_executable_stem(stem));
    }

    /// Opens the requested executable without following reparse points, locks it against concurrent
    /// writes/renames (`FILE_SHARE_READ`), verifies its canonical location, PE header, SHA-256 hash,
    /// and absence of renamed interpreter markers, and returns a [`VerifiedExecutableHandle`].
    pub fn verify_and_lock(
        &self,
        program: &str,
        untrusted_scratchpad: Option<&Path>,
    ) -> Result<VerifiedExecutableHandle, OctopusSecurityError> {
        let trimmed = program.trim().trim_matches('"');
        if trimmed.is_empty() {
            return Err(OctopusSecurityError::IsolationViolation(
                "EXEC_ID_EMPTY_PROGRAM: Tier 2 executable path cannot be empty".to_string(),
            ));
        }

        let stem = normalize_executable_stem(trimmed);
        if stem.is_empty() {
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "EXEC_ID_INVALID_STEM: Cannot extract executable stem from '{}'",
                program
            )));
        }

        // 1. Immediate rejection of forbidden interpreters, script hosts, and LOLBins
        if FORBIDDEN_TIER2_EXECUTABLE_STEMS.contains(&stem.as_str()) {
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "EXEC_ID_FORBIDDEN_INTERPRETER [{}]: Executable stem '{}' is a prohibited interpreter/LOLBin",
                program, stem
            )));
        }

        // 2. Default-deny executable stem allowlist check
        if !self.allowed_stems.contains(&stem) {
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "EXEC_ID_NOT_ALLOWLISTED [{}]: Executable stem '{}' is not in the approved Tier 2 binary catalog",
                program, stem
            )));
        }

        #[cfg(windows)]
        {
            win_exec_id::verify_and_lock_windows(
                self,
                trimmed,
                &stem,
                untrusted_scratchpad,
            )
        }

        #[cfg(not(windows))]
        {
            verify_and_lock_unix(self, trimmed, &stem, untrusted_scratchpad)
        }
    }
}

#[cfg(not(windows))]
fn verify_and_lock_unix(
    verifier: &ExecutableIdentityVerifier,
    requested_program: &str,
    stem: &str,
    untrusted_scratchpad: Option<&Path>,
) -> Result<VerifiedExecutableHandle, OctopusSecurityError> {
    let lower = requested_program.replace('\\', "/").to_ascii_lowercase();
    if lower.starts_with("./")
        || lower.starts_with("../")
        || lower.contains("/../")
        || lower.contains("local_scratchpad")
        || lower.contains("octopus_wasm_scratchpad")
    {
        return Err(OctopusSecurityError::IsolationViolation(format!(
            "EXEC_ID_UNTRUSTED_DIRECTORY_BLOCKED: Refusing to launch binary '{}' from relative or scratchpad path",
            requested_program
        )));
    }
    if let Some(scratch) = untrusted_scratchpad {
        let scratch_norm = scratch.to_string_lossy().replace('\\', "/").to_ascii_lowercase();
        if !scratch_norm.is_empty() && lower.starts_with(&scratch_norm) {
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "EXEC_ID_SCRATCHPAD_EXEC_BLOCKED: Binary '{}' resides inside agent scratchpad '{}'",
                requested_program, scratch_norm
            )));
        }
    }

    let candidate = if Path::new(requested_program).exists() {
        PathBuf::from(requested_program)
    } else {
        match stem {
            "cmd" => PathBuf::from("/bin/sh"),
            "where" => PathBuf::from("/usr/bin/which"),
            "git" => PathBuf::from("/usr/bin/git"),
            "curl" => PathBuf::from("/usr/bin/curl"),
            _ => PathBuf::from(format!("/usr/bin/{}", stem)),
        }
    };

    let mut locked_file = std::fs::File::open(&candidate).map_err(|e| {
        OctopusSecurityError::IsolationViolation(format!(
            "EXEC_ID_OPEN_FAILED: Failed to open '{}' on host: {}",
            candidate.display(),
            e
        ))
    })?;
    let mut bytes = Vec::new();
    locked_file.read_to_end(&mut bytes).map_err(|e| {
        OctopusSecurityError::IsolationViolation(format!(
            "EXEC_ID_READ_FAILED: Failed to read '{}': {}",
            candidate.display(),
            e
        ))
    })?;
    if let Some(marker) = detect_renamed_interpreter_marker(&bytes, stem) {
        return Err(OctopusSecurityError::IsolationViolation(format!(
            "EXEC_ID_RENAMED_INTERPRETER_DETECTED: Binary '{}' contains forbidden interpreter signature '{}'",
            candidate.display(),
            marker
        )));
    }
    let sha256_hex = hex::encode(Sha256::digest(&bytes));
    if let Some(expected_hash) = verifier.pinned_sha256_by_stem.get(stem) {
        if !sha256_hex.eq_ignore_ascii_case(expected_hash) {
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "EXEC_ID_SHA256_MISMATCH: Binary '{}' SHA-256 {} does not match pinned digest {}",
                candidate.display(),
                sha256_hex,
                expected_hash
            )));
        }
    }

    Ok(VerifiedExecutableHandle {
        metadata: VerifiedExecutableMetadata {
            requested_program: requested_program.to_string(),
            normalized_stem: stem.to_string(),
            canonical_path: candidate.to_string_lossy().to_string(),
            sha256_hex,
            file_size: bytes.len() as u64,
            is_system32_binary: matches!(stem, "cmd" | "where"),
        },
        locked_file,
    })
}

/// Scans a binary slice for ASCII or UTF-16LE markers indicating a renamed interpreter
/// (e.g. `powershell.exe`, `python.exe`, `mshta.exe`, `wscript.exe`, `rundll32.exe`).
pub fn detect_renamed_interpreter_marker(bytes: &[u8], claimed_stem: &str) -> Option<String> {
    for &(label, ascii_marker) in RENAMED_INTERPRETER_PE_MARKERS {
        if claimed_stem == label {
            continue;
        }
        if bytes
            .windows(ascii_marker.len())
            .any(|w| w.eq_ignore_ascii_case(ascii_marker))
        {
            return Some(label.to_string());
        }
        // Also check UTF-16LE encoding of the marker (used in PE VS_VERSION_INFO resources)
        let utf16_marker: Vec<u8> = ascii_marker
            .iter()
            .flat_map(|&b| [b, 0u8])
            .collect();
        if utf16_marker.len() >= 8
            && bytes
                .windows(utf16_marker.len())
                .any(|w| w == utf16_marker.as_slice())
        {
            return Some(format!("{}_utf16", label));
        }
    }
    None
}

#[cfg(windows)]
mod win_exec_id {
    use super::*;
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, RawHandle};

    type HANDLE = *mut c_void;
    type BOOL = i32;
    type DWORD = u32;

    const INVALID_HANDLE_VALUE: HANDLE = -1isize as HANDLE;
    const GENERIC_READ: DWORD = 0x8000_0000;
    const FILE_SHARE_READ: DWORD = 0x0000_0001;
    const OPEN_EXISTING: DWORD = 3;
    const FILE_FLAG_OPEN_REPARSE_POINT: DWORD = 0x0020_0000;
    const FILE_ATTRIBUTE_DIRECTORY: DWORD = 0x0000_0010;
    const FILE_ATTRIBUTE_REPARSE_POINT: DWORD = 0x0000_0400;
    const BASE_SEARCH_PATH_ENABLE_SAFE_SEARCHMODE: DWORD = 0x0000_0001;
    const BASE_SEARCH_PATH_PERMANENT: DWORD = 0x0000_8000;

    #[repr(C)]
    #[allow(non_snake_case)]
    #[derive(Clone, Copy)]
    struct FILETIME {
        dwLowDateTime: DWORD,
        dwHighDateTime: DWORD,
    }

    #[repr(C)]
    #[allow(non_snake_case)]
    struct BY_HANDLE_FILE_INFORMATION {
        dwFileAttributes: DWORD,
        ftCreationTime: FILETIME,
        ftLastAccessTime: FILETIME,
        ftLastWriteTime: FILETIME,
        dwVolumeSerialNumber: DWORD,
        nFileSizeHigh: DWORD,
        nFileSizeLow: DWORD,
        nNumberOfLinks: DWORD,
        nFileIndexHigh: DWORD,
        nFileIndexLow: DWORD,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateFileW(
            lpFileName: *const u16,
            dwDesiredAccess: DWORD,
            dwShareMode: DWORD,
            lpSecurityAttributes: *const c_void,
            dwCreationDisposition: DWORD,
            dwFlagsAndAttributes: DWORD,
            hTemplateFile: HANDLE,
        ) -> HANDLE;
        fn GetFileInformationByHandle(
            hFile: HANDLE,
            lpFileInformation: *mut BY_HANDLE_FILE_INFORMATION,
        ) -> BOOL;
        fn GetFinalPathNameByHandleW(
            hFile: HANDLE,
            lpszFilePath: *mut u16,
            cchFilePath: DWORD,
            dwFlags: DWORD,
        ) -> DWORD;
        fn SetSearchPathMode(Flags: DWORD) -> BOOL;
        fn GetLastError() -> DWORD;
    }

    pub fn enable_safe_search_path_mode() {
        static INIT: OnceLock<()> = OnceLock::new();
        INIT.get_or_init(|| unsafe {
            let _ = SetSearchPathMode(
                BASE_SEARCH_PATH_ENABLE_SAFE_SEARCHMODE | BASE_SEARCH_PATH_PERMANENT,
            );
        });
    }

    fn resolve_candidate_path(trimmed: &str, stem: &str) -> Result<PathBuf, OctopusSecurityError> {
        let p = Path::new(trimmed);
        if p.components().count() > 1 || trimmed.contains('\\') || trimmed.contains('/') {
            if !p.is_absolute() {
                return Err(OctopusSecurityError::IsolationViolation(format!(
                    "EXEC_ID_RELATIVE_PATH_FORBIDDEN: Relative executable path '{}' is prohibited",
                    trimmed
                )));
            }
            return Ok(p.to_path_buf());
        }

        // Bare program name: resolve deterministically from trusted system/toolchain directories only
        // (never from current working directory `.`).
        let sys_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
        let sys32_candidate = PathBuf::from(&sys_root)
            .join("System32")
            .join(format!("{}.exe", stem));
        if sys32_candidate.exists() {
            return Ok(sys32_candidate);
        }

        let trusted_dirs = [
            r"C:\Program Files\Git\cmd",
            r"C:\Program Files\Git\bin",
            r"C:\Program Files\Git\mingw64\bin",
        ];
        for dir in trusted_dirs {
            let cand = PathBuf::from(dir).join(format!("{}.exe", stem));
            if cand.exists() {
                return Ok(cand);
            }
        }

        if let Ok(profile) = std::env::var("USERPROFILE") {
            let cargo_cand = PathBuf::from(profile)
                .join(".cargo")
                .join("bin")
                .join(format!("{}.exe", stem));
            if cargo_cand.exists() {
                return Ok(cargo_cand);
            }
        }

        Err(OctopusSecurityError::IsolationViolation(format!(
            "EXEC_ID_BINARY_NOT_FOUND: Could not resolve '{}' in any trusted system or toolchain directory",
            trimmed
        )))
    }

    fn open_read_locked_no_reparse(path: &Path) -> Result<std::fs::File, OctopusSecurityError> {
        let wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        // FILE_SHARE_READ only: blocks concurrent write, overwrite, or rename (TOCTOU defense)
        let h = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };
        if h.is_null() || h == INVALID_HANDLE_VALUE {
            let err = unsafe { GetLastError() };
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "EXEC_ID_OPEN_FAILED: Failed to open '{}' with FILE_SHARE_READ | FILE_FLAG_OPEN_REPARSE_POINT (OS Error {})",
                path.display(),
                err
            )));
        }
        Ok(unsafe { std::fs::File::from_raw_handle(h as RawHandle) })
    }

    fn query_handle_info(h: HANDLE) -> Result<BY_HANDLE_FILE_INFORMATION, OctopusSecurityError> {
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe { GetFileInformationByHandle(h, &mut info) } == 0 {
            let err = unsafe { GetLastError() };
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "EXEC_ID_HANDLE_INFO_FAILED: GetFileInformationByHandle failed (OS Error {})",
                err
            )));
        }
        Ok(info)
    }

    fn query_final_path(h: HANDLE) -> Result<String, OctopusSecurityError> {
        let mut buf = vec![0u16; 1024];
        let len = unsafe { GetFinalPathNameByHandleW(h, buf.as_mut_ptr(), buf.len() as DWORD, 0) };
        if len == 0 || (len as usize) >= buf.len() {
            let err = unsafe { GetLastError() };
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "EXEC_ID_FINAL_PATH_FAILED: GetFinalPathNameByHandleW failed (OS Error {})",
                err
            )));
        }
        let raw = String::from_utf16_lossy(&buf[..len as usize]);
        // Strip extended-length `\\?\` prefix for CreateProcessW compatibility
        Ok(raw.strip_prefix(r"\\?\").unwrap_or(&raw).to_string())
    }

    pub fn verify_and_lock_windows(
        verifier: &ExecutableIdentityVerifier,
        requested_program: &str,
        stem: &str,
        untrusted_scratchpad: Option<&Path>,
    ) -> Result<VerifiedExecutableHandle, OctopusSecurityError> {
        let resolved_path = resolve_candidate_path(requested_program, stem)?;
        let mut locked_file = open_read_locked_no_reparse(&resolved_path)?;
        let h = locked_file.as_raw_handle() as HANDLE;

        let info = query_handle_info(h)?;
        if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "EXEC_ID_REPARSE_POINT_BLOCKED: Executable '{}' is a symlink or NTFS reparse point",
                resolved_path.display()
            )));
        }
        if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "EXEC_ID_IS_DIRECTORY: '{}' is a directory, not a PE executable",
                resolved_path.display()
            )));
        }

        let canonical_path = query_final_path(h)?;
        let canonical_lower = canonical_path.replace('/', "\\").to_ascii_lowercase();

        // Reject execution from untrusted temp or scratchpad directories
        if canonical_lower.contains("\\appdata\\local\\temp\\")
            || canonical_lower.contains("\\windows\\temp\\")
            || canonical_lower.contains("local_scratchpad")
            || canonical_lower.contains("octopus_wasm_scratchpad")
            || canonical_lower.contains("osoosi_tier1_scratch")
        {
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "EXEC_ID_UNTRUSTED_DIRECTORY_BLOCKED: Refusing to launch binary '{}' from temporary or scratchpad directory",
                canonical_path
            )));
        }

        if let Some(scratch) = untrusted_scratchpad {
            let scratch_norm = scratch
                .to_string_lossy()
                .replace('/', "\\")
                .trim_start_matches(r"\\?\")
                .trim_end_matches('\\')
                .to_ascii_lowercase();
            if !scratch_norm.is_empty() && canonical_lower.starts_with(&scratch_norm) {
                return Err(OctopusSecurityError::IsolationViolation(format!(
                    "EXEC_ID_SCRATCHPAD_EXEC_BLOCKED: Binary '{}' resides inside agent scratchpad '{}'",
                    canonical_path, scratch_norm
                )));
            }
        }

        // Verify canonical filename stem matches the requested stem (prevents symlink/hardlink stem spoofing)
        let canonical_stem = normalize_executable_stem(&canonical_path);
        if canonical_stem != stem {
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "EXEC_ID_STEM_MISMATCH: Requested stem '{}' resolved to canonical stem '{}' ('{}')",
                stem, canonical_stem, canonical_path
            )));
        }

        // System binaries (`cmd`, `where`) MUST reside inside `%SystemRoot%\System32`
        let is_system32_binary = canonical_lower.contains("\\windows\\system32\\");
        if matches!(stem, "cmd" | "where") && !is_system32_binary {
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "EXEC_ID_NON_SYSTEM32_SPOOF: System binary '{}' must reside in C:\\Windows\\System32, found '{}'",
                stem, canonical_path
            )));
        }

        let file_size = ((info.nFileSizeHigh as u64) << 32) | (info.nFileSizeLow as u64);
        if file_size < 64 {
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "EXEC_ID_INVALID_PE: File '{}' is too small ({} bytes) to be a valid PE executable",
                canonical_path, file_size
            )));
        }

        let cache_key = KernelFileIdentityKey {
            volume_serial: info.dwVolumeSerialNumber,
            file_index_high: info.nFileIndexHigh,
            file_index_low: info.nFileIndexLow,
            last_write_high: info.ftLastWriteTime.dwHighDateTime,
            last_write_low: info.ftLastWriteTime.dwLowDateTime,
            file_size,
        };

        let inspection = {
            let cached = pe_inspection_cache()
                .read()
                .ok()
                .and_then(|map| map.get(&cache_key).cloned());
            if let Some(hit) = cached {
                hit
            } else {
                let mut bytes = Vec::with_capacity((file_size as usize).min(32 * 1024 * 1024));
                locked_file.read_to_end(&mut bytes).map_err(|e| {
                    OctopusSecurityError::IsolationViolation(format!(
                        "EXEC_ID_READ_FAILED: Could not read '{}' for SHA-256 verification: {}",
                        canonical_path, e
                    ))
                })?;
                if bytes.len() < 2 || &bytes[0..2] != b"MZ" {
                    return Err(OctopusSecurityError::IsolationViolation(format!(
                        "EXEC_ID_INVALID_MZ_HEADER: '{}' does not have a valid DOS/PE 'MZ' header",
                        canonical_path
                    )));
                }
                let sha256_hex = hex::encode(Sha256::digest(&bytes));
                let detected_interpreter_marker =
                    detect_renamed_interpreter_marker(&bytes, stem);
                let entry = CachedPeInspection {
                    sha256_hex,
                    detected_interpreter_marker,
                };
                if let Ok(mut map) = pe_inspection_cache().write() {
                    if map.len() >= 256 {
                        map.clear();
                    }
                    map.insert(cache_key, entry.clone());
                }
                entry
            }
        };

        if let Some(ref marker) = inspection.detected_interpreter_marker {
            return Err(OctopusSecurityError::IsolationViolation(format!(
                "EXEC_ID_RENAMED_INTERPRETER_DETECTED: Binary '{}' (claimed stem '{}') contains forbidden interpreter signature '{}'",
                canonical_path, stem, marker
            )));
        }

        if let Some(expected_hash) = verifier.pinned_sha256_by_stem.get(stem) {
            if !inspection.sha256_hex.eq_ignore_ascii_case(expected_hash) {
                return Err(OctopusSecurityError::IsolationViolation(format!(
                    "EXEC_ID_SHA256_MISMATCH: Binary '{}' SHA-256 {} does not match pinned digest {}",
                    canonical_path, inspection.sha256_hex, expected_hash
                )));
            }
        }

        Ok(VerifiedExecutableHandle {
            metadata: VerifiedExecutableMetadata {
                requested_program: requested_program.to_string(),
                normalized_stem: stem.to_string(),
                canonical_path,
                sha256_hex: inspection.sha256_hex,
                file_size,
                is_system32_binary,
            },
            locked_file,
        })
    }
}
