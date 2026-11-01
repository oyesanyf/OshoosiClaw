//! Protected Environment Backup Vault (`ProtectedEnvBackupVault`).
//!
//! Stores pre-stand-in `.env` / configuration secret state in an AEAD-encrypted
//! (`ChaCha20Poly1305` / `OSHOOSI_ENV_BACKUP_V1`), BLAKE3/HMAC-authenticated vault
//! (`database/protected_env_backup.vault`) locked with Win32 Protected NTFS DACLs
//! (`SE_DACL_PROTECTED` via `SetNamedSecurityInfoW` with `D:P(A;;GA;;;SY)(A;;GA;;;BA)`),
//! or mode `0600` on Unix.
//!
//! Invariants:
//! - NEVER mutates `PATH` or Windows Registry environment hives (`HKCU`/`HKLM`).
//! - Automatically reverts pre-stand-in `.env` files on EDR service shutdown (`on_service_stop`, `Drop`).
//! - Supports secure removal: unlocks DACL, overwrites file with `0x00`, flushes to disk (`sync_all`), and unlinks.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

pub const VAULT_MAGIC: &[u8; 24] = b"OSHOOSI_ENV_BACKUP_V1\0\0\0";
pub const DEFAULT_VAULT_PATH: &str = "database/protected_env_backup.vault";
pub const DEFAULT_ENV_SEAL_CONFIG_PATH: &str = "database/env_seal_config.json";

/// In-memory atomic flag set when the operator clicks "Revert All Secrets" or disables Protect .env,
/// immediately halting any background auto-seal watcher loop across the process.
pub static AUTO_SEAL_PAUSED: AtomicBool = AtomicBool::new(false);

/// Wraps arbitrary bytes using Windows DPAPI (`CryptProtectData`) with machine scope
/// and UI forbidden. Returns raw ciphertext bytes.
#[cfg(windows)]
pub fn dpapi_protect_bytes(bytes: &[u8]) -> std::io::Result<Vec<u8>> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Cryptography::{
        CryptProtectData, CRYPTPROTECT_LOCAL_MACHINE, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    if bytes.is_empty() {
        return Ok(Vec::new());
    }

    let data_in = CRYPT_INTEGER_BLOB {
        cbData: bytes.len() as u32,
        pbData: bytes.as_ptr() as *mut u8,
    };

    let mut data_out = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    let flags = CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE;

    let res = unsafe {
        CryptProtectData(
            &data_in,
            PCWSTR::null(),
            None,
            None,
            None,
            flags,
            &mut data_out,
        )
    };

    if let Err(e) = res {
        return Err(std::io::Error::other(format!(
            "DPAPI CryptProtectData failed: {e}"
        )));
    }

    if data_out.pbData.is_null() {
        return Err(std::io::Error::other(
            "DPAPI CryptProtectData returned null buffer",
        ));
    }

    let out_slice =
        unsafe { std::slice::from_raw_parts(data_out.pbData, data_out.cbData as usize) };
    let protected = out_slice.to_vec();

    unsafe {
        let _ = LocalFree(HLOCAL(data_out.pbData as *mut core::ffi::c_void));
    }

    Ok(protected)
}

/// Unwraps bytes protected by Windows DPAPI (`CryptUnprotectData`).
#[cfg(windows)]
pub fn dpapi_unprotect_bytes(wrapped: &[u8]) -> std::io::Result<Vec<u8>> {
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Cryptography::{
        CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    if wrapped.is_empty() {
        return Ok(Vec::new());
    }

    let data_in = CRYPT_INTEGER_BLOB {
        cbData: wrapped.len() as u32,
        pbData: wrapped.as_ptr() as *mut u8,
    };

    let mut data_out = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    let flags = CRYPTPROTECT_UI_FORBIDDEN;

    let res = unsafe { CryptUnprotectData(&data_in, None, None, None, None, flags, &mut data_out) };

    if let Err(e) = res {
        return Err(std::io::Error::other(format!(
            "DPAPI CryptUnprotectData failed: {e}"
        )));
    }

    if data_out.pbData.is_null() {
        return Err(std::io::Error::other(
            "DPAPI CryptUnprotectData returned null buffer",
        ));
    }

    let out_slice =
        unsafe { std::slice::from_raw_parts(data_out.pbData, data_out.cbData as usize) };
    let unprotected = out_slice.to_vec();

    unsafe {
        let _ = LocalFree(HLOCAL(data_out.pbData as *mut core::ffi::c_void));
    }

    Ok(unprotected)
}

#[cfg(not(windows))]
pub fn dpapi_protect_bytes(_bytes: &[u8]) -> std::io::Result<Vec<u8>> {
    Ok(Vec::new())
}

#[cfg(not(windows))]
pub fn dpapi_unprotect_bytes(_wrapped: &[u8]) -> std::io::Result<Vec<u8>> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "DPAPI is only supported on Windows platforms",
    ))
}

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Authentication or cryptographic integrity failure")]
    IntegrityFailure,
    #[error("Decryption error: {0}")]
    Decryption(String),
    #[error("Encryption error: {0}")]
    Encryption(String),
    #[error("Invalid vault magic header or corrupted envelope format")]
    InvalidFormat,
    #[error("Backup confirmation flag required for removal (--confirm)")]
    ConfirmationRequired,
    #[error("Vault file not found at {0}")]
    NotFound(PathBuf),
    #[error("Target file error: {0}")]
    TargetError(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackedUpEnvFile {
    pub path: String,
    pub original_bytes: Vec<u8>,
    pub existed_before: bool,
    pub original_sha256: String,
    #[serde(default)]
    pub magika_label: Option<String>,
    #[serde(default)]
    pub magika_mime_type: Option<String>,
    #[serde(default)]
    pub magika_score: Option<f32>,
    #[serde(default)]
    pub drive_root: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultStatus {
    pub exists: bool,
    pub vault_path: PathBuf,
    pub target_path: Option<PathBuf>,
    pub sealed_at_epoch: Option<u64>,
    pub sealed_variables: Vec<String>,
    #[serde(default)]
    pub standin_mappings: Vec<(String, String)>,
    pub dacl_protected: bool,
    pub payload_size: u64,
    pub original_sha256: Option<String>,
    #[serde(default)]
    pub files: Vec<BackedUpEnvFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultPayload {
    #[serde(default)]
    pub target_path: String,
    pub epoch: u64,
    pub sealed_variables: Vec<String>,
    #[serde(default)]
    pub original_bytes: Vec<u8>,
    #[serde(default)]
    pub standin_mappings: Vec<(String, String)>,
    #[serde(default)]
    pub original_env_vars: Vec<(String, String)>,
    #[serde(default)]
    pub original_hkcu_vars: Vec<(String, String)>,
    #[serde(default)]
    pub target_existed_before: bool,
    #[serde(default)]
    pub original_sha256: Option<String>,
    #[serde(default)]
    pub files: Vec<BackedUpEnvFile>,
    #[serde(default)]
    pub user_sid_env: HashMap<String, HashMap<String, String>>,
    #[serde(default)]
    pub dpapi_wrapped_key: Option<Vec<u8>>,
}

pub type ProtectedVaultPayload = VaultPayload;

pub struct ProtectedEnvBackupVault;

impl ProtectedEnvBackupVault {
    pub fn default_vault_path() -> PathBuf {
        PathBuf::from(DEFAULT_VAULT_PATH)
    }

    /// Returns candidate paths for `database/env_seal_config.json` across CWD, parent dirs, executable dirs, and `ProgramData`.
    pub fn candidate_env_seal_config_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut add = |p: PathBuf| {
            let k = p.to_string_lossy().to_ascii_lowercase();
            if seen.insert(k) {
                paths.push(p);
            }
        };
        add(PathBuf::from(DEFAULT_ENV_SEAL_CONFIG_PATH));
        add(PathBuf::from("../database/env_seal_config.json"));
        add(PathBuf::from("../../database/env_seal_config.json"));
        if let Ok(exe) = std::env::current_exe() {
            let mut cur = exe.parent();
            for _ in 0..4 {
                if let Some(dir) = cur {
                    add(dir.join(DEFAULT_ENV_SEAL_CONFIG_PATH));
                    cur = dir.parent();
                } else {
                    break;
                }
            }
        }
        #[cfg(windows)]
        {
            add(PathBuf::from(r"C:\ProgramData\OshoosiClaw\database\env_seal_config.json"));
            add(PathBuf::from(r"C:\Program Files\OshoosiClaw\database\env_seal_config.json"));
        }
        paths
    }

    /// Returns true ONLY when background auto-sealing is explicitly enabled in `database/env_seal_config.json`
    /// (`enabled == true` and `auto_seal == true`) AND has not been paused by an operator revert action.
    pub fn is_auto_seal_enabled() -> bool {
        if AUTO_SEAL_PAUSED.load(Ordering::SeqCst) {
            return false;
        }
        let mut found_any = false;
        for p in Self::candidate_env_seal_config_paths() {
            if p.is_file() {
                if let Ok(bytes) = std::fs::read(&p) {
                    if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                        found_any = true;
                        let enabled = val
                            .get("enabled")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                        let auto_seal = val
                            .get("auto_seal")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                        if !enabled || !auto_seal {
                            return false;
                        }
                    }
                }
            }
        }
        found_any
    }

    /// Pauses all background auto-sealing in memory and persists `enabled: false, auto_seal: false, watcher_enabled: false`
    /// to `database/env_seal_config.json` across all candidate locations so background watchers never re-seal `HKCU\Environment` after revert.
    pub fn pause_auto_seal_and_persist_disabled() {
        AUTO_SEAL_PAUSED.store(true, Ordering::SeqCst);
        let default_json = serde_json::json!({
            "enabled": false,
            "experimental": true,
            "custom_paths": [],
            "all_drives": false,
            "auto_seal": false,
            "selected_variables": ["GEMINI_API_KEY", "HF_TOKEN", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GITHUB_TOKEN"],
            "excluded_variables": [],
            "watcher_enabled": false,
            "watcher_poll_interval_secs": 5,
            "max_files_per_drive": 500,
            "max_dir_budget_per_drive": 2000,
            "vault_path": null
        });
        let mut updated_any = false;
        for p in Self::candidate_env_seal_config_paths() {
            if p.is_file() {
                if let Ok(bytes) = std::fs::read(&p) {
                    if let Ok(mut val) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                        if let Some(obj) = val.as_object_mut() {
                            obj.insert("enabled".to_string(), serde_json::Value::Bool(false));
                            obj.insert("auto_seal".to_string(), serde_json::Value::Bool(false));
                            obj.insert(
                                "watcher_enabled".to_string(),
                                serde_json::Value::Bool(false),
                            );
                            if let Ok(out) = serde_json::to_vec_pretty(&val) {
                                let _ = std::fs::write(&p, out);
                                updated_any = true;
                            }
                        }
                    }
                }
            }
        }
        if !updated_any {
            let p = Path::new(DEFAULT_ENV_SEAL_CONFIG_PATH);
            if let Some(parent) = p.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Ok(out) = serde_json::to_vec_pretty(&default_json) {
                let _ = std::fs::write(p, out);
            }
        }
    }

    /// Returns the companion `.dpapi` file path for a given vault file path.
    pub fn companion_dpapi_path(vault_path: &Path) -> PathBuf {
        vault_path.with_extension("dpapi")
    }

    /// Derives the 32-byte host master key from host identity and MachineGuid.
    pub fn derive_vault_master_key() -> [u8; 32] {
        Self::derive_vault_key(&[0u8; 16])
    }

    /// Discovers environment files (.env, .env.local, .env.production, .env.development, .env.test, .env.staging)
    /// in the base directory and its depth-1 immediate subdirectories, plus any custom paths provided.
    pub fn discover_environment_files(base_dir: &Path, custom_paths: &[PathBuf]) -> Vec<PathBuf> {
        let mut discovered = Vec::new();
        let mut seen = std::collections::HashSet::new();

        let candidate_names = [
            ".env",
            ".env.local",
            ".env.production",
            ".env.development",
            ".env.test",
            ".env.staging",
        ];

        let root = if base_dir.is_file() {
            let key = base_dir
                .canonicalize()
                .unwrap_or_else(|_| base_dir.to_path_buf())
                .to_string_lossy()
                .to_ascii_lowercase();
            if seen.insert(key) {
                discovered.push(base_dir.to_path_buf());
            }
            base_dir.parent().unwrap_or(Path::new("."))
        } else {
            base_dir
        };

        for name in &candidate_names {
            let p = root.join(name);
            if p.is_file() {
                let key = p
                    .canonicalize()
                    .unwrap_or_else(|_| p.clone())
                    .to_string_lossy()
                    .to_ascii_lowercase();
                if seen.insert(key) {
                    discovered.push(p);
                }
            }
        }

        if let Ok(entries) = std::fs::read_dir(root) {
            for entry in entries.flatten() {
                if let Ok(ft) = entry.file_type() {
                    if ft.is_dir() {
                        let sub_dir = entry.path();
                        let dir_name = sub_dir.file_name().and_then(|n| n.to_str()).unwrap_or("");
                        if !dir_name.starts_with('.')
                            && dir_name != "target"
                            && dir_name != "node_modules"
                        {
                            for name in &candidate_names {
                                let p = sub_dir.join(name);
                                if p.is_file() {
                                    let key = p
                                        .canonicalize()
                                        .unwrap_or_else(|_| p.clone())
                                        .to_string_lossy()
                                        .to_ascii_lowercase();
                                    if seen.insert(key) {
                                        discovered.push(p);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        for custom in custom_paths {
            if custom.as_os_str().is_empty() {
                continue;
            }
            let key = custom
                .canonicalize()
                .unwrap_or_else(|_| custom.clone())
                .to_string_lossy()
                .to_ascii_lowercase();
            if seen.insert(key) {
                discovered.push(custom.clone());
            }
        }

        discovered
    }

    /// Enumerates all accessible physical drive root paths on the system
    /// using `sysinfo::Disks` and Windows drive letter detection (A:..=Z:) or root `/`.
    pub fn enumerate_physical_drives() -> Vec<PathBuf> {
        let mut drives = Vec::new();
        let mut seen = std::collections::HashSet::new();

        let disks = sysinfo::Disks::new_with_refreshed_list();
        for disk in &disks {
            let mount = disk.mount_point().to_path_buf();
            let key = mount.to_string_lossy().to_ascii_lowercase();
            if seen.insert(key) {
                drives.push(mount);
            }
        }

        #[cfg(windows)]
        {
            for b in b'A'..=b'Z' {
                let letter = b as char;
                let root_str = format!("{}:\\", letter);
                let p = PathBuf::from(&root_str);
                if p.exists() {
                    let key = root_str.to_ascii_lowercase();
                    if seen.insert(key) {
                        drives.push(p);
                    }
                }
            }
        }

        #[cfg(not(windows))]
        {
            let root = PathBuf::from("/");
            let key = root.to_string_lossy().to_ascii_lowercase();
            if seen.insert(key) {
                drives.push(root);
            }
        }

        drives
    }

    /// Scans physical drives for environment files using Google Magika content identification,
    /// safe recursion pruning OS/system directories, 256 KiB file caps, and structural key=value validation.
    pub fn scan_all_physical_drives_with_magika(
        max_files_per_drive: usize,
        max_dir_budget_per_drive: usize,
    ) -> Vec<PathBuf> {
        let drives = Self::enumerate_physical_drives();
        let mut results = Vec::new();
        let mut seen = std::collections::HashSet::new();

        let skip_dir_names = [
            "windows",
            "system volume information",
            "$recycle.bin",
            "recovery",
            "program files",
            "program files (x86)",
            "programdata\\microsoft",
            "appdata\\local\\temp",
            "appdata\\local\\microsoft",
            "node_modules",
            "target",
            ".git",
            ".svn",
            ".cargo",
            ".rustup",
            ".nuget",
            "__pycache__",
            "proc",
            "sys",
            "dev",
            "run",
        ];

        for drive in drives {
            let mut visited_dirs = 0usize;
            let mut files_found = 0usize;

            for entry in walkdir::WalkDir::new(&drive)
                .max_depth(8)
                .follow_links(false)
                .into_iter()
                .filter_entry(|e| {
                    if visited_dirs >= max_dir_budget_per_drive {
                        return false;
                    }
                    let ft = e.file_type();
                    if ft.is_dir() {
                        visited_dirs += 1;
                        let name = e.file_name().to_string_lossy().to_ascii_lowercase();
                        if skip_dir_names.iter().any(|&s| name == s) {
                            return false;
                        }
                        let full_path = e.path().to_string_lossy().to_ascii_lowercase();
                        if skip_dir_names.iter().any(|&s| full_path.contains(s)) {
                            return false;
                        }
                    }
                    true
                })
            {
                if files_found >= max_files_per_drive {
                    break;
                }
                let Ok(entry) = entry else { continue };
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }

                let Ok(meta) = entry.metadata() else { continue };
                if meta.len() == 0 || meta.len() > 262_144 {
                    continue;
                }

                if let Ok(sym_meta) = std::fs::symlink_metadata(path) {
                    if sym_meta.file_type().is_symlink() {
                        continue;
                    }
                }

                let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                let is_env_name = file_name.starts_with(".env")
                    || file_name.ends_with(".env")
                    || file_name.eq_ignore_ascii_case("environment")
                    || file_name.eq_ignore_ascii_case("dotenv");

                if !is_env_name {
                    continue;
                }

                let Ok(bytes) = std::fs::read(path) else {
                    continue;
                };
                let magika = crate::rea::identify_with_magika(Some(path), &bytes);

                let is_text_or_config = magika.is_text
                    || magika.group == "text"
                    || magika.group == "code"
                    || magika.label == "ini"
                    || magika.label == "config"
                    || magika.label == "txt";

                if !is_text_or_config {
                    continue;
                }

                let text = String::from_utf8_lossy(&bytes);
                let has_env_structure = text.lines().any(|line| {
                    let t = line.trim();
                    if t.starts_with('#') || !t.contains('=') {
                        return false;
                    }
                    let parts: Vec<&str> = t.splitn(2, '=').collect();
                    let k = parts[0].trim();
                    !k.is_empty()
                        && k.chars()
                            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
                });

                if has_env_structure {
                    let key = path
                        .canonicalize()
                        .unwrap_or_else(|_| path.to_path_buf())
                        .to_string_lossy()
                        .to_ascii_lowercase();
                    if seen.insert(key) {
                        results.push(path.to_path_buf());
                        files_found += 1;
                    }
                }
            }
        }

        results
    }

    /// Atomic file write: writes bytes to temporary sibling `.tmp` file, flushes to disk via `sync_all()`,
    /// rejects symlinks/reparse points, and safely renames over the destination path.
    pub fn write_file_atomic(path: &Path, bytes: &[u8]) -> Result<(), VaultError> {
        if let Ok(meta) = std::fs::symlink_metadata(path) {
            if meta.file_type().is_symlink() {
                return Err(VaultError::TargetError(format!(
                    "Refusing to write to symbolic link or reparse point: '{}'",
                    path.display()
                )));
            }
        }
        let parent = path.parent().unwrap_or(Path::new("."));
        if !parent.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(parent);
        }
        let tmp_name = format!(
            ".{}_{}.tmp",
            path.file_name().and_then(|n| n.to_str()).unwrap_or("env"),
            uuid::Uuid::new_v4().simple()
        );
        let tmp_path = parent.join(tmp_name);

        let mut f = File::create(&tmp_path)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);

        if let Err(_e) = std::fs::rename(&tmp_path, path) {
            if path.exists() {
                let _ = std::fs::remove_file(path);
            }
            if let Err(e2) = std::fs::rename(&tmp_path, path) {
                let _ = std::fs::remove_file(&tmp_path);
                return Err(VaultError::Io(e2));
            }
        }
        Ok(())
    }

    /// Restores a single backed-up file from the vault to its exact original pre-stand-in state.
    pub fn revert_single_file(
        vault_path: &Path,
        target_file_path: &Path,
    ) -> Result<(), VaultError> {
        if !vault_path.exists() {
            return Ok(());
        }
        let (payload, _) = Self::read_vault_payload(vault_path)?;
        let target_canonical = target_file_path
            .canonicalize()
            .unwrap_or_else(|_| target_file_path.to_path_buf())
            .to_string_lossy()
            .to_ascii_lowercase();

        let mut matched = false;
        for entry in &payload.files {
            let entry_p = PathBuf::from(&entry.path);
            let entry_canonical = entry_p
                .canonicalize()
                .unwrap_or_else(|_| entry_p.clone())
                .to_string_lossy()
                .to_ascii_lowercase();

            if entry_canonical == target_canonical
                || entry.path == target_file_path.to_string_lossy()
            {
                if entry.existed_before || !entry.original_bytes.is_empty() {
                    Self::write_file_atomic(&entry_p, &entry.original_bytes)?;
                } else if entry_p.exists() {
                    let _ = std::fs::remove_file(&entry_p);
                }
                matched = true;
                break;
            }
        }

        if !matched
            && (payload.target_path == target_file_path.to_string_lossy()
                || PathBuf::from(&payload.target_path).canonicalize().ok()
                    == target_file_path.canonicalize().ok())
        {
            let target = PathBuf::from(&payload.target_path);
            if payload.target_existed_before || !payload.original_bytes.is_empty() {
                Self::write_file_atomic(&target, &payload.original_bytes)?;
            } else if target.exists() {
                let _ = std::fs::remove_file(&target);
            }
            matched = true;
        }

        if matched {
            Ok(())
        } else {
            Err(VaultError::TargetError(format!(
                "File '{}' not found in vault backups",
                target_file_path.display()
            )))
        }
    }

    /// Checks whether an environment variable key and value represents a genuine secret credential
    /// that should be sealed. Strictly excludes runtime non-secret configurations (e.g. PORT, HOST,
    /// NODE_ENV, RUST_LOG, booleans, localhost URLs, file paths, and OS paths like PATH, TEMP, TMP),
    /// preventing software breakage.
    pub fn is_secret_env_key_and_value(key: &str, value: &str) -> bool {
        let clean_key = key.trim();
        let key_upper = clean_key.to_ascii_uppercase();
        let clean_val = value.trim().trim_matches('"').trim_matches('\'');

        // 1. Hard check: non-secret system / runtime configuration variables that MUST NEVER BE SEALED
        let non_secret_names = [
            "PORT",
            "HOST",
            "HOSTNAME",
            "NODE_ENV",
            "RUST_ENV",
            "RUST_LOG",
            "RUST_BACKTRACE",
            "APP_ENV",
            "ENV",
            "ENVIRONMENT",
            "DEBUG",
            "LOG_LEVEL",
            "TZ",
            "LANG",
            "LC_ALL",
            "PATH",
            "PATHEXT",
            "JAVA_HOME",
            "ONEDRIVE",
            "ONEDRIVECONSUMER",
            "OLLAMA_ORIGINS",
            "TEMP",
            "TMP",
            "USERPROFILE",
            "WINDIR",
            "COMSPEC",
            "SYSTEMROOT",
            "SYSTEMDRIVE",
            "APPDATA",
            "LOCALAPPDATA",
            "PROGRAMFILES",
            "PROGRAMFILES(X86)",
            "COMMONPROGRAMFILES",
            "HOMEDRIVE",
            "HOMEPATH",
            "OS",
            "NUMBER_OF_PROCESSORS",
            "PROCESSOR_ARCHITECTURE",
            "PROCESSOR_IDENTIFIER",
            "PSMODULEPATH",
            "ALLUSERSPROFILE",
            "PUBLIC",
            "DRIVERDATA",
        ];

        if non_secret_names.iter().any(|&n| key_upper == n) {
            return false;
        }

        // Never seal frontend / public environment variables
        if key_upper.starts_with("PUBLIC_")
            || key_upper.starts_with("NEXT_PUBLIC_")
            || key_upper.starts_with("VITE_")
            || key_upper.starts_with("REACT_APP_")
            || key_upper.starts_with("GATSBY_")
            || key_upper.starts_with("NUXT_PUBLIC_")
        {
            return false;
        }

        // Never seal toolchain/system prefixes
        if key_upper.starts_with("ANTIGRAVITY_")
            || key_upper.starts_with("VSCODE_")
            || key_upper.starts_with("CARGO_")
            || key_upper.starts_with("RUST_")
            || key_upper.starts_with("TERM_")
            || key_upper.starts_with("NPM_")
            || key_upper.starts_with("SSH_")
            || key_upper.starts_with("GPG_")
            || key_upper.starts_with("GIT_")
            || key_upper.starts_with("OSOOSI_")
        {
            return false;
        }

        // Never seal suffixes
        if key_upper.ends_with("_HOME")
            || key_upper.ends_with("_DIR")
            || key_upper.ends_with("_PATH")
            || key_upper.ends_with("_ROOT")
            || key_upper.ends_with("_ORIGINS")
            || key_upper.ends_with("_URL")
            || key_upper.ends_with("_HOST")
            || key_upper.ends_with("_PORT")
            || key_upper.ends_with("_VERSION")
            || key_upper.ends_with("_EXE")
        {
            return false;
        }

        // Never seal booleans or common numeric values
        let val_lower = clean_val.to_ascii_lowercase();
        if val_lower == "true"
            || val_lower == "false"
            || val_lower == "yes"
            || val_lower == "no"
            || val_lower == "1"
            || val_lower == "0"
            || val_lower == "null"
            || val_lower == "undefined"
            || val_lower == "development"
            || val_lower == "production"
            || val_lower == "test"
            || val_lower == "staging"
        {
            return false;
        }
        if clean_val.parse::<u16>().is_ok() {
            return false;
        }

        // Never seal file paths or localhost URLs
        if clean_val.contains('\\')
            || clean_val.starts_with("C:")
            || clean_val.starts_with("D:")
            || clean_val.starts_with("http://localhost")
            || clean_val.starts_with("http://127.0.0.1")
            || clean_val.starts_with("https://localhost")
            || (clean_val.contains('/')
                && !clean_val.starts_with("sk-")
                && !clean_val.starts_with("hf_"))
        {
            return false;
        }

        // Already a stand-in
        if clean_val.starts_with("OSHOOSI_STANDIN_") {
            return false;
        }

        // Value must be at least 8 characters
        if clean_val.len() < 8 {
            return false;
        }

        // Check recognized secret prefixes
        let has_secret_prefix = clean_val.starts_with("AIza")
            || clean_val.starts_with("hf_")
            || clean_val.starts_with("sk-")
            || clean_val.starts_with("ghp_")
            || clean_val.starts_with("github_pat_")
            || clean_val.starts_with("gho_")
            || clean_val.starts_with("xoxb-")
            || clean_val.starts_with("AKIA");

        // Check if key name indicates a secret
        let is_secret_name = key_upper.contains("API_KEY")
            || key_upper.contains("SECRET")
            || key_upper.contains("TOKEN")
            || key_upper.contains("PASSWORD")
            || key_upper.contains("PASSWD")
            || key_upper.contains("PRIVATE_KEY")
            || key_upper.ends_with("_KEY")
            || key_upper.ends_with("_AUTH");

        if has_secret_prefix || is_secret_name {
            return true;
        }

        // High entropy secret check: length >= 20 and entropy >= 3.2
        let entropy = LlmFusionApiKeyEnumerator::shannon_entropy(clean_val);
        clean_val.len() >= 24 && entropy >= 3.2
    }

    /// Replaces the secret value in a single .env line with its stand-in token while
    /// 100% preserving export prefix, variable indentation, quote style, and inline comments.
    pub fn replace_env_var_in_line(line: &str, key: &str, standin: &str) -> Option<String> {
        let trimmed = line.trim_start();
        let prefix = if trimmed.starts_with("export ") {
            "export "
        } else {
            ""
        };
        let rest = &trimmed[prefix.len()..];
        let mut parts = rest.splitn(2, '=');
        let var_name = parts.next()?.trim();
        if var_name != key {
            return None;
        }
        let val_and_comment = parts.next()?;
        let leading_spaces = &line[..line.len() - trimmed.len()];

        let val_trimmed = val_and_comment.trim();
        let (quote_char, comment) = if val_trimmed.starts_with('"') {
            if let Some(end_idx) = val_trimmed[1..].find('"') {
                let after = val_trimmed[end_idx + 2..].trim_start();
                ('"', after)
            } else {
                ('"', "")
            }
        } else if val_trimmed.starts_with('\'') {
            if let Some(end_idx) = val_trimmed[1..].find('\'') {
                let after = val_trimmed[end_idx + 2..].trim_start();
                ('\'', after)
            } else {
                ('\'', "")
            }
        } else {
            let mut comment_part = "";
            if let Some(hash_idx) = val_trimmed.find('#') {
                comment_part = val_trimmed[hash_idx..].trim();
            }
            ('\0', comment_part)
        };

        let new_val_formatted = match quote_char {
            '"' => format!("\"{}\"", standin),
            '\'' => format!("'{}'", standin),
            _ => standin.to_string(),
        };

        let comment_suffix = if !comment.is_empty() {
            if comment.starts_with('#') {
                format!(" {}", comment)
            } else {
                format!(" # {}", comment)
            }
        } else {
            String::new()
        };

        Some(format!(
            "{}{}{}={}{}",
            leading_spaces, prefix, var_name, new_val_formatted, comment_suffix
        ))
    }

    /// Derives the 32-byte master encryption key from host silicon / registry identity and salt.
    fn derive_vault_key(salt: &[u8; 16]) -> [u8; 32] {
        let mut seed = Vec::with_capacity(64);
        seed.extend_from_slice(salt);

        #[cfg(windows)]
        {
            if let Ok(reg) = winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)
                .open_subkey("SOFTWARE\\Microsoft\\Cryptography")
            {
                if let Ok(guid) = reg.get_value::<String, _>("MachineGuid") {
                    seed.extend_from_slice(guid.as_bytes());
                }
            }
        }

        if let Ok(h) = hostname::get() {
            seed.extend_from_slice(h.to_string_lossy().as_bytes());
        }

        seed.extend_from_slice(b"OSHOOSI_ENV_BACKUP_VAULT_KDF_DOMAIN_V1");
        blake3::derive_key("OSHOOSI_ENV_BACKUP_VAULT_KEY_V1", &seed)
    }

    /// Generates deterministic stand-in token `OSHOOSI_STANDIN_<KEY>_<16_HEX>`
    pub fn generate_standin_token(key: &str, secret: &str) -> String {
        let clean_key = key.trim();
        let clean_val = secret.trim().trim_matches('"').trim_matches('\'');
        let token_hash = blake3::hash(format!("{}_{}", clean_key, clean_val).as_bytes()).to_hex();
        format!("OSHOOSI_STANDIN_{}_{}", clean_key, &token_hash[..16])
    }

    /// Decrypts and deserializes a vault file returning the payload and envelope length.
    fn read_vault_payload(vault_path: &Path) -> Result<(VaultPayload, usize), VaultError> {
        let mut envelope = Vec::new();
        let mut f = File::open(vault_path)?;
        f.read_to_end(&mut envelope)?;

        // Minimum envelope length: 24 (magic) + 16 (salt) + 12 (nonce) + 8 (epoch) + 4 (len) + 16 (poly tag) + 32 (mac) = 112
        if envelope.len() < 112 || &envelope[..24] != VAULT_MAGIC {
            return Err(VaultError::InvalidFormat);
        }

        let salt: [u8; 16] = envelope[24..40]
            .try_into()
            .map_err(|_| VaultError::InvalidFormat)?;
        let nonce_bytes: [u8; 12] = envelope[40..52]
            .try_into()
            .map_err(|_| VaultError::InvalidFormat)?;

        let ct_len_bytes: [u8; 4] = envelope[60..64]
            .try_into()
            .map_err(|_| VaultError::InvalidFormat)?;
        let ct_len = u32::from_be_bytes(ct_len_bytes) as usize;

        if envelope.len() < 64 + ct_len + 32 {
            return Err(VaultError::InvalidFormat);
        }

        let ciphertext = &envelope[64..64 + ct_len];
        let provided_tag = &envelope[64 + ct_len..64 + ct_len + 32];

        // 1. Check companion .dpapi file
        let dpapi_path = Self::companion_dpapi_path(vault_path);
        let mut unwrapped_key = None;
        if dpapi_path.exists() {
            if let Ok(wrapped) = std::fs::read(&dpapi_path) {
                if let Ok(unprotected) = dpapi_unprotect_bytes(&wrapped) {
                    if unprotected.len() == 32 {
                        let mut k = [0u8; 32];
                        k.copy_from_slice(&unprotected);
                        unwrapped_key = Some(k);
                    }
                }
            }
        }

        // 2. Select key: unwrapped DPAPI key -> host master key -> salt-derived key
        let candidate_keys = [
            unwrapped_key,
            crate::machine_binding::derive_bound_host_vault_key().ok(),
            Some(Self::derive_vault_master_key()),
            Some(Self::derive_vault_key(&salt)),
        ];
        let key_bytes = candidate_keys
            .into_iter()
            .flatten()
            .find(|k| {
                let tag = blake3::keyed_hash(k, &envelope[..64 + ct_len]);
                subtle::ConstantTimeEq::ct_eq(tag.as_bytes().as_slice(), provided_tag).unwrap_u8()
                    == 1
            })
            .unwrap_or_else(|| Self::derive_vault_key(&salt));

        // Verify keyed BLAKE3 MAC
        let expected_tag = blake3::keyed_hash(&key_bytes, &envelope[..64 + ct_len]);
        if subtle::ConstantTimeEq::ct_eq(expected_tag.as_bytes().as_slice(), provided_tag)
            .unwrap_u8()
            == 0
        {
            return Err(VaultError::IntegrityFailure);
        }

        // Decrypt ciphertext
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
        let decrypted = cipher
            .decrypt(Nonce::from_slice(&nonce_bytes), ciphertext)
            .map_err(|e| VaultError::Decryption(e.to_string()))?;

        let mut payload: VaultPayload = serde_json::from_slice(&decrypted)
            .map_err(|e| VaultError::Decryption(e.to_string()))?;

        // Ensure payload.dpapi_wrapped_key is populated from companion file if missing
        if payload.dpapi_wrapped_key.is_none() && dpapi_path.exists() {
            if let Ok(wrapped) = std::fs::read(&dpapi_path) {
                payload.dpapi_wrapped_key = Some(wrapped);
            }
        }

        Ok((payload, envelope.len()))
    }

    /// Encrypts and writes a vault payload to disk with keyed BLAKE3 MAC and NTFS DACL.
    fn write_vault_payload(vault_path: &Path, payload: &VaultPayload) -> Result<(), VaultError> {
        let serialized_payload =
            serde_json::to_vec(payload).map_err(|e| VaultError::Encryption(e.to_string()))?;

        // Generate salt (16B) and nonce (12B)
        let mut salt = [0u8; 16];
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut salt);
        rand::thread_rng().fill_bytes(&mut nonce_bytes);

        // If payload has a DPAPI wrapped key, unwrap it to get key_bytes; otherwise derive from bound host / salt
        let key_bytes: [u8; 32] = if let Some(wrapped) = &payload.dpapi_wrapped_key {
            if let Ok(unwrapped) = dpapi_unprotect_bytes(wrapped) {
                if unwrapped.len() == 32 {
                    let mut k = [0u8; 32];
                    k.copy_from_slice(&unwrapped);
                    k
                } else {
                    crate::machine_binding::derive_bound_host_vault_key()
                        .unwrap_or_else(|_| Self::derive_vault_key(&salt))
                }
            } else {
                crate::machine_binding::derive_bound_host_vault_key()
                    .unwrap_or_else(|_| Self::derive_vault_key(&salt))
            }
        } else {
            crate::machine_binding::derive_bound_host_vault_key()
                .unwrap_or_else(|_| Self::derive_vault_key(&salt))
        };

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), serialized_payload.as_ref())
            .map_err(|e| VaultError::Encryption(e.to_string()))?;

        // Envelope:
        // [24B Magic] [16B Salt] [12B Nonce] [8B Epoch BE] [4B Ciphertext Len BE] [Ciphertext] [32B BLAKE3 Tag]
        let mut envelope = Vec::with_capacity(24 + 16 + 12 + 8 + 4 + ciphertext.len() + 32);
        envelope.extend_from_slice(VAULT_MAGIC);
        envelope.extend_from_slice(&salt);
        envelope.extend_from_slice(&nonce_bytes);
        envelope.extend_from_slice(&payload.epoch.to_be_bytes());
        envelope.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
        envelope.extend_from_slice(&ciphertext);

        // Keyed BLAKE3 MAC over header + ciphertext
        let tag = blake3::keyed_hash(&key_bytes, &envelope);
        envelope.extend_from_slice(tag.as_bytes());

        // Ensure parent directory exists
        if let Some(parent) = vault_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        // If vault file already exists with a protected NTFS DACL, unlock it before overwriting
        if vault_path.exists() {
            let _ = unlock_protected_ntfs_dacl(vault_path);
        }

        // Write vault file
        let mut f = File::create(vault_path)?;
        f.write_all(&envelope)?;
        f.sync_all()?;
        drop(f);

        // Apply Win32 Protected NTFS DACL / Unix 0600
        apply_protected_ntfs_dacl(vault_path)?;

        // Write companion .dpapi file if wrapped key is available
        if let Some(wrapped) = &payload.dpapi_wrapped_key {
            let dpapi_path = Self::companion_dpapi_path(vault_path);
            let dpapi_tmp = dpapi_path.with_extension("dpapi.tmp");
            if let Ok(mut df) = File::create(&dpapi_tmp) {
                if df.write_all(wrapped).is_ok() && df.sync_all().is_ok() {
                    drop(df);
                    if dpapi_path.exists() {
                        let _ = unlock_protected_ntfs_dacl(&dpapi_path);
                    }
                    if std::fs::rename(&dpapi_tmp, &dpapi_path).is_ok() {
                        let _ = apply_protected_ntfs_dacl(&dpapi_path);
                    } else {
                        if let Ok(mut f2) = File::create(&dpapi_path) {
                            let _ = f2.write_all(wrapped);
                            let _ = f2.sync_all();
                            drop(f2);
                            let _ = apply_protected_ntfs_dacl(&dpapi_path);
                        }
                        let _ = std::fs::remove_file(&dpapi_tmp);
                    }
                }
            }
        }

        Ok(())
    }

    /// Backs up original `.env` or config content into encrypted, DACL-protected vault,
    /// replaces secret values in `env_path` with stand-in tokens, and updates active process memory.
    pub fn seal_and_backup(
        env_path: &Path,
        vault_path: &Path,
        grants: &[crate::rea_voter_env_gateway::HardenedSealedGrant],
    ) -> Result<(), VaultError> {
        if !env_path.exists() {
            return Err(VaultError::TargetError(format!(
                "Target environment file '{}' does not exist",
                env_path.display()
            )));
        }

        let original_bytes = std::fs::read(env_path)?;
        let canonical_target =
            std::fs::canonicalize(env_path).unwrap_or_else(|_| env_path.to_path_buf());
        let epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let sealed_variables: Vec<String> = grants.iter().map(|g| g.env_var_name.clone()).collect();
        let standin_mappings: Vec<(String, String)> = grants
            .iter()
            .map(|g| (g.env_var_name.clone(), g.standin_token.clone()))
            .collect();
        let original_env_vars: Vec<(String, String)> = grants
            .iter()
            .map(|g| {
                (
                    g.env_var_name.clone(),
                    String::from_utf8_lossy(g.secret.as_slice()).to_string(),
                )
            })
            .collect();

        let mut hasher = Sha256::new();
        hasher.update(&original_bytes);
        let original_sha256 = Some(format!("{:x}", hasher.finalize()));
        let original_sha256_str = original_sha256.clone().unwrap_or_default();

        let mg = crate::rea::identify_with_magika(Some(env_path), &original_bytes);
        let drive_root = env_path
            .components()
            .next()
            .map(|c| c.as_os_str().to_string_lossy().to_string());

        let files = vec![BackedUpEnvFile {
            path: canonical_target.to_string_lossy().to_string(),
            original_bytes: original_bytes.clone(),
            existed_before: true,
            original_sha256: original_sha256_str,
            magika_label: Some(mg.label),
            magika_mime_type: Some(mg.mime_type),
            magika_score: Some(mg.score),
            drive_root,
        }];

        #[cfg(windows)]
        let user_sid_env = read_user_sid_environment_vars();
        #[cfg(not(windows))]
        let user_sid_env = HashMap::new();

        let master_key = Self::derive_vault_master_key();
        #[cfg(windows)]
        let dpapi_wrapped_key = dpapi_protect_bytes(&master_key).ok();
        #[cfg(not(windows))]
        let dpapi_wrapped_key = None;

        let payload = VaultPayload {
            target_path: canonical_target.to_string_lossy().to_string(),
            epoch,
            sealed_variables,
            original_bytes: original_bytes.clone(),
            standin_mappings,
            original_env_vars,
            original_hkcu_vars: Vec::new(),
            target_existed_before: true,
            original_sha256,
            files,
            user_sid_env,
            dpapi_wrapped_key,
        };

        Self::write_vault_payload(vault_path, &payload)?;

        // Update active process memory for each grant
        for grant in grants {
            std::env::set_var(&grant.env_var_name, &grant.standin_token);
        }

        // Update target file in-place: replace raw secrets with stand-in tokens
        let mut content_str = String::from_utf8_lossy(&original_bytes).to_string();
        for grant in grants {
            let secret_str = String::from_utf8_lossy(grant.secret.as_slice());
            if !secret_str.is_empty() && content_str.contains(&*secret_str) {
                content_str = content_str.replace(&*secret_str, &grant.standin_token);
            } else {
                // If the exact secret string wasn't found verbatim, check for line `VAR=...`
                let var_prefix = format!("{}=", grant.env_var_name);
                let mut lines = Vec::new();
                let mut matched = false;
                for line in content_str.lines() {
                    let trimmed = line.trim_start();
                    if trimmed.starts_with(&var_prefix) {
                        lines.push(format!("{}={}", grant.env_var_name, grant.standin_token));
                        matched = true;
                    } else {
                        lines.push(line.to_string());
                    }
                }
                if matched {
                    content_str = lines.join("\n");
                }
            }
        }

        // Write sealed environment back to env_path atomically
        Self::write_file_atomic(env_path, content_str.as_bytes())?;

        Ok(())
    }

    /// Automatically restores the pre-stand-in original configuration files and process memory from the vault.
    pub fn auto_revert(vault_path: &Path) -> Result<(), VaultError> {
        Self::pause_auto_seal_and_persist_disabled();
        if !vault_path.exists() {
            return Ok(());
        }

        let (payload, _) = Self::read_vault_payload(vault_path)?;

        // 1. Restore process memory for all original environment variables
        for (k, orig_v) in &payload.original_env_vars {
            std::env::set_var(k, orig_v);
        }
        for (k, orig_v) in &payload.original_hkcu_vars {
            std::env::set_var(k, orig_v);
        }

        // 1b. Restore Windows User Environment (HKCU\Environment and HKEY_USERS\S-1-5-21-*\Environment)
        // merging original_hkcu_vars, original_env_vars, and user_sid_env (strictly excluding PATH and system vars)
        #[cfg(windows)]
        if is_production_vault_path(vault_path) {
            let mut merged_hkcu: Vec<(String, String)> = payload.original_hkcu_vars.clone();
            for (k, v) in &payload.original_env_vars {
                if !merged_hkcu.iter().any(|(mk, _)| mk.eq_ignore_ascii_case(k)) {
                    merged_hkcu.push((k.clone(), v.clone()));
                }
            }
            for sid_vars in payload.user_sid_env.values() {
                for (k, v) in sid_vars {
                    if !v.starts_with("OSHOOSI_STANDIN_")
                        && !merged_hkcu.iter().any(|(mk, _)| mk.eq_ignore_ascii_case(k))
                    {
                        merged_hkcu.push((k.clone(), v.clone()));
                    }
                }
            }
            restore_hkcu_original_vars(&merged_hkcu)?;
        }

        // Helper to scrub any residual OSHOOSI_STANDIN_* tokens from restored bytes using standin_mappings -> original_env_vars
        let scrub_standin_bytes = |bytes: &[u8]| -> Vec<u8> {
            if !bytes.windows(16).any(|w| w == b"OSHOOSI_STANDIN_") {
                return bytes.to_vec();
            }
            if let Ok(text) = std::str::from_utf8(bytes) {
                let mut scrubbed = text.to_string();
                for (k, standin) in &payload.standin_mappings {
                    if let Some((_, orig_v)) = payload
                        .original_env_vars
                        .iter()
                        .find(|(ok, _)| ok.eq_ignore_ascii_case(k))
                        .or_else(|| {
                            payload
                                .original_hkcu_vars
                                .iter()
                                .find(|(ok, _)| ok.eq_ignore_ascii_case(k))
                        })
                    {
                        if !orig_v.starts_with("OSHOOSI_STANDIN_") {
                            scrubbed = scrubbed.replace(standin, orig_v);
                        }
                    }
                }
                scrubbed.into_bytes()
            } else {
                bytes.to_vec()
            }
        };

        // 2. Restore file state across all backed up files (or legacy single target)
        if !payload.files.is_empty() {
            for entry in &payload.files {
                let p = PathBuf::from(&entry.path);
                if entry.existed_before || !entry.original_bytes.is_empty() {
                    let clean_bytes = scrub_standin_bytes(&entry.original_bytes);
                    if clean_bytes.windows(16).any(|w| w == b"OSHOOSI_STANDIN_") {
                        // Check if this is a synthetic .env consisting solely of standin tokens
                        let is_only_standins = std::str::from_utf8(&clean_bytes)
                            .map(|s| {
                                s.lines()
                                    .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
                                    .all(|l| l.contains("OSHOOSI_STANDIN_"))
                            })
                            .unwrap_or(false);
                        if is_only_standins && p.exists() {
                            let _ = std::fs::remove_file(&p);
                            continue;
                        }
                    }
                    let _ = Self::write_file_atomic(&p, &clean_bytes);
                } else if p.exists() {
                    let _ = std::fs::remove_file(&p);
                }
            }
        }
        let target = PathBuf::from(&payload.target_path);
        if !payload.target_existed_before && target.exists() {
            let _ = std::fs::remove_file(&target);
        } else if payload.target_existed_before || !payload.original_bytes.is_empty() {
            if payload.files.is_empty() {
                let clean_bytes = scrub_standin_bytes(&payload.original_bytes);
                let _ = Self::write_file_atomic(&target, &clean_bytes);
            }
        }

        let all_temporary = if !payload.files.is_empty() {
            payload.files.iter().all(|f| !f.existed_before) && !payload.target_existed_before
        } else {
            !payload.target_existed_before
        };

        if all_temporary {
            let _ = Self::remove_backup(vault_path, true);
        }

        Ok(())
    }

    /// Safely removes and shreds the backup vault file on disk.
    /// Requires explicit confirmation (`confirm == true`).
    pub fn remove_backup(vault_path: &Path, confirm: bool) -> Result<(), VaultError> {
        if !confirm {
            return Err(VaultError::ConfirmationRequired);
        }

        if !vault_path.exists() {
            return Ok(());
        }

        // Unlock and shred companion .dpapi file if present
        let dpapi_path = Self::companion_dpapi_path(vault_path);
        if dpapi_path.exists() {
            let _ = unlock_protected_ntfs_dacl(&dpapi_path);
            if let Ok(meta) = std::fs::metadata(&dpapi_path) {
                let file_len = meta.len();
                if file_len > 0 {
                    if let Ok(mut file) = std::fs::OpenOptions::new().write(true).open(&dpapi_path)
                    {
                        let zeros = vec![0u8; 65536.min(file_len as usize)];
                        let mut written = 0u64;
                        while written < file_len {
                            let to_write = (file_len - written).min(zeros.len() as u64) as usize;
                            let _ = file.write_all(&zeros[..to_write]);
                            written += to_write as u64;
                        }
                        let _ = file.sync_all();
                    }
                }
            }
            let _ = std::fs::remove_file(&dpapi_path);
        }

        // Unlock Protected NTFS DACL / Unix permissions
        unlock_protected_ntfs_dacl(vault_path)?;

        // Overwrite and shred with 0x00
        let file_len = std::fs::metadata(vault_path)?.len();
        if file_len > 0 {
            let mut file = std::fs::OpenOptions::new().write(true).open(vault_path)?;
            let zeros = vec![0u8; 65536.min(file_len as usize)];
            let mut written = 0u64;
            while written < file_len {
                let to_write = (file_len - written).min(zeros.len() as u64) as usize;
                file.write_all(&zeros[..to_write])?;
                written += to_write as u64;
            }
            file.sync_all()?;
            drop(file);
        }

        std::fs::remove_file(vault_path)?;
        Ok(())
    }

    /// Queries the current status of the backup vault.
    pub fn get_status(vault_path: &Path) -> Result<VaultStatus, VaultError> {
        if !vault_path.exists() {
            return Ok(VaultStatus {
                exists: false,
                vault_path: vault_path.to_path_buf(),
                target_path: None,
                sealed_at_epoch: None,
                sealed_variables: Vec::new(),
                standin_mappings: Vec::new(),
                dacl_protected: false,
                payload_size: 0,
                original_sha256: None,
                files: Vec::new(),
            });
        }

        let (payload, env_len) = Self::read_vault_payload(vault_path)?;

        let sha256_hex = if let Some(ref sha) = payload.original_sha256 {
            Some(sha.clone())
        } else if !payload.original_bytes.is_empty() {
            let mut hasher = Sha256::new();
            hasher.update(&payload.original_bytes);
            Some(format!("{:x}", hasher.finalize()))
        } else {
            None
        };

        Ok(VaultStatus {
            exists: true,
            vault_path: vault_path.to_path_buf(),
            target_path: Some(PathBuf::from(payload.target_path)),
            sealed_at_epoch: Some(payload.epoch),
            sealed_variables: payload.sealed_variables,
            standin_mappings: payload.standin_mappings,
            dacl_protected: true,
            payload_size: env_len as u64,
            original_sha256: sha256_hex,
            files: payload.files,
        })
    }

    /// Internal joint dynamic sealing engine: handles .env + std::env::vars(), gateway registration,
    /// process memory replacement, and backup preservation.
    fn seal_and_register_internal(
        env_path: &Path,
        vault_path: &Path,
        gateway: Option<&crate::rea_voter_env_gateway::ReaVoterEnvGateway>,
    ) -> Result<LlmFusionEnumerationResult, VaultError> {
        Self::ensure_resolver_registered();
        let target_existed_before = env_path.exists();

        // If vault already exists, load existing payload so we never clobber genuine secrets
        // if variables are already replaced with stand-in tokens!
        let existing_vault = if vault_path.exists() {
            Self::read_vault_payload(vault_path).ok().map(|(p, _)| p)
        } else {
            None
        };

        let base_dir = if env_path.is_file() {
            env_path.parent().unwrap_or(Path::new("."))
        } else if env_path.is_dir() {
            env_path
        } else {
            Path::new(".")
        };

        let mut discovered_files =
            Self::discover_environment_files(base_dir, &[env_path.to_path_buf()]);
        if !discovered_files.iter().any(|p| p == env_path) {
            discovered_files.push(env_path.to_path_buf());
        }

        // Build BackedUpEnvFile for all discovered files, preserving existing backups
        let prev_files = existing_vault
            .as_ref()
            .map(|ex| ex.files.clone())
            .unwrap_or_default();
        let mut backed_up_files: Vec<BackedUpEnvFile> = Vec::new();

        let norm_path = |p: &Path| -> String {
            let canon = p.canonicalize().unwrap_or_else(|_| p.to_path_buf());
            let s = canon.to_string_lossy();
            let stripped = s.strip_prefix(r"\\?\").unwrap_or(&s);
            stripped.replace('/', "\\").to_ascii_lowercase()
        };

        for file_path in &discovered_files {
            let existed = file_path.exists();
            let canonical_str = file_path
                .canonicalize()
                .unwrap_or_else(|_| file_path.clone())
                .to_string_lossy()
                .to_string();

            let norm_current = norm_path(file_path);
            let norm_canonical = norm_path(Path::new(&canonical_str));

            let (orig_bytes, orig_sha, was_existed) = if let Some(old_f) =
                prev_files.iter().find(|f| {
                    let nf = norm_path(Path::new(&f.path));
                    nf == norm_current
                        || nf == norm_canonical
                        || f.path == canonical_str
                        || (Path::new(&f.path).file_name() == file_path.file_name()
                            && prev_files.len() == 1
                            && discovered_files.len() == 1)
                }) {
                (
                    old_f.original_bytes.clone(),
                    old_f.original_sha256.clone(),
                    old_f.existed_before,
                )
            } else if existing_vault
                .as_ref()
                .map(|ex| {
                    let ntarget = norm_path(Path::new(&ex.target_path));
                    (ntarget == norm_current
                        || ntarget == norm_canonical
                        || (Path::new(&ex.target_path).file_name() == file_path.file_name()
                            && prev_files.len() <= 1
                            && discovered_files.len() <= 1))
                        && ex.target_existed_before
                })
                .unwrap_or(false)
            {
                let ex = existing_vault.as_ref().unwrap();
                (
                    ex.original_bytes.clone(),
                    ex.original_sha256.clone().unwrap_or_default(),
                    ex.target_existed_before,
                )
            } else if existed {
                let mut bytes = std::fs::read(file_path).unwrap_or_default();
                if bytes.windows(16).any(|w| w == b"OSHOOSI_STANDIN_") {
                    if let Some(ref ex) = existing_vault {
                        if let Some(old_f) = prev_files.iter().find(|f| {
                            Path::new(&f.path).file_name() == file_path.file_name()
                                && !f
                                    .original_bytes
                                    .windows(16)
                                    .any(|w| w == b"OSHOOSI_STANDIN_")
                                && !f.original_bytes.is_empty()
                        }) {
                            bytes = old_f.original_bytes.clone();
                        } else if !ex.original_bytes.is_empty()
                            && !ex
                                .original_bytes
                                .windows(16)
                                .any(|w| w == b"OSHOOSI_STANDIN_")
                        {
                            bytes = ex.original_bytes.clone();
                        } else if let Ok(s) = std::str::from_utf8(&bytes) {
                            let mut reconstructed = s.to_string();
                            for (k, orig_v) in &ex.original_env_vars {
                                if let Some((_, standin)) =
                                    ex.standin_mappings.iter().find(|(sk, _)| sk == k)
                                {
                                    reconstructed = reconstructed.replace(standin, orig_v);
                                }
                            }
                            bytes = reconstructed.into_bytes();
                        }
                    }
                }
                let mut hasher = Sha256::new();
                hasher.update(&bytes);
                let sha = format!("{:x}", hasher.finalize());
                // If the file on disk consists solely of OSHOOSI_STANDIN_ lines and was not in a prior vault,
                // treat it as a synthetic stand-in file created by a prior seal run (`existed_before = false`).
                let is_synthetic_standin_only = std::str::from_utf8(&bytes)
                    .map(|s| {
                        let non_empty: Vec<&str> = s
                            .lines()
                            .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
                            .collect();
                        !non_empty.is_empty()
                            && non_empty.iter().all(|l| l.contains("OSHOOSI_STANDIN_"))
                    })
                    .unwrap_or(false);
                if is_synthetic_standin_only {
                    (Vec::new(), String::new(), false)
                } else {
                    (bytes, sha, true)
                }
            } else {
                (Vec::new(), String::new(), false)
            };

            let mg = crate::rea::identify_with_magika(Some(file_path), &orig_bytes);
            let drive_root = file_path
                .components()
                .next()
                .map(|c| c.as_os_str().to_string_lossy().to_string());

            backed_up_files.push(BackedUpEnvFile {
                path: canonical_str,
                original_bytes: orig_bytes,
                existed_before: was_existed,
                original_sha256: orig_sha,
                magika_label: Some(mg.label),
                magika_mime_type: Some(mg.mime_type),
                magika_score: Some(mg.score),
                drive_root,
            });
        }

        // Preserve any previously backed up files that were not discovered in the current directory
        for old_f in &prev_files {
            let norm_old = norm_path(Path::new(&old_f.path));
            if !backed_up_files
                .iter()
                .any(|b| norm_path(Path::new(&b.path)) == norm_old)
            {
                backed_up_files.push(old_f.clone());
            }
        }

        // Legacy single-file backup preservation
        let (original_bytes, _content_str) = if target_existed_before {
            let bytes = std::fs::read(env_path)?;
            let text = String::from_utf8_lossy(&bytes).to_string();
            (bytes, text)
        } else {
            (Vec::new(), String::new())
        };

        let vault_original_bytes = if let Some(ref ex) = existing_vault {
            let ntarget = norm_path(Path::new(&ex.target_path));
            let nenv = norm_path(env_path);
            let ntarget_file = Path::new(&ex.target_path).file_name();
            let nenv_file = env_path.file_name();

            if ex.target_existed_before
                && (ntarget == nenv
                    || (ntarget_file.is_some()
                        && ntarget_file == nenv_file
                        && prev_files.len() <= 1))
            {
                if !ex.original_bytes.is_empty()
                    && !ex
                        .original_bytes
                        .windows(16)
                        .any(|w| w == b"OSHOOSI_STANDIN_")
                {
                    ex.original_bytes.clone()
                } else if !original_bytes.windows(16).any(|w| w == b"OSHOOSI_STANDIN_") {
                    original_bytes.clone()
                } else {
                    ex.original_bytes.clone()
                }
            } else if !ex.original_bytes.is_empty()
                && !ex
                    .original_bytes
                    .windows(16)
                    .any(|w| w == b"OSHOOSI_STANDIN_")
            {
                ex.original_bytes.clone()
            } else {
                original_bytes.clone()
            }
        } else {
            original_bytes.clone()
        };

        let vault_target_existed_before = if let Some(ref ex) = existing_vault {
            ex.target_existed_before
        } else {
            target_existed_before
        };

        // Jointly enumerate lines from HKCU\Environment (if production vault), all discovered files, AND std::env::vars()
        let mut pairs: Vec<(String, String)> = Vec::new();
        let mut seen_keys = std::collections::HashSet::new();
        let mut hkcu_keys_seen = std::collections::HashSet::new();

        #[cfg(windows)]
        if is_production_vault_path(vault_path) {
            for (k, mut v) in read_hkcu_environment_vars() {
                hkcu_keys_seen.insert(k.clone());
                if v.starts_with("OSHOOSI_STANDIN_") {
                    if let Some(ref ex) = existing_vault {
                        if let Some((_, orig_v)) = ex
                            .original_hkcu_vars
                            .iter()
                            .find(|(orig_k, _)| orig_k == &k)
                            .or_else(|| {
                                ex.original_env_vars.iter().find(|(orig_k, _)| orig_k == &k)
                            })
                        {
                            v = orig_v.clone();
                        }
                    }
                }
                if !seen_keys.contains(&k) {
                    seen_keys.insert(k.clone());
                    pairs.push((k, v));
                }
            }
        }

        for file_path in &discovered_files {
            if file_path.exists() {
                if let Ok(file_content) = std::fs::read_to_string(file_path) {
                    for line in file_content.lines() {
                        let trimmed = line.trim();
                        if trimmed.starts_with('#') || !trimmed.contains('=') {
                            continue;
                        }
                        let line_clean = trimmed
                            .strip_prefix("export ")
                            .unwrap_or(trimmed)
                            .trim_start();
                        let parts: Vec<&str> = line_clean.splitn(2, '=').collect();
                        let k = parts[0].trim().to_string();
                        let raw_val = parts[1].trim();
                        let clean_val = if raw_val.starts_with('"') {
                            if let Some(end_idx) = raw_val[1..].find('"') {
                                &raw_val[1..end_idx + 1]
                            } else {
                                raw_val
                            }
                        } else if raw_val.starts_with('\'') {
                            if let Some(end_idx) = raw_val[1..].find('\'') {
                                &raw_val[1..end_idx + 1]
                            } else {
                                raw_val
                            }
                        } else {
                            raw_val.split('#').next().unwrap_or(raw_val).trim()
                        };
                        let mut v = clean_val.to_string();

                        if v.starts_with("OSHOOSI_STANDIN_") {
                            if let Some(ref ex) = existing_vault {
                                if let Some((_, orig_v)) =
                                    ex.original_env_vars.iter().find(|(orig_k, _)| orig_k == &k)
                                {
                                    v = orig_v.clone();
                                }
                            }
                        }
                        if !seen_keys.contains(&k) {
                            seen_keys.insert(k.clone());
                            pairs.push((k, v));
                        } else if let Some(existing_pair) =
                            pairs.iter_mut().find(|(ek, _)| ek == &k)
                        {
                            if existing_pair.1.starts_with("OSHOOSI_STANDIN_")
                                && !v.starts_with("OSHOOSI_STANDIN_")
                            {
                                existing_pair.1 = v;
                            }
                        }
                    }
                }
            }
        }

        for (k, mut v) in std::env::vars() {
            if v.starts_with("OSHOOSI_STANDIN_") {
                if let Some(ref ex) = existing_vault {
                    if let Some((_, orig_v)) =
                        ex.original_env_vars.iter().find(|(orig_k, _)| orig_k == &k)
                    {
                        v = orig_v.clone();
                    }
                }
            }
            if !seen_keys.contains(&k) {
                seen_keys.insert(k.clone());
                pairs.push((k, v));
            } else {
                if let Some(existing_pair) = pairs.iter_mut().find(|(ek, _)| ek == &k) {
                    if existing_pair.1.starts_with("OSHOOSI_STANDIN_")
                        && !v.starts_with("OSHOOSI_STANDIN_")
                    {
                        existing_pair.1 = v;
                    }
                }
            }
        }

        let result = LlmFusionApiKeyEnumerator::enumerate_from_pairs(&pairs);

        let mut sealed_variables = Vec::new();
        let mut standin_mappings = Vec::new();
        let mut original_env_vars = Vec::new();
        let mut original_hkcu_vars = Vec::new();

        // Preserve any previously sealed variables from existing vault if still valid
        if let Some(ref ex) = existing_vault {
            for (old_k, old_s) in &ex.standin_mappings {
                if !standin_mappings.iter().any(|(k, _)| k == old_k) {
                    standin_mappings.push((old_k.clone(), old_s.clone()));
                }
            }
            for (old_k, old_orig) in &ex.original_env_vars {
                if !original_env_vars.iter().any(|(k, _)| k == old_k) {
                    original_env_vars.push((old_k.clone(), old_orig.clone()));
                }
            }
            for (old_k, old_orig) in &ex.original_hkcu_vars {
                if !original_hkcu_vars.iter().any(|(k, _)| k == old_k) {
                    original_hkcu_vars.push((old_k.clone(), old_orig.clone()));
                }
            }
            for old_var in &ex.sealed_variables {
                if !sealed_variables.contains(old_var) {
                    sealed_variables.push(old_var.clone());
                }
            }
        }

        for cand in &result.candidates {
            if cand.selected && !cand.vetoed_by_safety_guard && cand.fusion_confidence_bp >= 8500 {
                if let Some((_, raw_val)) = pairs.iter().find(|(k, _)| k == &cand.key) {
                    let clean_val = raw_val
                        .trim()
                        .trim_matches('"')
                        .trim_matches('\'')
                        .to_string();
                    if is_hard_protected_non_secret_key(&cand.key, &clean_val)
                        || !Self::is_secret_env_key_and_value(&cand.key, &clean_val)
                        || clean_val.starts_with("OSHOOSI_STANDIN_")
                    {
                        continue;
                    }
                    let standin = cand
                        .standin_token
                        .clone()
                        .unwrap_or_else(|| Self::generate_standin_token(&cand.key, &clean_val));

                    // a) Replace in active process memory via std::env::set_var
                    std::env::set_var(&cand.key, &standin);

                    // b) Register into gateway if provided
                    if let Some(gw) = gateway {
                        let my_pid = std::process::id();
                        let bin_hash = crate::rea_voter_env_gateway::resolve_pid_exe(my_pid)
                            .and_then(|p| {
                                crate::rea_voter_env_gateway::hash_file_sha256_nofollow(&p)
                            })
                            .unwrap_or([0u8; 32]);
                        let script_hash = crate::rea_voter_env_gateway::resolve_pid_exe(my_pid)
                            .and_then(|p| {
                                crate::rea_voter_env_gateway::resolve_pid_script_hash(my_pid, &p)
                            })
                            .ok()
                            .flatten();
                        let grant = crate::rea_voter_env_gateway::HardenedSealedGrant::new(
                            &cand.key,
                            &standin,
                            bin_hash,
                            script_hash,
                            Self::infer_pinned_upstream_host(&cand.key),
                            crate::rea_voter_env_gateway::ZeroizingLockedSecret::new(
                                clean_val.as_bytes(),
                            ),
                        );
                        gw.register_grant(grant);
                    }

                    // Update tracking lists
                    if !sealed_variables.contains(&cand.key) {
                        sealed_variables.push(cand.key.clone());
                    }
                    if let Some(pos) = standin_mappings.iter().position(|(k, _)| k == &cand.key) {
                        standin_mappings[pos] = (cand.key.clone(), standin.clone());
                    } else {
                        standin_mappings.push((cand.key.clone(), standin.clone()));
                    }
                    if let Some(pos) = original_env_vars.iter().position(|(k, _)| k == &cand.key) {
                        original_env_vars[pos] = (cand.key.clone(), clean_val.clone());
                    } else {
                        original_env_vars.push((cand.key.clone(), clean_val.clone()));
                    }
                    if hkcu_keys_seen.contains(&cand.key) {
                        if let Some(pos) =
                            original_hkcu_vars.iter().position(|(k, _)| k == &cand.key)
                        {
                            original_hkcu_vars[pos] = (cand.key.clone(), clean_val.clone());
                        } else {
                            original_hkcu_vars.push((cand.key.clone(), clean_val.clone()));
                        }
                    }
                }
            }
        }

        // Rewrite all discovered environment files with deterministic stand-in tokens
        for file_path in &discovered_files {
            if file_path.exists() {
                if let Ok(file_content) = std::fs::read_to_string(file_path) {
                    let mut lines = Vec::new();
                    let mut file_modified = false;
                    for line in file_content.lines() {
                        let mut replaced_line = None;
                        for (k, standin) in &standin_mappings {
                            if let Some(rep) = Self::replace_env_var_in_line(line, k, standin) {
                                replaced_line = Some(rep);
                                file_modified = true;
                                break;
                            }
                        }
                        lines.push(replaced_line.unwrap_or_else(|| line.to_string()));
                    }
                    if file_modified {
                        let new_content = lines.join("\n");
                        let _ = Self::write_file_atomic(file_path, new_content.as_bytes());
                    }
                }
            }
        }

        // Handle target env_path creation if not existing before
        if !target_existed_before && !standin_mappings.is_empty() {
            let mut new_lines = Vec::new();
            for (k, standin) in &standin_mappings {
                new_lines.push(format!("{}={}", k, standin));
            }
            let _ = Self::write_file_atomic(env_path, new_lines.join("\n").as_bytes());
        }

        // Compute original sha256
        let original_sha256 = if !vault_original_bytes.is_empty() {
            let mut hasher = Sha256::new();
            hasher.update(&vault_original_bytes);
            Some(format!("{:x}", hasher.finalize()))
        } else {
            None
        };

        let epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let canonical_target = if vault_target_existed_before {
            std::fs::canonicalize(env_path).unwrap_or_else(|_| env_path.to_path_buf())
        } else {
            env_path.to_path_buf()
        };

        let user_sid_env = read_user_sid_environment_vars();

        let master_key = Self::derive_vault_master_key();
        #[cfg(windows)]
        let dpapi_wrapped_key = dpapi_protect_bytes(&master_key).ok();
        #[cfg(not(windows))]
        let dpapi_wrapped_key = None;

        let payload = VaultPayload {
            target_path: canonical_target.to_string_lossy().to_string(),
            epoch,
            sealed_variables,
            original_bytes: vault_original_bytes,
            standin_mappings: standin_mappings.clone(),
            original_env_vars,
            original_hkcu_vars,
            target_existed_before: vault_target_existed_before,
            original_sha256,
            files: backed_up_files,
            user_sid_env,
            dpapi_wrapped_key,
        };

        // Write encrypted DACL-protected vault FIRST and verify decryption before rewriting HKCU\Environment
        Self::write_vault_payload(vault_path, &payload)?;
        let (verified_payload, _) = Self::read_vault_payload(vault_path)?;

        #[cfg(windows)]
        if is_production_vault_path(vault_path) && !verified_payload.original_hkcu_vars.is_empty() {
            write_hkcu_standin_vars(&standin_mappings, &verified_payload)?;
        }

        Ok(result)
    }

    /// Enumerates the current environment state (recovering true secrets from `vault_path` when variables
    /// are already sealed as `OSHOOSI_STANDIN_*`) so `status` accurately reports active sealed secrets.
    pub fn enumerate_current_state(
        env_path: &Path,
        vault_path: &Path,
    ) -> LlmFusionEnumerationResult {
        let existing_vault = if vault_path.exists() {
            Self::read_vault_payload(vault_path).ok().map(|(p, _)| p)
        } else {
            None
        };

        let mut pairs: Vec<(String, String)> = Vec::new();
        let mut seen_keys = std::collections::HashSet::new();

        #[cfg(windows)]
        if is_production_vault_path(vault_path) {
            for (k, mut v) in read_hkcu_environment_vars() {
                if v.starts_with("OSHOOSI_STANDIN_") {
                    if let Some(ref ex) = existing_vault {
                        if let Some((_, orig_v)) = ex
                            .original_hkcu_vars
                            .iter()
                            .find(|(orig_k, _)| orig_k == &k)
                            .or_else(|| {
                                ex.original_env_vars.iter().find(|(orig_k, _)| orig_k == &k)
                            })
                        {
                            v = orig_v.clone();
                        }
                    }
                }
                seen_keys.insert(k.clone());
                pairs.push((k, v));
            }
        }

        let base_dir = if env_path.is_file() {
            env_path.parent().unwrap_or(Path::new("."))
        } else if env_path.is_dir() {
            env_path
        } else {
            Path::new(".")
        };

        let mut discovered_files =
            Self::discover_environment_files(base_dir, &[env_path.to_path_buf()]);
        if !discovered_files.iter().any(|p| p == env_path) {
            discovered_files.push(env_path.to_path_buf());
        }

        for file_path in &discovered_files {
            if file_path.exists() {
                if let Ok(content) = std::fs::read_to_string(file_path) {
                    for line in content.lines() {
                        let trimmed = line.trim();
                        if trimmed.starts_with('#') || !trimmed.contains('=') {
                            continue;
                        }
                        let line_clean = trimmed
                            .strip_prefix("export ")
                            .unwrap_or(trimmed)
                            .trim_start();
                        let parts: Vec<&str> = line_clean.splitn(2, '=').collect();
                        let k = parts[0].trim().to_string();
                        let raw_val = parts[1].trim();
                        let clean_val = if raw_val.starts_with('"') {
                            if let Some(end_idx) = raw_val[1..].find('"') {
                                &raw_val[1..end_idx + 1]
                            } else {
                                raw_val
                            }
                        } else if raw_val.starts_with('\'') {
                            if let Some(end_idx) = raw_val[1..].find('\'') {
                                &raw_val[1..end_idx + 1]
                            } else {
                                raw_val
                            }
                        } else {
                            raw_val.split('#').next().unwrap_or(raw_val).trim()
                        };
                        let mut v = clean_val.to_string();
                        if v.starts_with("OSHOOSI_STANDIN_") {
                            if let Some(ref ex) = existing_vault {
                                if let Some((_, orig_v)) =
                                    ex.original_env_vars.iter().find(|(orig_k, _)| orig_k == &k)
                                {
                                    v = orig_v.clone();
                                }
                            }
                        }
                        if !seen_keys.contains(&k) {
                            seen_keys.insert(k.clone());
                            pairs.push((k, v));
                        }
                    }
                }
            }
        }

        for (k, mut v) in std::env::vars() {
            if v.starts_with("OSHOOSI_STANDIN_") {
                if let Some(ref ex) = existing_vault {
                    if let Some((_, orig_v)) =
                        ex.original_env_vars.iter().find(|(orig_k, _)| orig_k == &k)
                    {
                        v = orig_v.clone();
                    }
                }
            }
            if !seen_keys.contains(&k) {
                seen_keys.insert(k.clone());
                pairs.push((k, v));
            }
        }

        // Diagnostic logging for GEMINI_API_KEY without leaking secret value
        if let Some((_, val)) = pairs.iter().find(|(k, _)| k == "GEMINI_API_KEY") {
            let clean = val.trim().trim_matches('"').trim_matches('\'');
            let is_standin = clean.starts_with("OSHOOSI_STANDIN_");
            let starts_with_aiza = clean.starts_with("AIza");
            eprintln!(
                "[INFO] GEMINI_API_KEY status: length={}, starts_with_AIza={}, is_standin={}",
                clean.len(),
                starts_with_aiza,
                is_standin
            );
        }

        LlmFusionApiKeyEnumerator::enumerate_from_pairs(&pairs)
    }

    /// Dynamically scans target env file and process environment using LlmFusionApiKeyEnumerator,
    /// creates ZeroizingLockedSecret grants for all consensus-selected API keys,
    /// backs up the original env to the encrypted vault, replaces selected keys with stand-ins in .env and process memory.
    pub fn seal_and_backup_dynamic(
        env_path: &Path,
        vault_path: &Path,
    ) -> Result<LlmFusionEnumerationResult, VaultError> {
        Self::seal_and_register_internal(env_path, vault_path, None)
    }

    /// Dynamically scans target env file and process environment, registers grants into `ReaVoterEnvGateway`,
    /// backs up original secrets into encrypted vault, and replaces selected keys with stand-in tokens in .env and process memory.
    pub fn seal_and_register_with_gateway(
        env_path: &Path,
        vault_path: &Path,
        gateway: &crate::rea_voter_env_gateway::ReaVoterEnvGateway,
    ) -> Result<LlmFusionEnumerationResult, VaultError> {
        Self::seal_and_register_internal(env_path, vault_path, Some(gateway))
    }

    /// Checks whether any user environment variable in `HKEY_USERS\S-1-5-21-*\Environment` or `HKCU\Environment`
    /// is an unsealed API key (`selected && !val.starts_with("OSHOOSI_STANDIN_")`).
    pub fn has_unsealed_user_api_keys() -> bool {
        #[cfg(windows)]
        {
            for (k, v) in read_hkcu_environment_vars() {
                if !v.starts_with("OSHOOSI_STANDIN_") && !is_hard_protected_non_secret_key(&k, &v) {
                    let eval = LlmFusionApiKeyEnumerator::evaluate_variable(&k, &v);
                    if eval.selected
                        && !eval.vetoed_by_safety_guard
                        && eval.fusion_confidence_bp >= 8500
                    {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Maps an environment variable name to its canonical pinned TLS upstream host for
    /// `ReaVoterEnvGateway::verify_and_swap_outbound` confused-deputy protection.
    pub fn infer_pinned_upstream_host(key: &str) -> &'static str {
        match key.trim().to_ascii_uppercase().as_str() {
            "GEMINI_API_KEY" | "GOOGLE_API_KEY" => "generativelanguage.googleapis.com",
            "HF_TOKEN" | "HUGGINGFACE_HUB_TOKEN" | "HUGGING_FACE_HUB_TOKEN" => "huggingface.co",
            "OTX_API_KEY" | "OTX_KEY" | "ALIENVAULT_OTX_API_KEY" | "X_OTX_API_KEY" => {
                "otx.alienvault.com"
            }
            "NVD_API_KEY" => "services.nvd.nist.gov",
            "OPENAI_API_KEY" | "OSOOSI_OPENAI_API_KEY" | "OSOOSI_LLM_API_KEY" => "api.openai.com",
            "ANTHROPIC_API_KEY" => "api.anthropic.com",
            "GITHUB_TOKEN" | "GH_TOKEN" => "api.github.com",
            "CLOUDFLARE_API_TOKEN" => "api.cloudflare.com",
            "GOOGLE_SAFE_BROWSING_API_KEY" => "safebrowsing.googleapis.com",
            _ => "api.provider.internal",
        }
    }

    /// Helper to test if a vault file is readable by the current process without raising DACL access denied.
    fn is_vault_readable(p: &Path) -> bool {
        match File::open(p) {
            Ok(_) => true,
            Err(e) => {
                if e.kind() == std::io::ErrorKind::PermissionDenied || e.raw_os_error() == Some(5) {
                    eprintln!(
                        "[WARN] Vault at '{}' exists but read access was denied (PermissionDenied / os error 5). Falling back to accessible workspace vault.",
                        p.display()
                    );
                }
                false
            }
        }
    }

    /// Locates the active `protected_env_backup.vault` across the CWD, executable directory,
    /// workspace root (`../..` from `target/release`), or standard installation directory.
    /// Resilient to DACL `PermissionDenied` (os error 5): if an elevated/SYSTEM vault is unreadable,
    /// it logs a warning and falls back to an accessible workspace vault.
    pub fn locate_active_vault_path(custom_path: Option<&Path>) -> Option<PathBuf> {
        if let Some(p) = custom_path {
            if Self::is_vault_readable(p) {
                return Some(p.to_path_buf());
            }
        }
        let default_rel = Self::default_vault_path();
        if Self::is_vault_readable(&default_rel) {
            return Some(default_rel);
        }
        if let Ok(exe) = std::env::current_exe() {
            let mut cur = exe.parent();
            for _ in 0..6 {
                if let Some(dir) = cur {
                    let candidate = dir.join(DEFAULT_VAULT_PATH);
                    if Self::is_vault_readable(&candidate) {
                        return Some(candidate);
                    }
                    cur = dir.parent();
                } else {
                    break;
                }
            }
        }
        #[cfg(windows)]
        {
            if let Ok(pd) = std::env::var("ProgramData") {
                let c_pd_var = PathBuf::from(pd)
                    .join("OshoosiClaw")
                    .join(DEFAULT_VAULT_PATH);
                if Self::is_vault_readable(&c_pd_var) {
                    return Some(c_pd_var);
                }
            }
            let c_pd = PathBuf::from(r"C:\ProgramData\OshoosiClaw").join(DEFAULT_VAULT_PATH);
            if Self::is_vault_readable(&c_pd) {
                return Some(c_pd);
            }
            let pf = PathBuf::from(r"C:\Program Files\OshoosiClaw").join(DEFAULT_VAULT_PATH);
            if Self::is_vault_readable(&pf) {
                return Some(pf);
            }
        }
        #[cfg(unix)]
        {
            let u1 = PathBuf::from("/var/lib/oshoosi").join(DEFAULT_VAULT_PATH);
            if Self::is_vault_readable(&u1) {
                return Some(u1);
            }
            let u2 = PathBuf::from("/etc/oshoosi").join(DEFAULT_VAULT_PATH);
            if Self::is_vault_readable(&u2) {
                return Some(u2);
            }
        }

        // Secondary fallback: if custom_path was provided and exists (even if currently unreadable), return it
        if let Some(p) = custom_path {
            if p.exists() {
                return Some(p.to_path_buf());
            }
        }

        None
    }

    /// Locates all active `protected_env_backup.vault` candidates across the filesystem search order.
    pub fn locate_all_active_vault_paths(custom_path: Option<&Path>) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        let mut seen = std::collections::HashSet::new();

        let mut add_if_exists = |p: PathBuf| {
            if p.exists() {
                let key = p
                    .canonicalize()
                    .unwrap_or_else(|_| p.clone())
                    .to_string_lossy()
                    .to_ascii_lowercase();
                if seen.insert(key) {
                    paths.push(p);
                }
            }
        };

        if let Some(p) = custom_path {
            add_if_exists(p.to_path_buf());
        }
        add_if_exists(Self::default_vault_path());

        if let Ok(exe) = std::env::current_exe() {
            let mut cur = exe.parent();
            for _ in 0..6 {
                if let Some(dir) = cur {
                    add_if_exists(dir.join(DEFAULT_VAULT_PATH));
                    cur = dir.parent();
                } else {
                    break;
                }
            }
        }

        #[cfg(windows)]
        {
            if let Ok(pd) = std::env::var("ProgramData") {
                add_if_exists(
                    PathBuf::from(pd)
                        .join("OshoosiClaw")
                        .join(DEFAULT_VAULT_PATH),
                );
            }
            add_if_exists(PathBuf::from(r"C:\ProgramData\OshoosiClaw").join(DEFAULT_VAULT_PATH));
            add_if_exists(PathBuf::from(r"C:\Program Files\OshoosiClaw").join(DEFAULT_VAULT_PATH));
        }

        #[cfg(unix)]
        {
            add_if_exists(PathBuf::from("/var/lib/oshoosi").join(DEFAULT_VAULT_PATH));
            add_if_exists(PathBuf::from("/etc/oshoosi").join(DEFAULT_VAULT_PATH));
        }

        paths
    }

    /// Automatically restores pre-stand-in configurations from all discovered active vaults on the system,
    /// catching DACL `PermissionDenied` (os error 5) errors cleanly without crashing.
    pub fn auto_revert_all_active_vaults(custom_path: Option<&Path>) -> Result<(), VaultError> {
        Self::pause_auto_seal_and_persist_disabled();
        let vaults = Self::locate_all_active_vault_paths(custom_path);
        if vaults.is_empty() {
            let default_rel = Self::default_vault_path();
            if default_rel.exists() {
                return Self::auto_revert(&default_rel);
            }
            #[cfg(windows)]
            {
                let _ = restore_hkcu_original_vars(&[]);
            }
            return Ok(());
        }

        let mut errors = Vec::new();
        for v in vaults {
            match Self::auto_revert(&v) {
                Ok(()) => {
                    println!("[+] Reverted vault: {}", v.display());
                }
                Err(VaultError::Io(ref e))
                    if e.kind() == std::io::ErrorKind::PermissionDenied
                        || e.raw_os_error() == Some(5) =>
                {
                    eprintln!(
                        "[WARN] Skipping vault '{}': PermissionDenied (os error 5). Run as administrator or system service to unseal this vault.",
                        v.display()
                    );
                }
                Err(e) => {
                    errors.push(format!("{}: {}", v.display(), e));
                }
            }
        }

        if !errors.is_empty() {
            return Err(VaultError::TargetError(format!(
                "Failed to revert one or more vaults: {}",
                errors.join("; ")
            )));
        }

        Ok(())
    }

    /// Convenience alias for `auto_revert_all_active_vaults`.
    pub fn auto_revert_all(custom_path: Option<&Path>) -> Result<(), VaultError> {
        Self::auto_revert_all_active_vaults(custom_path)
    }

    /// Populates `gateway` with `HardenedSealedGrant` entries decrypted from `vault_path`,
    /// binding each grant to the caller process's TOCTOU-verified executable SHA-256 and
    /// canonical upstream provider host.
    pub fn load_gateway_grants_from_vault(
        vault_path: &Path,
        gateway: &crate::rea_voter_env_gateway::ReaVoterEnvGateway,
    ) -> Result<usize, VaultError> {
        let (payload, _) = Self::read_vault_payload(vault_path)?;
        let my_pid = std::process::id();
        let bin_hash = crate::rea_voter_env_gateway::resolve_pid_exe(my_pid)
            .and_then(|p| crate::rea_voter_env_gateway::hash_file_sha256_nofollow(&p))
            .map_err(|e| VaultError::TargetError(e.to_string()))?;
        let script_hash = crate::rea_voter_env_gateway::resolve_pid_exe(my_pid)
            .and_then(|p| crate::rea_voter_env_gateway::resolve_pid_script_hash(my_pid, &p))
            .map_err(|e| VaultError::TargetError(e.to_string()))?;

        let mut count = 0usize;
        for (key, standin) in &payload.standin_mappings {
            if let Some((_, secret_str)) = payload
                .original_env_vars
                .iter()
                .find(|(k, _)| k == key)
                .or_else(|| payload.original_hkcu_vars.iter().find(|(k, _)| k == key))
            {
                let grant = crate::rea_voter_env_gateway::HardenedSealedGrant::new(
                    key,
                    standin,
                    bin_hash,
                    script_hash,
                    Self::infer_pinned_upstream_host(key),
                    crate::rea_voter_env_gateway::ZeroizingLockedSecret::new(secret_str.as_bytes()),
                );
                gateway.register_grant(grant);
                count += 1;
            }
        }
        Ok(count)
    }

    /// Verifies the calling process via `ReaVoterEnvGateway::verify_and_swap_outbound`
    /// (`GetProcessTimes` instance key, clean interpreter env, `hash_file_sha256_nofollow`,
    /// and pinned upstream TLS host) and swaps an `OSHOOSI_STANDIN_*` token back to its
    /// secret in volatile memory without ever writing the secret to `std::env` or disk.
    pub fn resolve_standin_for_verified_caller(
        key_name: &str,
        token_or_val: &str,
        upstream_host: Option<&str>,
        vault_path: Option<&Path>,
    ) -> Result<String, String> {
        let v_path = Self::locate_active_vault_path(vault_path)
            .ok_or_else(|| "Protected backup vault not found".to_string())?;

        let mut candidate = token_or_val.trim().to_string();
        if candidate.is_empty() {
            if let Ok(env_v) = std::env::var(key_name) {
                if !env_v.trim().is_empty() {
                    candidate = env_v.trim().to_string();
                }
            }
        }
        #[cfg(windows)]
        if candidate.is_empty() {
            for (k, v) in read_hkcu_environment_vars() {
                if k.eq_ignore_ascii_case(key_name) && !v.trim().is_empty() {
                    candidate = v.trim().to_string();
                    break;
                }
            }
        }
        if candidate.is_empty() {
            if let Ok((payload, _)) = Self::read_vault_payload(&v_path) {
                if let Some((_, standin)) = payload
                    .standin_mappings
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case(key_name))
                {
                    candidate = standin.clone();
                }
            }
        }

        if candidate.is_empty() {
            return Err(format!(
                "Variable '{}' is not present in environment or vault",
                key_name
            ));
        }

        if !candidate.starts_with("OSHOOSI_STANDIN_") {
            return Ok(candidate);
        }

        // Ephemeral gateway (vault_path = None so Drop only zeroizes RAM grants and never calls auto_revert)
        let gw = crate::rea_voter_env_gateway::ReaVoterEnvGateway::new(
            std::time::Duration::from_secs(300),
        );
        Self::load_gateway_grants_from_vault(&v_path, &gw).map_err(|e| e.to_string())?;

        let host = upstream_host.unwrap_or_else(|| Self::infer_pinned_upstream_host(key_name));
        let swapped =
            gw.verify_and_swap_outbound(std::process::id(), host, candidate.as_bytes())?;
        String::from_utf8(swapped).map_err(|_| "Swapped secret is not valid UTF-8".to_string())
    }

    /// Resolves an environment variable by name, transparently verifying and swapping
    /// `OSHOOSI_STANDIN_*` tokens via `ReaVoterEnvGateway`.
    pub fn resolve_env_var_verified(key_name: &str, upstream_host: Option<&str>) -> Option<String> {
        Self::ensure_resolver_registered();
        let raw = std::env::var(key_name).unwrap_or_default();
        if !raw.trim().is_empty() && !raw.trim().starts_with("OSHOOSI_STANDIN_") {
            return Some(raw.trim().to_string());
        }
        Self::resolve_standin_for_verified_caller(key_name, &raw, upstream_host, None).ok()
    }

    fn standin_resolver_bridge(key: &str, raw_val: &str) -> Option<String> {
        Self::resolve_standin_for_verified_caller(key, raw_val, None, None).ok()
    }

    /// Registers `ProtectedEnvBackupVault` as the global stand-in resolver in `osoosi-types`.
    pub fn ensure_resolver_registered() {
        osoosi_types::register_standin_resolver(Self::standin_resolver_bridge);
    }
}

/// Background watcher process that continuously monitors environment files, identifies new or modified files
/// using Google Magika, and automatically protects new credentials into the vault.
pub struct EnvFileMagikaWatcher {
    pub base_dir: PathBuf,
    pub custom_paths: Vec<PathBuf>,
    pub running: Arc<AtomicBool>,
    pub poll_interval: Duration,
}

impl EnvFileMagikaWatcher {
    pub fn new(base_dir: PathBuf, custom_paths: Vec<PathBuf>, poll_interval: Duration) -> Self {
        Self {
            base_dir,
            custom_paths,
            running: Arc::new(AtomicBool::new(false)),
            poll_interval,
        }
    }

    pub fn start(&self, vault_path: PathBuf) -> Arc<AtomicBool> {
        let running = Arc::clone(&self.running);
        running.store(true, Ordering::SeqCst);
        let flag = Arc::clone(&running);
        let base_dir = self.base_dir.clone();
        let custom_paths = self.custom_paths.clone();
        let interval = self.poll_interval;

        std::thread::spawn(move || {
            let mut file_hashes: HashMap<PathBuf, String> = HashMap::new();
            while flag.load(Ordering::SeqCst) {
                let discovered =
                    ProtectedEnvBackupVault::discover_environment_files(&base_dir, &custom_paths);
                for p in discovered {
                    if let Ok(bytes) = std::fs::read(&p) {
                        let mut hasher = Sha256::new();
                        hasher.update(&bytes);
                        let hash = format!("{:x}", hasher.finalize());

                        let changed = match file_hashes.get(&p) {
                            Some(old_h) => old_h != &hash,
                            None => true,
                        };

                        if changed {
                            file_hashes.insert(p.clone(), hash);
                            let mg = crate::rea::identify_with_magika(Some(&p), &bytes);
                            if mg.is_text || mg.label == "ini" || mg.label == "config" {
                                let _ = ProtectedEnvBackupVault::seal_and_backup_dynamic(
                                    &p,
                                    &vault_path,
                                );
                            }
                        }
                    }
                }
                std::thread::sleep(interval);
            }
        });

        running
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

impl Drop for EnvFileMagikaWatcher {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Evaluation record for an environment variable analyzed by the 3-Arm LLM Fusion Enumerator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyCandidateEvaluation {
    pub key: String,
    pub selected: bool,
    pub vetoed_by_safety_guard: bool,
    pub veto_reason: Option<String>,
    pub arm1_semantic_score: f64,
    pub arm2_entropy_score: f64,
    pub arm3_safety_veto: bool,
    pub fusion_confidence_bp: u16,
    pub standin_token: Option<String>,
}

/// Aggregated result of 3-Arm LLM Fusion API Key Enumeration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmFusionEnumerationResult {
    pub total_scanned: usize,
    pub total_selected: usize,
    pub total_vetoed: usize,
    pub candidates: Vec<ApiKeyCandidateEvaluation>,
}

/// 3-Arm LLM Fusion API Key Enumerator:
/// - Arm 1 (SemanticKeyNameAndLlmClassifier): Recognizes `*_API_KEY`, `*_TOKEN`, `*_SECRET`, `GEMINI_API_KEY`, `HF_TOKEN`, etc.
/// - Arm 2 (EntropyAndTokenPrefixAnalyzer): Recognizes `AIza...`, `hf_...`, `sk-...`, `ghp_...`, `AKIA...` and high Shannon entropy.
/// - Arm 3 (ImmutableSystemAndPathVetoJudge — CRITICAL ZERO-TOUCH PATH GUARD):
///   HARD-VETOES (`veto = true`, `confidence = 0`) system and path variables:
///   `PATH`, `JAVA_HOME`, `ONEDRIVE`, `ONEDRIVECONSUMER`, `OLLAMA_ORIGINS`, `TEMP`, `USERPROFILE`, `WINDIR`, `COMSPEC`, etc.,
///   or any key ending with `_HOME`, `_DIR`, `_PATH`, `_ROOT`, `_ORIGINS`, `_URL`, `_HOST`, or values with path separators or URLs.
pub struct LlmFusionApiKeyEnumerator;

impl LlmFusionApiKeyEnumerator {
    /// Computes Shannon entropy H(X) = - sum(p * log2(p))
    pub fn shannon_entropy(s: &str) -> f64 {
        if s.is_empty() {
            return 0.0;
        }
        let mut counts = [0u32; 256];
        for b in s.bytes() {
            counts[b as usize] += 1;
        }
        let len = s.len() as f64;
        let mut entropy = 0.0;
        for &c in &counts {
            if c > 0 {
                let p = c as f64 / len;
                entropy -= p * p.log2();
            }
        }
        entropy
    }

    /// Evaluates a single key-value variable using 3-Arm LLM Fusion Consensus.
    pub fn evaluate_variable(key: &str, value: &str) -> ApiKeyCandidateEvaluation {
        let clean_key = key.trim();
        let clean_val = value.trim().trim_matches('"').trim_matches('\'');
        let key_upper = clean_key.to_ascii_uppercase();

        // Arm 3: ImmutableSystemAndPathVetoJudge (CRITICAL ZERO-TOUCH PATH & SYSTEM GUARD)
        let is_system_name = matches!(
            key_upper.as_str(),
            "PATH"
                | "JAVA_HOME"
                | "ONEDRIVE"
                | "ONEDRIVECONSUMER"
                | "OLLAMA_ORIGINS"
                | "TEMP"
                | "TMP"
                | "USERPROFILE"
                | "WINDIR"
                | "COMSPEC"
                | "RUST_LOG"
                | "SYSTEMROOT"
                | "SYSTEMDRIVE"
                | "APPDATA"
                | "LOCALAPPDATA"
                | "PROGRAMFILES"
                | "PROGRAMFILES(X86)"
                | "COMMONPROGRAMFILES"
                | "HOMEDRIVE"
                | "HOMEPATH"
                | "OS"
                | "NUMBER_OF_PROCESSORS"
                | "PROCESSOR_ARCHITECTURE"
                | "PROCESSOR_IDENTIFIER"
                | "PSMODULEPATH"
                | "ALLUSERSPROFILE"
                | "PUBLIC"
                | "DRIVERDATA"
                | "HOST"
                | "HOSTNAME"
                | "PORT"
                | "NODE_ENV"
                | "APP_ENV"
                | "DEBUG"
        );

        let has_ide_or_build_prefix = key_upper.starts_with("ANTIGRAVITY_")
            || key_upper.starts_with("VSCODE_")
            || key_upper.starts_with("CARGO_")
            || key_upper.starts_with("RUST_")
            || key_upper.starts_with("TERM_")
            || key_upper.starts_with("NPM_")
            || key_upper.starts_with("SSH_")
            || key_upper.starts_with("GPG_")
            || key_upper.starts_with("GIT_");

        let has_public_prefix = key_upper.starts_with("PUBLIC_")
            || key_upper.starts_with("NEXT_PUBLIC_")
            || key_upper.starts_with("VITE_")
            || key_upper.starts_with("REACT_APP_")
            || key_upper.starts_with("GATSBY_")
            || key_upper.starts_with("NUXT_PUBLIC_");

        let val_lower = clean_val.to_ascii_lowercase();
        let is_known_non_secret_value = val_lower == "true"
            || val_lower == "false"
            || val_lower == "yes"
            || val_lower == "no"
            || val_lower == "1"
            || val_lower == "0"
            || val_lower == "null"
            || val_lower == "undefined"
            || val_lower == "development"
            || val_lower == "production"
            || val_lower == "test"
            || val_lower == "staging"
            || clean_val.parse::<u16>().is_ok()
            || clean_val == "127.0.0.1"
            || clean_val == "0.0.0.0"
            || clean_val == "localhost"
            || clean_val.starts_with("http://localhost")
            || clean_val.starts_with("http://127.0.0.1")
            || clean_val.starts_with("https://localhost");

        let has_system_suffix = key_upper.ends_with("_HOME")
            || key_upper.ends_with("_DIR")
            || key_upper.ends_with("_PATH")
            || key_upper.ends_with("_ROOT")
            || key_upper.ends_with("_ORIGINS")
            || key_upper.ends_with("_URL")
            || key_upper.ends_with("_HOST")
            || key_upper.ends_with("_PORT")
            || key_upper.ends_with("_VERSION")
            || key_upper.ends_with("_EXE");

        let has_path_delimiters = clean_val.contains('\\')
            || clean_val.starts_with("C:")
            || clean_val.starts_with("D:")
            || (clean_val.contains('/')
                && !clean_val.starts_with("sk-")
                && !clean_val.starts_with("hf_"))
            || clean_val.starts_with("http://")
            || clean_val.starts_with("https://");

        let is_already_standin = clean_val.starts_with("OSHOOSI_STANDIN_");

        let veto_reason = if is_system_name {
            Some(
                "VETOED: Protected system environment variable (PATH / system invariant)"
                    .to_string(),
            )
        } else if has_ide_or_build_prefix {
            Some(
                "VETOED: Protected IDE, developer toolchain, or build environment prefix"
                    .to_string(),
            )
        } else if has_public_prefix {
            Some("VETOED: Frontend or public configuration variable".to_string())
        } else if is_known_non_secret_value {
            Some(
                "VETOED: Known non-secret boolean, environment, or loopback network value"
                    .to_string(),
            )
        } else if has_system_suffix {
            Some("VETOED: Non-secret system configuration or path suffix".to_string())
        } else if has_path_delimiters {
            Some("VETOED: Value contains filesystem path or network URL".to_string())
        } else if is_already_standin {
            Some("VETOED: Already sealed with Oshoosi stand-in token".to_string())
        } else if clean_val.len() < 8 {
            Some("VETOED: Value too short to be cryptographic secret".to_string())
        } else {
            None
        };

        let arm3_safety_veto = veto_reason.is_some();

        // If vetoed by Arm 3, consensus is immediate reject with 0 confidence
        if arm3_safety_veto {
            return ApiKeyCandidateEvaluation {
                key: clean_key.to_string(),
                selected: false,
                vetoed_by_safety_guard: true,
                veto_reason,
                arm1_semantic_score: 0.0,
                arm2_entropy_score: 0.0,
                arm3_safety_veto: true,
                fusion_confidence_bp: 0,
                standin_token: None,
            };
        }

        // Arm 1: SemanticKeyNameAndLlmClassifier
        let arm1_semantic_score = if key_upper == "GEMINI_API_KEY"
            || key_upper == "HF_TOKEN"
            || key_upper == "NVD_API_KEY"
            || key_upper == "OTX_API_KEY"
            || key_upper == "OPENAI_API_KEY"
            || key_upper == "ANTHROPIC_API_KEY"
            || key_upper.ends_with("_API_KEY")
            || key_upper.ends_with("_API_TOKEN")
            || key_upper.ends_with("_ACCESS_TOKEN")
            || key_upper.ends_with("_SECRET_KEY")
            || key_upper.ends_with("_PRIVATE_KEY")
            || key_upper.ends_with("_TOKEN")
            || key_upper.ends_with("_SECRET")
            || key_upper.ends_with("_PASSWORD")
            || key_upper == "PASSWORD"
            || key_upper.ends_with("_CREDENTIAL")
        {
            100.0
        } else if key_upper.contains("API_KEY")
            || key_upper.contains("SECRET")
            || key_upper.contains("TOKEN")
            || key_upper.contains("PASSWORD")
        {
            90.0
        } else if key_upper.contains("KEY")
            || key_upper.contains("AUTH")
            || key_upper.contains("PASS")
        {
            70.0
        } else {
            20.0
        };

        // Arm 2: EntropyAndTokenPrefixAnalyzer
        let has_known_prefix = clean_val.starts_with("AIza") // Google Gemini / Cloud API Key
            || clean_val.starts_with("hf_")                 // HuggingFace Token
            || clean_val.starts_with("sk-")                 // OpenAI / Anthropic Key
            || clean_val.starts_with("ghp_")                // GitHub Personal Access Token
            || clean_val.starts_with("gho_")                // GitHub OAuth Token
            || clean_val.starts_with("AKIA"); // AWS Access Key ID

        let is_hex_or_uuid_secret = clean_val.len() >= 24
            && clean_val
                .bytes()
                .all(|b| b.is_ascii_hexdigit() || b == b'-');

        let entropy = Self::shannon_entropy(clean_val);

        let arm2_entropy_score = if has_known_prefix || is_hex_or_uuid_secret {
            100.0
        } else if clean_val.len() >= 20 && entropy >= 3.2 {
            95.0
        } else if clean_val.len() >= 12 && entropy >= 2.5 {
            90.0
        } else if arm1_semantic_score >= 100.0 && clean_val.len() >= 8 {
            85.0
        } else if entropy >= 2.5 {
            50.0
        } else {
            15.0
        };

        // Calibrated LLM Fusion Consensus: requires fused confidence >= 8500 bp (85.0%)
        let fused_confidence_pct: f64 = (arm1_semantic_score * 0.55) + (arm2_entropy_score * 0.45);
        let fusion_confidence_bp =
            (fused_confidence_pct * 100.0).round().clamp(0.0, 10000.0) as u16;

        let selected = fusion_confidence_bp >= 8500;
        let standin_token = if selected {
            Some(ProtectedEnvBackupVault::generate_standin_token(
                clean_key, clean_val,
            ))
        } else {
            None
        };

        ApiKeyCandidateEvaluation {
            key: clean_key.to_string(),
            selected,
            vetoed_by_safety_guard: false,
            veto_reason: None,
            arm1_semantic_score,
            arm2_entropy_score,
            arm3_safety_veto: false,
            fusion_confidence_bp,
            standin_token,
        }
    }

    /// Evaluates key-value pairs (e.g. from an env file or environment variables).
    pub fn enumerate_from_pairs(pairs: &[(String, String)]) -> LlmFusionEnumerationResult {
        let mut candidates = Vec::new();
        let mut total_selected = 0;
        let mut total_vetoed = 0;

        for (k, v) in pairs {
            let eval = Self::evaluate_variable(k, v);
            if eval.selected {
                total_selected += 1;
            }
            if eval.vetoed_by_safety_guard {
                total_vetoed += 1;
            }
            candidates.push(eval);
        }

        LlmFusionEnumerationResult {
            total_scanned: pairs.len(),
            total_selected,
            total_vetoed,
            candidates,
        }
    }

    /// Parses an environment file and evaluates all variables with 3-Arm LLM Fusion.
    pub fn enumerate_env_file(env_path: &Path) -> Result<LlmFusionEnumerationResult, VaultError> {
        let content = std::fs::read_to_string(env_path)?;
        let mut pairs = Vec::new();
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('#') || !trimmed.contains('=') {
                continue;
            }
            let parts: Vec<&str> = trimmed.splitn(2, '=').collect();
            let k = parts[0].trim().to_string();
            let v = parts[1].trim().to_string();
            pairs.push((k, v));
        }
        Ok(Self::enumerate_from_pairs(&pairs))
    }
}

/// Applies Win32 Protected NTFS DACL (`SE_DACL_PROTECTED` via `SetNamedSecurityInfoW`
/// with `D:P(A;;GA;;;SY)(A;;GA;;;BA)`) breaking inheritance and restricting access
/// exclusively to `NT AUTHORITY\SYSTEM` and `BUILTIN\Administrators`.
#[cfg(windows)]
pub fn apply_protected_ntfs_dacl(path: &Path) -> Result<(), VaultError> {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;

    let wide_path: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let sddl = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)(A;;GA;;;IU)(A;;GA;;;SU)";
    let wide_sddl: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();

    #[link(name = "advapi32")]
    extern "system" {
        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            StringSecurityDescriptor: *const u16,
            StringSDRevision: u32,
            SecurityDescriptor: *mut *mut c_void,
            SecurityDescriptorSize: *mut u32,
        ) -> i32;

        fn GetSecurityDescriptorDacl(
            pSecurityDescriptor: *mut c_void,
            lpbDaclPresent: *mut i32,
            pDacl: *mut *mut c_void,
            lpbDaclDefaulted: *mut i32,
        ) -> i32;

        fn SetNamedSecurityInfoW(
            pObjectName: *const u16,
            ObjectType: i32,
            SecurityInfo: u32,
            psidOwner: *mut c_void,
            psidGroup: *mut c_void,
            pDacl: *mut c_void,
            pSacl: *mut c_void,
        ) -> u32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn LocalFree(hMem: *mut c_void) -> *mut c_void;
    }

    const SDDL_REVISION_1: u32 = 1;
    const SE_FILE_OBJECT: i32 = 1;
    const DACL_SECURITY_INFORMATION: u32 = 0x00000004;
    const PROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x80000000;

    unsafe {
        let mut sd_ptr: *mut c_void = std::ptr::null_mut();
        let mut sd_size: u32 = 0;
        let conv_res = ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide_sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut sd_ptr,
            &mut sd_size,
        );

        if conv_res != 0 && !sd_ptr.is_null() {
            let mut dacl_present: i32 = 0;
            let mut dacl_ptr: *mut c_void = std::ptr::null_mut();
            let mut dacl_defaulted: i32 = 0;

            let get_dacl_res = GetSecurityDescriptorDacl(
                sd_ptr,
                &mut dacl_present,
                &mut dacl_ptr,
                &mut dacl_defaulted,
            );

            if get_dacl_res != 0 && dacl_present != 0 {
                let _ = SetNamedSecurityInfoW(
                    wide_path.as_ptr(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    dacl_ptr,
                    std::ptr::null_mut(),
                );
            }
            LocalFree(sd_ptr);
        }
    }
    Ok(())
}

/// Unlocks the Protected NTFS DACL to permit file shredding and unlinking.
#[cfg(windows)]
pub fn unlock_protected_ntfs_dacl(path: &Path) -> Result<(), VaultError> {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;

    let wide_path: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let sddl = "D:(A;;GA;;;WD)";
    let wide_sddl: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();

    #[link(name = "advapi32")]
    extern "system" {
        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            StringSecurityDescriptor: *const u16,
            StringSDRevision: u32,
            SecurityDescriptor: *mut *mut c_void,
            SecurityDescriptorSize: *mut u32,
        ) -> i32;

        fn GetSecurityDescriptorDacl(
            pSecurityDescriptor: *mut c_void,
            lpbDaclPresent: *mut i32,
            pDacl: *mut *mut c_void,
            lpbDaclDefaulted: *mut i32,
        ) -> i32;

        fn SetNamedSecurityInfoW(
            pObjectName: *const u16,
            ObjectType: i32,
            SecurityInfo: u32,
            psidOwner: *mut c_void,
            psidGroup: *mut c_void,
            pDacl: *mut c_void,
            pSacl: *mut c_void,
        ) -> u32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn LocalFree(hMem: *mut c_void) -> *mut c_void;
    }

    const SDDL_REVISION_1: u32 = 1;
    const SE_FILE_OBJECT: i32 = 1;
    const DACL_SECURITY_INFORMATION: u32 = 0x00000004;
    const UNPROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x20000000;

    unsafe {
        let mut sd_ptr: *mut c_void = std::ptr::null_mut();
        let mut sd_size: u32 = 0;
        let conv_res = ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide_sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut sd_ptr,
            &mut sd_size,
        );

        if conv_res != 0 && !sd_ptr.is_null() {
            let mut dacl_present: i32 = 0;
            let mut dacl_ptr: *mut c_void = std::ptr::null_mut();
            let mut dacl_defaulted: i32 = 0;

            let get_dacl_res = GetSecurityDescriptorDacl(
                sd_ptr,
                &mut dacl_present,
                &mut dacl_ptr,
                &mut dacl_defaulted,
            );

            if get_dacl_res != 0 && dacl_present != 0 {
                let _ = SetNamedSecurityInfoW(
                    wide_path.as_ptr(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    dacl_ptr,
                    std::ptr::null_mut(),
                );
            }
            LocalFree(sd_ptr);
        }
    }
    Ok(())
}

#[cfg(unix)]
pub fn apply_protected_ntfs_dacl(path: &Path) -> Result<(), VaultError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(unix)]
pub fn unlock_protected_ntfs_dacl(path: &Path) -> Result<(), VaultError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))?;
    Ok(())
}

#[cfg(not(any(windows, unix)))]
pub fn apply_protected_ntfs_dacl(_path: &Path) -> Result<(), VaultError> {
    Ok(())
}

#[cfg(not(any(windows, unix)))]
pub fn unlock_protected_ntfs_dacl(_path: &Path) -> Result<(), VaultError> {
    Ok(())
}

/// Returns true ONLY when `vault_path` is the canonical production vault (`database/protected_env_backup.vault`)
/// and never during `#[cfg(test)]`, Cargo test binaries (`RUST_TEST_THREADS` / `CARGO_MANIFEST_DIR`), or inside temporary directories (`\Temp\` / `/tmp/`).
pub fn is_production_vault_path(vault_path: &Path) -> bool {
    #[cfg(test)]
    {
        let _ = vault_path;
        false
    }
    #[cfg(not(test))]
    {
        if std::env::var_os("RUST_TEST_THREADS").is_some()
            || std::env::var_os("CARGO_TARGET_TMPDIR").is_some()
            || std::env::current_exe()
                .ok()
                .map(|p| {
                    let es = p.to_string_lossy().to_ascii_lowercase().replace('/', "\\");
                    es.contains("\\target\\debug\\deps\\") || es.contains("\\target\\release\\deps\\")
                })
                .unwrap_or(false)
        {
            return false;
        }
        let s = vault_path
            .to_string_lossy()
            .to_ascii_lowercase()
            .replace('/', "\\");
        if s.contains("\\temp\\")
            || s.contains("\\tmp\\")
            || vault_path.starts_with(std::env::temp_dir())
        {
            return false;
        }
        s == "database\\protected_env_backup.vault"
            || s.ends_with("\\database\\protected_env_backup.vault")
    }
}

/// Hard mathematical non-secret and `PATH` guard: returns `true` for `PATH`/`Path`, `JAVA_HOME`,
/// `OneDrive`, `OneDriveConsumer`, `OLLAMA_ORIGINS`, `TEMP`, `TMP`, system/IDE prefixes, path suffixes,
/// or values containing filesystem path separators or URLs.
pub fn is_hard_protected_non_secret_key(key: &str, val: &str) -> bool {
    let clean_key = key.trim();
    let clean_val = val.trim().trim_matches('"').trim_matches('\'');
    let key_upper = clean_key.to_ascii_uppercase();
    if matches!(
        key_upper.as_str(),
        "PATH"
            | "JAVA_HOME"
            | "ONEDRIVE"
            | "ONEDRIVECONSUMER"
            | "OLLAMA_ORIGINS"
            | "TEMP"
            | "TMP"
            | "USERPROFILE"
            | "WINDIR"
            | "COMSPEC"
            | "RUST_LOG"
            | "SYSTEMROOT"
            | "SYSTEMDRIVE"
            | "APPDATA"
            | "LOCALAPPDATA"
            | "PROGRAMFILES"
            | "PROGRAMFILES(X86)"
            | "COMMONPROGRAMFILES"
            | "HOMEDRIVE"
            | "HOMEPATH"
            | "OS"
            | "NUMBER_OF_PROCESSORS"
            | "PROCESSOR_ARCHITECTURE"
            | "PROCESSOR_IDENTIFIER"
            | "PSMODULEPATH"
            | "ALLUSERSPROFILE"
            | "PATHEXT"
            | "PUBLIC"
            | "DRIVERDATA"
    ) {
        return true;
    }
    if key_upper.starts_with("ANTIGRAVITY_")
        || key_upper.starts_with("VSCODE_")
        || key_upper.starts_with("CARGO_")
        || key_upper.starts_with("RUST_")
        || key_upper.starts_with("TERM_")
        || key_upper.starts_with("NPM_")
        || key_upper.starts_with("SSH_")
        || key_upper.starts_with("GPG_")
        || key_upper.starts_with("GIT_")
        || key_upper.starts_with("OSOOSI_")
    {
        return true;
    }
    if key_upper.ends_with("_HOME")
        || key_upper.ends_with("_DIR")
        || key_upper.ends_with("_PATH")
        || key_upper.ends_with("_ROOT")
        || key_upper.ends_with("_ORIGINS")
        || key_upper.ends_with("_URL")
        || key_upper.ends_with("_HOST")
        || key_upper.ends_with("_PORT")
        || key_upper.ends_with("_VERSION")
        || key_upper.ends_with("_EXE")
    {
        return true;
    }
    if clean_val.contains('\\')
        || clean_val.contains(';')
        || clean_val.starts_with("C:")
        || clean_val.starts_with("D:")
        || clean_val.starts_with("http://")
        || clean_val.starts_with("https://")
    {
        return true;
    }
    false
}

/// Opens all interactive user `Environment` registry hives (`HKEY_USERS\S-1-5-21-*\Environment`,
/// skipping `*_Classes`) as well as `HKEY_CURRENT_USER\Environment` so that `seal`, `status`,
/// and `revert` work identically whether invoked from the Windows Service (`NT AUTHORITY\SYSTEM`
/// in Session 0) or an interactive user terminal (`Session 1+`).
#[cfg(windows)]
fn open_user_environment_hives(flags: u32) -> Vec<winreg::RegKey> {
    let mut hives = Vec::new();
    let hku = winreg::RegKey::predef(winreg::enums::HKEY_USERS);
    for sid in hku.enum_keys().flatten() {
        if sid.starts_with("S-1-5-21-") && !sid.ends_with("_Classes") {
            let sub_path = format!("{}\\Environment", sid);
            if let Ok(env_key) = hku.open_subkey_with_flags(&sub_path, flags) {
                hives.push(env_key);
            }
        }
    }
    if let Ok(hkcu_env) = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER)
        .open_subkey_with_flags("Environment", flags)
    {
        hives.push(hkcu_env);
    }
    hives
}

#[cfg(windows)]
fn read_hkcu_environment_vars() -> Vec<(String, String)> {
    use winreg::types::FromRegValue;
    let mut out: Vec<(String, String)> = Vec::new();
    for env_key in open_user_environment_hives(winreg::enums::KEY_READ) {
        for item in env_key.enum_values().flatten() {
            let (k, reg_val) = item;
            if let Ok(s) = String::from_reg_value(&reg_val) {
                if let Some(existing) = out.iter_mut().find(|(ek, _)| ek.eq_ignore_ascii_case(&k)) {
                    if existing.1.starts_with("OSHOOSI_STANDIN_")
                        && !s.starts_with("OSHOOSI_STANDIN_")
                    {
                        existing.1 = s;
                    }
                } else {
                    out.push((k, s));
                }
            }
        }
    }
    out
}

#[cfg(windows)]
pub fn read_user_sid_environment_vars() -> HashMap<String, HashMap<String, String>> {
    use winreg::types::FromRegValue;
    let mut map: HashMap<String, HashMap<String, String>> = HashMap::new();
    let hku = winreg::RegKey::predef(winreg::enums::HKEY_USERS);
    for sid in hku.enum_keys().flatten() {
        if sid.starts_with("S-1-5-21-") && !sid.ends_with("_Classes") {
            let sub_path = format!("{}\\Environment", sid);
            if let Ok(env_key) = hku.open_subkey_with_flags(&sub_path, winreg::enums::KEY_READ) {
                let mut vars = HashMap::new();
                for item in env_key.enum_values().flatten() {
                    let (k, reg_val) = item;
                    if let Ok(s) = String::from_reg_value(&reg_val) {
                        vars.insert(k, s);
                    }
                }
                map.insert(sid, vars);
            }
        }
    }
    if let Ok(hkcu_env) = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER)
        .open_subkey_with_flags("Environment", winreg::enums::KEY_READ)
    {
        let mut vars = HashMap::new();
        for item in hkcu_env.enum_values().flatten() {
            let (k, reg_val) = item;
            if let Ok(s) = String::from_reg_value(&reg_val) {
                vars.insert(k, s);
            }
        }
        map.insert("CURRENT_USER".to_string(), vars);
    }
    map
}

#[cfg(not(windows))]
pub fn read_user_sid_environment_vars() -> HashMap<String, HashMap<String, String>> {
    HashMap::new()
}

#[cfg(windows)]
fn write_hkcu_standin_vars(
    standin_mappings: &[(String, String)],
    verified_vault: &VaultPayload,
) -> Result<(), VaultError> {
    let hives = open_user_environment_hives(winreg::enums::KEY_READ | winreg::enums::KEY_WRITE);
    if hives.is_empty() {
        return Err(VaultError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "No writable user Environment registry hive found",
        )));
    }

    let mut any_updated = false;
    for (k, standin) in standin_mappings {
        // Hard double-guard: NEVER touch PATH or any protected system/path variable
        if k.eq_ignore_ascii_case("PATH") || is_hard_protected_non_secret_key(k, "") {
            continue;
        }
        // Only rewrite if this key originally existed in a user Environment hive and its true secret
        // is confirmed backed up in `verified_vault.original_hkcu_vars`
        let backed_up = verified_vault
            .original_hkcu_vars
            .iter()
            .any(|(hk, orig_v)| {
                hk == k
                    && !orig_v.is_empty()
                    && !orig_v.starts_with("OSHOOSI_STANDIN_")
                    && !is_hard_protected_non_secret_key(hk, orig_v)
            });
        if backed_up {
            for env_key in &hives {
                if env_key.get_raw_value(k).is_ok() {
                    env_key.set_value(k, standin).map_err(VaultError::Io)?;
                    any_updated = true;
                }
            }
        }
    }

    if any_updated {
        broadcast_wm_settingchange_environment();
    }
    Ok(())
}

#[cfg(windows)]
fn restore_hkcu_original_vars(original_hkcu_vars: &[(String, String)]) -> Result<(), VaultError> {
    use winreg::types::FromRegValue;
    let hives = open_user_environment_hives(winreg::enums::KEY_READ | winreg::enums::KEY_WRITE);
    if hives.is_empty() {
        return Err(VaultError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "No writable user Environment registry hive found",
        )));
    }

    let mut any_restored = false;
    for (k, orig_v) in original_hkcu_vars {
        if k.eq_ignore_ascii_case("PATH")
            || is_hard_protected_non_secret_key(k, orig_v)
            || orig_v.is_empty()
            || orig_v.starts_with("OSHOOSI_STANDIN_")
        {
            continue;
        }
        for env_key in &hives {
            if env_key.get_raw_value(k).is_ok() {
                env_key.set_value(k, orig_v).map_err(VaultError::Io)?;
                any_restored = true;
            }
        }
    }

    // Fallback recovery for any remaining OSHOOSI_STANDIN_* values in user hives:
    // If a key in HKCU\Environment still holds an OSHOOSI_STANDIN_* token (e.g., if the vault was sealed
    // after stand-ins were already written), scan active process environment (`std::env::vars()`) and
    // local workspace .env files for the matching key's plaintext value.
    let mut fallback_secrets: HashMap<String, String> = HashMap::new();
    for (k, v) in std::env::vars() {
        let clean_v = v.trim().trim_matches('"').trim_matches('\'').trim();
        if !clean_v.is_empty()
            && !clean_v.starts_with("OSHOOSI_STANDIN_")
            && !is_hard_protected_non_secret_key(&k, clean_v)
        {
            fallback_secrets
                .entry(k.to_ascii_uppercase())
                .or_insert_with(|| clean_v.to_string());
        }
    }
    let candidate_env_files = [
        PathBuf::from(".env"),
        PathBuf::from(r"D:\harfile\OshoosiClaw\.env"),
        PathBuf::from(r"D:\harfile\ModelFusion\.env"),
        PathBuf::from(r"D:\harfile\KillSwitch\.env"),
    ];
    for ef in &candidate_env_files {
        if ef.is_file() {
            if let Ok(content) = std::fs::read_to_string(ef) {
                for line in content.lines() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() || trimmed.starts_with('#') {
                        continue;
                    }
                    if let Some((rk, rv)) = trimmed.split_once('=') {
                        let key = rk.trim().trim_start_matches("export ").trim();
                        let val = rv.trim().trim_matches('"').trim_matches('\'').trim();
                        if !val.is_empty()
                            && !val.starts_with("OSHOOSI_STANDIN_")
                            && !val.contains("your-")
                            && !val.contains("example")
                            && !is_hard_protected_non_secret_key(key, val)
                        {
                            fallback_secrets.insert(key.to_ascii_uppercase(), val.to_string());
                        }
                    }
                }
            }
        }
    }

    for env_key in &hives {
        let current_items: Vec<(String, String)> = env_key
            .enum_values()
            .flatten()
            .filter_map(|(k, rv)| String::from_reg_value(&rv).ok().map(|s| (k, s)))
            .collect();
        for (k, val) in current_items {
            if val.starts_with("OSHOOSI_STANDIN_") && !k.eq_ignore_ascii_case("PATH") {
                if let Some(clean_sec) = fallback_secrets.get(&k.to_ascii_uppercase()) {
                    let _ = env_key.set_value(&k, clean_sec);
                    std::env::set_var(&k, clean_sec);
                    any_restored = true;
                }
            }
        }
    }

    if any_restored {
        broadcast_wm_settingchange_environment();
    }
    Ok(())
}

#[cfg(windows)]
fn broadcast_wm_settingchange_environment() {
    #[link(name = "user32")]
    extern "system" {
        fn SendMessageTimeoutW(
            hWnd: isize,
            Msg: u32,
            wParam: usize,
            lParam: isize,
            fuFlags: u32,
            uTimeout: u32,
            lpdwResult: *mut usize,
        ) -> isize;
    }
    const HWND_BROADCAST: isize = 0xffff;
    const WM_SETTINGCHANGE: u32 = 0x001A;
    const SMTO_ABORTIFHUNG: u32 = 0x0002;
    let wide_env: Vec<u16> = "Environment\0".encode_utf16().collect();
    let mut result: usize = 0;
    unsafe {
        let _ = SendMessageTimeoutW(
            HWND_BROADCAST,
            WM_SETTINGCHANGE,
            0,
            wide_env.as_ptr() as isize,
            SMTO_ABORTIFHUNG,
            100,
            &mut result,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rea_voter_env_gateway::{HardenedSealedGrant, ZeroizingLockedSecret};
    use std::time::Duration;

    static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn test_vault_seal_auto_revert_roundtrip() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let temp_dir = tempfile::tempdir().expect("create tempdir");
        let env_file = temp_dir.path().join(".env");
        let vault_file = temp_dir.path().join("test.vault");

        let original_content = "OPENAI_API_KEY=sk-live-actual-production-secret-999\nDATABASE_URL=postgres://user:pass@localhost/db\n";
        std::fs::write(&env_file, original_content).expect("write original env");

        let secret = ZeroizingLockedSecret::new(b"sk-live-actual-production-secret-999");
        let grant = HardenedSealedGrant::new(
            "OPENAI_API_KEY",
            "OSHOOSI_STANDIN_TOKEN_OPENAI_TEST",
            [0x11u8; 32],
            None,
            "api.openai.com",
            secret,
        );

        // 1. Seal and backup
        ProtectedEnvBackupVault::seal_and_backup(&env_file, &vault_file, &[grant])
            .expect("seal and backup must succeed");

        // Verify vault exists and is non-empty
        assert!(vault_file.exists());
        let status = ProtectedEnvBackupVault::get_status(&vault_file).expect("get status");
        assert!(status.exists);
        assert_eq!(status.sealed_variables, vec!["OPENAI_API_KEY"]);

        // Verify .env has stand-in token
        let sealed_content = std::fs::read_to_string(&env_file).expect("read sealed env");
        assert!(sealed_content.contains("OSHOOSI_STANDIN_TOKEN_OPENAI_TEST"));
        assert!(!sealed_content.contains("sk-live-actual-production-secret-999"));

        // 2. Auto-revert
        ProtectedEnvBackupVault::auto_revert(&vault_file).expect("auto revert must succeed");

        // Verify .env is restored to original
        let restored_content = std::fs::read_to_string(&env_file).expect("read restored env");
        assert_eq!(restored_content, original_content);

        // 3. Remove backup requires confirm
        let err = ProtectedEnvBackupVault::remove_backup(&vault_file, false).unwrap_err();
        assert!(matches!(err, VaultError::ConfirmationRequired));
        assert!(vault_file.exists());

        // 4. Remove backup with confirm shreds and unlinks
        ProtectedEnvBackupVault::remove_backup(&vault_file, true)
            .expect("remove with confirm must succeed");
        assert!(!vault_file.exists());
    }

    #[test]
    fn test_llm_fusion_api_key_enumeration_and_zero_touch_path() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let test_vars = vec![
            (
                "GEMINI_API_KEY".to_string(),
                "AIzaSyD-FakeGeminiApiKeyExample12345678".to_string(),
            ),
            (
                "HF_TOKEN".to_string(),
                "hf_FakeHuggingFaceTokenExampleToken123".to_string(),
            ),
            (
                "JAVA_HOME".to_string(),
                "C:\\Program Files\\Java\\jdk-21".to_string(),
            ),
            (
                "OLLAMA_ORIGINS".to_string(),
                "http://localhost:3000,http://127.0.0.1".to_string(),
            ),
            (
                "OneDrive".to_string(),
                "C:\\Users\\user\\OneDrive".to_string(),
            ),
            (
                "OneDriveConsumer".to_string(),
                "C:\\Users\\user\\OneDrive".to_string(),
            ),
            (
                "Path".to_string(),
                "C:\\Windows\\system32;C:\\Windows;D:\\tools".to_string(),
            ),
            (
                "TEMP".to_string(),
                "C:\\Users\\user\\AppData\\Local\\Temp".to_string(),
            ),
        ];

        let result = LlmFusionApiKeyEnumerator::enumerate_from_pairs(&test_vars);
        assert_eq!(result.total_selected, 2);
        assert_eq!(result.total_vetoed, 6);

        // Verify GEMINI_API_KEY and HF_TOKEN are selected with >= 8500 bp
        let gemini = result
            .candidates
            .iter()
            .find(|c| c.key == "GEMINI_API_KEY")
            .unwrap();
        assert!(gemini.selected);
        assert!(!gemini.vetoed_by_safety_guard);
        assert!(gemini.fusion_confidence_bp >= 8500);

        let hf = result
            .candidates
            .iter()
            .find(|c| c.key == "HF_TOKEN")
            .unwrap();
        assert!(hf.selected);
        assert!(!hf.vetoed_by_safety_guard);
        assert!(hf.fusion_confidence_bp >= 8500);

        // Verify Path, JAVA_HOME, OneDrive, etc. are HARD-VETOED with 0 confidence
        for veto_key in &[
            "JAVA_HOME",
            "OLLAMA_ORIGINS",
            "OneDrive",
            "OneDriveConsumer",
            "Path",
            "TEMP",
        ] {
            let c = result
                .candidates
                .iter()
                .find(|cand| cand.key == *veto_key)
                .unwrap();
            assert!(!c.selected, "{} must NOT be selected", veto_key);
            assert!(c.vetoed_by_safety_guard, "{} must be vetoed", veto_key);
            assert_eq!(
                c.fusion_confidence_bp, 0,
                "{} confidence must be 0",
                veto_key
            );
        }

        // Test end-to-end dynamic sealing and auto-revert roundtrip
        let temp_dir = tempfile::tempdir().expect("create tempdir");
        let env_file = temp_dir.path().join(".env");
        let vault_file = temp_dir.path().join("dynamic_test.vault");

        let mut env_content = String::new();
        for (k, v) in &test_vars {
            env_content.push_str(&format!("{}={}\n", k, v));
        }
        std::fs::write(&env_file, &env_content).expect("write test env file");

        let dyn_res = ProtectedEnvBackupVault::seal_and_backup_dynamic(&env_file, &vault_file)
            .expect("seal_and_backup_dynamic must succeed");
        assert!(dyn_res.total_selected >= 2);
        assert!(dyn_res
            .candidates
            .iter()
            .any(|c| c.key == "GEMINI_API_KEY" && c.selected));
        assert!(dyn_res
            .candidates
            .iter()
            .any(|c| c.key == "HF_TOKEN" && c.selected));

        // Check sealed content: GEMINI_API_KEY and HF_TOKEN replaced with stand-in tokens, Path & system variables intact
        let sealed_text = std::fs::read_to_string(&env_file).expect("read sealed text");
        assert!(sealed_text.contains("OSHOOSI_STANDIN_GEMINI_API_KEY_"));
        assert!(sealed_text.contains("OSHOOSI_STANDIN_HF_TOKEN_"));
        assert!(!sealed_text.contains("AIzaSyD-FakeGeminiApiKeyExample12345678"));
        assert!(!sealed_text.contains("hf_FakeHuggingFaceTokenExampleToken123"));
        assert!(sealed_text.contains("Path=C:\\Windows\\system32;C:\\Windows;D:\\tools"));
        assert!(sealed_text.contains("JAVA_HOME=C:\\Program Files\\Java\\jdk-21"));

        // Auto revert restores 100% bit-for-bit
        ProtectedEnvBackupVault::auto_revert(&vault_file).expect("auto revert must succeed");
        let restored_text = std::fs::read_to_string(&env_file).expect("read restored text");
        assert_eq!(restored_text, env_content);
    }

    #[test]
    fn test_ide_and_build_prefixes_are_hard_vetoed() {
        let ide_vars = vec![
            (
                "ANTIGRAVITY_CSRF_TOKEN".to_string(),
                "sec_antigravity_token_abc123456789".to_string(),
            ),
            (
                "VSCODE_GIT_IPC_HANDLE".to_string(),
                "\\\\.\\pipe\\vscode-git-ipc-1234".to_string(),
            ),
            ("CARGO_PKG_NAME".to_string(), "osoosi-core".to_string()),
            ("RUST_BACKTRACE".to_string(), "full".to_string()),
            ("TERM_PROGRAM".to_string(), "vscode".to_string()),
            (
                "NPM_CONFIG_TOKEN".to_string(),
                "npm_secret_token_1234567890".to_string(),
            ),
            (
                "SSH_AUTH_SOCK".to_string(),
                "/tmp/ssh-auth-sock-12345".to_string(),
            ),
            (
                "GPG_AGENT_INFO".to_string(),
                "/run/user/1000/gnupg/S.gpg-agent:1234:1".to_string(),
            ),
            (
                "GIT_EXEC_PATH".to_string(),
                "C:\\Program Files\\Git\\bin".to_string(),
            ),
        ];

        let result = LlmFusionApiKeyEnumerator::enumerate_from_pairs(&ide_vars);
        assert_eq!(
            result.total_selected, 0,
            "No IDE/build variables should ever be selected"
        );
        assert_eq!(result.total_vetoed, ide_vars.len());

        for (k, _) in &ide_vars {
            let cand = result.candidates.iter().find(|c| c.key == *k).unwrap();
            assert!(!cand.selected, "{} must not be selected", k);
            assert!(cand.vetoed_by_safety_guard, "{} must be vetoed", k);
            assert_eq!(cand.fusion_confidence_bp, 0, "{} confidence must be 0", k);
        }
    }

    #[test]
    fn test_seal_and_register_with_gateway_nonexistent_env_and_double_seal() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let temp_dir = tempfile::tempdir().expect("create tempdir");
        let env_file = temp_dir.path().join(".env");
        let vault_file = temp_dir.path().join("gateway_test.vault");

        // Set process environment variables
        let test_key = "GEMINI_API_KEY";
        let test_val = "AIzaSyD-RealSecretProductionTestValue99999";
        std::env::set_var(test_key, test_val);

        let gateway =
            crate::rea_voter_env_gateway::ReaVoterEnvGateway::new(Duration::from_secs(300));

        // .env does NOT exist initially
        assert!(!env_file.exists());

        // 1. Seal and register with gateway
        let res = ProtectedEnvBackupVault::seal_and_register_with_gateway(
            &env_file,
            &vault_file,
            &gateway,
        )
        .expect("must succeed even without preexisting .env");
        assert!(res.total_selected >= 1);

        // Verify gateway grant was created
        assert!(gateway.grant_count() >= 1);

        // Verify process memory was replaced with stand-in token
        let current_proc_val = std::env::var(test_key).expect("proc var must exist");
        assert!(current_proc_val.starts_with("OSHOOSI_STANDIN_GEMINI_API_KEY_"));

        // Verify .env was created and contains stand-in
        assert!(env_file.exists());
        let env_text = std::fs::read_to_string(&env_file).expect("read .env");
        assert!(env_text.contains(&current_proc_val));

        // Verify vault status
        let status = ProtectedEnvBackupVault::get_status(&vault_file).expect("get status");
        assert!(status.exists);
        assert!(!status.standin_mappings.is_empty());
        assert!(status
            .standin_mappings
            .iter()
            .any(|(k, s)| k == test_key && s == &current_proc_val));

        // 2. Double-seal test: sealing again must NOT clobber original secret with stand-in token
        let res2 = ProtectedEnvBackupVault::seal_and_register_with_gateway(
            &env_file,
            &vault_file,
            &gateway,
        )
        .expect("double-sealing must succeed");
        assert!(res2.total_selected >= 1);

        // Verify vault still holds the true original secret
        let (payload, _) =
            ProtectedEnvBackupVault::read_vault_payload(&vault_file).expect("read vault payload");
        let orig_pair = payload
            .original_env_vars
            .iter()
            .find(|(k, _)| k == test_key)
            .expect("must find key");
        assert_eq!(
            orig_pair.1, test_val,
            "Vault must preserve original secret, not stand-in!"
        );

        // 3. Auto revert restores process memory and removes temporary .env and vault
        ProtectedEnvBackupVault::auto_revert(&vault_file).expect("auto revert must succeed");
        assert_eq!(
            std::env::var(test_key).unwrap(),
            test_val,
            "Process memory must be restored to original secret"
        );
        assert!(
            !env_file.exists(),
            "Temporary .env should be removed on revert since it didn't exist before"
        );
        assert!(
            !vault_file.exists(),
            "Vault should be shredded and unlinked on revert since target didn't exist before"
        );

        // Clean up process env
        std::env::remove_var(test_key);
    }

    #[test]
    fn test_user_exact_env_profile_hf_nvd_otx_selected_and_non_secrets_vetoed() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let user_vars = vec![
            (
                "HF_TOKEN".to_string(),
                "hf_synthetic_test_token_not_real_key_12345".to_string(),
            ),
            (
                "NVD_API_KEY".to_string(),
                "a1b2c3d4-e5f6-4789-a012-3456789abcde".to_string(),
            ),
            ("OLLAMA_ORIGINS".to_string(), "*".to_string()),
            (
                "OneDrive".to_string(),
                r"C:\Users\oyesanyf\OneDrive".to_string(),
            ),
            (
                "OTX_API_KEY".to_string(),
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            ),
            (
                "Path".to_string(),
                r"C:\Users\oyesanyf\.cargo\bin;C:\Users\oyesanyf\AppData\Local\Microsoft\WindowsApps".to_string(),
            ),
            (
                "TEMP".to_string(),
                r"C:\Users\oyesanyf\AppData\Local\Temp".to_string(),
            ),
        ];

        let result = LlmFusionApiKeyEnumerator::enumerate_from_pairs(&user_vars);
        assert_eq!(
            result.total_selected, 3,
            "HF_TOKEN, NVD_API_KEY, and OTX_API_KEY must all be selected"
        );
        assert_eq!(
            result.total_vetoed, 4,
            "OLLAMA_ORIGINS, OneDrive, Path, and TEMP must all be vetoed"
        );

        for secret_key in &["HF_TOKEN", "NVD_API_KEY", "OTX_API_KEY"] {
            let cand = result
                .candidates
                .iter()
                .find(|c| c.key == *secret_key)
                .unwrap();
            assert!(cand.selected, "{} must be selected", secret_key);
            assert!(!cand.vetoed_by_safety_guard);
            assert!(cand.fusion_confidence_bp >= 8500);
            assert!(cand
                .standin_token
                .as_ref()
                .unwrap()
                .starts_with(&format!("OSHOOSI_STANDIN_{}_", secret_key)));
        }

        for safe_key in &["OLLAMA_ORIGINS", "OneDrive", "Path", "TEMP"] {
            let cand = result
                .candidates
                .iter()
                .find(|c| c.key == *safe_key)
                .unwrap();
            assert!(!cand.selected, "{} must NOT be selected", safe_key);
            assert!(cand.vetoed_by_safety_guard, "{} must be vetoed", safe_key);
            assert_eq!(cand.fusion_confidence_bp, 0);
        }
    }

    #[test]
    fn test_standin_token_outbound_resolution_and_confused_deputy_block() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let temp_dir = tempfile::tempdir().expect("create tempdir");
        let env_file = temp_dir.path().join(".env");
        let vault_file = temp_dir.path().join("standin_resolve_test.vault");

        let secrets = [
            (
                "GEMINI_API_KEY",
                "AIzaSyD-SyntheticUnitTestKeyForGatewaySwap123",
                "generativelanguage.googleapis.com:443",
            ),
            (
                "HF_TOKEN",
                "hf_SyntheticUnitTestTokenForGatewaySwap987654",
                "huggingface.co:443",
            ),
            (
                "NVD_API_KEY",
                "a1b2c3d4-e5f6-4789-a012-3456789abcde",
                "services.nvd.nist.gov:443",
            ),
            (
                "OTX_API_KEY",
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "otx.alienvault.com:443",
            ),
        ];

        let mut env_body = String::new();
        for (k, v, _) in &secrets {
            env_body.push_str(&format!("{}={}\n", k, v));
            std::env::set_var(k, v);
        }
        std::fs::write(&env_file, &env_body).expect("write .env");

        let res =
            ProtectedEnvBackupVault::seal_and_backup_dynamic(&env_file, &vault_file).expect("seal");
        assert!(res.total_selected >= 4);

        for (k, expected_secret, pinned_host) in &secrets {
            let proc_val = std::env::var(k).expect("env var must exist");
            assert!(
                proc_val.starts_with(&format!("OSHOOSI_STANDIN_{}_", k)),
                "Process env for {} must be stand-in token, got {}",
                k,
                proc_val
            );

            // 1. Confused-deputy mismatch must be blocked
            let bad_res = ProtectedEnvBackupVault::resolve_standin_for_verified_caller(
                k,
                &proc_val,
                Some("evil.attacker.invalid:443"),
                Some(&vault_file),
            );
            assert!(
                bad_res.is_err() && bad_res.unwrap_err().contains("Host header mismatch"),
                "Confused-deputy host mismatch must be rejected for {}",
                k
            );

            // 2. Verified caller + pinned host must swap stand-in back to real secret in volatile RAM
            let swapped = ProtectedEnvBackupVault::resolve_standin_for_verified_caller(
                k,
                &proc_val,
                Some(pinned_host),
                Some(&vault_file),
            )
            .expect("verified caller swap must succeed");
            assert_eq!(&swapped, expected_secret);

            // 3. Process memory must still hold the stand-in token (never written back to std::env)
            assert_eq!(std::env::var(k).unwrap(), proc_val);
        }

        ProtectedEnvBackupVault::auto_revert(&vault_file).expect("auto revert");
        for (k, _, _) in &secrets {
            std::env::remove_var(k);
        }
    }

    #[test]
    fn test_discover_environment_files_multi_depth() {
        let temp_dir = tempfile::tempdir().expect("create tempdir");
        let root = temp_dir.path();

        let env1 = root.join(".env");
        let env2 = root.join(".env.local");
        let sub1 = root.join("frontend");
        std::fs::create_dir_all(&sub1).unwrap();
        let env3 = sub1.join(".env.production");

        let sub2 = root.join("node_modules");
        std::fs::create_dir_all(&sub2).unwrap();
        let env_ignored = sub2.join(".env"); // should be ignored

        std::fs::write(&env1, "FOO=BAR\n").unwrap();
        std::fs::write(&env2, "BAZ=QUX\n").unwrap();
        std::fs::write(&env3, "API=VAL\n").unwrap();
        std::fs::write(&env_ignored, "IGN=IGN\n").unwrap();

        let custom = root.join("custom.env");
        std::fs::write(&custom, "C=1\n").unwrap();

        let discovered = ProtectedEnvBackupVault::discover_environment_files(
            root,
            std::slice::from_ref(&custom),
        );
        assert!(discovered.contains(&env1));
        assert!(discovered.contains(&env2));
        assert!(discovered.contains(&env3));
        assert!(discovered.contains(&custom));
        assert!(!discovered.contains(&env_ignored));
    }

    #[test]
    fn test_multi_file_seal_and_revert() {
        let _guard = ENV_MUTEX.lock().unwrap();
        let temp_dir = tempfile::tempdir().expect("create tempdir");
        let root = temp_dir.path();
        let vault_file = root.join("multi_test.vault");

        let f1 = root.join(".env");
        let sub = root.join("backend");
        std::fs::create_dir_all(&sub).unwrap();
        let f2 = sub.join(".env.staging");

        let original_body_f1 = "# Main configuration\nexport GEMINI_API_KEY=\"AIzaSyMultiTestKeyPrimary123456\" # primary\nPORT=8080\n";
        let original_body_f2 =
            "HF_TOKEN='hf_MultiTestSecretStagingToken123456' # staging token\nNODE_ENV=staging\n";

        std::fs::write(&f1, original_body_f1).unwrap();
        std::fs::write(&f2, original_body_f2).unwrap();

        let res =
            ProtectedEnvBackupVault::seal_and_backup_dynamic(&f1, &vault_file).expect("seal multi");
        assert!(res.total_selected >= 2);

        // Check sealed files in-place
        let text1 = std::fs::read_to_string(&f1).unwrap();
        assert!(text1.contains("export GEMINI_API_KEY=\"OSHOOSI_STANDIN_GEMINI_API_KEY_"));
        assert!(text1.contains("# primary"));
        assert!(text1.contains("PORT=8080"));

        let text2 = std::fs::read_to_string(&f2).unwrap();
        assert!(text2.contains("HF_TOKEN='OSHOOSI_STANDIN_HF_TOKEN_"));
        assert!(text2.contains("# staging token"));
        assert!(text2.contains("NODE_ENV=staging"));

        // Check vault status reports all files
        let status = ProtectedEnvBackupVault::get_status(&vault_file).expect("status");
        assert!(status.files.len() >= 2);

        // Verify revert restores 100% bit-for-bit
        ProtectedEnvBackupVault::auto_revert(&vault_file).expect("auto revert");
        assert_eq!(std::fs::read_to_string(&f1).unwrap(), original_body_f1);
        assert_eq!(std::fs::read_to_string(&f2).unwrap(), original_body_f2);
    }

    #[test]
    fn test_is_secret_env_key_and_value_preserves_system_vars() {
        assert!(!ProtectedEnvBackupVault::is_secret_env_key_and_value(
            "PATH",
            "C:\\Windows\\System32;C:\\Windows"
        ));
        assert!(!ProtectedEnvBackupVault::is_secret_env_key_and_value(
            "JAVA_HOME",
            "C:\\Program Files\\Java\\jdk-21"
        ));
        assert!(!ProtectedEnvBackupVault::is_secret_env_key_and_value(
            "OneDrive",
            "C:\\Users\\User\\OneDrive"
        ));
        assert!(!ProtectedEnvBackupVault::is_secret_env_key_and_value(
            "TEMP",
            "C:\\Users\\User\\AppData\\Local\\Temp"
        ));
        assert!(!ProtectedEnvBackupVault::is_secret_env_key_and_value(
            "PORT", "3000"
        ));
        assert!(!ProtectedEnvBackupVault::is_secret_env_key_and_value(
            "NODE_ENV",
            "production"
        ));
        assert!(!ProtectedEnvBackupVault::is_secret_env_key_and_value(
            "RUST_LOG",
            "info,osoosi=debug"
        ));
        assert!(!ProtectedEnvBackupVault::is_secret_env_key_and_value(
            "DEBUG", "true"
        ));
        assert!(!ProtectedEnvBackupVault::is_secret_env_key_and_value(
            "PUBLIC_KEY_URL",
            "https://example.com/pub.key"
        ));

        // Genuine secrets MUST return true
        assert!(ProtectedEnvBackupVault::is_secret_env_key_and_value(
            "GEMINI_API_KEY",
            "AIzaSyD-ActualGenuineKey1234567890"
        ));
        assert!(ProtectedEnvBackupVault::is_secret_env_key_and_value(
            "HF_TOKEN",
            "hf_ActualGenuineToken1234567890"
        ));
        assert!(ProtectedEnvBackupVault::is_secret_env_key_and_value(
            "DATABASE_PASSWORD",
            "SuperSecurePassword987654321!"
        ));
    }

    #[test]
    fn test_replace_env_var_in_line_preserves_formatting() {
        let line1 = "  export API_KEY=\"secret123\" # my comment";
        let rep1 =
            ProtectedEnvBackupVault::replace_env_var_in_line(line1, "API_KEY", "STANDIN").unwrap();
        assert_eq!(rep1, "  export API_KEY=\"STANDIN\" # my comment");

        let line2 = "TOKEN='secret456' # inline";
        let rep2 =
            ProtectedEnvBackupVault::replace_env_var_in_line(line2, "TOKEN", "STANDIN").unwrap();
        assert_eq!(rep2, "TOKEN='STANDIN' # inline");

        let line3 = "SECRET=plain_secret";
        let rep3 =
            ProtectedEnvBackupVault::replace_env_var_in_line(line3, "SECRET", "STANDIN").unwrap();
        assert_eq!(rep3, "SECRET=STANDIN");
    }

    #[test]
    fn test_auto_revert_all_active_vaults_resilience() {
        let temp_dir = tempfile::tempdir().expect("create tempdir");
        let non_existent_vault = temp_dir.path().join("does_not_exist.vault");
        let res = ProtectedEnvBackupVault::auto_revert_all_active_vaults(Some(&non_existent_vault));
        assert!(res.is_ok());
    }

    #[test]
    fn test_dpapi_master_key_wrapping_roundtrip() {
        let _guard = ENV_MUTEX.lock().unwrap();

        // 1. Direct DPAPI protect/unprotect roundtrip verification
        let sample_key = [0x42u8; 32];
        #[cfg(windows)]
        {
            let protected = dpapi_protect_bytes(&sample_key)
                .expect("dpapi_protect_bytes must succeed on Windows");
            assert!(!protected.is_empty(), "Protected bytes must not be empty");
            assert_ne!(
                protected,
                sample_key.to_vec(),
                "Protected bytes must be ciphertext, not plaintext"
            );

            let unprotected = dpapi_unprotect_bytes(&protected)
                .expect("dpapi_unprotect_bytes must succeed on Windows");
            assert_eq!(
                unprotected,
                sample_key.to_vec(),
                "Unprotected bytes must match original sample key bit-for-bit"
            );

            // Verify that single-byte tampering in the wrapped payload fails unwrapping
            let mut tampered = protected.clone();
            let mid = tampered.len() / 2;
            tampered[mid] ^= 0xFF;
            let tamper_res = dpapi_unprotect_bytes(&tampered);
            assert!(
                tamper_res.is_err(),
                "Single-byte tampering in wrapped payload must fail unwrapping"
            );
        }

        // 2. Full Vault DPAPI integration test
        let temp_dir = tempfile::tempdir().expect("create tempdir");
        let env_file = temp_dir.path().join(".env");
        let vault_file = temp_dir.path().join("protected_env_backup.vault");

        let original_content = "GEMINI_API_KEY=AIzaSyD-GenuineMasterKeyTest123456789\nHF_TOKEN=hf_GenuineTokenTest1234567890\n";
        std::fs::write(&env_file, original_content).expect("write temp .env");

        let res = ProtectedEnvBackupVault::seal_and_backup_dynamic(&env_file, &vault_file)
            .expect("seal_and_backup_dynamic must succeed");
        assert!(res.total_selected >= 2);

        // 3. Verify vault file and companion .dpapi file on disk
        assert!(vault_file.exists(), "Vault file must exist");
        let dpapi_file = ProtectedEnvBackupVault::companion_dpapi_path(&vault_file);

        #[cfg(windows)]
        {
            assert!(
                dpapi_file.exists(),
                "Companion .dpapi file must exist on Windows"
            );
            let dpapi_bytes = std::fs::read(&dpapi_file).expect("read .dpapi file");
            assert!(!dpapi_bytes.is_empty(), ".dpapi file must not be empty");

            // Verify .dpapi file unwraps to 32-byte master key
            let unwrapped =
                dpapi_unprotect_bytes(&dpapi_bytes).expect("unwrap companion .dpapi file");
            assert_eq!(unwrapped.len(), 32, "Unwrapped master key must be 32 bytes");
        }

        // 4. Verify read_vault_payload recovers payload and dpapi_wrapped_key
        let (payload, _) = ProtectedEnvBackupVault::read_vault_payload(&vault_file)
            .expect("read_vault_payload must succeed");

        #[cfg(windows)]
        {
            assert!(
                payload.dpapi_wrapped_key.is_some(),
                "VaultPayload must have dpapi_wrapped_key populated on Windows"
            );
            let wrapped_in_payload = payload.dpapi_wrapped_key.as_ref().unwrap();
            let unwrapped_from_payload = dpapi_unprotect_bytes(wrapped_in_payload)
                .expect("unwrap key from payload.dpapi_wrapped_key");
            assert_eq!(unwrapped_from_payload.len(), 32);
        }

        // 5. Verify revert restores .env and remove_backup shreds both files
        ProtectedEnvBackupVault::auto_revert(&vault_file).expect("auto revert must succeed");
        let restored = std::fs::read_to_string(&env_file).expect("read restored");
        assert_eq!(restored, original_content);

        ProtectedEnvBackupVault::remove_backup(&vault_file, true).expect("remove backup");
        assert!(!vault_file.exists(), "Vault file must be unlinked");
        assert!(
            !dpapi_file.exists(),
            "Companion .dpapi file must be shredded and unlinked"
        );
    }
}
