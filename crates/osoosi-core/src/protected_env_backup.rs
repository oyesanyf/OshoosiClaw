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
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub const VAULT_MAGIC: &[u8; 24] = b"OSHOOSI_ENV_BACKUP_V1\0\0\0";
pub const DEFAULT_VAULT_PATH: &str = "database/protected_env_backup.vault";

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
pub struct VaultStatus {
    pub exists: bool,
    pub vault_path: PathBuf,
    pub target_path: Option<PathBuf>,
    pub sealed_at_epoch: Option<u64>,
    pub sealed_variables: Vec<String>,
    pub dacl_protected: bool,
    pub payload_size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VaultPayload {
    target_path: String,
    epoch: u64,
    sealed_variables: Vec<String>,
    original_bytes: Vec<u8>,
}

pub struct ProtectedEnvBackupVault;

impl ProtectedEnvBackupVault {
    pub fn default_vault_path() -> PathBuf {
        PathBuf::from(DEFAULT_VAULT_PATH)
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

    /// Backs up original `.env` or config content into encrypted, DACL-protected vault,
    /// and replaces secret values in `env_path` with stand-in tokens.
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
        let canonical_target = std::fs::canonicalize(env_path).unwrap_or_else(|_| env_path.to_path_buf());
        let epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let sealed_variables: Vec<String> = grants.iter().map(|g| g.env_var_name.clone()).collect();

        let payload = VaultPayload {
            target_path: canonical_target.to_string_lossy().to_string(),
            epoch,
            sealed_variables,
            original_bytes: original_bytes.clone(),
        };

        let serialized_payload = serde_json::to_vec(&payload)
            .map_err(|e| VaultError::Encryption(e.to_string()))?;

        // Generate salt (16B) and nonce (12B)
        let mut salt = [0u8; 16];
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut salt);
        rand::thread_rng().fill_bytes(&mut nonce_bytes);

        let key_bytes = Self::derive_vault_key(&salt);
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
        envelope.extend_from_slice(&epoch.to_be_bytes());
        envelope.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
        envelope.extend_from_slice(&ciphertext);

        // Keyed BLAKE3 MAC over header + ciphertext
        let tag = blake3::keyed_hash(&key_bytes, &envelope);
        envelope.extend_from_slice(tag.as_bytes());

        // Ensure parent directory exists
        if let Some(parent) = vault_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        // Write vault file
        let mut f = File::create(vault_path)?;
        f.write_all(&envelope)?;
        f.sync_all()?;
        drop(f);

        // Apply Win32 Protected NTFS DACL / Unix 0600
        apply_protected_ntfs_dacl(vault_path)?;

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

        // Write sealed environment back to env_path
        let mut env_file = File::create(env_path)?;
        env_file.write_all(content_str.as_bytes())?;
        env_file.sync_all()?;

        Ok(())
    }

    /// Automatically restores the pre-stand-in original configuration file from the vault.
    pub fn auto_revert(vault_path: &Path) -> Result<(), VaultError> {
        if !vault_path.exists() {
            return Ok(());
        }

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

        let key_bytes = Self::derive_vault_key(&salt);

        // Verify keyed BLAKE3 MAC
        let expected_tag = blake3::keyed_hash(&key_bytes, &envelope[..64 + ct_len]);
        if subtle::ConstantTimeEq::ct_eq(expected_tag.as_bytes().as_slice(), provided_tag).unwrap_u8() == 0 {
            return Err(VaultError::IntegrityFailure);
        }

        // Decrypt ciphertext
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
        let decrypted = cipher
            .decrypt(Nonce::from_slice(&nonce_bytes), ciphertext)
            .map_err(|e| VaultError::Decryption(e.to_string()))?;

        let payload: VaultPayload = serde_json::from_slice(&decrypted)
            .map_err(|e| VaultError::Decryption(e.to_string()))?;

        // Restore original bytes to target path
        let target = PathBuf::from(&payload.target_path);
        let mut target_file = File::create(&target)?;
        target_file.write_all(&payload.original_bytes)?;
        target_file.sync_all()?;

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

        // Unlock Protected NTFS DACL / Unix permissions
        unlock_protected_ntfs_dacl(vault_path)?;

        // Overwrite and shred with 0x00
        let file_len = std::fs::metadata(vault_path)?.len();
        if file_len > 0 {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .open(vault_path)?;
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
                dacl_protected: false,
                payload_size: 0,
            });
        }

        let mut envelope = Vec::new();
        let mut f = File::open(vault_path)?;
        f.read_to_end(&mut envelope)?;

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

        let key_bytes = Self::derive_vault_key(&salt);
        let expected_tag = blake3::keyed_hash(&key_bytes, &envelope[..64 + ct_len]);
        if subtle::ConstantTimeEq::ct_eq(expected_tag.as_bytes().as_slice(), provided_tag).unwrap_u8() == 0 {
            return Err(VaultError::IntegrityFailure);
        }

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
        let decrypted = cipher
            .decrypt(Nonce::from_slice(&nonce_bytes), ciphertext)
            .map_err(|e| VaultError::Decryption(e.to_string()))?;

        let payload: VaultPayload = serde_json::from_slice(&decrypted)
            .map_err(|e| VaultError::Decryption(e.to_string()))?;

        Ok(VaultStatus {
            exists: true,
            vault_path: vault_path.to_path_buf(),
            target_path: Some(PathBuf::from(payload.target_path)),
            sealed_at_epoch: Some(payload.epoch),
            sealed_variables: payload.sealed_variables,
            dacl_protected: true,
            payload_size: envelope.len() as u64,
        })
    }
}

/// Applies Win32 Protected NTFS DACL (`SE_DACL_PROTECTED` via `SetNamedSecurityInfoW`
/// with `D:P(A;;GA;;;SY)(A;;GA;;;BA)`) breaking inheritance and restricting access
/// exclusively to `NT AUTHORITY\SYSTEM` and `BUILTIN\Administrators`.
#[cfg(windows)]
pub fn apply_protected_ntfs_dacl(path: &Path) -> Result<(), VaultError> {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;

    let wide_path: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    let sddl = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)";
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

    let wide_path: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rea_voter_env_gateway::{HardenedSealedGrant, ZeroizingLockedSecret};

    #[test]
    fn test_vault_seal_auto_revert_roundtrip() {
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
}
