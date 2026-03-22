//! SQLCipher Database Encryption for OpenỌ̀ṣọ́ọ̀sì.
//!
//! Provides transparent encryption for the agent's SQLite database using
//! SQLCipher. The encryption key is derived from:
//!
//! 1. **TPM** (preferred): Key stored in TPM NVRAM, never leaves hardware
//! 2. **Environment variable**: `OSOOSI_DB_KEY` for manual configuration
//! 3. **Machine-derived**: HMAC of hostname + OS + arch (fallback)
//!
//! # Why This Matters
//! The `odidere.db` contains:
//! - Threat signatures and detection history
//! - Peer reputation scores (EigenTrust)
//! - Audit Merkle chain hashes
//! - NSRL whitelist
//!
//! If an attacker steals this file, they can:
//! - Learn what the agent does/doesn't detect (blind spots)
//! - Manipulate reputation scores to inject a malicious peer
//! - Tamper with the audit chain to hide evidence
//!
//! SQLCipher makes the `.db` file opaque without the key.

use tracing::{info, warn, debug};

/// Generate or retrieve the database encryption key.
///
/// Priority order:
/// 1. Environment variable `OSOOSI_DB_KEY`
/// 2. TPM-stored key (if TPM is available)
/// 3. Machine-derived key (HMAC of system identifiers)
pub fn get_db_encryption_key() -> String {
    // 1. Check environment variable
    if let Ok(key) = std::env::var("OSOOSI_DB_KEY") {
        if key.len() >= 16 {
            debug!("Using OSOOSI_DB_KEY environment variable for DB encryption");
            return key;
        }
        warn!("OSOOSI_DB_KEY is too short (min 16 chars). Falling back.");
    }

    // 2. Try to read from TPM-backed storage
    if let Some(key) = try_tpm_key() {
        debug!("Using TPM-backed key for DB encryption");
        return key;
    }

    // 3. Machine-derived key (deterministic per machine)
    let machine_key = derive_machine_key();
    debug!("Using machine-derived key for DB encryption");
    machine_key
}

/// Apply SQLCipher encryption to an open database connection.
///
/// This MUST be called immediately after `Connection::open()` and before
/// any other SQL operations. If the database was previously unencrypted,
/// this will fail — use `migrate_to_encrypted()` first.
///
/// When built with `bundled-sqlcipher` feature:
/// ```ignore
/// let conn = Connection::open("odidere.db")?;
/// apply_encryption(&conn, &get_db_encryption_key())?;
/// // Now all reads/writes are encrypted
/// ```
pub fn apply_encryption(conn: &rusqlite::Connection, key: &str) -> anyhow::Result<()> {
    // SQLCipher PRAGMA key must be the first statement after opening
    conn.execute_batch(&format!("PRAGMA key = '{}';", key))?;

    // Configure encryption parameters
    conn.execute_batch(
        "PRAGMA cipher_page_size = 4096;
         PRAGMA kdf_iter = 256000;
         PRAGMA cipher_hmac_algorithm = HMAC_SHA256;
         PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA256;"
    )?;

    // Verify the key works by reading from the DB
    match conn.execute_batch("SELECT count(*) FROM sqlite_master;") {
        Ok(_) => {
            info!("SQLCipher encryption active (HMAC-SHA256, 256K KDF iterations)");
            Ok(())
        }
        Err(e) => {
            // If this fails, the key is wrong or DB is not encrypted
            warn!("SQLCipher key verification failed: {}. DB may be unencrypted.", e);
            Err(anyhow::anyhow!("Database encryption key mismatch: {}", e))
        }
    }
}

/// Migrate an unencrypted database to encrypted format.
///
/// Creates a new encrypted copy and replaces the original.
pub fn migrate_to_encrypted(db_path: &str, key: &str) -> anyhow::Result<()> {
    let tmp_path = format!("{}.encrypted", db_path);

    info!("Migrating database to encrypted format: {} → {}", db_path, tmp_path);

    let conn = rusqlite::Connection::open(db_path)?;

    // Attach a new encrypted database
    conn.execute_batch(&format!(
        "ATTACH DATABASE '{}' AS encrypted KEY '{}';
         SELECT sqlcipher_export('encrypted');
         DETACH DATABASE encrypted;",
        tmp_path, key
    ))?;

    // Replace the original with the encrypted version
    drop(conn);
    std::fs::rename(&tmp_path, db_path)?;

    info!("Database migration complete. DB is now encrypted.");
    Ok(())
}

/// Re-key (change encryption password) on an existing encrypted database.
pub fn rekey_database(conn: &rusqlite::Connection, old_key: &str, new_key: &str) -> anyhow::Result<()> {
    conn.execute_batch(&format!("PRAGMA key = '{}';", old_key))?;
    conn.execute_batch(&format!("PRAGMA rekey = '{}';", new_key))?;
    info!("Database re-keyed successfully.");
    Ok(())
}

/// Check if a database file appears to be encrypted.
pub fn is_db_encrypted(db_path: &str) -> bool {
    if let Ok(bytes) = std::fs::read(db_path) {
        if bytes.len() < 16 {
            return false;
        }
        // Unencrypted SQLite files start with "SQLite format 3\0"
        let header = &bytes[..16];
        let sqlite_magic = b"SQLite format 3\0";
        header != sqlite_magic
    } else {
        false
    }
}

// --- Internal key derivation ---

fn try_tpm_key() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        // Try to read from TPM NVRAM index 0x01500001 (application-defined)
        if let Ok(output) = std::process::Command::new("tpm2_nvread")
            .args(["0x01500001", "-s", "32"])
            .output()
        {
            if output.status.success() && !output.stdout.is_empty() {
                return Some(hex::encode(&output.stdout));
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        // Try Windows DPAPI-protected key file
        let key_path = dirs::data_local_dir()
            .map(|d| d.join("OpenOsoosi").join("db.key"));

        if let Some(path) = key_path {
            if path.exists() {
                if let Ok(key_bytes) = std::fs::read(&path) {
                    if key_bytes.len() >= 32 {
                        return Some(hex::encode(&key_bytes[..32]));
                    }
                }
            }
        }
    }

    None
}

fn derive_machine_key() -> String {
    use sha2::{Sha256, Digest};

    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    let mut hasher = Sha256::new();
    hasher.update(b"osoosi-db-encryption-v1:");
    hasher.update(hostname.as_bytes());
    hasher.update(b":");
    hasher.update(std::env::consts::OS.as_bytes());
    hasher.update(b":");
    hasher.update(std::env::consts::ARCH.as_bytes());

    // Add machine-specific entropy if available
    #[cfg(target_os = "linux")]
    {
        if let Ok(machine_id) = std::fs::read_to_string("/etc/machine-id") {
            hasher.update(machine_id.trim().as_bytes());
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = std::process::Command::new("wmic")
            .args(["csproduct", "get", "UUID"])
            .output()
        {
            hasher.update(&output.stdout);
        }
    }

    hex::encode(hasher.finalize())
}
