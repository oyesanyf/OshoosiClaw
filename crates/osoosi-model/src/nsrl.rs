//! NIST NSRL (National Software Reference Library) Whitelisting.
//!
//! Ingests the NSRL RDS (Reference Data Set) so the agent can skip
//! scanning known-good files. This prevents denial-of-service attacks
//! where an attacker floods the scan queue with legitimate system files.
//!
//! The NSRL database contains SHA-256 hashes of known, trusted software
//! (OS files, common applications, drivers). Files matching these hashes
//! are immediately cleared without ML/YARA analysis.

use rusqlite::{params, Connection};
use std::path::Path;
use tracing::{info, debug};

/// NSRL ingester and lookup engine.
pub struct NsrlIngester {
    conn: Connection,
}

impl NsrlIngester {
    /// Open or create the NSRL whitelist database.
    pub fn new(db_path: &Path) -> anyhow::Result<Self> {
        let conn = Connection::open(db_path)?;

        // Create the whitelist table with an index for fast lookups
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS nsrl_whitelist (
                sha256 TEXT PRIMARY KEY,
                product_name TEXT,
                os_name TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_nsrl_sha256 ON nsrl_whitelist(sha256);"
        )?;

        info!("NSRL whitelist database opened: {:?}", db_path);
        Ok(Self { conn })
    }

    /// Ingest NSRL RDS v3 (SQLite format) into the local whitelist.
    ///
    /// The NSRL RDS v3 is distributed as an SQLite database. This method
    /// attaches it and performs a high-speed cross-database transfer.
    ///
    /// Download RDS from: https://www.nist.gov/itl/ssd/software-quality-group/nsrl-resources
    pub fn ingest_rds_v3(&self, rds_path: &Path) -> anyhow::Result<usize> {
        if !rds_path.exists() {
            anyhow::bail!("NSRL RDS file not found: {:?}", rds_path);
        }

        info!("Ingesting NSRL RDS v3 from {:?} (this may take several minutes)...", rds_path);

        // Attach the NSRL database
        self.conn.execute(
            &format!("ATTACH DATABASE '{}' AS nist", rds_path.display()),
            [],
        )?;

        // Bulk insert — uses SQLite's efficient cross-DB transfer
        let count = self.conn.execute(
            "INSERT OR IGNORE INTO nsrl_whitelist (sha256)
             SELECT sha256 FROM nist.FILE WHERE sha256 IS NOT NULL",
            [],
        )?;

        self.conn.execute("DETACH DATABASE nist", [])?;

        info!("NSRL ingestion complete: {} known-good hashes imported", count);
        Ok(count)
    }

    /// Ingest NSRL from CSV format (legacy RDS v2).
    ///
    /// Reads the NSRLFile.txt CSV and extracts SHA-256 hashes.
    pub fn ingest_csv(&self, csv_path: &Path) -> anyhow::Result<usize> {
        use std::io::{BufRead, BufReader};

        if !csv_path.exists() {
            anyhow::bail!("NSRL CSV file not found: {:?}", csv_path);
        }

        info!("Ingesting NSRL CSV from {:?}...", csv_path);

        let file = std::fs::File::open(csv_path)?;
        let reader = BufReader::new(file);
        let mut count = 0usize;

        // Begin transaction for bulk insert performance
        let tx = self.conn.unchecked_transaction()?;

        for line in reader.lines().skip(1) {
            // Skip header
            let line = match line {
                Ok(l) => l,
                Err(_) => continue,
            };

            // CSV format: "SHA-1","MD5","CRC32","FileName","FileSize","ProductCode","OpSystemCode","SpecialCode","SHA-256"
            let fields: Vec<&str> = line.split(',').collect();
            if fields.len() >= 9 {
                let sha256 = fields[8].trim().trim_matches('"');
                if sha256.len() == 64 {
                    let _ = tx.execute(
                        "INSERT OR IGNORE INTO nsrl_whitelist (sha256) VALUES (?1)",
                        params![sha256.to_lowercase()],
                    );
                    count += 1;
                }
            }

            if count % 500_000 == 0 && count > 0 {
                debug!("NSRL CSV progress: {} hashes processed", count);
            }
        }

        tx.commit()?;
        info!("NSRL CSV ingestion complete: {} hashes imported", count);
        Ok(count)
    }

    /// Check if a SHA-256 hash is in the NSRL whitelist (known-good).
    pub fn is_known_good(&self, sha256: &str) -> bool {
        let normalized = sha256.to_lowercase();
        match self.conn.query_row(
            "SELECT 1 FROM nsrl_whitelist WHERE sha256 = ?1 LIMIT 1",
            params![normalized],
            |_row| Ok(true),
        ) {
            Ok(true) => true,
            _ => false,
        }
    }

    /// Get the total count of known-good hashes in the whitelist.
    pub fn count(&self) -> usize {
        self.conn
            .query_row("SELECT COUNT(*) FROM nsrl_whitelist", [], |row: &rusqlite::Row| row.get(0))
            .unwrap_or(0)
    }

    /// Batch check multiple hashes. Returns the set of hashes that are known-good.
    pub fn batch_check(&self, hashes: &[String]) -> Vec<String> {
        hashes
            .iter()
            .filter(|h| self.is_known_good(h))
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_nsrl_create_and_lookup() {
        // Use a temp file for testing
        let tmp = std::env::temp_dir().join("test_nsrl.db");
        let ingester = NsrlIngester::new(&tmp).expect("create nsrl db");

        // Insert a test hash
        ingester.conn.execute(
            "INSERT INTO nsrl_whitelist (sha256) VALUES (?1)",
            params!["abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"],
        ).unwrap();

        assert!(ingester.is_known_good("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"));
        assert!(!ingester.is_known_good("0000000000000000000000000000000000000000000000000000000000000000"));
        assert_eq!(ingester.count(), 1);

        let _ = std::fs::remove_file(&tmp);
    }
}
