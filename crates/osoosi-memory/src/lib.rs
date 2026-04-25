//! Local SQLite persistence for threat intelligence and file integrity.

use rusqlite::{params, Connection};
use osoosi_types::{Kev, ThreatSignature, ReputationScore, PendingJoinRequest, QuarantinedPeer, ResponseAction, ActionState, PeerAnnounce, PeerStatus, MalwareSample};
use chrono::{DateTime, Utc};
use tracing::debug;
use std::path::Path;
use std::sync::Mutex;

pub mod encryption;
pub mod scanner;
pub mod memory_scanner;

pub use memory_scanner::*;

pub struct MemoryStore {
    conn: Mutex<Connection>,
    bloom_filter: Mutex<bloomfilter::Bloom<String>>,
}

impl MemoryStore {
    pub fn new(path: &str) -> anyhow::Result<Self> {
        let conn = Connection::open(path)?;

        // SQLCipher: Apply encryption if available and DB is not in-memory
        if path != ":memory:" {
            let key = encryption::get_db_encryption_key();
            // Try to apply encryption — if rusqlite wasn't compiled with sqlcipher,
            // the PRAGMA key will be silently ignored (no-op).
            let _ = encryption::apply_encryption(&conn, &key);
        }

        let lock = Mutex::new(conn);
        
        // Initialize Bloom filter: 1,000,000 items with 0.01% false positive rate
        let bloom = bloomfilter::Bloom::new_for_fp_rate(1_000_000, 0.0001);
        
        let s = Self { 
            conn: lock,
            bloom_filter: Mutex::new(bloom),
        };
        s.init_db()?;
        s.repopulate_bloom_filter()?;
        Ok(s)
    }

    fn init_db(&self) -> anyhow::Result<()> {
        debug!("Initializing memory store tables...");
        let conn = self.conn.lock().unwrap();
        
        // KEV table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS kev (
                cve_id TEXT PRIMARY KEY,
                vendor_project TEXT,
                product TEXT,
                vulnerability_name TEXT,
                date_added TEXT,
                required_action TEXT,
                known_exploited INTEGER
            )",
            [],
        )?;

        // File Integrity table: caches scan results for paths (performance optimization)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS file_integrity (
                path TEXT PRIMARY KEY,
                hash_blake3 TEXT,
                is_nsrl_validated INTEGER DEFAULT 0,
                product_version TEXT,
                last_seen TEXT
            )",
            [],
        )?;

        // Detected Threats table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS threats (
                id TEXT PRIMARY KEY,
                cve_id TEXT,
                hash_blake3 TEXT,
                process_name TEXT,
                confidence REAL,
                detected_at TEXT,
                source_node TEXT,
                file_path TEXT,
                reason TEXT
            )",
            [],
        )?;

        // Reputation scores for mesh peers (EigenTrust-lite)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS reputation (
                node_id TEXT PRIMARY KEY,
                score REAL,
                alerts_verified INTEGER,
                false_positives INTEGER,
                last_updated TEXT
            )",
            [],
        )?;

        // Pending join requests (awaiting user approval)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS pending_joins (
                peer_id TEXT PRIMARY KEY,
                multiaddr TEXT,
                reputation_score REAL,
                alerts_verified INTEGER,
                false_positives INTEGER,
                discovered_at TEXT
            )",
            [],
        )?;

        // Quarantined peers (blocked from mesh messaging/discovery)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS quarantined_peers (
                peer_id TEXT PRIMARY KEY,
                reason TEXT,
                reputation_score REAL,
                quarantined_at TEXT,
                released_at TEXT,
                active INTEGER
            )",
            [],
        )?;

        // Repair Engine status (last patch, pending count)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS repair_status (
                key TEXT PRIMARY KEY,
                value TEXT,
                updated_at TEXT
            )",
            [],
        )?;

        // Backup status (last run, result)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS backup_status (
                key TEXT PRIMARY KEY,
                value TEXT,
                updated_at TEXT
            )",
            [],
        )?;

        // Model training status (last run/health/metrics)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS model_training_status (
                key TEXT PRIMARY KEY,
                value TEXT,
                updated_at TEXT
            )",
            [],
        )?;

        // File skip list: paths that failed to hash (locked, permission denied) — avoid retry spam
        conn.execute(
            "CREATE TABLE IF NOT EXISTS file_skip_list (
                path TEXT PRIMARY KEY,
                reason TEXT,
                added_at TEXT
            )",
            [],
        )?;

        // Distributed malware classifier: samples from mesh for EMBER-style training
        conn.execute(
            "CREATE TABLE IF NOT EXISTS malware_samples (
                file_hash TEXT PRIMARY KEY,
                source_node TEXT,
                label INTEGER,
                features_json TEXT,
                feature_version TEXT,
                received_at TEXT
            )",
            [],
        )?;

        // Federated: false positive patterns (process_name, hash) shared across mesh
        conn.execute(
            "CREATE TABLE IF NOT EXISTS false_positive_patterns (
                process_name TEXT,
                hash_blake3 TEXT,
                source_node TEXT,
                marked_at TEXT,
                PRIMARY KEY (process_name, hash_blake3)
            )",
            [],
        )?;

        // Peer status from PeerAnnounce (for join rules: require_patched, require_supported_os)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS peer_status (
                peer_id TEXT PRIMARY KEY,
                is_patched INTEGER,
                os_name TEXT,
                os_version TEXT,
                os_supported INTEGER,
                received_at TEXT
            )",
            [],
        )?;

        // OTX Indicators table (synchronized from OTX TAXII / pulses)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS otx_indicators (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator_type TEXT NOT NULL,
                value TEXT NOT NULL,
                source TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                UNIQUE(indicator_type, value, source)
            )",
            [],
        )?;

        // NSRL (National Software Reference Library) Known Good table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS nsrl (
                sha1 TEXT PRIMARY KEY,
                md5 TEXT,
                sha256 TEXT,
                file_name TEXT,
                file_size INTEGER,
                product_code TEXT,
                os_code TEXT
            )",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_nsrl_sha1 ON nsrl(sha1)",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_otx_lookup ON otx_indicators(indicator_type, value)",
            [],
        )?;

        Ok(())
    }

    /// Check if a SHA1 hash exists in the NSRL 'Known Good' list (compares lowercase hex).
    pub fn is_nsrl_known_good(&self, sha1: &str) -> anyhow::Result<bool> {
        let key = sha1.trim().to_ascii_lowercase();
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare_cached("SELECT 1 FROM nsrl WHERE sha1 = ? LIMIT 1")?;
        let exists = stmt.exists([key])?;
        Ok(exists)
    }

    /// Bulk-import NSRL from an official NIST **RDS** SQLite (Modern `FILE` table) by `ATTACH` + `INSERT…SELECT`.
    /// This avoids loading millions of rows into Rust and completes much faster with lower RAM use than
    /// `import_nsrl_from_sqlite` + `upsert_nsrl_records`. Safe to run while the agent is up (WAL + readers).
    pub fn import_nsrl_from_nist_rds_sqlite(&self, nist_rds_path: &Path) -> anyhow::Result<u64> {
        let p = nist_rds_path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("NSRL RDS path is not valid UTF-8"))?;
        if !nist_rds_path.exists() {
            anyhow::bail!("NSRL RDS file not found: {:?}", nist_rds_path);
        }
        let mut conn = self.conn.lock().unwrap();
        let before: u64 = conn.query_row("SELECT COUNT(*) FROM nsrl", [], |r| r.get(0))?;

        // Tuned for one-shot bulk copy (reduces disk sync overhead; still crash-safe on WAL).
        let _ = conn.query_row("PRAGMA journal_mode", [], |r: &rusqlite::Row| -> rusqlite::Result<String> {
            r.get(0)
        });
        let _ = conn.execute("PRAGMA synchronous = NORMAL", []);
        let _ = conn.execute("PRAGMA temp_store = MEMORY", []);
        // ~200MB page cache: speeds reading the attached NIST file (env overridable for fast SSDs)
        let cache_kb: i32 = std::env::var("OSOOSI_NSRL_IMPORT_CACHE_KB")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(200_000i32);
        let _ = conn.execute(&format!("PRAGMA cache_size = -{cache_kb}"), []);
        // SQLite 3.39+: extra worker threads for large INSERT..SELECT (default env: 4; set 0 to leave default)
        if let Some(t) = std::env::var("OSOOSI_NSRL_IMPORT_THREADS")
            .ok()
            .and_then(|s| s.parse::<i32>().ok())
        {
            if t > 0 {
                let t = t.clamp(1, 32);
                let _ = conn.execute(&format!("PRAGMA threads = {t}"), []);
            }
        } else {
            let _ = conn.execute("PRAGMA threads = 4", []);
        }

        let tx = conn.transaction()?;
        tx.execute("ATTACH DATABASE ? AS nist", [p])?;
        let file_tbl: i64 = tx.query_row(
            "SELECT COUNT(*) FROM nist.sqlite_master WHERE type='table' AND name='FILE'",
            [],
            |r| r.get(0),
        )?;
        if file_tbl == 0 {
            let _ = tx.execute("DETACH DATABASE nist", []);
            tx.commit()?;
            anyhow::bail!("NSRL file has no FILE table (expected NIST modern RDS): {:?}", nist_rds_path);
        }

        // Map NIST `FILE` columns → our schema; hashes in RDS are typically hex strings.
        tx.execute(
            "INSERT OR REPLACE INTO main.nsrl (sha1, md5, sha256, file_name, file_size, product_code, os_code)
             SELECT lower(sha1), lower(md5), lower(sha256), name, size, product, os FROM nist.FILE",
            [],
        )?;

        let _ = tx.execute("DETACH DATABASE nist", []);
        tx.commit()?;

        let after: u64 = conn.query_row("SELECT COUNT(*) FROM nsrl", [], |r| r.get(0))?;
        // Restore conservative sync for steady-state operation (small cost).
        let _ = conn.execute("PRAGMA synchronous = FULL", []);
        let _ = conn.execute("PRAGMA cache_size = -2000", []); // back to a modest default
        let _ = conn.execute("PRAGMA threads = 0", []); // restore SQLite default worker count
        let added = after.saturating_sub(before);
        debug!(
            "NSRL bulk import: +{} rows (total {} in nsrl) from {:?}",
            added, after, nist_rds_path
        );
        Ok(added)
    }

    /// Upsert a batch of NSRL records.
    pub fn upsert_nsrl_records(&self, records: &[osoosi_types::NsrlRecord]) -> anyhow::Result<()> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        {
            let mut stmt = tx.prepare_cached(
                "INSERT OR REPLACE INTO nsrl (sha1, md5, sha256, file_name, file_size, product_code, os_code) 
                 VALUES (?, ?, ?, ?, ?, ?, ?)"
            )?;
            for r in records {
                let sha1 = r.sha1.to_ascii_lowercase();
                let md5 = r.md5.as_ref().map(|s| s.to_ascii_lowercase());
                let sha256 = r.sha256.as_ref().map(|s| s.to_ascii_lowercase());
                stmt.execute(params![
                    sha1,
                    md5,
                    sha256,
                    r.file_name,
                    r.file_size,
                    r.product_code,
                    r.os_code,
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Count NSRL records in the database.
    pub fn nsrl_record_count(&self) -> anyhow::Result<u64> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM nsrl",
            [],
            |r| r.get(0),
        )?;
        Ok(count.max(0) as u64)
    }

    /// Retrieve the cached integrity status for a file path.
    /// Returns (hash_blake3, is_nsrl_validated, product_version).
    pub fn get_file_integrity(&self, path: &str) -> anyhow::Result<Option<(String, bool, Option<String>)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare_cached("SELECT hash_blake3, is_nsrl_validated, product_version FROM file_integrity WHERE path = ?")?;
        let mut rows = stmt.query([path])?;
        if let Some(row) = rows.next()? {
            Ok(Some((row.get(0)?, row.get::<_, i32>(1)? == 1, row.get(2)?)))
        } else {
            Ok(None)
        }
    }

    /// Record a file's integrity status.
    pub fn upsert_file_integrity(&self, path: &str, hash: &str, is_nsrl: bool, version: Option<&str>) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO file_integrity (path, hash_blake3, is_nsrl_validated, product_version, last_seen) VALUES (?, ?, ?, ?, ?)",
            params![path, hash, if is_nsrl { 1 } else { 0 }, version, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn insert_kev(&self, kev: &Kev) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO kev (cve_id, vendor_project, product, vulnerability_name, date_added, required_action, known_exploited)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                kev.cve_id,
                kev.vendor_project,
                kev.product,
                kev.vulnerability_name,
                kev.date_added.to_rfc3339(),
                kev.required_action,
                if kev.known_exploited { 1 } else { 0 }
            ],
        )?;
        Ok(())
    }

    /// Batch insert KEVs in a single transaction to avoid database lock contention.
    pub fn insert_kevs_batch(&self, kevs: &[Kev]) -> anyhow::Result<()> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        for kev in kevs {
            tx.execute(
                "INSERT OR REPLACE INTO kev (cve_id, vendor_project, product, vulnerability_name, date_added, required_action, known_exploited)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    kev.cve_id,
                    kev.vendor_project,
                    kev.product,
                    kev.vulnerability_name,
                    kev.date_added.to_rfc3339(),
                    kev.required_action,
                    if kev.known_exploited { 1 } else { 0 }
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn get_kev(&self, cve_id: &str) -> anyhow::Result<Option<Kev>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT * FROM kev WHERE cve_id = ?1")?;
        let mut rows = stmt.query(params![cve_id])?;
        
        if let Some(row) = rows.next()? {
            Ok(Some(Kev {
                cve_id: row.get(0)?,
                vendor_project: row.get(1)?,
                product: row.get(2)?,
                vulnerability_name: row.get(3)?,
                date_added: DateTime::parse_from_rfc3339(&row.get::<_, String>(4)?)?.with_timezone(&Utc),
                required_action: row.get(5)?,
                due_date: Utc::now(), // Placeholder as it's not in schema currently
                known_exploited: row.get::<_, i32>(6)? == 1,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn get_all_kevs(&self) -> anyhow::Result<Vec<Kev>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT * FROM kev")?;
        let rows = stmt.query_map([], |row| {
            Ok(Kev {
                cve_id: row.get(0)?,
                vendor_project: row.get(1)?,
                product: row.get(2)?,
                vulnerability_name: row.get(3)?,
                date_added: DateTime::parse_from_rfc3339(&row.get::<_, String>(4)?)
                    .map_err(|_| rusqlite::Error::InvalidQuery)?
                    .with_timezone(&Utc),
                required_action: row.get(5)?,
                due_date: Utc::now(),
                known_exploited: row.get::<_, i32>(6)? == 1,
            })
        })?;

        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn update_file_hash(&self, path: &str, hash: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO file_integrity (path, hash_blake3, last_seen)
             VALUES (?1, ?2, ?3)",
            params![path, hash, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn set_repair_status(&self, key: &str, value: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO repair_status (key, value, updated_at) VALUES (?1, ?2, ?3)",
            params![key, value, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn get_repair_status(&self, key: &str) -> anyhow::Result<Option<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT value FROM repair_status WHERE key = ?1")?;
        let res = stmt.query_row(params![key], |row| row.get(0)).ok();
        Ok(res)
    }

    pub fn set_backup_status(&self, key: &str, value: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO backup_status (key, value, updated_at) VALUES (?1, ?2, ?3)",
            params![key, value, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn get_backup_status(&self, key: &str) -> anyhow::Result<Option<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT value FROM backup_status WHERE key = ?1")?;
        let res = stmt.query_row(params![key], |row| row.get(0)).ok();
        Ok(res)
    }

    pub fn set_model_training_status(&self, key: &str, value: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO model_training_status (key, value, updated_at) VALUES (?1, ?2, ?3)",
            params![key, value, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn get_model_training_status(&self, key: &str) -> anyhow::Result<Option<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT value FROM model_training_status WHERE key = ?1")?;
        let res = stmt.query_row(params![key], |row| row.get(0)).ok();
        Ok(res)
    }

    pub fn get_file_hash(&self, path: &str) -> anyhow::Result<Option<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT hash_blake3 FROM file_integrity WHERE path = ?1")?;
        let res = stmt.query_row(params![path], |row| row.get(0)).ok();
        Ok(res)
    }

    /// Add a path to the skip list (e.g. locked files that cannot be hashed).
    pub fn add_file_to_skip_list(&self, path: &str, reason: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO file_skip_list (path, reason, added_at) VALUES (?1, ?2, ?3)",
            params![path, reason, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    /// Check if a path is in the skip list.
    pub fn is_file_in_skip_list(&self, path: &str) -> anyhow::Result<bool> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT 1 FROM file_skip_list WHERE path = ?1")?;
        let res = stmt.exists(params![path])?;
        Ok(res)
    }

    pub fn get_reputation(&self, node_id: &str) -> anyhow::Result<Option<ReputationScore>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT node_id, score, alerts_verified, false_positives, last_updated FROM reputation WHERE node_id = ?1"
        )?;
        let mut rows = stmt.query(params![node_id])?;
        if let Some(row) = rows.next()? {
            Ok(Some(ReputationScore {
                node_id: row.get(0)?,
                score: row.get(1)?,
                alerts_verified: row.get(2)?,
                false_positives: row.get(3)?,
                last_updated: DateTime::parse_from_rfc3339(&row.get::<_, String>(4)?)?.with_timezone(&Utc),
            }))
        } else {
            Ok(None)
        }
    }

    pub fn upsert_reputation(&self, rep: &ReputationScore) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO reputation (node_id, score, alerts_verified, false_positives, last_updated)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                rep.node_id,
                rep.score,
                rep.alerts_verified,
                rep.false_positives,
                rep.last_updated.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn add_pending_join(&self, req: &PendingJoinRequest) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO pending_joins (peer_id, multiaddr, reputation_score, alerts_verified, false_positives, discovered_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                req.peer_id,
                req.multiaddr,
                req.reputation_score,
                req.alerts_verified,
                req.false_positives,
                req.discovered_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn get_pending_joins(&self) -> anyhow::Result<Vec<PendingJoinRequest>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT peer_id, multiaddr, reputation_score, alerts_verified, false_positives, discovered_at FROM pending_joins"
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(PendingJoinRequest {
                peer_id: row.get(0)?,
                multiaddr: row.get(1)?,
                reputation_score: row.get(2)?,
                alerts_verified: row.get(3)?,
                false_positives: row.get(4)?,
                discovered_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(5)?)
                    .map_err(|_| rusqlite::Error::InvalidQuery)?
                    .with_timezone(&Utc),
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn remove_pending_join(&self, peer_id: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM pending_joins WHERE peer_id = ?1", params![peer_id])?;
        Ok(())
    }

    pub fn upsert_peer_status(&self, announce: &PeerAnnounce) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO peer_status (peer_id, is_patched, os_name, os_version, os_supported, received_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                announce.source_node,
                if announce.is_patched { 1 } else { 0 },
                announce.os_name,
                announce.os_version,
                if announce.os_supported { 1 } else { 0 },
                announce.timestamp.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn get_peer_status(&self, peer_id: &str) -> anyhow::Result<Option<PeerStatus>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT peer_id, is_patched, os_name, os_version, os_supported, received_at FROM peer_status WHERE peer_id = ?1"
        )?;
        let mut rows = stmt.query(params![peer_id])?;
        if let Some(row) = rows.next()? {
            return Ok(Some(PeerStatus {
                peer_id: row.get(0)?,
                is_patched: row.get::<_, i32>(1)? != 0,
                os_name: row.get(2)?,
                os_version: row.get(3)?,
                os_supported: row.get::<_, i32>(4)? != 0,
                received_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(5)?)
                    .map_err(|_| rusqlite::Error::InvalidQuery)?
                    .with_timezone(&Utc),
            }));
        }
        Ok(None)
    }

    pub fn quarantine_peer(&self, peer_id: &str, reason: &str, reputation_score: f32) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO quarantined_peers (peer_id, reason, reputation_score, quarantined_at, released_at, active)
             VALUES (?1, ?2, ?3, ?4, NULL, 1)",
            params![peer_id, reason, reputation_score, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn release_quarantined_peer(&self, peer_id: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE quarantined_peers SET active = 0, released_at = ?2 WHERE peer_id = ?1",
            params![peer_id, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn is_peer_quarantined(&self, peer_id: &str) -> anyhow::Result<bool> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT 1 FROM quarantined_peers WHERE peer_id = ?1 AND active = 1")?;
        let exists = stmt.exists(params![peer_id])?;
        Ok(exists)
    }

    pub fn get_quarantined_peers(&self) -> anyhow::Result<Vec<QuarantinedPeer>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT peer_id, reason, reputation_score, quarantined_at, released_at, active
             FROM quarantined_peers
             WHERE active = 1
             ORDER BY quarantined_at DESC"
        )?;
        let rows = stmt.query_map([], |row| {
            let released_at: Option<String> = row.get(4)?;
            Ok(QuarantinedPeer {
                peer_id: row.get(0)?,
                reason: row.get(1)?,
                reputation_score: row.get(2)?,
                quarantined_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(3)?)
                    .map_err(|_| rusqlite::Error::InvalidQuery)?
                    .with_timezone(&Utc),
                released_at: released_at
                    .and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
                    .map(|dt| dt.with_timezone(&Utc)),
                active: row.get::<_, i32>(5)? == 1,
            })
        })?;

        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn log_threat(&self, sig: &ThreatSignature) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO threats (id, cve_id, hash_blake3, process_name, confidence, detected_at, source_node, file_path, reason)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                sig.id,
                sig.cve_id,
                sig.hash_blake3,
                sig.process_name,
                sig.confidence,
                sig.detected_at.to_rfc3339(),
                sig.source_node,
                sig.process_name, // Use process_name as a placeholder for file_path if not separate
                sig.reason
            ],
        )?;
        Ok(())
    }

    /// Store malware sample from mesh for distributed EMBER-style training.
    pub fn insert_malware_sample(&self, sample: &MalwareSample) -> anyhow::Result<()> {
        let features_json = serde_json::to_string(&sample.features).unwrap_or_default();
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO malware_samples (file_hash, source_node, label, features_json, feature_version, received_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                sample.file_hash,
                sample.source_node,
                sample.label as i64,
                features_json,
                sample.feature_version,
                Utc::now().to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    /// Count mesh samples for training.
    pub fn malware_sample_count(&self) -> anyhow::Result<u64> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM malware_samples",
            [],
            |r| r.get(0),
        )?;
        Ok(count.max(0) as u64)
    }

    /// Get malware samples for training (export to JSON/CSV for EMBER script).
    pub fn get_malware_samples(&self, limit: usize) -> anyhow::Result<Vec<MalwareSample>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT file_hash, source_node, label, features_json, feature_version, received_at
             FROM malware_samples ORDER BY received_at DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            let features_json: String = row.get(3)?;
            let features: Vec<f64> = serde_json::from_str(&features_json).unwrap_or_default();
            let received_at: String = row.get(5)?;
            Ok(MalwareSample {
                file_hash: row.get(0)?,
                source_node: row.get(1)?,
                label: row.get::<_, i64>(2)? as u8,
                features,
                feature_version: row.get(4).unwrap_or_else(|_| "legacy".to_string()),
                timestamp: DateTime::parse_from_rfc3339(&received_at)
                    .map_err(|_| rusqlite::Error::InvalidQuery)?
                    .with_timezone(&Utc),
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Get threats as ThreatSignature for model training (self + peer data).
    pub fn get_threats_for_training(&self, limit: usize) -> anyhow::Result<Vec<ThreatSignature>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, cve_id, hash_blake3, process_name, confidence, detected_at, source_node 
             FROM threats ORDER BY detected_at DESC LIMIT ?1"
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            Ok(ThreatSignature {
                id: row.get(0)?,
                cve_id: row.get(1)?,
                hash_blake3: row.get(2)?,
                process_name: row.get(3)?,
                confidence: row.get(4)?,
                detected_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(5)?)
                    .map_err(|_| rusqlite::Error::InvalidQuery)?
                    .with_timezone(&Utc),
                source_node: row.get(6)?,
                signature: None,
                public_key: None,
                merkle_proof: None,
                recommended_action: ResponseAction::Alert,
                reason: None,
                predicted_next: None,
                epsilon: None,
                detector_count: 1,
                require_approval: false,
                action_state: ActionState::Executed,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Get recent threats for dashboard (from memory + audit THREAT_DETECTED events).
    pub fn get_recent_threats(&self, limit: usize) -> anyhow::Result<Vec<serde_json::Value>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, cve_id, process_name, confidence, MAX(detected_at), source_node, file_path, reason 
             FROM threats 
             GROUP BY COALESCE(NULLIF(cve_id, ''), NULLIF(process_name, ''), file_path), source_node
             ORDER BY detected_at DESC 
             LIMIT ?1"
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            Ok(serde_json::json!({
                "id": row.get::<_, String>(0)?,
                "cve_id": row.get::<_, Option<String>>(1)?,
                "process_name": row.get::<_, Option<String>>(2)?,
                "confidence": row.get::<_, f64>(3)?,
                "timestamp": row.get::<_, String>(4)?,
                "source_node": row.get::<_, String>(5)?,
                "file_path": row.get::<_, Option<String>>(6)?,
                "reason": row.get::<_, Option<String>>(7)?,
            }))
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Mark a threat as false positive (federated learning: pattern shared).
    pub fn mark_threat_false_positive(&self, threat_id: &str, source_node: &str) -> anyhow::Result<bool> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT process_name, hash_blake3 FROM threats WHERE id = ?1"
        )?;
        let mut rows = stmt.query(params![threat_id])?;
        let Some(row) = rows.next()? else {
            return Ok(false);
        };
        let process_name: Option<String> = row.get(0)?;
        let hash_blake3: Option<String> = row.get(1)?;
        let proc = process_name.as_deref().unwrap_or("");
        let hash = hash_blake3.as_deref().unwrap_or("");
        conn.execute(
            "INSERT OR REPLACE INTO false_positive_patterns (process_name, hash_blake3, source_node, marked_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![proc, hash, source_node, Utc::now().to_rfc3339()],
        )?;
        Ok(true)
    }

    /// Mark a threat as a confirmed true positive (reinforcement).
    pub fn mark_threat_true_positive(&self, threat_id: &str, source_node: &str) -> anyhow::Result<bool> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT process_name, hash_blake3 FROM threats WHERE id = ?1"
        )?;
        let mut rows = stmt.query(params![threat_id])?;
        let Some(row) = rows.next()? else {
            return Ok(false);
        };
        let process_name: Option<String> = row.get(0)?;
        let hash_blake3: Option<String> = row.get(1)?;
        let proc = process_name.as_deref().unwrap_or("");
        let hash = hash_blake3.as_deref().unwrap_or("");
        
        conn.execute(
            "INSERT OR REPLACE INTO verified_threat_patterns (process_name, hash_blake3, source_node, marked_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![proc, hash, source_node, Utc::now().to_rfc3339()],
        )?;
        Ok(true)
    }

    /// Check if process/hash matches a known false positive pattern.
    pub fn is_false_positive_pattern(&self, process_name: Option<&str>, hash_blake3: Option<&str>) -> anyhow::Result<bool> {
        let conn = self.conn.lock().unwrap();
        let proc = process_name.unwrap_or("");
        let hash = hash_blake3.unwrap_or("");
        let mut stmt = conn.prepare(
            "SELECT 1 FROM false_positive_patterns WHERE (process_name != '' AND process_name = ?1) OR (hash_blake3 != '' AND hash_blake3 = ?2) LIMIT 1"
        )?;
        let mut rows = stmt.query(params![proc, hash])?;
        Ok(rows.next()?.is_some())
    }

    /// Check if process/hash matches a confirmed true positive pattern.
    pub fn is_true_positive_pattern(&self, process_name: Option<&str>, hash_blake3: Option<&str>) -> anyhow::Result<bool> {
        let conn = self.conn.lock().unwrap();
        let proc = process_name.unwrap_or("");
        let hash = hash_blake3.unwrap_or("");
        let mut stmt = conn.prepare(
            "SELECT 1 FROM verified_threat_patterns WHERE (process_name != '' AND process_name = ?1) OR (hash_blake3 != '' AND hash_blake3 = ?2) LIMIT 1"
        )?;
        let mut rows = stmt.query(params![proc, hash])?;
        Ok(rows.next()?.is_some())
    }

    /// Generic JSON query for the WASM brain.
    pub fn query_json(&self, query: &str, parameters: &[String]) -> anyhow::Result<Vec<serde_json::Value>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(query)?;
        let column_count = stmt.column_count();
        let column_names: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();

        let mut rows = stmt.query(rusqlite::params_from_iter(parameters))?;
        let mut results = Vec::new();

        while let Some(row) = rows.next()? {
            let mut map = serde_json::Map::new();
            for (i, name) in column_names.iter().enumerate().take(column_count) {
                let value: rusqlite::types::Value = row.get(i)?;
                let json_value = match value {
                    rusqlite::types::Value::Null => serde_json::Value::Null,
                    rusqlite::types::Value::Integer(i) => serde_json::Value::Number(i.into()),
                    rusqlite::types::Value::Real(f) => serde_json::Value::Number(serde_json::Number::from_f64(f).unwrap_or_else(|| serde_json::Number::from(0))),
                    rusqlite::types::Value::Text(s) => serde_json::Value::String(s),
                    rusqlite::types::Value::Blob(b) => serde_json::Value::String(hex::encode(b)),
                };
                map.insert(name.clone(), json_value);
            }
            results.push(serde_json::Value::Object(map));
        }
        Ok(results)
    }

    pub fn repopulate_bloom_filter(&self) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT hash_blake3 FROM threats WHERE hash_blake3 IS NOT NULL")?;
        let hashes = stmt.query_map([], |row| row.get::<_, String>(0))?;
        
        let mut bloom = self.bloom_filter.lock().unwrap();
        for hash in hashes {
            if let Ok(h) = hash {
                bloom.set(&h);
            }
        }
        Ok(())
    }

    /// Fast probabilistic check for malicious hash. Returns true if POSSIBLY malicious.
    pub fn is_hash_known_malicious_fast(&self, hash: &str) -> bool {
        let bloom = self.bloom_filter.lock().unwrap();
        bloom.check(&hash.to_string())
    }

    pub fn get_reputation_value(&self, node_id: &str) -> anyhow::Result<f32> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT score FROM reputation WHERE node_id = ?")?;
        let mut rows = stmt.query([node_id])?;
        if let Some(row) = rows.next()? {
            Ok(row.get(0)?)
        } else {
            Ok(0.5) // Default neutral reputation
        }
    }

    pub fn update_reputation(&self, node_id: &str, delta: f32) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO reputation (node_id, score, last_updated) 
             VALUES (?, ?, ?) 
             ON CONFLICT(node_id) DO UPDATE SET 
             score = MAX(0.0, MIN(1.0, score + ?)),
             last_updated = ?",
            params![node_id, 0.5 + delta, Utc::now().to_rfc3339(), delta, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    /// Upsert OTX indicators in batch.
    pub fn upsert_otx_indicators(&self, indicators: &[osoosi_types::OtxIndicator]) -> anyhow::Result<()> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        {
            let mut stmt = tx.prepare_cached(
                "INSERT INTO otx_indicators (indicator_type, value, source, first_seen, last_seen)
                 VALUES (?, ?, ?, ?, ?)
                 ON CONFLICT(indicator_type, value, source) DO UPDATE SET last_seen = ?5"
            )?;
            let now = Utc::now().to_rfc3339();
            for ind in indicators {
                stmt.execute(params![
                    ind.indicator_type,
                    ind.value,
                    ind.source,
                    now,
                    now,
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Check if a value (IP, Domain, Hash, etc.) exists in the OTX indicator database.
    pub fn is_indicator_malicious(&self, kind: &str, value: &str) -> anyhow::Result<bool> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare_cached("SELECT 1 FROM otx_indicators WHERE indicator_type = ? AND value = ? LIMIT 1")?;
        let exists = stmt.exists(params![kind, value])?;
        Ok(exists)
    }
}
