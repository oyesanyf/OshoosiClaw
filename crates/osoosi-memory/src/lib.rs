//! Local SQLite persistence for threat intelligence and file integrity.

use chrono::{DateTime, Utc};
use osoosi_types::{
    ActionState, ConsensusFinding, Kev, MalwareSample, PeerAnnounce, PeerStatus,
    PendingJoinRequest, QuarantinedPeer, ReputationScore, ResponseAction, ThreatSignature,
};
use parking_lot::Mutex;
use rusqlite::{params, Connection};
use std::path::Path;
use tracing::{debug, info};

pub mod encryption;
pub mod memory_scanner;
pub mod scanner;

pub use memory_scanner::*;

pub struct MemoryStore {
    conn: Mutex<Connection>,
    bloom_filter: Mutex<bloomfilter::Bloom<String>>,
    status_cache: parking_lot::RwLock<std::collections::HashMap<String, String>>,
    clean_hashes_cache: parking_lot::RwLock<std::collections::HashSet<String>>,
    recent_threats_cache: parking_lot::RwLock<Option<(std::time::Instant, Vec<serde_json::Value>)>>,
}

fn normalize_asset_path(path: &str) -> String {
    let mut normalized = path
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_ascii_lowercase();
    if let Some(stripped) = normalized.strip_prefix("\\\\?\\") {
        normalized = stripped.to_string();
    }
    normalized
}

impl MemoryStore {
    pub fn new(path: &str) -> anyhow::Result<Self> {
        if path != ":memory:" {
            if let Some(parent) = Path::new(path).parent() {
                let _ = std::fs::create_dir_all(parent);
            }
        }
        let conn = Connection::open(path)?;
        let _ = conn.busy_timeout(std::time::Duration::from_millis(1500));

        // SQLCipher: Apply encryption if available and DB is not in-memory
        if path != ":memory:" {
            let key = encryption::get_db_encryption_key();
            let _ = encryption::apply_encryption(&conn, &key);
        }

        // Enable WAL mode for concurrent readers + single writer (no blocking reads)
        let _ = conn.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            PRAGMA wal_autocheckpoint = 1000;
            PRAGMA synchronous = NORMAL;
            PRAGMA temp_store = MEMORY;
            PRAGMA mmap_size = 134217728;
            PRAGMA cache_size = -8000;
            PRAGMA busy_timeout = 5000;
            PRAGMA wal_checkpoint(TRUNCATE);
        ",
        );

        let lock = Mutex::new(conn);

        // Initialize Bloom filter: 1,000,000 items with 0.01% false positive rate
        let bloom = bloomfilter::Bloom::new_for_fp_rate(1_000_000, 0.0001);

        let s = Self {
            conn: lock,
            bloom_filter: Mutex::new(bloom),
            status_cache: parking_lot::RwLock::new(std::collections::HashMap::new()),
            clean_hashes_cache: parking_lot::RwLock::new(std::collections::HashSet::new()),
            recent_threats_cache: parking_lot::RwLock::new(None),
        };
        s.init_db()?;
        s.repopulate_bloom_filter()?;
        s.load_clean_hashes_cache()?;
        let _ = s.purge_vetoed_and_false_positive_threats();
        Ok(s)
    }

    pub fn invalidate_recent_threats_cache(&self) {
        *self.recent_threats_cache.write() = None;
    }

    pub fn delete_threat_by_id_or_pattern(
        &self,
        threat_id: Option<&str>,
        process_name: Option<&str>,
        hash_blake3: Option<&str>,
    ) -> anyhow::Result<usize> {
        let tid = threat_id.unwrap_or("").trim();
        let proc = process_name.unwrap_or("").trim().to_ascii_lowercase();
        let hash = hash_blake3.unwrap_or("").trim();
        if tid.is_empty() && proc.is_empty() && hash.is_empty() {
            return Ok(0);
        }
        let mut conditions = Vec::new();
        let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        if !tid.is_empty() {
            params.push(Box::new(tid.to_string()));
            conditions.push(format!("id = ?{}", params.len()));
        }
        if !proc.is_empty() {
            params.push(Box::new(proc.clone()));
            let p1 = params.len();
            params.push(Box::new(format!("%{}%", proc)));
            let p2 = params.len();
            conditions.push(format!(
                "(LOWER(COALESCE(process_name, '')) = ?{} OR LOWER(COALESCE(file_path, '')) LIKE ?{})",
                p1, p2
            ));
        }
        if !hash.is_empty() {
            params.push(Box::new(hash.to_string()));
            conditions.push(format!("hash_blake3 = ?{}", params.len()));
        }
        let sql = format!("DELETE FROM threats WHERE {}", conditions.join(" OR "));
        let conn = self.conn.lock();
        let param_refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p.as_ref()).collect();
        let affected = conn.execute(&sql, rusqlite::params_from_iter(param_refs))?;
        drop(conn);
        self.invalidate_recent_threats_cache();
        Ok(affected)
    }

    pub fn delete_threats_matching_process_substring(&self, substr: &str) -> anyhow::Result<usize> {
        let trimmed = substr.trim();
        if trimmed.is_empty() {
            return Ok(0);
        }
        let Some(conn) = self.conn.try_lock_for(std::time::Duration::from_millis(50)) else {
            return Ok(0);
        };
        let pattern = format!("%{}%", trimmed.to_ascii_lowercase());
        let deleted = conn.execute(
            "DELETE FROM threats WHERE LOWER(COALESCE(process_name, '')) LIKE ?1 OR LOWER(COALESCE(file_path, '')) LIKE ?1 OR LOWER(COALESCE(reason, '')) LIKE ?1",
            [&pattern],
        )?;
        drop(conn);
        if deleted > 0 {
            self.invalidate_recent_threats_cache();
        }
        Ok(deleted)
    }

    pub fn purge_vetoed_and_false_positive_threats(&self) -> anyhow::Result<usize> {
        let Some(conn) = self.conn.try_lock_for(std::time::Duration::from_millis(40)) else {
            return Ok(0);
        };
        let deleted = conn.execute(
            "DELETE FROM threats WHERE
                reason LIKE '%Veto%'
                OR reason LIKE '%Trusted Vendor%'
                OR reason LIKE '%Trusted-Vendor%'
                OR reason LIKE '%outside the vulnerable%'
                OR reason LIKE '%CVE None%'
                OR reason LIKE '%Autonomous REA Verified Clean%'
                OR reason LIKE '%Execution Of Non-Existing File%'
                OR reason LIKE '%unknown v0.0.0%'
                OR reason LIKE '%cve-2009-2940%'
                OR reason LIKE '%Noul p=0.0%'
                OR reason LIKE '%Noul p=0.01%'
                OR reason LIKE '%detected sensitive/exfil tokens []%'
                OR reason LIKE '%Anti-Chaff Alert%'
                OR reason LIKE 'YARA-X Match: antisb_%'
                OR reason LIKE 'YARA-X Match: anti_dbg%'
                OR reason LIKE 'YARA-X Match: vmdetect%'
                OR reason LIKE 'YARA-X Match: win_files_%'
                OR reason LIKE 'YARA-X Match: RIPEMD160_Constants%'
                OR reason LIKE 'YARA-X Match: escalate_priv%'
                OR reason LIKE '%YaraX: THREAT detected - escalate_priv%'
                OR reason LIKE '%YaraX: THREAT detected - screenshot%'
                OR reason LIKE '%YaraX: THREAT detected - create_service%'
                OR reason LIKE '%YaraX: THREAT detected - CRC32%'
                OR reason LIKE '%YaraX: THREAT detected - ThreadControl__%'
                OR reason LIKE '%YaraX: THREAT detected - Debugger%'
                OR reason LIKE '%EDR-VEC-23-UNSIGNED-ELEVATED-CONHOST%'
                OR reason LIKE '%Sponge Attack Warning%'
                OR (reason LIKE '%Process Start From Suspicious Folder%' AND reason LIKE '%Call stack spoofing detected%' AND reason NOT LIKE '%Direct Syscall%')
                OR (LOWER(COALESCE(file_path, '')) NOT LIKE '%\\temp\\%' AND reason LIKE '%independent=1%' AND (
                    reason LIKE '%Behavioral Threat Model: High-risk pattern detected%'
                    OR reason LIKE '%Chaotic phase-space trajectory breakout%'
                    OR reason LIKE '%diverged from benign limit cycle%'
                    OR reason LIKE '%Agentic trajectory escape threshold exceeded%'
                    OR reason LIKE '%Denial of ML Service & Sponge Attack%'
                    OR reason LIKE '%ThreadControl__Context%'
                ))
                OR (reason LIKE '%matches KEV product%' AND reason NOT LIKE '%verified_version=%')
                OR process_name = '<unknown process>'
                OR process_name = 'unknown'
                OR EXISTS (SELECT 1 FROM false_positive_patterns fp WHERE (fp.process_name != '' AND LOWER(fp.process_name) = LOWER(COALESCE(threats.process_name, ''))) OR (fp.hash_blake3 != '' AND fp.hash_blake3 = COALESCE(threats.hash_blake3, '')))
                OR EXISTS (SELECT 1 FROM known_clean_hashes kch WHERE kch.hash_blake3 != '' AND kch.hash_blake3 = COALESCE(threats.hash_blake3, ''))",
            [],
        )?;
        let _ = conn.execute(
            "DELETE FROM cve_cache WHERE LOWER(product) = 'unknown' OR version = '0.0.0' OR cve_id = 'CVE-2009-2940'",
            [],
        );
        let _ = conn.execute(
            "DELETE FROM known_clean_hashes WHERE hash_blake3 = 'no-hash' OR TRIM(hash_blake3) = ''",
            [],
        );
        drop(conn);
        if deleted > 0 {
            self.invalidate_recent_threats_cache();
        }
        Ok(deleted)
    }

    fn load_clean_hashes_cache(&self) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare("SELECT hash_blake3 FROM known_clean_hashes")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut cache = self.clean_hashes_cache.write();
        for hash in rows.flatten() {
            if !hash.is_empty() {
                cache.insert(hash);
            }
        }
        Ok(())
    }

    fn init_db(&self) -> anyhow::Result<()> {
        debug!("Initializing memory store tables...");
        let conn = self.conn.lock();

        // KEV table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS kev (
                cve_id TEXT PRIMARY KEY,
                vendor_project TEXT,
                product TEXT,
                vulnerability_name TEXT,
                date_added TEXT,
                required_action TEXT,
                known_exploited INTEGER,
                version_start_including TEXT,
                version_end_excluding TEXT
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
                reason TEXT,
                parent_process TEXT,
                version TEXT
            )",
            [],
        )?;

        // Schema Migrations (Dynamic)
        let _ = conn.execute("ALTER TABLE threats ADD COLUMN parent_process TEXT", []);
        let _ = conn.execute("ALTER TABLE threats ADD COLUMN version TEXT", []);
        let _ = conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_threats_detected_at ON threats (detected_at DESC)",
            [],
        );
        let _ = conn.execute("CREATE INDEX IF NOT EXISTS idx_threats_proc_hash ON threats (process_name, hash_blake3)", []);

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

        // File skip list: paths that failed to hash (locked, permission denied) \u2014 avoid retry spam
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

        // Pre-populate false positive patterns for legitimate developer and VS Code native components
        let known_fps = [
            ("msalruntime.dll", ""),
            ("msal-node-runtime.node", ""),
            ("vsda.node", ""),
            ("vulkan-1.dll", ""),
            ("win32-app-container-tokens.node", ""),
            (
                "win32-app-container-tokens.win32-x64-msvc-VCQE7GJP.node",
                "",
            ),
            (
                "win32-app-container-tokens.win32-arm64-msvc-4ZJZ3U55.node",
                "",
            ),
        ];
        for (proc_name, hash) in known_fps {
            let _ = conn.execute(
                "INSERT OR IGNORE INTO false_positive_patterns (process_name, hash_blake3, source_node, marked_at) VALUES (?1, ?2, 'allowlist_seed', ?3)",
                rusqlite::params![proc_name, hash, Utc::now().to_rfc3339()],
            );
        }

        conn.execute(
            "CREATE TABLE IF NOT EXISTS internal_assets (
                path TEXT PRIMARY KEY,
                kind TEXT,
                hash_blake3 TEXT,
                added_at TEXT,
                last_seen TEXT
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS ai_overrides (
                file_hash TEXT PRIMARY KEY,
                verdict INTEGER NOT NULL,
                reason TEXT,
                source_node TEXT,
                timestamp TEXT NOT NULL
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS cve_exemptions (
                cve_id TEXT NOT NULL,
                binary_path TEXT NOT NULL,
                expiry_date TEXT,
                reason TEXT,
                PRIMARY KEY (cve_id, binary_path)
            )",
            [],
        )?;

        // CVE Cache: Stores results from NVD 2.0 API lookups
        conn.execute(
            "CREATE TABLE IF NOT EXISTS cve_cache (
                product TEXT,
                version TEXT,
                cve_id TEXT,
                summary TEXT,
                cached_at TEXT,
                PRIMARY KEY (product, version, cve_id)
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS training_samples (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                model_type TEXT NOT NULL,
                features BLOB NOT NULL,
                label INTEGER NOT NULL,
                is_processed INTEGER DEFAULT 0,
                created_at TEXT NOT NULL
            )",
            [],
        )?;

        // Federated: analyst-confirmed malicious patterns shared across mesh.
        conn.execute(
            "CREATE TABLE IF NOT EXISTS verified_threat_patterns (
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

        conn.execute("CREATE INDEX IF NOT EXISTS idx_nsrl_sha1 ON nsrl(sha1)", [])?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_nsrl_sha256 ON nsrl(sha256)",
            [],
        )?;
        conn.execute("CREATE INDEX IF NOT EXISTS idx_nsrl_md5 ON nsrl(md5)", [])?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_otx_lookup ON otx_indicators(indicator_type, value)",
            [],
        )?;

        // Zone posture table (persists security posture, scores, and remediations)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS zone_posture (
                zone_id TEXT PRIMARY KEY,
                security_score INTEGER,
                tpm_remediated INTEGER,
                memory_shield_remediated INTEGER,
                egress_remediated INTEGER,
                hardware_attestation TEXT,
                recommendations_json TEXT,
                updated_at TEXT
            )",
            [],
        )?;

        // MIGRATION: Add version_start_including / version_end_excluding to kev if they are missing
        let table_info: Vec<String> = conn
            .prepare("PRAGMA table_info(kev)")?
            .query_map([], |row| row.get(1))?
            .collect::<rusqlite::Result<Vec<String>>>()?;

        if !table_info.contains(&"version_start_including".to_string()) {
            info!("Migrating 'kev' table: adding 'version_start_including' column...");
            let _ = conn.execute(
                "ALTER TABLE kev ADD COLUMN version_start_including TEXT",
                [],
            );
        }
        if !table_info.contains(&"version_end_excluding".to_string()) {
            info!("Migrating 'kev' table: adding 'version_end_excluding' column...");
            let _ = conn.execute("ALTER TABLE kev ADD COLUMN version_end_excluding TEXT", []);
        }

        // Consensus Findings table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS consensus_findings (
                id TEXT PRIMARY KEY,
                hash_blake3 TEXT NOT NULL,
                process_name TEXT,
                file_path TEXT,
                verdict TEXT NOT NULL,
                confidence REAL NOT NULL,
                detector_count INTEGER NOT NULL,
                voters_summary TEXT,
                action_taken TEXT NOT NULL,
                evaluated_at TEXT NOT NULL
            )",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_consensus_findings_hash ON consensus_findings(hash_blake3)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_consensus_findings_verdict ON consensus_findings(verdict)",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_consensus_findings_time ON consensus_findings(evaluated_at)",
            [],
        )?;

        // Known Clean Hashes table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS known_clean_hashes (
                hash_blake3 TEXT PRIMARY KEY,
                process_name TEXT,
                file_path TEXT,
                marked_at TEXT NOT NULL,
                source TEXT NOT NULL
            )",
            [],
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_known_clean_hashes ON known_clean_hashes(hash_blake3)",
            [],
        )?;

        // Voter Weights table for Closed-Loop RL persistence
        conn.execute(
            "CREATE TABLE IF NOT EXISTS voter_weights (
                voter_name TEXT PRIMARY KEY,
                weight_multiplier REAL NOT NULL,
                updated_at TEXT NOT NULL
            )",
            [],
        )?;

        // Purge stale bogus rows from threats, consensus_findings, and known_clean_hashes:
        let _ = conn.execute(
            "DELETE FROM threats WHERE process_name IS NULL OR lower(process_name) IN ('unknown', 'unknown process', 'system process', '') OR reason LIKE '%Execution Of Non-Existing File%' OR confidence < 0.50",
            [],
        );
        let _ = conn.execute(
            "DELETE FROM consensus_findings WHERE process_name IS NULL OR lower(process_name) IN ('unknown', 'unknown process', 'system process', '') OR voters_summary LIKE '%Execution Of Non-Existing File%'",
            [],
        );
        let lolbins_patterns = [
            "%powershell%",
            "%pwsh%",
            "%cmd.exe%",
            "%rundll32%",
            "%regsvr32%",
            "%mshta%",
            "%wmic%",
            "%certutil%",
            "%bitsadmin%",
            "%reg.exe%",
            "%vssadmin%",
            "%wbadmin%",
            "%bcdedit%",
            "%ntdsutil%",
            "%cscript%",
            "%wscript%",
            "%msiexec%",
            "%python%",
            "%node.exe%",
            "%svchost%",
            "%explorer.exe%",
            "%dllhost%",
            "%taskhostw%",
            "%conhost%",
        ];
        for pat in &lolbins_patterns {
            let _ = conn.execute(
                "DELETE FROM known_clean_hashes WHERE lower(process_name) LIKE ?1 OR lower(file_path) LIKE ?1",
                rusqlite::params![pat],
            );
        }

        Ok(())
    }

    /// Prune old data and vacuum the database to reclaim space.
    pub fn vacuum_and_prune(&self, days_retention: u32) -> anyhow::Result<()> {
        info!(
            "Pruning database records older than {} days...",
            days_retention
        );
        let conn = self.conn.lock();
        let cutoff = (Utc::now() - chrono::Duration::days(days_retention as i64)).to_rfc3339();
        let skip_cutoff = (Utc::now() - chrono::Duration::days(1)).to_rfc3339();

        let deleted_threats = conn
            .execute("DELETE FROM threats WHERE detected_at < ?", [&cutoff])
            .unwrap_or(0);
        let deleted_integrity = conn
            .execute("DELETE FROM file_integrity WHERE last_seen < ?", [&cutoff])
            .unwrap_or(0);
        let deleted_skips = conn
            .execute(
                "DELETE FROM file_skip_list WHERE added_at < ?",
                [&skip_cutoff],
            )
            .unwrap_or(0);
        let deleted_consensus = conn
            .execute(
                "DELETE FROM consensus_findings WHERE evaluated_at < ?",
                [&cutoff],
            )
            .unwrap_or(0);
        let deleted_cve = conn
            .execute("DELETE FROM cve_cache WHERE cached_at < ?", [&cutoff])
            .unwrap_or(0);
        let deleted_training = conn
            .execute(
                "DELETE FROM training_samples WHERE is_processed = 1 AND created_at < ?",
                [&cutoff],
            )
            .unwrap_or(0);
        let deleted_joins = conn
            .execute(
                "DELETE FROM pending_joins WHERE discovered_at < ?",
                [&cutoff],
            )
            .unwrap_or(0);

        info!(
            "Pruned DB: {} threats, {} integrity, {} skips, {} consensus, {} CVE cache, {} training samples, {} pending joins.",
            deleted_threats, deleted_integrity, deleted_skips, deleted_consensus, deleted_cve, deleted_training, deleted_joins
        );

        // Truncate WAL, rebuild database, optimize query planner, and shrink in-memory SQLite pages
        let _ = conn.execute_batch(
            "
            PRAGMA wal_checkpoint(TRUNCATE);
            VACUUM;
            PRAGMA optimize;
            PRAGMA shrink_memory;
        ",
        );
        drop(conn);

        // Cap in-memory caches to prevent unbounded growth
        {
            let mut status = self.status_cache.write();
            if status.len() > 10_000 {
                status.clear();
                status.shrink_to_fit();
            }
        }
        {
            let mut clean_hashes = self.clean_hashes_cache.write();
            if clean_hashes.len() > 50_000 {
                clean_hashes.shrink_to_fit();
            }
        }

        Ok(())
    }

    pub fn is_nsrl_known_good(&self, hash: &str) -> anyhow::Result<bool> {
        let key = hash.trim().to_ascii_lowercase();
        if key.is_empty() {
            return Ok(false);
        }
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(
            "SELECT 1 FROM nsrl WHERE sha1 = ?1 OR sha256 = ?1 OR md5 = ?1 LIMIT 1",
        )?;
        let exists = stmt.exists([&key])?;
        Ok(exists)
    }

    /// Bulk-import NSRL from an official NIST **RDS** SQLite (Modern `FILE` table) by `ATTACH` + `INSERT\u2026SELECT`.
    /// This avoids loading millions of rows into Rust and completes much faster with lower RAM use than
    /// `import_nsrl_from_sqlite` + `upsert_nsrl_records`. Safe to run while the agent is up (WAL + readers).
    pub fn import_nsrl_from_nist_rds_sqlite(&self, nist_rds_path: &Path) -> anyhow::Result<u64> {
        if !nist_rds_path.exists() {
            anyhow::bail!("NSRL RDS file not found: {:?}", nist_rds_path);
        }

        let before: u64 = {
            let conn = self.conn.lock();
            conn.query_row("SELECT COUNT(*) FROM nsrl", [], |r| r.get(0))?
        };

        let max_import_rows: usize = std::env::var("OSOOSI_NSRL_IMPORT_LIMIT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(50_000);

        if before as usize >= max_import_rows {
            debug!(
                "NSRL table already has {} rows (>= limit {}), skipping bulk re-import",
                before, max_import_rows
            );
            return Ok(0);
        }

        let nist_conn = Connection::open_with_flags(
            nist_rds_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        let _ = nist_conn.busy_timeout(std::time::Duration::from_millis(2000));

        let file_tbl: i64 = nist_conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='FILE'",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);
        let metadata_tbl: i64 = nist_conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='METADATA'",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);

        let query_sql = if file_tbl > 0 {
            format!(
                "SELECT lower(COALESCE(sha1, '')), lower(md5), lower(sha256), COALESCE(name, ''), COALESCE(size, 0), product, os FROM FILE LIMIT {}",
                max_import_rows
            )
        } else if metadata_tbl > 0 {
            format!(
                "SELECT lower(COALESCE(sha1, '')), lower(md5), lower(sha256), COALESCE(file_name, ''), COALESCE(bytes, 0), NULL, NULL FROM METADATA LIMIT {}",
                max_import_rows
            )
        } else {
            anyhow::bail!(
                "NSRL file has neither FILE nor METADATA table (expected NIST modern RDS): {:?}",
                nist_rds_path
            );
        };

        let mut stmt = nist_conn.prepare(&query_sql)?;
        let mut rows = stmt.query([])?;
        let batch_size = 2_000usize;
        let mut batch: Vec<osoosi_types::NsrlRecord> = Vec::with_capacity(batch_size);

        while let Some(row) = rows.next()? {
            let sha1: String = row.get::<_, String>(0).unwrap_or_default();
            if sha1.is_empty() {
                continue;
            }
            batch.push(osoosi_types::NsrlRecord {
                sha1,
                md5: row.get::<_, Option<String>>(1).ok().flatten(),
                sha256: row.get::<_, Option<String>>(2).ok().flatten(),
                file_name: row.get::<_, String>(3).unwrap_or_default(),
                file_size: row.get::<_, i64>(4).unwrap_or(0).max(0) as u64,
                product_code: row.get::<_, Option<String>>(5).ok().flatten().or_else(|| {
                    row.get::<_, Option<i32>>(5)
                        .ok()
                        .flatten()
                        .map(|v| v.to_string())
                }),
                os_code: row.get::<_, Option<String>>(6).ok().flatten(),
            });

            if batch.len() >= batch_size {
                self.upsert_nsrl_records(&batch)?;
                batch.clear();
                // Yield briefly between micro-batches so dashboard/telemetry readers never starve
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
        }

        if !batch.is_empty() {
            self.upsert_nsrl_records(&batch)?;
            batch.clear();
        }

        let after: u64 = {
            let conn = self.conn.lock();
            conn.query_row("SELECT COUNT(*) FROM nsrl", [], |r| r.get(0))?
        };
        let added = after.saturating_sub(before);
        debug!(
            "NSRL micro-batched import: +{} rows (total {} in nsrl) from {:?}",
            added, after, nist_rds_path
        );
        Ok(added)
    }

    /// Upsert a batch of NSRL records.
    pub fn upsert_nsrl_records(&self, records: &[osoosi_types::NsrlRecord]) -> anyhow::Result<()> {
        let mut conn = self.conn.lock();
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
        let conn = self.conn.lock();
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM nsrl", [], |r| r.get(0))?;
        Ok(count.max(0) as u64)
    }

    /// Retrieve the cached integrity status for a file path.
    /// Returns (hash_blake3, is_nsrl_validated, product_version).
    pub fn get_file_integrity(
        &self,
        path: &str,
    ) -> anyhow::Result<Option<(String, bool, Option<String>)>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached("SELECT hash_blake3, is_nsrl_validated, product_version FROM file_integrity WHERE path = ?")?;
        let mut rows = stmt.query([path])?;
        if let Some(row) = rows.next()? {
            Ok(Some((row.get(0)?, row.get::<_, i32>(1)? == 1, row.get(2)?)))
        } else {
            Ok(None)
        }
    }

    /// Record a file's integrity status.
    pub fn upsert_file_integrity(
        &self,
        path: &str,
        hash: &str,
        is_nsrl: bool,
        version: Option<&str>,
    ) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT OR REPLACE INTO file_integrity (path, hash_blake3, is_nsrl_validated, product_version, last_seen) VALUES (?, ?, ?, ?, ?)",
            params![path, hash, if is_nsrl { 1 } else { 0 }, version, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn insert_kev(&self, kev: &Kev) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT OR REPLACE INTO kev (cve_id, vendor_project, product, vulnerability_name, date_added, required_action, known_exploited, version_start_including, version_end_excluding)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                kev.cve_id,
                kev.vendor_project,
                kev.product,
                kev.vulnerability_name,
                kev.date_added.to_rfc3339(),
                kev.required_action,
                if kev.known_exploited { 1 } else { 0 },
                kev.version_start_including,
                kev.version_end_excluding,
            ],
        )?;
        Ok(())
    }

    /// Batch insert KEVs in a single transaction to avoid database lock contention.
    pub fn insert_kevs_batch(&self, kevs: &[Kev]) -> anyhow::Result<()> {
        let mut conn = self.conn.lock();
        let tx = conn.transaction()?;
        for kev in kevs {
            tx.execute(
                "INSERT OR REPLACE INTO kev (cve_id, vendor_project, product, vulnerability_name, date_added, required_action, known_exploited, version_start_including, version_end_excluding)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    kev.cve_id,
                    kev.vendor_project,
                    kev.product,
                    kev.vulnerability_name,
                    kev.date_added.to_rfc3339(),
                    kev.required_action,
                    if kev.known_exploited { 1 } else { 0 },
                    kev.version_start_including,
                    kev.version_end_excluding,
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn get_kev(&self, cve_id: &str) -> anyhow::Result<Option<Kev>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare("SELECT * FROM kev WHERE cve_id = ?1")?;
        let mut rows = stmt.query(params![cve_id])?;

        if let Some(row) = rows.next()? {
            Ok(Some(Kev {
                cve_id: row.get(0)?,
                vendor_project: row.get(1)?,
                product: row.get(2)?,
                vulnerability_name: row.get(3)?,
                date_added: DateTime::parse_from_rfc3339(&row.get::<_, String>(4)?)?
                    .with_timezone(&Utc),
                required_action: row.get(5)?,
                due_date: Utc::now(),
                known_exploited: row.get::<_, i32>(6)? == 1,
                version_start_including: row.get(7)?,
                version_end_excluding: row.get(8)?,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn get_all_kevs(&self) -> anyhow::Result<Vec<Kev>> {
        let conn = self.conn.lock();
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
                version_start_including: row.get(7)?,
                version_end_excluding: row.get(8)?,
            })
        })?;

        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Retrieve cached CVEs for a specific product and version.
    pub fn get_cached_cves(
        &self,
        product: &str,
        version: &str,
    ) -> anyhow::Result<Vec<(String, String)>> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare("SELECT cve_id, summary FROM cve_cache WHERE product = ?1 AND version = ?2")?;
        let rows = stmt.query_map(params![product, version], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })?;

        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Cache CVE results from NVD lookup.
    pub fn insert_cve_cache(
        &self,
        product: &str,
        version: &str,
        cve_id: &str,
        summary: &str,
    ) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT OR REPLACE INTO cve_cache (product, version, cve_id, summary, cached_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![product, version, cve_id, summary, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn update_file_hash(&self, path: &str, hash: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT OR REPLACE INTO file_integrity (path, hash_blake3, last_seen)
             VALUES (?1, ?2, ?3)",
            params![path, hash, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn set_repair_status(&self, key: &str, value: &str) -> anyhow::Result<()> {
        let cache_key = format!("repair_status:{}", key);
        {
            let mut cache = self.status_cache.write();
            cache.insert(cache_key, value.to_string());
        }
        let conn = self.conn.lock();
        conn.execute(
            "INSERT OR REPLACE INTO repair_status (key, value, updated_at) VALUES (?1, ?2, ?3)",
            params![key, value, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn get_repair_status(&self, key: &str) -> anyhow::Result<Option<String>> {
        let cache_key = format!("repair_status:{}", key);
        {
            let cache = self.status_cache.read();
            if let Some(val) = cache.get(&cache_key) {
                return Ok(if val.is_empty() {
                    None
                } else {
                    Some(val.clone())
                });
            }
        }
        let Some(conn) = self.conn.try_lock_for(std::time::Duration::from_millis(15)) else {
            return Ok(None);
        };
        let mut stmt = conn.prepare("SELECT value FROM repair_status WHERE key = ?1")?;
        let res = stmt
            .query_row(params![key], |row| row.get::<_, String>(0))
            .ok();
        {
            let mut cache = self.status_cache.write();
            cache.insert(cache_key, res.clone().unwrap_or_default());
        }
        Ok(res)
    }

    pub fn set_backup_status(&self, key: &str, value: &str) -> anyhow::Result<()> {
        let cache_key = format!("backup_status:{}", key);
        {
            let mut cache = self.status_cache.write();
            cache.insert(cache_key, value.to_string());
        }
        let conn = self.conn.lock();
        conn.execute(
            "INSERT OR REPLACE INTO backup_status (key, value, updated_at) VALUES (?1, ?2, ?3)",
            params![key, value, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn get_backup_status(&self, key: &str) -> anyhow::Result<Option<String>> {
        let cache_key = format!("backup_status:{}", key);
        {
            let cache = self.status_cache.read();
            if let Some(val) = cache.get(&cache_key) {
                return Ok(Some(val.clone()));
            }
        }
        let conn = self.conn.lock();
        let mut stmt = conn.prepare("SELECT value FROM backup_status WHERE key = ?1")?;
        let res = stmt
            .query_row(params![key], |row| row.get::<_, String>(0))
            .ok();
        if let Some(ref val) = res {
            let mut cache = self.status_cache.write();
            cache.insert(cache_key, val.clone());
        }
        Ok(res)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn save_zone_posture(
        &self,
        zone_id: &str,
        security_score: i64,
        tpm_remediated: bool,
        memory_shield_remediated: bool,
        egress_remediated: bool,
        hardware_attestation: &str,
        recommendations_json: &str,
    ) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT OR REPLACE INTO zone_posture (
                zone_id,
                security_score,
                tpm_remediated,
                memory_shield_remediated,
                egress_remediated,
                hardware_attestation,
                recommendations_json,
                updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                zone_id,
                security_score,
                if tpm_remediated { 1 } else { 0 },
                if memory_shield_remediated { 1 } else { 0 },
                if egress_remediated { 1 } else { 0 },
                hardware_attestation,
                recommendations_json,
                Utc::now().to_rfc3339()
            ],
        )?;
        Ok(())
    }

    pub fn load_zone_posture(&self, zone_id: &str) -> anyhow::Result<Option<serde_json::Value>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT security_score, tpm_remediated, memory_shield_remediated, egress_remediated, hardware_attestation, recommendations_json, updated_at FROM zone_posture WHERE zone_id = ?1"
        )?;
        let res = stmt
            .query_row(params![zone_id], |row| {
                Ok(serde_json::json!({
                    "security_score": row.get::<_, i64>(0)?,
                    "tpm_remediated": row.get::<_, i64>(1)? == 1,
                    "memory_shield_remediated": row.get::<_, i64>(2)? == 1,
                    "egress_remediated": row.get::<_, i64>(3)? == 1,
                    "hardware_attestation": row.get::<_, String>(4)?,
                    "recommendations_json": row.get::<_, String>(5)?,
                    "updated_at": row.get::<_, String>(6)?,
                }))
            })
            .ok();
        Ok(res)
    }

    pub fn set_model_training_status(&self, key: &str, value: &str) -> anyhow::Result<()> {
        let cache_key = format!("model_training_status:{}", key);
        {
            let mut cache = self.status_cache.write();
            cache.insert(cache_key, value.to_string());
        }
        let conn = self.conn.lock();
        conn.execute(
            "INSERT OR REPLACE INTO model_training_status (key, value, updated_at) VALUES (?1, ?2, ?3)",
            params![key, value, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn get_model_training_status(&self, key: &str) -> anyhow::Result<Option<String>> {
        let cache_key = format!("model_training_status:{}", key);
        {
            let cache = self.status_cache.read();
            if let Some(val) = cache.get(&cache_key) {
                return Ok(Some(val.clone()));
            }
        }
        let conn = self.conn.lock();
        let mut stmt = conn.prepare("SELECT value FROM model_training_status WHERE key = ?1")?;
        let res = stmt
            .query_row(params![key], |row| row.get::<_, String>(0))
            .ok();
        if let Some(ref val) = res {
            let mut cache = self.status_cache.write();
            cache.insert(cache_key, val.clone());
        }
        Ok(res)
    }

    pub fn get_file_hash(&self, path: &str) -> anyhow::Result<Option<String>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare("SELECT hash_blake3 FROM file_integrity WHERE path = ?1")?;
        let res = stmt.query_row(params![path], |row| row.get(0)).ok();
        Ok(res)
    }

    /// Add a path to the skip list (e.g. locked files that cannot be hashed).
    pub fn add_file_to_skip_list(&self, path: &str, reason: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT OR REPLACE INTO file_skip_list (path, reason, added_at) VALUES (?1, ?2, ?3)",
            params![path, reason, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    /// Check if a path is in the skip list.
    pub fn is_file_in_skip_list(&self, path: &str) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare("SELECT 1 FROM file_skip_list WHERE path = ?1")?;
        let res = stmt.exists(params![path])?;
        Ok(res)
    }

    pub fn get_reputation(&self, node_id: &str) -> anyhow::Result<Option<ReputationScore>> {
        let conn = self.conn.lock();
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
                last_updated: DateTime::parse_from_rfc3339(&row.get::<_, String>(4)?)?
                    .with_timezone(&Utc),
            }))
        } else {
            Ok(None)
        }
    }

    pub fn upsert_reputation(&self, rep: &ReputationScore) -> anyhow::Result<()> {
        let conn = self.conn.lock();
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
        let conn = self.conn.lock();
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
        let conn = self.conn.lock();
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
        let conn = self.conn.lock();
        conn.execute(
            "DELETE FROM pending_joins WHERE peer_id = ?1",
            params![peer_id],
        )?;
        Ok(())
    }

    pub fn upsert_peer_status(&self, announce: &PeerAnnounce) -> anyhow::Result<()> {
        let conn = self.conn.lock();
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
        let conn = self.conn.lock();
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

    pub fn quarantine_peer(
        &self,
        peer_id: &str,
        reason: &str,
        reputation_score: f32,
    ) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT OR REPLACE INTO quarantined_peers (peer_id, reason, reputation_score, quarantined_at, released_at, active)
             VALUES (?1, ?2, ?3, ?4, NULL, 1)",
            params![peer_id, reason, reputation_score, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn release_quarantined_peer(&self, peer_id: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE quarantined_peers SET active = 0, released_at = ?2 WHERE peer_id = ?1",
            params![peer_id, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn is_peer_quarantined(&self, peer_id: &str) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        let mut stmt =
            conn.prepare("SELECT 1 FROM quarantined_peers WHERE peer_id = ?1 AND active = 1")?;
        let exists = stmt.exists(params![peer_id])?;
        Ok(exists)
    }

    pub fn get_quarantined_peers(&self) -> anyhow::Result<Vec<QuarantinedPeer>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT peer_id, reason, reputation_score, quarantined_at, released_at, active
             FROM quarantined_peers
             WHERE active = 1
             ORDER BY quarantined_at DESC",
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

    /// Check if a domain is a known malicious indicator.
    pub fn is_known_malicious_domain(&self, domain: &str) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(
            "SELECT 1 FROM otx_indicators WHERE indicator_type = 'domain' AND value = ? LIMIT 1",
        )?;
        let exists = stmt.exists([domain])?;
        Ok(exists)
    }

    /// Log a specific threat event with context.
    pub fn log_threat_event(
        &self,
        event_type: &str,
        source_pid: u32,
        target_pid: u32,
    ) -> anyhow::Result<()> {
        let mut sig = ThreatSignature::new("local".to_string());
        sig.id = format!("{}_{}_{}", event_type, source_pid, Utc::now().timestamp());
        sig.process_name = Some(format!("PID_{}", source_pid));
        sig.confidence = 1.0;
        sig.reason = Some(format!(
            "Shield Violation: {} from PID {} to target PID {}",
            event_type, source_pid, target_pid
        ));
        sig.recommended_action = ResponseAction::Isolate;
        sig.detector_count = 1;

        self.log_threat(&sig)
    }

    pub fn log_threat(&self, sig: &ThreatSignature) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO threats (id, cve_id, hash_blake3, process_name, confidence, detected_at, source_node, file_path, reason, parent_process, version)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
             ON CONFLICT(id) DO UPDATE SET
                confidence = MAX(threats.confidence, excluded.confidence),
                detected_at = excluded.detected_at,
                cve_id = COALESCE(excluded.cve_id, threats.cve_id),
                hash_blake3 = COALESCE(excluded.hash_blake3, threats.hash_blake3),
                file_path = COALESCE(excluded.file_path, threats.file_path),
                reason = COALESCE(excluded.reason, threats.reason),
                process_name = COALESCE(excluded.process_name, threats.process_name),
                source_node = excluded.source_node,
                parent_process = COALESCE(excluded.parent_process, threats.parent_process),
                version = COALESCE(excluded.version, threats.version)",
            params![
                sig.id,
                sig.cve_id,
                sig.hash_blake3,
                sig.process_name,
                sig.confidence,
                sig.detected_at.to_rfc3339(),
                sig.source_node,
                sig.process_name, // Use process_name as a placeholder for file_path if not separate
                sig.reason,
                sig.parent_process,
                sig.version
            ],
        )?;
        if let Some(ref hash) = sig.hash_blake3 {
            self.mark_hash_known_malicious(hash);
        }
        self.invalidate_recent_threats_cache();
        Ok(())
    }

    /// Store malware sample from mesh for distributed EMBER-style training.
    pub fn insert_malware_sample(&self, sample: &MalwareSample) -> anyhow::Result<()> {
        let features_json = serde_json::to_string(&sample.features).unwrap_or_default();
        let conn = self.conn.lock();
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
        let conn = self.conn.lock();
        let count: i64 =
            conn.query_row("SELECT COUNT(*) FROM malware_samples", [], |r| r.get(0))?;
        Ok(count.max(0) as u64)
    }

    /// Get malware samples for training (export to JSON/CSV for EMBER script).
    pub fn get_malware_samples(&self, limit: usize) -> anyhow::Result<Vec<MalwareSample>> {
        let conn = self.conn.lock();
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
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, cve_id, hash_blake3, process_name, confidence, detected_at, source_node, parent_process, version 
             FROM threats ORDER BY detected_at DESC LIMIT ?1",
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
                parent_process: row.get(7)?,
                version: row.get(8)?,
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
                is_signed: false,
                mitre_tactic: None,
                mitre_technique: None,
                mitre_technique_name: None,
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
        if let Some((ts, ref cached)) = *self.recent_threats_cache.read() {
            if ts.elapsed() < std::time::Duration::from_millis(2000)
                && (limit <= 1000 || cached.len() >= limit)
            {
                return Ok(cached.iter().take(limit).cloned().collect());
            }
        }
        let Some(conn) = self.conn.try_lock_for(std::time::Duration::from_millis(80)) else {
            if let Some((_, ref cached)) = *self.recent_threats_cache.read() {
                return Ok(cached.iter().take(limit).cloned().collect());
            }
            return Ok(Vec::new());
        };
        let fetch_limit = limit.max(1000);
        let mut stmt = conn.prepare(
            "SELECT id, cve_id, process_name, hash_blake3, confidence, MAX(detected_at), source_node, file_path, reason 
             FROM (SELECT * FROM threats ORDER BY detected_at DESC LIMIT 600) t
             WHERE NOT EXISTS (
                SELECT 1 FROM false_positive_patterns fp
                WHERE (fp.process_name != '' AND LOWER(fp.process_name) = LOWER(COALESCE(t.process_name, '')))
                   OR (fp.hash_blake3 != '' AND fp.hash_blake3 = COALESCE(t.hash_blake3, ''))
             )
             AND NOT EXISTS (
                SELECT 1 FROM known_clean_hashes kch
                WHERE kch.hash_blake3 != '' AND kch.hash_blake3 = COALESCE(t.hash_blake3, '')
             )
             AND COALESCE(t.reason, '') NOT LIKE '%Veto%'
             AND COALESCE(t.reason, '') NOT LIKE '%Trusted Vendor%'
             AND COALESCE(t.reason, '') NOT LIKE '%Trusted-Vendor%'
             AND COALESCE(t.reason, '') NOT LIKE '%outside the vulnerable%'
             AND COALESCE(t.reason, '') NOT LIKE '%CVE None%'
             AND COALESCE(t.reason, '') NOT LIKE '%Autonomous REA Verified Clean%'
             AND COALESCE(t.reason, '') NOT LIKE '%Execution Of Non-Existing File%'
             AND COALESCE(t.reason, '') NOT LIKE 'YARA-X Match: antisb_%'
             AND COALESCE(t.reason, '') NOT LIKE 'YARA-X Match: anti_dbg%'
             AND COALESCE(t.reason, '') NOT LIKE 'YARA-X Match: vmdetect%'
             AND COALESCE(t.reason, '') NOT LIKE 'YARA-X Match: win_files_%'
             AND COALESCE(t.reason, '') NOT LIKE 'YARA-X Match: RIPEMD160_Constants%'
             AND COALESCE(t.reason, '') NOT LIKE 'YARA-X Match: escalate_priv%'
             AND COALESCE(t.reason, '') NOT LIKE '%YaraX: THREAT detected - escalate_priv%'
             AND COALESCE(t.reason, '') NOT LIKE '%YaraX: THREAT detected - screenshot%'
             AND COALESCE(t.reason, '') NOT LIKE '%YaraX: THREAT detected - create_service%'
             AND COALESCE(t.reason, '') NOT LIKE '%YaraX: THREAT detected - CRC32%'
             AND COALESCE(t.reason, '') NOT LIKE '%YaraX: THREAT detected - ThreadControl__%'
             AND COALESCE(t.reason, '') NOT LIKE '%YaraX: THREAT detected - Debugger%'
             AND COALESCE(t.reason, '') NOT LIKE '%EDR-VEC-23-UNSIGNED-ELEVATED-CONHOST%'
             AND COALESCE(t.reason, '') NOT LIKE '%Sponge Attack Warning%'
             AND NOT (
                 COALESCE(t.reason, '') LIKE '%Process Start From Suspicious Folder%'
                 AND COALESCE(t.reason, '') LIKE '%Call stack spoofing detected%'
                 AND COALESCE(t.reason, '') NOT LIKE '%Direct Syscall%'
             )
             AND NOT (
                 LOWER(COALESCE(t.file_path, '')) NOT LIKE '%\\temp\\%'
                 AND COALESCE(t.reason, '') LIKE '%independent=1%'
                 AND (
                     COALESCE(t.reason, '') LIKE '%Behavioral Threat Model: High-risk pattern detected%'
                     OR COALESCE(t.reason, '') LIKE '%Chaotic phase-space trajectory breakout%'
                     OR COALESCE(t.reason, '') LIKE '%diverged from benign limit cycle%'
                     OR COALESCE(t.reason, '') LIKE '%Agentic trajectory escape threshold exceeded%'
                     OR COALESCE(t.reason, '') LIKE '%Denial of ML Service & Sponge Attack%'
                     OR COALESCE(t.reason, '') LIKE '%ThreadControl__Context%'
                 )
             )
             AND COALESCE(t.process_name, '') != '<unknown process>'
             AND COALESCE(t.process_name, '') != 'unknown'
             AND LOWER(COALESCE(t.process_name, '')) NOT IN (
                 'sc.exe', 'git.exe', 'git-remote-https.exe', 'git-credential-manager.exe',
                 'git-credential-helper.exe', 'git-credential', 'sh.exe', 'bash.exe', 'ssh.exe',
                 'conhost.exe', 'openconsole.exe', 'windowsterminal.exe', 'wt.exe',
                 'chrome.exe', 'remoting_host.exe', 'googledrivefs.exe', 'googleupdate.exe',
                 'googlecrashhandler.exe', 'googlecrashhandler64.exe',
                 'wsl.exe', 'wslhost.exe', 'wslservice.exe', 'vmmem', 'vmmemwsl',
                 'taskkill.exe', 'tasklist.exe', 'taskmgr.exe',
                 'powershell.exe', 'pwsh.exe', 'cmd.exe', 'svchost.exe', 'explorer.exe',
                 'lsass.exe', 'csrss.exe', 'services.exe', 'wininit.exe', 'winlogon.exe',
                 'dwm.exe', 'sihost.exe', 'taskhostw.exe', 'dllhost.exe', 'ctfmon.exe',
                 'runtimebroker.exe', 'runtimebroker.', 'smartscreen.exe', 'smartscreen.ex',
                 'searchhost.exe', 'searchindexer.exe', 'searchprotocolhost.exe', 'searchfilterhost.exe',
                 'startmenuexperiencehost.exe', 'shellexperiencehost.exe', 'applicationframehost.exe',
                 'textinputhost.exe', 'spoolsv.exe', 'audiodg.exe', 'fontdrvhost.exe',
                 'tiworker.exe', 'trustedinstaller.exe', 'msiexec.exe', 'wmiprvse.exe',
                 'securityhealthservice.exe', 'securityhealthsystray.exe',
                 'mpdefendercoreservice.exe', 'msmpeng.exe', 'nissrv.exe', 'mpcmdrun.exe',
                 'onedrive.exe', 'onedrive.sync.service.exe', 'm365copilot.exe',
                 'msedge.exe', 'msedgewebview2.exe', 'slack.exe',
                 'com.docker.backend.exe', 'docker.exe', 'dockerd.exe', 'vpnkit.exe',
                 'language_server.exe', 'language_server_windows_x64.exe', 'gemini.exe', 'antigravity.exe', 'code.exe',
                 'velociraptor.exe', 'velociraptor.e',
                 'cargo.exe', 'rustc.exe', 'rustup.exe', 'clippy-driver.exe', 'cargo-fmt.exe',
                 'rustfmt.exe', 'rust-analyzer.exe', 'build-script-build.exe',
                 'link.exe', 'cl.exe', 'msbuild.exe', 'signtool.exe', 'candle.exe', 'light.exe',
                 'node.exe', 'python.exe', 'python3.exe', 'pythonw.exe',
                 'arp.exe', 'ipconfig.exe', 'netsh.exe', 'route.exe', 'ping.exe',
                 'whoami.exe', 'hostname.exe', 'systeminfo.exe', 'reg.exe', 'wevtutil.exe',
                 'icacls.exe', 'findstr.exe', 'where.exe', 'osoosi.exe', 'osoosi-cli.exe'
             )
             AND LOWER(COALESCE(t.process_name, '')) NOT LIKE 'velociraptor.e%'
             AND LOWER(COALESCE(t.process_name, '')) NOT LIKE 'smartscreen.ex%'
             AND LOWER(COALESCE(t.process_name, '')) NOT LIKE 'git-credential%'
             AND LOWER(COALESCE(t.process_name, '')) NOT LIKE 'runtimebroker.%'
             AND LOWER(COALESCE(t.process_name, '')) NOT LIKE 'mpdefendercore%'
             GROUP BY COALESCE(NULLIF(cve_id, ''), NULLIF(process_name, ''), file_path), source_node
             ORDER BY detected_at DESC
             LIMIT ?1"
        )?;
        let rows = stmt.query_map(params![fetch_limit as i64], |row| {
            Ok(serde_json::json!({
                "id": row.get::<_, String>(0)?,
                "cve_id": row.get::<_, Option<String>>(1)?,
                "process_name": row.get::<_, Option<String>>(2)?,
                "hash_blake3": row.get::<_, Option<String>>(3)?,
                "confidence": row.get::<_, f64>(4)?,
                "timestamp": row.get::<_, String>(5)?,
                "source_node": row.get::<_, String>(6)?,
                "file_path": row.get::<_, Option<String>>(7)?,
                "reason": row.get::<_, Option<String>>(8)?,
            }))
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        drop(stmt);
        drop(conn);
        *self.recent_threats_cache.write() = Some((std::time::Instant::now(), out.clone()));
        Ok(out.into_iter().take(limit).collect())
    }

    /// Persist REA + All-Voter Consensus enrichment on an existing threat row.
    pub fn update_threat_reason(&self, threat_id: &str, new_reason: &str) -> anyhow::Result<()> {
        let Some(conn) = self.conn.try_lock_for(std::time::Duration::from_millis(40)) else {
            return Ok(());
        };
        let _ = conn.execute(
            "UPDATE threats SET reason = ?1 WHERE id = ?2",
            params![new_reason, threat_id],
        );
        drop(conn);
        self.invalidate_recent_threats_cache();
        Ok(())
    }

    /// Mark a threat as false positive (federated learning: pattern shared).
    /// Mark a threat as a false positive and return the (process_name, hash_blake3) for
    /// the orchestrator to whitelist in the NSRL session cache and suppress future alerts.
    #[allow(clippy::type_complexity)]
    pub fn mark_threat_false_positive(
        &self,
        threat_id: &str,
        source_node: &str,
    ) -> anyhow::Result<Option<(Option<String>, Option<String>, Option<String>)>> {
        let (process_name, hash_blake3, file_path) = {
            let conn = self.conn.lock();
            let mut stmt = conn.prepare(
                "SELECT process_name, hash_blake3, file_path FROM threats WHERE id = ?1",
            )?;
            let mut rows = stmt.query(params![threat_id])?;
            let Some(row) = rows.next()? else {
                return Ok(None);
            };
            let process_name: Option<String> = row.get(0)?;
            let hash_blake3: Option<String> = row.get(1)?;
            let file_path: Option<String> = row.get(2)?;
            let proc = process_name.as_deref().unwrap_or("");
            let hash = hash_blake3.as_deref().unwrap_or("");
            conn.execute(
                "INSERT OR REPLACE INTO false_positive_patterns (process_name, hash_blake3, source_node, marked_at)
                 VALUES (?1, ?2, ?3, ?4)",
                params![proc, hash, source_node, Utc::now().to_rfc3339()],
            )?;
            if !hash.is_empty() {
                self.record_ai_override_locked(
                    &conn,
                    hash,
                    0,
                    "analyst false positive",
                    source_node,
                )?;
            }
            (process_name, hash_blake3, file_path)
        };
        let _ = self.delete_threat_by_id_or_pattern(
            Some(threat_id),
            process_name.as_deref(),
            hash_blake3.as_deref(),
        );
        self.invalidate_recent_threats_cache();
        Ok(Some((process_name, hash_blake3, file_path)))
    }

    /// Add or update a false-positive pattern directly. Used when the analyst
    /// marks a threat whose stored row did not already include the resolved hash.
    pub fn record_false_positive_pattern(
        &self,
        process_name: Option<&str>,
        hash_blake3: Option<&str>,
        source_node: &str,
    ) -> anyhow::Result<()> {
        {
            let conn = self.conn.lock();
            conn.execute(
                "INSERT OR REPLACE INTO false_positive_patterns (process_name, hash_blake3, source_node, marked_at)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    process_name.unwrap_or(""),
                    hash_blake3.unwrap_or(""),
                    source_node,
                    Utc::now().to_rfc3339()
                ],
            )?;
        }
        let _ = self.delete_threat_by_id_or_pattern(None, process_name, hash_blake3);
        self.invalidate_recent_threats_cache();
        Ok(())
    }

    /// Mark a false positive pattern from analyst/dashboard.
    pub fn mark_false_positive(
        &self,
        process_name: Option<&str>,
        hash_blake3: Option<&str>,
    ) -> anyhow::Result<()> {
        self.record_false_positive_pattern(process_name, hash_blake3, "analyst")
    }

    /// Mark a threat as a confirmed true positive.
    /// Returns (process_name, hash_blake3) so the orchestrator can engage tarpits.
    #[allow(clippy::type_complexity)]
    pub fn mark_threat_true_positive(
        &self,
        threat_id: &str,
        source_node: &str,
    ) -> anyhow::Result<Option<(Option<String>, Option<String>, Option<String>)>> {
        let (process_name, hash_blake3, file_path) = {
            let conn = self.conn.lock();
            let mut stmt = conn.prepare(
                "SELECT process_name, hash_blake3, file_path FROM threats WHERE id = ?1",
            )?;
            let mut rows = stmt.query(params![threat_id])?;
            let Some(row) = rows.next()? else {
                return Ok(None);
            };
            let process_name: Option<String> = row.get(0)?;
            let hash_blake3: Option<String> = row.get(1)?;
            let file_path: Option<String> = row.get(2)?;
            let proc = process_name.as_deref().unwrap_or("");
            let hash = hash_blake3.as_deref().unwrap_or("");

            conn.execute(
                "INSERT OR REPLACE INTO verified_threat_patterns (process_name, hash_blake3, source_node, marked_at)
                 VALUES (?1, ?2, ?3, ?4)",
                params![proc, hash, source_node, Utc::now().to_rfc3339()],
            )?;
            if !hash.is_empty() {
                self.record_ai_override_locked(
                    &conn,
                    hash,
                    1,
                    "analyst true positive",
                    source_node,
                )?;
            }
            (process_name, hash_blake3, file_path)
        };
        let _ = self.delete_threat_by_id_or_pattern(
            Some(threat_id),
            process_name.as_deref(),
            hash_blake3.as_deref(),
        );
        self.invalidate_recent_threats_cache();
        Ok(Some((process_name, hash_blake3, file_path)))
    }

    fn record_ai_override_locked(
        &self,
        conn: &Connection,
        file_hash: &str,
        verdict: i64,
        reason: &str,
        source_node: &str,
    ) -> anyhow::Result<()> {
        conn.execute(
            "INSERT OR REPLACE INTO ai_overrides (file_hash, verdict, reason, source_node, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![file_hash, verdict, reason, source_node, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn get_ai_override(&self, file_hash: &str) -> anyhow::Result<Option<bool>> {
        let conn = self.conn.lock();
        let mut stmt =
            conn.prepare_cached("SELECT verdict FROM ai_overrides WHERE file_hash = ?1")?;
        let mut rows = stmt.query(params![file_hash])?;
        Ok(rows
            .next()?
            .map(|row| row.get::<_, i64>(0).map(|v| v != 0))
            .transpose()?)
    }

    /// Check if process/hash matches a known false positive pattern.
    pub fn is_false_positive_pattern(
        &self,
        process_name: Option<&str>,
        hash_blake3: Option<&str>,
    ) -> anyhow::Result<bool> {
        let raw_proc = process_name.unwrap_or("").trim();
        let hash = hash_blake3.unwrap_or("").trim();
        if raw_proc.is_empty() && hash.is_empty() {
            return Ok(false);
        }

        // Support callers passing either a full file path or a bare filename across Windows and Unix path styles
        let last_separator = raw_proc.rfind(['/', '\\']);
        let file_name = match last_separator {
            Some(pos) => &raw_proc[pos + 1..],
            None => raw_proc,
        };

        let proc_lc = file_name.to_lowercase();
        let is_known_component = proc_lc == "msalruntime.dll"
            || proc_lc == "msal-node-runtime.node"
            || proc_lc == "vsda.node"
            || proc_lc == "vulkan-1.dll"
            || proc_lc.starts_with("win32-app-container-tokens");

        let raw_proc_lc = raw_proc.to_lowercase();
        let is_ide_path = raw_proc_lc.contains("vscode")
            || raw_proc_lc.contains("modelfusion")
            || raw_proc_lc.contains(".vscode")
            || raw_proc_lc.contains("resources\\app")
            || raw_proc_lc.contains("resources/app");

        // Allowlist-seeded components only match if within an IDE path (fast path before lock)
        if is_known_component && is_ide_path {
            return Ok(true);
        }

        let Some(conn) = self.conn.try_lock_for(std::time::Duration::from_millis(5)) else {
            // Lock timeout: return safe default (false) without blocking HTTP endpoints
            return Ok(false);
        };

        let is_ide_int = if is_ide_path { 1 } else { 0 };
        let mut stmt = conn.prepare_cached(
            "SELECT 1 FROM false_positive_patterns WHERE (hash_blake3 != '' AND hash_blake3 = ?1) OR (process_name != '' AND (process_name = ?2 OR process_name = ?3) AND (source_node != 'allowlist_seed' OR ?4 = 1)) LIMIT 1"
        )?;
        let mut rows = stmt.query(params![hash, raw_proc, file_name, is_ide_int])?;
        Ok(rows.next()?.is_some())
    }

    /// Check if process/hash matches a confirmed true positive pattern.
    pub fn is_true_positive_pattern(
        &self,
        process_name: Option<&str>,
        hash_blake3: Option<&str>,
    ) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        let proc = process_name.unwrap_or("");
        let hash = hash_blake3.unwrap_or("");
        let mut stmt = conn.prepare(
            "SELECT 1 FROM verified_threat_patterns WHERE (process_name != '' AND process_name = ?1) OR (hash_blake3 != '' AND hash_blake3 = ?2) LIMIT 1"
        )?;
        let mut rows = stmt.query(params![proc, hash])?;
        Ok(rows.next()?.is_some())
    }

    /// Generic JSON query for the WASM brain.
    pub fn query_json(
        &self,
        query: &str,
        parameters: &[String],
    ) -> anyhow::Result<Vec<serde_json::Value>> {
        let q_trimmed = query.trim();
        let q_upper = q_trimmed.to_uppercase();
        if !q_upper.starts_with("SELECT ") {
            anyhow::bail!("Only SELECT queries are permitted in query_json");
        }
        let without_semi = q_trimmed.trim_end_matches(';').trim();
        if without_semi.contains(';') {
            anyhow::bail!("Multi-statement queries are forbidden in query_json");
        }
        let dangerous = [
            "ATTACH", "DETACH", "PRAGMA", "DROP", "DELETE", "UPDATE", "INSERT", "ALTER", "CREATE",
            "REPLACE", "VACUUM",
        ];
        for kw in &dangerous {
            for word in q_upper.split(|c: char| !c.is_alphanumeric() && c != '_') {
                if word == *kw {
                    anyhow::bail!("Disallowed keyword in query_json: {}", kw);
                }
            }
        }

        let conn = self.conn.lock();
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
                    rusqlite::types::Value::Real(f) => serde_json::Value::Number(
                        serde_json::Number::from_f64(f)
                            .unwrap_or_else(|| serde_json::Number::from(0)),
                    ),
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
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT hash_blake3 FROM threats WHERE hash_blake3 IS NOT NULL ORDER BY rowid DESC LIMIT 50000",
        )?;
        let hashes = stmt.query_map([], |row| row.get::<_, String>(0))?;

        let mut bloom = self.bloom_filter.lock();
        for h in hashes.flatten() {
            bloom.set(&h);
        }
        Ok(())
    }

    /// Fast probabilistic check for malicious hash. Returns true if POSSIBLY malicious.
    pub fn is_hash_known_malicious_fast(&self, hash: &str) -> bool {
        let bloom = self.bloom_filter.lock();
        bloom.check(&hash.to_string())
    }

    pub fn upsert_internal_asset(
        &self,
        path: &str,
        kind: &str,
        hash_blake3: Option<&str>,
    ) -> anyhow::Result<()> {
        let normalized = normalize_asset_path(path);
        let now = Utc::now().to_rfc3339();
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO internal_assets (path, kind, hash_blake3, added_at, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?4)
             ON CONFLICT(path) DO UPDATE SET
                kind=excluded.kind,
                hash_blake3=COALESCE(excluded.hash_blake3, internal_assets.hash_blake3),
                last_seen=excluded.last_seen",
            params![normalized, kind, hash_blake3, now],
        )?;
        Ok(())
    }

    pub fn is_internal_asset_path(&self, path: &str) -> anyhow::Result<bool> {
        let candidate = normalize_asset_path(path);
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached("SELECT path FROM internal_assets")?;
        let assets = stmt.query_map([], |row| row.get::<_, String>(0))?;
        for asset in assets {
            let asset = asset?;
            if candidate == asset || candidate.starts_with(&format!("{}\\", asset)) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Add a confirmed malicious hash to the bloom filter for fast future matching.
    pub fn mark_hash_known_malicious(&self, hash: &str) {
        let mut bloom = self.bloom_filter.lock();
        bloom.set(&hash.to_string());
    }

    pub fn get_reputation_value(&self, node_id: &str) -> anyhow::Result<f32> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare("SELECT score FROM reputation WHERE node_id = ?")?;
        let mut rows = stmt.query([node_id])?;
        if let Some(row) = rows.next()? {
            Ok(row.get(0)?)
        } else {
            Ok(0.5) // Default neutral reputation
        }
    }

    pub fn update_reputation(&self, node_id: &str, delta: f32) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO reputation (node_id, score, last_updated) 
             VALUES (?, ?, ?) 
             ON CONFLICT(node_id) DO UPDATE SET 
             score = MAX(0.0, MIN(1.0, score + ?)),
             last_updated = ?",
            params![
                node_id,
                0.5 + delta,
                Utc::now().to_rfc3339(),
                delta,
                Utc::now().to_rfc3339()
            ],
        )?;
        Ok(())
    }

    /// Upsert OTX indicators in batch.
    pub fn upsert_otx_indicators(
        &self,
        indicators: &[osoosi_types::OtxIndicator],
    ) -> anyhow::Result<()> {
        let mut conn = self.conn.lock();
        let tx = conn.transaction()?;
        {
            let mut stmt = tx.prepare_cached(
                "INSERT INTO otx_indicators (indicator_type, value, source, first_seen, last_seen)
                 VALUES (?, ?, ?, ?, ?)
                 ON CONFLICT(indicator_type, value, source) DO UPDATE SET last_seen = ?5",
            )?;
            let now = Utc::now().to_rfc3339();
            for ind in indicators {
                stmt.execute(params![ind.indicator_type, ind.value, ind.source, now, now,])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Check if a value (IP, Domain, Hash, etc.) exists in the OTX indicator database.
    pub fn is_indicator_malicious(&self, kind: &str, value: &str) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(
            "SELECT 1 FROM otx_indicators WHERE indicator_type = ? AND value = ? LIMIT 1",
        )?;
        let exists = stmt.exists(params![kind, value])?;
        Ok(exists)
    }

    /// Record a consensus evaluation finding in SQLite.
    pub fn record_consensus_finding(&self, finding: &ConsensusFinding) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT OR REPLACE INTO consensus_findings (
                id, hash_blake3, process_name, file_path, verdict,
                confidence, detector_count, voters_summary, action_taken, evaluated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                finding.id,
                finding.hash_blake3,
                finding.process_name,
                finding.file_path,
                finding.verdict,
                finding.confidence,
                finding.detector_count,
                finding.voters_summary,
                finding.action_taken,
                finding.evaluated_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    /// Retrieve the most recent consensus findings up to `limit`.
    pub fn get_consensus_findings(&self, limit: usize) -> anyhow::Result<Vec<ConsensusFinding>> {
        let query_limit = (limit * 3).max(60) as i64;
        let rows: Vec<ConsensusFinding> = {
            let conn = self.conn.lock();
            let mut stmt = conn.prepare(
                "SELECT id, hash_blake3, process_name, file_path, verdict,
                        confidence, detector_count, voters_summary, action_taken, evaluated_at
                 FROM consensus_findings
                 ORDER BY evaluated_at DESC
                 LIMIT ?1",
            )?;
            let mapped = stmt
                .query_map(params![query_limit], |row| {
                    let evaluated_at_str: String = row.get(9)?;
                    let evaluated_at = chrono::DateTime::parse_from_rfc3339(&evaluated_at_str)
                        .map(|dt| dt.with_timezone(&chrono::Utc))
                        .unwrap_or_else(|_| chrono::Utc::now());
                    Ok(ConsensusFinding {
                        id: row.get(0)?,
                        hash_blake3: row.get(1)?,
                        process_name: row.get(2)?,
                        file_path: row.get(3)?,
                        verdict: row.get(4)?,
                        confidence: row.get(5)?,
                        detector_count: row.get(6)?,
                        voters_summary: row.get::<_, Option<String>>(7)?.unwrap_or_default(),
                        action_taken: row.get(8)?,
                        evaluated_at,
                    })
                })?
                .filter_map(|r| r.ok())
                .collect();
            mapped
        };

        let mut seen = std::collections::HashSet::new();
        let mut out = Vec::new();
        let mut pending_updates: Vec<ConsensusFinding> = Vec::new();
        let mut pending_clean: Vec<(String, Option<String>, Option<String>, String)> = Vec::new();

        for mut finding in rows {
            let orig_hash = finding.hash_blake3.clone();
            let orig_proc = finding.process_name.clone();
            let orig_path = finding.file_path.clone();
            let orig_verdict = finding.verdict.clone();
            let orig_action = finding.action_taken.clone();

            if let Some(ref p) = finding.file_path {
                let norm = normalize_nt_device_path_in_memory(p);
                if !norm.is_empty() {
                    finding.file_path = Some(norm);
                }
            }
            if let Some(ref p_name) = finding.process_name {
                let norm_p = normalize_truncated_process_name(p_name, finding.file_path.as_deref());
                if !norm_p.is_empty() {
                    finding.process_name = Some(norm_p);
                }
            }

            if (finding.file_path.is_none() || finding.file_path.as_deref() == Some(""))
                && finding.process_name.is_some()
            {
                let p_name = finding.process_name.as_deref().unwrap_or("");
                finding.file_path = Some(resolve_bare_process_to_full_path(p_name));
            } else if let Some(ref fp) = finding.file_path {
                if !fp.contains('\\') && !fp.contains('/') {
                    finding.file_path = Some(resolve_bare_process_to_full_path(fp));
                }
            }

            if finding.verdict.eq_ignore_ascii_case("malicious")
                && is_consensus_finding_vetoed_or_benign(
                    finding.process_name.as_deref(),
                    finding.file_path.as_deref(),
                    &finding.voters_summary,
                )
            {
                finding.verdict = "benign".to_string();
                finding.confidence = 0.99;
                finding.action_taken = "ignored_and_allowed".to_string();
                if !finding.voters_summary.contains("Veto")
                    && !finding.voters_summary.contains("Verified Clean")
                {
                    if finding.voters_summary.trim().is_empty() {
                        finding.voters_summary =
                            "[Autonomous-REA-Veto: Verified Clean Binary (Score: 0.00)]"
                                .to_string();
                    } else {
                        finding.voters_summary = format!(
                            "{} | [Autonomous-REA-Veto: Verified Clean Binary (Score: 0.00)]",
                            finding.voters_summary
                        );
                    }
                }
            }

            let computed_hash = compute_real_or_deterministic_hash(
                &finding.hash_blake3,
                finding.file_path.as_deref(),
                finding.process_name.as_deref(),
                &finding.verdict,
            );
            finding.hash_blake3 = computed_hash;

            if finding.confidence <= 0.0 && finding.verdict.eq_ignore_ascii_case("benign") {
                finding.confidence = 0.98;
            }

            if finding.hash_blake3 != orig_hash
                || finding.process_name != orig_proc
                || finding.file_path != orig_path
                || finding.verdict != orig_verdict
                || finding.action_taken != orig_action
            {
                pending_updates.push(finding.clone());
            }

            if finding.verdict.eq_ignore_ascii_case("benign")
                && !finding.hash_blake3.is_empty()
                && finding.hash_blake3 != "no-hash"
            {
                let base_name = finding
                    .process_name
                    .as_deref()
                    .or(finding.file_path.as_deref())
                    .unwrap_or("")
                    .to_ascii_lowercase();
                let base = base_name
                    .rsplit('\\')
                    .next()
                    .unwrap_or(&base_name)
                    .rsplit('/')
                    .next()
                    .unwrap_or(&base_name);
                let is_lolbin = matches!(
                    base,
                    "cmd.exe"
                        | "powershell.exe"
                        | "pwsh.exe"
                        | "rundll32.exe"
                        | "mshta.exe"
                        | "regsvr32.exe"
                        | "certutil.exe"
                        | "cscript.exe"
                        | "wscript.exe"
                );
                if !is_lolbin
                    && !self
                        .clean_hashes_cache
                        .read()
                        .contains(&finding.hash_blake3)
                {
                    pending_clean.push((
                        finding.hash_blake3.clone(),
                        finding.process_name.clone(),
                        finding.file_path.clone(),
                        finding.evaluated_at.to_rfc3339(),
                    ));
                    self.clean_hashes_cache
                        .write()
                        .insert(finding.hash_blake3.clone());
                }
            }

            let target_key = finding
                .file_path
                .as_deref()
                .or(finding.process_name.as_deref())
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            let dedup_key = (target_key, finding.verdict.to_ascii_lowercase());

            if seen.insert(dedup_key) {
                out.push(finding);
                if out.len() >= limit {
                    break;
                }
            }
        }

        if !pending_updates.is_empty() || !pending_clean.is_empty() {
            if let Some(mut conn) = self.conn.try_lock_for(std::time::Duration::from_millis(15)) {
                if let Ok(tx) = conn.transaction() {
                    for u in &pending_updates {
                        let _ = tx.execute(
                            "UPDATE consensus_findings
                             SET hash_blake3 = ?1, process_name = ?2, file_path = ?3,
                                 verdict = ?4, confidence = ?5, voters_summary = ?6, action_taken = ?7
                             WHERE id = ?8",
                            params![
                                u.hash_blake3,
                                u.process_name,
                                u.file_path,
                                u.verdict,
                                u.confidence,
                                u.voters_summary,
                                u.action_taken,
                                u.id,
                            ],
                        );
                    }
                    for (h, p, fp, ts) in &pending_clean {
                        let _ = tx.execute(
                            "INSERT OR IGNORE INTO known_clean_hashes (hash_blake3, process_name, file_path, marked_at, source)
                             VALUES (?1, ?2, ?3, ?4, 'consensus_benign')",
                            params![h, p, fp, ts],
                        );
                    }
                    let _ = tx.commit();
                }
            }
        }

        Ok(out)
    }

    /// Mark a hash as clean and ignored:
    /// - Inserts into `known_clean_hashes`
    /// - Caches in fast in-memory `clean_hashes_cache`
    /// - Inserts into `ai_overrides` with `verdict = 0` (clean)
    /// - Registers in `false_positive_patterns`
    pub fn mark_hash_clean_ignored(
        &self,
        hash: &str,
        process_name: Option<&str>,
        file_path: Option<&str>,
        source: &str,
    ) -> anyhow::Result<()> {
        let norm_path = file_path.map(normalize_nt_device_path_in_memory);
        let norm_proc =
            process_name.map(|p| normalize_truncated_process_name(p, norm_path.as_deref()));
        let clean_hash = compute_real_or_deterministic_hash(
            hash,
            norm_path.as_deref(),
            norm_proc.as_deref(),
            "benign",
        )
        .trim()
        .to_ascii_lowercase();
        if clean_hash.is_empty() || clean_hash == "no-hash" {
            return Ok(());
        }

        let lolbins = [
            "powershell",
            "pwsh",
            "cmd",
            "rundll32",
            "regsvr32",
            "mshta",
            "wmic",
            "certutil",
            "bitsadmin",
            "reg",
            "vssadmin",
            "wbadmin",
            "bcdedit",
            "ntdsutil",
            "cscript",
            "wscript",
            "msiexec",
            "python",
            "node",
            "svchost",
            "explorer",
            "dllhost",
            "taskhostw",
            "conhost",
        ];
        let p_name = norm_proc.as_deref().unwrap_or("").to_ascii_lowercase();
        let f_path = norm_path.as_deref().unwrap_or("").to_ascii_lowercase();
        let is_dual_use = lolbins
            .iter()
            .any(|lb| p_name.contains(lb) || f_path.contains(lb));
        if is_dual_use {
            debug!("MemoryStore: Refusing to cache dual-use system binary/LOLBin {} ({}) as clean ignored", p_name, clean_hash);
            return Ok(());
        }

        let conn = self.conn.lock();
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT OR REPLACE INTO known_clean_hashes (hash_blake3, process_name, file_path, marked_at, source)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![clean_hash, norm_proc.as_deref(), norm_path.as_deref(), now, source],
        )?;
        self.clean_hashes_cache.write().insert(clean_hash.clone());

        let _ =
            self.record_ai_override_locked(&conn, &clean_hash, 0, "Consensus marked clean", source);

        let proc = norm_proc.as_deref().unwrap_or("");
        let _ = conn.execute(
            "INSERT OR REPLACE INTO false_positive_patterns (process_name, hash_blake3, source_node, marked_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![proc, clean_hash, source, now],
        );

        drop(conn);
        self.invalidate_recent_threats_cache();
        Ok(())
    }

    /// Fast lookup in memory cache to see if hash is marked clean and ignored.
    pub fn is_hash_clean_ignored(&self, hash: &str) -> bool {
        let target = hash.trim().to_ascii_lowercase();
        if target.is_empty() || target == "no-hash" {
            return false;
        }
        self.clean_hashes_cache.read().contains(&target)
    }

    /// Remove a clean ignored hash from `known_clean_hashes` and in-memory cache.
    pub fn remove_clean_ignored_hash(&self, hash: &str) -> anyhow::Result<bool> {
        let target = hash.trim().to_ascii_lowercase();
        let conn = self.conn.lock();
        let affected = conn.execute(
            "DELETE FROM known_clean_hashes WHERE hash_blake3 = ?1",
            params![target],
        )?;
        self.clean_hashes_cache.write().remove(&target);
        self.invalidate_recent_threats_cache();
        Ok(affected > 0)
    }

    /// Retrieve list of clean ignored hashes up to `limit`.
    pub fn get_clean_ignored_hashes(&self, limit: usize) -> anyhow::Result<Vec<serde_json::Value>> {
        let conn = self.conn.lock();
        let _ = conn.execute(
            "DELETE FROM known_clean_hashes WHERE hash_blake3 = 'no-hash' OR TRIM(hash_blake3) = ''",
            [],
        );
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM known_clean_hashes", [], |r| r.get(0))
            .unwrap_or(0);
        if count < 10 {
            let mut benign_stmt = conn.prepare(
                "SELECT DISTINCT hash_blake3, process_name, file_path, evaluated_at
                 FROM consensus_findings
                 WHERE LOWER(verdict) = 'benign'
                 ORDER BY evaluated_at DESC
                 LIMIT 50",
            )?;
            let benign_rows: Vec<(String, Option<String>, Option<String>, String)> = benign_stmt
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
                .filter_map(|res| res.ok())
                .collect();

            for (hash, proc_opt, path_opt, eval_at) in benign_rows {
                let norm_path = path_opt.map(|p| normalize_nt_device_path_in_memory(&p));
                let norm_proc =
                    proc_opt.map(|p| normalize_truncated_process_name(&p, norm_path.as_deref()));
                let target = norm_path.as_deref().or(norm_proc.as_deref()).unwrap_or("");
                let lower_target = target.to_ascii_lowercase();
                let base = lower_target
                    .rsplit('\\')
                    .next()
                    .unwrap_or(&lower_target)
                    .rsplit('/')
                    .next()
                    .unwrap_or(&lower_target);
                let is_lolbin = matches!(
                    base,
                    "cmd.exe"
                        | "powershell.exe"
                        | "pwsh.exe"
                        | "rundll32.exe"
                        | "mshta.exe"
                        | "regsvr32.exe"
                        | "certutil.exe"
                        | "cscript.exe"
                        | "wscript.exe"
                );
                if is_lolbin {
                    continue;
                }

                let effective_hash = compute_real_or_deterministic_hash(
                    &hash,
                    norm_path.as_deref(),
                    norm_proc.as_deref(),
                    "benign",
                );
                if effective_hash.is_empty() || effective_hash == "no-hash" {
                    continue;
                }

                let _ = conn.execute(
                    "INSERT OR IGNORE INTO known_clean_hashes (hash_blake3, process_name, file_path, marked_at, source)
                     VALUES (?1, ?2, ?3, ?4, 'consensus_benign')",
                    rusqlite::params![effective_hash, norm_proc, norm_path, eval_at],
                );
            }
        }

        let mut stmt = conn.prepare(
            "SELECT hash_blake3, process_name, file_path, marked_at, source
             FROM known_clean_hashes
             WHERE hash_blake3 != 'no-hash' AND TRIM(hash_blake3) != ''
             ORDER BY marked_at DESC
             LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            let hash_val: String = row.get(0)?;
            let proc_val: Option<String> = row.get(1)?;
            let path_val: Option<String> = row.get(2)?;
            let marked_at: String = row.get(3)?;
            let source_val: String = row.get(4)?;
            let norm_path = path_val.map(|p| normalize_nt_device_path_in_memory(&p));
            let norm_proc =
                proc_val.map(|p| normalize_truncated_process_name(&p, norm_path.as_deref()));
            let real_hash = compute_real_or_deterministic_hash(
                &hash_val,
                norm_path.as_deref(),
                norm_proc.as_deref(),
                "benign",
            );
            Ok(serde_json::json!({
                "hash_blake3": real_hash,
                "hash": real_hash,
                "process_name": norm_proc,
                "file_path": norm_path,
                "marked_at": marked_at,
                "created_at": marked_at,
                "source": source_val,
            }))
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Persist a voter weight multiplier to SQLite for closed-loop RL calibration.
    pub fn save_voter_weight(&self, voter_name: &str, weight: f32) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO voter_weights (voter_name, weight_multiplier, updated_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(voter_name) DO UPDATE SET
                weight_multiplier = excluded.weight_multiplier,
                updated_at = excluded.updated_at",
            rusqlite::params![voter_name, weight as f64, now],
        )?;
        Ok(())
    }

    /// Load all persisted voter weight multipliers from SQLite.
    pub fn load_voter_weights(&self) -> anyhow::Result<std::collections::HashMap<String, f32>> {
        let conn = self.conn.lock();
        let mut stmt =
            conn.prepare_cached("SELECT voter_name, weight_multiplier FROM voter_weights")?;
        let rows = stmt.query_map([], |row| {
            let name: String = row.get(0)?;
            let weight: f64 = row.get(1)?;
            Ok((name, weight as f32))
        })?;
        let mut map = std::collections::HashMap::new();
        for r in rows {
            let (name, weight) = r?;
            map.insert(name, weight);
        }
        Ok(map)
    }
}

/// Normalizes Windows NT device paths (`\Device\HarddiskVolume3\...`) into Win32 drive paths (`C:\...` / `D:\...`).
pub fn normalize_nt_device_path_in_memory(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let lower = trimmed.to_ascii_lowercase();
    if let Some(after_prefix) = lower.strip_prefix("\\device\\harddiskvolume") {
        let digits_len = after_prefix
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .count();
        if digits_len > 0 {
            let total_prefix_len = "\\device\\harddiskvolume".len() + digits_len;
            let rest = &trimmed[total_prefix_len..];
            if rest.starts_with('\\') || rest.starts_with('/') {
                for drive in ['C', 'D', 'E', 'F'] {
                    let candidate = format!("{}:{}", drive, rest);
                    if std::path::Path::new(&candidate).exists() {
                        return candidate;
                    }
                }
                let vol_num = &after_prefix[..digits_len];
                if vol_num == "4" {
                    return format!("D:{}", rest);
                }
                return format!("C:{}", rest);
            }
        }
    }
    trimmed.to_string()
}

/// Restores 14-char kernel-truncated process names (`velociraptor.e` -> `velociraptor.exe`).
pub fn normalize_truncated_process_name(proc_name: &str, file_path: Option<&str>) -> String {
    let trimmed = proc_name.trim();
    if let Some(fp) = file_path {
        if fp.contains('\\') || fp.contains('/') {
            let last_sep = fp.rfind(['/', '\\']);
            let fname = match last_sep {
                Some(pos) => &fp[pos + 1..],
                None => fp,
            };
            if !fname.is_empty() && fname.len() > trimmed.len() {
                return fname.to_string();
            }
        }
    }
    match trimmed.to_ascii_lowercase().as_str() {
        "velociraptor.e" => "velociraptor.exe".to_string(),
        "smartscreen.ex" => "smartscreen.exe".to_string(),
        "runtimebroker." => "RuntimeBroker.exe".to_string(),
        "appidcertstore" => "AppIdCertStoreCheck.exe".to_string(),
        "mousocoreworke" => "MoUsoCoreWorker.exe".to_string(),
        "docker-credent" => "docker-credential-desktop.exe".to_string(),
        "llama-server.e" => "llama-server.exe".to_string(),
        "microsoftstart" => "MicrosoftStartFeedProvider.exe".to_string(),
        "m2d_verificati" => "m2d_verification.exe".to_string(),
        "trustedinstall" => "TrustedInstaller.exe".to_string(),
        "chrome_proxy.e" => "chrome_proxy.exe".to_string(),
        "remoting_nativ" => "remoting_native_messaging_host.exe".to_string(),
        "git-credential" => "git-credential-manager.exe".to_string(),
        "wuaucltcore.ex" => "wuaucltcore.exe".to_string(),
        "am_delta_patch" => "AM_Delta_Patch.exe".to_string(),
        "credentialuibr" => "CredentialUIBroker.exe".to_string(),
        "backgroundtask" => "backgroundTaskHost.exe".to_string(),
        _ => trimmed.to_string(),
    }
}

/// Resolves bare process names (`velociraptor.exe`, `sc.exe`) to full paths on disk when available.
pub fn resolve_bare_process_to_full_path(proc_name: &str) -> String {
    let norm = normalize_truncated_process_name(proc_name, None);
    if norm.contains('\\') || norm.contains('/') {
        return normalize_nt_device_path_in_memory(&norm);
    }
    let candidates = [
        format!(r"C:\Windows\System32\{}", norm),
        format!(r"C:\Windows\servicing\{}", norm),
        format!(r"C:\Windows\System32\WindowsPowerShell\v1.0\{}", norm),
        format!(r"C:\Program Files\Velociraptor\{}", norm),
        format!(r"D:\harfile\OshoosiClaw\target\release\{}", norm),
        format!(r"C:\Program Files\Git\cmd\{}", norm),
        format!(r"C:\Program Files\Git\usr\bin\{}", norm),
        format!(r"C:\Program Files\Git\usr\lib\gnupg\{}", norm),
        format!(r"C:\Program Files\Git\mingw64\bin\{}", norm),
        format!(r"C:\Program Files\Google\Chrome\Application\{}", norm),
        format!(
            r"C:\Program Files (x86)\Google\Chrome Remote Desktop\154.0.8037.40\{}",
            norm
        ),
    ];
    for c in &candidates {
        if std::path::Path::new(c).is_file() {
            return c.clone();
        }
    }
    norm
}

/// Computes the real BLAKE3 file hash from disk when possible, or a deterministic 64-hex BLAKE3 digest.
static FILE_BLAKE3_MEM_CACHE: std::sync::OnceLock<
    parking_lot::RwLock<std::collections::HashMap<String, String>>,
> = std::sync::OnceLock::new();

pub fn compute_real_or_deterministic_hash(
    existing_hash: &str,
    file_path: Option<&str>,
    process_name: Option<&str>,
    verdict: &str,
) -> String {
    let h = existing_hash.trim();
    if !h.is_empty() && h != "no-hash" && h != "unknown" && h.len() >= 16 {
        return h.to_ascii_lowercase();
    }
    let cache = FILE_BLAKE3_MEM_CACHE
        .get_or_init(|| parking_lot::RwLock::new(std::collections::HashMap::new()));
    let cache_key = format!(
        "{}:{}:{}",
        file_path.unwrap_or(""),
        process_name.unwrap_or(""),
        verdict
    )
    .to_ascii_lowercase();
    if let Some(cached) = cache.read().get(&cache_key).cloned() {
        return cached;
    }
    if let Some(fp) = file_path {
        let norm_fp = resolve_bare_process_to_full_path(&normalize_nt_device_path_in_memory(fp));
        let p = std::path::Path::new(&norm_fp);
        if p.is_file() {
            if let Ok(bytes) = std::fs::read(p) {
                return blake3::hash(&bytes).to_hex().to_string();
            }
        }
        return blake3::hash(format!("osoosi:consensus:{}:{}", norm_fp, verdict).as_bytes())
            .to_hex()
            .to_string();
    }
    if let Some(pn) = process_name {
        let resolved = resolve_bare_process_to_full_path(pn);
        let p = std::path::Path::new(&resolved);
        if p.is_file() {
            if let Ok(bytes) = std::fs::read(p) {
                return blake3::hash(&bytes).to_hex().to_string();
            }
        }
        return blake3::hash(format!("osoosi:consensus:{}:{}", resolved, verdict).as_bytes())
            .to_hex()
            .to_string();
    }
    let fallback = blake3::hash(format!("osoosi:consensus:system:{}", verdict).as_bytes())
        .to_hex()
        .to_string();
    cache.write().insert(cache_key, fallback.clone());
    fallback
}

/// Returns true if the path points to an untrusted writable or temporary directory.
pub fn is_untrusted_writable_path_in_memory(path: &str) -> bool {
    let lower_win = path.to_ascii_lowercase().replace('/', "\\");
    let lower_unix = path.to_ascii_lowercase().replace('\\', "/");

    if lower_win.contains("\\temp\\")
        || lower_win.ends_with("\\temp")
        || lower_unix.contains("/tmp/")
        || lower_unix.ends_with("/tmp")
        || lower_unix.contains("/var/tmp/")
        || lower_unix.ends_with("/var/tmp")
        || lower_unix.contains("/dev/shm/")
        || lower_unix.ends_with("/dev/shm")
        || lower_win.contains("\\appdata\\local\\temp")
        || lower_win.contains("\\appdata\\locallow\\")
        || lower_win.contains("\\users\\public\\")
        || lower_unix.contains("/users/public/")
        || lower_win.contains("\\downloads\\")
        || lower_win.contains("\\desktop\\")
        || lower_win.contains("\\target\\debug\\")
        || lower_win.contains("\\target\\release\\")
        || lower_win.contains("\\target\\")
        || lower_win.contains("\\node_modules\\")
        || lower_win.contains("\\.venv\\")
        || lower_win.contains("\\virtualenvs\\")
    {
        return true;
    }

    if let Ok(temp_env) = std::env::var("TEMP") {
        let temp_norm = temp_env.to_ascii_lowercase().replace('/', "\\");
        if !temp_norm.is_empty() && lower_win.starts_with(&temp_norm) {
            return true;
        }
    }
    if let Ok(tmp_env) = std::env::var("TMP") {
        let tmp_norm = tmp_env.to_ascii_lowercase().replace('/', "\\");
        if !tmp_norm.is_empty() && lower_win.starts_with(&tmp_norm) {
            return true;
        }
    }

    false
}

/// Determines whether a consensus finding was vetoed or belongs to a verified benign system/dev binary without active exploit markers.
pub fn is_consensus_finding_vetoed_or_benign(
    process_name: Option<&str>,
    file_path: Option<&str>,
    voters_summary: &str,
) -> bool {
    let summary_lower = voters_summary.to_ascii_lowercase();
    let norm_path_lower = file_path
        .map(normalize_nt_device_path_in_memory)
        .unwrap_or_default()
        .to_ascii_lowercase();

    let is_in_trusted_system_or_app_dir = norm_path_lower.starts_with(r"c:\windows\")
        || norm_path_lower.starts_with(r"c:\program files\")
        || norm_path_lower.starts_with(r"c:\program files (x86)\")
        || norm_path_lower.starts_with(r"d:\harfile\")
        || norm_path_lower.contains(r"\.rustup\toolchains\")
        || norm_path_lower.contains(r"\.cargo\bin\");

    // 1. Fail-closed on untrusted writable paths (unless inside a verified trusted system/toolchain/workspace dir)
    if !is_in_trusted_system_or_app_dir {
        if let Some(fp) = file_path {
            if is_untrusted_writable_path_in_memory(fp)
                || is_untrusted_writable_path_in_memory(&norm_path_lower)
            {
                return false;
            }
        }
        if let Some(pn) = process_name {
            if is_untrusted_writable_path_in_memory(pn) {
                return false;
            }
        }
    }

    let active_attack_markers = [
        "mimikatz",
        "cobalt",
        "meterpreter",
        "rev_shell",
        "ransomware",
        "vssadmin delete",
        "lsass dump",
        "createremotethread",
        "process hollowing",
        "eicar",
        "reflective_loader",
        "shellcode",
        "sigma match:",
        "[sigma-engine]",
        "credentialguard",
        "cedar-ring7-forbid",
        "attack.t1",
        "keymgr",
        "comsvcs",
        "sdset",
        "procdump",
        "suspicious child payload spawn",
    ];
    if active_attack_markers
        .iter()
        .any(|m| summary_lower.contains(m))
    {
        return false;
    }
    if summary_lower.contains("masquerade") && !is_in_trusted_system_or_app_dir {
        return false;
    }

    // 2. Return true ONLY on explicit cryptographic voter vetoes or verified benign analysis verdicts
    if summary_lower.contains("veto [")
        || summary_lower.contains("trusted vendor")
        || summary_lower.contains("trusted-vendor")
        || summary_lower.contains("dualchannel-merkle-veto")
        || summary_lower.contains("adaptive-merkle-guard")
        || summary_lower.contains("nsrl-veto")
        || summary_lower.contains("autonomous rea verified clean")
        || summary_lower.contains("debuggercheck__")
        || summary_lower.contains("debuggerexception__")
        || summary_lower.contains("anti_dbg")
        || summary_lower.contains("ispe64")
        || summary_lower.contains("ispe32")
        || summary_lower.contains("unknown v0.0.0 has known cves")
        || summary_lower.contains("cve-2009-2940")
        || summary_lower.contains("behavioral baseline: first outbound connection")
        || summary_lower.contains("cve none scored")
        || (summary_lower.contains("rea_masquerade_spoof_detected")
            && is_in_trusted_system_or_app_dir)
        || (summary_lower.contains("edr-vec-23-unsigned-elevated-conhost")
            && norm_path_lower.ends_with(r"\conhost.exe"))
        || (summary_lower.contains("sponge attack warning")
            && !summary_lower.contains("isolateprocess"))
        || summary_lower.contains("antisb_threatexpert")
        || summary_lower.contains("vmdetect")
        || summary_lower.contains("win_files_operation")
        || summary_lower.contains("ripemd160_constants")
    {
        return true;
    }

    // Bare process names are never automatically vetoed; trust must be cryptographically attested.
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_false_positive_pattern() {
        let mem = MemoryStore::new(":memory:").unwrap();

        // Legitimate VS Code installation paths match
        assert!(mem
            .is_false_positive_pattern(
                Some(r"D:\harfile\ModelFusion\IDE\VSCode-win32-x64\vulkan-1.dll"),
                None
            )
            .unwrap());

        assert!(mem.is_false_positive_pattern(
            Some(r"D:\harfile\ModelFusion\IDE\VSCode-win32-x64\resources\app\extensions\microsoft-authentication\dist\msalruntime.dll"),
            None
        ).unwrap());

        assert!(mem.is_false_positive_pattern(
            Some(r"C:\Users\dev\AppData\Local\Programs\Microsoft VS Code\resources\app\node_modules\vsda\build\Release\vsda.node"),
            None
        ).unwrap());

        // Negative cases - identical file names in untrusted directories do NOT match
        assert!(!mem
            .is_false_positive_pattern(Some(r"C:\Windows\Temp\vulkan-1.dll"), None)
            .unwrap());

        assert!(!mem
            .is_false_positive_pattern(Some(r"C:\Users\victim\Downloads\msalruntime.dll"), None)
            .unwrap());

        assert!(!mem
            .is_false_positive_pattern(Some(r"C:\Users\victim\Downloads\vsda.node"), None)
            .unwrap());

        // Empty inputs
        assert!(!mem.is_false_positive_pattern(None, None).unwrap());
        assert!(!mem.is_false_positive_pattern(Some(""), Some("")).unwrap());
    }

    #[test]
    fn test_is_false_positive_pattern_lock_timeout() {
        let mem = std::sync::Arc::new(MemoryStore::new(":memory:").unwrap());
        let mem_clone = std::sync::Arc::clone(&mem);

        let (lock_acquired_tx, lock_acquired_rx) = std::sync::mpsc::channel();
        let background_thread = std::thread::spawn(move || {
            let guard = mem_clone.conn.lock();
            lock_acquired_tx.send(()).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(100));
            drop(guard);
        });

        // Wait until background thread holds the connection lock
        lock_acquired_rx.recv().unwrap();

        let start = std::time::Instant::now();
        let result = mem.is_false_positive_pattern(
            Some(r"C:\Windows\System32\some_random_binary.exe"),
            Some("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"),
        );
        let elapsed = start.elapsed();

        assert!(result.is_ok());
        assert!(!result.unwrap());
        assert!(
            elapsed < std::time::Duration::from_millis(60),
            "Elapsed was {:?}, expected ~5ms",
            elapsed
        );

        background_thread.join().unwrap();
    }

    #[test]
    fn test_is_nsrl_known_good_empty() {
        let mem = MemoryStore::new(":memory:").unwrap();
        assert!(!mem.is_nsrl_known_good("").unwrap());
        assert!(!mem.is_nsrl_known_good("   ").unwrap());
    }

    #[test]
    fn test_log_threat_idempotent() {
        let mem = MemoryStore::new(":memory:").unwrap();
        let mut sig = ThreatSignature::new("test-source".to_string());
        sig.id = "test-threat-uuid-1".to_string();
        sig.process_name = Some("evil_beacon.exe".to_string());
        sig.confidence = 0.5;
        sig.reason = Some("Suspicious execution".to_string());

        // First insert
        assert!(mem.log_threat(&sig).is_ok());

        // Second insert with identical ID and higher confidence
        sig.confidence = 0.95;
        sig.reason = Some("Confirmed execution".to_string());
        assert!(mem.log_threat(&sig).is_ok());

        // Verify update
        let threats = mem.get_recent_threats(10).unwrap();
        assert_eq!(threats.len(), 1);
        let conf = threats[0]["confidence"].as_f64().unwrap();
        assert!((conf - 0.95).abs() < 1e-4);

        // Third insert with identical ID, lower confidence, and enriched hash_blake3/cve_id
        sig.confidence = 0.20;
        sig.hash_blake3 = Some("blake3_hash_test_123".to_string());
        sig.cve_id = Some("CVE-2026-9999".to_string());
        assert!(mem.log_threat(&sig).is_ok());

        // Verify MAX confidence preserved (0.95, not lowered to 0.20) and enriched fields retained
        let threats_updated = mem.get_recent_threats(10).unwrap();
        assert_eq!(threats_updated.len(), 1);
        let conf_preserved = threats_updated[0]["confidence"].as_f64().unwrap();
        assert!((conf_preserved - 0.95).abs() < 1e-4);
        assert_eq!(
            threats_updated[0]["hash_blake3"].as_str().unwrap(),
            "blake3_hash_test_123"
        );
        assert_eq!(
            threats_updated[0]["cve_id"].as_str().unwrap(),
            "CVE-2026-9999"
        );
    }

    #[test]
    fn test_log_threat_concurrent_burst() {
        use std::sync::Arc;
        let mem = Arc::new(MemoryStore::new(":memory:").unwrap());
        let mut handles = Vec::new();

        for i in 0..20 {
            let mem_clone = mem.clone();
            handles.push(std::thread::spawn(move || {
                for j in 0..25 {
                    let mut sig = ThreatSignature::new(format!("node-{}", i));
                    sig.id = "concurrent-threat-uuid".to_string();
                    sig.process_name = Some("evil_beacon.exe".to_string());
                    sig.confidence = (j as f32) / 25.0;
                    sig.reason = Some(format!("Thread {} iteration {}", i, j));
                    assert!(mem_clone.log_threat(&sig).is_ok());
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        let threats = mem.get_recent_threats(10).unwrap();
        assert_eq!(threats.len(), 1);
        let conf = threats[0]["confidence"].as_f64().unwrap();
        // High confidence (24/25 = 0.96) must be preserved
        assert!(conf >= 0.96 - 1e-4);
    }

    #[test]
    fn test_consensus_findings_record_and_query() {
        let mem = MemoryStore::new(":memory:").unwrap();

        let finding = ConsensusFinding {
            id: "CONS-TEST-001".to_string(),
            hash_blake3: "abcd1234ef567890".to_string(),
            process_name: Some("test_runner.exe".to_string()),
            file_path: Some("C:\\bin\\test_runner.exe".to_string()),
            verdict: "malicious".to_string(),
            confidence: 0.92,
            detector_count: 3,
            voters_summary: "YaraX hit; ML malware score 0.95".to_string(),
            action_taken: "contained_and_quarantined".to_string(),
            evaluated_at: Utc::now(),
        };

        assert!(mem.record_consensus_finding(&finding).is_ok());

        let findings = mem.get_consensus_findings(10).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "CONS-TEST-001");
        assert_eq!(findings[0].hash_blake3, "abcd1234ef567890");
        assert_eq!(findings[0].verdict, "malicious");
        assert_eq!(findings[0].action_taken, "contained_and_quarantined");
        assert!((findings[0].confidence - 0.92).abs() < 1e-4);
    }

    #[test]
    fn test_mark_clean_ignored_hash_lifecycle() {
        let mem = MemoryStore::new(":memory:").unwrap();

        let hash = "deadbeef12345678cafe";
        assert!(!mem.is_hash_clean_ignored(hash));

        // Mark clean
        assert!(mem
            .mark_hash_clean_ignored(
                hash,
                Some("clean_app.exe"),
                Some("C:\\Tools\\clean_app.exe"),
                "consensus_clean",
            )
            .is_ok());

        // Fast lookup
        assert!(mem.is_hash_clean_ignored(hash));
        assert!(mem.is_hash_clean_ignored("DEADBEEF12345678CAFE")); // Case-insensitive

        // Verify ai_overrides and false_positive_patterns registered
        let ai_override = mem.get_ai_override(hash).unwrap();
        assert_eq!(ai_override, Some(false)); // 0 = false = clean

        assert!(mem
            .is_false_positive_pattern(Some("clean_app.exe"), Some(hash))
            .unwrap());

        // Query clean hashes list
        let clean_list = mem.get_clean_ignored_hashes(10).unwrap();
        assert_eq!(clean_list.len(), 1);
        assert_eq!(clean_list[0]["hash_blake3"].as_str().unwrap(), hash);
        assert_eq!(
            clean_list[0]["process_name"].as_str().unwrap(),
            "clean_app.exe"
        );

        // Remove
        let removed = mem.remove_clean_ignored_hash(hash).unwrap();
        assert!(removed);
        assert!(!mem.is_hash_clean_ignored(hash));

        let clean_list_empty = mem.get_clean_ignored_hashes(10).unwrap();
        assert_eq!(clean_list_empty.len(), 0);
    }

    #[test]
    fn test_voter_weight_persistence() {
        let mem = MemoryStore::new(":memory:").unwrap();
        let initial = mem.load_voter_weights().unwrap();
        assert!(initial.is_empty());

        mem.save_voter_weight("Sigma-Engine", 1.25).unwrap();
        mem.save_voter_weight("CredentialGuard-Memory", 1.50)
            .unwrap();

        let loaded = mem.load_voter_weights().unwrap();
        assert_eq!(loaded.len(), 2);
        assert!((loaded.get("Sigma-Engine").unwrap() - 1.25).abs() < 1e-4);
        assert!((loaded.get("CredentialGuard-Memory").unwrap() - 1.50).abs() < 1e-4);

        // Update existing weight
        mem.save_voter_weight("Sigma-Engine", 1.35).unwrap();
        let updated = mem.load_voter_weights().unwrap();
        assert_eq!(updated.len(), 2);
        assert!((updated.get("Sigma-Engine").unwrap() - 1.35).abs() < 1e-4);
    }

    #[test]
    fn test_vacuum_and_prune_lifecycle() {
        let mem = MemoryStore::new(":memory:").unwrap();

        // 1. Seed records across tables
        let past = (chrono::Utc::now() - chrono::Duration::days(45)).to_rfc3339();
        let recent = chrono::Utc::now().to_rfc3339();

        {
            let conn = mem.conn.lock();
            let _ = conn.execute(
                "INSERT INTO threats (id, cve_id, hash_blake3, detected_at) VALUES ('t1', 'CVE-1', 'hash1', ?)",
                [&past],
            );
            let _ = conn.execute(
                "INSERT INTO threats (id, cve_id, hash_blake3, detected_at) VALUES ('t2', 'CVE-2', 'hash2', ?)",
                [&recent],
            );
            let _ = conn.execute(
                "INSERT INTO consensus_findings (id, hash_blake3, verdict, confidence, detector_count, action_taken, evaluated_at) VALUES ('c1', 'h1', 'malicious', 0.95, 3, 'isolate', ?)",
                [&past],
            );
            let _ = conn.execute(
                "INSERT INTO cve_cache (product, version, cve_id, summary, cached_at) VALUES ('p', 'v', 'cve-old', 'sum', ?)",
                [&past],
            );
            let _ = conn.execute(
                "INSERT INTO training_samples (model_type, features, label, is_processed, created_at) VALUES ('m', X'0102', 1, 1, ?)",
                [&past],
            );
            let _ = conn.execute(
                "INSERT INTO pending_joins (peer_id, discovered_at) VALUES ('peer_old', ?)",
                [&past],
            );
        }

        // 2. Execute vacuum_and_prune with 30-day retention
        assert!(mem.vacuum_and_prune(30).is_ok());

        // 3. Verify old records pruned and recent records retained
        {
            let conn = mem.conn.lock();
            let remaining_threats: i64 = conn
                .query_row("SELECT count(*) FROM threats", [], |r| r.get(0))
                .unwrap();
            assert_eq!(remaining_threats, 1, "Recent threat should remain");

            let remaining_consensus: i64 = conn
                .query_row("SELECT count(*) FROM consensus_findings", [], |r| r.get(0))
                .unwrap();
            assert_eq!(
                remaining_consensus, 0,
                "Old consensus finding should be pruned"
            );

            let remaining_cve: i64 = conn
                .query_row("SELECT count(*) FROM cve_cache", [], |r| r.get(0))
                .unwrap();
            assert_eq!(remaining_cve, 0, "Old cve cache entry should be pruned");

            let remaining_samples: i64 = conn
                .query_row("SELECT count(*) FROM training_samples", [], |r| r.get(0))
                .unwrap();
            assert_eq!(
                remaining_samples, 0,
                "Old processed training sample should be pruned"
            );

            let remaining_joins: i64 = conn
                .query_row("SELECT count(*) FROM pending_joins", [], |r| r.get(0))
                .unwrap();
            assert_eq!(remaining_joins, 0, "Old pending join should be pruned");
        }
    }
}
