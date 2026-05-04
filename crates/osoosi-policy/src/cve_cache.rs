use rusqlite::{params, Connection};
use std::path::Path;
use osoosi_types::Kev;
use tracing::{info, warn};

pub struct CveCache {
    conn: Connection,
}

impl CveCache {
    pub fn new(db_path: &Path) -> anyhow::Result<Self> {
        let conn = Connection::open(db_path)?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS nvd_cache (
                product TEXT,
                version TEXT,
                cve_id TEXT,
                summary TEXT,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (product, version, cve_id)
            )",
            [],
        )?;
        Ok(Self { conn })
    }

    pub fn insert_cves(&self, product: &str, version: &str, cves: &[Kev]) -> anyhow::Result<()> {
        for cve in cves {
            self.conn.execute(
                "INSERT OR REPLACE INTO nvd_cache (product, version, cve_id, summary) VALUES (?1, ?2, ?3, ?4)",
                params![product, version, cve.cve_id, cve.vulnerability_name],
            )?;
        }
        Ok(())
    }

    pub fn get_cves(&self, product: &str, version: &str) -> anyhow::Result<Vec<(String, String)>> {
        let mut stmt = self.conn.prepare(
            "SELECT cve_id, summary FROM nvd_cache WHERE product = ?1 AND (version = ?2 OR version = 'any')"
        )?;
        let rows = stmt.query_map(params![product, version], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }

    pub fn bulk_import(&self, kevs: &[Kev]) -> anyhow::Result<()> {
        info!("[CveCache] Bulk importing {} records into local cache...", kevs.len());
        for kev in kevs {
            self.conn.execute(
                "INSERT OR REPLACE INTO nvd_cache (product, version, cve_id, summary) VALUES (?1, 'any', ?2, ?3)",
                params![kev.product, kev.cve_id, kev.vulnerability_name],
            )?;
        }
        Ok(())
    }
}
