use rusqlite::{params, Connection, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Mutex;
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabeledSample {
    pub sentence: String,
    pub label: bool, // true = suspicious, false = benign
    pub confidence: f32,
}

pub struct FeedbackStore {
    conn: Mutex<Connection>,
}

impl FeedbackStore {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS feedback (
                id INTEGER PRIMARY KEY,
                sentence TEXT UNIQUE,
                label INTEGER,
                confidence REAL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )",
            [],
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn add_feedback(&self, sentence: &str, label: bool) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        info!(
            "Adding feedback: label={} for sentence \"{}\"",
            label, sentence
        );
        conn.execute(
            "INSERT INTO feedback (sentence, label, confidence)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(sentence) DO UPDATE SET label=?2, confidence=1.0",
            params![sentence, label as i32, 1.0],
        )?;
        Ok(())
    }

    pub fn get_feedback(&self, sentence: &str) -> Result<Option<bool>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT label FROM feedback WHERE sentence = ?1")?;
        let mut rows = stmt.query(params![sentence])?;
        if let Some(row) = rows.next()? {
            let label: i32 = row.get(0)?;
            Ok(Some(label != 0))
        } else {
            Ok(None)
        }
    }

    pub fn list_feedback(&self) -> Result<Vec<LabeledSample>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT sentence, label, confidence FROM feedback")?;
        let samples = stmt
            .query_map([], |row| {
                Ok(LabeledSample {
                    sentence: row.get(0)?,
                    label: row.get::<_, i32>(1)? != 0,
                    confidence: row.get(2)?,
                })
            })?
            .filter_map(|s| s.ok())
            .collect();
        Ok(samples)
    }
}
