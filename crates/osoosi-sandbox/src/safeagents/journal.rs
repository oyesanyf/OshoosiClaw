//! Calls Journal Emitter (`~/.safeagents/calls.jsonl`)
//!
//! Provides thread-safe, lock-free, append-only telemetry logging
//! conforming to SafeAgents `docs/journal.md`.

use crate::safeagents::atif_scanner::AtifSignal;
use crate::safeagents::scrubber::OshoosiScrubber;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc::{channel, Receiver, Sender};

static JOURNAL_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// Structured 10-field telemetry record conforming to docs/journal.md.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CallsJournalRecord {
    pub id: u64,
    pub time: f64,
    pub verdict: String,
    pub tool: String,
    pub arguments: String,
    pub reason: Option<String>,
    pub signals: Vec<AtifSignal>,
    pub judge: Option<String>,
    pub model: String,
    pub task: String,
}

impl CallsJournalRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        verdict: &str,
        tool: &str,
        raw_arguments: &str,
        reason: Option<&str>,
        signals: Vec<AtifSignal>,
        judge: Option<&str>,
        model: &str,
        raw_task: &str,
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        let id = JOURNAL_SEQUENCE.fetch_add(1, Ordering::SeqCst);

        // Pre-scrub arguments and task to ensure no raw secrets or PII are written
        let scrubbed_args = OshoosiScrubber::scrub(raw_arguments);
        let scrubbed_task = OshoosiScrubber::scrub(raw_task);

        Self {
            id,
            time: now,
            verdict: verdict.to_string(),
            tool: tool.to_string(),
            arguments: scrubbed_args,
            reason: reason.map(|s| s.to_string()),
            signals,
            judge: judge.map(|s| s.to_string()),
            model: model.to_string(),
            task: scrubbed_task,
        }
    }

    pub fn to_jsonl(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

/// Calls Journal manager for appending telemetry records.
#[derive(Clone)]
pub struct CallsJournal {
    journal_path: PathBuf,
    sender: Option<Sender<CallsJournalRecord>>,
}

impl CallsJournal {
    /// Initializes journal pointing to default `~/.safeagents/calls.jsonl`.
    pub fn default_path() -> std::io::Result<Self> {
        let path = Self::resolve_default_path();
        Self::with_path(path)
    }

    /// Resolves the default OS user path for `~/.safeagents/calls.jsonl`.
    pub fn resolve_default_path() -> PathBuf {
        let home = dirs::home_dir()
            .or_else(|| std::env::var_os("USERPROFILE").map(PathBuf::from))
            .or_else(|| std::env::var_os("HOME").map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from("."));
        home.join(".safeagents").join("calls.jsonl")
    }

    /// Initializes journal pointing to an explicit file path.
    pub fn with_path(journal_path: PathBuf) -> std::io::Result<Self> {
        if let Some(parent) = journal_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Bounded MPSC channel for background emission
        let (tx, rx) = channel::<CallsJournalRecord>(1024);
        let path_clone = journal_path.clone();

        // If inside a tokio runtime, spawn background writer task
        if tokio::runtime::Handle::try_current().is_ok() {
            tokio::spawn(async move {
                Self::background_writer_loop(path_clone, rx).await;
            });
        }

        Ok(Self {
            journal_path,
            sender: Some(tx),
        })
    }

    pub fn journal_path(&self) -> &Path {
        &self.journal_path
    }

    /// Logs a blocked tool call record synchronously.
    pub fn log_blocked(
        &self,
        agent_id: &str,
        tool: &str,
        raw_arguments: &str,
        reason: &str,
        signals: &[AtifSignal],
    ) {
        let record = CallsJournalRecord::new(
            "blocked",
            tool,
            raw_arguments,
            Some(reason),
            signals.to_vec(),
            None,
            "oshoosi-sandbox",
            &format!("agent_id={}", agent_id),
        );
        self.emit_sync(record);
    }

    /// Logs a flagged tool call record synchronously.
    pub fn log_flagged(
        &self,
        agent_id: &str,
        tool: &str,
        raw_arguments: &str,
        signals: &[AtifSignal],
    ) {
        let record = CallsJournalRecord::new(
            "flagged",
            tool,
            raw_arguments,
            Some("suspicious signals flagged for review"),
            signals.to_vec(),
            None,
            "oshoosi-sandbox",
            &format!("agent_id={}", agent_id),
        );
        self.emit_sync(record);
    }

    /// Logs an allowed tool call record synchronously.
    pub fn log_allowed(&self, agent_id: &str, tool: &str, raw_arguments: &str) {
        let record = CallsJournalRecord::new(
            "allow",
            tool,
            raw_arguments,
            None,
            Vec::new(),
            None,
            "oshoosi-sandbox",
            &format!("agent_id={}", agent_id),
        );
        self.emit_sync(record);
    }

    /// Asynchronously emits a journal record (non-blocking).
    pub async fn emit(&self, record: CallsJournalRecord) {
        if let Some(ref sender) = self.sender {
            if sender.send(record.clone()).await.is_err() {
                self.write_record_sync(&record);
            }
        } else {
            self.write_record_sync(&record);
        }
    }

    /// Synchronously emits a journal record (safe in sync callers).
    pub fn emit_sync(&self, record: CallsJournalRecord) {
        if let Some(ref sender) = self.sender {
            if sender.try_send(record.clone()).is_err() {
                self.write_record_sync(&record);
            }
        } else {
            self.write_record_sync(&record);
        }
    }

    /// Direct synchronous file write with safe sharing mode.
    pub fn write_record_sync(&self, record: &CallsJournalRecord) {
        let line = record.to_jsonl();
        if line.is_empty() {
            return;
        }

        if let Ok(mut file) = Self::open_journal_file(&self.journal_path) {
            let _ = writeln!(file, "{}", line);
            let _ = file.flush();
        }
    }

    /// Background writer task draining records and writing to disk with safe sharing.
    async fn background_writer_loop(path: PathBuf, mut rx: Receiver<CallsJournalRecord>) {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        while let Some(record) = rx.recv().await {
            let line = record.to_jsonl();
            if line.is_empty() {
                continue;
            }

            if let Ok(mut file) = Self::open_journal_file(&path) {
                let _ = writeln!(file, "{}", line);
                let _ = file.flush();
            }
        }
    }

    /// Opens file with OS-safe sharing flags and strict permissions.
    pub fn open_journal_file(path: &Path) -> std::io::Result<File> {
        let mut opts = OpenOptions::new();
        opts.create(true).append(true).write(true);

        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            // FILE_SHARE_READ (1) | FILE_SHARE_WRITE (2) | FILE_SHARE_DELETE (4) = 7
            opts.share_mode(7);
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }

        opts.open(path)
    }
}
