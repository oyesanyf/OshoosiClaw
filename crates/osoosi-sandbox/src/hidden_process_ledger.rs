//! Hidden Process Ledger (`crates/osoosi-sandbox/src/hidden_process_ledger.rs`).
//!
//! `CREATE_NO_WINDOW` keeps helper subprocesses (`curl.exe`, `sqlite3`, `python`, `cargo`, `reg.exe`)
//! from flashing console windows — but it also hides them from the operator. Every hidden spawn made
//! through sandbox/agent code paths is recorded here (program, full argument vector, purpose, PID when
//! available, parent PID, timestamp) and appended to `logs/hidden_processes.jsonl`.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::io::Write;
use std::sync::{Mutex, OnceLock};

/// Maximum in-memory ledger entries (oldest evicted first; the JSONL file keeps the full history).
pub const MAX_HIDDEN_SPAWN_RECORDS: usize = 2048;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HiddenSpawnRecord {
    pub sequence: u64,
    pub timestamp_ms: u128,
    pub parent_pid: u32,
    /// Child PID; `None` when the spawn failed before a process existed.
    pub pid: Option<u32>,
    pub program: String,
    pub args: Vec<String>,
    pub purpose: String,
    pub spawn_ok: bool,
    pub error: Option<String>,
}

struct Ledger {
    next_seq: u64,
    records: VecDeque<HiddenSpawnRecord>,
}

fn ledger() -> &'static Mutex<Ledger> {
    static LEDGER: OnceLock<Mutex<Ledger>> = OnceLock::new();
    LEDGER.get_or_init(|| {
        Mutex::new(Ledger {
            next_seq: 1,
            records: VecDeque::with_capacity(256),
        })
    })
}

fn describe(cmd: &std::process::Command) -> (String, Vec<String>) {
    let program = cmd.get_program().to_string_lossy().into_owned();
    let args = cmd
        .get_args()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    (program, args)
}

/// Records one hidden spawn attempt and returns the stored record.
pub fn record_hidden_spawn(
    cmd: &std::process::Command,
    purpose: &str,
    pid: Option<u32>,
    error: Option<&std::io::Error>,
) -> HiddenSpawnRecord {
    let (program, args) = describe(cmd);
    let timestamp_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);

    let record = {
        let mut guard = ledger().lock().unwrap_or_else(|p| p.into_inner());
        let rec = HiddenSpawnRecord {
            sequence: guard.next_seq,
            timestamp_ms,
            parent_pid: std::process::id(),
            pid,
            program,
            args,
            purpose: purpose.to_string(),
            spawn_ok: error.is_none(),
            error: error.map(|e| e.to_string()),
        };
        guard.next_seq += 1;
        if guard.records.len() >= MAX_HIDDEN_SPAWN_RECORDS {
            guard.records.pop_front();
        }
        guard.records.push_back(rec.clone());
        rec
    };

    if let Ok(line) = serde_json::to_string(&record) {
        let _ = std::fs::create_dir_all("logs");
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open("logs/hidden_processes.jsonl")
        {
            let _ = writeln!(f, "{}", line);
        }
    }
    record
}

/// Snapshot of the in-memory ledger (oldest first).
pub fn list_hidden_spawns() -> Vec<HiddenSpawnRecord> {
    ledger()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .records
        .iter()
        .cloned()
        .collect()
}

/// Spawns `cmd` with `CREATE_NO_WINDOW` and records it in the ledger.
pub fn spawn_hidden(
    cmd: &mut std::process::Command,
    purpose: &str,
) -> std::io::Result<std::process::Child> {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(osoosi_types::CREATE_NO_WINDOW);
    }
    match cmd.spawn() {
        Ok(child) => {
            record_hidden_spawn(cmd, purpose, Some(child.id()), None);
            Ok(child)
        }
        Err(e) => {
            record_hidden_spawn(cmd, purpose, None, Some(&e));
            Err(e)
        }
    }
}

/// Runs `cmd` hidden to completion (`spawn` + `wait_with_output`), recording its PID.
pub fn output_hidden(
    cmd: &mut std::process::Command,
    purpose: &str,
) -> std::io::Result<std::process::Output> {
    cmd.stdin(std::process::Stdio::null());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    let child = spawn_hidden(cmd, purpose)?;
    child.wait_with_output()
}

/// Runs `cmd` hidden to completion and returns its exit status, recording its PID.
pub fn status_hidden(
    cmd: &mut std::process::Command,
    purpose: &str,
) -> std::io::Result<std::process::ExitStatus> {
    let mut child = spawn_hidden(cmd, purpose)?;
    child.wait()
}

/// Ledgered drop-in replacements for `Command::{spawn, output, status}` (always `CREATE_NO_WINDOW`).
pub trait LedgeredCommandExt {
    fn spawn_logged(&mut self, purpose: &str) -> std::io::Result<std::process::Child>;
    fn output_logged(&mut self, purpose: &str) -> std::io::Result<std::process::Output>;
    fn status_logged(&mut self, purpose: &str) -> std::io::Result<std::process::ExitStatus>;
}

impl LedgeredCommandExt for std::process::Command {
    fn spawn_logged(&mut self, purpose: &str) -> std::io::Result<std::process::Child> {
        spawn_hidden(self, purpose)
    }
    fn output_logged(&mut self, purpose: &str) -> std::io::Result<std::process::Output> {
        output_hidden(self, purpose)
    }
    fn status_logged(&mut self, purpose: &str) -> std::io::Result<std::process::ExitStatus> {
        status_hidden(self, purpose)
    }
}

/// Spawns a `tokio::process::Command` hidden and records it in the ledger.
pub fn spawn_hidden_tokio(
    cmd: &mut tokio::process::Command,
    purpose: &str,
) -> std::io::Result<tokio::process::Child> {
    #[cfg(windows)]
    {
        cmd.creation_flags(osoosi_types::CREATE_NO_WINDOW);
    }
    match cmd.spawn() {
        Ok(child) => {
            record_hidden_spawn(cmd.as_std(), purpose, child.id(), None);
            Ok(child)
        }
        Err(e) => {
            record_hidden_spawn(cmd.as_std(), purpose, None, Some(&e));
            Err(e)
        }
    }
}
