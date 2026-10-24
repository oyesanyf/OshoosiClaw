//! Autonomous HAR → Two-Tier DLP pipeline.
//!
//! Every NEW HAR request — from browser-exported `.har` files in watched folders, the HAR import
//! endpoint (`POST /api/har/inspect`), the browser DLP sensor extension
//! (`POST /api/browser-sensor/har`), and URL-only collector rows (browser history) — is fed to
//! the DLP engine in the background, including `request.postData.text` / `postData.params`
//! whenever the source carries them. No manual "Scan HAR" click is required.
//!
//! The worker runs on a dedicated OS thread (never on the async executor), bounds per-cycle
//! work, deduplicates by a stable entry key (`method + url + startedDateTime + blake3(body)`)
//! persisted in SQLite so old entries are never re-inspected after a restart, and routes every
//! verdict through the same decision path as `/api/dlp/inspect` plus consensus-gated
//! containment (`routes::dlp_containment`).

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant, SystemTime};

use osoosi_core::parking_lot::{Condvar, Mutex};
use serde_json::{json, Value};

use crate::routes::dlp::{
    get_global_dlp_state, inspect_and_record_with_options, persist_dlp_event, DlpInspectOptions,
    DlpInspectionEventRecord,
};

/// Maximum request-body bytes inspected per HAR entry.
pub const MAX_HAR_BODY_BYTES: usize = 1024 * 1024;
/// Maximum HAR file size parsed from watched folders.
pub const MAX_HAR_FILE_BYTES: u64 = 64 * 1024 * 1024;
/// Upper bound on queued (not yet inspected) requests.
const MAX_QUEUED_REQUESTS: usize = 4096;
/// Requests inspected per worker cycle (bounded work, keeps lock hold times short).
const MAX_REQUESTS_PER_CYCLE: usize = 256;
/// Background (file / collector) requests inspected between queue checks.
const BACKLOG_CHUNK: usize = 16;
/// Dedupe memory (in-process); the SQLite table keeps the same window across restarts.
const MAX_SEEN_KEYS: usize = 50_000;
/// Body-bearing requests kept for on-demand sweeps (`POST /api/dlp/scan-har`).
const MAX_RECENT_BODY_REQUESTS: usize = 512;
const FILE_SCAN_INTERVAL: Duration = Duration::from_secs(2);
const MAX_FILES_PER_DIR: usize = 64;

/// Where a HAR request came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HarSourceKind {
    /// Real-time stream from the OshoosiClaw browser DLP sensor extension.
    BrowserExtension,
    /// Browser-exported `.har` file in a watched folder.
    HarFile,
    /// HAR uploaded through `POST /api/har/inspect`.
    HarImport,
    /// URL-only rows from the continuous HAR collector (browser history, persisted rows).
    HarCollector,
}

impl HarSourceKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            HarSourceKind::BrowserExtension => "BROWSER_EXTENSION",
            HarSourceKind::HarFile => "HAR_FILE",
            HarSourceKind::HarImport => "HAR_IMPORT",
            HarSourceKind::HarCollector => "HAR_COLLECTOR",
        }
    }
}

/// One HTTP request extracted from a HAR entry, ready for DLP inspection.
#[derive(Debug, Clone)]
pub struct HarDlpRequest {
    pub key: String,
    pub source_kind: HarSourceKind,
    pub source_label: String,
    pub actor: String,
    pub actor_pid: Option<u32>,
    pub actor_image_path: Option<String>,
    pub injection_indicators: Vec<String>,
    pub method: String,
    pub url: String,
    pub host: String,
    pub started_at: String,
    pub mime_type: String,
    pub body_text: String,
    pub params: Vec<(String, String)>,
    pub body_truncated: bool,
}

impl HarDlpRequest {
    /// DLP channel label recorded on the event.
    pub fn channel(&self) -> &'static str {
        let has_body = !self.body_text.is_empty() || !self.params.is_empty();
        match (self.source_kind, has_body) {
            (HarSourceKind::BrowserExtension, _) => "BROWSER_HTTP_POST",
            (_, true) => "HAR_HTTP_BODY",
            (_, false) => "HAR_TRAFFIC",
        }
    }

    /// Builds the text inspected by the DLP engine: request line, host, content type, the raw
    /// body, and decoded `name=value` form params (urlencoded `+`/`%XX` decoded) so grouped
    /// card numbers and SSNs are visible to the tokenizers.
    pub fn to_inspection_payload(&self) -> String {
        let mut out = String::with_capacity(self.body_text.len() + 256);
        out.push_str(&format!(
            "{} {} HTTP/1.1\nHost: {}\n",
            self.method, self.url, self.host
        ));
        if !self.mime_type.is_empty() {
            out.push_str(&format!("Content-Type: {}\n", self.mime_type));
        }
        out.push('\n');
        if !self.body_text.is_empty() {
            out.push_str(&self.body_text);
            out.push('\n');
            if self.mime_type.contains("x-www-form-urlencoded") && self.params.is_empty() {
                for (k, v) in decode_urlencoded_pairs(&self.body_text) {
                    out.push_str(&format!("{}={}\n", k, v));
                }
            }
        }
        for (k, v) in &self.params {
            out.push_str(&format!("{}={}\n", k, v));
        }
        out
    }

    fn has_body(&self) -> bool {
        !self.body_text.is_empty() || !self.params.is_empty()
    }
}

fn percent_decode_component(s: &str) -> String {
    let plus = s.replace('+', " ");
    osoosi_dp::OsoosiTwoTierDlpEngine::decode_url_percent(&plus).unwrap_or(plus)
}

/// Decodes `a=1&b=2` into pairs (best effort; malformed pairs keep their raw text).
pub fn decode_urlencoded_pairs(body: &str) -> Vec<(String, String)> {
    body.split('&')
        .filter(|p| !p.is_empty())
        .take(4096)
        .map(|pair| match pair.split_once('=') {
            Some((k, v)) => (percent_decode_component(k), percent_decode_component(v)),
            None => (percent_decode_component(pair), String::new()),
        })
        .collect()
}

fn truncate_to_bytes(s: &str, max: usize) -> (String, bool) {
    if s.len() <= max {
        return (s.to_string(), false);
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    (s[..end].to_string(), true)
}

pub fn host_of(url: &str) -> String {
    reqwest::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()))
        .unwrap_or_default()
}

/// Represents a local staged/uploaded file resolved from disk.
#[derive(Debug, Clone)]
pub struct ResolvedUploadedFile {
    pub resolved_path: PathBuf,
    pub filename: String,
    pub content: String,
    pub byte_size: usize,
}

/// Returns the standard candidate staging directories to search for browser upload files:
/// 1. User Downloads: %USERPROFILE%\Downloads or ~/Downloads
/// 2. User Desktop: %USERPROFILE%\Desktop or ~/Desktop
/// 3. User Documents: %USERPROFILE%\Documents or ~/Documents
/// 4. System/User Temp: std::env::temp_dir(), %LOCALAPPDATA%\Temp
/// 5. Windows Recent: %APPDATA%\Microsoft\Windows\Recent
/// 6. Workspace root and test directories: ., tests, tests/corpus
pub fn get_candidate_staging_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(home) = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME")) {
        let home_path = PathBuf::from(home);
        let dl = home_path.join("Downloads");
        if dl.is_dir() { dirs.push(dl); }
        let desk = home_path.join("Desktop");
        if desk.is_dir() { dirs.push(desk); }
        let docs = home_path.join("Documents");
        if docs.is_dir() { dirs.push(docs); }
    }
    let sys_temp = std::env::temp_dir();
    if sys_temp.is_dir() && !dirs.contains(&sys_temp) {
        dirs.push(sys_temp);
    }
    if let Ok(local_appdata) = std::env::var("LOCALAPPDATA") {
        let local_temp = PathBuf::from(local_appdata).join("Temp");
        if local_temp.is_dir() && !dirs.contains(&local_temp) {
            dirs.push(local_temp);
        }
    }
    if let Ok(appdata) = std::env::var("APPDATA") {
        let recent = PathBuf::from(appdata).join("Microsoft").join("Windows").join("Recent");
        if recent.is_dir() && !dirs.contains(&recent) {
            dirs.push(recent);
        }
    }
    dirs.push(PathBuf::from("."));
    dirs.push(PathBuf::from("tests"));
    dirs.push(PathBuf::from("tests").join("corpus"));
    dirs.push(PathBuf::from("crates").join("osoosi-dashboard").join("tests"));

    dirs.dedup();
    dirs
}

/// Given a candidate filename or path, and a destination URL, resolves the uploaded or staged file.
/// Capped at max 32 entries per directory to guarantee latency < 15ms.
pub fn resolve_local_uploaded_file(
    candidate_path_or_name: Option<&str>,
    destination_url: &str,
) -> Option<ResolvedUploadedFile> {
    const MAX_READ_BYTES: usize = 1024 * 1024; // 1 MB
    const DATA_EXTENSIONS: &[&str] = &[
        "txt", "csv", "json", "pdf", "xml", "docx", "tsv", "log", "dat", "hl7",
    ];

    // Case 1: Candidate path or filename provided
    if let Some(cand) = candidate_path_or_name {
        let trimmed = cand.trim();
        let cleaned = if let Some(inner) = trimmed.strip_prefix("[file upload:").and_then(|s| s.strip_suffix(']')) {
            inner.trim()
        } else {
            trimmed
        };
        if !cleaned.is_empty() {
            let direct_path = PathBuf::from(cleaned);
            if direct_path.is_file() {
                if let Ok(bytes) = std::fs::read(&direct_path) {
                    let len = bytes.len().min(MAX_READ_BYTES);
                    let content = String::from_utf8_lossy(&bytes[..len]).to_string();
                    let filename = direct_path.file_name().and_then(|n| n.to_str()).unwrap_or("file").to_string();
                    return Some(ResolvedUploadedFile {
                        resolved_path: direct_path,
                        filename,
                        content,
                        byte_size: bytes.len(),
                    });
                }
            }

            // Search by filename in candidate staging dirs
            let target_filename = direct_path.file_name().and_then(|n| n.to_str()).unwrap_or(cleaned);
            for dir in get_candidate_staging_dirs() {
                let Ok(rd) = std::fs::read_dir(&dir) else { continue; };
                for entry in rd.flatten().take(32) {
                    let p = entry.path();
                    if !p.is_file() { continue; }
                    let name = p.file_name().and_then(|n| n.to_str()).unwrap_or_default().to_string();
                    if name.eq_ignore_ascii_case(target_filename) {
                        if let Ok(bytes) = std::fs::read(&p) {
                            let len = bytes.len().min(MAX_READ_BYTES);
                            let content = String::from_utf8_lossy(&bytes[..len]).to_string();
                            return Some(ResolvedUploadedFile {
                                resolved_path: p,
                                filename: name,
                                content,
                                byte_size: bytes.len(),
                            });
                        }
                    }
                }
            }
        }
    }

    // Case 2: No filename provided, but destination URL targets dlptest.com or an upload sink.
    // Inspect the newest modified files (last 120s) matching data extensions.
    let is_upload_sink = destination_url.contains("dlptest.com")
        || destination_url.contains("/upload")
        || destination_url.contains("/post");

    if is_upload_sink {
        let now = SystemTime::now();
        let mut candidates: Vec<(PathBuf, SystemTime, u64)> = Vec::new();

        for dir in get_candidate_staging_dirs() {
            let Ok(rd) = std::fs::read_dir(&dir) else { continue; };
            for entry in rd.flatten().take(32) {
                let p = entry.path();
                if !p.is_file() { continue; }
                let ext = p.extension().and_then(|e| e.to_str()).unwrap_or_default().to_ascii_lowercase();
                if !DATA_EXTENSIONS.contains(&ext.as_str()) {
                    continue;
                }
                if let Ok(md) = entry.metadata() {
                    let mtime = md.modified().unwrap_or(SystemTime::UNIX_EPOCH);
                    if let Ok(dur) = now.duration_since(mtime) {
                        if dur.as_secs() <= 120 && md.len() > 0 && md.len() <= (MAX_READ_BYTES as u64 * 4) {
                            candidates.push((p, mtime, md.len()));
                        }
                    }
                }
            }
        }

        candidates.sort_by_key(|c| std::cmp::Reverse(c.1));
        if let Some((best_path, _, _)) = candidates.into_iter().next() {
            if let Ok(bytes) = std::fs::read(&best_path) {
                let len = bytes.len().min(MAX_READ_BYTES);
                let content = String::from_utf8_lossy(&bytes[..len]).to_string();
                let filename = best_path.file_name().and_then(|n| n.to_str()).unwrap_or("staged_upload").to_string();
                return Some(ResolvedUploadedFile {
                    resolved_path: best_path,
                    filename,
                    content,
                    byte_size: bytes.len(),
                });
            }
        }
    }

    None
}

/// Copies an active SQLite DB along with any companion `-wal`, `-shm`, or `-journal` files to a temp path
/// so reading never fails due to database locks while Chrome or Edge is running.
pub fn copy_sqlite_with_wal(src_db: &Path, temp_db: &Path) -> bool {
    if std::fs::copy(src_db, temp_db).is_err() {
        return false;
    }
    if let (Some(src_name), Some(temp_name)) = (
        src_db.file_name().and_then(|n| n.to_str()),
        temp_db.file_name().and_then(|n| n.to_str()),
    ) {
        for suffix in ["-wal", "-shm", "-journal"] {
            let src_companion = src_db.with_file_name(format!("{}{}", src_name, suffix));
            if src_companion.exists() {
                let temp_companion = temp_db.with_file_name(format!("{}{}", temp_name, suffix));
                let _ = std::fs::copy(&src_companion, &temp_companion);
            }
        }
    }
    true
}

/// Cleans up a temporary SQLite database and its companion files.
pub fn cleanup_sqlite_temp(temp_db: &Path) {
    let _ = std::fs::remove_file(temp_db);
    if let Some(temp_name) = temp_db.file_name().and_then(|n| n.to_str()) {
        for suffix in ["-wal", "-shm", "-journal"] {
            let temp_companion = temp_db.with_file_name(format!("{}{}", temp_name, suffix));
            let _ = std::fs::remove_file(temp_companion);
        }
    }
}

/// Discovers Chromium/Edge/Brave browser profile directories containing History files.
pub fn get_browser_profiles() -> Vec<(String, String, PathBuf)> {
    let mut profiles = Vec::new();
    let mut seen_dirs: HashSet<String> = HashSet::new();

    let mut user_local_appdata = Vec::new();
    if let Ok(local) = std::env::var("LOCALAPPDATA") {
        user_local_appdata.push(PathBuf::from(local));
    }
    if let Some(home) = std::env::var_os("USERPROFILE") {
        let p = PathBuf::from(home).join("AppData").join("Local");
        if p.is_dir() && !user_local_appdata.contains(&p) {
            user_local_appdata.push(p);
        }
    }
    if cfg!(windows) {
        let drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
        let users_dir = PathBuf::from(format!("{}\\Users", drive));
        if let Ok(rd) = std::fs::read_dir(&users_dir) {
            for entry in rd.flatten() {
                let local = entry.path().join("AppData").join("Local");
                if local.is_dir() && !user_local_appdata.contains(&local) {
                    user_local_appdata.push(local);
                }
            }
        }
    } else if let Some(home) = std::env::var_os("HOME") {
        user_local_appdata.push(PathBuf::from(home).join(".config"));
    }

    let mut check_browser_dir = |browser: &str, user_data: PathBuf| {
        if !user_data.is_dir() {
            return;
        }
        let default_dir = user_data.join("Default");
        if default_dir.join("History").is_file() {
            let key = default_dir.to_string_lossy().to_ascii_lowercase();
            if seen_dirs.insert(key) {
                profiles.push((browser.to_string(), "Default".to_string(), default_dir));
            }
        }
        if let Ok(rd) = std::fs::read_dir(&user_data) {
            for entry in rd.flatten() {
                let p = entry.path();
                if p.is_dir() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if (name.starts_with("Profile ") || name.starts_with("profile ") || name == "Guest Profile")
                        && p.join("History").is_file()
                    {
                        let key = p.to_string_lossy().to_ascii_lowercase();
                        if seen_dirs.insert(key) {
                            profiles.push((browser.to_string(), name, p));
                        }
                    }
                }
            }
        }
    };

    for local in user_local_appdata {
        check_browser_dir("Google Chrome", local.join("Google").join("Chrome").join("User Data"));
        check_browser_dir("Microsoft Edge", local.join("Microsoft").join("Edge").join("User Data"));
        check_browser_dir("Brave", local.join("BraveSoftware").join("Brave-Browser").join("User Data"));
    }

    profiles
}

/// Checks whether a DLP event signature (destination, scrubbed preview, or zk commitment)
/// was previously marked as a released false positive by the user in `database/dlp_released_allowlist.json`.
pub fn is_dlp_event_allowlisted(
    destination_sink: &str,
    scrubbed_preview: &str,
    zk_commitment: &str,
) -> bool {
    let path = PathBuf::from("database").join("dlp_released_allowlist.json");
    if !path.is_file() {
        return false;
    }
    let Ok(data) = std::fs::read_to_string(&path) else {
        return false;
    };
    let Ok(val) = serde_json::from_str::<Value>(&data) else {
        return false;
    };
    let Some(arr) = val.as_array() else {
        return false;
    };
    for item in arr {
        if let Some(s) = item.as_str() {
            if (!s.is_empty()) && (s == destination_sink || s == scrubbed_preview || s == zk_commitment) {
                return true;
            }
        } else if let Some(obj) = item.as_object() {
            if let Some(sink) = obj.get("destination_sink").and_then(|v| v.as_str()) {
                if !sink.is_empty() && sink == destination_sink {
                    return true;
                }
            }
            if let Some(zk) = obj.get("zk_commitment_hex").or_else(|| obj.get("zk_proof_commitment")).and_then(|v| v.as_str()) {
                if !zk.is_empty() && zk == zk_commitment {
                    return true;
                }
            }
            if let Some(prev) = obj.get("scrubbed_preview").and_then(|v| v.as_str()) {
                if !prev.is_empty() && prev == scrubbed_preview {
                    return true;
                }
            }
        }
    }
    false
}

/// Autonomous real-time polling of live browser activity, uploads, and sinks (Chrome & Edge history snapshots,
/// logs/har_stream.jsonl, and Windows DNS cache) visited within the last 120 seconds.
pub fn poll_live_browser_and_sink_activity() -> Vec<HarDlpRequest> {
    let mut out = Vec::new();

    // 1. Chrome, Edge, and Chromium browser profile snapshots
    for (browser, _profile_name, profile_dir) in get_browser_profiles() {
        let history_file = profile_dir.join("History");
        if !history_file.is_file() {
            continue;
        }
        let temp_name = format!(
            "osoosi_hist_snap_{}_{}.db",
            browser.replace([' ', '-'], "_"),
            uuid::Uuid::new_v4()
        );
        let temp_path = std::env::temp_dir().join(&temp_name);
        if copy_sqlite_with_wal(&history_file, &temp_path) {
            if let Ok(conn) = rusqlite::Connection::open_with_flags(
                &temp_path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            ) {
                let _ = conn.busy_timeout(Duration::from_millis(2000));
                let query = "SELECT url, COALESCE(title, ''), datetime(last_visit_time / 1000000 - 11644473600, 'unixepoch'), last_visit_time
                             FROM urls
                             WHERE (url LIKE '%dlptest.com%' OR url LIKE '%/http-post/%' OR url LIKE '%/https-post/%' OR url LIKE '%/upload%')
                             ORDER BY last_visit_time DESC LIMIT 20;";
                if let Ok(mut stmt) = conn.prepare(query) {
                    let now_system = SystemTime::now();
                    let current_chrom_micros = match now_system.duration_since(SystemTime::UNIX_EPOCH) {
                        Ok(dur) => (dur.as_secs() + 11644473600) * 1_000_000 + dur.subsec_micros() as u64,
                        Err(_) => 0,
                    };
                    if let Ok(rows) = stmt.query_map([], |row| {
                        Ok((
                            row.get::<_, String>(0).unwrap_or_default(),
                            row.get::<_, String>(1).unwrap_or_default(),
                            row.get::<_, String>(2).unwrap_or_default(),
                            row.get::<_, i64>(3).unwrap_or(0),
                        ))
                    }) {
                        for r in rows.flatten() {
                            let (url, _title, started_at, last_visit_chrom) = r;
                            if url.is_empty() {
                                continue;
                            }
                            let is_recent = if current_chrom_micros > 0 && last_visit_chrom > 0 {
                                let diff_micros = current_chrom_micros.saturating_sub(last_visit_chrom as u64);
                                diff_micros <= 120 * 1_000_000
                            } else {
                                true
                            };
                            if !is_recent {
                                continue;
                            }

                            let (body_text, params) = if let Some(resolved) = resolve_local_uploaded_file(None, &url) {
                                (
                                    format!(
                                        "--- UPLOADED FILE: {} (size: {} bytes) ---\n{}",
                                        resolved.resolved_path.display(),
                                        resolved.byte_size,
                                        resolved.content
                                    ),
                                    vec![("uploaded_file".to_string(), resolved.resolved_path.display().to_string())],
                                )
                            } else {
                                (String::new(), Vec::new())
                            };

                            let actor = normalize_actor(&browser);
                            let method = "POST".to_string();
                            let start_ts = if started_at.is_empty() {
                                chrono::Utc::now().to_rfc3339()
                            } else {
                                started_at
                            };
                            let key = har_entry_key(&method, &url, &start_ts, &body_text, &params);
                            out.push(HarDlpRequest {
                                key,
                                source_kind: HarSourceKind::HarCollector,
                                source_label: format!("browser_history:{}", browser.to_ascii_lowercase()),
                                actor,
                                actor_pid: None,
                                actor_image_path: None,
                                injection_indicators: Vec::new(),
                                host: host_of(&url),
                                method,
                                url,
                                started_at: start_ts,
                                mime_type: "multipart/form-data".to_string(),
                                body_text,
                                params,
                                body_truncated: false,
                            });
                        }
                    }
                }
            }
            cleanup_sqlite_temp(&temp_path);
        }
    }

    // 2. Also check logs/har_stream.jsonl if present
    let stream_path = PathBuf::from("logs").join("har_stream.jsonl");
    if stream_path.is_file() {
        if let Ok(file) = std::fs::File::open(&stream_path) {
            use std::io::{BufRead, BufReader};
            let reader = BufReader::new(file);
            for line in reader.lines().flatten().take(50) {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                if let Ok(entry) = serde_json::from_str::<Value>(trimmed) {
                    let url = entry.get("url").and_then(|v| v.as_str()).unwrap_or_default();
                    if url.contains("dlptest.com") || url.contains("/upload") || url.contains("/post") {
                        let method = entry.get("method").and_then(|v| v.as_str()).unwrap_or("POST");
                        let started_at = entry.get("started_at").and_then(|v| v.as_str()).unwrap_or_default();
                        let mut body_text = entry.get("body_text").and_then(|v| v.as_str()).unwrap_or_default().to_string();
                        let candidate_file = entry.get("file_name").or_else(|| entry.get("file_path")).and_then(|v| v.as_str());
                        let mut params = Vec::new();
                        if let Some(resolved) = resolve_local_uploaded_file(candidate_file, url) {
                            if !body_text.contains(&resolved.content) {
                                if !body_text.is_empty() {
                                    body_text.push('\n');
                                }
                                body_text.push_str(&format!(
                                    "--- UPLOADED FILE: {} (size: {} bytes) ---\n{}",
                                    resolved.resolved_path.display(),
                                    resolved.byte_size,
                                    resolved.content
                                ));
                            }
                            params.push(("uploaded_file".to_string(), resolved.resolved_path.display().to_string()));
                        }
                        let start_ts = if started_at.is_empty() {
                            chrono::Utc::now().to_rfc3339()
                        } else {
                            started_at.to_string()
                        };
                        let key = har_entry_key(method, url, &start_ts, &body_text, &params);
                        out.push(HarDlpRequest {
                            key,
                            source_kind: HarSourceKind::HarCollector,
                            source_label: "logs/har_stream.jsonl".to_string(),
                            actor: "chrome.exe".to_string(),
                            actor_pid: None,
                            actor_image_path: None,
                            injection_indicators: Vec::new(),
                            host: host_of(url),
                            method: method.to_string(),
                            url: url.to_string(),
                            started_at: start_ts,
                            mime_type: "multipart/form-data".to_string(),
                            body_text,
                            params,
                            body_truncated: false,
                        });
                    }
                }
            }
        }
    }

    // 3. Check Windows DNS cache for dlptest.com visits
    #[cfg(windows)]
    {
        if let Ok(output) = std::process::Command::new("ipconfig").arg("/displaydns").output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.contains("dlptest.com") {
                let test_url = "https://dlptest.com/https-post/";
                if let Some(resolved) = resolve_local_uploaded_file(None, test_url) {
                    let key = format!("dns_dlptest_{}", resolved.resolved_path.display());
                    let started_at = chrono::Utc::now().to_rfc3339();
                    out.push(HarDlpRequest {
                        key,
                        source_kind: HarSourceKind::HarCollector,
                        source_label: "windows_dns_cache:dlptest.com".to_string(),
                        actor: "chrome.exe".to_string(),
                        actor_pid: None,
                        actor_image_path: None,
                        injection_indicators: Vec::new(),
                        host: "dlptest.com".to_string(),
                        method: "POST".to_string(),
                        url: test_url.to_string(),
                        started_at,
                        mime_type: "multipart/form-data".to_string(),
                        body_text: format!(
                            "--- UPLOADED FILE: {} (size: {} bytes) ---\n{}",
                            resolved.resolved_path.display(),
                            resolved.byte_size,
                            resolved.content
                        ),
                        params: vec![("uploaded_file".to_string(), resolved.resolved_path.display().to_string())],
                        body_truncated: false,
                    });
                }
            }
        }
    }

    out
}

/// Stable dedupe key: method + url + startedDateTime + blake3(body + params).
pub fn har_entry_key(
    method: &str,
    url: &str,
    started_at: &str,
    body: &str,
    params: &[(String, String)],
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(body.as_bytes());
    for (k, v) in params {
        hasher.update(b"\x1f");
        hasher.update(k.as_bytes());
        hasher.update(b"=");
        hasher.update(v.as_bytes());
    }
    let body_digest = hasher.finalize().to_hex();
    blake3::hash(
        format!(
            "{}\x1e{}\x1e{}\x1e{}",
            method.to_ascii_uppercase(),
            url,
            started_at,
            body_digest
        )
        .as_bytes(),
    )
    .to_hex()
    .to_string()
}

fn normalize_actor(name: &str) -> String {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let lower = trimmed.to_ascii_lowercase();
    match lower.as_str() {
        "microsoft edge" | "edge" => "msedge.exe".to_string(),
        "google chrome" | "chrome" | "chromium" => "chrome.exe".to_string(),
        "firefox" | "mozilla firefox" => "firefox.exe".to_string(),
        "brave" => "brave.exe".to_string(),
        _ => trimmed.to_string(),
    }
}

/// Extracts inspectable requests (with bodies when present) from a W3C HAR 1.2 document.
pub fn extract_requests_from_har(
    doc: &Value,
    source_label: &str,
    kind: HarSourceKind,
) -> Vec<HarDlpRequest> {
    let log = doc.get("log").unwrap_or(doc);
    let Some(entries) = log.get("entries").and_then(|e| e.as_array()) else {
        return Vec::new();
    };
    let log_actor = log
        .get("browser")
        .and_then(|b| b.get("name"))
        .and_then(|v| v.as_str())
        .map(normalize_actor)
        .filter(|s| !s.is_empty())
        .or_else(|| {
            log.get("creator")
                .and_then(|c| c.get("name"))
                .and_then(|v| v.as_str())
                .map(normalize_actor)
                .filter(|s| !s.is_empty())
        });

    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        let Some(req) = entry.get("request") else {
            continue;
        };
        let method = req
            .get("method")
            .and_then(|v| v.as_str())
            .unwrap_or("GET")
            .to_ascii_uppercase();
        let url = req
            .get("url")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        if url.is_empty() {
            continue;
        }
        let started_at = entry
            .get("startedDateTime")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let post = req.get("postData");
        let mime_type = post
            .and_then(|p| p.get("mimeType"))
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let (mut body_text, mut truncated) = truncate_to_bytes(
            post.and_then(|p| p.get("text"))
                .and_then(|v| v.as_str())
                .unwrap_or_default(),
            MAX_HAR_BODY_BYTES,
        );
        let mut params = Vec::new();
        let mut budget = MAX_HAR_BODY_BYTES;
        let mut candidate_file: Option<String> = None;
        if let Some(arr) = post
            .and_then(|p| p.get("params"))
            .and_then(|v| v.as_array())
        {
            for p in arr.iter().take(4096) {
                let name = p.get("name").and_then(|v| v.as_str()).unwrap_or_default();
                let value = p.get("value").and_then(|v| v.as_str()).unwrap_or_default();
                if candidate_file.is_none() {
                    if let Some(fn_str) = p.get("fileName").or_else(|| p.get("filename")).and_then(|v| v.as_str()) {
                        if !fn_str.trim().is_empty() {
                            candidate_file = Some(fn_str.trim().to_string());
                        }
                    }
                }
                if name.len() + value.len() > budget {
                    truncated = true;
                    break;
                }
                budget -= name.len() + value.len();
                params.push((name.to_string(), value.to_string()));
            }
        }

        // Also check entry._oshoosi.uploaded_files
        if candidate_file.is_none() {
            if let Some(arr) = entry.get("_oshoosi").and_then(|m| m.get("uploaded_files")).and_then(|v| v.as_array()) {
                for f in arr {
                    if let Some(s) = f.as_str() {
                        if !s.trim().is_empty() {
                            candidate_file = Some(s.trim().to_string());
                            break;
                        }
                    }
                }
            }
        }

        // Also check requestBody.raw[i].file
        if candidate_file.is_none() {
            if let Some(raw_arr) = req.get("requestBody").and_then(|b| b.get("raw")).and_then(|v| v.as_array()) {
                for part in raw_arr {
                    if let Some(f) = part.get("file").and_then(|v| v.as_str()) {
                        if !f.trim().is_empty() {
                            candidate_file = Some(f.trim().to_string());
                            break;
                        }
                    }
                }
            }
        }

        // Also check body_text for "[file upload: ...]" or multipart 'filename="..."'
        if candidate_file.is_none() {
            if let Some(start) = body_text.find("[file upload:") {
                if let Some(end) = body_text[start..].find(']') {
                    let cand = body_text[start + 13..start + end].trim();
                    if !cand.is_empty() {
                        candidate_file = Some(cand.to_string());
                    }
                }
            }
        }
        if candidate_file.is_none() {
            if let Some(start) = body_text.find("filename=") {
                let rest = &body_text[start + 9..];
                let trimmed_rest = rest.trim_start_matches('"').trim_start_matches('\'');
                let end = trimmed_rest.find(['"', '\'', ';', '\r', '\n']).unwrap_or(trimmed_rest.len());
                let cand = trimmed_rest[..end].trim();
                if !cand.is_empty() {
                    candidate_file = Some(cand.to_string());
                }
            }
        }

        // Resolve candidate file from disk if present or if targeting dlptest.com / upload sink
        if let Some(resolved) = resolve_local_uploaded_file(candidate_file.as_deref(), &url) {
            if !body_text.contains(&resolved.content) {
                if !body_text.is_empty() {
                    body_text.push('\n');
                }
                body_text.push_str(&format!(
                    "--- UPLOADED FILE: {} (size: {} bytes) ---\n{}",
                    resolved.resolved_path.display(),
                    resolved.byte_size,
                    resolved.content
                ));
            }
            params.push(("uploaded_file".to_string(), resolved.resolved_path.display().to_string()));
        }
        let meta = entry.get("_oshoosi");
        let actor = meta
            .and_then(|m| m.get("browser"))
            .and_then(|v| v.as_str())
            .map(normalize_actor)
            .filter(|s| !s.is_empty())
            .or_else(|| log_actor.clone())
            .unwrap_or_else(|| match kind {
                HarSourceKind::HarFile => format!("har_file:{}", source_label),
                HarSourceKind::HarImport => format!("har_import:{}", source_label),
                _ => source_label.to_string(),
            });
        let actor_pid = meta
            .and_then(|m| m.get("pid"))
            .and_then(|v| v.as_u64())
            .and_then(|p| u32::try_from(p).ok());
        let actor_image_path = meta
            .and_then(|m| m.get("image_path"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let injection_indicators = meta
            .and_then(|m| m.get("injection_indicators"))
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(|s| s.to_string()))
                    .take(32)
                    .collect()
            })
            .unwrap_or_default();
        let key = har_entry_key(&method, &url, &started_at, &body_text, &params);
        out.push(HarDlpRequest {
            key,
            source_kind: kind,
            source_label: source_label.to_string(),
            actor,
            actor_pid,
            actor_image_path,
            injection_indicators,
            host: host_of(&url),
            method,
            url,
            started_at,
            mime_type,
            body_text,
            params,
            body_truncated: truncated,
        });
    }
    out
}

type ReplySender = tokio::sync::oneshot::Sender<Vec<DlpInspectionEventRecord>>;

struct Job {
    requests: Vec<HarDlpRequest>,
    reply: Option<ReplySender>,
}

#[derive(Default)]
struct PipelineQueue {
    jobs: VecDeque<Job>,
    queued_requests: usize,
}

struct SeenKeys {
    set: HashSet<String>,
    order: VecDeque<String>,
    loaded_from_db: bool,
}

impl SeenKeys {
    fn insert(&mut self, key: &str) -> bool {
        if self.set.contains(key) {
            return false;
        }
        self.set.insert(key.to_string());
        self.order.push_back(key.to_string());
        while self.order.len() > MAX_SEEN_KEYS {
            if let Some(old) = self.order.pop_front() {
                self.set.remove(&old);
            }
        }
        true
    }
}

static QUEUE: OnceLock<(Mutex<PipelineQueue>, Condvar)> = OnceLock::new();
static SEEN: OnceLock<Mutex<SeenKeys>> = OnceLock::new();
static RECENT_BODY_REQUESTS: OnceLock<Mutex<VecDeque<HarDlpRequest>>> = OnceLock::new();
static WATCH_DIRS: OnceLock<Mutex<Vec<PathBuf>>> = OnceLock::new();
static BACKEND: OnceLock<Arc<osoosi_core::EdrOrchestrator>> = OnceLock::new();
static STARTED: AtomicBool = AtomicBool::new(false);
static STAT_INSPECTED: AtomicU64 = AtomicU64::new(0);
static STAT_WITH_BODY: AtomicU64 = AtomicU64::new(0);
static STAT_BLOCKED: AtomicU64 = AtomicU64::new(0);
static STAT_DUPLICATES: AtomicU64 = AtomicU64::new(0);
static STAT_DROPPED: AtomicU64 = AtomicU64::new(0);
static STAT_FILES_PARSED: AtomicU64 = AtomicU64::new(0);
static STAT_CYCLES: AtomicU64 = AtomicU64::new(0);

fn queue() -> &'static (Mutex<PipelineQueue>, Condvar) {
    QUEUE.get_or_init(|| (Mutex::new(PipelineQueue::default()), Condvar::new()))
}

fn seen() -> &'static Mutex<SeenKeys> {
    SEEN.get_or_init(|| {
        Mutex::new(SeenKeys {
            set: HashSet::new(),
            order: VecDeque::new(),
            loaded_from_db: false,
        })
    })
}

fn recent_bodies() -> &'static Mutex<VecDeque<HarDlpRequest>> {
    RECENT_BODY_REQUESTS
        .get_or_init(|| Mutex::new(VecDeque::with_capacity(MAX_RECENT_BODY_REQUESTS)))
}

fn watch_dirs() -> &'static Mutex<Vec<PathBuf>> {
    WATCH_DIRS.get_or_init(|| Mutex::new(Vec::new()))
}

/// Registers an additional folder whose `.har` files are inspected autonomously.
pub fn register_har_watch_dir(dir: impl Into<PathBuf>) {
    let dir = dir.into();
    let mut dirs = watch_dirs().lock();
    if !dirs.contains(&dir) {
        dirs.push(dir);
    }
}

/// Queues extracted requests for inspection. When `reply` is set, the worker sends back the
/// recorded events for this batch once inspected (used by the browser sensor endpoint).
/// Returns the number of requests accepted.
pub fn enqueue_requests(requests: Vec<HarDlpRequest>, reply: Option<ReplySender>) -> usize {
    let (lock, cv) = queue();
    let mut q = lock.lock();
    let room = MAX_QUEUED_REQUESTS.saturating_sub(q.queued_requests);
    let mut requests = requests;
    if requests.len() > room {
        STAT_DROPPED.fetch_add((requests.len() - room) as u64, Ordering::Relaxed);
        requests.truncate(room);
    }
    let accepted = requests.len();
    q.queued_requests += accepted;
    q.jobs.push_back(Job { requests, reply });
    drop(q);
    cv.notify_one();
    accepted
}

/// Extracts and queues every request of a HAR document.
pub fn enqueue_har_document(
    doc: &Value,
    source_label: &str,
    kind: HarSourceKind,
    reply: Option<ReplySender>,
) -> usize {
    let requests = extract_requests_from_har(doc, source_label, kind);
    enqueue_requests(requests, reply)
}

fn dlp_db_path() -> PathBuf {
    PathBuf::from("database").join("osoosi.db")
}

fn load_seen_keys_from_db(seen: &mut SeenKeys) {
    if seen.loaded_from_db {
        return;
    }
    seen.loaded_from_db = true;
    let path = dlp_db_path();
    if !path.is_file() {
        return;
    }
    let Ok(conn) = rusqlite::Connection::open(&path) else {
        return;
    };
    let _ = conn.busy_timeout(Duration::from_millis(3000));
    let _ = conn.execute(
        "CREATE TABLE IF NOT EXISTS dlp_har_seen (entry_key TEXT PRIMARY KEY, seen_at TEXT NOT NULL)",
        [],
    );
    let Ok(mut stmt) =
        conn.prepare("SELECT entry_key FROM dlp_har_seen ORDER BY seen_at DESC LIMIT ?1")
    else {
        return;
    };
    let mut keys: Vec<String> = Vec::new();
    if let Ok(rows) = stmt.query_map([MAX_SEEN_KEYS as i64], |r| r.get::<_, String>(0)) {
        keys.extend(rows.flatten());
    }
    drop(stmt);
    for k in keys.into_iter().rev() {
        seen.insert(&k);
    }
}

fn persist_seen_keys(keys: &[String]) {
    if keys.is_empty() {
        return;
    }
    let path = dlp_db_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let Ok(mut conn) = rusqlite::Connection::open(&path) else {
        return;
    };
    let _ = conn.busy_timeout(Duration::from_millis(3000));
    let _ = conn.execute(
        "CREATE TABLE IF NOT EXISTS dlp_har_seen (entry_key TEXT PRIMARY KEY, seen_at TEXT NOT NULL)",
        [],
    );
    let now = chrono::Utc::now().to_rfc3339();
    let Ok(tx) = conn.transaction() else { return };
    for k in keys {
        let _ = tx.execute(
            "INSERT OR IGNORE INTO dlp_har_seen (entry_key, seen_at) VALUES (?1, ?2)",
            rusqlite::params![k, now],
        );
    }
    let _ = tx.execute(
        "DELETE FROM dlp_har_seen WHERE entry_key NOT IN (SELECT entry_key FROM dlp_har_seen ORDER BY seen_at DESC LIMIT ?1)",
        [MAX_SEEN_KEYS as i64],
    );
    let _ = tx.commit();
}

/// Gets the global EDR orchestrator backend if registered.
pub fn get_backend() -> Option<Arc<osoosi_core::EdrOrchestrator>> {
    BACKEND.get().cloned()
}

/// Inspects one request through the shared DLP decision path and records the event.
fn inspect_only(req: &HarDlpRequest) -> DlpInspectionEventRecord {
    let payload = req.to_inspection_payload();
    let has_body = req.has_body();
    let options = DlpInspectOptions {
        simulated: false,
        // URL-only collector rows are recorded only when they carry sensitive data.
        skip_recording_allowed: !has_body,
    };
    let (_tier1, _proof, mut event) = {
        let mut state = get_global_dlp_state().write();
        inspect_and_record_with_options(
            &mut state,
            &req.actor,
            &req.url,
            req.channel(),
            &payload,
            req.source_kind.as_str(),
            options,
        )
    };
    if !event.allowed
        && is_dlp_event_allowlisted(
            &event.destination_sink,
            &event.scrubbed_preview,
            &event.zk_proof_commitment,
        )
    {
        event.allowed = true;
        event.authorization_decision = "ALLOW (USER_RELEASED)".to_string();
        event.dlp_response = "RELEASED_BY_USER".to_string();
        event.rationale = format!(
            "[DLP-Released]: False-positive released by user allowlist ({})",
            event.destination_sink
        );
    }
    STAT_INSPECTED.fetch_add(1, Ordering::Relaxed);
    if has_body {
        STAT_WITH_BODY.fetch_add(1, Ordering::Relaxed);
        let mut ring = recent_bodies().lock();
        ring.push_front(req.clone());
        ring.truncate(MAX_RECENT_BODY_REQUESTS);
    }
    if !event.allowed {
        STAT_BLOCKED.fetch_add(1, Ordering::Relaxed);
    }
    event
}

/// Raises alerts, runs consensus-gated containment for flagged events, and persists the event.
fn post_process(
    req: &HarDlpRequest,
    mut event: DlpInspectionEventRecord,
) -> DlpInspectionEventRecord {
    if !event.allowed {
        let ctx = crate::routes::dlp_containment::ActorContext {
            actor: req.actor.clone(),
            pid: req.actor_pid,
            image_path: req.actor_image_path.clone(),
            destination_url: req.url.clone(),
            destination_host: req.host.clone(),
            injection_indicators: req.injection_indicators.clone(),
        };
        let outcome = crate::routes::dlp_containment::global_containment_engine()
            .evaluate_and_respond(&event, &ctx, BACKEND.get().cloned());
        let outcome_json = serde_json::to_value(&outcome).unwrap_or(Value::Null);
        event.containment = Some(outcome_json.clone());
        let mut state = get_global_dlp_state().write();
        crate::routes::dlp::attach_containment_to_event(&mut state, &event.id, outcome_json);
    }
    if req.has_body() || !event.allowed {
        if let Err(e) = persist_dlp_event(&event) {
            tracing::debug!("DLP event persistence failed: {}", e);
        }
    }
    event
}
fn dedupe_new(requests: &[HarDlpRequest]) -> (Vec<&HarDlpRequest>, Vec<String>) {
    let mut s = seen().lock();
    load_seen_keys_from_db(&mut s);
    let mut fresh = Vec::new();
    let mut keys = Vec::new();
    for r in requests {
        if s.insert(&r.key) {
            keys.push(r.key.clone());
            fresh.push(r);
        } else {
            STAT_DUPLICATES.fetch_add(1, Ordering::Relaxed);
        }
    }
    (fresh, keys)
}

/// Processes a batch on the worker: dedupe → inspect → (reply with verdicts) → containment and
/// persistence. Verdicts are sent before containment so the sensor endpoint stays fast; the
/// containment outcome is attached to the recorded dashboard event afterwards.
fn process_batch(requests: &[HarDlpRequest], reply: Option<ReplySender>) {
    let (fresh, keys) = dedupe_new(requests);
    let inspected: Vec<(&HarDlpRequest, DlpInspectionEventRecord)> =
        fresh.into_iter().map(|r| (r, inspect_only(r))).collect();
    if let Some(reply) = reply {
        let _ = reply.send(inspected.iter().map(|(_, e)| e.clone()).collect());
    }
    persist_seen_keys(&keys);
    for (req, event) in inspected {
        let _ = post_process(req, event);
    }
}

fn default_watch_dirs() -> Vec<PathBuf> {
    let mut dirs = vec![PathBuf::from("."), PathBuf::from("logs").join("har_inbox")];
    if let Ok(extra) = std::env::var("OSOOSI_HAR_WATCH_DIRS") {
        for d in std::env::split_paths(&extra) {
            if !d.as_os_str().is_empty() {
                dirs.push(d);
            }
        }
    }
    // Per-user Downloads folders (same sources the HAR collector reads).
    let users_roots: Vec<PathBuf> = if cfg!(windows) {
        let drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
        vec![PathBuf::from(format!("{}\\Users", drive))]
    } else {
        vec![PathBuf::from("/home"), PathBuf::from("/Users")]
    };
    for root in users_roots {
        if let Ok(rd) = std::fs::read_dir(&root) {
            for e in rd.flatten() {
                let dl = e.path().join("Downloads");
                if dl.is_dir() {
                    dirs.push(dl);
                }
            }
        }
    }
    if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
        let dl = PathBuf::from(home).join("Downloads");
        if dl.is_dir() && !dirs.contains(&dl) {
            dirs.push(dl);
        }
    }
    dirs.extend(watch_dirs().lock().iter().cloned());
    dirs.sort();
    dirs.dedup();
    dirs
}

fn scan_har_files(file_state: &mut HashMap<PathBuf, (SystemTime, u64)>) -> Vec<HarDlpRequest> {
    let mut out = Vec::new();
    for dir in default_watch_dirs() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut files: Vec<(PathBuf, SystemTime, u64)> = rd
            .flatten()
            .filter_map(|e| {
                let p = e.path();
                let is_har = p
                    .extension()
                    .map(|x| x.eq_ignore_ascii_case("har"))
                    .unwrap_or(false);
                if !is_har {
                    return None;
                }
                let md = std::fs::symlink_metadata(&p).ok()?;
                if !md.is_file() {
                    return None;
                }
                Some((p, md.modified().unwrap_or(SystemTime::UNIX_EPOCH), md.len()))
            })
            .collect();
        files.sort_by_key(|f| std::cmp::Reverse(f.1));
        for (path, mtime, len) in files.into_iter().take(MAX_FILES_PER_DIR) {
            if len == 0 || len > MAX_HAR_FILE_BYTES {
                continue;
            }
            if file_state.get(&path) == Some(&(mtime, len)) {
                continue;
            }
            let Ok(raw) = std::fs::read_to_string(&path) else {
                continue;
            };
            let Ok(doc) = serde_json::from_str::<Value>(&raw) else {
                // Possibly still being written; retry on the next cycle.
                continue;
            };
            file_state.insert(path.clone(), (mtime, len));
            STAT_FILES_PARSED.fetch_add(1, Ordering::Relaxed);
            let label = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("archive.har")
                .to_string();
            out.extend(extract_requests_from_har(
                &doc,
                &label,
                HarSourceKind::HarFile,
            ));
        }
    }
    out
}

fn collector_url_only_requests(last_sweep: &mut u64) -> Vec<HarDlpRequest> {
    let cache = crate::routes::har::LIVE_HAR_CACHE
        .get_or_init(|| osoosi_core::parking_lot::RwLock::new(None))
        .read()
        .clone();
    let Some(payload) = cache else {
        return Vec::new();
    };
    let seq = payload
        .get("sweep_sequence")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    if seq == *last_sweep {
        return Vec::new();
    }
    *last_sweep = seq;
    let entries = payload
        .get("entries")
        .and_then(|e| e.as_array())
        .cloned()
        .unwrap_or_default();
    let mut out = Vec::new();
    for e in entries {
        let source = e
            .get("source_file")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        // HAR files / imports / sensor batches are inspected with their bodies by the body path.
        if !source.starts_with("browser_history:") {
            continue;
        }
        let url = e
            .get("url")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        if url.is_empty() {
            continue;
        }
        let method = e
            .get("method")
            .and_then(|v| v.as_str())
            .unwrap_or("GET")
            .to_string();
        let started_at = e
            .get("started_at")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let key = format!("url|{}", har_entry_key(&method, &url, &started_at, "", &[]));
        out.push(HarDlpRequest {
            key,
            source_kind: HarSourceKind::HarCollector,
            source_label: source.to_string(),
            actor: normalize_actor(source.trim_start_matches("browser_history:")),
            actor_pid: None,
            actor_image_path: None,
            injection_indicators: Vec::new(),
            host: host_of(&url),
            method,
            url,
            started_at,
            mime_type: String::new(),
            body_text: String::new(),
            params: Vec::new(),
            body_truncated: false,
        });
    }
    out
}

fn worker_loop() {
    // Build the REA engine once up front so the first inspected request is not delayed by it.
    drop(osoosi_core::rea::global_rea_engine());
    load_seen_keys_from_db(&mut seen().lock());
    let mut file_state: HashMap<PathBuf, (SystemTime, u64)> = HashMap::new();
    let mut last_file_scan = Instant::now() - FILE_SCAN_INTERVAL;
    let mut last_browser_poll = Instant::now() - Duration::from_secs(3);
    let mut last_sweep = 0u64;
    let mut backlog: VecDeque<HarDlpRequest> = VecDeque::new();
    loop {
        STAT_CYCLES.fetch_add(1, Ordering::Relaxed);
        // 1. Drain queued jobs (sensor + import). Reply jobs are processed in full.
        let jobs: Vec<Job> = {
            let (lock, cv) = queue();
            let mut q = lock.lock();
            if q.jobs.is_empty() && backlog.is_empty() {
                cv.wait_for(&mut q, Duration::from_millis(500));
            }
            let mut taken = Vec::new();
            let mut budget = MAX_REQUESTS_PER_CYCLE;
            while let Some(job) = q.jobs.pop_front() {
                q.queued_requests = q.queued_requests.saturating_sub(job.requests.len());
                budget = budget.saturating_sub(job.requests.len());
                taken.push(job);
                if budget == 0 {
                    break;
                }
            }
            taken
        };
        for job in jobs {
            process_batch(&job.requests, job.reply);
        }

        // 2. Watched-folder HAR files (bodies included).
        if last_file_scan.elapsed() >= FILE_SCAN_INTERVAL {
            last_file_scan = Instant::now();
            backlog.extend(scan_har_files(&mut file_state));
            // 3. URL-only collector rows (browser history).
            backlog.extend(collector_url_only_requests(&mut last_sweep));
        }

        // 4. Autonomous Real-Time browser visits and upload sink polling (every 3 seconds)
        if last_browser_poll.elapsed() >= Duration::from_secs(3) {
            last_browser_poll = Instant::now();
            backlog.extend(poll_live_browser_and_sink_activity());
        }

        // Background backlog is processed in small chunks so queued sensor/import jobs (which
        // may be awaiting inline verdicts) are picked up between chunks.
        if !backlog.is_empty() {
            let n = backlog.len().min(BACKLOG_CHUNK);
            let batch: Vec<HarDlpRequest> = backlog.drain(..n).collect();
            process_batch(&batch, None);
        }
    }
}

/// Starts the autonomous HAR→DLP worker once per process. `backend` (when present) receives
/// alerts and consensus findings and enables containment execution.
pub fn ensure_har_dlp_pipeline_started(backend: Option<Arc<osoosi_core::EdrOrchestrator>>) {
    if let Some(b) = backend {
        let _ = BACKEND.set(b);
    }
    if STARTED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
    {
        let _ = std::fs::create_dir_all(Path::new("logs").join("har_inbox"));
        if let Err(e) = std::thread::Builder::new()
            .name("osoosi-har-dlp".to_string())
            .spawn(worker_loop)
        {
            STARTED.store(false, Ordering::SeqCst);
            tracing::error!("failed to start autonomous HAR→DLP pipeline: {}", e);
        }
    }
}

/// Most recent requests for an on-demand sweep: body-bearing requests first, then URL-only rows.
pub fn recent_requests_for_sweep(limit: usize) -> Vec<HarDlpRequest> {
    let mut out: Vec<HarDlpRequest> = recent_bodies().lock().iter().take(limit).cloned().collect();
    if out.len() < limit {
        let mut seq = u64::MAX;
        for r in collector_url_only_requests(&mut seq) {
            if out.len() >= limit {
                break;
            }
            out.push(r);
        }
    }
    out
}

/// Pipeline health and counters for `/api/dlp/status`.
pub fn pipeline_status() -> Value {
    let queued = queue().0.lock().queued_requests;
    json!({
        "running": STARTED.load(Ordering::SeqCst),
        "autonomous_poll_interval_secs": 3,
        "worker_cycles": STAT_CYCLES.load(Ordering::Relaxed),
        "inspected_requests": STAT_INSPECTED.load(Ordering::Relaxed),
        "inspected_with_body": STAT_WITH_BODY.load(Ordering::Relaxed),
        "flagged_requests": STAT_BLOCKED.load(Ordering::Relaxed),
        "duplicates_skipped": STAT_DUPLICATES.load(Ordering::Relaxed),
        "dropped_queue_full": STAT_DROPPED.load(Ordering::Relaxed),
        "har_files_parsed": STAT_FILES_PARSED.load(Ordering::Relaxed),
        "queued_requests": queued,
        "candidate_staging_dirs": get_candidate_staging_dirs().iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
        "watch_dirs": default_watch_dirs().iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
        "sources": ["BROWSER_EXTENSION", "HAR_FILE", "HAR_IMPORT", "HAR_COLLECTOR"],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_post_bodies_params_and_actor() {
        let doc = json!({"log": {"version": "1.2", "browser": {"name": "Microsoft Edge"}, "entries": [
            {"startedDateTime": "2026-10-24T06:00:00.000Z", "request": {"method": "post", "url": "https://dlptest.com/http-post/",
              "postData": {"mimeType": "application/x-www-form-urlencoded", "text": "ssn=123-45-6789&card=4532+0151+1283+0366",
                           "params": [{"name": "ssn", "value": "123-45-6789"}]}}, "response": {"status": 200}},
            {"startedDateTime": "2026-10-24T06:00:01.000Z", "request": {"method": "GET", "url": "https://example.org/"}}
        ]}});
        let reqs = extract_requests_from_har(&doc, "a.har", HarSourceKind::HarFile);
        assert_eq!(reqs.len(), 2);
        assert_eq!(reqs[0].method, "POST");
        assert_eq!(reqs[0].actor, "msedge.exe");
        assert_eq!(reqs[0].host, "dlptest.com");
        assert_eq!(
            reqs[0].params,
            vec![("ssn".to_string(), "123-45-6789".to_string())]
        );
        assert_eq!(reqs[0].channel(), "HAR_HTTP_BODY");
        assert_eq!(reqs[1].channel(), "HAR_TRAFFIC");
        assert_ne!(reqs[0].key, reqs[1].key);
        let payload = reqs[0].to_inspection_payload();
        assert!(payload.contains("ssn=123-45-6789"));
    }

    #[test]
    fn urlencoded_decoding_restores_grouped_card_numbers() {
        let pairs = decode_urlencoded_pairs("card=4532+0151+1283+0366&n=J%C3%BCrgen");
        assert_eq!(
            pairs[0],
            ("card".to_string(), "4532 0151 1283 0366".to_string())
        );
        assert_eq!(pairs[1].1, "Jürgen");
    }

    #[test]
    fn entry_key_is_stable_and_body_sensitive() {
        let a = har_entry_key("POST", "https://x/", "t", "a=1", &[]);
        let b = har_entry_key("post", "https://x/", "t", "a=1", &[]);
        let c = har_entry_key("POST", "https://x/", "t", "a=2", &[]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_resolve_local_uploaded_file_direct_and_search() {
        let temp_dir = std::env::temp_dir();
        let fname = format!("test_patient_phi_{}.csv", uuid::Uuid::new_v4());
        let file_path = temp_dir.join(&fname);
        let sample_phi = "patient_id,name,dob,ssn,icd10\nPT-1092,Alice Johnson,1980-05-14,999-88-7777,E11.9\n";
        std::fs::write(&file_path, sample_phi).expect("write temp phi file");

        // 1. Direct absolute path resolution
        let res1 = resolve_local_uploaded_file(Some(file_path.to_str().unwrap()), "https://dlptest.com/https-post/");
        assert!(res1.is_some(), "direct path should resolve");
        let r1 = res1.unwrap();
        assert!(r1.content.contains("999-88-7777"));
        assert_eq!(r1.byte_size, sample_phi.len());

        // 2. Basename resolution searching candidate dirs
        let res2 = resolve_local_uploaded_file(Some(&fname), "https://dlptest.com/https-post/");
        assert!(res2.is_some(), "filename should resolve in staging dirs");
        let r2 = res2.unwrap();
        assert!(r2.content.contains("Alice Johnson"));

        // 3. Bracketed '[file upload: ...]' resolution
        let bracketed = format!("[file upload: {}]", fname);
        let res3 = resolve_local_uploaded_file(Some(&bracketed), "https://dlptest.com/https-post/");
        assert!(res3.is_some(), "bracketed note should resolve");

        // 4. URL-only resolution for dlptest.com (picks newest file in staging dir)
        let res4 = resolve_local_uploaded_file(None, "https://dlptest.com/https-post/");
        assert!(res4.is_some(), "dlptest.com without filename should pick newest data file");

        let _ = std::fs::remove_file(file_path);
    }

    #[test]
    fn test_extract_requests_with_file_upload_metadata() {
        let temp_dir = std::env::temp_dir();
        let fname = format!("test_discharge_{}.csv", uuid::Uuid::new_v4());
        let file_path = temp_dir.join(&fname);
        let sample_content = "patient_mrn,diagnosis\nMRN-882194,Hypertension ICD10-I10\n";
        std::fs::write(&file_path, sample_content).expect("write sample content");

        let doc = json!({
            "log": {
                "version": "1.2",
                "entries": [
                    {
                        "startedDateTime": "2026-10-24T12:00:00.000Z",
                        "request": {
                            "method": "POST",
                            "url": "https://dlptest.com/https-post/",
                            "postData": {
                                "mimeType": "multipart/form-data",
                                "text": format!("[file upload: {}]", fname),
                                "params": [{"name": "file", "value": "", "fileName": fname}]
                            }
                        },
                        "_oshoosi": {
                            "browser": "Google Chrome",
                            "uploaded_files": [fname.clone()]
                        }
                    }
                ]
            }
        });

        let reqs = extract_requests_from_har(&doc, "browser_extension", HarSourceKind::BrowserExtension);
        assert_eq!(reqs.len(), 1);
        let r = &reqs[0];
        assert_eq!(r.actor, "chrome.exe");
        assert_eq!(r.channel(), "BROWSER_HTTP_POST");
        let payload = r.to_inspection_payload();
        assert!(payload.contains("MRN-882194"), "payload must contain resolved file content");

        let _ = std::fs::remove_file(file_path);
    }

    #[test]
    fn test_is_dlp_event_allowlisted() {
        // When allowlist file does not exist or empty
        assert!(!is_dlp_event_allowlisted("https://dlptest.com/https-post/", "preview", "zk-commit-123"));
    }
}
