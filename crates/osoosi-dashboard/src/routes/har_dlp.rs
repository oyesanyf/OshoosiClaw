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
        out.push_str(&format!("{} {} HTTP/1.1\nHost: {}\n", self.method, self.url, self.host));
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

fn host_of(url: &str) -> String {
    reqwest::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()))
        .unwrap_or_default()
}

/// Stable dedupe key: method + url + startedDateTime + blake3(body + params).
pub fn har_entry_key(method: &str, url: &str, started_at: &str, body: &str, params: &[(String, String)]) -> String {
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
pub fn extract_requests_from_har(doc: &Value, source_label: &str, kind: HarSourceKind) -> Vec<HarDlpRequest> {
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
        let Some(req) = entry.get("request") else { continue };
        let method = req
            .get("method")
            .and_then(|v| v.as_str())
            .unwrap_or("GET")
            .to_ascii_uppercase();
        let url = req.get("url").and_then(|v| v.as_str()).unwrap_or_default().to_string();
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
        let (body_text, mut truncated) = truncate_to_bytes(
            post.and_then(|p| p.get("text")).and_then(|v| v.as_str()).unwrap_or_default(),
            MAX_HAR_BODY_BYTES,
        );
        let mut params = Vec::new();
        let mut budget = MAX_HAR_BODY_BYTES;
        if let Some(arr) = post.and_then(|p| p.get("params")).and_then(|v| v.as_array()) {
            for p in arr.iter().take(4096) {
                let name = p.get("name").and_then(|v| v.as_str()).unwrap_or_default();
                let value = p.get("value").and_then(|v| v.as_str()).unwrap_or_default();
                if name.len() + value.len() > budget {
                    truncated = true;
                    break;
                }
                budget -= name.len() + value.len();
                params.push((name.to_string(), value.to_string()));
            }
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
    RECENT_BODY_REQUESTS.get_or_init(|| Mutex::new(VecDeque::with_capacity(MAX_RECENT_BODY_REQUESTS)))
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
pub fn enqueue_har_document(doc: &Value, source_label: &str, kind: HarSourceKind, reply: Option<ReplySender>) -> usize {
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
    let Ok(conn) = rusqlite::Connection::open(&path) else { return };
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
    let keys: Vec<String> = stmt
        .query_map([MAX_SEEN_KEYS as i64], |r| r.get::<_, String>(0))
        .map(|rows| rows.flatten().collect())
        .unwrap_or_default();
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
    let Ok(mut conn) = rusqlite::Connection::open(&path) else { return };
    let _ = conn.busy_timeout(Duration::from_millis(3000));
    let _ = conn.execute(
        "CREATE TABLE IF NOT EXISTS dlp_har_seen (entry_key TEXT PRIMARY KEY, seen_at TEXT NOT NULL)",
        [],
    );
    let now = chrono::Utc::now().to_rfc3339();
    if let Ok(tx) = conn.transaction() {
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
}

/// Inspects one request through the shared DLP decision path, persists it, raises alerts and
/// runs consensus-gated containment. Returns the recorded event (None for skipped duplicates).
fn inspect_request(req: &HarDlpRequest) -> Option<DlpInspectionEventRecord> {
    let payload = req.to_inspection_payload();
    let has_body = req.has_body();
    let options = DlpInspectOptions {
        simulated: false,
        // URL-only collector rows are recorded only when they carry sensitive data.
        skip_recording_allowed: !has_body,
    };
    let (_tier1, _proof, event) = {
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
    STAT_INSPECTED.fetch_add(1, Ordering::Relaxed);
    if has_body {
        STAT_WITH_BODY.fetch_add(1, Ordering::Relaxed);
        let mut ring = recent_bodies().lock();
        ring.push_front(req.clone());
        ring.truncate(MAX_RECENT_BODY_REQUESTS);
    }
    let mut event = event;
    if !event.allowed {
        STAT_BLOCKED.fetch_add(1, Ordering::Relaxed);
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
    if has_body || !event.allowed {
        if let Err(e) = persist_dlp_event(&event) {
            tracing::debug!("DLP event persistence failed: {}", e);
        }
    }
    Some(event)
}

fn dedupe_new<'a>(requests: &'a [HarDlpRequest]) -> (Vec<&'a HarDlpRequest>, Vec<String>) {
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

/// Processes a batch synchronously (dedupe → inspect). Used by the worker.
fn process_batch(requests: &[HarDlpRequest]) -> Vec<DlpInspectionEventRecord> {
    let (fresh, keys) = dedupe_new(requests);
    persist_seen_keys(&keys);
    fresh.into_iter().filter_map(inspect_request).collect()
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
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
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
        files.sort_by(|a, b| b.1.cmp(&a.1));
        for (path, mtime, len) in files.into_iter().take(MAX_FILES_PER_DIR) {
            if len == 0 || len > MAX_HAR_FILE_BYTES {
                continue;
            }
            if file_state.get(&path) == Some(&(mtime, len)) {
                continue;
            }
            let Ok(raw) = std::fs::read_to_string(&path) else { continue };
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
            out.extend(extract_requests_from_har(&doc, &label, HarSourceKind::HarFile));
        }
    }
    out
}

fn collector_url_only_requests(last_sweep: &mut u64) -> Vec<HarDlpRequest> {
    let cache = crate::routes::har::LIVE_HAR_CACHE
        .get_or_init(|| osoosi_core::parking_lot::RwLock::new(None))
        .read()
        .clone();
    let Some(payload) = cache else { return Vec::new() };
    let seq = payload.get("sweep_sequence").and_then(|v| v.as_u64()).unwrap_or(0);
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
        let source = e.get("source_file").and_then(|v| v.as_str()).unwrap_or_default();
        // HAR files / imports / sensor batches are inspected with their bodies by the body path.
        if !source.starts_with("browser_history:") {
            continue;
        }
        let url = e.get("url").and_then(|v| v.as_str()).unwrap_or_default().to_string();
        if url.is_empty() {
            continue;
        }
        let method = e.get("method").and_then(|v| v.as_str()).unwrap_or("GET").to_string();
        let started_at = e.get("started_at").and_then(|v| v.as_str()).unwrap_or_default().to_string();
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
    let mut file_state: HashMap<PathBuf, (SystemTime, u64)> = HashMap::new();
    let mut last_file_scan = Instant::now() - FILE_SCAN_INTERVAL;
    let mut last_sweep = 0u64;
    let mut backlog: VecDeque<HarDlpRequest> = VecDeque::new();
    loop {
        STAT_CYCLES.fetch_add(1, Ordering::Relaxed);
        // 1. Drain queued jobs (sensor + import). Reply jobs are processed in full.
        let jobs: Vec<Job> = {
            let (lock, cv) = queue();
            let mut q = lock.lock();
            if q.jobs.is_empty() && backlog.is_empty() {
                cv.wait_for(&mut q, Duration::from_millis(1000));
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
            let events = process_batch(&job.requests);
            if let Some(reply) = job.reply {
                let _ = reply.send(events);
            }
        }

        // 2. Watched-folder HAR files (bodies included).
        if last_file_scan.elapsed() >= FILE_SCAN_INTERVAL {
            last_file_scan = Instant::now();
            backlog.extend(scan_har_files(&mut file_state));
            // 3. URL-only collector rows (browser history).
            backlog.extend(collector_url_only_requests(&mut last_sweep));
        }
        if !backlog.is_empty() {
            let n = backlog.len().min(MAX_REQUESTS_PER_CYCLE);
            let batch: Vec<HarDlpRequest> = backlog.drain(..n).collect();
            let _ = process_batch(&batch);
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
        "worker_cycles": STAT_CYCLES.load(Ordering::Relaxed),
        "inspected_requests": STAT_INSPECTED.load(Ordering::Relaxed),
        "inspected_with_body": STAT_WITH_BODY.load(Ordering::Relaxed),
        "flagged_requests": STAT_BLOCKED.load(Ordering::Relaxed),
        "duplicates_skipped": STAT_DUPLICATES.load(Ordering::Relaxed),
        "dropped_queue_full": STAT_DROPPED.load(Ordering::Relaxed),
        "har_files_parsed": STAT_FILES_PARSED.load(Ordering::Relaxed),
        "queued_requests": queued,
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
        assert_eq!(reqs[0].params, vec![("ssn".to_string(), "123-45-6789".to_string())]);
        assert_eq!(reqs[0].channel(), "HAR_HTTP_BODY");
        assert_eq!(reqs[1].channel(), "HAR_TRAFFIC");
        assert_ne!(reqs[0].key, reqs[1].key);
        let payload = reqs[0].to_inspection_payload();
        assert!(payload.contains("ssn=123-45-6789"));
    }

    #[test]
    fn urlencoded_decoding_restores_grouped_card_numbers() {
        let pairs = decode_urlencoded_pairs("card=4532+0151+1283+0366&n=J%C3%BCrgen");
        assert_eq!(pairs[0], ("card".to_string(), "4532 0151 1283 0366".to_string()));
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
}
