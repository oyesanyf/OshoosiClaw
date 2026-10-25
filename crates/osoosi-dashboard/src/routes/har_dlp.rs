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
    get_global_dlp_state, persist_dlp_event, DlpInspectOptions, DlpInspectionEventRecord,
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

/// Represents a local staged/uploaded file resolved from disk and classified by Google Magika.
#[derive(Debug, Clone)]
pub struct ResolvedUploadedFile {
    pub resolved_path: PathBuf,
    pub filename: String,
    pub magika_label: String,
    pub content: String,
    pub byte_size: usize,
    pub last_touch_epoch_ms: u64,
}

/// Returns the user-facing upload staging directories (excluding workspace `.` / `tests` dirs)
/// used when inferring browser file uploads without an explicit filename.
pub fn get_user_upload_staging_dirs() -> Vec<PathBuf> {
    static USER_UPLOAD_DIRS: OnceLock<Vec<PathBuf>> = OnceLock::new();
    USER_UPLOAD_DIRS
        .get_or_init(|| {
            let mut dirs = Vec::new();
            for exfil_root in [r"C:\exfil", r"D:\exfil", "/tmp/exfil"] {
                let p = PathBuf::from(exfil_root);
                if p.is_dir() {
                    dirs.push(p);
                }
            }
            if cfg!(windows) {
                let drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
                let users_root = PathBuf::from(format!("{}\\Users", drive));
                if let Ok(rd) = std::fs::read_dir(&users_root) {
                    for e in rd.flatten() {
                        let u_path = e.path();
                        if !u_path.is_dir() {
                            continue;
                        }
                        let candidate_subdirs = [
                            u_path
                                .join("AppData")
                                .join("Roaming")
                                .join("Microsoft")
                                .join("Windows")
                                .join("Recent"),
                            u_path.join("AppData").join("Local").join("Temp"),
                            u_path.join("exfil"),
                            u_path.join("Downloads"),
                            u_path.join("Desktop"),
                            u_path.join("Documents"),
                            u_path.join("OneDrive").join("Desktop"),
                            u_path.join("OneDrive").join("Documents"),
                            u_path.join("OneDrive").join("Downloads"),
                        ];
                        for sub_dir in candidate_subdirs {
                            if sub_dir.is_dir() && !dirs.contains(&sub_dir) {
                                dirs.push(sub_dir);
                            }
                        }
                    }
                }
            }
            if let Some(home) = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME"))
            {
                let home_exfil = PathBuf::from(&home).join("exfil");
                if home_exfil.is_dir() && !dirs.contains(&home_exfil) {
                    dirs.push(home_exfil);
                }
                let home_path = PathBuf::from(home);
                for sub in ["Downloads", "Desktop", "Documents"] {
                    let d = home_path.join(sub);
                    if d.is_dir() && !dirs.contains(&d) {
                        dirs.push(d);
                    }
                }
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
                let recent = PathBuf::from(appdata)
                    .join("Microsoft")
                    .join("Windows")
                    .join("Recent");
                if recent.is_dir() && !dirs.contains(&recent) {
                    dirs.push(recent);
                }
            }
            dirs.dedup();
            dirs
        })
        .clone()
}

/// Returns the standard candidate staging directories to search for browser upload files:
/// 1. User Downloads: %USERPROFILE%\Downloads or ~/Downloads
/// 2. User Desktop: %USERPROFILE%\Desktop or ~/Desktop
/// 3. User Documents: %USERPROFILE%\Documents or ~/Documents
/// 4. System/User Temp: std::env::temp_dir(), %LOCALAPPDATA%\Temp
/// 5. Windows Recent: %APPDATA%\Microsoft\Windows\Recent
/// 6. Workspace root and test directories: ., tests, tests/corpus
pub fn get_candidate_staging_dirs() -> Vec<PathBuf> {
    static ALL_STAGING_DIRS: OnceLock<Vec<PathBuf>> = OnceLock::new();
    ALL_STAGING_DIRS
        .get_or_init(|| {
            let mut dirs = get_user_upload_staging_dirs();
            dirs.push(PathBuf::from("."));
            dirs.push(PathBuf::from("tests"));
            dirs.push(PathBuf::from("tests").join("corpus"));
            dirs.push(
                PathBuf::from("crates")
                    .join("osoosi-dashboard")
                    .join("tests"),
            );
            dirs.dedup();
            dirs
        })
        .clone()
}

/// Reads up to `max_stream_bytes` from `path`, identifies its true content type via Google Magika
/// (`osoosi_core::rea::identify_and_extract_document_text`), and extracts inspectable plaintext from
/// PDF, Word (`.docx`/`.doc`), Excel (`.xlsx`/`.xls`), PowerPoint (`.pptx`), XML, CSV, JSON, Markdown, or text.
pub fn read_and_classify_uploaded_file(
    path: &Path,
    max_stream_bytes: usize,
    max_text_bytes: usize,
) -> Option<ResolvedUploadedFile> {
    use std::io::Read;
    static UPLOADED_FILE_CACHE: std::sync::LazyLock<
        std::sync::Mutex<std::collections::HashMap<(PathBuf, u64), ResolvedUploadedFile>>,
    > = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

    let md = std::fs::metadata(path).ok()?;
    if !md.is_file() || md.len() == 0 {
        return None;
    }
    let total_size = md.len() as usize;
    let mtime_dur = md
        .modified()
        .ok()
        .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
        .unwrap_or_default();
    let mtime_ms = mtime_dur.as_millis() as u64;
    let cache_key = (path.to_path_buf(), mtime_ms ^ (total_size as u64));
    if let Ok(guard) = UPLOADED_FILE_CACHE.lock() {
        if let Some(cached) = guard.get(&cache_key) {
            return Some(cached.clone());
        }
    }

    let filename = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("uploaded_file")
        .to_string();

    let file = std::fs::File::open(path).ok()?;
    let mut buf = Vec::with_capacity(total_size.min(max_stream_bytes));
    file.take(max_stream_bytes as u64)
        .read_to_end(&mut buf)
        .ok()?;

    let (magika_label, content) = osoosi_core::rea::identify_and_extract_document_text(
        &buf,
        Some(&filename),
        max_text_bytes,
    )?;

    let resolved = ResolvedUploadedFile {
        resolved_path: path.to_path_buf(),
        filename,
        magika_label,
        content,
        byte_size: total_size,
        last_touch_epoch_ms: mtime_ms,
    };
    if let Ok(mut guard) = UPLOADED_FILE_CACHE.lock() {
        if guard.len() > 128 {
            guard.clear();
        }
        guard.insert(cache_key, resolved.clone());
    }
    Some(resolved)
}

/// Parses a Windows Shell Link (`.lnk`, `[MS-SHLLINK]`) binary file to extract its target file path.
/// Uses both the structured `LinkInfo` (`LocalBasePath` + `CommonPathSuffix`) header and a fallback
/// scan for null-terminated drive-letter paths (`[A-Za-z]:\...`), returning the target `PathBuf`
/// only when it exists on disk as a regular file. Results are cached by `(lnk_path, mtime_ms ^ size)`
/// so polling never repeatedly opens `.lnk` files on disk.
pub fn resolve_windows_lnk_target(lnk_path: &Path) -> Option<PathBuf> {
    use std::io::Read;
    static LNK_CACHE: std::sync::LazyLock<
        std::sync::Mutex<std::collections::HashMap<(PathBuf, u64), Option<PathBuf>>>,
    > = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

    let md = std::fs::metadata(lnk_path).ok()?;
    if !md.is_file() || md.len() < 4 || md.len() > 64 * 1024 {
        return None;
    }
    let mtime_ms = md
        .modified()
        .ok()
        .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let cache_key = (lnk_path.to_path_buf(), mtime_ms ^ md.len());
    if let Ok(guard) = LNK_CACHE.lock() {
        if let Some(cached) = guard.get(&cache_key) {
            if let Some(ref target) = cached {
                if target.is_file() {
                    return Some(target.clone());
                }
            } else {
                return None;
            }
        }
    }

    let mut f = std::fs::File::open(lnk_path).ok()?;
    let mut buf = Vec::with_capacity(md.len() as usize);
    f.read_to_end(&mut buf).ok()?;

    // Verify MS-SHLLINK 4-byte HeaderSize = 0x0000004C (76)
    if buf.len() < 8 || buf[0..4] != [0x4C, 0x00, 0x00, 0x00] {
        return None;
    }

    let read_cstr = |start: usize| -> Option<String> {
        if start >= buf.len() {
            return None;
        }
        let end = buf[start..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| start + p)?;
        if end <= start {
            return None;
        }
        std::str::from_utf8(&buf[start..end])
            .ok()
            .map(|s| s.trim().to_string())
    };

    let mut resolved_out: Option<PathBuf> = None;

    if buf.len() >= 76 {
        let link_flags = u32::from_le_bytes([buf[20], buf[21], buf[22], buf[23]]);
        let mut offset = 76usize;
        // HasLinkTargetIDList (bit 0)
        if (link_flags & 0x01) != 0 {
            if offset + 2 <= buf.len() {
                let id_list_size = u16::from_le_bytes([buf[offset], buf[offset + 1]]) as usize;
                offset = offset.saturating_add(2).saturating_add(id_list_size);
            }
        }
        // HasLinkInfo (bit 1)
        if (link_flags & 0x02) != 0 && offset + 28 <= buf.len() {
            let link_info_flags = u32::from_le_bytes([
                buf[offset + 8],
                buf[offset + 9],
                buf[offset + 10],
                buf[offset + 11],
            ]);
            // VolumeIDAndLocalBasePath (bit 0)
            if (link_info_flags & 0x01) != 0 {
                let local_base_offset = u32::from_le_bytes([
                    buf[offset + 16],
                    buf[offset + 17],
                    buf[offset + 18],
                    buf[offset + 19],
                ]) as usize;
                let common_suffix_offset = u32::from_le_bytes([
                    buf[offset + 24],
                    buf[offset + 25],
                    buf[offset + 26],
                    buf[offset + 27],
                ]) as usize;
                if let Some(base) = read_cstr(offset.saturating_add(local_base_offset)) {
                    let suffix =
                        read_cstr(offset.saturating_add(common_suffix_offset)).unwrap_or_default();
                    let combined = if suffix.is_empty() {
                        PathBuf::from(&base)
                    } else {
                        PathBuf::from(&base).join(&suffix)
                    };
                    if combined.is_file() {
                        resolved_out = Some(combined);
                    }
                }
            }
        }
    }

    // Fallback: scan for null-terminated ASCII paths starting with `[A-Za-z]:\`
    if resolved_out.is_none() {
        let mut i = 0usize;
        while i + 4 < buf.len() {
            if buf[i].is_ascii_alphabetic()
                && buf[i + 1] == b':'
                && (buf[i + 2] == b'\\' || buf[i + 2] == b'/')
            {
                if let Some(cand_str) = read_cstr(i) {
                    if cand_str.len() >= 4 && cand_str.bytes().all(|b| (0x20..=0x7E).contains(&b)) {
                        let p = PathBuf::from(&cand_str);
                        if p.is_file() {
                            resolved_out = Some(p);
                            break;
                        }
                    }
                }
            }
            i += 1;
        }
    }

    if let Ok(mut guard) = LNK_CACHE.lock() {
        if guard.len() > 256 {
            guard.clear();
        }
        guard.insert(cache_key, resolved_out.clone());
    }

    resolved_out
}

fn is_excluded_non_document_ext(ext: &str) -> bool {
    matches!(
        ext,
        "exe"
            | "dll"
            | "sys"
            | "msi"
            | "msixbundle"
            | "pdb"
            | "obj"
            | "lib"
            | "rlib"
            | "db"
            | "db-wal"
            | "db-shm"
            | "lnk"
            | "har"
            | "zip"
            | "tmp"
            | "temp"
            | "log"
            | "ini"
            | "crdownload"
            | "part"
            | "lock"
            | "etl"
            | "pf"
    )
}

fn is_inspectable_document_ext(ext: &str) -> bool {
    matches!(
        ext,
        "xlsx"
            | "xls"
            | "docx"
            | "doc"
            | "pdf"
            | "pptx"
            | "ppt"
            | "csv"
            | "tsv"
            | "txt"
            | "json"
            | "xml"
            | "md"
            | "yaml"
            | "yml"
            | "rtf"
    )
}

/// Given a candidate filename or path, and a destination URL, resolves the uploaded or staged file
/// using Google Magika content identification across PDF, Word, Excel, XML, CSV, and text files.
pub fn resolve_local_uploaded_file(
    candidate_path_or_name: Option<&str>,
    destination_url: &str,
) -> Option<ResolvedUploadedFile> {
    const MAX_STREAM_BYTES: usize = 2 * 1024 * 1024; // Stream first 2 MB (covers xl/sharedStrings.xml in 10MB+ .xlsx)
    const MAX_TEXT_BYTES: usize = 64 * 1024; // 64 KB extracted plaintext per file

    // Case 1: Candidate path or filename provided
    if let Some(cand) = candidate_path_or_name {
        let trimmed = cand.trim();
        let cleaned = if let Some(inner) = trimmed
            .strip_prefix("[file upload:")
            .and_then(|s| s.strip_suffix(']'))
        {
            inner.trim()
        } else {
            trimmed
        };
        if !cleaned.is_empty() {
            let direct_path = PathBuf::from(cleaned);
            if direct_path.is_file() {
                let (actual_path, lnk_touch_ms) = if direct_path
                    .extension()
                    .and_then(|e| e.to_str())
                    .map(|e| e.eq_ignore_ascii_case("lnk"))
                    .unwrap_or(false)
                {
                    let touch_ms = std::fs::metadata(&direct_path)
                        .ok()
                        .and_then(|m| m.modified().ok())
                        .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
                        .map(|d| d.as_millis() as u64)
                        .unwrap_or(0);
                    (
                        resolve_windows_lnk_target(&direct_path)
                            .unwrap_or_else(|| direct_path.clone()),
                        touch_ms,
                    )
                } else {
                    (direct_path.clone(), 0)
                };
                if let Some(mut res) =
                    read_and_classify_uploaded_file(&actual_path, MAX_STREAM_BYTES, MAX_TEXT_BYTES)
                {
                    if lnk_touch_ms > res.last_touch_epoch_ms {
                        res.last_touch_epoch_ms = lnk_touch_ms;
                    }
                    return Some(res);
                }
            }

            // Search by filename or stem in candidate staging dirs (including Windows Recent .lnk shortcuts)
            let target_filename = direct_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(cleaned);
            let target_stem = Path::new(target_filename)
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or(target_filename);
            let staging_dirs = get_candidate_staging_dirs();

            // Fast O(1) direct join check across all candidate staging dirs (never truncated by large directory size in %TEMP%)
            for dir in &staging_dirs {
                let exact = dir.join(target_filename);
                if exact.is_file() {
                    if let Some(res) =
                        read_and_classify_uploaded_file(&exact, MAX_STREAM_BYTES, MAX_TEXT_BYTES)
                    {
                        return Some(res);
                    }
                }
                for lnk_name in [
                    format!("{}.lnk", target_filename),
                    format!("{}.lnk", target_stem),
                ] {
                    let lnk_candidate = dir.join(&lnk_name);
                    if lnk_candidate.is_file() {
                        let touch_ms = std::fs::metadata(&lnk_candidate)
                            .ok()
                            .and_then(|m| m.modified().ok())
                            .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
                            .map(|d| d.as_millis() as u64)
                            .unwrap_or(0);
                        if let Some(resolved_target) = resolve_windows_lnk_target(&lnk_candidate) {
                            if let Some(mut res) = read_and_classify_uploaded_file(
                                &resolved_target,
                                MAX_STREAM_BYTES,
                                MAX_TEXT_BYTES,
                            ) {
                                if touch_ms > res.last_touch_epoch_ms {
                                    res.last_touch_epoch_ms = touch_ms;
                                }
                                return Some(res);
                            }
                        }
                    }
                }
            }

            let mut matched_paths: Vec<(PathBuf, SystemTime)> = Vec::new();
            for dir in staging_dirs {
                let Ok(rd) = std::fs::read_dir(&dir) else {
                    continue;
                };
                for entry in rd.flatten().take(16384) {
                    let p = entry.path();
                    let ext = p
                        .extension()
                        .and_then(|e| e.to_str())
                        .unwrap_or_default()
                        .to_ascii_lowercase();
                    if ext == "lnk" {
                        let lnk_stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or_default();
                        if lnk_stem.eq_ignore_ascii_case(target_filename)
                            || lnk_stem.eq_ignore_ascii_case(target_stem)
                        {
                            let entry_touch = entry
                                .metadata()
                                .ok()
                                .and_then(|md| md.modified().ok())
                                .unwrap_or(SystemTime::UNIX_EPOCH);
                            if let Some(resolved_target) = resolve_windows_lnk_target(&p) {
                                matched_paths.push((resolved_target, entry_touch));
                            }
                        }
                        continue;
                    }
                    let name = p
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or_default()
                        .to_string();
                    let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or_default();
                    if (name.eq_ignore_ascii_case(target_filename)
                        || stem.eq_ignore_ascii_case(target_filename)
                        || stem.eq_ignore_ascii_case(target_stem))
                        && p.is_file()
                    {
                        let entry_touch = entry
                            .metadata()
                            .ok()
                            .and_then(|md| md.modified().ok())
                            .unwrap_or(SystemTime::UNIX_EPOCH);
                        matched_paths.push((p, entry_touch));
                    }
                }
            }
            matched_paths.sort_by(|a, b| b.1.cmp(&a.1));
            for (p, touch) in matched_paths {
                if let Some(mut res) =
                    read_and_classify_uploaded_file(&p, MAX_STREAM_BYTES, MAX_TEXT_BYTES)
                {
                    let touch_ms = touch
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .map(|d| d.as_millis() as u64)
                        .unwrap_or(0);
                    if touch_ms > res.last_touch_epoch_ms {
                        res.last_touch_epoch_ms = touch_ms;
                    }
                    return Some(res);
                }
            }
        }
        // An explicit candidate filename or path was specified but was not found on disk.
        // Fail resolution rather than picking an unrelated ambient file.
        return None;
    }

    // Case 2: No filename provided, but destination URL targets dlptest.com or an upload sink.
    // Use Google Magika to classify candidate files in C:\exfil, Downloads, Desktop, Documents, Recent, Temp.
    let is_upload_sink = destination_url.contains("dlptest.com")
        || destination_url.contains("/upload")
        || destination_url.contains("/https-post")
        || destination_url.contains("/http-post");

    if is_upload_sink {
        let mut by_path: HashMap<String, (PathBuf, bool, SystemTime, u64)> = HashMap::new();
        let now = SystemTime::now();
        let sys_temp_low = std::env::temp_dir().to_string_lossy().to_ascii_lowercase();

        let mut upsert_candidate = |path: PathBuf, is_exfil: bool, touch: SystemTime, len: u64| {
            let key = path.to_string_lossy().to_ascii_lowercase();
            match by_path.get_mut(&key) {
                Some(existing) => {
                    if touch > existing.2 {
                        existing.2 = touch;
                    }
                    existing.1 |= is_exfil;
                }
                None => {
                    by_path.insert(key, (path, is_exfil, touch, len));
                }
            }
        };

        for dir in get_user_upload_staging_dirs() {
            let dir_low = dir.to_string_lossy().to_ascii_lowercase();
            let is_exfil_dir = dir_low.contains("exfil");
            let is_temp_dir = dir_low == sys_temp_low
                || dir_low.ends_with("\\temp")
                || dir_low.ends_with("/temp");
            let Ok(rd) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in rd.flatten().take(16384) {
                let p = entry.path();
                let ext = p
                    .extension()
                    .and_then(|e| e.to_str())
                    .unwrap_or_default()
                    .to_ascii_lowercase();

                // Resolve Windows Recent `.lnk` shortcut files created/updated when the user selects a file in OpenFileDialog.
                // Critically, use `lnk_md.modified()` (`lnk_mtime`) and `t_md.modified()` (`t_mtime`), NEVER `accessed()` (`atime`),
                // because opening a file during DLP scanning updates `atime` and would otherwise corrupt recency ordering!
                if ext == "lnk" {
                    let Ok(lnk_md) = entry.metadata() else {
                        continue;
                    };
                    if !lnk_md.is_file() {
                        continue;
                    }
                    let lnk_mtime = lnk_md.modified().unwrap_or(SystemTime::UNIX_EPOCH);
                    let lnk_age = now
                        .duration_since(lnk_mtime)
                        .map(|d| d.as_secs())
                        .unwrap_or(u64::MAX);
                    // Allow Recent `.lnk` files up to 7 days old so user file-dialog selections never
                    // expire before older files in `C:\exfil`.
                    if lnk_age <= 7 * 86_400 {
                        if let Some(target_path) = resolve_windows_lnk_target(&p) {
                            let target_ext = target_path
                                .extension()
                                .and_then(|e| e.to_str())
                                .unwrap_or_default()
                                .to_ascii_lowercase();
                            if !is_excluded_non_document_ext(&target_ext) {
                                if let Ok(t_md) = std::fs::metadata(&target_path) {
                                    if t_md.is_file()
                                        && t_md.len() > 0
                                        && t_md.len() <= 500 * 1024 * 1024
                                    {
                                        let t_mtime =
                                            t_md.modified().unwrap_or(SystemTime::UNIX_EPOCH);
                                        let effective_touch = lnk_mtime.max(t_mtime);
                                        let target_is_exfil = target_path
                                            .to_string_lossy()
                                            .to_ascii_lowercase()
                                            .contains("exfil");
                                        upsert_candidate(
                                            target_path,
                                            target_is_exfil,
                                            effective_touch,
                                            t_md.len(),
                                        );
                                    }
                                }
                            }
                        }
                    }
                    continue;
                }

                if is_excluded_non_document_ext(&ext) {
                    continue;
                }
                if is_temp_dir && !is_inspectable_document_ext(&ext) {
                    continue;
                }
                if let Ok(md) = entry.metadata() {
                    if !md.is_file() || md.len() == 0 || md.len() > 500 * 1024 * 1024 {
                        continue;
                    }
                    // Use `modified()` (`mtime`) strictly — never `accessed()` (`atime`), which gets updated
                    // by the scanner itself whenever `read_and_classify_uploaded_file` opens a file!
                    let mtime = md.modified().unwrap_or(SystemTime::UNIX_EPOCH);
                    let age_secs = now
                        .duration_since(mtime)
                        .map(|d| d.as_secs())
                        .unwrap_or(u64::MAX);
                    if is_exfil_dir || age_secs <= 600 {
                        upsert_candidate(p, is_exfil_dir, mtime, md.len());
                    }
                }
            }
        }

        let mut candidates: Vec<(PathBuf, bool, SystemTime, u64)> = by_path.into_values().collect();

        // Prioritize the most recently touched/selected file FIRST (`recent_touch`: `b.2.cmp(&a.2)`),
        // breaking ties with `is_exfil_dir` (`b.1.cmp(&a.1)`) and Office/PDF/CSV document formats.
        candidates.sort_by(|a, b| {
            let a_office =
                a.0.extension()
                    .and_then(|e| e.to_str())
                    .map(|e| {
                        matches!(
                            e.to_ascii_lowercase().as_str(),
                            "xlsx" | "docx" | "pdf" | "xls" | "doc" | "csv"
                        )
                    })
                    .unwrap_or(false);
            let b_office =
                b.0.extension()
                    .and_then(|e| e.to_str())
                    .map(|e| {
                        matches!(
                            e.to_ascii_lowercase().as_str(),
                            "xlsx" | "docx" | "pdf" | "xls" | "doc" | "csv"
                        )
                    })
                    .unwrap_or(false);
            b.2.cmp(&a.2)
                .then_with(|| b.1.cmp(&a.1))
                .then_with(|| b_office.cmp(&a_office))
        });

        if let Some((best_path, _, best_touch, _)) = candidates.into_iter().next() {
            if let Some(mut resolved) =
                read_and_classify_uploaded_file(&best_path, MAX_STREAM_BYTES, MAX_TEXT_BYTES)
            {
                let touch_ms = best_touch
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);
                if touch_ms > resolved.last_touch_epoch_ms {
                    resolved.last_touch_epoch_ms = touch_ms;
                }
                return Some(resolved);
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
                    if (name.starts_with("Profile ")
                        || name.starts_with("profile ")
                        || name == "Guest Profile")
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
        check_browser_dir(
            "Google Chrome",
            local.join("Google").join("Chrome").join("User Data"),
        );
        check_browser_dir(
            "Microsoft Edge",
            local.join("Microsoft").join("Edge").join("User Data"),
        );
        check_browser_dir(
            "Brave",
            local
                .join("BraveSoftware")
                .join("Brave-Browser")
                .join("User Data"),
        );
    }

    profiles
}

/// Checks whether a DLP event signature (destination, scrubbed preview, or zk commitment)
/// was previously marked as a released false positive by the user in `database/dlp_released_allowlist.json`.
/// Checks whether a HAR request (URL, host, or BLAKE3 hash) was excluded/released by the user
/// in `database/dlp_released_allowlist.json`.
pub fn is_har_entry_allowlisted(url: &str, host: &str, hash_blake3: &str) -> bool {
    let path = crate::routes::dlp::released_allowlist_path();
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
    let url_low = url.trim().to_ascii_lowercase();
    let host_low = host.trim().to_ascii_lowercase();
    let hash_low = hash_blake3
        .trim()
        .trim_start_matches('#')
        .to_ascii_lowercase();

    for item in arr {
        if let Some(s) = item.as_str() {
            let pat = s.trim().trim_start_matches('#').to_ascii_lowercase();
            if !pat.is_empty()
                && (pat == url_low
                    || pat == host_low
                    || (!hash_low.is_empty() && hash_low.starts_with(&pat))
                    || (pat.len() >= 4 && url_low.contains(&pat)))
            {
                return true;
            }
        } else if let Some(obj) = item.as_object() {
            if let Some(sink) = obj
                .get("destination_sink")
                .or_else(|| obj.get("url"))
                .and_then(|v| v.as_str())
            {
                let s_low = sink.trim().to_ascii_lowercase();
                if !s_low.is_empty()
                    && (s_low == url_low
                        || s_low == host_low
                        || (s_low.len() >= 4 && url_low.contains(&s_low)))
                {
                    return true;
                }
            }
            if let Some(h) = obj.get("host").and_then(|v| v.as_str()) {
                let h_low = h.trim().to_ascii_lowercase();
                if !h_low.is_empty() && h_low == host_low {
                    return true;
                }
            }
            if let Some(bh) = obj
                .get("hash_blake3")
                .or_else(|| obj.get("zk_commitment_hex"))
                .and_then(|v| v.as_str())
            {
                let bh_low = bh.trim().trim_start_matches('#').to_ascii_lowercase();
                if !bh_low.is_empty()
                    && !hash_low.is_empty()
                    && (hash_low == bh_low || hash_low.starts_with(&bh_low))
                {
                    return true;
                }
            }
            if let Some(pat) = obj.get("pattern").and_then(|v| v.as_str()) {
                let p_low = pat.trim().trim_start_matches('#').to_ascii_lowercase();
                if !p_low.is_empty()
                    && (p_low == host_low
                        || p_low == url_low
                        || (!hash_low.is_empty() && hash_low.starts_with(&p_low))
                        || url_low.contains(&p_low))
                {
                    return true;
                }
            }
        }
    }
    false
}

pub fn is_dlp_event_allowlisted(
    destination_sink: &str,
    scrubbed_preview: &str,
    zk_commitment: &str,
) -> bool {
    let path = crate::routes::dlp::released_allowlist_path();
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
            // A raw string entry is ONLY valid if it cryptographically matches the zk_commitment
            // or the exact scrubbed_preview. A raw string matching destination_sink alone is FORBIDDEN.
            if !s.is_empty() {
                if (!zk_commitment.is_empty() && s == zk_commitment)
                    || (!scrubbed_preview.is_empty() && s == scrubbed_preview)
                {
                    return true;
                }
            }
        } else if let Some(obj) = item.as_object() {
            let entry_sink = obj
                .get("destination_sink")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let entry_zk = obj
                .get("zk_commitment_hex")
                .or_else(|| obj.get("zk_proof_commitment"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let entry_prev = obj
                .get("scrubbed_preview")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            // Path 1: Cryptographic Zero-Knowledge Commitment Match
            if !entry_zk.is_empty() && !zk_commitment.is_empty() && entry_zk == zk_commitment {
                return true;
            }

            // Path 2: Exact Destination Sink + Non-Empty Content Preview Match
            if !entry_sink.is_empty()
                && (entry_sink == destination_sink
                    || host_of(entry_sink) == host_of(destination_sink))
            {
                if !entry_prev.is_empty()
                    && !scrubbed_preview.is_empty()
                    && (entry_prev == scrubbed_preview || scrubbed_preview.contains(entry_prev))
                {
                    return true;
                }
                // Never blanket-allow a destination sink when zk_commitment and preview are empty
            }

            // Path 3: Empty Sink but Non-Empty Exact Content Preview Match
            if entry_sink.is_empty()
                && !entry_prev.is_empty()
                && !scrubbed_preview.is_empty()
                && entry_prev == scrubbed_preview
            {
                return true;
            }
        }
    }
    false
}

/// Computes a deduplication key for live upload-sink polling that advances a monotonic transition
/// counter (`LIVE_SINK_TRANSITION_SEQ`) whenever the winning resolved file path or its touch timestamp
/// (`last_touch_epoch_ms`) changes. This guarantees that rapid alternating uploads (`A -> B -> A`)
/// within the same 15-second `time_bucket` never collide in `SEEN` and are immediately re-inspected.
pub fn compute_live_sink_dedupe_key(resolved: &ResolvedUploadedFile, time_bucket: i64) -> String {
    static LAST_LIVE_SINK_SELECTION: OnceLock<Mutex<(PathBuf, u64)>> = OnceLock::new();
    static LIVE_SINK_TRANSITION_SEQ: AtomicU64 = AtomicU64::new(1);

    let lock = LAST_LIVE_SINK_SELECTION.get_or_init(|| Mutex::new((PathBuf::new(), 0)));
    let mut guard = lock.lock();
    let current = (resolved.resolved_path.clone(), resolved.last_touch_epoch_ms);
    let seq = if *guard != current {
        *guard = current;
        LIVE_SINK_TRANSITION_SEQ.fetch_add(1, Ordering::SeqCst) + 1
    } else {
        LIVE_SINK_TRANSITION_SEQ.load(Ordering::SeqCst)
    };
    drop(guard);

    format!(
        "dns_dlptest_magika_{}_{}_{}_{}_{}",
        resolved.magika_label,
        resolved.resolved_path.display(),
        resolved.last_touch_epoch_ms,
        time_bucket,
        seq
    )
}

/// Autonomous real-time polling of live browser activity, uploads, and sinks (Chrome & Edge history snapshots,
/// logs/har_stream.jsonl, and Windows DNS cache) visited within the last 120 seconds.
pub fn poll_live_browser_and_sink_activity() -> Vec<HarDlpRequest> {
    let mut out = Vec::new();
    let mut cached_sink_resolved: Option<Option<ResolvedUploadedFile>> = None;

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
                    let current_chrom_micros = match now_system
                        .duration_since(SystemTime::UNIX_EPOCH)
                    {
                        Ok(dur) => {
                            (dur.as_secs() + 11644473600) * 1_000_000 + dur.subsec_micros() as u64
                        }
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
                                let diff_micros =
                                    current_chrom_micros.saturating_sub(last_visit_chrom as u64);
                                diff_micros <= 600 * 1_000_000
                            } else {
                                true
                            };
                            if !is_recent {
                                continue;
                            }

                            let resolved_opt = cached_sink_resolved
                                .get_or_insert_with(|| resolve_local_uploaded_file(None, &url))
                                .clone();

                            let (body_text, params) = if let Some(ref resolved) = resolved_opt {
                                (
                                    format!(
                                        "--- UPLOADED FILE: {} (magika: {}, size: {} bytes) ---\n{}",
                                        resolved.resolved_path.display(),
                                        resolved.magika_label,
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
                            let mut key =
                                har_entry_key(&method, &url, &start_ts, &body_text, &params);
                            if let Some(ref resolved) = resolved_opt {
                                let time_bucket = chrono::Utc::now().timestamp() / 15;
                                let sink_dedupe_key =
                                    compute_live_sink_dedupe_key(resolved, time_bucket);
                                key = format!("{}_{}", key, sink_dedupe_key);
                            }
                            out.push(HarDlpRequest {
                                key,
                                source_kind: HarSourceKind::HarCollector,
                                source_label: format!(
                                    "browser_history:{}",
                                    browser.to_ascii_lowercase()
                                ),
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
                    let url = entry
                        .get("url")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default();
                    if url.contains("dlptest.com")
                        || url.contains("/upload")
                        || url.contains("/post")
                    {
                        let method = entry
                            .get("method")
                            .and_then(|v| v.as_str())
                            .unwrap_or("POST");
                        let started_at = entry
                            .get("started_at")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default();
                        let mut body_text = entry
                            .get("body_text")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default()
                            .to_string();
                        let candidate_file = entry
                            .get("file_name")
                            .or_else(|| entry.get("file_path"))
                            .and_then(|v| v.as_str());
                        let mut params = Vec::new();
                        let resolved_opt = if candidate_file.is_some() {
                            resolve_local_uploaded_file(candidate_file, url)
                        } else {
                            cached_sink_resolved
                                .get_or_insert_with(|| resolve_local_uploaded_file(None, url))
                                .clone()
                        };
                        if let Some(resolved) = resolved_opt {
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
                            params.push((
                                "uploaded_file".to_string(),
                                resolved.resolved_path.display().to_string(),
                            ));
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

    // 3. Check active TCP sockets, Windows DNS cache, or active browser destination block for dlptest.com visits
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let dlptest_ips = [
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(104, 26, 0, 68)),
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(104, 26, 1, 68)),
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(172, 67, 75, 74)),
        ];
        let has_live_dlptest_socket = osoosi_core::wfp::has_active_tcp_socket_for_ips(&dlptest_ips);
        let has_active_block = crate::routes::dlp_containment::global_containment_engine()
            .has_active_browser_block_for_host("dlptest.com");
        let has_dns = std::process::Command::new("ipconfig")
            .arg("/displaydns")
            .creation_flags(0x08000000)
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains("dlptest.com"))
            .unwrap_or(false);
        if has_live_dlptest_socket || has_dns || has_active_block {
            let test_url = "https://dlptest.com/https-post/";
            let resolved_opt = cached_sink_resolved
                .get_or_insert_with(|| resolve_local_uploaded_file(None, test_url))
                .clone();
            if let Some(resolved) = resolved_opt {
                // If an active TCP socket or active block to dlptest.com is present right now, bucket by 15s window
                // so every live browser test run by the user triggers a fresh inspection + kernel WFP block or unblock.
                let time_bucket = if has_live_dlptest_socket || has_active_block {
                    chrono::Utc::now().timestamp() / 15
                } else {
                    chrono::Utc::now().timestamp() / 120
                };
                let key = compute_live_sink_dedupe_key(&resolved, time_bucket);
                let started_at = chrono::Utc::now().to_rfc3339();
                out.push(HarDlpRequest {
                    key,
                    source_kind: HarSourceKind::HarCollector,
                    source_label: if has_live_dlptest_socket {
                        "live_tcp_socket:dlptest.com".to_string()
                    } else if has_active_block {
                        "active_block_monitor:dlptest.com".to_string()
                    } else {
                        "windows_dns_cache:dlptest.com".to_string()
                    },
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
                        "--- UPLOADED FILE: {} (magika: {}, size: {} bytes) ---\n{}",
                        resolved.resolved_path.display(),
                        resolved.magika_label,
                        resolved.byte_size,
                        resolved.content
                    ),
                    params: vec![(
                        "uploaded_file".to_string(),
                        resolved.resolved_path.display().to_string(),
                    )],
                    body_truncated: false,
                });
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
                    if let Some(fn_str) = p
                        .get("fileName")
                        .or_else(|| p.get("filename"))
                        .and_then(|v| v.as_str())
                    {
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
            if let Some(arr) = entry
                .get("_oshoosi")
                .and_then(|m| m.get("uploaded_files"))
                .and_then(|v| v.as_array())
            {
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
            if let Some(raw_arr) = req
                .get("requestBody")
                .and_then(|b| b.get("raw"))
                .and_then(|v| v.as_array())
            {
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
                let end = trimmed_rest
                    .find(['"', '\'', ';', '\r', '\n'])
                    .unwrap_or(trimmed_rest.len());
                let cand = trimmed_rest[..end].trim();
                if !cand.is_empty() {
                    candidate_file = Some(cand.to_string());
                }
            }
        }

        // Resolve candidate file from disk if present or if multipart / body-less POST targeting dlptest.com / upload sink
        let should_resolve_file = candidate_file.is_some()
            || mime_type
                .to_ascii_lowercase()
                .contains("multipart/form-data")
            || (method == "POST" && body_text.is_empty() && params.is_empty());
        if should_resolve_file {
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
                params.push((
                    "uploaded_file".to_string(),
                    resolved.resolved_path.display().to_string(),
                ));
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
    let (_tier1, _proof, mut event) = crate::routes::dlp::inspect_and_record_shared(
        &req.actor,
        &req.url,
        req.channel(),
        &payload,
        req.source_kind.as_str(),
        options,
    );
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

/// Raises alerts, runs consensus-gated containment for flagged events, restores any prior
/// temporary browser destination block when a subsequent verified-clean or non-containment
/// upload targets that host, and persists the event.
fn post_process(
    req: &HarDlpRequest,
    mut event: DlpInspectionEventRecord,
) -> DlpInspectionEventRecord {
    let engine = crate::routes::dlp_containment::global_containment_engine();
    if !event.allowed {
        let ctx = crate::routes::dlp_containment::ActorContext {
            actor: req.actor.clone(),
            pid: req.actor_pid,
            image_path: req.actor_image_path.clone(),
            destination_url: req.url.clone(),
            destination_host: req.host.clone(),
            injection_indicators: req.injection_indicators.clone(),
        };
        let mut outcome = engine.evaluate_and_respond(&event, &ctx, BACKEND.get().cloned());
        if outcome.decision == crate::routes::dlp_containment::ContainmentDecision::AlertOnly
            && req.has_body()
            && !event.redactx_confirmed_containment
            && !event.cedar_forbid
            && !event.protected_export_denied
        {
            let restored = engine.restore_browser_destination_blocks_for_host(
                &req.host,
                "non-containment-upload-auto-restore",
            );
            if !restored.is_empty() {
                outcome.reasons.push(format!(
                    "Auto-restored {} prior temporary browser destination block(s) for '{}'",
                    restored.len(),
                    req.host
                ));
            }
        }
        let outcome_json = serde_json::to_value(&outcome).unwrap_or(Value::Null);
        event.containment = Some(outcome_json.clone());
        let mut state = get_global_dlp_state().write();
        crate::routes::dlp::attach_containment_to_event(&mut state, &event.id, outcome_json);
    } else if req.has_body() || engine.has_active_browser_block_for_host(&req.host) {
        let restored =
            engine.restore_browser_destination_blocks_for_host(&req.host, "verified-clean-upload");
        if let Some(first_restored) = restored.first() {
            let outcome_json = serde_json::to_value(first_restored).unwrap_or(Value::Null);
            event.containment = Some(outcome_json.clone());
            let mut state = get_global_dlp_state().write();
            crate::routes::dlp::attach_containment_to_event(&mut state, &event.id, outcome_json);
        }
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

    static TEST_HAR_STAGE_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_resolve_local_uploaded_file_direct_and_search() {
        let _guard = TEST_HAR_STAGE_LOCK.lock();
        let temp_dir = std::env::temp_dir();
        let fname = format!("test_patient_phi_{}.csv", uuid::Uuid::new_v4());
        let file_path = temp_dir.join(&fname);
        let sample_phi =
            "patient_id,name,dob,ssn,icd10\nPT-1092,Alice Johnson,1980-05-14,999-88-7777,E11.9\n";
        std::fs::write(&file_path, sample_phi).expect("write temp phi file");

        // 1. Direct absolute path resolution
        let res1 = resolve_local_uploaded_file(
            Some(file_path.to_str().unwrap()),
            "https://dlptest.com/https-post/",
        );
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
        assert!(
            res4.is_some(),
            "dlptest.com without filename should pick newest data file"
        );

        let _ = std::fs::remove_file(file_path);
    }

    #[test]
    fn test_extract_requests_with_file_upload_metadata() {
        let _guard = TEST_HAR_STAGE_LOCK.lock();
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

        let reqs =
            extract_requests_from_har(&doc, "browser_extension", HarSourceKind::BrowserExtension);
        assert_eq!(reqs.len(), 1);
        let r = &reqs[0];
        assert_eq!(r.actor, "chrome.exe");
        assert_eq!(r.channel(), "BROWSER_HTTP_POST");
        let payload = r.to_inspection_payload();
        assert!(
            payload.contains("MRN-882194"),
            "payload must contain resolved file content"
        );

        let _ = std::fs::remove_file(file_path);
    }

    #[test]
    fn test_is_dlp_event_allowlisted() {
        let _guard = TEST_HAR_STAGE_LOCK.lock();
        let allowlist_file = crate::routes::dlp::released_allowlist_path();
        let orig_content = std::fs::read(&allowlist_file).ok();

        // 1. Non-existent or empty allowlist check
        assert!(!is_dlp_event_allowlisted(
            "https://dlptest.com/https-post/",
            "preview",
            "zk-commit-123"
        ));

        // 2. Allowlist with empty zk and empty preview for dlptest.com must NEVER return true
        if let Some(parent) = allowlist_file.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let dummy_entries = serde_json::json!([
            {
                "destination_sink": "https://dlptest.com/https-post/",
                "zk_commitment_hex": "",
                "scrubbed_preview": "",
                "released_at": "2026-10-25T00:00:00Z"
            },
            {
                "destination_sink": "https://dlptest.com/https-post/",
                "zk_commitment_hex": "valid-zk-commitment-hex",
                "scrubbed_preview": "specific-scrubbed-preview-content",
                "released_at": "2026-10-25T00:00:00Z"
            }
        ]);
        std::fs::write(
            &allowlist_file,
            serde_json::to_string(&dummy_entries).unwrap(),
        )
        .unwrap();

        // Must NOT match on destination sink alone with empty zk/preview
        assert!(!is_dlp_event_allowlisted(
            "https://dlptest.com/https-post/",
            "different-unreleased-content",
            "different-zk"
        ));
        // Must match on valid zk commitment
        assert!(is_dlp_event_allowlisted(
            "https://dlptest.com/https-post/",
            "any-preview",
            "valid-zk-commitment-hex"
        ));
        // Must match on destination sink + matching scrubbed preview
        assert!(is_dlp_event_allowlisted(
            "https://dlptest.com/https-post/",
            "specific-scrubbed-preview-content",
            ""
        ));

        // Cleanup: restore exact original bytes so git status -s remains 100% clean
        if let Some(ref bytes) = orig_content {
            let _ = std::fs::write(&allowlist_file, bytes);
        } else {
            let _ = std::fs::remove_file(&allowlist_file);
        }
    }

    #[test]
    fn test_recent_touch_and_clean_upload_restores_browser_block() {
        let _guard = TEST_HAR_STAGE_LOCK.lock();
        let reg_paths = vec![
            std::path::PathBuf::from("database").join("dlp_containment_registry.json"),
            std::path::PathBuf::from("crates")
                .join("osoosi-dashboard")
                .join("database")
                .join("dlp_containment_registry.json"),
        ];
        let mut backups = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for p in reg_paths {
            let key = p
                .canonicalize()
                .map(|c| c.to_string_lossy().to_string())
                .unwrap_or_else(|_| p.to_string_lossy().to_string());
            if seen.insert(key) {
                let bytes = std::fs::read(&p).ok();
                backups.push((p, bytes));
            }
        }

        // 1. Verify that a newly touched benign file in temp_dir is resolved by URL-only lookup
        //    ahead of any older files on disk because `recent_touch` is sorted first (`b.2.cmp(&a.2)`).
        let temp_dir = std::env::temp_dir();
        let clean_name = format!("covergeneral_test_{}.txt", uuid::Uuid::new_v4());
        let clean_path = temp_dir.join(&clean_name);
        let benign_cover_letter = "Dear Hiring Committee,\nI am writing to express my strong interest in the Principal Security Engineer role.\nSincerely,\nApplicant\n";
        std::fs::write(&clean_path, benign_cover_letter).expect("write benign cover letter");

        let resolved = resolve_local_uploaded_file(None, "https://dlptest.com/https-post/");
        assert!(resolved.is_some(), "should resolve newest touched file");
        let r = resolved.unwrap();
        assert_eq!(
            r.resolved_path.file_name().and_then(|n| n.to_str()),
            Some(clean_name.as_str()),
            "newest touched benign file must not be shadowed by older C:\\exfil files"
        );

        // 2. Verify that inspecting and post-processing the clean upload produces `allowed == true`
        let req = HarDlpRequest {
            key: format!("test_clean_{}", uuid::Uuid::new_v4()),
            source_kind: HarSourceKind::BrowserExtension,
            source_label: "browser_extension".to_string(),
            actor: "chrome.exe".to_string(),
            actor_pid: None,
            actor_image_path: None,
            injection_indicators: Vec::new(),
            method: "POST".to_string(),
            url: "https://dlptest.com/https-post/".to_string(),
            host: "dlptest.com".to_string(),
            started_at: chrono::Utc::now().to_rfc3339(),
            mime_type: "multipart/form-data".to_string(),
            body_text: r.content.clone(),
            params: vec![(
                "uploaded_file".to_string(),
                r.resolved_path.display().to_string(),
            )],
            body_truncated: false,
        };
        let ev = inspect_only(&req);
        assert!(ev.allowed, "benign cover letter must be allowed by DLP");
        let processed = post_process(&req, ev);
        assert!(processed.allowed);

        // 3. Verify Windows .lnk binary shortcut resolution resolves target paths accurately
        let lnk_path = temp_dir.join(format!("{}.lnk", clean_name));
        let mut lnk_bytes = vec![0x4C, 0x00, 0x00, 0x00];
        lnk_bytes.extend_from_slice(clean_path.to_string_lossy().as_bytes());
        lnk_bytes.push(0x00);
        std::fs::write(&lnk_path, &lnk_bytes).expect("write test .lnk");
        let resolved_lnk = resolve_windows_lnk_target(&lnk_path);
        assert_eq!(resolved_lnk, Some(clean_path.clone()));

        let _ = std::fs::remove_file(lnk_path);
        let _ = std::fs::remove_file(clean_path);

        // Restore disk state
        for (p, orig) in backups {
            if let Some(ref bytes) = orig {
                let _ = std::fs::write(&p, bytes);
            } else if p.exists() {
                let _ = std::fs::remove_file(&p);
            }
        }
    }

    #[test]
    fn test_rapid_alternating_uploads_within_single_bucket_and_atime_immunity() {
        let _guard = TEST_HAR_STAGE_LOCK.lock();
        // Verify that rapid alternating uploads (Sensitive A -> Benign B -> Sensitive A) within the
        // EXACT SAME 15-second `time_bucket` produce distinct deduplication keys (`compute_live_sink_dedupe_key`)
        // so `dedupe_new` never drops the re-selected file as a duplicate.
        let temp_dir = std::env::temp_dir();
        let sens_name = format!("alt_sensitive_{}.csv", uuid::Uuid::new_v4());
        let clean_name = format!("alt_covergeneral_{}.txt", uuid::Uuid::new_v4());
        let sens_path = temp_dir.join(&sens_name);
        let clean_path = temp_dir.join(&clean_name);

        let sensitive_csv = "name,ssn,ccn\nJohn Doe,123-45-6789,4532015112830366\n";
        let benign_txt = "Dear Hiring Manager,\nAttached is my resume and cover letter.\n";

        // Step 1: User selects/creates Sensitive A (`10-MB-Test` equivalent)
        std::fs::write(&sens_path, sensitive_csv).expect("write sensitive csv");
        let r_a1 = resolve_local_uploaded_file(None, "https://dlptest.com/https-post/")
            .expect("resolve sensitive A1");
        assert_eq!(r_a1.resolved_path, sens_path);

        let fixed_bucket = 119_500_000i64;
        let key_a1 = compute_live_sink_dedupe_key(&r_a1, fixed_bucket);
        let key_a1_repeat = compute_live_sink_dedupe_key(&r_a1, fixed_bucket);
        assert_eq!(
            key_a1, key_a1_repeat,
            "unchanged selection inside the same bucket must keep the same key"
        );

        // Step 2: 15ms later (still in `fixed_bucket`), user selects Benign B (`covergeneral` equivalent)
        std::thread::sleep(std::time::Duration::from_millis(15));
        std::fs::write(&clean_path, benign_txt).expect("write benign txt");

        // Simulate scanner/background reading `sens_path` (which updates `atime` on `sens_path` but NOT `mtime`)
        let _ = std::fs::read(&sens_path);

        let r_b1 = resolve_local_uploaded_file(None, "https://dlptest.com/https-post/")
            .expect("resolve benign B1");
        assert_eq!(
            r_b1.resolved_path, clean_path,
            "reading an older file must never let its atime shadow a newer mtime selection"
        );
        let key_b1 = compute_live_sink_dedupe_key(&r_b1, fixed_bucket);
        assert_ne!(key_a1, key_b1);

        // Step 3: 15ms later (STILL in `fixed_bucket`), user touches/re-selects Sensitive A via `.lnk` shortcut
        std::thread::sleep(std::time::Duration::from_millis(15));
        let lnk_a_path = temp_dir.join(format!("{}.lnk", sens_name));
        let mut lnk_bytes = vec![0x4C, 0x00, 0x00, 0x00];
        lnk_bytes.extend_from_slice(sens_path.to_string_lossy().as_bytes());
        lnk_bytes.push(0x00);
        std::fs::write(&lnk_a_path, &lnk_bytes).expect("write .lnk for sensitive A2");

        let r_a2 = resolve_local_uploaded_file(None, "https://dlptest.com/https-post/")
            .expect("resolve sensitive A2 via .lnk");
        assert_eq!(
            r_a2.resolved_path, sens_path,
            "touching .lnk for Sensitive A must immediately make Sensitive A the winner again"
        );
        let key_a2 = compute_live_sink_dedupe_key(&r_a2, fixed_bucket);
        assert_ne!(
            key_a1, key_a2,
            "alternating A -> B -> A within the same 15s bucket must produce a fresh dedupe key"
        );

        // Verify `dedupe_new` accepts all three transitions (A1 -> B1 -> A2) without dropping A2
        let make_req = |k: String, r: &ResolvedUploadedFile| HarDlpRequest {
            key: k,
            source_kind: HarSourceKind::HarCollector,
            source_label: "live_tcp_socket:dlptest.com".to_string(),
            actor: "chrome.exe".to_string(),
            actor_pid: None,
            actor_image_path: None,
            injection_indicators: Vec::new(),
            host: "dlptest.com".to_string(),
            method: "POST".to_string(),
            url: "https://dlptest.com/https-post/".to_string(),
            started_at: chrono::Utc::now().to_rfc3339(),
            mime_type: "multipart/form-data".to_string(),
            body_text: r.content.clone(),
            params: vec![(
                "uploaded_file".to_string(),
                r.resolved_path.display().to_string(),
            )],
            body_truncated: false,
        };
        let batch = vec![
            make_req(key_a1, &r_a1),
            make_req(key_b1, &r_b1),
            make_req(key_a2, &r_a2),
        ];
        let (fresh, _) = dedupe_new(&batch);
        assert_eq!(
            fresh.len(),
            3,
            "all 3 alternating uploads (A -> B -> A) within the same 15s bucket must pass deduplication"
        );

        let _ = std::fs::remove_file(lnk_a_path);
        let _ = std::fs::remove_file(sens_path);
        let _ = std::fs::remove_file(clean_path);
    }

    #[test]
    fn test_user_upload_staging_dirs_discovers_recent_and_temp() {
        let dirs = get_user_upload_staging_dirs();
        assert!(
            !dirs.is_empty(),
            "get_user_upload_staging_dirs must return non-empty staging directories"
        );
        if cfg!(windows) {
            let has_recent_or_temp = dirs.iter().any(|d| {
                let s = d.to_string_lossy().to_ascii_lowercase();
                s.contains("recent") || s.contains("temp") || s.contains("downloads")
            });
            assert!(
                has_recent_or_temp,
                "on Windows, staging dirs must include Recent, Temp, or Downloads"
            );
        }
    }
}
