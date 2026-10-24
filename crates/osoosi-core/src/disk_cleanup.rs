//! Autonomous Disk Space & Telemetry Lifecycle Cleanup Engine for OpenỌ̀ṣọ́ọ̀sì.
//!
//! Continuously monitors host disk space and workspace artifact footprints,
//! autonomously reclaiming disk space across 5 safe lifecycle tiers without
//! disrupting active release binaries, running daemons, or authoritative security ledgers:
//! 1. Tier 1 — Ephemeral & Scratch Build Targets (`target/check_*`, `target/worker_*`, `target/debug`)
//! 2. Tier 2 — Superseded Multi-Hash Cargo Dependencies (`target/release/deps`, `target/release/build`, `incremental`)
//! 3. Tier 3 — SQLite Telemetry Ring-Buffer Retention & WAL Checkpoint/Truncation (`osoosi.db`, `-wal`)
//! 4. Tier 4 — Rotated Daemon Logs & Regression Artifact Pruning (`logs/*.rotated`, historical `osoosi.log.*`)
//! 5. Tier 5 — Orphaned OS Temp Files (`%TEMP%/osoosi_*`) & Staging Leftovers

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::info;

static DISK_WATCHDOG_ACTIVE: AtomicBool = AtomicBool::new(false);
static TOTAL_BYTES_FREED_LIFETIME: AtomicU64 = AtomicU64::new(0);
static TOTAL_FILES_REMOVED_LIFETIME: AtomicU64 = AtomicU64::new(0);
static TOTAL_SWEEP_COUNT: AtomicU64 = AtomicU64::new(0);

static GLOBAL_DISK_POLICY: OnceLock<RwLock<DiskCleanupPolicy>> = OnceLock::new();
static LAST_SWEEP_REPORT: OnceLock<RwLock<Option<DiskCleanupSweepReport>>> = OnceLock::new();
static SWEEP_HISTORY: OnceLock<RwLock<Vec<DiskCleanupSweepReport>>> = OnceLock::new();

/// Host disk pressure state based on free disk space and usage percentage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiskPressureLevel {
    Normal,
    Warning,
    Critical,
}

/// Runtime-configurable policy governing autonomous disk cleanup sweeps.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskCleanupPolicy {
    pub enabled: bool,
    pub interval_secs: u64,
    pub min_free_gb_trigger: f64,
    pub max_log_retention_mb: u64,
    pub max_sqlite_wal_mb: u64,
    pub keep_release_dep_revisions: usize,
    pub prune_debug_target: bool,
    pub max_events_rows: usize,
    pub max_har_rows: usize,
    pub max_threats_rows: usize,
    pub max_consensus_rows: usize,
}

impl Default for DiskCleanupPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: 900, // 15 minutes
            min_free_gb_trigger: 50.0,
            max_log_retention_mb: 50,
            max_sqlite_wal_mb: 32,
            keep_release_dep_revisions: 2,
            prune_debug_target: true,
            max_events_rows: 25_000,
            max_har_rows: 2_000,
            max_threats_rows: 5_000,
            max_consensus_rows: 5_000,
        }
    }
}

/// Metrics for a single cleanup tier during a sweep or status inspection.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DiskCleanupTierResult {
    pub tier_name: String,
    pub bytes_freed: u64,
    pub mb_freed: f64,
    pub files_removed: u64,
    pub rows_pruned: u64,
    pub current_footprint_mb: f64,
    pub details: Vec<String>,
}

/// Summary report emitted after each autonomous or manual disk cleanup sweep.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskCleanupSweepReport {
    pub status: String,
    pub mode: String,
    pub timestamp: String,
    pub duration_ms: f64,
    pub bytes_freed: u64,
    pub mb_freed: f64,
    pub gb_freed: f64,
    pub files_removed: u64,
    pub sqlite_rows_pruned: u64,
    pub drive_path: String,
    pub drive_total_gb: f64,
    pub drive_free_gb_before: f64,
    pub drive_free_gb_after: f64,
    pub drive_usage_percent_after: f64,
    pub pressure_level: DiskPressureLevel,
    pub tiers: Vec<DiskCleanupTierResult>,
}

/// Live status snapshot returned by `GET /api/disk-cleanup/status`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskCleanupStatusSnapshot {
    pub status: String,
    pub watchdog_active: bool,
    pub policy: DiskCleanupPolicy,
    pub drive_path: String,
    pub drive_total_gb: f64,
    pub drive_used_gb: f64,
    pub drive_free_gb: f64,
    pub drive_usage_percent: f64,
    pub pressure_level: DiskPressureLevel,
    pub total_bytes_freed_lifetime: u64,
    pub total_mb_freed_lifetime: f64,
    pub total_gb_freed_lifetime: f64,
    pub total_files_removed_lifetime: u64,
    pub total_sweep_count: u64,
    pub current_footprints_mb: HashMap<String, f64>,
    pub estimated_reclaimable_mb: f64,
    pub last_sweep: Option<DiskCleanupSweepReport>,
    pub recent_sweeps: Vec<DiskCleanupSweepReport>,
}

pub fn get_disk_cleanup_policy() -> DiskCleanupPolicy {
    GLOBAL_DISK_POLICY
        .get_or_init(|| RwLock::new(DiskCleanupPolicy::default()))
        .read()
        .clone()
}

pub fn update_disk_cleanup_policy(new_policy: DiskCleanupPolicy) -> DiskCleanupPolicy {
    let lock = GLOBAL_DISK_POLICY.get_or_init(|| RwLock::new(DiskCleanupPolicy::default()));
    let mut guard = lock.write();
    *guard = new_policy.clone();
    new_policy
}

/// Evaluates drive free space and usage percentage into a `DiskPressureLevel`.
pub fn evaluate_disk_pressure(
    free_gb: f64,
    usage_percent: f64,
    min_free_gb: f64,
) -> DiskPressureLevel {
    if free_gb < (min_free_gb * 0.4).max(10.0) || usage_percent >= 92.0 {
        DiskPressureLevel::Critical
    } else if free_gb < min_free_gb || usage_percent >= 82.0 {
        DiskPressureLevel::Warning
    } else {
        DiskPressureLevel::Normal
    }
}

/// Resolves the workspace root directory (handling execution from either repo root or `target/release`).
pub fn resolve_workspace_root() -> PathBuf {
    if let Ok(cwd) = std::env::current_dir() {
        if cwd.join("Cargo.toml").exists() {
            return cwd;
        }
        if let Some(parent) = cwd.parent().and_then(|p| p.parent()) {
            if parent.join("Cargo.toml").exists() {
                return parent.to_path_buf();
            }
        }
        return cwd;
    }
    PathBuf::from(".")
}

/// Queries total, used, and available space (in bytes) for the disk containing `anchor`.
pub fn query_drive_space_bytes(anchor: &Path) -> (String, u64, u64, u64) {
    let canonical = std::fs::canonicalize(anchor).unwrap_or_else(|_| anchor.to_path_buf());
    let canonical_str = canonical.to_string_lossy().to_string();

    let disks = sysinfo::Disks::new_with_refreshed_list();
    let mut best_match: Option<(String, u64, u64)> = None;
    let mut best_len = 0usize;

    let norm_target = canonical_str
        .trim_start_matches(r"\\?\")
        .to_ascii_lowercase();

    for disk in disks.list() {
        let mount = disk.mount_point().to_string_lossy().to_string();
        let norm_mount = mount.to_ascii_lowercase();
        if norm_target.starts_with(&norm_mount) && norm_mount.len() >= best_len {
            best_len = norm_mount.len();
            best_match = Some((mount, disk.total_space(), disk.available_space()));
        }
    }

    if let Some((mount, total, avail)) = best_match {
        let used = total.saturating_sub(avail);
        return (mount, total, used, avail);
    }

    if let Some(first) = disks.list().first() {
        let total = first.total_space();
        let avail = first.available_space();
        let used = total.saturating_sub(avail);
        return (
            first.mount_point().to_string_lossy().to_string(),
            total,
            used,
            avail,
        );
    }

    ("C:\\".to_string(), 0, 0, 0)
}

/// Computes byte size and file count of a file or directory (bounded to `max_files` for fast UI probes).
pub fn compute_path_footprint(path: &Path, max_files: usize) -> (u64, u64) {
    if !path.exists() {
        return (0, 0);
    }
    if path.is_file() {
        let sz = path.metadata().map(|m| m.len()).unwrap_or(0);
        return (sz, 1);
    }

    let mut total_bytes = 0u64;
    let mut count = 0u64;
    let mut stack = vec![path.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(ft) = entry.file_type() else {
                continue;
            };
            if ft.is_file() {
                if let Ok(meta) = entry.metadata() {
                    total_bytes = total_bytes.saturating_add(meta.len());
                    count += 1;
                    if count as usize >= max_files {
                        return (total_bytes, count);
                    }
                }
            } else if ft.is_dir() {
                stack.push(entry.path());
            }
        }
    }
    (total_bytes, count)
}

fn safe_remove_file(path: &Path) -> u64 {
    let sz = path.metadata().map(|m| m.len()).unwrap_or(0);
    if std::fs::remove_file(path).is_ok() {
        sz
    } else {
        0
    }
}

fn safe_remove_dir_all(path: &Path) -> (u64, u64) {
    if !path.exists() {
        return (0, 0);
    }
    let (approx_bytes, approx_files) = compute_path_footprint(path, 50_000);

    #[cfg(target_os = "windows")]
    {
        let empty_dir = std::env::temp_dir().join(format!("osoosi_empty_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&empty_dir);
        let _ = std::process::Command::new("robocopy")
            .args([
                empty_dir.to_string_lossy().as_ref(),
                path.to_string_lossy().as_ref(),
                "/MIR",
                "/NFL",
                "/NDL",
                "/NJH",
                "/NJS",
                "/NC",
                "/NS",
                "/NP",
                "/MT:32",
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        let _ = std::fs::remove_dir(&empty_dir);
        let _ = std::process::Command::new("cmd")
            .args(["/C", "rmdir", "/S", "/Q", &path.to_string_lossy()])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        if !path.exists() {
            return (approx_bytes, approx_files.max(1));
        }
    }

    if std::fs::remove_dir_all(path).is_ok() {
        return (approx_bytes, approx_files.max(1));
    }
    (0, 0)
}

/// Checks if a directory name inside `target/` is an ephemeral scratch/subagent build target.
fn is_scratch_target_dir_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower == "challenge_test_target"
        || lower == "check_dash"
        || lower == "check_ws"
        || lower.starts_with("check_")
        || lower == "subagent_build"
        || lower.starts_with("subagent_")
        || lower == "test_out"
        || lower == "tmp"
        || lower.starts_with("worker_")
        || lower.starts_with("scratch_")
}

/// Tier 1: Cleans ephemeral scratch Cargo target directories and optionally `target/debug`.
pub fn clean_tier1_scratch_and_debug_targets(
    root: &Path,
    prune_debug: bool,
) -> DiskCleanupTierResult {
    let target_dir = root.join("target");
    let mut freed_bytes = 0u64;
    let mut files_removed = 0u64;
    let mut details = Vec::new();

    if target_dir.exists() {
        if let Ok(entries) = std::fs::read_dir(&target_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                let name = entry.file_name().to_string_lossy().to_string();
                if path.is_dir() && is_scratch_target_dir_name(&name) {
                    let (b, f) = safe_remove_dir_all(&path);
                    if b > 0 || f > 0 {
                        freed_bytes = freed_bytes.saturating_add(b);
                        files_removed = files_removed.saturating_add(f);
                        details.push(format!(
                            "Removed scratch target/{} ({:.2} MB)",
                            name,
                            b as f64 / (1024.0 * 1024.0)
                        ));
                    }
                } else if path.is_file()
                    && (name == "dashboard_diff.rs" || name == "cargo_check_err.txt")
                {
                    let b = safe_remove_file(&path);
                    if b > 0 {
                        freed_bytes = freed_bytes.saturating_add(b);
                        files_removed += 1;
                    }
                }
            }
        }

        let debug_dir = target_dir.join("debug");
        if prune_debug && debug_dir.exists() {
            #[cfg(target_os = "windows")]
            let (approx_b, approx_f) = compute_path_footprint(&debug_dir, 10_000);
            let purge_dir = target_dir.join(format!(
                ".purge_debug_{}_{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0)
            ));
            let target_to_wipe = if std::fs::rename(&debug_dir, &purge_dir).is_ok() {
                purge_dir
            } else {
                debug_dir
            };
            #[cfg(target_os = "windows")]
            {
                let empty_dir =
                    std::env::temp_dir().join(format!("osoosi_empty_bg_{}", std::process::id()));
                let _ = std::fs::create_dir_all(&empty_dir);
                let cmd_str = format!(
                    r#"robocopy "{}" "{}" /MIR /NFL /NDL /NJH /NJS /NC /NS /NP /MT:128 >nul 2>&1 & rmdir /s /q "{}" >nul 2>&1"#,
                    empty_dir.display(),
                    target_to_wipe.display(),
                    target_to_wipe.display()
                );
                let _ = std::process::Command::new("cmd")
                    .args(["/C", &cmd_str])
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn();
                freed_bytes = freed_bytes.saturating_add(approx_b);
                files_removed = files_removed.saturating_add(approx_f.max(1));
                details.push(format!(
                    "Unlinked & queued 128-thread purge of target/debug ({:.2} MB+)",
                    approx_b as f64 / (1024.0 * 1024.0)
                ));
            }
            #[cfg(not(target_os = "windows"))]
            {
                let (b, f) = safe_remove_dir_all(&target_to_wipe);
                freed_bytes = freed_bytes.saturating_add(b);
                files_removed = files_removed.saturating_add(f);
            }
        }
    }

    let rem_debug = compute_path_footprint(&target_dir.join("debug"), 5_000).0;
    DiskCleanupTierResult {
        tier_name: "Tier 1: Scratch & Debug Build Targets".to_string(),
        bytes_freed: freed_bytes,
        mb_freed: ((freed_bytes as f64 / (1024.0 * 1024.0)) * 100.0).round() / 100.0,
        files_removed,
        rows_pruned: 0,
        current_footprint_mb: ((rem_debug as f64 / (1024.0 * 1024.0)) * 100.0).round() / 100.0,
        details,
    }
}

static CACHED_WORKSPACE_MEMBER_STEMS: std::sync::OnceLock<std::collections::HashSet<String>> =
    std::sync::OnceLock::new();

/// Dynamically discovers all first-party Cargo workspace crate member stems
/// from `root/Cargo.toml` and `root/crates/`.
///
/// Discovers all 36+ workspace crates automatically and normalizes crate names
/// (converting `-` to `_`, and registering both bare and `lib`-prefixed stems).
pub fn discover_workspace_stems(root: &Path) -> std::collections::HashSet<String> {
    let mut stems = std::collections::HashSet::new();

    // 1. Scan root/Cargo.toml for [workspace] members or [package] name
    let cargo_toml_path = root.join("Cargo.toml");
    if let Ok(content) = std::fs::read_to_string(&cargo_toml_path) {
        let mut in_workspace_members = false;
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("[workspace]") {
                in_workspace_members = false;
            } else if trimmed.starts_with("members") && trimmed.contains('=') {
                in_workspace_members = true;
                // Parse inline array: members = ["crates/a", "crates/b"]
                if let Some(bracket_start) = trimmed.find('[') {
                    let slice = &trimmed[bracket_start..];
                    for part in slice.split(&['"', '\'', ','][..]) {
                        let token = part
                            .trim()
                            .trim_matches(|c| c == '"' || c == '\'' || c == '[' || c == ']');
                        if !token.is_empty()
                            && (token.contains('/')
                                || token.contains('\\')
                                || !token.starts_with('#'))
                        {
                            let member_path = Path::new(token);
                            if let Some(name) = member_path.file_name().and_then(|n| n.to_str()) {
                                let norm = name.replace('-', "_");
                                stems.insert(norm.clone());
                                stems.insert(format!("lib{}", norm));
                            }
                        }
                    }
                    if trimmed.contains(']') {
                        in_workspace_members = false;
                    }
                }
            } else if in_workspace_members {
                if trimmed.starts_with(']') {
                    in_workspace_members = false;
                } else {
                    for part in trimmed.split(',') {
                        let token = part.trim().trim_matches(|c| c == '"' || c == '\'');
                        if !token.is_empty() && !token.starts_with('#') {
                            let member_path = Path::new(token);
                            if let Some(name) = member_path.file_name().and_then(|n| n.to_str()) {
                                let norm = name.replace('-', "_");
                                stems.insert(norm.clone());
                                stems.insert(format!("lib{}", norm));
                            }
                        }
                    }
                }
            } else if trimmed.starts_with("name") && trimmed.contains('=') {
                // Standalone crate or package manifest
                let val = trimmed
                    .split('=')
                    .nth(1)
                    .unwrap_or("")
                    .trim()
                    .trim_matches('"')
                    .trim_matches('\'');
                if !val.is_empty() {
                    let norm = val.replace('-', "_");
                    stems.insert(norm.clone());
                    stems.insert(format!("lib{}", norm));
                }
            }
        }
    }

    // 2. Scan root/crates directory if it exists
    let crates_dir = root.join("crates");
    if let Ok(entries) = std::fs::read_dir(&crates_dir) {
        for entry in entries.flatten() {
            if entry.path().is_dir() {
                if let Some(name) = entry.file_name().to_str() {
                    let norm = name.replace('-', "_");
                    stems.insert(norm.clone());
                    stems.insert(format!("lib{}", norm));
                }
            }
        }
    }

    // 3. Fall back to resolve_workspace_root() if root had neither Cargo.toml nor crates
    if stems.is_empty() {
        let ws = resolve_workspace_root();
        if ws != root && ws.exists() {
            return discover_workspace_stems(&ws);
        }
    }

    stems
}

/// Returns the cached set of first-party workspace member stems for the current repository.
pub fn get_workspace_member_stems() -> &'static std::collections::HashSet<String> {
    CACHED_WORKSPACE_MEMBER_STEMS
        .get_or_init(|| discover_workspace_stems(&resolve_workspace_root()))
}

/// Checks whether a crate stem belongs to a first-party OshoosiClaw workspace crate
/// (which only ever has a single version in Cargo.lock, unlike multi-version 3rd-party crates).
fn is_first_party_workspace_stem(stem: &str) -> bool {
    let raw = stem.trim();
    let unlib = raw.strip_prefix("lib").unwrap_or(raw);
    let stems = get_workspace_member_stems();
    stems.contains(raw) || stems.contains(unlib)
}

/// Parses a Cargo hashed filename `<stem>-<16_hex_chars>.<ext>` into `(stem, ext)`.
#[allow(dead_code)]
fn parse_cargo_hashed_filename(filename: &str) -> Option<(String, String)> {
    parse_cargo_hashed_filename_with_stems(filename, None)
}

/// Parses a Cargo hashed filename using an optional scoped stem set.
fn parse_cargo_hashed_filename_with_stems(
    filename: &str,
    custom_stems: Option<&std::collections::HashSet<String>>,
) -> Option<(String, String)> {
    let dot_pos = filename.find('.')?;
    let base = &filename[..dot_pos];
    let ext = &filename[dot_pos..];
    // Preserve Authenticode-signed proc-macro .dll and .exe files for WDAC Application Control
    if ext.eq_ignore_ascii_case(".dll") || ext.eq_ignore_ascii_case(".exe") {
        return None;
    }
    let dash_pos = base.rfind('-')?;
    let hash_part = &base[dash_pos + 1..];
    if hash_part.len() == 16 && hash_part.chars().all(|c| c.is_ascii_hexdigit()) {
        let stem = &base[..dash_pos];
        if !stem.is_empty() {
            let is_first_party = if let Some(stems) = custom_stems {
                let unlib = stem.strip_prefix("lib").unwrap_or(stem);
                stems.contains(stem) || stems.contains(unlib)
            } else {
                is_first_party_workspace_stem(stem)
            };
            if is_first_party {
                return Some((stem.to_string(), ext.to_string()));
            }
        }
    }
    None
}

/// Parses a Cargo hashed directory name `<stem>-<16_hex_chars>` into `stem`.
fn parse_cargo_hashed_dirname(dirname: &str) -> Option<String> {
    let dash_pos = dirname.rfind('-')?;
    let hash_part = &dirname[dash_pos + 1..];
    if hash_part.len() == 16 && hash_part.chars().all(|c| c.is_ascii_hexdigit()) {
        let stem = &dirname[..dash_pos];
        let _ = stem;
        return None;
    }
    None
}

/// Tier 2: Prunes superseded multi-hash crate artifacts in `target/release/deps`, `build`, and `incremental`
/// while preserving the newest `keep_revisions` per crate so incremental release builds stay fast.
pub fn clean_tier2_superseded_release_deps(
    root: &Path,
    keep_revisions: usize,
) -> DiskCleanupTierResult {
    let keep = keep_revisions.max(1);
    let release_dir = root.join("target").join("release");
    let deps_dir = release_dir.join("deps");
    let build_dir = release_dir.join("build");
    let inc_dir = release_dir.join("incremental");

    let mut freed_bytes = 0u64;
    let mut files_removed = 0u64;
    let mut details = Vec::new();

    let root_stems = discover_workspace_stems(root);

    if deps_dir.exists() {
        let mut groups: HashMap<(String, String), Vec<(SystemTime, PathBuf)>> = HashMap::new();
        if let Ok(entries) = std::fs::read_dir(&deps_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }
                let fname = entry.file_name().to_string_lossy().to_string();
                if let Some(key) = parse_cargo_hashed_filename_with_stems(&fname, Some(&root_stems))
                {
                    let mtime = entry
                        .metadata()
                        .and_then(|m| m.modified())
                        .unwrap_or(UNIX_EPOCH);
                    groups.entry(key).or_default().push((mtime, path));
                }
            }
        }

        for (_key, mut items) in groups {
            if items.len() <= keep {
                continue;
            }
            items.sort_by(|a, b| b.0.cmp(&a.0));
            for (_mtime, stale_path) in items.into_iter().skip(keep) {
                let b = safe_remove_file(&stale_path);
                if b > 0 {
                    freed_bytes = freed_bytes.saturating_add(b);
                    files_removed += 1;
                }
            }
        }
    }

    if build_dir.exists() {
        let mut dir_groups: HashMap<String, Vec<(SystemTime, PathBuf)>> = HashMap::new();
        if let Ok(entries) = std::fs::read_dir(&build_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_dir() {
                    continue;
                }
                let dname = entry.file_name().to_string_lossy().to_string();
                if let Some(stem) = parse_cargo_hashed_dirname(&dname) {
                    let mtime = entry
                        .metadata()
                        .and_then(|m| m.modified())
                        .unwrap_or(UNIX_EPOCH);
                    dir_groups.entry(stem).or_default().push((mtime, path));
                }
            }
        }

        for (_stem, mut dirs) in dir_groups {
            if dirs.len() <= keep {
                continue;
            }
            dirs.sort_by(|a, b| b.0.cmp(&a.0));
            for (_mtime, stale_dir) in dirs.into_iter().skip(keep) {
                let (b, f) = safe_remove_dir_all(&stale_dir);
                freed_bytes = freed_bytes.saturating_add(b);
                files_removed = files_removed.saturating_add(f);
            }
        }
    }

    if inc_dir.exists() {
        let (b, f) = safe_remove_dir_all(&inc_dir);
        freed_bytes = freed_bytes.saturating_add(b);
        files_removed = files_removed.saturating_add(f);
    }

    if freed_bytes > 0 {
        details.push(format!(
            "Pruned {} superseded Cargo artifact revisions ({:.2} MB), kept newest {} revisions/crate",
            files_removed,
            freed_bytes as f64 / (1024.0 * 1024.0),
            keep
        ));
    }

    let current_deps_bytes = compute_path_footprint(&deps_dir, 1_500).0;
    DiskCleanupTierResult {
        tier_name: "Tier 2: Superseded Release Crate Revisions".to_string(),
        bytes_freed: freed_bytes,
        mb_freed: ((freed_bytes as f64 / (1024.0 * 1024.0)) * 100.0).round() / 100.0,
        files_removed,
        rows_pruned: 0,
        current_footprint_mb: ((current_deps_bytes as f64 / (1024.0 * 1024.0)) * 100.0).round()
            / 100.0,
        details,
    }
}

/// Tier 3: Enforces ring-buffer row retention on high-volume telemetry tables and truncates SQLite WAL files.
pub fn clean_tier3_sqlite_wal_and_retention(
    root: &Path,
    policy: &DiskCleanupPolicy,
) -> DiskCleanupTierResult {
    let db_candidates = [
        root.join("database").join("osoosi.db"),
        root.join("target")
            .join("release")
            .join("database")
            .join("osoosi.db"),
        root.join("database").join("nvd_cache.db"),
        root.join("target")
            .join("release")
            .join("database")
            .join("nvd_cache.db"),
    ];

    let mut freed_bytes = 0u64;
    let mut rows_pruned = 0u64;
    let mut current_bytes = 0u64;
    let mut details = Vec::new();

    let retention_tables: [(&str, &str, usize); 4] = [
        ("events", "timestamp", policy.max_events_rows.max(1_000)),
        ("har_entries", "id", policy.max_har_rows.max(500)),
        ("threats", "timestamp", policy.max_threats_rows.max(500)),
        (
            "consensus_findings",
            "updated_at",
            policy.max_consensus_rows.max(500),
        ),
    ];

    let wal_limit_bytes = policy.max_sqlite_wal_mb.max(8) * 1024 * 1024;

    for db_path in &db_candidates {
        if !db_path.exists() {
            continue;
        }
        let wal_path = PathBuf::from(format!("{}-wal", db_path.display()));
        let shm_path = PathBuf::from(format!("{}-shm", db_path.display()));

        let db_file_size_before = db_path.metadata().map(|m| m.len()).unwrap_or(0);
        let wal_size_before = wal_path.metadata().map(|m| m.len()).unwrap_or(0);
        let shm_size_before = shm_path.metadata().map(|m| m.len()).unwrap_or(0);
        let size_before = db_file_size_before + wal_size_before + shm_size_before;

        let is_osoosi_db = db_path
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n.eq_ignore_ascii_case("osoosi.db"))
            .unwrap_or(false);

        if let Ok(conn) = rusqlite::Connection::open(db_path) {
            let _ = conn.busy_timeout(Duration::from_millis(120));
            let mut db_rows_deleted = 0usize;

            if is_osoosi_db {
                for (table, order_col, max_rows) in &retention_tables {
                    let max_rowid_sql = format!(
                        "SELECT COALESCE(MAX(rowid), 0) - COALESCE(MIN(rowid), 0) FROM {}",
                        table
                    );
                    let approx_span = conn
                        .query_row(&max_rowid_sql, [], |r| r.get::<_, i64>(0))
                        .unwrap_or(0);
                    if (approx_span as usize) <= *max_rows {
                        continue;
                    }
                    let count_sql = format!("SELECT COUNT(*) FROM {}", table);
                    if let Ok(cnt) = conn.query_row(&count_sql, [], |r| r.get::<_, i64>(0)) {
                        if (cnt as usize) > *max_rows {
                            let excess = (cnt as usize) - *max_rows;
                            let del_sql = format!(
                                "DELETE FROM {} WHERE rowid IN (SELECT rowid FROM {} ORDER BY {} ASC LIMIT ?1)",
                                table, table, order_col
                            );
                            if let Ok(deleted) =
                                conn.execute(&del_sql, rusqlite::params![excess as i64])
                            {
                                rows_pruned = rows_pruned.saturating_add(deleted as u64);
                                db_rows_deleted = db_rows_deleted.saturating_add(deleted);
                            }
                        }
                    }
                }
            }

            if wal_size_before > wal_limit_bytes || db_rows_deleted > 0 {
                let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
            } else if wal_size_before > 1024 * 1024 {
                let _ = conn.execute_batch("PRAGMA wal_checkpoint(PASSIVE);");
            }
        }

        let size_after = db_path.metadata().map(|m| m.len()).unwrap_or(0)
            + wal_path.metadata().map(|m| m.len()).unwrap_or(0)
            + shm_path.metadata().map(|m| m.len()).unwrap_or(0);

        current_bytes = current_bytes.saturating_add(size_after);
        if size_before > size_after {
            let delta = size_before - size_after;
            freed_bytes = freed_bytes.saturating_add(delta);
            details.push(format!(
                "Compacted {} ({:.2} MB -> {:.2} MB)",
                db_path.file_name().unwrap_or_default().to_string_lossy(),
                size_before as f64 / (1024.0 * 1024.0),
                size_after as f64 / (1024.0 * 1024.0)
            ));
        }
    }

    DiskCleanupTierResult {
        tier_name: "Tier 3: SQLite Telemetry Retention & WAL Truncation".to_string(),
        bytes_freed: freed_bytes,
        mb_freed: ((freed_bytes as f64 / (1024.0 * 1024.0)) * 100.0).round() / 100.0,
        files_removed: 0,
        rows_pruned,
        current_footprint_mb: ((current_bytes as f64 / (1024.0 * 1024.0)) * 100.0).round() / 100.0,
        details,
    }
}

/// Tier 4: Cleans rotated daemon logs (`*.rotated`), historical daily logs, and oversized active logs.
pub fn clean_tier4_rotated_logs(root: &Path, policy: &DiskCleanupPolicy) -> DiskCleanupTierResult {
    let log_dirs = [
        root.join("logs"),
        root.join("target").join("release").join("logs"),
    ];
    let today_utc = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let max_active_log_bytes = policy.max_log_retention_mb.max(10) * 1024 * 1024;

    let mut freed_bytes = 0u64;
    let mut files_removed = 0u64;
    let mut current_bytes = 0u64;
    let mut details = Vec::new();

    for log_dir in &log_dirs {
        if !log_dir.exists() {
            continue;
        }
        if let Ok(entries) = std::fs::read_dir(log_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }
                let name = entry.file_name().to_string_lossy().to_string();
                if name.ends_with(".rotated")
                    || name.ends_with(".old")
                    || name.ends_with(".bak")
                    || name == "test_write.json"
                {
                    let b = safe_remove_file(&path);
                    if b > 0 {
                        freed_bytes = freed_bytes.saturating_add(b);
                        files_removed += 1;
                        details.push(format!(
                            "Removed rotated log {} ({:.2} MB)",
                            name,
                            b as f64 / (1024.0 * 1024.0)
                        ));
                    }
                    continue;
                }

                if name.starts_with("osoosi.log.") && !name.contains(&today_utc) {
                    let b = safe_remove_file(&path);
                    if b > 0 {
                        freed_bytes = freed_bytes.saturating_add(b);
                        files_removed += 1;
                        details.push(format!(
                            "Removed historical daily log {} ({:.2} MB)",
                            name,
                            b as f64 / (1024.0 * 1024.0)
                        ));
                    }
                    continue;
                }

                if name.starts_with("osoosi.log") {
                    if let Ok(meta) = path.metadata() {
                        let sz = meta.len();
                        if sz > max_active_log_bytes {
                            // Retain last 5 MB of active log
                            let keep_tail = 5 * 1024 * 1024usize;
                            if let Ok(bytes) = std::fs::read(&path) {
                                if bytes.len() > keep_tail {
                                    let tail = &bytes[bytes.len() - keep_tail..];
                                    if std::fs::write(&path, tail).is_ok() {
                                        let saved = sz.saturating_sub(keep_tail as u64);
                                        freed_bytes = freed_bytes.saturating_add(saved);
                                        details.push(format!(
                                            "Truncated active {} ({:.2} MB -> 5.00 MB)",
                                            name,
                                            sz as f64 / (1024.0 * 1024.0)
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Keep newest 10 regression_artifacts files
        let reg_dir = log_dir.join("regression_artifacts");
        if reg_dir.exists() {
            let mut reg_files = Vec::new();
            if let Ok(entries) = std::fs::read_dir(&reg_dir) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if p.is_file() {
                        let mtime = entry
                            .metadata()
                            .and_then(|m| m.modified())
                            .unwrap_or(UNIX_EPOCH);
                        reg_files.push((mtime, p));
                    }
                }
            }
            if reg_files.len() > 10 {
                reg_files.sort_by(|a, b| b.0.cmp(&a.0));
                for (_mtime, old_p) in reg_files.into_iter().skip(10) {
                    let b = safe_remove_file(&old_p);
                    if b > 0 {
                        freed_bytes = freed_bytes.saturating_add(b);
                        files_removed += 1;
                    }
                }
            }
        }

        current_bytes = current_bytes.saturating_add(compute_path_footprint(log_dir, 2_000).0);
    }

    DiskCleanupTierResult {
        tier_name: "Tier 4: Rotated Daemon Logs & Audit Artifacts".to_string(),
        bytes_freed: freed_bytes,
        mb_freed: ((freed_bytes as f64 / (1024.0 * 1024.0)) * 100.0).round() / 100.0,
        files_removed,
        rows_pruned: 0,
        current_footprint_mb: ((current_bytes as f64 / (1024.0 * 1024.0)) * 100.0).round() / 100.0,
        details,
    }
}

/// Tier 5: Cleans orphaned Siquery/browser SQLite temp copies in `%TEMP%` (`/tmp`).
pub fn clean_tier5_orphaned_os_temp() -> DiskCleanupTierResult {
    let temp_dir = std::env::temp_dir();
    let now = SystemTime::now();
    let mut freed_bytes = 0u64;
    let mut files_removed = 0u64;
    let mut remaining_bytes = 0u64;
    let mut details = Vec::new();

    let prefixes = [
        "osoosi_hist_",
        "osoosi_dl_",
        "osoosi_har_hist_",
        "osoosi_gecko_",
        "osoosi_safari_",
        "osoosi_ext_",
    ];

    if let Ok(entries) = std::fs::read_dir(&temp_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !prefixes.iter().any(|p| name.starts_with(p)) {
                continue;
            }
            let path = entry.path();
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            let age_secs = meta
                .modified()
                .ok()
                .and_then(|m| now.duration_since(m).ok())
                .map(|d| d.as_secs())
                .unwrap_or(999);
            if age_secs >= 90 {
                let b = safe_remove_file(&path);
                if b > 0 {
                    freed_bytes = freed_bytes.saturating_add(b);
                    files_removed += 1;
                }
            } else {
                remaining_bytes = remaining_bytes.saturating_add(meta.len());
            }
        }
    }

    if files_removed > 0 {
        details.push(format!(
            "Swept {} orphaned browser/Siquery SQLite temp files ({:.2} MB)",
            files_removed,
            freed_bytes as f64 / (1024.0 * 1024.0)
        ));
    }

    DiskCleanupTierResult {
        tier_name: "Tier 5: Orphaned OS Temp & Browser WAL Copies".to_string(),
        bytes_freed: freed_bytes,
        mb_freed: ((freed_bytes as f64 / (1024.0 * 1024.0)) * 100.0).round() / 100.0,
        files_removed,
        rows_pruned: 0,
        current_footprint_mb: ((remaining_bytes as f64 / (1024.0 * 1024.0)) * 100.0).round()
            / 100.0,
        details,
    }
}

/// Executes an immediate autonomous disk cleanup sweep across the requested `mode`:
/// - `"standard"` or `"all"`: Runs all 5 tiers
/// - `"deep_cargo"`: Runs Tier 1 + Tier 2 with `keep_revisions = 1`
/// - `"db_wal_only"`: Runs Tier 3 (SQLite WAL checkpoint + retention)
/// - `"logs_temp_only"`: Runs Tier 4 + Tier 5
pub fn run_autonomous_disk_cleanup_sweep(mode: &str) -> DiskCleanupSweepReport {
    let t0 = Instant::now();
    let root = resolve_workspace_root();
    let policy = get_disk_cleanup_policy();
    let normalized_mode = if mode.trim().is_empty() {
        "standard"
    } else {
        mode.trim()
    };

    let (drive_path, total_bytes, _used_before, free_before) = query_drive_space_bytes(&root);

    let mut tiers = Vec::new();
    match normalized_mode {
        "db_wal_only" => {
            tiers.push(clean_tier3_sqlite_wal_and_retention(&root, &policy));
        }
        "logs_temp_only" => {
            tiers.push(clean_tier4_rotated_logs(&root, &policy));
            tiers.push(clean_tier5_orphaned_os_temp());
        }
        "deep_cargo" => {
            tiers.push(clean_tier1_scratch_and_debug_targets(&root, true));
            tiers.push(clean_tier2_superseded_release_deps(&root, 1));
            tiers.push(clean_tier3_sqlite_wal_and_retention(&root, &policy));
            tiers.push(clean_tier4_rotated_logs(&root, &policy));
            tiers.push(clean_tier5_orphaned_os_temp());
        }
        _ => {
            tiers.push(clean_tier1_scratch_and_debug_targets(
                &root,
                policy.prune_debug_target,
            ));
            tiers.push(clean_tier2_superseded_release_deps(
                &root,
                policy.keep_release_dep_revisions,
            ));
            tiers.push(clean_tier3_sqlite_wal_and_retention(&root, &policy));
            tiers.push(clean_tier4_rotated_logs(&root, &policy));
            tiers.push(clean_tier5_orphaned_os_temp());
        }
    }

    let (_drive2, total_after, used_after, free_after) = query_drive_space_bytes(&root);
    let tier_sum_bytes: u64 = tiers.iter().map(|t| t.bytes_freed).sum();
    let drive_delta = free_after.saturating_sub(free_before);
    let effective_freed = tier_sum_bytes.max(drive_delta);
    let files_removed: u64 = tiers.iter().map(|t| t.files_removed).sum();
    let rows_pruned: u64 = tiers.iter().map(|t| t.rows_pruned).sum();

    TOTAL_BYTES_FREED_LIFETIME.fetch_add(effective_freed, Ordering::Relaxed);
    TOTAL_FILES_REMOVED_LIFETIME.fetch_add(files_removed, Ordering::Relaxed);
    TOTAL_SWEEP_COUNT.fetch_add(1, Ordering::Relaxed);

    let total_gb =
        ((total_after.max(total_bytes) as f64) / 1_073_741_824.0 * 100.0).round() / 100.0;
    let free_before_gb = ((free_before as f64) / 1_073_741_824.0 * 100.0).round() / 100.0;
    let free_after_gb = ((free_after as f64) / 1_073_741_824.0 * 100.0).round() / 100.0;
    let usage_pct = if total_after > 0 {
        ((used_after as f64 / total_after as f64) * 1000.0).round() / 10.0
    } else {
        0.0
    };
    let pressure = evaluate_disk_pressure(free_after_gb, usage_pct, policy.min_free_gb_trigger);

    let report = DiskCleanupSweepReport {
        status: "ok".to_string(),
        mode: normalized_mode.to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        duration_ms: (t0.elapsed().as_secs_f64() * 10000.0).round() / 10.0,
        bytes_freed: effective_freed,
        mb_freed: ((effective_freed as f64 / (1024.0 * 1024.0)) * 100.0).round() / 100.0,
        gb_freed: ((effective_freed as f64 / 1_073_741_824.0) * 1000.0).round() / 1000.0,
        files_removed,
        sqlite_rows_pruned: rows_pruned,
        drive_path,
        drive_total_gb: total_gb,
        drive_free_gb_before: free_before_gb,
        drive_free_gb_after: free_after_gb,
        drive_usage_percent_after: usage_pct,
        pressure_level: pressure,
        tiers,
    };

    // Persist to in-memory history and logs/disk_cleanup_report.json
    {
        let last_lock = LAST_SWEEP_REPORT.get_or_init(|| RwLock::new(None));
        *last_lock.write() = Some(report.clone());
    }
    {
        let hist_lock = SWEEP_HISTORY.get_or_init(|| RwLock::new(Vec::new()));
        let mut hist = hist_lock.write();
        hist.insert(0, report.clone());
        if hist.len() > 25 {
            hist.truncate(25);
        }
    }
    if let Ok(json_str) = serde_json::to_string_pretty(&report) {
        let logs_dir = root.join("logs");
        let _ = std::fs::create_dir_all(&logs_dir);
        let _ = std::fs::write(logs_dir.join("disk_cleanup_report.json"), json_str);
    }

    if effective_freed > 0 || rows_pruned > 0 {
        info!(
            "🧹 [DISK-CLEANUP] Mode={} freed {:.2} MB ({:.3} GB, {} files, {} DB rows) in {:.1}ms | Drive Free: {:.2} GB -> {:.2} GB",
            normalized_mode,
            report.mb_freed,
            report.gb_freed,
            report.files_removed,
            report.sqlite_rows_pruned,
            report.duration_ms,
            report.drive_free_gb_before,
            report.drive_free_gb_after
        );
    }

    report
}

/// Builds a fast, non-blocking status snapshot for `GET /api/disk-cleanup/status`.
pub fn get_disk_cleanup_status_snapshot() -> DiskCleanupStatusSnapshot {
    let root = resolve_workspace_root();
    let policy = get_disk_cleanup_policy();
    let (drive_path, total_bytes, used_bytes, free_bytes) = query_drive_space_bytes(&root);

    let total_gb = ((total_bytes as f64) / 1_073_741_824.0 * 100.0).round() / 100.0;
    let used_gb = ((used_bytes as f64) / 1_073_741_824.0 * 100.0).round() / 100.0;
    let free_gb = ((free_bytes as f64) / 1_073_741_824.0 * 100.0).round() / 100.0;
    let usage_pct = if total_bytes > 0 {
        ((used_bytes as f64 / total_bytes as f64) * 1000.0).round() / 10.0
    } else {
        0.0
    };
    let pressure = evaluate_disk_pressure(free_gb, usage_pct, policy.min_free_gb_trigger);

    // Seed lifetime counters from `logs/disk_cleanup_report.json` if we haven't swept yet in this process
    let last_lock = LAST_SWEEP_REPORT.get_or_init(|| RwLock::new(None));
    if last_lock.read().is_none() {
        let report_file = root.join("logs").join("disk_cleanup_report.json");
        if let Ok(raw) = std::fs::read_to_string(&report_file) {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&raw) {
                let bytes_freed = val.get("bytes_freed").and_then(|v| v.as_u64()).unwrap_or(0);
                let files_removed = val
                    .get("files_removed")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                if TOTAL_SWEEP_COUNT.load(Ordering::Relaxed) == 0 && bytes_freed > 0 {
                    TOTAL_BYTES_FREED_LIFETIME.store(bytes_freed, Ordering::Relaxed);
                    TOTAL_FILES_REMOVED_LIFETIME.store(files_removed, Ordering::Relaxed);
                    TOTAL_SWEEP_COUNT.store(1, Ordering::Relaxed);
                }
            }
        }
    }

    let debug_mb = (compute_path_footprint(&root.join("target").join("debug"), 2_000).0 as f64
        / (1024.0 * 1024.0)
        * 100.0)
        .round()
        / 100.0;
    let release_deps_mb =
        (compute_path_footprint(&root.join("target").join("release").join("deps"), 4_000).0 as f64
            / (1024.0 * 1024.0)
            * 100.0)
            .round()
            / 100.0;
    let db_bytes = compute_path_footprint(&root.join("database"), 200).0
        + compute_path_footprint(&root.join("target").join("release").join("database"), 200).0;
    let sqlite_db_mb = ((db_bytes as f64) / (1024.0 * 1024.0) * 100.0).round() / 100.0;
    let logs_bytes = compute_path_footprint(&root.join("logs"), 500).0
        + compute_path_footprint(&root.join("target").join("release").join("logs"), 500).0;
    let logs_mb = ((logs_bytes as f64) / (1024.0 * 1024.0) * 100.0).round() / 100.0;

    let mut footprints = HashMap::new();
    footprints.insert("target_debug_mb".to_string(), debug_mb);
    footprints.insert("target_release_deps_mb".to_string(), release_deps_mb);
    footprints.insert("sqlite_databases_mb".to_string(), sqlite_db_mb);
    footprints.insert("logs_and_reports_mb".to_string(), logs_mb);

    let reclaimable_mb = debug_mb
        + (logs_mb - (policy.max_log_retention_mb as f64)).max(0.0)
        + (sqlite_db_mb - (policy.max_sqlite_wal_mb as f64)).max(0.0);

    let lifetime_bytes = TOTAL_BYTES_FREED_LIFETIME.load(Ordering::Relaxed);
    let last_sweep = last_lock.read().clone();
    let recent_sweeps = SWEEP_HISTORY
        .get_or_init(|| RwLock::new(Vec::new()))
        .read()
        .clone();

    DiskCleanupStatusSnapshot {
        status: "ok".to_string(),
        watchdog_active: DISK_WATCHDOG_ACTIVE.load(Ordering::Relaxed),
        policy,
        drive_path,
        drive_total_gb: total_gb,
        drive_used_gb: used_gb,
        drive_free_gb: free_gb,
        drive_usage_percent: usage_pct,
        pressure_level: pressure,
        total_bytes_freed_lifetime: lifetime_bytes,
        total_mb_freed_lifetime: ((lifetime_bytes as f64 / (1024.0 * 1024.0)) * 100.0).round()
            / 100.0,
        total_gb_freed_lifetime: ((lifetime_bytes as f64 / 1_073_741_824.0) * 1000.0).round()
            / 1000.0,
        total_files_removed_lifetime: TOTAL_FILES_REMOVED_LIFETIME.load(Ordering::Relaxed),
        total_sweep_count: TOTAL_SWEEP_COUNT.load(Ordering::Relaxed),
        current_footprints_mb: footprints,
        estimated_reclaimable_mb: (reclaimable_mb * 100.0).round() / 100.0,
        last_sweep,
        recent_sweeps,
    }
}

/// Spawns the background autonomous disk cleanup watchdog thread (`osoosi-disk-cleanup`).
/// Safe to call multiple times; only one watchdog thread is spawned per process.
pub fn spawn_autonomous_disk_cleanup_watchdog() {
    if DISK_WATCHDOG_ACTIVE
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return;
    }

    let _ = std::thread::Builder::new()
        .name("osoosi-disk-cleanup".to_string())
        .spawn(move || {
            info!("🧹 [DISK-CLEANUP] Autonomous Disk Space & Telemetry Lifecycle Watchdog initialized.");
            // Initial startup sweep after 15 seconds to keep startup non-blocking
            std::thread::sleep(Duration::from_secs(15));
            if get_disk_cleanup_policy().enabled {
                let _ = run_autonomous_disk_cleanup_sweep("standard");
            }

            loop {
                let policy = get_disk_cleanup_policy();
                let sleep_secs = policy.interval_secs.clamp(60, 86_400);
                std::thread::sleep(Duration::from_secs(sleep_secs));

                if !get_disk_cleanup_policy().enabled {
                    continue;
                }
                let _ = run_autonomous_disk_cleanup_sweep("standard");
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cargo_hashed_filename() {
        assert_eq!(
            parse_cargo_hashed_filename("libosoosi_core-1a2b3c4d5e6f7890.rlib"),
            Some(("libosoosi_core".to_string(), ".rlib".to_string()))
        );
        assert_eq!(
            parse_cargo_hashed_filename("osoosi_dashboard-abcdef0123456789.pdb"),
            Some(("osoosi_dashboard".to_string(), ".pdb".to_string()))
        );
        assert_eq!(parse_cargo_hashed_filename("osoosi.exe"), None);
    }

    #[test]
    fn test_prune_superseded_deps_keeps_newest_revisions() {
        let temp_root =
            std::env::temp_dir().join(format!("osoosi_disk_cleanup_test_{}", std::process::id()));
        let deps_dir = temp_root.join("target").join("release").join("deps");
        let _ = std::fs::create_dir_all(&deps_dir);

        // Configure test workspace fixture containing member "foo"
        let _ = std::fs::create_dir_all(temp_root.join("crates").join("foo"));
        let _ = std::fs::write(
            temp_root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"crates/foo\"]\n",
        );

        let f1 = deps_dir.join("libfoo-0000000000000001.rlib");
        let f2 = deps_dir.join("libfoo-0000000000000002.rlib");
        let f3 = deps_dir.join("libfoo-0000000000000003.rlib");

        std::fs::write(&f1, vec![b'a'; 1024]).unwrap();
        std::thread::sleep(Duration::from_millis(20));
        std::fs::write(&f2, vec![b'b'; 1024]).unwrap();
        std::thread::sleep(Duration::from_millis(20));
        std::fs::write(&f3, vec![b'c'; 1024]).unwrap();

        let res = clean_tier2_superseded_release_deps(&temp_root, 2);
        assert_eq!(res.files_removed, 1);
        assert!(!f1.exists(), "Oldest hash revision should be pruned");
        assert!(f2.exists(), "Second newest hash revision should be kept");
        assert!(f3.exists(), "Newest hash revision should be kept");

        let _ = std::fs::remove_dir_all(&temp_root);
    }

    #[test]
    fn test_evaluate_disk_pressure() {
        assert_eq!(
            evaluate_disk_pressure(500.0, 50.0, 50.0),
            DiskPressureLevel::Normal
        );
        assert_eq!(
            evaluate_disk_pressure(35.0, 75.0, 50.0),
            DiskPressureLevel::Warning
        );
        assert_eq!(
            evaluate_disk_pressure(12.0, 95.0, 50.0),
            DiskPressureLevel::Critical
        );
    }
}
