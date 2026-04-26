//! Real-time file system monitoring.
//!
//! Uses the `notify` crate to detect file creations and modifications.

use crate::hash::calculate_blake3_hash;
use chrono::Utc;
use notify::{Event, EventKind, RecursiveMode, Watcher};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use sysinfo::{Pid, System};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Files and paths to skip: SQLite ephemeral, OpenỌ̀ṣọ́ọ̀sì's own data, common noisy dirs, and user exclusions.
fn should_skip_path(path: &Path, osoosi_dir: &Path, exclude_paths: &[String]) -> bool {
    let s = path.to_string_lossy();
    let s_lower = s.to_lowercase();

    // SQLite ephemeral files
    if s_lower.ends_with("-journal")
        || s_lower.ends_with(".db-journal")
        || s_lower.ends_with("-wal")
        || s_lower.ends_with(".db-wal")
        || s_lower.ends_with("-shm")
        || s_lower.ends_with(".db-shm")
    {
        return true;
    }

    // OpenỌ̀ṣọ́ọ̀sì's own files (self-writes cause feedback loop)
    // Check for both the exact name and common log rotation patterns (.log.2026-04-23, .log.1, etc)
    if s_lower.contains("osoosi.db")
        || s_lower.contains("osoosi.log")
        || s_lower.contains("osoosi_core.log")
    {
        return true;
    }

    // Skip the entire OpenỌ̀ṣọ́ọ̀sì install directory (canonical comparison if possible)
    if let Ok(canon_path) = path.canonicalize() {
        if canon_path.starts_with(osoosi_dir) {
            return true;
        }
    }

    // Belt-and-suspenders: also check via string prefix (case-insensitive on Windows)
    let dir_str = osoosi_dir
        .to_string_lossy()
        .to_lowercase()
        .replace("\\\\?\\", "");
    let s_clean = s_lower.replace("\\\\?\\", "");
    if s_clean.starts_with(&dir_str) {
        return true;
    }

    // Registry transaction logs (always locked by Windows)
    let fname = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if fname.starts_with("ntuser.dat.LOG") || fname.starts_with("usrclass.dat.LOG") {
        return true;
    }

    // Common noisy directories
    for segment in path.components() {
        let seg = segment.as_os_str().to_string_lossy().to_lowercase();
        match seg.as_ref() {
            ".git"
            | "node_modules"
            | "target"
            | "__pycache__"
            | "$recycle.bin"
            | "system volume information"
            | ".trash"
            | "appdata"
            | "windows"
            | "programdata" => return true,
            _ => {}
        }
    }

    // User-defined exclusions
    for exclude in exclude_paths {
        let clean_exclude = exclude.to_lowercase().replace("\\\\?\\", "");
        if s_clean.contains(&clean_exclude) {
            return true;
        }
    }

    false
}

/// Auto-detect the OpenỌ̀ṣọ́ọ̀sì install directory (the CWD of the running process).
/// Canonicalized so path comparisons work even when notify produces .\-style paths.
fn osoosi_install_dir() -> std::path::PathBuf {
    std::env::current_dir()
        .and_then(|p| p.canonicalize())
        .unwrap_or_else(|_| {
            std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."))
        })
}

pub struct FileWatcher {
    watcher: notify::RecommendedWatcher,
    pub trap_paths: Arc<dashmap::DashSet<String>>,
}

#[derive(Debug, Clone)]
pub struct FileChangeEvent {
    pub path: String,
    pub hash: String,
    pub kind: EventKind,
}

impl FileWatcher {
    /// Create a new file watcher. Pass `Some(memory)` to persist unhashable paths to a skip list.
    pub fn new(
        memory: Option<Arc<osoosi_memory::MemoryStore>>,
        exclude_paths: Vec<String>,
    ) -> anyhow::Result<(Self, mpsc::Receiver<anyhow::Result<FileChangeEvent>>)> {
        let (tx, rx) = mpsc::channel(100);
        let rt = tokio::runtime::Handle::current();
        let install_dir = osoosi_install_dir();
        let excludes = exclude_paths.clone();
        let trap_paths = Arc::new(dashmap::DashSet::new());
        let traps = trap_paths.clone();

        // Notify watcher callback
        let watcher = notify::recommended_watcher(move |res: notify::Result<Event>| {
            match res {
                Ok(event) => {
                    if event.kind.is_access() || event.kind.is_create() || event.kind.is_modify() {
                        for path in event.paths {
                            if !path.is_file() || should_skip_path(&path, &install_dir, &excludes) {
                                continue;
                            }

                            let path_str = path.to_string_lossy().to_string();

                            // IMMEDIATE TRAP DETECTION
                            if traps.contains(&path_str) {
                                warn!("HONEYTOKEN ACCESS DETECTED: {} - Triggering immediate quarantine!", path_str);
                                // In a real implementation, this would call the quarantine module
                            }

                            // Check SQLite skip list (files that previously failed to hash)
                            if let Some(ref mem) = memory {
                                if mem.is_file_in_skip_list(&path_str).unwrap_or(false) {
                                    debug!("Skipped (in skip list): {}", path_str);
                                    continue;
                                }
                            }
                            let tx = tx.clone();
                            let kind = event.kind;
                            let path_for_hash = path.clone();
                            let memory_for_error = memory.clone();

                            rt.spawn(async move {
                                match calculate_blake3_hash(&path_for_hash).await {
                                    Ok(hash) => {
                                        let _ = tx
                                            .send(Ok(FileChangeEvent {
                                                path: path_str,
                                                hash,
                                                kind,
                                            }))
                                            .await;
                                    }
                                    Err(e) => {
                                        let err_str = e.to_string();
                                        let is_not_found = e
                                            .downcast_ref::<std::io::Error>()
                                            .map(|io| io.kind() == std::io::ErrorKind::NotFound)
                                            .unwrap_or(false)
                                            || err_str.contains("cannot find")
                                            || err_str.contains("No such file");
                                        let is_locked = err_str
                                            .contains("being used by another process")
                                            || err_str.contains("Permission denied")
                                            || err_str.contains("Access is denied")
                                            || err_str.contains("os error 32");
                                        if is_not_found {
                                            debug!(
                                                "Skipped hashing (file gone): {:?}",
                                                path_for_hash
                                            );
                                        } else if is_locked {
                                            if let Some(ref mem) = memory_for_error {
                                                let _ = mem.add_file_to_skip_list(
                                                    &path_for_hash.to_string_lossy(),
                                                    &err_str,
                                                );
                                                debug!(
                                                    "Added to skip list (locked): {}",
                                                    path_for_hash.to_string_lossy()
                                                );
                                            } else {
                                                error!(
                                                    "Failed to hash file {:?}: {}",
                                                    path_for_hash, e
                                                );
                                            }
                                        } else {
                                            error!(
                                                "Failed to hash file {:?}: {}",
                                                path_for_hash, e
                                            );
                                        }
                                    }
                                }
                            });
                        }
                    }
                }
                Err(e) => {
                    let _ = tx.try_send(Err(anyhow::anyhow!("Watcher error: {}", e)));
                }
            }
        })?;

        Ok((
            Self {
                watcher,
                trap_paths,
            },
            rx,
        ))
    }

    pub fn watch<P: AsRef<Path>>(&mut self, path: P) -> anyhow::Result<()> {
        info!("Starting watch on: {:?}", path.as_ref());
        self.watcher
            .watch(path.as_ref(), RecursiveMode::Recursive)?;
        Ok(())
    }
}

/// Run a background task on startup to build a baseline hash table of every file in the watch paths.
/// This hashes the entire filesystem from the specified roots and stores it in SQLite
/// so we can understand file changes and verify updates/patches.
pub async fn build_os_file_hash_baseline(
    paths: Vec<String>,
    memory: Arc<osoosi_memory::MemoryStore>,
    exclude_paths: Vec<String>,
) {
    info!(
        "Starting background hash of all files in watch paths: {}",
        paths.join(", ")
    );
    let _ = memory.set_repair_status("baseline_status", "running");
    let _ = memory.set_repair_status("baseline_start", &Utc::now().to_rfc3339());
    let _ = memory.set_repair_status("baseline_count", "0");

    // Run walkdir on a blocking thread because it is synchronous.
    // We collect paths and send them over a channel to be hashed asynchronously.
    let (tx, mut rx) = mpsc::channel::<std::path::PathBuf>(10000);
    let install_dir = osoosi_install_dir();

    tokio::task::spawn_blocking(move || {
        for root in paths {
            for entry in walkdir::WalkDir::new(&root)
                .into_iter()
                .filter_entry(|e| !should_skip_path(e.path(), &install_dir, &exclude_paths))
                .filter_map(|e| e.ok())
            {
                if entry.file_type().is_file() && tx.blocking_send(entry.into_path()).is_err() {
                    return;
                }
            }
        }
    });

    let mut join_set = tokio::task::JoinSet::new();
    let hashed_count = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let mut last_report = std::time::Instant::now();
    let mut sys = System::new_all();
    let self_pid = Pid::from(std::process::id() as usize);

    // Dynamic throttling parameters
    let mut current_concurrency = std::env::var("OSOOSI_BASELINE_CONCURRENCY")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(20); // Lowered default
    let min_concurrency = 1;
    let _target_cpu_usage = 40.0; // Don't use more than 40% of a single core for hashing if global load is high

    while let Some(path) = rx.recv().await {
        // 1. Periodically check system load and adjust throttle
        if last_report.elapsed().as_secs() >= 5 {
            sys.refresh_all();
            let total_cpu = sys.global_cpu_info().cpu_usage();
            let process_cpu = sys.process(self_pid).map(|p| p.cpu_usage()).unwrap_or(0.0);

            // If system is heavily loaded or we are exceeding our own "fair share"
            if total_cpu > 70.0 || process_cpu > 50.0 {
                current_concurrency = (current_concurrency / 2).max(min_concurrency);
                debug!("Resource throttling active: CPU {:.1}% (Agent {:.1}%), reducing concurrency to {}", total_cpu, process_cpu, current_concurrency);
                // Introduce a small pause to let the OS breathe
                tokio::time::sleep(Duration::from_millis(100)).await;
            } else if total_cpu < 30.0 && process_cpu < 20.0 {
                // Calm system, can ramp up slightly
                current_concurrency = (current_concurrency + 2).min(50);
            }

            let current = hashed_count.load(std::sync::atomic::Ordering::Relaxed);
            let _ = memory.set_repair_status("baseline_count", &current.to_string());
            last_report = std::time::Instant::now();
        }

        // 2. Keep concurrency bounded
        while join_set.len() >= current_concurrency {
            let _ = join_set.join_next().await;
        }

        let mem = memory.clone();
        let path_str = path.to_string_lossy().to_string();
        let count_ptr = hashed_count.clone();

        // Skip files that previously errored out
        if mem.is_file_in_skip_list(&path_str).unwrap_or(false) {
            continue;
        }

        join_set.spawn(async move {
            // Use spawn_blocking for the actual hashing to avoid tokio fs overhead and allow BLAKE3 to run at full speed
            let res = tokio::task::spawn_blocking(move || {
                let data = std::fs::read(&path)?;
                Ok::<String, anyhow::Error>(blake3::hash(&data).to_hex().to_string())
            })
            .await;

            match res {
                Ok(Ok(hash)) => {
                    let _ = mem.update_file_hash(&path_str, &hash);
                    let current = count_ptr.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                    debug!("Baselined: {} -> {}", path_str, hash);

                    if current % 1000 == 0 {
                        info!("File baseline progress: {} files hashed", current);
                    }
                }
                Ok(Err(e)) => {
                    let err_str = e.to_string();
                    let is_locked = err_str.contains("being used by another process")
                        || err_str.contains("Permission denied")
                        || err_str.contains("Access is denied")
                        || err_str.contains("os error 32");

                    if is_locked {
                        let _ = mem.add_file_to_skip_list(&path_str, &err_str);
                    }
                }
                Err(e) => {
                    error!("Baseline task panicked for {}: {}", path_str, e);
                }
            }
        });

        // Periodic DB status update
        if last_report.elapsed().as_secs() >= 5 {
            let current = hashed_count.load(std::sync::atomic::Ordering::Relaxed);
            let _ = memory.set_repair_status("baseline_count", &current.to_string());
            last_report = std::time::Instant::now();
        }
    }

    // Wait for remaining tasks to complete
    while join_set.join_next().await.is_some() {}

    let final_count = hashed_count.load(std::sync::atomic::Ordering::Relaxed);
    let _ = memory.set_repair_status("baseline_count", &final_count.to_string());
    let _ = memory.set_repair_status("baseline_status", "finished");
    let _ = memory.set_repair_status("baseline_end", &Utc::now().to_rfc3339());
    info!(
        "Finished building baseline hash table: {} files total.",
        final_count
    );
}
