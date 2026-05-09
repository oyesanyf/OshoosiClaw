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
        || s_lower.ends_with(".lock")
        || s_lower.ends_with(".part")
        || s_lower.ends_with(".incomplete")
        || s_lower.ends_with(".tmp")
    {
        return true;
    }

    if s_lower.contains("osoosi.db")
        || s_lower.contains("osoosi.log")
        || s_lower.contains("osoosi_core.log")
    {
        return true;
    }

    if let Ok(canon_path) = path.canonicalize() {
        if canon_path.starts_with(osoosi_dir) {
            return true;
        }
    }

    let dir_str = osoosi_dir
        .to_string_lossy()
        .to_lowercase()
        .replace("\\\\?\\", "");
    let s_clean = s_lower.replace("\\\\?\\", "");
    if s_clean.starts_with(&dir_str) {
        return true;
    }

    let fname = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if fname.starts_with("ntuser.dat.LOG") || fname.starts_with("usrclass.dat.LOG") {
        return true;
    }

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
            | "programdata"
            | "google drive"
            | "onedrive"
            | "dropbox" => return true,
            _ => {}
        }
    }

    for exclude in exclude_paths {
        let clean_exclude = exclude.to_lowercase().replace("\\\\?\\", "");
        if s_clean.contains(&clean_exclude) {
            return true;
        }
    }

    false
}

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
    pub currently_hashing: Arc<dashmap::DashSet<String>>,
}

#[derive(Debug, Clone)]
pub struct FileChangeEvent {
    pub path: String,
    pub hash: String,
    pub kind: EventKind,
}

impl FileWatcher {
    pub fn new(
        memory: Option<Arc<osoosi_memory::MemoryStore>>,
        exclude_paths: Vec<String>,
        adaptive: Arc<dyn osoosi_types::TelemetryControllerInterface>,
    ) -> anyhow::Result<(Self, mpsc::Receiver<anyhow::Result<FileChangeEvent>>)> {
        let (tx, rx) = mpsc::channel(100);
        let (event_tx, mut event_rx) = mpsc::channel::<Event>(1000);
        let install_dir = osoosi_install_dir();
        let excludes = exclude_paths.clone();
        let trap_paths = Arc::new(dashmap::DashSet::new());
        let currently_hashing = Arc::new(dashmap::DashSet::new());
        let hashing_set = currently_hashing.clone();
        
        let watcher_tx = event_tx.clone();
        let watcher = notify::recommended_watcher(move |res: notify::Result<Event>| {
            if let Ok(event) = res {
                let _ = watcher_tx.try_send(event);
            }
        })?;

        // Background event processor
        let processor_tx = tx.clone();
        let processor_traps = trap_paths.clone();
        let processor_memory = memory.clone();
        let processor_adaptive = adaptive.clone();
        let processor_excludes = excludes.clone();
        let processor_install_dir = install_dir.clone();

        tokio::spawn(async move {
            while let Some(event) = event_rx.recv().await {
                if event.kind.is_access() || event.kind.is_create() || event.kind.is_modify() {
                    for path in event.paths {
                        if !path.is_file() || should_skip_path(&path, &processor_install_dir, &processor_excludes) {
                            continue;
                        }

                        // PERFORMANCE HARDENING: Skip hashing massive files (>200MB) in real-time
                        if let Ok(meta) = path.metadata() {
                            if meta.len() > 200 * 1024 * 1024 {
                                debug!("Skipping hash for massive file: {} ({} bytes)", path.display(), meta.len());
                                continue;
                            }
                        }

                        let path_str = path.to_string_lossy().to_string();

                        if processor_traps.contains(&path_str) {
                            warn!("HONEYTOKEN ACCESS DETECTED: {}!", path_str);
                        }

                        if let Some(ref mem) = processor_memory {
                            if mem.is_file_in_skip_list(&path_str).unwrap_or(false) {
                                continue;
                            }
                        }

                        if hashing_set.contains(&path_str) {
                            continue;
                        }
                        hashing_set.insert(path_str.clone());

                        let tx_clone = processor_tx.clone();
                        let kind = event.kind;
                        let path_for_hash = path.clone();
                        let memory_for_error = processor_memory.clone();
                        let hashing_set_inner = hashing_set.clone();
                        let path_str_inner = path_str.clone();

                        let task: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>> = Box::pin(async move {
                            match calculate_blake3_hash(&path_for_hash).await {
                                Ok(hash) => {
                                    let _ = tx_clone.send(Ok(FileChangeEvent {
                                        path: path_str_inner.clone(),
                                        hash,
                                        kind,
                                    })).await;
                                }
                                Err(e) => {
                                    let err_str = e.to_string();
                                    if let Some(ref mem) = memory_for_error {
                                        let _ = mem.add_file_to_skip_list(&path_str_inner, &err_str);
                                    }
                                }
                            }
                            hashing_set_inner.remove(&path_str_inner);
                        });

                        processor_adaptive.spawn_adaptive(
                            osoosi_types::ResourceCategory::IO,
                            osoosi_types::Priority::Low,
                            task,
                        );
                    }
                }
            }
        });

        Ok((
            Self {
                watcher,
                trap_paths,
                currently_hashing,
            },
            rx,
        ))
    }

    pub fn watch<P: AsRef<Path>>(&mut self, path: P) -> anyhow::Result<()> {
        info!("Starting watch on: {:?}", path.as_ref());
        self.watcher.watch(path.as_ref(), RecursiveMode::Recursive)?;
        Ok(())
    }
}

pub async fn build_os_file_hash_baseline(
    paths: Vec<String>,
    memory: Arc<osoosi_memory::MemoryStore>,
    exclude_paths: Vec<String>,
    adaptive: Arc<dyn osoosi_types::TelemetryControllerInterface>,
) {
    info!("Starting background hash of all files in watch paths: {}", paths.join(", "));
    let _ = memory.set_repair_status("baseline_status", "running");
    let _ = memory.set_repair_status("baseline_start", &Utc::now().to_rfc3339());
    let _ = memory.set_repair_status("baseline_count", "0");

    let (tx, mut rx) = mpsc::channel::<std::path::PathBuf>(10000);
    let install_dir = osoosi_install_dir();
    let excludes = exclude_paths.clone();

    tokio::task::spawn_blocking(move || {
        for root in paths {
            for entry in walkdir::WalkDir::new(&root)
                .into_iter()
                .filter_entry(|e| !should_skip_path(e.path(), &install_dir, &excludes))
                .filter_map(|e| e.ok())
            {
                if entry.file_type().is_file() {
                    // PERFORMANCE HARDENING: Skip massive files in baseline
                    if let Ok(meta) = entry.metadata() {
                        if meta.len() > 200 * 1024 * 1024 {
                            continue;
                        }
                    }
                    if tx.blocking_send(entry.into_path()).is_err() {
                        return;
                    }
                }
            }
        }
    });

    let mut join_set = tokio::task::JoinSet::new();
    let hashed_count = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let mut last_report = std::time::Instant::now();
    let mut sys = System::new_all();
    let self_pid = Pid::from(std::process::id() as usize);

    let mut current_concurrency = 4;
    let min_concurrency = 1;

    while let Some(path) = rx.recv().await {
        while adaptive.is_burst_mode() {
            tokio::time::sleep(Duration::from_secs(2)).await;
        }

        if last_report.elapsed().as_secs() >= 2 {
            sys.refresh_cpu_usage();
            sys.refresh_process(self_pid);
            let total_cpu = sys.global_cpu_info().cpu_usage();
            if total_cpu > 60.0 || adaptive.is_socket_exhaustion() {
                current_concurrency = (current_concurrency / 2).max(min_concurrency);
                tokio::time::sleep(Duration::from_millis(500)).await;
            } else if total_cpu < 25.0 {
                current_concurrency = (current_concurrency + 1).min(12);
            }
            let current = hashed_count.load(std::sync::atomic::Ordering::Relaxed);
            let _ = memory.set_repair_status("baseline_count", &current.to_string());
            last_report = std::time::Instant::now();
        }

        while join_set.len() >= current_concurrency {
            let _ = join_set.join_next().await;
        }

        let mem = memory.clone();
        let path_str = path.to_string_lossy().to_string();
        let count_ptr = hashed_count.clone();

        if mem.is_file_in_skip_list(&path_str).unwrap_or(false) {
            continue;
        }

        join_set.spawn(async move {
            let res = tokio::task::spawn_blocking(move || {
                let mut file = std::fs::File::open(&path)?;
                let mut hasher = blake3::Hasher::new();
                let mut buffer = [0u8; 65536];
                use std::io::Read;
                loop {
                    let n = file.read(&mut buffer)?;
                    if n == 0 { break; }
                    hasher.update(&buffer[..n]);
                }
                Ok::<String, anyhow::Error>(hasher.finalize().to_hex().to_string())
            }).await;

            match res {
                Ok(Ok(hash)) => {
                    let _ = mem.update_file_hash(&path_str, &hash);
                    count_ptr.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                _ => {}
            }
        });
    }

    while join_set.join_next().await.is_some() {}
    let final_count = hashed_count.load(std::sync::atomic::Ordering::Relaxed);
    let _ = memory.set_repair_status("baseline_count", &final_count.to_string());
    let _ = memory.set_repair_status("baseline_status", "finished");
    let _ = memory.set_repair_status("baseline_end", &Utc::now().to_rfc3339());
}
