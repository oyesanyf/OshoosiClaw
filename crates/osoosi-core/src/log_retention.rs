//! Log Retention & Intelligent Rotation Engine for OpenỌ̀ṣọ́ọ̀sì.
//!
//! Handles log directory scanning, automatic age/size-based pruning,
//! live tailing with search filtering, and path traversal protection.

use anyhow::Result;
use chrono::{DateTime, Utc};
use osoosi_types::LogRetentionConfig;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use tracing::{debug, error, info, warn};

/// Summary of a log maintenance run.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct LogMaintenanceSummary {
    pub total_files: usize,
    pub total_size_bytes: u64,
    pub files_pruned: usize,
    pub bytes_freed: u64,
}

pub struct LogRetentionManager;

impl LogRetentionManager {
    /// Determines whether a filename matches log file naming patterns.
    pub fn is_log_file(filename: &str) -> bool {
        let lower = filename.to_ascii_lowercase();
        lower.ends_with(".log") || lower.starts_with("osoosi.log")
    }

    /// Format bytes into a human readable display string.
    pub fn format_bytes(bytes: u64) -> String {
        const KB: u64 = 1024;
        const MB: u64 = 1024 * KB;
        const GB: u64 = 1024 * MB;

        if bytes >= GB {
            format!("{:.2} GB", bytes as f64 / GB as f64)
        } else if bytes >= MB {
            format!("{:.2} MB", bytes as f64 / MB as f64)
        } else if bytes >= KB {
            format!("{:.1} KB", bytes as f64 / KB as f64)
        } else {
            format!("{} B", bytes)
        }
    }

    /// Performs maintenance on log files in `log_dir`:
    /// 1. Prunes files older than `config.max_log_days` (excluding active `osoosi.log`).
    /// 2. If total size > `config.max_total_size_mb`, prunes oldest rotated logs down to 80%.
    /// 3. Safely handles file locks (Windows sharing violation) without aborting.
    pub fn maintain_logs(
        log_dir: &Path,
        config: &LogRetentionConfig,
    ) -> Result<LogMaintenanceSummary> {
        if !log_dir.exists() {
            fs::create_dir_all(log_dir)?;
            return Ok(LogMaintenanceSummary::default());
        }

        let mut files_pruned = 0;
        let mut bytes_freed = 0;

        let now = SystemTime::now();
        let max_age = Duration::from_secs(config.max_log_days as u64 * 86400);

        struct LogFileEntry {
            path: PathBuf,
            filename: String,
            size_bytes: u64,
            modified: SystemTime,
            is_active: bool,
        }

        let mut entries_found = Vec::new();

        let dir_entries = match fs::read_dir(log_dir) {
            Ok(entries) => entries,
            Err(e) => {
                warn!("LogRetentionManager: cannot read directory {}: {}", log_dir.display(), e);
                return Ok(LogMaintenanceSummary::default());
            }
        };

        for entry in dir_entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            let filename = match path.file_name().and_then(|f| f.to_str()) {
                Some(f) => f.to_string(),
                None => continue,
            };

            if !Self::is_log_file(&filename) {
                continue;
            }

            let metadata = match fs::metadata(&path) {
                Ok(m) => m,
                Err(e) => {
                    debug!("Failed to read metadata for {}: {}", path.display(), e);
                    continue;
                }
            };

            let size_bytes = metadata.len();
            let modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
            let is_active = filename.eq_ignore_ascii_case("osoosi.log");

            entries_found.push(LogFileEntry {
                path,
                filename,
                size_bytes,
                modified,
                is_active,
            });
        }

        let mut surviving = Vec::new();

        // 1. Age-based pruning
        for entry in entries_found {
            if !entry.is_active {
                let age = now.duration_since(entry.modified).unwrap_or_default();
                if age > max_age {
                    info!(
                        "LogRetentionManager: Pruning expired log file {} (age: {:.1} days)",
                        entry.filename,
                        age.as_secs_f64() / 86400.0
                    );
                    match fs::remove_file(&entry.path) {
                        Ok(_) => {
                            files_pruned += 1;
                            bytes_freed += entry.size_bytes;
                            continue;
                        }
                        Err(e) => {
                            warn!(
                                "LogRetentionManager: Could not remove expired log {} (may be locked): {}",
                                entry.filename, e
                            );
                            // Keep in surviving if deletion failed
                        }
                    }
                }
            }
            surviving.push(entry);
        }

        // 2. Size-based pruning
        let mut total_size_bytes: u64 = surviving.iter().map(|e| e.size_bytes).sum();
        let max_total_bytes = config.max_total_size_mb * 1024 * 1024;

        if total_size_bytes > max_total_bytes {
            let target_bytes = (max_total_bytes * 8) / 10; // 80% threshold
            info!(
                "LogRetentionManager: Total log size ({} MB) exceeds limit ({} MB). Pruning to {} MB...",
                total_size_bytes / (1024 * 1024),
                config.max_total_size_mb,
                target_bytes / (1024 * 1024)
            );

            // Separate active vs rotated
            let mut rotated: Vec<_> = surviving.into_iter().filter(|e| !e.is_active).collect();
            // Sort oldest modified time first
            rotated.sort_by_key(|e| e.modified);

            let mut final_surviving = Vec::new();
            for entry in rotated {
                if total_size_bytes > target_bytes {
                    match fs::remove_file(&entry.path) {
                        Ok(_) => {
                            files_pruned += 1;
                            bytes_freed += entry.size_bytes;
                            total_size_bytes = total_size_bytes.saturating_sub(entry.size_bytes);
                            continue;
                        }
                        Err(e) => {
                            warn!(
                                "LogRetentionManager: Could not remove log {} during size reduction: {}",
                                entry.filename, e
                            );
                        }
                    }
                }
                final_surviving.push(entry);
            }
            surviving = final_surviving;
        }

        let total_files = surviving.len();
        let final_total_size: u64 = surviving.iter().map(|e| e.size_bytes).sum();

        debug!(
            "LogRetentionManager: Maintenance complete. {} active/rotated files ({} bytes). Pruned: {} files ({} freed).",
            total_files, final_total_size, files_pruned, bytes_freed
        );

        Ok(LogMaintenanceSummary {
            total_files,
            total_size_bytes: final_total_size,
            files_pruned,
            bytes_freed,
        })
    }

    /// Starts a background retention maintenance loop running every hour.
    pub async fn start_retention_loop(log_dir: PathBuf, config: LogRetentionConfig) {
        info!(
            "LogRetentionManager: Background retention loop started for {} (max_days: {}, max_total_mb: {}).",
            log_dir.display(),
            config.max_log_days,
            config.max_total_size_mb
        );

        // Run immediately on boot
        if let Err(e) = Self::maintain_logs(&log_dir, &config) {
            error!("LogRetentionManager initial maintenance error: {}", e);
        }

        let mut interval = tokio::time::interval(Duration::from_secs(3600));
        loop {
            interval.tick().await;
            if let Err(e) = Self::maintain_logs(&log_dir, &config) {
                error!("LogRetentionManager periodic maintenance error: {}", e);
            }
        }
    }

    /// Lists all `.log` files in `log_dir` with metadata, sorted newest modified first.
    pub fn list_log_files(log_dir: &Path) -> Vec<serde_json::Value> {
        if !log_dir.exists() {
            return Vec::new();
        }

        let mut file_list = Vec::new();

        if let Ok(entries) = fs::read_dir(log_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }

                let filename = match path.file_name().and_then(|f| f.to_str()) {
                    Some(f) => f.to_string(),
                    None => continue,
                };

                if !Self::is_log_file(&filename) {
                    continue;
                }

                let (size_bytes, modified_at, modified_sys) = match fs::metadata(&path) {
                    Ok(m) => {
                        let sz = m.len();
                        let sys = m.modified().unwrap_or(SystemTime::UNIX_EPOCH);
                        let dt: DateTime<Utc> = sys.into();
                        (sz, dt.to_rfc3339(), sys)
                    }
                    Err(_) => (0, Utc::now().to_rfc3339(), SystemTime::UNIX_EPOCH),
                };

                let is_active = filename.eq_ignore_ascii_case("osoosi.log");
                let size_display = Self::format_bytes(size_bytes);

                file_list.push((
                    modified_sys,
                    serde_json::json!({
                        "filename": filename,
                        "size_bytes": size_bytes,
                        "size_display": size_display,
                        "modified_at": modified_at,
                        "is_active": is_active,
                    }),
                ));
            }
        }

        // Sort descending by modified time (newest first)
        file_list.sort_by(|a, b| b.0.cmp(&a.0));
        file_list.into_iter().map(|(_, val)| val).collect()
    }

    /// Reads up to `max_lines` from the tail of `filename` in `log_dir`,
    /// optionally filtering by `search` query. Protects against path traversal.
    pub fn read_log_tail(
        log_dir: &Path,
        filename: &str,
        max_lines: usize,
        search: Option<&str>,
    ) -> Result<Vec<String>> {
        // Path traversal protection: filename must be pure filename
        if filename.is_empty()
            || filename.contains('/')
            || filename.contains('\\')
            || filename.contains("..")
            || filename.contains('\0')
        {
            return Err(anyhow::anyhow!("Invalid log filename: path traversal characters detected"));
        }

        let target_path = log_dir.join(filename);
        if !target_path.exists() || !target_path.is_file() {
            return Err(anyhow::anyhow!("Log file not found: {}", filename));
        }

        // Verify canonical path boundary if canonicalization succeeds
        if let (Ok(can_file), Ok(can_dir)) = (target_path.canonicalize(), log_dir.canonicalize()) {
            if !can_file.starts_with(&can_dir) {
                return Err(anyhow::anyhow!("Forbidden log access: path escapes log directory"));
            }
        }

        let file = fs::File::open(&target_path)?;
        let reader = BufReader::new(file);

        let search_pattern = search.map(|s| s.trim().to_ascii_lowercase());
        let cap = max_lines.clamp(1, 5000);
        let mut buffer = VecDeque::with_capacity(cap);

        for line_res in reader.lines() {
            let line = line_res?;
            if let Some(ref pattern) = search_pattern {
                if !line.to_ascii_lowercase().contains(pattern) {
                    continue;
                }
            }

            if buffer.len() >= cap {
                buffer.pop_front();
            }
            buffer.push_back(line);
        }

        Ok(buffer.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;

    struct TestDir(PathBuf);
    impl TestDir {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!(
                "test_osoosi_logs_{}_{}",
                std::process::id(),
                rand::random::<u64>()
            ));
            let _ = fs::create_dir_all(&p);
            Self(p)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn test_log_filename_matching() {
        assert!(LogRetentionManager::is_log_file("osoosi.log"));
        assert!(LogRetentionManager::is_log_file("osoosi.log.2026-09-25"));
        assert!(LogRetentionManager::is_log_file("audit_trail.log"));
        assert!(!LogRetentionManager::is_log_file("osoosi.toml"));
        assert!(!LogRetentionManager::is_log_file("data.db"));
    }

    #[test]
    fn test_path_traversal_prevention() {
        let temp = TestDir::new();
        let log_dir = temp.path();

        assert!(LogRetentionManager::read_log_tail(log_dir, "../windows/win.ini", 50, None).is_err());
        assert!(LogRetentionManager::read_log_tail(log_dir, "foo/bar.log", 50, None).is_err());
        assert!(LogRetentionManager::read_log_tail(log_dir, "foo\\bar.log", 50, None).is_err());
        assert!(LogRetentionManager::read_log_tail(log_dir, "..\\secret.log", 50, None).is_err());
    }

    #[test]
    fn test_read_log_tail_with_search() {
        let temp = TestDir::new();
        let log_dir = temp.path();
        let file_path = log_dir.join("test.log");

        let mut file = File::create(&file_path).unwrap();
        writeln!(file, "Line 1: INFO Agent starting").unwrap();
        writeln!(file, "Line 2: WARN High memory usage").unwrap();
        writeln!(file, "Line 3: ERROR Connection refused").unwrap();
        writeln!(file, "Line 4: INFO Agent operational").unwrap();
        drop(file);

        let all = LogRetentionManager::read_log_tail(log_dir, "test.log", 10, None).unwrap();
        assert_eq!(all.len(), 4);

        let errors = LogRetentionManager::read_log_tail(log_dir, "test.log", 10, Some("ERROR")).unwrap();
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("Connection refused"));

        let tail = LogRetentionManager::read_log_tail(log_dir, "test.log", 2, None).unwrap();
        assert_eq!(tail.len(), 2);
        assert!(tail[1].contains("Agent operational"));
    }

    #[test]
    fn test_maintain_logs_pruning_and_active_preservation() {
        let temp = TestDir::new();
        let log_dir = temp.path();

        // 1. Create active log file
        let active_path = log_dir.join("osoosi.log");
        let mut active = File::create(&active_path).unwrap();
        writeln!(active, "Active current logs").unwrap();
        drop(active);

        // 2. Create a rotated log file
        let rotated_path = log_dir.join("osoosi.log.2026-09-01");
        let mut rotated = File::create(&rotated_path).unwrap();
        writeln!(rotated, "Old rotated logs").unwrap();
        drop(rotated);

        let config = LogRetentionConfig {
            max_log_days: 14,
            max_total_size_mb: 500,
            max_single_file_size_mb: 50,
        };

        // Run maintenance
        let summary = LogRetentionManager::maintain_logs(log_dir, &config).unwrap();
        assert_eq!(summary.total_files, 2);
        assert!(active_path.exists());
        assert!(rotated_path.exists());

        // Now test list_log_files
        let list = LogRetentionManager::list_log_files(log_dir);
        assert_eq!(list.len(), 2);
        let has_active = list.iter().any(|v| v["is_active"] == true && v["filename"] == "osoosi.log");
        assert!(has_active);
    }
}
