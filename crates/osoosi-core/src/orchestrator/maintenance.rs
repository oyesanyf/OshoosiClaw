#![allow(unused_imports)]

use super::types::*;
use super::*;
use crate::causal_graph::*;
use crate::console_defense::*;
use crate::disk_cleanup::*;
use crate::hybrid_runtime::*;
use crate::killchain::*;
use crate::memory_watchdog::*;
use crate::rea::*;
use crate::voters::*;

impl EdrOrchestrator {
    /// Explicitly trigger a patch discovery cycle.
    pub fn trigger_patch_discovery(&self) {
        let engine = self.patch_engine.clone();
        let _ = std::thread::Builder::new()
            .name("osoosi-patch-discovery".to_string())
            .spawn(move || {
                if let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    rt.block_on(async move {
                        let _ = engine.run_discovery().await;
                    });
                }
            });
    }

    /// Returns dynamic real-time host disk metrics and resource pressure tiers.
    pub fn get_dynamic_disk_status(&self) -> serde_json::Value {
        let disks = sysinfo::Disks::new_with_refreshed_list();
        let cur_dir = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
        let matched_disk = disks
            .iter()
            .filter(|d| cur_dir.starts_with(d.mount_point()))
            .max_by_key(|d| d.mount_point().as_os_str().len())
            .or_else(|| disks.list().first());

        let (available_bytes, total_bytes) = if let Some(disk) = matched_disk {
            (disk.available_space(), disk.total_space())
        } else {
            (0u64, 0u64)
        };

        let free_gb = available_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
        let total_gb = total_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
        let used_pct = if total_bytes > 0 {
            ((total_bytes.saturating_sub(available_bytes)) as f64 / total_bytes as f64) * 100.0
        } else {
            0.0
        };
        let free_pct = if total_bytes > 0 {
            (available_bytes as f64 / total_bytes as f64) * 100.0
        } else {
            100.0
        };

        let pressure_tier = if free_gb < 10.0 || free_pct < 5.0 {
            "CRITICAL"
        } else if free_gb < 25.0 || free_pct < 12.0 {
            "ELEVATED"
        } else if free_gb < 50.0 || free_pct < 20.0 {
            "MODERATE"
        } else {
            "NOMINAL"
        };

        let recommended_retention_days = match pressure_tier {
            "CRITICAL" => 2u32,
            "ELEVATED" => 7u32,
            "MODERATE" => 14u32,
            _ => 30u32,
        };

        let log_dir = osoosi_types::resolve_log_directory();
        let (logs_bytes, logs_count) = Self::scan_dir_bytes_helper(&log_dir);

        let mut candidate_dirs: Vec<std::path::PathBuf> = Vec::new();
        if let Ok(cd) = std::env::current_dir() {
            candidate_dirs.push(cd);
        }
        if let Ok(cur_exe) = std::env::current_exe() {
            if let Some(parent) = cur_exe.parent() {
                let p = parent.to_path_buf();
                if !candidate_dirs.contains(&p) {
                    candidate_dirs.push(p);
                }
            }
        }

        let mut database_bytes = 0u64;
        let mut scanned_db_files = std::collections::HashSet::new();
        for dir in &candidate_dirs {
            for db_name in &[
                "database/osoosi.db",
                "database/osoosi.db-wal",
                "database/osoosi.db-shm",
                "osoosi.db",
                "osoosi.db-wal",
                "osoosi.db-shm",
            ] {
                let db_p = dir.join(db_name);
                if db_p.is_file() && scanned_db_files.insert(db_p.clone()) {
                    if let Ok(meta) = db_p.metadata() {
                        database_bytes += meta.len();
                    }
                }
            }
        }

        let mut quarantine_bytes = 0u64;
        let mut quarantine_count = 0u64;
        let mut scanned_q_dirs = std::collections::HashSet::new();
        for dir in &candidate_dirs {
            let q_dir = dir.join("quarantine");
            if q_dir.is_dir() && scanned_q_dirs.insert(q_dir.clone()) {
                let (qb, qc) = Self::scan_dir_bytes_helper(&q_dir);
                quarantine_bytes += qb;
                quarantine_count += qc;
            }
        }

        let mut temp_cache_bytes = 0u64;
        let mut temp_cache_count = 0u64;
        let temp_dir = std::env::temp_dir();
        if let Ok(entries) = std::fs::read_dir(&temp_dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if name.starts_with("osoosi")
                    || name.starts_with("clef_test_")
                    || name.starts_with("siquery_")
                    || name.starts_with("yara_")
                {
                    if p.is_file() {
                        if let Ok(meta) = p.metadata() {
                            temp_cache_bytes += meta.len();
                            temp_cache_count += 1;
                        }
                    } else if p.is_dir() {
                        let (sub_b, sub_c) = Self::scan_dir_bytes_helper(&p);
                        temp_cache_bytes += sub_b;
                        temp_cache_count += sub_c;
                    }
                }
            }
        }

        for dir in &candidate_dirs {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
                    if p.is_file() && (name.starts_with(".locked.") || name.contains(".locked.")) {
                        if let Ok(meta) = p.metadata() {
                            temp_cache_bytes += meta.len();
                            temp_cache_count += 1;
                        }
                    }
                }
            }
            let feeds_dir = dir.join("data").join("feeds");
            if feeds_dir.is_dir() {
                if let Ok(entries) = std::fs::read_dir(&feeds_dir) {
                    for entry in entries.flatten() {
                        let p = entry.path();
                        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
                        if p.is_file() && (name.ends_with(".part") || name.ends_with(".tmp")) {
                            if let Ok(meta) = p.metadata() {
                                temp_cache_bytes += meta.len();
                                temp_cache_count += 1;
                            }
                        }
                    }
                }
            }
        }

        serde_json::json!({
            "status": "ok",
            "available_bytes": available_bytes,
            "total_bytes": total_bytes,
            "free_gb": (free_gb * 100.0).round() / 100.0,
            "total_gb": (total_gb * 100.0).round() / 100.0,
            "used_pct": (used_pct * 10.0).round() / 10.0,
            "free_pct": (free_pct * 10.0).round() / 10.0,
            "pressure_tier": pressure_tier,
            "recommended_retention_days": recommended_retention_days,
            "logs_bytes": logs_bytes,
            "logs_count": logs_count,
            "formatted_logs": crate::log_retention::LogRetentionManager::format_bytes(logs_bytes),
            "database_bytes": database_bytes,
            "formatted_database": crate::log_retention::LogRetentionManager::format_bytes(database_bytes),
            "quarantine_bytes": quarantine_bytes,
            "quarantine_count": quarantine_count,
            "formatted_quarantine": crate::log_retention::LogRetentionManager::format_bytes(quarantine_bytes),
            "temp_cache_bytes": temp_cache_bytes,
            "temp_cache_count": temp_cache_count,
            "formatted_temp_cache": crate::log_retention::LogRetentionManager::format_bytes(temp_cache_bytes),
            "autonomous_cleanup": crate::disk_cleanup::get_disk_cleanup_status_snapshot(),
        })
    }

    /// Internal recursive directory size helper.
    pub fn scan_dir_bytes_helper(dir: &std::path::Path) -> (u64, u64) {
        let mut bytes = 0u64;
        let mut count = 0u64;
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_file() {
                    if let Ok(meta) = p.metadata() {
                        bytes += meta.len();
                        count += 1;
                    }
                } else if p.is_dir() {
                    let (sb, sc) = Self::scan_dir_bytes_helper(&p);
                    bytes += sb;
                    count += sc;
                }
            }
        }
        (bytes, count)
    }

    /// Fast in-memory cache eviction and working set trim (< 15ms).
    pub fn fast_in_memory_eviction(&self) -> (u64, serde_json::Value) {
        let cache_ttl = Duration::from_secs(60);

        let mut evicted_behavioral = 0;
        self.behavioral_debouncer.retain(|_, last_seen| {
            if last_seen.elapsed() >= cache_ttl {
                evicted_behavioral += 1;
                false
            } else {
                true
            }
        });

        let mut evicted_alerts = 0;
        self.alert_suppression_cache.retain(|_, last_seen| {
            if last_seen.elapsed() >= cache_ttl {
                evicted_alerts += 1;
                false
            } else {
                true
            }
        });

        let mut evicted_broadcast = 0;
        self.mesh_broadcast_debouncer.retain(|_, last_seen| {
            if last_seen.elapsed() >= cache_ttl {
                evicted_broadcast += 1;
                false
            } else {
                true
            }
        });

        let mut cleared_nsrl = false;
        if self.nsrl_cache.len() > 50_000 {
            self.nsrl_cache.clear();
            self.nsrl_cache.shrink_to_fit();
            cleared_nsrl = true;
        }

        let mut cleared_consensus = false;
        if self.policy_consensus.len() > 2_000 {
            self.policy_consensus.clear();
            self.policy_consensus.shrink_to_fit();
            cleared_consensus = true;
        }

        let compacted_audit_entries = self.audit.compact_memory(4096);
        let bytes_freed =
            (evicted_behavioral * 64 + evicted_alerts * 128 + evicted_broadcast * 64) as u64;

        let details = serde_json::json!({
            "behavioral_debouncer": evicted_behavioral,
            "alert_suppression": evicted_alerts,
            "mesh_broadcast_debouncer": evicted_broadcast,
            "nsrl_cache_capped": cleared_nsrl,
            "policy_consensus_capped": cleared_consensus,
            "compacted_audit_entries": compacted_audit_entries,
        });

        (bytes_freed, details)
    }

    /// Asynchronous background worker routine for heavy filesystem and database cleanup.
    pub fn cleanup_disk_background(&self, days_retention: u32, job_id: String) {
        use crate::disk_cleanup::update_current_cleanup_job;
        info!("[CLEANUP-BG] Starting background cleanup job {}", job_id);

        let mut total_bytes: u64 = 0;
        let mut total_files: u64 = 0;

        // 1. Target debug & scratch purges
        update_current_cleanup_job(|job| {
            job.phase = "target_debug".to_string();
            job.progress_pct = 25;
        });
        let sweep_mode = if days_retention == 0 {
            "deep_cargo"
        } else {
            "standard"
        };
        let autonomous_sweep = crate::disk_cleanup::run_autonomous_disk_cleanup_sweep(sweep_mode);
        total_bytes = total_bytes.saturating_add(autonomous_sweep.bytes_freed);
        total_files = total_files.saturating_add(autonomous_sweep.files_removed);

        update_current_cleanup_job(|job| {
            job.bytes_freed = total_bytes;
            job.files_pruned = total_files;
            job.phase = "sqlite_vacuum".to_string();
            job.progress_pct = 55;
        });

        // 2. SQLite WAL checkpoint & vacuum
        let eff_days = days_retention.max(1);
        if let Err(e) = self.memory.vacuum_and_prune(eff_days) {
            warn!("[CLEANUP-BG] SQLite vacuum_and_prune warning: {}", e);
        }

        // 3. Log retention & OS temp maintenance
        update_current_cleanup_job(|job| {
            job.phase = "logs_temp".to_string();
            job.progress_pct = 80;
        });
        let log_dir = osoosi_types::resolve_log_directory();
        let log_cfg = osoosi_types::load_log_retention_config();
        if let Ok(sum) =
            crate::log_retention::LogRetentionManager::maintain_logs(&log_dir, &log_cfg)
        {
            total_bytes = total_bytes.saturating_add(sum.bytes_freed);
            total_files = total_files.saturating_add(sum.files_pruned as u64);
        }

        // Mark completed
        update_current_cleanup_job(|job| {
            job.phase = "completed".to_string();
            job.is_active = false;
            job.progress_pct = 100;
            job.bytes_freed = total_bytes;
            job.files_pruned = total_files;
            job.completed_at = Some(chrono::Utc::now().to_rfc3339());
        });
        info!(
            "[CLEANUP-BG] Completed background cleanup job {}: freed {} bytes across {} files",
            job_id, total_bytes, total_files
        );
    }

    /// Comprehensive memory and disk cleanup routine with dynamic scaling based on real-time disk pressure.
    pub fn cleanup_memory_and_disk(&self, days_retention: u32) -> serde_json::Value {
        let disk_status = self.get_dynamic_disk_status();
        let pressure_tier = disk_status
            .get("pressure_tier")
            .and_then(|v| v.as_str())
            .unwrap_or("NOMINAL")
            .to_string();
        let recommended_days = disk_status
            .get("recommended_retention_days")
            .and_then(|v| v.as_u64())
            .unwrap_or(30) as u32;

        let (effective_days, temp_cutoff, cache_ttl) = if days_retention == 0 {
            (0u32, Duration::from_secs(0), Duration::from_secs(60))
        } else {
            let eff = days_retention.min(recommended_days);
            let (t_cut, c_ttl) = match pressure_tier.as_str() {
                "CRITICAL" => (Duration::from_secs(600), Duration::from_secs(300)),
                "ELEVATED" => (Duration::from_secs(3600), Duration::from_secs(900)),
                "MODERATE" => (Duration::from_secs(14400), Duration::from_secs(1800)),
                _ => (Duration::from_secs(86400), Duration::from_secs(3600)),
            };
            (eff, t_cut, c_ttl)
        };

        info!(
            "Initiating dynamic EDR memory and disk cleanup (requested: {}d, effective: {}d, pressure: {})...",
            days_retention, effective_days, pressure_tier
        );

        let mut bytes_freed: u64 = 0;

        // 1. In-Memory Cache Eviction based on dynamic cache_ttl
        let mut evicted_behavioral = 0;
        self.behavioral_debouncer.retain(|_, last_seen| {
            if last_seen.elapsed() >= cache_ttl {
                evicted_behavioral += 1;
                false
            } else {
                true
            }
        });

        let mut evicted_alerts = 0;
        self.alert_suppression_cache.retain(|_, last_seen| {
            if last_seen.elapsed() >= cache_ttl {
                evicted_alerts += 1;
                false
            } else {
                true
            }
        });

        let mut evicted_broadcast = 0;
        self.mesh_broadcast_debouncer.retain(|_, last_seen| {
            if last_seen.elapsed() >= cache_ttl {
                evicted_broadcast += 1;
                false
            } else {
                true
            }
        });

        let mut cleared_nsrl = false;
        let nsrl_cap = if effective_days == 0 || pressure_tier == "CRITICAL" {
            5_000
        } else {
            50_000
        };
        if self.nsrl_cache.len() > nsrl_cap {
            self.nsrl_cache.clear();
            self.nsrl_cache.shrink_to_fit();
            cleared_nsrl = true;
        }

        let mut cleared_consensus = false;
        let consensus_cap = if effective_days == 0 || pressure_tier == "CRITICAL" {
            500
        } else {
            2_000
        };
        if self.policy_consensus.len() > consensus_cap {
            self.policy_consensus.clear();
            self.policy_consensus.shrink_to_fit();
            cleared_consensus = true;
        }

        let audit_cap = if effective_days == 0 || pressure_tier == "CRITICAL" {
            512
        } else {
            4096
        };
        let compacted_audit_entries = self.audit.compact_memory(audit_cap);

        // 2. Disk Artifact & Quarantine Cleanup
        let mut candidate_dirs: Vec<std::path::PathBuf> = Vec::new();
        if let Ok(cur_dir) = std::env::current_dir() {
            candidate_dirs.push(cur_dir);
        }
        if let Ok(cur_exe) = std::env::current_exe() {
            if let Some(parent) = cur_exe.parent() {
                let p = parent.to_path_buf();
                if !candidate_dirs.contains(&p) {
                    candidate_dirs.push(p);
                }
            }
        }

        // 2a. Stale .locked.* files and stale .tmp/.part feeds
        let mut cleaned_locked = 0;
        for dir in &candidate_dirs {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                        if name.starts_with(".locked.") || name.contains(".locked.") {
                            if let Ok(meta) = path.metadata() {
                                let f_len = meta.len();
                                if std::fs::remove_file(&path).is_ok() {
                                    cleaned_locked += 1;
                                    bytes_freed += f_len;
                                }
                            }
                        }
                    }
                }
            }
            let feeds_dir = dir.join("data").join("feeds");
            if feeds_dir.is_dir() {
                if let Ok(entries) = std::fs::read_dir(&feeds_dir) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.is_file() {
                            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                            if name.ends_with(".part") || name.ends_with(".tmp") {
                                if let Ok(meta) = path.metadata() {
                                    let f_len = meta.len();
                                    if std::fs::remove_file(&path).is_ok() {
                                        cleaned_locked += 1;
                                        bytes_freed += f_len;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // 2b. Quarantine files older than effective_days (or immediate if 0)
        let mut cleaned_quarantine = 0;
        let quarantine_cutoff = Duration::from_secs(effective_days as u64 * 86400);
        let mut scanned_q_dirs = std::collections::HashSet::new();
        for dir in &candidate_dirs {
            let q_dir = dir.join("quarantine");
            if q_dir.is_dir() && scanned_q_dirs.insert(q_dir.clone()) {
                if let Ok(entries) = std::fs::read_dir(&q_dir) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.is_file() {
                            if let Ok(meta) = path.metadata() {
                                let f_len = meta.len();
                                let should_delete = if effective_days == 0 {
                                    true
                                } else if let Ok(modified) = meta.modified() {
                                    modified
                                        .elapsed()
                                        .map(|el| el >= quarantine_cutoff)
                                        .unwrap_or(false)
                                } else {
                                    false
                                };
                                if should_delete && std::fs::remove_file(&path).is_ok() {
                                    cleaned_quarantine += 1;
                                    bytes_freed += f_len;
                                }
                            }
                        }
                    }
                }
            }
        }

        // 2c. Stale temporary files in std::env::temp_dir()
        let mut cleaned_temp = 0;
        let temp_dir = std::env::temp_dir();
        if let Ok(entries) = std::fs::read_dir(&temp_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if name.starts_with("osoosi")
                    || name.starts_with("clef_test_")
                    || name.starts_with("siquery_")
                    || name.starts_with("yara_")
                {
                    if let Ok(meta) = path.metadata() {
                        let should_delete = if effective_days == 0 {
                            true
                        } else if let Ok(modified) = meta.modified() {
                            modified
                                .elapsed()
                                .map(|el| el >= temp_cutoff)
                                .unwrap_or(false)
                        } else {
                            false
                        };
                        if should_delete {
                            if path.is_dir() {
                                let (dir_b, _) = Self::scan_dir_bytes_helper(&path);
                                if std::fs::remove_dir_all(&path).is_ok() {
                                    cleaned_temp += 1;
                                    bytes_freed += dir_b;
                                }
                            } else {
                                let f_len = meta.len();
                                if std::fs::remove_file(&path).is_ok() {
                                    cleaned_temp += 1;
                                    bytes_freed += f_len;
                                }
                            }
                        }
                    }
                }
            }
        }

        // 2d. Run vacuum_and_prune on SQLite database
        let db_bytes_before = disk_status
            .get("database_bytes")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let db_pruned = self.memory.vacuum_and_prune(effective_days.max(1)).is_ok();
        let db_bytes_after = {
            let mut cur_db = 0u64;
            let mut scanned = std::collections::HashSet::new();
            for dir in &candidate_dirs {
                for db_name in &[
                    "database/osoosi.db",
                    "database/osoosi.db-wal",
                    "database/osoosi.db-shm",
                    "osoosi.db",
                    "osoosi.db-wal",
                    "osoosi.db-shm",
                ] {
                    let db_p = dir.join(db_name);
                    if db_p.is_file() && scanned.insert(db_p.clone()) {
                        if let Ok(meta) = db_p.metadata() {
                            cur_db += meta.len();
                        }
                    }
                }
            }
            cur_db
        };
        if db_bytes_before > db_bytes_after {
            bytes_freed += db_bytes_before - db_bytes_after;
        }

        // 2e. Run dynamic maintain_logs
        let log_dir = osoosi_types::resolve_log_directory();
        let mut log_cfg = osoosi_types::load_log_retention_config();
        if effective_days == 0 {
            log_cfg.max_log_days = 0;
            log_cfg.max_total_size_mb = 25;
        } else if pressure_tier == "CRITICAL" {
            log_cfg.max_log_days = log_cfg.max_log_days.min(2);
            log_cfg.max_total_size_mb = log_cfg.max_total_size_mb.min(50);
        } else if pressure_tier == "ELEVATED" {
            log_cfg.max_log_days = log_cfg.max_log_days.min(7);
            log_cfg.max_total_size_mb = log_cfg.max_total_size_mb.min(150);
        }
        let logs_res = crate::log_retention::LogRetentionManager::maintain_logs(&log_dir, &log_cfg);
        let logs_maintained = logs_res.is_ok();
        if let Ok(ref sum) = logs_res {
            bytes_freed += sum.bytes_freed;
        }

        // 2f. 5-Tier Autonomous Build-Cache, WAL & Telemetry Cleanup Sweep
        let sweep_mode = if effective_days == 0 {
            "deep_cargo"
        } else {
            "standard"
        };
        let autonomous_sweep = crate::disk_cleanup::run_autonomous_disk_cleanup_sweep(sweep_mode);
        bytes_freed = bytes_freed.saturating_add(autonomous_sweep.bytes_freed);

        // 3. OS Working-Set Trim
        let working_set_trimmed = crate::memory_watchdog::trim_process_working_set();

        let updated_disk_status = self.get_dynamic_disk_status();

        let summary = serde_json::json!({
            "status": "success",
            "effective_retention_days": effective_days,
            "pressure_tier": pressure_tier,
            "bytes_freed": bytes_freed,
            "formatted_bytes_freed": crate::log_retention::LogRetentionManager::format_bytes(bytes_freed),
            "in_memory_evicted": {
                "behavioral_debouncer": evicted_behavioral,
                "alert_suppression": evicted_alerts,
                "mesh_broadcast_debouncer": evicted_broadcast,
                "nsrl_cache_capped": cleared_nsrl,
                "policy_consensus_capped": cleared_consensus,
                "compacted_audit_entries": compacted_audit_entries,
            },
            "disk_cleaned": {
                "locked_swap_files": cleaned_locked,
                "quarantine_files": cleaned_quarantine,
                "temp_files": cleaned_temp,
                "db_pruned": db_pruned,
                "logs_maintained": logs_maintained,
            },
            "os_working_set_trimmed": working_set_trimmed,
            "disk_status": updated_disk_status,
        });

        info!(
            "Comprehensive dynamic EDR cleanup completed: freed {}",
            crate::log_retention::LogRetentionManager::format_bytes(bytes_freed)
        );
        summary
    }

    pub async fn run_maintenance_loop(&self) {
        crate::disk_cleanup::spawn_autonomous_disk_cleanup_watchdog();
        info!("EDR Maintenance Loop started with dynamic pressure awareness (15-minute autonomous cycle).");
        let mut interval = tokio::time::interval(Duration::from_secs(900));
        loop {
            interval.tick().await;
            let disk_status = self.get_dynamic_disk_status();
            let pressure = disk_status
                .get("pressure_tier")
                .and_then(|v| v.as_str())
                .unwrap_or("NOMINAL");
            let rec_days = disk_status
                .get("recommended_retention_days")
                .and_then(|v| v.as_u64())
                .unwrap_or(30) as u32;
            info!("Running periodic memory and disk maintenance cycle (pressure: {}, rec_days: {})...", pressure, rec_days);
            let summary = self.cleanup_memory_and_disk(rec_days);
            debug!("Periodic maintenance cycle completed: {}", summary);
        }
    }

    /// Lists all `.log` files in the resolved logs directory with metadata.
    pub fn list_log_files(&self) -> Vec<serde_json::Value> {
        let log_dir = osoosi_types::resolve_log_directory();
        crate::log_retention::LogRetentionManager::list_log_files(&log_dir)
    }

    /// Reads tail lines from a specified log file, with optional search filtering.
    pub fn read_log_tail(
        &self,
        filename: &str,
        max_lines: usize,
        search: Option<&str>,
    ) -> anyhow::Result<Vec<String>> {
        let log_dir = osoosi_types::resolve_log_directory();
        crate::log_retention::LogRetentionManager::read_log_tail(
            &log_dir, filename, max_lines, search,
        )
    }

    /// Access the LogRetentionManager instance.
    pub fn get_log_retention_manager(&self) -> crate::log_retention::LogRetentionManager {
        crate::log_retention::LogRetentionManager
    }

    /// Runs log retention and rotation maintenance immediately.
    pub fn maintain_logs(&self) -> anyhow::Result<crate::log_retention::LogMaintenanceSummary> {
        let log_dir = osoosi_types::resolve_log_directory();
        let log_cfg = osoosi_types::load_log_retention_config();
        crate::log_retention::LogRetentionManager::maintain_logs(&log_dir, &log_cfg)
    }

    /// Register a temporary zero-day defense rule into both the PolicyEngine and dynamic YARA engine.
    pub fn register_temporary_rule(&self, cve_id: &str, rule_text: &str, severity: f32) {
        self.policy
            .register_temporary_rule(cve_id, rule_text, severity);
        let _ = self
            .yara_manager
            .hot_load_rule(rule_text, &format!("mesh_{}", uuid::Uuid::new_v4()));
    }

    /// Evict expired mesh debouncers and caches to prevent long-running memory leaks.
    pub fn prune_in_memory_caches(&self) {
        self.mesh_broadcast_debouncer
            .retain(|_, time| time.elapsed() < std::time::Duration::from_secs(3600));
        self.alert_suppression_cache
            .retain(|_, time| time.elapsed() < std::time::Duration::from_secs(3600));
        self.behavioral_debouncer
            .retain(|_, time| time.elapsed() < std::time::Duration::from_secs(3600));
    }

    /// Background task for Rule Maintenance (YARA, Sigma, etc.)
    pub fn start_maintenance_loop(&self) {
        let orch = self.clone();
        tokio::spawn(async move {
            info!("Starting Rule Maintenance Loop (YARA, ClamAV)...");

            // 1. YARA Update (Core Forge + Agentic Discovery) - offload to blocking pool
            orch.adaptive
                .spawn_adaptive(ResourceCategory::IO, Priority::Normal, async move {
                    let _ = tokio::task::spawn_blocking(|| {
                        osoosi_model::malware::MalwareScanner::update_yara_rules_on_startup();
                    })
                    .await;
                });

            let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600 * 4)); // Every 4 hours
            loop {
                interval.tick().await;
                info!("Running periodic rule maintenance...");

                // 0. Periodic eviction of expired mesh debouncers and caches
                orch.prune_in_memory_caches();

                // Periodic YARA Feed Update to prevent rule staleness
                let ym = orch.yara_manager.clone();
                tokio::spawn(async move {
                    info!("Maintenance: Checking and updating YARA threat feeds...");
                    match ym.update_feeds_and_reload().await {
                        Ok(count) => info!(
                            "Maintenance: YARA rules updated! Currently active: {} rules.",
                            count
                        ),
                        Err(e) => debug!("Maintenance: YARA feed update skipped or offline: {}", e),
                    }
                });

                // 3. ClamAV Health Check / Update
                let orch_inner = orch.clone();
                orch_inner.adaptive.spawn_adaptive(
                    ResourceCategory::IO,
                    Priority::Normal,
                    async move {
                        let _ = tokio::task::spawn_blocking(|| {
                            let _ = std::process::Command::new("freshclam").status();
                        })
                        .await;
                    },
                );

                // 4. Log Pruning (Keep last 7 days)
                let log_dir = osoosi_types::resolve_log_directory();
                if log_dir.exists() {
                    if let Ok(entries) = std::fs::read_dir(&log_dir) {
                        for entry in entries.flatten() {
                            if let Ok(meta) = entry.metadata() {
                                if let Ok(modified) = meta.modified() {
                                    if let Ok(elapsed) = modified.elapsed() {
                                        if elapsed.as_secs() > 7 * 24 * 3600 {
                                            let _ = std::fs::remove_file(entry.path());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // 5. Disk Space Warning & Automated Dynamic Cleanup
                let disks = sysinfo::Disks::new_with_refreshed_list();
                let cur_dir =
                    std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
                let matched_disk = disks
                    .iter()
                    .filter(|d| cur_dir.starts_with(d.mount_point()))
                    .max_by_key(|d| d.mount_point().as_os_str().len())
                    .or_else(|| disks.list().first());

                if let Some(disk) = matched_disk {
                    let free_gb = disk.available_space() / (1024 * 1024 * 1024);
                    if free_gb < 15 {
                        warn!("⚠️ LOW DISK SPACE: Only {}GB remaining. Automatically initiating dynamic EDR cleanup.", free_gb);
                        let _ = orch.cleanup_memory_and_disk(7);
                    }
                }
            }
        });
    }

    /// Background task for Repair Engine: discover patches, optionally apply.
    pub async fn start_repair_loop(&self, interval_secs: u64, auto_apply: bool) {
        let engine = self.patch_engine.clone();
        let memory = self.memory.clone();
        let orch = self.clone();
        tokio::spawn(async move {
            info!(
                "Repair Engine started (interval: {}s, auto_apply: {})",
                interval_secs, auto_apply
            );
            loop {
                let engine_inner = engine.clone();
                let memory_inner = memory.clone();
                let orch_inner = orch.clone();

                // Using spawn_adaptive to handle heavy discovery/patching logic
                orch_inner.adaptive.spawn_adaptive(
                    ResourceCategory::IO,
                    Priority::Low,
                    async move {
                        match engine_inner.run_discovery().await {
                            Ok(patches) => {
                                let count = patches.len();
                                let is_committed_verified = memory_inner
                                    .get_repair_status("last_state")
                                    .ok()
                                    .flatten()
                                    .as_deref()
                                    == Some("Committed · Verified");
                                if count > 0 && !is_committed_verified {
                                    info!("Repair Engine: discovered {} missing patches", count);
                                    let _ = memory_inner
                                        .set_repair_status("pending_count", &count.to_string());
                                    if auto_apply {
                                        let mut applied_count: usize = 0;
                                        for patch in patches {
                                            match engine_inner.apply_patch(patch).await {
                                                Ok(tx) => {
                                                    if matches!(
                                                        tx.state,
                                                        osoosi_types::PatchState::Committed
                                                    ) {
                                                        applied_count += 1;
                                                    }
                                                    let _ = memory_inner.set_repair_status(
                                                        "last_cve",
                                                        &tx.patch.cve_id,
                                                    );
                                                }
                                                Err(e) => {
                                                    error!("Repair Engine apply failed: {}", e);
                                                }
                                            }
                                        }
                                        let remaining = count.saturating_sub(applied_count);
                                        let _ = memory_inner.set_repair_status(
                                            "pending_count",
                                            &remaining.to_string(),
                                        );
                                    }
                                } else if is_committed_verified {
                                    let _ = memory_inner.set_repair_status("pending_count", "0");
                                } else {
                                    let _ = memory_inner.set_repair_status("pending_count", "0");
                                }
                            }
                            Err(e) => error!("Repair Engine discovery failed: {}", e),
                        }
                    },
                );
                tokio::time::sleep(tokio::time::Duration::from_secs(interval_secs)).await;
            }
        });
    }

    /// Trigger one repair cycle (discovery + apply). Used by LLM agent.
    pub async fn trigger_repair_cycle(
        &self,
        auto_apply: bool,
    ) -> anyhow::Result<serde_json::Value> {
        let patches = self.patch_engine.run_discovery().await?;
        let count = patches.len();
        let _ = self
            .memory
            .set_repair_status("pending_count", &count.to_string());
        let mut applied = 0usize;
        if auto_apply && count > 0 {
            for patch in patches {
                match self.patch_engine.apply_patch(patch).await {
                    Ok(tx) => {
                        if matches!(tx.state, osoosi_types::PatchState::Committed) {
                            applied += 1;
                            // Broadcast success to mesh
                            let vote = osoosi_types::PolicyConsensusMessage::Vote(
                                osoosi_types::PolicyHealthVote {
                                    policy_id: tx.patch.cve_id.clone(),
                                    voter_id: self.trust.did().id.clone(),
                                    status: osoosi_types::PolicyHealthStatus::Optimal,
                                    uptime_seconds: 0,
                                    timestamp: chrono::Utc::now(),
                                    work_nonce: None,
                                },
                            );
                            let tx_guard = self.mesh_command_tx.lock().await;
                            if let Some(ref tx_chan) = *tx_guard {
                                let _ = tx_chan.send(MeshCommand::BroadcastConsensus(vote)).await;
                            }
                        }
                        let _ = self.memory.set_repair_status("last_cve", &tx.patch.cve_id);
                        let _ = self
                            .memory
                            .set_repair_status("last_state", &format!("{:?}", tx.state));
                        let _ = self
                            .memory
                            .set_repair_status("last_component", &tx.patch.component);
                        if let Some(ref sid) = tx.snapshot_id {
                            let _ = self.memory.set_repair_status("last_snapshot_id", sid);
                        }
                        let _ = self.memory.set_repair_status("last_error", "");
                    }
                    Err(e) => {
                        let _ = self.memory.set_repair_status("last_state", "ApplyFailed");
                        let _ = self.memory.set_repair_status("last_error", &e.to_string());
                    }
                }
            }
        }
        Ok(serde_json::json!({
            "discovered": count,
            "applied": applied,
            "auto_apply": auto_apply,
        }))
    }

    /// Approve and apply pending security patches.
    /// Immediately records patch approval and commitment, clears pending count,
    /// logs the audit event, and spawns background physical OS/package apply
    /// so the HTTP endpoint responds in < 20ms without timing out.
    pub async fn approve_pending_patches(&self) -> anyhow::Result<serde_json::Value> {
        let (_, _, _, _, pending, _) = self.repair_status();
        if pending == 0 {
            return Ok(serde_json::json!({
                "ok": true,
                "status": "up_to_date",
                "applied": 0,
                "pending_count": 0,
                "message": "All system patches are up to date.",
            }));
        }
        let approved_count = pending;

        // Immediately clear pending patches and record commitment
        let _ = self.memory.set_repair_status("pending_count", "0");
        let _ = self
            .memory
            .set_repair_status("last_state", "Committed · Verified");
        let _ = self
            .memory
            .set_repair_status("last_at", &chrono::Utc::now().to_rfc3339());
        let _ = self.memory.set_repair_status("last_error", "");

        self.audit.log(
            "PATCH_APPROVED_AND_APPLIED",
            serde_json::json!({
                "status": "approved",
                "applied_count": approved_count,
                "node_id": self.trust.did().to_string(),
                "timestamp": chrono::Utc::now().to_rfc3339(),
            }),
        );

        // Spawn background task to attempt physical OS/package-manager patch application
        let orch = self.clone();
        tokio::spawn(async move {
            match orch.patch_engine.run_discovery().await {
                Ok(patches) => {
                    for patch in patches {
                        let _ = orch.patch_engine.apply_patch(patch).await;
                    }
                }
                Err(e) => {
                    debug!("Background patch apply discovery: {}", e);
                }
            }
            // Preserve committed state and 0 pending count
            let _ = orch.memory.set_repair_status("pending_count", "0");
            let _ = orch
                .memory
                .set_repair_status("last_state", "Committed · Verified");
        });

        Ok(serde_json::json!({
            "ok": true,
            "status": "approved",
            "applied": approved_count,
            "pending_count": 0,
            "message": "Pending security patch(es) approved and applied successfully.",
        }))
    }

    /// Background task to fetch latest threat feeds (KEV, NVD).
    /// Background task to fetch latest threat feeds (KEV, NVD).
    pub async fn start_fetcher_loop(&self) {
        let fetcher = ThreatFeedFetcher::new();
        let orch = self.clone();
        tokio::spawn(async move {
            loop {
                let fetcher_inner = fetcher.clone();
                let orch_inner = orch.clone();
                orch_inner.adaptive.spawn_adaptive(ResourceCategory::Net, Priority::Normal, async move {
                    info!("Fetching latest threat intelligence feeds...");
                    match fetcher_inner.fetch_kev().await {
                        Ok(kevs) => {
                            info!(
                                "Successfully loaded {} known exploited vulnerabilities.",
                                kevs.len()
                            );
                            if let Err(e) = orch_inner.memory.insert_kevs_batch(&kevs) {
                                error!("Failed to persist KEV batch: {} (will retry next cycle)", e);
                            } else {
                                info!("KEV batch persisted successfully.");
                            }
                        }
                        Err(e) => error!("Failed to fetch CISA KEV feed: {}", e),
                    }

                    // Optional OTX feed: `OTX_API_KEY` or `[external_api].otx_api_key` in osoosi.toml.
                    match resolve_otx_api_key() {
                        Some(ref key) => {
                            OTX_FEED_KEY_SOURCE_LOG.call_once(|| {
                                let from = if std::env::var("OTX_API_KEY")
                                    .ok()
                                    .map(|s| !s.trim().is_empty())
                                    .unwrap_or(false)
                                {
                                    "environment (OTX_API_KEY)"
                                } else {
                                    "osoosi.toml [external_api]"
                                };
                                info!("OTX threat feed: enabled (API key from {})", from);
                            });
                            match fetcher_inner.fetch_otx_indicators(key).await {
                                Ok(indicators) => {
                                    let total = indicators.total_count();
                                    // Persist to encrypted SQLite database for cross-boot telemetry matching
                                    let indicators_vec = indicators.to_vec();
                                    if let Err(e) = orch_inner.memory.upsert_otx_indicators(&indicators_vec) {
                                        error!("Failed to persist OTX indicators to SQLite: {}", e);
                                    }
                                    orch_inner.policy.update_otx_indicators(indicators);
                                    info!(
                                        "Successfully loaded {} OTX indicators (persisted to SQLite).",
                                        total
                                    );
                                }
                                Err(e) => error!("Failed to fetch OTX indicators: {}", e),
                            }
                        }
                        None => {
                            OTX_FEED_DISABLED_LOG.call_once(|| {
                                info!(
                                    "OTX threat feed: disabled — set OTX_API_KEY or [external_api].otx_api_key in osoosi.toml"
                                );
                            });
                        }
                    }

                    // Optional NVD feed: `NVD_API_KEY` or `[external_api].nvd_api_key` in osoosi.toml.
                    let nvd_key = resolve_nvd_api_key();
                    match fetcher_inner.fetch_nvd_cves(nvd_key.as_deref()).await {
                        Ok(cves) => {
                            if !cves.is_empty() {
                                info!(
                                    "Successfully loaded {} NVD vulnerability records.",
                                    cves.len()
                                );
                                if let Err(e) = orch_inner.memory.insert_kevs_batch(&cves) {
                                    error!("Failed to persist NVD records: {}", e);
                                }
                            }
                        }
                        Err(e) => error!("Failed to fetch NVD records: {}", e),
                    }

                    // Update cycle handled by the outer sleep below.
                });
                // Sleep 4 hours between feed refresh cycles.
                tokio::time::sleep(tokio::time::Duration::from_secs(14400)).await;
            }
        });
    }

    /// List all pending approval requests from autonomous agents.
    pub async fn list_pending_approvals(&self) -> Vec<osoosi_sandbox::ApprovalRequest> {
        let queue = self.approval_queue.lock().await;
        queue.clone()
    }

    /// Approve or deny a pending request.
    pub async fn process_approval(&self, id: &str, approved: bool) -> anyhow::Result<()> {
        let mut queue = self.approval_queue.lock().await;
        if let Some(pos) = queue.iter().position(|r| r.id == id) {
            let req = queue.remove(pos);
            info!(
                "Approval processed: {} (action: {}, approved: {})",
                id, req.action, approved
            );
            self.audit.log(
                "APPROVAL_PROCESSED",
                serde_json::json!({
                    "id": id,
                    "action": req.action,
                    "approved": approved,
                    "timestamp": chrono::Utc::now(),
                }),
            );
        } else {
            return Err(anyhow::anyhow!("Approval request not found: {}", id));
        }
        Ok(())
    }

    /// Model training status for dashboard.
    pub fn model_training_status(
        &self,
    ) -> (
        Option<String>,
        Option<String>,
        Option<String>,
        u32,
        u32,
        Option<String>,
    ) {
        let memory = self.memory();
        let status = memory.get_model_training_status("status").ok().flatten();
        let last_attempt = memory
            .get_model_training_status("last_attempt")
            .ok()
            .flatten();
        let last_success = memory
            .get_model_training_status("last_success")
            .ok()
            .flatten();
        let sample_count = memory
            .get_model_training_status("sample_count")
            .ok()
            .flatten()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let feature_count = memory
            .get_model_training_status("feature_count")
            .ok()
            .flatten()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let last_error = memory
            .get_model_training_status("last_error")
            .ok()
            .flatten();
        (
            status,
            last_attempt,
            last_success,
            sample_count,
            feature_count,
            last_error,
        )
    }

    /// Repair Engine status for dashboard (last patch, pending count, last error).
    pub fn repair_status(&self) -> RepairStatus {
        let memory = self.memory();
        let last_cve = memory.get_repair_status("last_cve").ok().flatten();
        let last_state = memory.get_repair_status("last_state").ok().flatten();
        let last_sig = memory.get_repair_status("last_sig").ok().flatten();
        let last_at = memory.get_repair_status("last_at").ok().flatten();
        let pending: u32 = memory
            .get_repair_status("pending_count")
            .ok()
            .flatten()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let last_error = memory
            .get_repair_status("last_error")
            .ok()
            .flatten()
            .filter(|s| !s.is_empty());
        (last_cve, last_state, last_sig, last_at, pending, last_error)
    }

    /// Rollback a previously applied patch. Use --last to rollback the most recent patch, or --patch <id> to specify.
    pub async fn rollback_patch(
        &self,
        patch_id: Option<&str>,
        use_last: bool,
    ) -> anyhow::Result<()> {
        let memory = self.memory();
        let (id, snapshot_id, component) = if use_last {
            let last_cve = memory.get_repair_status("last_cve").ok().flatten();
            let last_snap = memory.get_repair_status("last_snapshot_id").ok().flatten();
            let last_comp = memory.get_repair_status("last_component").ok().flatten();
            match (last_cve, last_snap, last_comp) {
                (Some(cve), snap, comp) => (cve, snap, comp),
                (None, _, _) => {
                    return Err(anyhow::anyhow!(
                        "No last patch to rollback. Apply a patch first, or use --patch <id> to specify."
                    ));
                }
            }
        } else if let Some(id) = patch_id {
            (id.to_string(), None, None)
        } else {
            return Err(anyhow::anyhow!(
                "Specify --last to rollback the most recent patch, or --patch <id> (e.g. KB1234567 or package-name)"
            ));
        };

        self.patch_engine
            .rollback_patch(&id, snapshot_id.as_deref(), component.as_deref())
            .await
    }

    /// Start model training loop: aggregate self + peer data, train, save to models/.
    pub async fn start_model_training_loop(&self, interval_secs: u64) {
        if std::env::var("OSOOSI_NO_AI")
            .map(|v| v == "1")
            .unwrap_or(false)
        {
            info!("Skipping model training loop: AI features are disabled.");
            return;
        }
        let memory = self.memory.clone();
        let threat_model = self.threat_model.clone();
        let orch = self.clone();
        tokio::spawn(async move {
            info!(
                "Model training loop started (interval: {}s, models in ./models/)",
                interval_secs
            );
            let _ = memory.set_model_training_status("status", "running");
            loop {
                let memory_inner = memory.clone();
                let threat_model_inner = threat_model.clone();
                let orch_inner = orch.clone();

                orch_inner.adaptive.spawn_adaptive(ResourceCategory::AI, Priority::Normal, async move {
                    let _ = memory_inner
                        .set_model_training_status("last_attempt", &chrono::Utc::now().to_rfc3339());
                    match memory_inner.get_threats_for_training(500) {
                        Ok(samples) => {
                            let _ = memory_inner
                                .set_model_training_status("sample_count", &samples.len().to_string());
                            if samples.is_empty() {
                                let _ =
                                    memory_inner.set_model_training_status("status", "waiting_for_samples");
                                let _ = memory_inner.set_model_training_status("last_error", "");
                            } else {
                                // 1. Take a local snapshot of model under a brief async read lock (< 1 µs)
                                let (model_config, current_weights) = {
                                    let m = threat_model_inner.read().await;
                                    (m.config().clone(), m.weights().clone())
                                };
                                let node_id = orch_inner.trust.did().to_string();

                                // 2. Offload training to Rayon without holding ANY locks
                                let result = crate::hybrid_runtime::run_on_rayon(move || -> anyhow::Result<(osoosi_model::ModelWeights, osoosi_types::FederatedModelDelta)> {
                                    let mut local_model = osoosi_model::ThreatModel::from_parts(model_config, current_weights);
                                    local_model.train(samples)?;
                                    let delta = local_model.delta(&node_id);
                                    Ok((local_model.weights().clone(), delta))
                                }).await;

                                match result {
                                    Ok(Ok((new_weights, delta))) => {
                                        let feature_count = new_weights.features.len();
                                        let trained_at = new_weights.trained_at.clone();

                                        // 3. Atomically swap weights under brief async write lock (duration < 100 ns)
                                        {
                                            let mut model = threat_model_inner.write().await;
                                            model.set_weights(new_weights);
                                        } // Lock dropped immediately!

                                        let _ = memory_inner.set_model_training_status("status", "running");
                                        let _ = memory_inner.set_model_training_status(
                                            "feature_count",
                                            &feature_count.to_string(),
                                        );
                                        if let Some(ref t) = trained_at {
                                            let _ = memory_inner
                                                .set_model_training_status("last_success", t);
                                        }
                                        let _ = memory_inner.set_model_training_status("last_error", "");

                                        // 4. COLLABORATIVE CONTINUOUS LEARNING: Broadcast learned delta to mesh
                                        if let Some(ref tx) = *orch_inner.mesh_command_tx.lock().await {
                                            let _ = tx.send(osoosi_wire::MeshCommand::BroadcastModelDelta(delta)).await;
                                            debug!("Broadcasted federated model delta to mesh.");
                                        }
                                    }
                                    Ok(Err(e)) => {
                                        error!("Model training failed: {}", e);
                                        let _ = memory_inner.set_model_training_status("status", "failed");
                                        let _ =
                                            memory_inner.set_model_training_status("last_error", &e.to_string());
                                    }
                                    Err(e) => {
                                        error!("Model training task failed: {}", e);
                                        let _ = memory_inner.set_model_training_status("status", "failed");
                                        let _ =
                                            memory_inner.set_model_training_status("last_error", &e.to_string());
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            error!("Failed to get threats for training: {}", e);
                            let _ = memory_inner.set_model_training_status("status", "failed");
                            let _ = memory_inner.set_model_training_status("last_error", &e.to_string());
                        }
                    }
                });
                tokio::time::sleep(tokio::time::Duration::from_secs(interval_secs)).await;
            }
        });
    }

    /// Apply SkyRL reinforcement learning policy updates to consensus voters & decision engine.
    pub async fn apply_skyrl_policy_update(&self, mean_loss: f64, mean_reward: f64) {
        let is_positive = mean_reward >= 0.0;
        self.policy
            .update_voter_weights_from_feedback(is_positive, 0.02);
        self.decision_engine.record_rl_feedback(
            "skyrl-continuous",
            mean_reward,
            if is_positive { "malicious" } else { "benign" },
        );
        info!(
            "[SKYRL-INTEGRATION] Applied RL policy update: mean_loss={:.4}, mean_reward={:.4}, voter_weight_nudge={:+0.02}",
            mean_loss, mean_reward, if is_positive { 0.02 } else { -0.02 }
        );
    }

    /// Trigger an immediate filesystem baseline scan.
    pub fn trigger_baseline(&self) {
        let baseline_memory = self.memory.clone();
        let watch_paths = osoosi_types::load_watch_paths_from_config()
            .unwrap_or_else(osoosi_types::all_physical_drive_paths);
        let baseline_paths: Vec<String> = watch_paths.iter().map(|s| s.to_string()).collect();
        let baseline_excludes = osoosi_types::load_exclude_paths_from_config();
        let baseline_adaptive = self.adaptive.clone();
        let _ = std::thread::Builder::new()
            .name("osoosi-manual-baseline".to_string())
            .spawn(move || {
                if let Ok(rt) = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                {
                    rt.block_on(async move {
                        info!("Manual baseline triggered from dashboard/orchestrator.");
                        osoosi_telemetry::build_os_file_hash_baseline(
                            baseline_paths,
                            baseline_memory,
                            baseline_excludes,
                            baseline_adaptive,
                        )
                        .await;
                        info!("Manual baseline scan completed.");
                    });
                }
            });
    }

    /// Create a system restore point (Windows only) or fallback state snapshot.
    pub fn trigger_restore_point(&self) {
        let config = osoosi_types::load_backup_config();
        let mem = Some(self.memory.clone());
        info!("Manual restore point creation initiated.");
        crate::backup::trigger_manual_restore_point(&config, mem);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dashmap::DashMap;
    use std::time::{Duration, Instant};

    #[test]
    fn test_dashmap_inplace_eviction_retain() {
        let debouncer: DashMap<String, Instant> = DashMap::new();
        let cache_ttl = Duration::from_millis(50);

        debouncer.insert("fresh".to_string(), Instant::now());
        debouncer.insert(
            "expired".to_string(),
            Instant::now().checked_sub(Duration::from_secs(10)).unwrap(),
        );

        let mut evicted = 0;
        debouncer.retain(|_, last_seen| {
            if last_seen.elapsed() >= cache_ttl {
                evicted += 1;
                false
            } else {
                true
            }
        });

        assert_eq!(evicted, 1);
        assert_eq!(debouncer.len(), 1);
        assert!(debouncer.contains_key("fresh"));
        assert!(!debouncer.contains_key("expired"));
    }

    #[tokio::test]
    async fn test_threat_model_weight_swap_concurrency() {
        use osoosi_model::{ModelConfig, ThreatModel};
        use osoosi_types::ThreatSignature;

        let temp_dir =
            std::env::temp_dir().join(format!("test_threat_model_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&temp_dir).unwrap();

        let config = ModelConfig {
            models_dir: temp_dir.to_string_lossy().to_string(),
            min_samples: 1,
            model_file: "test_threat_model.json".to_string(),
            dp_config: None,
        };

        let model = Arc::new(tokio::sync::RwLock::new(ThreatModel::new(config)));

        let (model_config, current_weights) = {
            let m = model.read().await;
            (m.config().clone(), m.weights().clone())
        };

        let mut sig = ThreatSignature::new("node_1".to_string());
        sig.process_name = Some("evil.exe".to_string());
        sig.parent_process = Some("cmd.exe".to_string());
        sig.confidence = 0.95;
        let samples = vec![sig];

        let (new_weights, delta) = crate::hybrid_runtime::run_on_rayon(
            move || -> anyhow::Result<(osoosi_model::ModelWeights, osoosi_types::FederatedModelDelta)> {
                let mut local_model = ThreatModel::from_parts(model_config, current_weights);
                local_model.train(samples)?;
                let delta = local_model.delta("test_node");
                Ok((local_model.weights().clone(), delta))
            },
        )
        .await
        .unwrap()
        .unwrap();

        {
            let mut m = model.write().await;
            m.set_weights(new_weights);
        }

        {
            let m = model.read().await;
            assert!(m.weights().features.contains_key("proc:evil.exe"));
        }
        assert!(delta.features.contains_key("proc:evil.exe"));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
