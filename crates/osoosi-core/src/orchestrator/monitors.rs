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
    /// CEREBUS port: CyberShield Real-Time Monitor
    /// Tracks processes for high resource usage and suspicious behavior.
    pub fn start_cybershield_monitor(&self) {
        let orchestrator = self.clone();
        tokio::spawn(async move {
            use sysinfo::*;
            let mut sys = System::new_all();
            info!("CyberShield Real-Time Monitor active (CEREBUS-AI port).");

            // Auto-start browser auditor alongside cybershield
            orchestrator.start_browser_auditor();

            // Auto-start Phantom Memory Flux (Deceptive Memory Tarpit)
            let flux_regions =
                std::sync::Arc::new(tokio::sync::RwLock::new(std::collections::HashSet::new()));
            let tarpit_manager = osoosi_runtime::TarpitManager::new();
            tarpit_manager.start_phantom_memory_flux(flux_regions.clone());

            let mut interval = tokio::time::interval(Duration::from_secs(30));
            let process_debounce =
                std::sync::Arc::new(dashmap::DashMap::<String, std::time::Instant>::new());
            loop {
                interval.tick().await;
                sys.refresh_all();

                // Periodic eviction of expired debounce entries to prevent unbounded growth in long-running daemons
                if process_debounce.len() > 1024 {
                    process_debounce
                        .retain(|_, last_seen| last_seen.elapsed() < Duration::from_secs(600));
                }

                let total_memory = sys.total_memory();
                let memory_threshold = total_memory / 2; // 50%
                let my_pid = Pid::from(std::process::id() as usize);

                for (pid, process) in sys.processes() {
                    if *pid == my_pid {
                        continue; // NEVER scan self
                    }

                    let process_name = process.name().to_string();
                    let process_name_lc = process_name.to_lowercase();
                    let exe_path = process.exe().map(|p| p.to_path_buf());

                    // EXEMPTIONS: Critical system processes, cloud sync / virtual filesystems, and developer tools
                    let is_exempt_system = process_name_lc == "msmpeng.exe"
                        || process_name_lc == "trustedinstaller.exe"
                        || process_name_lc == "tiworker.exe"
                        || process_name_lc == "googleupdater.exe"
                        || process_name_lc == "updater.exe"
                        || process_name_lc == "taskhostw.exe"
                        || process_name_lc == "searchindexer.exe"
                        || process_name_lc == "wermgr.exe"
                        || process_name_lc == "compattelrunner.exe"
                        || process_name_lc == "sihost.exe"
                        || process_name_lc == "ctfmon.exe";
                    let is_exempt_dev = is_developer_tool(&process_name_lc, exe_path.as_deref());
                    let is_exempt_cloud =
                        is_cloud_storage_service(&process_name_lc, exe_path.as_deref());

                    if is_exempt_system || is_exempt_dev || is_exempt_cloud {
                        let cpu_usage = process.cpu_usage();
                        let raw_memory = process.memory();
                        let private_commit = process.virtual_memory();
                        let effective_memory = if raw_memory > total_memory {
                            private_commit.min(total_memory)
                        } else if private_commit > 0
                            && private_commit < memory_threshold
                            && raw_memory > memory_threshold
                        {
                            private_commit
                        } else {
                            raw_memory
                        };
                        let memory_usage = effective_memory.min(total_memory);

                        if cpu_usage > 300.0 || memory_usage > memory_threshold {
                            let pid_val = pid.as_u32();
                            let pid_key = format!("{}:{}", pid_val, process_name_lc);
                            let name_key = format!("name:{}", process_name_lc);
                            let is_debounced =
                                if let Some(last_seen) = process_debounce.get(&pid_key) {
                                    last_seen.elapsed() < Duration::from_secs(600)
                                } else if let Some(last_seen) = process_debounce.get(&name_key) {
                                    last_seen.elapsed() < Duration::from_secs(600)
                                } else {
                                    false
                                };
                            if is_debounced {
                                continue;
                            }
                            let now = std::time::Instant::now();
                            process_debounce.insert(pid_key, now);
                            process_debounce.insert(name_key, now);

                            let exemption_label = if is_exempt_cloud {
                                "cloud_storage_vfs"
                            } else if is_exempt_system {
                                "system_maintenance"
                            } else {
                                "developer_tool"
                            };
                            orchestrator.audit.log(
                                "CYBERSHIELD_RESOURCE_ANOMALY",
                                serde_json::json!({
                                    "process_name": process_name,
                                    "pid": pid_val,
                                    "cpu_usage": cpu_usage,
                                    "memory_usage_kb": memory_usage / 1024,
                                    "threshold_memory_kb": memory_threshold / 1024,
                                    "exemption": exemption_label,
                                    "action": "monitored_no_kill",
                                }),
                            );
                        }
                        continue;
                    }

                    let cpu_usage = process.cpu_usage();
                    let raw_memory = process.memory();
                    let private_commit = process.virtual_memory();
                    // Working-set / physical memory check:
                    // Mapped virtual files and VFS sparse views inflate raw working set beyond installed RAM.
                    let effective_memory = if raw_memory > total_memory {
                        private_commit.min(total_memory)
                    } else if private_commit > 0
                        && private_commit < memory_threshold
                        && raw_memory > memory_threshold
                    {
                        private_commit
                    } else {
                        raw_memory
                    };
                    let memory_usage = effective_memory.min(total_memory);

                    // Higher thresholds for alerting (3.0 cores CPU, 50% RAM)
                    if cpu_usage > 300.0 || memory_usage > memory_threshold {
                        let orch = orchestrator.clone();
                        let pid_val = pid.as_u32();

                        if pid_val == 0
                            || pid_val == 4
                            || process_name.eq_ignore_ascii_case("System")
                            || process_name.eq_ignore_ascii_case("Registry")
                        {
                            continue;
                        }

                        // Per-process debounce (10-minute cooldown) to prevent warning floods
                        let pid_key = format!("{}:{}", pid_val, process_name_lc);
                        let name_key = format!("name:{}", process_name_lc);
                        let is_debounced = if let Some(last_alert) = process_debounce.get(&pid_key)
                        {
                            last_alert.elapsed() < Duration::from_secs(600)
                        } else if let Some(last_alert) = process_debounce.get(&name_key) {
                            last_alert.elapsed() < Duration::from_secs(600)
                        } else {
                            false
                        };
                        if is_debounced {
                            continue;
                        }
                        let now = std::time::Instant::now();
                        process_debounce.insert(pid_key, now);
                        process_debounce.insert(name_key, now);

                        orchestrator.adaptive().spawn_adaptive(ResourceCategory::AI, Priority::High, async move {
                            warn!(
                                "CyberShield Insight: Process {} (PID {}) exceeds resource thresholds (CPU: {:.1}%, Mem: {}KB).",
                                process_name, pid_val, cpu_usage, memory_usage / 1024
                            );
                            orch.audit.log(
                                "CYBERSHIELD_RESOURCE_ANOMALY",
                                serde_json::json!({
                                    "process_name": process_name,
                                    "pid": pid_val,
                                    "cpu_usage": cpu_usage,
                                    "memory_usage_kb": memory_usage / 1024,
                                    "threshold_memory_kb": memory_threshold / 1024,
                                    "action": "inspecting_binary",
                                }),
                            );

                            // Analyze the image path immediately using the CEREBUS-enhanced MalwareScanner
                            if let Some(path) = exe_path {
                                let path_str = path.to_string_lossy();
                                if should_skip_file_malware_scan(&path)
                                    || orch
                                        .memory
                                        .is_internal_asset_path(&path_str)
                                        .unwrap_or(false)
                                {
                                    debug!(
                                        "CyberShield: skipping internal asset image {}",
                                        path.display()
                                    );
                                    return;
                                }
                                if let Some(result) = orch.malware_scanner.scan_file(&path).await {
                                    if !result.is_malware {
                                        orch.audit.log(
                                            "SCAN_CLEAN",
                                            serde_json::json!({
                                                "file_path": result.file_path,
                                                "context": "CyberShield",
                                                "process_name": process_name,
                                                "action": "allowed",
                                            }),
                                        );
                                        return; // Clean — let it go
                                    }
                                    // Distinguish between a pure resource anomaly and confirmed malicious code.
                                    // Never kill a process on an ambiguous or borderline heuristic ML score.
                                    let is_dev = is_developer_tool(&process_name_lc, Some(&path));
                                    let confirmed_malicious = if is_dev {
                                        // Developer tools must not be classified as a malicious kill target
                                        // unless signature_score >= 0.95 with confirmed C2 signatures.
                                        let has_confirmed_c2 = result.malware_type.to_lowercase().contains("c2")
                                            || result.malware_type.to_lowercase().contains("beacon")
                                            || result.malware_type.to_lowercase().contains("sliver")
                                            || result.malware_type.to_lowercase().contains("cobalt")
                                            || result.yara_matches.iter().any(|m| {
                                                let m_lc = m.to_lowercase();
                                                m_lc.contains("c2") || m_lc.contains("beacon") || m_lc.contains("sliver") || m_lc.contains("cobalt")
                                            });
                                        result.is_malware && result.signature_score >= 0.95 && has_confirmed_c2
                                    } else {
                                        result.is_malware
                                            && (result.signature_score >= 0.85
                                                || result.ml_score >= 0.90
                                                || (result.signature_score > 0.0 && result.combined_score >= 0.85))
                                    };

                                    if confirmed_malicious {
                                        warn!("CyberShield INTERCEPTION: High-resource process {} is CONFIRMED MALICIOUS (sig: {:.2}, ml: {:.2}, combined: {:.2}). Triggering active response.",
                                            process_name, result.signature_score, result.ml_score, result.combined_score);

                                        // NEW: Holographic Deception Sharding (HDS) activation
                                        // Calculate "fake" attacker IP (prototype uses local loopback for testing)
                                        let _ = orch.activate_mesh_hologram("127.0.0.1").await;

                                        // Tarpit the suspicious process
                                        #[cfg(target_os = "windows")]
                                        unsafe {
                                            use windows::Win32::System::Threading::{OpenProcess, PROCESS_SUSPEND_RESUME};
                                            use windows::Win32::Foundation::CloseHandle;

                                            if let Ok(handle) = OpenProcess(PROCESS_SUSPEND_RESUME, false, pid_val) {
                                                // NtSuspendProcess is the most reliable way to suspend a whole process
                                                let ntdll = windows::Win32::System::LibraryLoader::GetModuleHandleW(windows::core::w!("ntdll.dll")).unwrap_or_default();
                                                if !ntdll.is_invalid() {
                                                    if let Some(nt_suspend) = windows::Win32::System::LibraryLoader::GetProcAddress(ntdll, windows::core::s!("NtSuspendProcess")) {
                                                        let nt_suspend: extern "system" fn(windows::Win32::Foundation::HANDLE) -> i32 = std::mem::transmute(nt_suspend);
                                                        let _ = nt_suspend(handle);
                                                        info!("CyberShield: Suspended malicious process {} (PID {}) via native NT API.", process_name, pid_val);
                                                    }
                                                }
                                                let _ = CloseHandle(handle);
                                            }
                                        }
                                    } else {
                                        info!(
                                            "CyberShield: High-resource process {} flagged as resource anomaly without confirmed malicious indicators (sig: {:.2}, ml: {:.2}). Skipping kill.",
                                            process_name, result.signature_score, result.ml_score
                                        );
                                    }
                                }
                            }
                        });
                    }
                }
            }
        });
    }

    /// Start behavioral detector: streams System/Application logs (Windows, Linux, macOS)
    /// into SecureBERT-style classification. First detection layer before file/malware scan.
    pub fn start_behavioral_detector(&self) {
        let orchestrator = self.clone();
        tokio::spawn(async move {
            let reader = osoosi_behavioral::BehavioralLogReader::new();
            let classifier = orchestrator.behavioral_classifier.clone();
            let analyzer = orchestrator.behavioral_analyzer.clone();
            let interval_secs: u64 = std::env::var("OSOOSI_BEHAVIORAL_INTERVAL")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(10);
            info!(
                "Behavioral detector active (System/App logs, interval: {}s)",
                interval_secs
            );
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
            loop {
                interval.tick().await;
                let reader_clone = reader.clone();
                let poll_result =
                    tokio::task::spawn_blocking(move || reader_clone.poll_events()).await;
                match poll_result.unwrap_or(Err(anyhow::anyhow!("Poll task panicked"))) {
                    Ok(events) => {
                        for event in events {
                            // Self-audit filter: skip events generated by osoosi itself
                            // to prevent feedback loops where our own log writes trigger
                            // more anomaly detections.
                            let is_self = event
                                .data
                                .get("ProcessName")
                                .or(event.data.get("Image"))
                                .or(event.data.get("NewProcessName"))
                                .and_then(|v| v.as_str())
                                .map(|s| {
                                    let lower = s.to_ascii_lowercase();
                                    lower.contains("osoosi") || lower.contains("oshoosi")
                                })
                                .unwrap_or(false);
                            if is_self {
                                continue;
                            }

                            // Synthetic Canary Filter: suppress canary heartbeats from sliding-window
                            // process tree and prevent RL baseline drift.
                            if osoosi_telemetry::canary::is_canary_event(&event) {
                                continue;
                            }

                            let classifier_clone = classifier.clone();
                            let orchestrator_clone = orchestrator.clone();
                            let analyzer_clone = analyzer.clone();
                            let event_clone = event.clone();

                            orchestrator.adaptive.spawn_adaptive(ResourceCategory::AI, Priority::High, async move {
                                // Tier 1: CoLog Autonomous Sequence Check
                                let colog_score = analyzer_clone.autonomous_check(event_clone).await;
                                if colog_score > 0.85 {
                                    warn!("COLOG ANOMALY: Sequence deviation detected (score={:.2}) for source {}", colog_score, event.source);
                                    orchestrator_clone.audit.log(
                                        "COLOG_ANOMALY",
                                        serde_json::json!({
                                            "source": event.source,
                                            "score": colog_score,
                                            "event_id": event.event_id,
                                            "data": event.data.get("Message"),
                                        }),
                                    );
                                }

                                // Layer 2: SecureBERT / Rule-based Classification
                                let result = classifier_clone.classify(&event).await;
                                if result.is_suspicious {
                                    let should_log =
                                        match orchestrator_clone.behavioral_debouncer.get(&result.reason) {
                                            Some(last) => last.elapsed() > std::time::Duration::from_secs(300),
                                            None => true,
                                        };

                                    if should_log {
                                        warn!(
                                            "BEHAVIORAL ALERT: {} (score={:.2}, reason={})",
                                            result.sentence.chars().take(80).collect::<String>(),
                                            result.score,
                                            result.reason
                                        );
                                        orchestrator_clone
                                            .behavioral_debouncer
                                            .insert(result.reason.clone(), std::time::Instant::now());
                                    }

                                    orchestrator_clone.audit.log(
                                        "BEHAVIORAL_ALERT",
                                        serde_json::json!({
                                            "sentence": result.sentence,
                                            "score": result.score,
                                            "reason": result.reason,
                                            "event_id": result.event_id,
                                            "source": result.source,
                                            "timestamp": chrono::Utc::now(),
                                        }),
                                    );
                                }
                            });
                        }
                    }
                    Err(e) => {
                        tracing::debug!("Behavioral log poll failed: {}", e);
                    }
                }
            }
        });
    }

    /// Start watching directories for changes. Call once with all paths.
    pub async fn start_file_watcher(&self, path: &str) -> anyhow::Result<()> {
        self.start_file_watcher_paths(&[path]).await
    }

    /// Start watching multiple directories. Active real-time monitoring.
    pub async fn start_file_watcher_paths(&self, paths: &[&str]) -> anyhow::Result<()> {
        {
            let mut watcher: tokio::sync::MutexGuard<osoosi_telemetry::FileWatcher> =
                self.watcher.lock().await;
            for path in paths {
                if let Err(e) = watcher.watch(path) {
                    tracing::warn!("Could not watch {}: {}", path, e);
                } else {
                    info!("File Monitor: Watching {}", path);
                }
            }
        }
        info!(
            "File Change Monitor is active ({} paths registered).",
            paths.len()
        );

        // Start background OS file baseline hash on startup
        let baseline_memory = self.memory.clone();
        let baseline_paths: Vec<String> = paths.iter().map(|&s| s.to_string()).collect();
        let baseline_excludes = osoosi_types::load_exclude_paths_from_config();
        let baseline_adaptive = self.adaptive.clone();
        tokio::spawn(async move {
            // Delay baseline hashing to allow the agent to finish startup and settle
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            osoosi_telemetry::build_os_file_hash_baseline(
                baseline_paths,
                baseline_memory,
                baseline_excludes,
                baseline_adaptive,
            )
            .await;
        });

        let orchestrator = self.clone();
        let rx_opt = {
            let mut guard = self.file_event_rx.lock().await;
            guard.take()
        };

        if let Some(mut rx) = rx_opt {
            tokio::spawn(async move {
                info!("File Monitor: Real-time event loop started.");
                let mut set = tokio::task::JoinSet::new();
                // Cache concurrency limit; refresh lazily every 64 events to avoid async overhead
                // in the tight file-event loop. The adaptive controller updates this in background.
                let mut limit_refresh_counter: u32 = 0;
                let mut cached_limit: usize = 6;
                while let Some(res) = rx.recv().await {
                    if let Ok(event) = res {
                        limit_refresh_counter += 1;
                        if limit_refresh_counter % 64 == 1 {
                            cached_limit = orchestrator
                                .adaptive()
                                .get_concurrency_limit()
                                .await
                                .clamp(2, 6);
                        }
                        while set.len() >= cached_limit {
                            let _ = set.join_next().await;
                        }
                        let orchestrator = orchestrator.clone();
                        set.spawn(async move {
                            if event.path.contains(".tmp.driveupload") || event.path.contains(".tmp.drivedownload") {
                                debug!("File Monitor: skipping Google Drive sync temp file: {}", event.path);
                                return;
                            }

                            info!(
                                "File change detected: {} (Hash: {})",
                                event.path, event.hash
                            );

                            if orchestrator.memory.is_hash_clean_ignored(&event.hash) {
                                debug!("File Monitor: skipping clean-ignored hash: {} ({})", event.hash, event.path);
                                return;
                            }

                            let path = std::path::Path::new(&event.path);
                            if !path.exists() {
                                debug!("File Monitor: skipping vanished/ephemeral file: {}", event.path);
                                return;
                            }

                            // Intercept browser HTTP Archive (.har) logs for Layer-7 threat inspection (event_id: 77)
                            if event.path.to_ascii_lowercase().ends_with(".har") {
                                info!("File Monitor: Intercepted .har file modification for Layer-7 inspection: {}", event.path);
                                let har_sec_event = osoosi_types::HostSecurityEvent {
                                    source: osoosi_types::HostEventSource::WindowsEventLog,
                                    event_id: 77,
                                    timestamp: chrono::Utc::now(),
                                    computer: orchestrator.trust.did().to_string(),
                                    data: serde_json::json!({
                                        "TargetFilename": event.path,
                                        "FilePath": event.path,
                                        "EventDescription": "Browser HAR Network Archive Created/Modified",
                                    }),
                                    causal_parent: None,
                                };
                                let _ = orchestrator.process_security_event_internal(har_sec_event).await;
                            }

                            if orchestrator.canary.is_canary(path) {
                                warn!("CANARY_TRIPWIRE_ALERT: Honey-file access detected at {:?} (Hash: {})", event.path, event.hash);
                                orchestrator.audit.log(
                                    "CANARY_TRIPWIRE_ALERT",
                                    serde_json::json!({
                                        "path": event.path,
                                        "hash": event.hash,
                                        "node_id": orchestrator.trust.did().to_string(),
                                    }),
                                );
                                let mut sig = osoosi_types::ThreatSignature::new(orchestrator.trust.did().to_string());
                                sig.add_reason(format!("Canary Honey-File tripwire triggered on {:?}", path));
                                sig.confidence = 1.0;
                                sig.action_state = osoosi_types::ActionState::Pending;
                                sig.recommended_action = osoosi_types::ResponseAction::Isolate;
                                let _ = orchestrator.memory.log_threat(&sig);

                                let alert = osoosi_types::MeshTripwireAlert {
                                    source_node_id: orchestrator.trust.did().to_string(),
                                    timestamp_utc: chrono::Utc::now().timestamp_millis(),
                                    trigger: osoosi_types::TarpitArtifact::PoisonedCredential {
                                        hash: event.hash.clone(),
                                        token_type: format!("Canary Honey-File: {:?}", path.file_name().unwrap_or_default()),
                                    },
                                    offender: osoosi_types::OffendingProcess {
                                        pid: 0,
                                        name: "Unknown Process".to_string(),
                                        executable_path: event.path.clone(),
                                        blake3_hash: event.hash.clone(),
                                        command_line: Some(format!("Canary honey-file tripwire on {}", event.path)),
                                    },
                                    cryptographic_signature: Vec::new(),
                                    merkle_proof: None,
                                };
                                let tx_guard = orchestrator.mesh_command_tx.lock().await;
                                if let Some(ref tx) = *tx_guard {
                                    let _ = tx.try_send(osoosi_wire::MeshCommand::BroadcastTripwire(alert));
                                }
                                return;
                            }
                            let file_stem = path.file_name().and_then(|n| n.to_str());
                            if should_skip_file_malware_scan(path)
                                || is_internal_or_deception_path(&event.path)
                                || orchestrator
                                    .memory
                                    .is_internal_asset_path(&event.path)
                                    .unwrap_or(false)
                                || crate::win_trust::is_trusted_signed_binary(path)
                                || orchestrator.memory.is_nsrl_known_good(&event.hash).unwrap_or(false)
                                || orchestrator.memory.is_false_positive_pattern(file_stem, Some(&event.hash)).unwrap_or(false)
                            {
                                debug!(
                                    "File Monitor: skipping scan for trusted/excluded path {:?} (Hash: {})",
                                    event.path, event.hash
                                );
                                return;
                            }

                            let _ = orchestrator
                                .memory
                                .update_file_hash(&event.path, &event.hash);

                            if let Ok(Some(verdict)) = orchestrator.memory.get_ai_override(&event.hash)
                            {
                                if verdict {
                                    warn!("File Monitor: local ledger marks {} as malicious; escalating without model scan.", event.path);
                                } else {
                                    info!(
                                        "File Monitor: local ledger allows {}; skipping AI scan.",
                                        event.path
                                    );
                                    return;
                                }
                            }

                            if let Some(result) = orchestrator.malware_scanner.scan_file(path).await {
                            // ClamAV is decommissioned. Rely on native YaraX and ML scores.

                            // 2. Trigger Deep Static Analysis (CAPA, FLOSS, Falcon) for suspicious files or executables
                            let is_executable = result.magika_label.contains("exe")
                                || result.magika_label.contains("pe")
                                || result.magika_label.contains("elf");
                            if (result.combined_score > 0.5 || is_executable)
                                && !crate::win_trust::is_trusted_signed_binary(path)
                                && !osoosi_model::malware::is_ide_or_build_path(&event.path)
                                && !crate::voters::scanner_skip_path(&event.path)
                                && !should_skip_file_malware_scan(path)
                            {
                                let analyzer = orchestrator.static_analyzer.clone();
                                let path_buf = path.to_path_buf();
                                let orch_clone = orchestrator.clone();
                                tokio::spawn(async move {
                                    match analyzer.analyze_file(&path_buf).await {
                                    Ok(Some(deep_sig)) => {
                                        let sig_key = deep_sig
                                            .hash_blake3
                                            .clone()
                                            .unwrap_or_else(|| format!("{}:{}", path_buf.to_string_lossy().replace('/', "\\"), deep_sig.id));
                                        if orch_clone.alert_suppression_cache.len() > 2048 {
                                            orch_clone.alert_suppression_cache.retain(|_, last_warn| last_warn.elapsed() < Duration::from_secs(3600));
                                        }
                                        let is_suppressed = {
                                            if let Some(last_warn) = orch_clone.alert_suppression_cache.get(&sig_key) {
                                                last_warn.elapsed() < Duration::from_secs(3600)
                                            } else {
                                                false
                                            }
                                        };
                                        if !is_suppressed {
                                            orch_clone.alert_suppression_cache.insert(sig_key, Instant::now());
                                            if deep_sig.confidence >= 0.85 {
                                                warn!(
                                                    "DEEP ANALYSIS IDENTIFIED THREAT (CAPA/FLOSS): {} ({}) - confidence {:.2}",
                                                    deep_sig.id,
                                                    path_buf.display(),
                                                    deep_sig.confidence
                                                );
                                            } else {
                                                info!(
                                                    "Deep analysis heuristic signal: {} ({}) - confidence {:.2}",
                                                    deep_sig.id,
                                                    path_buf.display(),
                                                    deep_sig.confidence
                                                );
                                            }
                                            let _ = orch_clone.memory.log_threat(&deep_sig);
                                            orch_clone.audit.log("DEEP_STATIC_THREAT", serde_json::json!({
                                                "path": path_buf.display().to_string(),
                                                "reasons": deep_sig.reason,
                                                "confidence": deep_sig.confidence
                                            }));
                                        }
                                    }
                                    Ok(None) => debug!("Deep analysis complete: no additional threats found for {:?}", path_buf),
                                    Err(e) => error!("Deep static analysis failed for {:?}: {}", path_buf, e),
                                }
                                });
                            }

                            if result.is_malware {
                                if !path.exists() {
                                    debug!(
                                        "File Monitor: candidate malware vanished before action: {}",
                                        result.file_path
                                    );
                                    return;
                                }

                                let sig_info = crate::win_trust::inspect_binary_authenticode(path);
                                if sig_info.is_valid {
                                    if let Some(ref subject) = sig_info.signer_subject {
                                        if crate::win_trust::is_trusted_vendor(subject) {
                                            info!(
                                                "File Monitor: verified Authenticode digital signature for trusted vendor '{}' on {}. Disregarding ML flag as false positive (SUPPRESSED_FP).",
                                                subject, result.file_path
                                            );
                                            orchestrator.malware_scanner.purge_detection_by_path_or_hash(Some(&result.file_path), Some(&result.file_hash));
                                            return;
                                        }
                                    }
                                    if crate::win_trust::is_trusted_signed_binary(path) {
                                        info!(
                                            "File Monitor: verified Authenticode digital signature on {}. Disregarding ML flag as false positive (SUPPRESSED_FP).",
                                            result.file_path
                                        );
                                        orchestrator.malware_scanner.purge_detection_by_path_or_hash(Some(&result.file_path), Some(&result.file_hash));
                                        return;
                                    }
                                }

                                // Extra guard against false-positive detection/quarantine for trusted binaries, dev tools, or IDE paths
                                if crate::win_trust::is_trusted_signed_binary(path)
                                    || osoosi_model::malware::is_ide_or_build_path(&result.file_path)
                                    || crate::voters::scanner_skip_path(&result.file_path)
                                    || should_skip_file_malware_scan(path)
                                {
                                    info!(
                                        "File Monitor: suppressed false-positive detection on trusted component: {}",
                                        result.file_path
                                    );
                                    orchestrator.malware_scanner.purge_detection_by_path_or_hash(Some(&result.file_path), Some(&result.file_hash));
                                    return;
                                }

                                let autonomy = osoosi_types::load_autonomy_config();
                                let mut should_hard_block = false;

                                if orchestrator.decision_engine.is_enabled() {
                                    let is_signed = crate::win_trust::is_trusted_signed_binary(path);
                                    let yara_str = if result.yara_matches.is_empty() {
                                        "none".to_string()
                                    } else {
                                        result.yara_matches.join(",")
                                    };
                                    let (san_file_path, inj1) = osoosi_types::sanitize_untrusted_log_field(&result.file_path, 256);
                                    let (san_magika, inj2) = osoosi_types::sanitize_untrusted_log_field(&result.magika_label, 64);
                                    let (san_yara, inj3) = osoosi_types::sanitize_untrusted_log_field(&yara_str, 256);
                                    let inj_flag = inj1 || inj2 || inj3;
                                    let state_text = format!(
                                        "Target: File\nPath: {}\nMagika: {}\nML Score: {:.2}\nYARA: {}\nSigned: {}\nInjectionDetected: {}",
                                        san_file_path, san_magika, result.ml_score, san_yara, is_signed, inj_flag
                                    );

                                    match orchestrator.decision_engine.evaluate_security_incident(&state_text).await {
                                        Ok(decision) => {
                                            if !inj_flag && (decision.verdict == "benign" || decision.containment_action == "allow") {
                                                info!(
                                                    "File Monitor: Decision model evaluated {} as benign (prob={:.2}, action='{}'). Alert suppressed.",
                                                    result.file_path, decision.verdict_probability, decision.containment_action
                                                );
                                                orchestrator.malware_scanner.purge_detection_by_path_or_hash(Some(&result.file_path), Some(&result.file_hash));
                                                let _ = orchestrator.memory.mark_hash_clean_ignored(
                                                    &event.hash,
                                                    file_stem,
                                                    Some(&event.path),
                                                    "decision_model_benign",
                                                );
                                                let finding = osoosi_types::ConsensusFinding {
                                                    id: format!("CONS-BENIGN-{}", &event.hash[..event.hash.len().min(12)]),
                                                    hash_blake3: event.hash.clone(),
                                                    process_name: file_stem.map(|s| s.to_string()),
                                                    file_path: Some(event.path.clone()),
                                                    verdict: "benign".to_string(),
                                                    confidence: decision.verdict_probability as f32,
                                                    detector_count: 1,
                                                    voters_summary: format!(
                                                        "Decision Model ({}): verdict={}, action={}, severity={}",
                                                        decision.provider_used, decision.verdict, decision.containment_action, decision.threat_severity
                                                    ),
                                                    action_taken: "ignored_and_allowed".to_string(),
                                                    evaluated_at: chrono::Utc::now(),
                                                };
                                                let _ = orchestrator.memory.record_consensus_finding(&finding);
                                                return;
                                            } else if decision.verdict == "malicious"
                                                || decision.containment_action == "isolate"
                                                || decision.containment_action == "quarantine"
                                            {
                                                warn!(
                                                    "MALWARE DETECTED: {} (magika={}, ml={:.2}, decision='{}' prob={:.2})",
                                                    result.file_path, result.magika_label, result.ml_score,
                                                    decision.verdict, decision.verdict_probability
                                                );
                                                let action_str = if decision.human_escalation_required {
                                                    "pending_human_escalation"
                                                } else {
                                                    "contained_and_quarantined"
                                                };
                                                let finding = osoosi_types::ConsensusFinding {
                                                    id: format!("CONS-MALICIOUS-{}", &event.hash[..event.hash.len().min(12)]),
                                                    hash_blake3: event.hash.clone(),
                                                    process_name: file_stem.map(|s| s.to_string()),
                                                    file_path: Some(event.path.clone()),
                                                    verdict: "malicious".to_string(),
                                                    confidence: decision.verdict_probability as f32,
                                                    detector_count: 1,
                                                    voters_summary: format!(
                                                        "Decision Model ({}): verdict={}, action={}, severity={}, human_escalation={}",
                                                        decision.provider_used, decision.verdict, decision.containment_action, decision.threat_severity, decision.human_escalation_required
                                                    ),
                                                    action_taken: action_str.to_string(),
                                                    evaluated_at: chrono::Utc::now(),
                                                };
                                                let _ = orchestrator.memory.record_consensus_finding(&finding);

                                                if is_executable && decision.verdict_probability >= 0.85 && !decision.human_escalation_required {
                                                    if crate::secured_executor::OpenShellExecutor::is_available().await {
                                                        let p_clone = path.to_path_buf();
                                                        tokio::spawn(async move {
                                                            let executor = crate::secured_executor::get_forensic_executor().await;
                                                            let cmd = std::process::Command::new(&p_clone);
                                                            info!("Forensic Detonation: Running suspicious program in isolated sandbox: {:?}", p_clone);
                                                            let _ = executor.execute(cmd).await;
                                                        });
                                                    } else {
                                                        warn!("Forensic Detonation: MicroVM/OpenShell unavailable; refusing uncontained host execution of {:?}", path);
                                                    }
                                                }

                                                if !decision.human_escalation_required && decision.action_probability >= autonomy.action_confidence_threshold as f64 {
                                                    should_hard_block = true;
                                                }
                                            } else {
                                                info!(
                                                    "File Monitor: Incident flagged for review: {} (decision='{}')",
                                                    result.file_path, decision.verdict
                                                );
                                                return;
                                            }
                                        }
                                        Err(e) => {
                                            tracing::error!("File Monitor: Decision engine evaluation failed: {}. Falling back to heuristic gates.", e);
                                            if result.ml_score >= 0.90 && (result.signature_score > 0.0 || !result.yara_matches.is_empty()) {
                                                warn!(
                                                    "MALWARE DETECTED: {} (magika={}, ml={:.2}, combined={:.2})",
                                                    result.file_path, result.magika_label,
                                                    result.ml_score, result.combined_score
                                                );
                                                if result.combined_score >= autonomy.action_confidence_threshold as f64 {
                                                    should_hard_block = true;
                                                }
                                            } else {
                                                return;
                                            }
                                        }
                                    }
                                } else {
                                    // If decision engine is not enabled:
                                    // Require both result.ml_score >= 0.90 AND (result.signature_score > 0.0 OR !result.yara_matches.is_empty()) before hard-blocking.
                                    if result.ml_score >= 0.90 && (result.signature_score > 0.0 || !result.yara_matches.is_empty()) {
                                        warn!(
                                            "MALWARE DETECTED: {} (magika={}, ml={:.2}, combined={:.2})",
                                            result.file_path, result.magika_label,
                                            result.ml_score, result.combined_score
                                        );
                                        if result.combined_score >= autonomy.action_confidence_threshold as f64 {
                                            should_hard_block = true;
                                        }
                                    } else {
                                        return;
                                    }
                                }

                                if should_hard_block {
                                    let target_p = std::path::Path::new(&result.file_path);
                                    if !target_p.exists() {
                                        debug!("Autonomous response skipped: file vanished before action: {}", result.file_path);
                                        return;
                                    }

                                    info!("AUTONOMOUS RESPONSE: Applying hard-block and quarantine for {}", result.file_path);

                                    // 1. Block the path persistently
                                    let rule = osoosi_types::BlockingRule {
                                        path: result.file_path.clone(),
                                        kind: osoosi_types::BlockingKind::Executable,
                                    };
                                    let _ = orchestrator.blocking_manager.add_rule(rule).await;
                                    if let Some(ref kd) = *orchestrator.kernel_driver.read() {
                                        let _ = kd.add_blocked_path(&result.file_path);
                                    }

                                    // 2. Physical Quarantine + Autonomous REA Deep-Inspection & YARA Synthesis
                                    match crate::quarantine::quarantine_file(&result.file_path) {
                                        Ok(quarantined_path) => {
                                            crate::rea::spawn_autonomous_rea_for_threat(
                                                quarantined_path,
                                                format!(
                                                    "live_quarantine_detection:magika={}:score={:.2}",
                                                    result.magika_label, result.combined_score
                                                ),
                                            );
                                        }
                                        Err(e) => {
                                            let err_msg = e.to_string();
                                            if err_msg.contains("File does not exist") || err_msg.contains("The system cannot find the file specified") {
                                                debug!("Quarantine skipped: file was removed by parent installer: {}", result.file_path);
                                            } else {
                                                error!("Quarantine failed for {}: {}", result.file_path, e);
                                            }
                                        }
                                    }
                                } else {
                                    // Monitor Mode: trigger autonomous REA inspection & YARA synthesis in-place
                                    crate::rea::spawn_autonomous_rea_for_threat(
                                        std::path::PathBuf::from(&result.file_path),
                                        format!(
                                            "live_monitor_detection:magika={}:score={:.2}",
                                            result.magika_label, result.combined_score
                                        ),
                                    );
                                }
                                // Broadcast to mesh for distributed EMBER training (PE samples with features)
                                if let Some(ref features) = result.features {
                                    let autonomy = osoosi_types::load_autonomy_config();
                                    if result.combined_score
                                        >= autonomy.quarantine_confidence_threshold as f64
                                    {
                                        let sample = osoosi_types::MalwareSample {
                                            source_node: orchestrator.trust.did().to_string(),
                                            file_hash: result.file_hash.clone(),
                                            label: 0, // malware
                                            features: features.clone(),
                                            feature_version: "legacy".to_string(),
                                            timestamp: chrono::Utc::now(),
                                        };
                                        if let Some(ref tx) =
                                            *orchestrator.mesh_command_tx.lock().await
                                        {
                                            let _ = tx.try_send(
                                                osoosi_wire::MeshCommand::BroadcastMalwareSample(
                                                    sample,
                                                ),
                                            );
                                        }
                                    }
                                }
                                orchestrator.audit.log(
                                    "MALWARE_DETECTED",
                                    serde_json::json!({
                                        "file_path": result.file_path,
                                        "file_hash": result.file_hash,
                                        "magika_label": result.magika_label,
                                        "malware_type": result.malware_type,
                                        "ml_score": result.ml_score,
                                        "signature_score": result.signature_score,
                                        "combined_score": result.combined_score,
                                        "evasion": result.evasion_indicators,
                                    }),
                                );

                                // Autonomous: try search-and-replace first, then quarantine
                                let autonomy = osoosi_types::load_autonomy_config();
                                let path_excluded = autonomy
                                    .quarantine_exclude_paths
                                    .iter()
                                    .any(|p| result.file_path.contains(p));
                                let should_quarantine = !path_excluded
                                    && autonomy.auto_quarantine_malware
                                    && (result.combined_score
                                        >= autonomy.quarantine_confidence_threshold as f64
                                        || result.malware_type.contains("EICAR"));
                                if path_excluded && result.is_malware {
                                    info!("Malware in excluded path (cloud sync temp?): {} — alert only, no quarantine", result.file_path);
                                } else if autonomy.auto_replace_malware_binaries
                                    && should_quarantine
                                {
                                    // Search for vuln-free version and replace (no hardcoded URLs)
                                    if let Some(download_url) =
                                        crate::software_replacement::resolve_replacement_url(
                                            &result.file_path,
                                        )
                                        .await
                                    {
                                        match orchestrator
                                            .patch_engine
                                            .remediate_file(&result.file_path, &download_url)
                                            .await
                                        {
                                            Ok(backup) => {
                                                info!("Replaced compromised binary {} with clean version from {} (backup: {:?})", result.file_path, download_url, backup);
                                                orchestrator.audit.log(
                                                    "MALWARE_REPLACED",
                                                    serde_json::json!({
                                                        "file_path": result.file_path,
                                                        "download_url": download_url,
                                                        "backup": backup.to_string_lossy(),
                                                    }),
                                                );
                                            }
                                            Err(e) => {
                                                warn!("Search-and-replace failed for {}: {}. Falling back to quarantine.", result.file_path, e);
                                                if let Err(qe) = crate::quarantine::quarantine_file(
                                                    &result.file_path,
                                                ) {
                                                    error!(
                                                        "Failed to quarantine malware file {}: {}",
                                                        result.file_path, qe
                                                    );
                                                } else {
                                                    info!("Quarantined malware: {} -> {} (conf={:.2})", result.file_path, autonomy.quarantine_path, result.combined_score);
                                                }
                                            }
                                        }
                                    } else if let Err(e) = crate::quarantine::quarantine_file(
                                        &result.file_path,
                                    ) {
                                        error!(
                                            "Failed to quarantine malware file {}: {}",
                                            result.file_path, e
                                        );
                                    } else {
                                        info!(
                                            "Quarantined malware: {} -> {} (conf={:.2})",
                                            result.file_path,
                                            autonomy.quarantine_path,
                                            result.combined_score
                                        );
                                    }
                                } else if should_quarantine {
                                    info!(
                                        "Quarantined malware: {} -> {} (conf={:.2})",
                                        result.file_path,
                                        autonomy.quarantine_path,
                                        result.combined_score
                                    );
                                    orchestrator.audit.log("AUTONOMOUS_ACTION", serde_json::json!({
                                        "message": format!("Quarantined malicious file: {}", result.file_path),
                                        "details": {
                                            "path": result.file_path,
                                            "score": result.combined_score,
                                            "type": result.malware_type
                                        }
                                    }));
                                } else if autonomy.auto_quarantine_malware && result.is_malware {
                                    info!("Malware detected but below quarantine threshold (conf={:.2} < {:.2}): alert only", result.combined_score, autonomy.quarantine_confidence_threshold);
                                }
                            }
                        }
                    });
                    }
                }
                while let Some(_) = set.join_next().await {}
            });
        }
        Ok(())
    }

    /// Start polling host security event logs (Windows Event Log, Linux auditd, macOS audit).
    /// Events are fed into the policy engine for protection.
    pub async fn start_host_event_loop(
        &self,
        event_channel_or_path: &str,
        poll_interval_secs: u64,
    ) {
        let channel = if event_channel_or_path.is_empty() {
            #[cfg(target_os = "windows")]
            {
                "Microsoft-Windows-Sysmon/Operational".to_string()
            }
            #[cfg(target_os = "linux")]
            {
                "default".to_string()
            }
            #[cfg(target_os = "macos")]
            {
                "default".to_string()
            }
            #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
            {
                "default".to_string()
            }
        } else {
            event_channel_or_path.to_string()
        };

        match osoosi_telemetry::create_host_event_reader(&channel) {
            Ok(mut reader) => {
                let resolved_source = reader.source_name();
                let orchestrator = self.clone();
                let interval = poll_interval_secs;
                tokio::spawn(async move {
                    info!(
                        "Host security event loop started (requested: {}, resolved: {})",
                        channel, resolved_source
                    );
                    let mut last_access_denied_log: Option<std::time::Instant> = None;
                    let mut last_channel_missing_log: Option<std::time::Instant> = None;
                    loop {
                        match reader.poll_events() {
                            Ok(events) => {
                                if !events.is_empty() {
                                    debug!(
                                        "Host event loop: {} event(s) from {}",
                                        events.len(),
                                        resolved_source
                                    );
                                }
                                for ev in events {
                                    let orch = orchestrator.clone();
                                    orch.adaptive.report_event();
                                    orchestrator.adaptive.spawn_adaptive(
                                        ResourceCategory::IO,
                                        Priority::Normal,
                                        async move {
                                            if let Err(e) = orch.process_telemetry(ev).await {
                                                error!("Failed to process host event: {}", e);
                                            }
                                        },
                                    );
                                }
                            }
                            Err(e) => {
                                let is_access_denied = e.to_string().contains("access denied");
                                let is_channel_missing = e.to_string().contains("channel")
                                    && e.to_string().contains("not found");
                                if is_access_denied {
                                    let should_log = last_access_denied_log
                                        .map(|t| t.elapsed().as_secs() >= 300)
                                        .unwrap_or(true);
                                    if should_log {
                                        error!("Host event poll failed: {}. Run scripts/grant-sysmon-read.ps1 as Admin to fix.", e);
                                        last_access_denied_log = Some(std::time::Instant::now());
                                    }
                                } else if is_channel_missing {
                                    let should_log = last_channel_missing_log
                                        .map(|t| t.elapsed().as_secs() >= 300)
                                        .unwrap_or(true);
                                    if should_log {
                                        error!("Host event poll failed: {}.", e);
                                        last_channel_missing_log = Some(std::time::Instant::now());
                                    }
                                } else {
                                    error!("Host event poll failed: {}", e);
                                }
                            }
                        }
                        tokio::time::sleep(tokio::time::Duration::from_secs(interval)).await;
                    }
                });
            }
            Err(e) => {
                error!(
                    "Could not create host event reader: {}. Host logs will not be monitored.",
                    e
                );
            }
        }
    }
}
