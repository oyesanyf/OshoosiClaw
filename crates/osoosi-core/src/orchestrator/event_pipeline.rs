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
    /// Access the autonomous AI Threat Feed Collector.
    pub fn ai_feed_collector(&self) -> &Arc<ai_feeds::AutonomousAiFeedCollector> {
        &self.ai_feed_collector
    }

    /// Trigger on-demand sync of AI threat feeds.
    pub async fn trigger_ai_feeds_sync(&self) -> anyhow::Result<ai_feeds::AiFeedStatus> {
        self.ai_feed_collector.poll_and_compile_all_feeds().await
    }

    /// Access the RL Adaptive Controller.
    pub fn rl_controller(
        &self,
    ) -> Arc<parking_lot::RwLock<osoosi_agent_anomaly::RLAdaptiveController>> {
        self.rl_controller.clone()
    }

    /// Access the synthetic canary correlator.
    pub fn canary_correlator(
        &self,
    ) -> Arc<tokio::sync::Mutex<osoosi_telemetry::canary::CanaryCorrelator>> {
        self.canary_correlator.clone()
    }

    /// Access the autonomous MITRE ATT&CK and ATLAS synchronizer.
    pub fn mitre_synchronizer(&self) -> &Arc<mitre::AutonomousMitreSynchronizer> {
        &self.mitre_synchronizer
    }

    /// Trigger on-demand autonomous refresh of MITRE ATT&CK + ATLAS STIX 2.1 catalog.
    pub async fn trigger_autonomous_stix_atlas_refresh(
        &self,
    ) -> anyhow::Result<mitre::MitreRefreshTelemetry> {
        self.mitre_synchronizer
            .trigger_autonomous_stix_atlas_refresh()
            .await
    }

    /// Process a verified CanaryAlert breach: triggers deterministic quorum isolation, RL reward update, and P2P swarm broadcast.
    pub async fn handle_canary_alert(
        &self,
        alert: &osoosi_runtime::canary_cage::CanaryAlert,
    ) -> anyhow::Result<()> {
        info!(
            "[CanaryTrap] Ephemeral Canary Breach detected: ID={} Session={} PID={} Trap={}",
            alert.alert_id, alert.session_id, alert.pid, alert.trap_path
        );

        // 1. Build HostSecurityEvent injecting Canary indicators directly into event.data
        let mut data = serde_json::Map::new();
        data.insert("CanaryTrapTripped".to_string(), serde_json::json!(true));
        data.insert(
            "CanaryAlertId".to_string(),
            serde_json::json!(alert.alert_id),
        );
        data.insert("ProcessId".to_string(), serde_json::json!(alert.pid));
        data.insert("SessionId".to_string(), serde_json::json!(alert.session_id));
        data.insert("TrapKind".to_string(), serde_json::json!(alert.trap_kind));
        data.insert("TrapPath".to_string(), serde_json::json!(alert.trap_path));
        data.insert("Confidence".to_string(), serde_json::json!(1.00));
        data.insert("PromptInjectionExfil".to_string(), serde_json::json!(true));
        data.insert("SacrificialFracture".to_string(), serde_json::json!(true));
        data.insert(
            "SilkRegime".to_string(),
            serde_json::json!("SacrificialFracture"),
        );
        data.insert("StrainEpsilon".to_string(), serde_json::json!(1.0));

        let event = osoosi_types::HostSecurityEvent {
            source: if cfg!(target_os = "windows") {
                osoosi_types::HostEventSource::WindowsEventLog
            } else {
                osoosi_types::HostEventSource::LinuxAudit
            },
            event_id: 9999,
            timestamp: chrono::Utc::now(),
            computer: hostname::get()
                .map(|h| h.to_string_lossy().to_string())
                .unwrap_or_else(|_| "localhost".to_string()),
            data: serde_json::Value::Object(data),
            causal_parent: None,
        };

        // 2. Evaluate through PolicyEngine; Agentic-Escape-Detector & SpiderWeb-Containment both vote 1.00
        let _decision = self.policy.scan_event(&event).await;

        // 3. Update RLAdaptiveController with positive high-priority containment reward and voter nudges
        {
            let mut rl = self.rl_controller.write();
            rl.record_canary_containment_reward();
            rl.nudge_voter_weights();
        }

        // 4. Attribute CanaryAlert to ingested file/HAR BLAKE3 digest in FileLineageTracker / broadcast
        if let Some(ref digest) = alert.attributed_file_digest {
            osoosi_policy::traffic_adapter::register_swarm_poisoned_har_digest(digest);
            self.broadcast_poisoned_digest_to_mesh(digest, &alert.session_id)
                .await;
        }

        Ok(())
    }

    pub async fn process_security_event_internal(
        &self,
        event: osoosi_types::HostSecurityEvent,
    ) -> anyhow::Result<()> {
        self.process_telemetry(event).await
    }

    pub async fn process_telemetry(
        &self,
        mut event: osoosi_types::HostSecurityEvent,
    ) -> anyhow::Result<()> {
        use osoosi_types::ResponseAction;

        // Fast Clean-Ignored Hash Bypass
        let hash_opt = event
            .data
            .get("hash_blake3")
            .or_else(|| event.data.get("Hash"))
            .or_else(|| event.data.get("hash"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .or_else(|| {
                event
                    .data
                    .get("Hashes")
                    .and_then(|v| v.as_str())
                    .and_then(|hashes| {
                        for prefix in ["SHA256=", "SHA256:", "SHA1=", "SHA1:", "MD5=", "MD5:"] {
                            if let Some(val) = hashes
                                .split(',')
                                .map(str::trim)
                                .find_map(|p| p.strip_prefix(prefix))
                            {
                                let val = val.trim();
                                if !val.is_empty() {
                                    return Some(val.to_ascii_lowercase());
                                }
                            }
                        }
                        None
                    })
            });

        if let Some(ref h) = hash_opt {
            let is_behavioral_event = matches!(
                event.event_id,
                1 | 3 | 7 | 8 | 10 | 12 | 13 | 22 | 25 | 4688
            );
            if !is_behavioral_event && self.memory.is_hash_clean_ignored(h) {
                debug!("Telemetry: Bypassing clean ignored hash: {}", h);
                return Ok(());
            }
        }

        // Synthetic Canary Fast-Path & Suppression:
        // Update canary correlation, suppress from RL feature vector & baseline drift,
        // and return immediately to prevent disk I/O exhaustion and skip tactical AI inference.
        if osoosi_telemetry::canary::is_canary_event(&event) {
            let mut correlator = self.canary_correlator.lock().await;
            osoosi_telemetry::canary::inspect_event_for_canary(&mut correlator, &event);
            return Ok(());
        }

        // Dual-Stage 5-Sigma Frozen Process Forensic Snapshot (Event ID 9995):
        // Synthesize multi-token YARA-X signature from extracted in-memory payload
        // and broadcast signed IOC to the P2P/Nostr mesh.
        if event.event_id == 9995
            || event.data.get("EventName").and_then(|v| v.as_str())
                == Some("Frozen5SigmaForensicSnapshot")
        {
            let snap_pid = event
                .data
                .get("ProcessId")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u32;
            let comm = event
                .data
                .get("CommandLine")
                .or_else(|| event.data.get("Image"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let rip_hex = event
                .data
                .get("RipHex")
                .and_then(|v| v.as_str())
                .unwrap_or("0x0");
            let payload_sha256 = event
                .data
                .get("PayloadSha256")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let sigma_score = event
                .data
                .get("SigmaScore")
                .and_then(|v| v.as_f64())
                .unwrap_or(5.0);
            let payload_hex = event
                .data
                .get("PayloadHex")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            let mut synthesized_yara = None;
            if !payload_hex.is_empty() {
                if let Ok(payload_bytes) = hex::decode(payload_hex) {
                    synthesized_yara = crate::rea::synthesize_yara_from_raw_payload(
                        &format!("frozen_pid_{}_{}", snap_pid, comm),
                        &payload_bytes,
                        format!(
                            "five_sigma_kernel_quarantine:z={:.2}:rip={}",
                            sigma_score, rip_hex
                        ),
                    );
                    std::mem::drop(payload_bytes);
                }
            }

            let mut sig = osoosi_types::ThreatSignature::new(self.trust.did().to_string());
            sig.confidence = 0.99;
            sig.process_name = Some(comm.to_string());
            sig.mitre_technique = Some("T1055".to_string());
            sig.mitre_technique_name =
                Some("Process Injection / 5-Sigma Memory Anomaly".to_string());
            sig.mitre_tactic = Some("Defense Evasion".to_string());
            sig.recommended_action = ResponseAction::Isolate;
            sig.action_state = osoosi_types::ActionState::Executed;
            if !payload_sha256.is_empty() {
                sig.hash_blake3 = Some(payload_sha256.to_string());
                self.memory.mark_hash_known_malicious(payload_sha256);
            }
            sig.add_reason(format!(
                "Dual-Stage 5-Sigma Kernel Quarantine + Cgroup v2 Freeze (PID={}, comm={}, RIP={}, z={:.2}σ, sha256={})",
                snap_pid, comm, rip_hex, sigma_score, payload_sha256
            ));
            self.privacy.protect_signature(&mut sig);
            let _ = self.memory.log_threat(&sig);
            self.audit.log(
                "FIVE_SIGMA_FORENSIC_SNAPSHOT",
                serde_json::json!({
                    "pid": snap_pid,
                    "comm": comm,
                    "rip_hex": rip_hex,
                    "payload_sha256": payload_sha256,
                    "sigma_score": sigma_score,
                    "yara_synthesized": synthesized_yara.is_some(),
                }),
            );
            self.broadcast_threat_to_mesh(sig).await;
            return Ok(());
        }

        // Drop internal/deception operations performed by osoosi.exe itself to eliminate feedback loop
        let image = event
            .data
            .get("Image")
            .or_else(|| event.data.get("image"))
            .or_else(|| event.data.get("ImagePath"))
            .or_else(|| event.data.get("NewProcessName"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let pid = event
            .data
            .get("ProcessId")
            .or_else(|| event.data.get("process_id"))
            .and_then(|v| {
                v.as_u64()
                    .or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
            });
        let ppid = event
            .data
            .get("ParentProcessId")
            .or_else(|| event.data.get("parent_process_id"))
            .and_then(|v| {
                v.as_u64()
                    .or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
            });
        if ppid
            .map(|p| p as u32 == std::process::id())
            .unwrap_or(false)
        {
            return Ok(());
        }
        let img_lower = image.to_lowercase().replace('/', "\\");
        let is_internal_velociraptor = img_lower.ends_with("\\velociraptor.exe")
            && (img_lower.contains("\\tools\\velociraptor\\") || img_lower.contains("oshoosiclaw"));
        if is_internal_velociraptor {
            return Ok(());
        }
        let is_self = img_lower.ends_with("osoosi.exe")
            || img_lower.ends_with("osoosi_service.exe")
            || img_lower.ends_with("osoosi-cli.exe")
            || pid.map(|p| p as u32 == std::process::id()).unwrap_or(false);

        let target_path = event
            .data
            .get("TargetFilename")
            .or_else(|| event.data.get("target_filename"))
            .or_else(|| event.data.get("TargetObject"))
            .or_else(|| event.data.get("target_object"))
            .or_else(|| event.data.get("PipeName"))
            .or_else(|| event.data.get("Destination"))
            .or_else(|| event.data.get("Path"))
            .or_else(|| event.data.get("path"))
            .or_else(|| event.data.get("FilePath"))
            .or_else(|| event.data.get("file_path"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        if is_self
            && (is_internal_or_deception_path(target_path) || is_internal_or_deception_path(image))
        {
            debug!(
                "Telemetry: Dropping internal/deception self-event by osoosi for target '{}'",
                target_path
            );
            return Ok(());
        }

        // 1. Report event rate to adaptive controller.
        self.adaptive.report_event();

        // 1b. Periodic Telemetry Summary (for Dashboard performance)
        let total = self.telemetry_total_count.fetch_add(1, Ordering::Relaxed) + 1;
        if total.is_multiple_of(100) {
            if let Ok(mut last) = self.last_telemetry_summary.try_lock() {
                if last.elapsed() > Duration::from_secs(60) {
                    let prev_count = self
                        .last_telemetry_summary_count
                        .swap(total, Ordering::Relaxed);
                    let diff = total.saturating_sub(prev_count);
                    self.audit.log(
                        "TELEMETRY_SUMMARY",
                        serde_json::json!({
                            "count": diff,
                            "total_ingested": total,
                            "computer": self.trust.did().to_string(),
                        }),
                    );
                    *last = Instant::now();
                }
            }
        }

        // 0. Intelligent Load-Aware Throttling (The "Brain")
        let current_mode = *self
            .adaptive
            .current_mode
            .read()
            .unwrap_or_else(|e| e.into_inner());
        let is_high_pressure = current_mode == TelemetryMode::Silent;

        // Deduplication: Avoid redundant heavy analysis for the same image in a burst
        if let Some(image_path) = event.data.get("Image").and_then(|v| v.as_str()) {
            let cmd_for_cache = event
                .data
                .get("CommandLine")
                .or_else(|| event.data.get("command_line"))
                .or_else(|| event.data.get("cmdline"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let pid_for_cache = extract_event_pid(&event).unwrap_or(0);
            let target_for_cache = event
                .data
                .get("TargetFilename")
                .or_else(|| event.data.get("TargetImage"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let cache_key = format!(
                "{}:{}:{}:{}:{}",
                event.event_id, image_path, pid_for_cache, cmd_for_cache, target_for_cache
            );
            if let Some(last_seen) = self.alert_suppression_cache.get(&cache_key) {
                if last_seen.elapsed() < Duration::from_secs(5) {
                    return Ok(()); // Burst suppression
                }
            }
            self.alert_suppression_cache
                .insert(cache_key, Instant::now());
        }

        // --- IDENTITY ENRICHMENT ---
        if let Some(image_path) = event.data.get("Image").and_then(|v| v.as_str()) {
            // In high pressure mode, we skip PE metadata extraction unless it's a critical process spawn
            let should_enrich = !is_high_pressure || event.event_id == 1;

            if should_enrich {
                if let Some(meta) = osoosi_types::get_pe_metadata(std::path::Path::new(image_path))
                {
                    // Enrich event with actual on-disk version if missing or generic
                    let needs_version = event
                        .data
                        .get("ProductVersion")
                        .and_then(|v| v.as_str())
                        .map(|v| v.is_empty() || v == "0.0.0.0" || v == "0.0.0")
                        .unwrap_or(true);
                    if needs_version {
                        if let Some(obj) = event.data.as_object_mut() {
                            obj.insert(
                                "ProductVersion".to_string(),
                                serde_json::Value::String(meta.version.clone()),
                            );
                        }
                    }
                    // Inject into event data for voters to prioritize
                    if let Some(obj) = event.data.as_object_mut() {
                        obj.insert(
                            "VerifiedVersion".to_string(),
                            serde_json::Value::String(meta.version),
                        );
                        obj.insert(
                            "VerifiedProduct".to_string(),
                            serde_json::Value::String(meta.product_name),
                        );
                        obj.insert(
                            "VerifiedSigned".to_string(),
                            serde_json::Value::Bool(meta.is_signed),
                        );
                    }
                }
            }
        }

        // --- MILITARY-GRADE TACTICAL ANALYSIS ---
        // Skip heavy tactical reasoning in Silent mode to preserve system responsiveness
        if !is_high_pressure {
            if let Some(mut sig) = self.military.analyze_event(&event).await {
                warn!(
                    "MILITARY-GUARD: Tactical threat detected! {}",
                    sig.reason.as_deref().unwrap_or("Unknown")
                );
                self.privacy.protect_signature(&mut sig);

                self.broadcast_threat_to_mesh(sig.clone()).await;

                if sig.recommended_action == ResponseAction::Isolate {
                    if let Some(pid) = event.data.get("ProcessId").and_then(|v| v.as_u64()) {
                        let _ = self.blocking_manager.block_by_pid(pid as u32).await;
                    }
                }
            }
        }

        // --- SHIELD LAYER INTERCEPTION (Reality-Distortion & Self-Defense) ---
        {
            match event.event_id {
                // 1. Process Access Guard (Self-Defense & LSASS Protection)
                10 => {
                    if let (Some(source_pid), Some(target_pid), Some(access_mask_str)) = (
                        event.data.get("SourceProcessId").and_then(|v| v.as_u64()),
                        event.data.get("TargetProcessId").and_then(|v| v.as_u64()),
                        event.data.get("GrantedAccess").and_then(|v| v.as_str()),
                    ) {
                        let mask =
                            u32::from_str_radix(access_mask_str.trim_start_matches("0x"), 16)
                                .unwrap_or(0);
                        if !self.shield.verify_process_access(
                            source_pid as u32,
                            target_pid as u32,
                            mask,
                        ) {
                            warn!("Shield violation detected! Blocking access from PID {} to target PID {}.", source_pid, target_pid);

                            // Log to local memory store
                            let _ = self.memory.log_threat_event(
                                "SHIELD_ACCESS_VIOLATION",
                                source_pid as u32,
                                target_pid as u32,
                            );

                            // BROADCAST TO MESH: Create a high-confidence signature and send to peers
                            let mut sig = osoosi_types::ThreatSignature::new("local".to_string());
                            sig.confidence = 1.0;
                            sig.reason = Some(format!("Shield Self-Defense: Blocked process access violation from PID {} (Mask: {})", source_pid, access_mask_str));
                            sig.recommended_action = osoosi_types::ResponseAction::Isolate;

                            // Apply Merkle Proof and Differential Privacy noise
                            self.privacy.protect_signature(&mut sig);

                            self.broadcast_threat_to_mesh(sig).await;

                            // Neutralize locally
                            let _ = self.blocking_manager.block_by_pid(source_pid as u32).await;
                            return Ok(());
                        }
                    }
                }
                // 2. DNS Sinkhole & Redirection
                22 => {
                    if let Some(query) = event.data.get("QueryName").and_then(|v| v.as_str()) {
                        if let Some(sinkhole_ip) = self.shield.resolve_sinkhole(query) {
                            info!(
                                "Shield Redirection: DNS Query for '{}' sinkholed to {}.",
                                query, sinkhole_ip
                            );
                            // Log the redirection in audit
                            self.audit.log("DNS_SINKHOLE_REDIRECTION", serde_json::json!({
                                "query": query,
                                "redirected_to": sinkhole_ip,
                                "source_pid": event.data.get("ProcessId").and_then(|v| v.as_u64())
                            }));
                        }
                    }
                }
                _ => {}
            }
        }

        // --- MORPHIC ENTANGLEMENT INTERCEPTION ---
        {
            if let Some(pid) = event.data.get("ProcessId").and_then(|v| v.as_u64()) {
                let has_spider = {
                    let engine = self.deception_engine.read().await;
                    engine.get_spider(pid as u32).is_some()
                };
                if has_spider {
                    let mut engine = self.deception_engine.write().await;
                    if engine.get_spider(pid as u32).is_some() {
                        match event.event_id {
                            // 11: FileCreate, 23: FileDeleteArchived, 26: FileDeleteLogged
                            11 | 23 | 26 => {
                                let path = event
                                    .data
                                    .get("TargetFilename")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("");
                                if let Some(res) =
                                    engine.handle_event(pid as u32, "io_access", path)
                                {
                                    info!(
                                        "🕸️ [ENTANGLED I/O] Intercepted access from PID {}: {}",
                                        pid, res
                                    );
                                }
                            }
                            3 => {
                                // NetworkConnect
                                if engine
                                    .handle_event(pid as u32, "exfil", "network")
                                    .is_some()
                                {
                                    info!(
                                    "🕸️ [ENTANGLED EXFIL] Redirected network activity for PID {}",
                                    pid
                                );
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        // --- PROCESS HOLLOWING INTERCEPTION (T1055.012) ---
        {
            if event.event_id == 1 || event.event_id == 0 || event.event_id == 4688 {
                if let Some(pid) = extract_event_pid(&event) {
                    let image = event
                        .data
                        .get("Image")
                        .or_else(|| event.data.get("NewProcessName"))
                        .or_else(|| event.data.get("image"))
                        .or_else(|| event.data.get("ImagePath"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let flags = event
                        .data
                        .get("CreationFlags")
                        .or_else(|| event.data.get("create_flags"))
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as u32;
                    let is_suspended_cmd = event
                        .data
                        .get("CommandLine")
                        .and_then(|v| v.as_str())
                        .map(|c| c.contains("CREATE_SUSPENDED"))
                        .unwrap_or(false);
                    if (flags & osoosi_telemetry::hollowing::CREATE_SUSPENDED != 0)
                        || flags == 4
                        || is_suspended_cmd
                    {
                        self.hollowing_detector.on_process_create(
                            pid,
                            image,
                            osoosi_telemetry::hollowing::CREATE_SUSPENDED,
                        );
                    }
                }
            } else if event.event_id == 8 || event.event_id == 10 || event.event_id == 25 {
                let target_pid = event
                    .data
                    .get("TargetProcessId")
                    .and_then(|v| {
                        v.as_u64().map(|n| n as u32).or_else(|| {
                            v.as_str()
                                .and_then(|s| s.trim().trim_start_matches("0x").parse::<u32>().ok())
                        })
                    })
                    .or_else(|| extract_event_pid(&event));
                let source_pid = event
                    .data
                    .get("SourceProcessId")
                    .and_then(|v| {
                        v.as_u64().map(|n| n as u32).or_else(|| {
                            v.as_str()
                                .and_then(|s| s.trim().trim_start_matches("0x").parse::<u32>().ok())
                        })
                    })
                    .unwrap_or(0);
                if let Some(t_pid) = target_pid {
                    if self
                        .hollowing_detector
                        .on_remote_memory_write(t_pid, source_pid)
                    {
                        warn!("HOLLOWING INTERCEPTION: Confirmed process hollowing! Suspended PID {} received remote memory writes from PID {}", t_pid, source_pid);

                        // Trigger immediate process termination of the hollowed process (t_pid) and source_pid
                        let _ = self.blocking_manager.block_by_pid(t_pid).await;
                        if source_pid > 0 && source_pid != t_pid {
                            let _ = self.blocking_manager.block_by_pid(source_pid).await;
                        }

                        // Emit a High/Critical ThreatSignature and record in database
                        let mut sig = osoosi_types::ThreatSignature::new("local".to_string());
                        sig.confidence = 1.0;
                        sig.detector_count = 1;
                        sig.process_name = Some(format!("hollowed_pid_{}", t_pid));
                        sig.mitre_technique = Some("T1055.012".to_string());
                        sig.mitre_technique_name = Some("Process Hollowing".to_string());
                        sig.mitre_tactic =
                            Some("Defense Evasion / Privilege Escalation".to_string());
                        sig.reason = Some(format!(
                            "HOLLOWING INTERCEPTION: Confirmed process hollowing! Suspended PID {} received remote memory writes from PID {}",
                            t_pid, source_pid
                        ));
                        sig.recommended_action = osoosi_types::ResponseAction::Isolate;
                        sig.action_state = osoosi_types::ActionState::Executed;

                        // Apply Differential Privacy / Merkle protection and record in DB + audit log
                        self.privacy.protect_signature(&mut sig);
                        if let Err(e) = self.memory.log_threat(&sig) {
                            error!(
                                "Failed to persist process hollowing threat signature: {}",
                                e
                            );
                        }
                        self.audit.log(
                            "PROCESS_HOLLOWING_TERMINATED",
                            serde_json::json!({
                                "threat_id": sig.id,
                                "target_pid": t_pid,
                                "source_pid": source_pid,
                                "mitre": "T1055.012",
                                "action": "Terminated"
                            }),
                        );
                        self.broadcast_threat_to_mesh(sig).await;
                    }
                }
            } else if event.event_id == 5 {
                if let Some(pid) = extract_event_pid(&event) {
                    self.hollowing_detector.on_process_terminate(pid);
                }
            }
        }

        // --- GLOBAL VERSION AWARENESS ---
        // Resolve and cache product version for the event's image to prevent false positives.
        if let Some(image_path) = event.data.get("Image").and_then(|v| v.as_str()) {
            let path = std::path::Path::new(image_path);

            // Try cache first
            if let Ok(Some((_, _, Some(version)))) = self.memory.get_file_integrity(image_path) {
                if let Some(obj) = event.data.as_object_mut() {
                    obj.insert(
                        "ProductVersion".to_string(),
                        serde_json::Value::String(version),
                    );
                }
            } else {
                // Resolve and update cache if it's a process create or image load
                if event.event_id == 1 || event.event_id == 7
                // ProcessCreate | ImageLoad
                {
                    if let Some(version) = version_utils::get_file_version_info(path) {
                        if let Some(obj) = event.data.as_object_mut() {
                            obj.insert(
                                "ProductVersion".to_string(),
                                serde_json::Value::String(version),
                            );
                        }
                    }
                }
            }
        }

        // 1. Tier-1/2 on Async Consensus (policy)
        let mut signature = self.policy.scan_event(&event).await;

        // Route into Behavioral Analysis Pipeline (SecureBERT / CoLog autonomous sequence check)
        let log_ev = osoosi_behavioral::LogEvent::from(&event);
        let colog_score = self
            .behavioral_analyzer
            .autonomous_check(log_ev.clone())
            .await;
        if colog_score > 0.85 {
            warn!(
                "BEHAVIORAL PIPELINE: Sysmon/Host anomaly detected (score={:.2}) for source {}",
                colog_score, log_ev.source
            );
            if let Some(ref mut sig) = signature {
                sig.confidence = (sig.confidence + 0.25).min(1.0);
                sig.add_reason(format!(
                    "Behavioral CoLog Anomaly: score {:.2}",
                    colog_score
                ));
            } else {
                let mut sig = osoosi_types::ThreatSignature::new(event.computer.clone());
                sig.confidence = colog_score;
                sig.process_name = event
                    .data
                    .get("Image")
                    .and_then(|i| i.as_str())
                    .and_then(|p| std::path::Path::new(p).file_name())
                    .and_then(|n| n.to_str())
                    .map(String::from);
                sig.add_reason(format!(
                    "Behavioral Pipeline: CoLog sequence deviation (score {:.2})",
                    colog_score
                ));
                signature = Some(sig);
            }
        }

        // 2. Entropy analysis on Rayon (CPU-bound)
        // Skip entropy calculation for all events in Silent mode (extreme I/O saver)
        let signature = if is_high_pressure {
            signature
        } else {
            let static_analyzer = self.static_analyzer.clone();
            let event_clone = event.clone();
            let current_sig = signature;
            crate::run_on_rayon(move || {
                let mut signature = current_sig;
            if let Some(image_path) = event_clone.data.get("Image").and_then(|v| v.as_str()) {
                let path = std::path::PathBuf::from(image_path);
                // Entropy check for packed/obfuscated files
                if let Ok(entropy) = static_analyzer.calculate_entropy(&path) {
                    if entropy > 7.0 {
                        warn!("High entropy detected (packed/encrypted): {} - {:.2}", path.display(), entropy);
                    }

                    let is_browser = image_path.to_lowercase().contains("chrome.exe")
                        || image_path.to_lowercase().contains("msedge.exe")
                        || image_path.to_lowercase().contains("firefox.exe");

                    if entropy < 6.5 && is_browser {
                        if signature.is_some() {
                            signature = None; // Suppression logic
                        }
                    } else if entropy > 7.5 {
                        if let Some(ref mut sig) = signature {
                            sig.confidence = (sig.confidence + 0.15).min(1.0);
                            sig.add_reason(format!(
                                "Static Analysis: High entropy detected ({:.2}), suggesting packed/obfuscated binary.",
                                entropy
                            ));
                        }
                    }
                }
            }
            signature
        })
        .await?
        };

        if let Some(mut signature) = signature {
            let det_pipeline = match event.event_id {
                3 | 22 => "HAR/Network",
                7 | 8 | 10 | 25 => "Malware/YARA",
                _ => "Process/ETW/CLI",
            };
            let target_proc = signature
                .process_name
                .as_deref()
                .or_else(|| event.data.get("Image").and_then(|v| v.as_str()))
                .unwrap_or("unknown");
            let rea_eval = crate::rea::global_rea_engine().evaluate_detector_candidate(
                det_pipeline,
                target_proc,
                signature.reason.as_deref().unwrap_or(""),
                signature.confidence as f64,
            );
            if rea_eval.masquerade_escalated || rea_eval.prompt_injection_escalated {
                signature.confidence = signature.confidence.max(rea_eval.adjusted_score as f32);
                signature.add_reason(rea_eval.explanation);
            }

            info!(
                "Consensus Threat Identified: {} (Confidence: {:.2}, Detectors: {})",
                signature.id, signature.confidence, signature.detector_count
            );

            // Closed-Loop RL Feedback & Local YARA Hot-Synthesis
            if signature.confidence >= 0.85
                || (signature.confidence >= 0.80 && signature.detector_count >= 2)
            {
                let rl_cmd = event
                    .data
                    .get("CommandLine")
                    .or_else(|| event.data.get("command_line"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let rl_context_str = format!(
                    "Process: {}\nCmdLine: {}\nMITRE: {}\nReason: {}\nConfidence: {:.2}",
                    signature.process_name.as_deref().unwrap_or("unknown"),
                    rl_cmd,
                    signature.mitre_technique.as_deref().unwrap_or("none"),
                    signature.reason.as_deref().unwrap_or(""),
                    signature.confidence
                );
                self.decision_engine.record_contextual_rl_feedback(
                    &signature.id,
                    &rl_context_str,
                    1.0,
                    "isolate",
                );
                if let Some(ref reason_str) = signature.reason {
                    let mut voters = Vec::new();
                    let mut chars = reason_str.chars().peekable();
                    while let Some(c) = chars.next() {
                        if c == '[' {
                            let mut tag = String::new();
                            while let Some(&next_c) = chars.peek() {
                                if next_c == ']' {
                                    chars.next();
                                    break;
                                }
                                if let Some(ch) = chars.next() {
                                    tag.push(ch);
                                }
                            }
                            let trimmed = tag.trim();
                            if !trimmed.is_empty()
                                && !trimmed.starts_with("Veto")
                                && !trimmed.starts_with("Tags:")
                                && !voters.contains(&trimmed.to_string())
                            {
                                voters.push(trimmed.to_string());
                            }
                        }
                    }
                    if !voters.is_empty() {
                        self.policy
                            .update_specific_voter_weights(&voters, true, 0.02);
                        info!(
                            target: crate::CONSENSUS_LOG_TARGET,
                            voters = ?voters,
                            "Closed-loop RL: Calibrated weights for {} consensus voters (+0.02 reward)",
                            voters.len()
                        );
                    }
                }

                if let Some(rule) = crate::yara_gen::generate_yara_from_threat(&signature) {
                    let _ = self.yara_manager.hot_load_rule(&rule, &signature.id);
                }
            }

            let p_name = signature
                .process_name
                .clone()
                .or_else(|| {
                    for field in &[
                        "Image",
                        "NewProcessName",
                        "ProcessName",
                        "ImagePath",
                        "SourceImage",
                        "TargetImage",
                        "Application",
                    ] {
                        if let Some(val) = event.data.get(*field).and_then(|v| v.as_str()) {
                            if let Some(n) = std::path::Path::new(val)
                                .file_name()
                                .and_then(|n| n.to_str())
                            {
                                if !n.trim().is_empty() && n != "unknown" {
                                    return Some(n.to_string());
                                }
                            }
                        }
                    }
                    for field in &["CommandLine", "command_line", "cmdline", "Command"] {
                        if let Some(cmd) = event.data.get(*field).and_then(|v| v.as_str()) {
                            let trimmed = cmd.trim();
                            if !trimmed.is_empty() {
                                let first_tok = if trimmed.starts_with('"') {
                                    trimmed[1..].split('"').next().unwrap_or(trimmed)
                                } else if trimmed.starts_with('\'') {
                                    trimmed[1..].split('\'').next().unwrap_or(trimmed)
                                } else {
                                    trimmed.split_whitespace().next().unwrap_or(trimmed)
                                };
                                let fname = std::path::Path::new(first_tok)
                                    .file_name()
                                    .and_then(|n| n.to_str())
                                    .unwrap_or(first_tok);
                                if !fname.trim().is_empty() && fname != "unknown" {
                                    return Some(fname.to_string());
                                }
                            }
                        }
                    }
                    None
                })
                .unwrap_or_else(|| "unknown".to_string());

            let f_path = event
                .data
                .get("Image")
                .or_else(|| event.data.get("NewProcessName"))
                .or_else(|| event.data.get("ImagePath"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            let cmd_line = event
                .data
                .get("CommandLine")
                .or_else(|| event.data.get("command_line"))
                .or_else(|| event.data.get("cmdline"))
                .or_else(|| event.data.get("ParentCommandLine"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            let hash_val = signature
                .hash_blake3
                .clone()
                .or_else(|| {
                    event
                        .data
                        .get("Hashes")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                })
                .unwrap_or_else(|| {
                    if !f_path.is_empty() {
                        std::fs::read(&f_path)
                            .map(|b| blake3::hash(&b).to_hex().to_string())
                            .unwrap_or_else(|_| {
                                if !cmd_line.is_empty() {
                                    blake3::hash(cmd_line.as_bytes()).to_hex().to_string()
                                } else {
                                    blake3::hash(signature.id.as_bytes()).to_hex().to_string()
                                }
                            })
                    } else if !cmd_line.is_empty() {
                        blake3::hash(cmd_line.as_bytes()).to_hex().to_string()
                    } else {
                        blake3::hash(signature.id.as_bytes()).to_hex().to_string()
                    }
                });

            signature.process_name = Some(p_name.clone());
            signature.hash_blake3 = Some(hash_val.clone());

            // 2. Autonomous Remediation Logic (Lockdown Mode and Active Response)
            let autonomy = osoosi_types::load_autonomy_config();
            let is_lockdown_mode = autonomy.is_strict_lockdown();
            let is_critical_attack = is_critical_security_attack(&signature, &event);
            let is_destructive = is_destructive_mutation(&signature, &event);
            let has_mitre_technique = signature
                .mitre_technique
                .as_ref()
                .map(|t| !t.trim().is_empty())
                .unwrap_or(false);

            let mut effective_action = if is_lockdown_mode
                && (signature.confidence >= autonomy.action_confidence_threshold
                    || is_critical_attack
                    || is_destructive
                    || has_mitre_technique)
            {
                signature.require_approval = false;
                ResponseAction::Isolate
            } else if (is_destructive || is_critical_attack) && autonomy.auto_quarantine_malware {
                signature.require_approval = false;
                if is_destructive
                    || signature.recommended_action == ResponseAction::Isolate
                    || signature.confidence >= autonomy.quarantine_confidence_threshold
                {
                    ResponseAction::Isolate
                } else if signature.recommended_action == ResponseAction::GhostTarpit {
                    ResponseAction::GhostTarpit
                } else {
                    ResponseAction::Isolate
                }
            } else if signature.confidence >= autonomy.action_confidence_threshold {
                if autonomy.auto_quarantine_malware
                    && signature.recommended_action == ResponseAction::Alert
                    && has_mitre_technique
                {
                    signature.require_approval = false;
                    ResponseAction::Isolate
                } else {
                    signature.recommended_action
                }
            } else {
                debug!(
                    "Fast-path threat confidence {:.2} below action threshold {:.2}: using Alert only",
                    signature.confidence,
                    autonomy.action_confidence_threshold
                );
                ResponseAction::Alert
            };

            if self.is_monitor_only() {
                effective_action = ResponseAction::Alert;
            }

            signature.recommended_action = effective_action;
            if signature.require_approval {
                signature.action_state = osoosi_types::ActionState::Pending;
            } else if effective_action != ResponseAction::Alert {
                signature.action_state = osoosi_types::ActionState::Executed;
            } else {
                signature.action_state = osoosi_types::ActionState::Pending;
            }

            let _ = self.memory.log_threat(&signature);

            let finding = osoosi_types::ConsensusFinding {
                id: signature.id.clone(),
                hash_blake3: hash_val.clone(),
                process_name: Some(p_name.clone()),
                file_path: Some(f_path.clone()),
                verdict: "malicious".to_string(),
                confidence: signature.confidence,
                detector_count: signature.detector_count,
                voters_summary: signature.reason.clone().unwrap_or_default(),
                action_taken: format!("{:?}", effective_action),
                evaluated_at: chrono::Utc::now(),
            };
            let _ = self.memory.record_consensus_finding(&finding);

            // Real-time Global Immunization: Broadcast threat with populated metadata to the P2P mesh
            self.broadcast_threat_to_mesh(signature.clone()).await;

            let src_node = self.trust.did().id.clone();

            // Audit log for tamper-evidence
            self.audit.log(
                "THREAT_DETECTED",
                serde_json::json!({
                    "id": signature.id,
                    "confidence": signature.confidence,
                    "detector_count": signature.detector_count,
                    "reason": signature.reason,
                    "action": effective_action,
                    "process_name": p_name,
                    "file_path": f_path,
                    "command_line": cmd_line,
                    "arguments": cmd_line,
                    "hash_blake3": hash_val,
                    "source_node": src_node,
                }),
            );

            // Human-in-the-Loop check: high-impact actions may require approval
            if signature.require_approval
                || signature.action_state == osoosi_types::ActionState::Pending
            {
                info!(
                    "Fast-path: Action {:?} requires administrator approval. Queuing for review.",
                    effective_action
                );
                self.audit.log(
                    "ACTION_PENDING_APPROVAL",
                    serde_json::json!({
                        "threat_id": signature.id,
                        "action": format!("{:?}", effective_action)
                    }),
                );
                return Ok(());
            }

            // Dynamic forensic sandbox execution if confidence >= 0.85
            if signature.confidence >= 0.85 {
                let target_path = event
                    .data
                    .get("Image")
                    .or_else(|| event.data.get("TargetFilename"))
                    .or_else(|| event.data.get("ImagePath"))
                    .or_else(|| event.data.get("NewProcessName"))
                    .and_then(|v| v.as_str());
                if let Some(tp) = target_path {
                    let tp_buf = std::path::PathBuf::from(tp);
                    if tp_buf.exists() && tp_buf.is_file() {
                        if !crate::blocking_manager::is_protected_or_benign_system_path(tp) {
                            crate::rea::spawn_autonomous_rea_for_threat(
                                tp_buf.clone(),
                                format!(
                                    "telemetry_threat_detected:{}",
                                    signature.reason.as_deref().unwrap_or("consensus_threat")
                                ),
                            );
                        }
                        if crate::secured_executor::OpenShellExecutor::is_available().await {
                            tokio::spawn(async move {
                                let executor =
                                    crate::secured_executor::get_forensic_executor().await;
                                let cmd = std::process::Command::new(&tp_buf);
                                info!("Forensic Detonation: Running suspicious program in isolated sandbox: {:?}", tp_buf);
                                let _ = executor.execute(cmd).await;
                            });
                        } else {
                            warn!("Forensic Detonation: MicroVM/OpenShell unavailable; refusing uncontained host execution of {:?}", tp_buf);
                        }
                    }
                }
            }

            match effective_action {
                ResponseAction::Isolate => {
                    let image_opt = event
                        .data
                        .get("Image")
                        .or_else(|| event.data.get("NewProcessName"))
                        .or_else(|| event.data.get("image"))
                        .or_else(|| event.data.get("ImagePath"))
                        .and_then(|v| v.as_str());

                    if let Some(image) = image_opt {
                        // ABSOLUTE OS SAFEGUARD: If this is a core, Microsoft-signed Windows binary, NEVER kill it (prevents BSOD).
                        if is_system_critical(&event) {
                            warn!("AUTONOMOUS BLOCK SKIPPED: {} is a SYSTEM CRITICAL binary (Microsoft Signed). Downgrading to Alert to prevent OS crash.", image);
                            return Ok(());
                        }

                        // GENERAL SAFELIST GUARD: Never block trusted developer/operational binaries UNLESS they exhibit confirmed malicious behavior.
                        let is_trusted = is_trusted_operational_image(&event, &self.policy.config);
                        let reason = signature.reason.as_deref().unwrap_or("");
                        let is_behavioral_threat = reason.contains("Behavioral")
                            || reason.contains("Sigma")
                            || reason.contains("CredentialGuard")
                            || reason.contains("Cedar")
                            || reason.contains("Yara")
                            || reason.contains("Memory")
                            || reason.contains("Hollows-Hunter")
                            || signature.mitre_technique.is_some()
                            || is_lockdown_mode;

                        if is_trusted && !is_behavioral_threat {
                            warn!("AUTONOMOUS BLOCK SKIPPED: {} is a trusted operational binary with no behavioral/memory evidence. Downgrading to Alert.", image);
                            return Ok(());
                        }

                        if is_trusted && is_behavioral_threat {
                            warn!("AUTONOMOUS BLOCK OVERRIDE: {} is trusted but exhibits behavioral threats: {}. Proceeding with block.", image, reason);
                        }

                        let is_protected =
                            crate::blocking_manager::is_protected_or_benign_system_path(image);
                        if !is_protected && !self.is_monitor_only() {
                            warn!("AUTONOMOUS BLOCK: Consensus threshold met for {}. Applying FileBlockExecutable.", image);
                            let rule = osoosi_types::BlockingRule {
                                path: image.to_string(),
                                kind: osoosi_types::BlockingKind::Executable,
                            };
                            // Apply dynamic Sysmon block
                            let bm = self.blocking_manager.clone();
                            self.adaptive.spawn_adaptive(
                                ResourceCategory::IO,
                                Priority::Normal,
                                async move {
                                    if let Err(e) = bm.add_rule(rule).await {
                                        error!("Failed to apply autonomous block: {}", e);
                                    }
                                },
                            );

                            // Apply Ring-0 kernel driver block
                            if let Some(ref kd) = *self.kernel_driver.read() {
                                let _ = kd.add_blocked_path(image);
                            }

                            // Immediate termination + self-healing rollback
                            if let Some(pid) = extract_event_pid(&event) {
                                warn!("Terminating suspicious process PID: {}", pid);
                                let _ = self.remediation.kill_process_tree(pid);
                                let _ = self.blocking_manager.block_by_pid(pid).await;

                                // Block network access via WFP
                                let _ =
                                    crate::firewall::block_process_network(Some(pid), Some(image));

                                // Self-Healing: Rollback any file changes made by the malicious process
                                let self_healer = self.self_healing.clone();
                                self.adaptive.spawn_adaptive(ResourceCategory::IO, Priority::Normal, async move {
                                    match self_healer.rollback_process_actions(pid).await {
                                        Ok(count) if count > 0 => {
                                            warn!("Self-Healing: Rolled back {} file(s) for terminated PID {}.", count, pid);
                                        }
                                        Ok(_) => info!("Self-Healing: No rollback targets found for PID {}.", pid),
                                        Err(e) => warn!("Self-Healing rollback failed for PID {}: {}", pid, e),
                                    }
                                });
                            }
                        } else if !self.is_monitor_only()
                            && (is_lockdown_mode || is_behavioral_threat || signature.confidence >= 0.85)
                            && extract_event_pid(&event)
                                .map(|pid| {
                                    crate::blocking_manager::can_terminate_transient_lolbin_or_payload_pid(
                                        pid, image, &cmd_line,
                                    )
                                })
                                .unwrap_or(false)
                        {
                            if let Some(pid) = extract_event_pid(&event) {
                                warn!(
                                    "ACTIVE IPS / STRICT LOCKDOWN: Terminating transient LOLBin/payload child PID {} ({}) under confirmed Sigma/MITRE match (System32 binary on disk untouched).",
                                    pid, image
                                );
                                let _ = self
                                    .blocking_manager
                                    .kill_transient_lolbin_or_payload_pid(
                                        pid,
                                        ppid.map(|p| p as u32),
                                        image,
                                        &cmd_line,
                                        reason,
                                        is_lockdown_mode,
                                    )
                                    .await;
                                self.audit.log(
                                    "TRANSIENT_LOLBIN_PID_TERMINATED",
                                    serde_json::json!({
                                        "threat_id": signature.id,
                                        "pid": pid,
                                        "parent_pid": ppid,
                                        "process_name": p_name,
                                        "image": image,
                                        "command_line": cmd_line,
                                        "confidence": signature.confidence,
                                        "mitre_technique": signature.mitre_technique,
                                        "disk_binary_untouched": true,
                                    }),
                                );
                            }
                        } else {
                            warn!("AUTONOMOUS BLOCK: Skipping persistent FileBlockExecutable and process termination for protected/benign system binary or monitor-only mode: {}", image);
                        }

                        // Autonomous non-destructive account containment for T1136.001
                        if let Some(cmd) = event
                            .data
                            .get("CommandLine")
                            .or_else(|| event.data.get("command_line"))
                            .or_else(|| event.data.get("cmdline"))
                            .and_then(|v| v.as_str())
                        {
                            if let Some(username) = extract_created_username(cmd) {
                                warn!("Non-Destructive Account Containment: Detected T1136.001 rogue account creation for user '{}'. Enqueueing account disable task.", username);
                                self.trigger_account_rollback(username);
                            }
                        }
                    }
                }
                action => {
                    // When applying Tarpit or GhostTarpit, immediately freeze process threads (unless in Monitor Mode)
                    if matches!(action, ResponseAction::Tarpit | ResponseAction::GhostTarpit) {
                        if self.is_monitor_only() {
                            debug!(
                                "Monitor Mode active: skipping fast-path Tarpit for PID {:?}",
                                extract_raw_event_pid(&event)
                            );
                        } else if is_system_critical(&event) {
                            warn!(
                                "[SECURITY SAFEGUARD] Fast-path Tarpit skipped for PID {:?}: SYSTEM CRITICAL or Security Provider binary. Containment refused.",
                                extract_raw_event_pid(&event)
                            );
                            return Ok(());
                        } else if let Some(pid) = extract_event_pid(&event) {
                            let now = std::time::Instant::now();
                            let debounced = if let Some(last) = RECENT_TARPITTED_PIDS.get(&pid) {
                                now.duration_since(*last) < std::time::Duration::from_secs(60)
                            } else {
                                false
                            };

                            if !debounced {
                                RECENT_TARPITTED_PIDS.insert(pid, now);
                                warn!("Immediately freezing process threads via ActiveProcessTarpit for PID: {}", pid);
                                let active_tarpit =
                                    osoosi_runtime::tarpit::ActiveProcessTarpit::new();
                                let dur_secs = if action == ResponseAction::GhostTarpit {
                                    120
                                } else {
                                    60
                                };
                                active_tarpit.trap_pid(
                                    pid,
                                    std::time::Duration::from_millis(500),
                                    std::time::Duration::from_secs(dur_secs),
                                );
                            }
                        }
                        if let Some(cmd) = event
                            .data
                            .get("CommandLine")
                            .or_else(|| event.data.get("command_line"))
                            .or_else(|| event.data.get("cmdline"))
                            .and_then(|v| v.as_str())
                        {
                            if let Some(username) = extract_created_username(cmd) {
                                warn!("Non-Destructive Account Containment: Detected T1136.001 rogue account creation for user '{}'. Enqueueing account disable task.", username);
                                self.trigger_account_rollback(username);
                            }
                        }
                    }

                    // Perform non-isolating actions (Tarpit, Deception, Alert)
                    let orch = self.clone();
                    let ev = event.clone();
                    let sig = signature.clone();
                    self.adaptive.spawn_adaptive(
                        ResourceCategory::AI,
                        Priority::Normal,
                        async move {
                            if let Err(e) = orch.perform_action(&ev, &sig, action).await {
                                error!("Failed to perform response action {:?}: {}", action, e);
                            }
                        },
                    );
                }
            }
        }

        // Note: Threat events are already audited individually via THREAT_DETECTED above.
        // We intentionally do NOT audit every clean telemetry event to the Merkle chain —
        // doing so causes O(n) recomputation per event and double-serialization overhead.
        // The Causal AI graph below captures the full event timeline for forensic replay.

        // Log at DEBUG only — logging full event.data JSON at INFO level on every event
        // causes severe disk I/O pressure at high event rates and was the primary freeze cause.
        debug!(
            "PRO-FORENSIC [ID={}]: EventID={} | computer={}",
            event.event_id, event.event_id, event.computer
        );

        // 10/10 Causal Engine: Ingest event into the Causal AI Attack Graph
        self.causal_ai.ingest_event(&event);

        // Einstein Engine: Check for "Dilation of Truth" (temporal anomalies)
        let temporal_score = self.relativistic.check_temporal_dilation(&event);

        // --- Intelligent Event Correlation ---
        let correlated_sig = self.correlator.correlate_sysmon(&event).await;

        let mut signature: Option<osoosi_types::ThreatSignature> = correlated_sig;

        // PII Scanning for File creations
        if event.event_id == 11 {
            // 11: FileCreate
            if let Some(target_filename) = event.data.get("TargetFilename").and_then(|v| v.as_str())
            {
                if self.pii_classifier.is_scannable(target_filename) {
                    let pii_classifier = self.pii_classifier.clone();
                    let file_path = target_filename.to_string();
                    let computer = event.computer.clone();
                    let self_inner = self.clone();
                    self.adaptive.spawn_adaptive(ResourceCategory::IO, Priority::Normal, async move {
                        if let Ok(results) = pii_classifier.analyze_file(&file_path).await {
                            if !results.is_empty() {
                                tracing::warn!("PII Alert: Found {} sensitive entities in {}", results.len(), file_path);
                                let mut sig = osoosi_types::ThreatSignature::new(computer);
                                sig.confidence = 0.6;
                                sig.add_reason(format!("PII Classifier found {} sensitive entities in file creation", results.len()));
                                self_inner.broadcast_threat_to_mesh(sig).await;
                            }
                        }
                    });
                }
            }
        }

        // 0. Bloom Filter "Known Malicious" Fast-Path:
        // Immediately flag hashes we've already identified as malicious across the mesh.
        if let Some(hashes) = event.data.get("Hashes").and_then(|h| h.as_str()) {
            for hash_part in hashes.split(',') {
                let parts: Vec<&str> = hash_part.split('=').collect();
                if parts.len() == 2 {
                    let hash_val = parts[1];
                    if self.memory.is_hash_known_malicious_fast(hash_val) {
                        warn!(
                            "Bloom Filter HIT: Known malicious hash detected: {}",
                            hash_val
                        );
                        let mut sig = osoosi_types::ThreatSignature::new(event.computer.clone());
                        sig.confidence = 1.0;
                        sig.hash_blake3 = Some(hash_val.to_string());
                        sig.add_reason(format!("Bloom Filter: Hash {} matches a known malicious signature from the mesh", hash_val));
                        signature = Some(sig);
                        break;
                    }
                }
            }
        }

        // 1. NSRL "Known Good" Fast-Path: Skip deep analysis for trusted binaries.
        // We use a three-tier check: In-Memory L1 -> Persistent L2 -> Authoritative DB L3.
        if let Some(sha1) = event
            .data
            .get("Hashes")
            .and_then(|h| h.as_str())
            .and_then(|hashes| hashes.split(',').find(|s| s.starts_with("SHA1=")))
            .map(|s| &s[5..])
        {
            // Tier 1: In-memory session cache (Extremely fast)
            if let Some(is_good) = self.nsrl_cache.get(sha1) {
                if *is_good {
                    info!("NSRL Bypass (Memory Cache): Trusted hash {}", sha1);
                    return Ok(());
                }
            }

            // Tier 2: Persistent integrity cache (Checks if hash for this path has been validated before)
            if let Some(path) = event.data.get("Image").and_then(|v| v.as_str()) {
                if let Ok(Some((last_sha1, is_nsrl, _))) = self.memory.get_file_integrity(path) {
                    if last_sha1 == sha1 && is_nsrl {
                        self.nsrl_cache.insert(sha1.to_string(), true);
                        info!("NSRL Bypass (Persistent Cache): Trusted path {}", path);
                        return Ok(());
                    }
                }
            }

            // Tier 3: Authoritative NSRL database lookup
            if self.memory.is_nsrl_known_good(sha1).unwrap_or(false) {
                self.nsrl_cache.insert(sha1.to_string(), true);
                if let Some(path) = event.data.get("Image").and_then(|v| v.as_str()) {
                    let version = event.data.get("ProductVersion").and_then(|v| v.as_str());
                    let _ = self.memory.upsert_file_integrity(path, sha1, true, version);
                }
                info!(
                    "NSRL Bypass (DB Verified): {} -> Known Good.",
                    event
                        .data
                        .get("Image")
                        .and_then(|i| i.as_str())
                        .unwrap_or("Unknown")
                );
                return Ok(());
            }
        }

        if temporal_score > 0.6 {
            warn!(
                "Einstein Alert: Significant temporal dilation ({}) for event from {}.",
                temporal_score, event.computer
            );
            if let Some(ref mut sig) = signature {
                sig.confidence = sig.confidence.max(temporal_score);
                sig.add_reason(format!(
                    "Einstein Engine: Critical temporal anomaly detected (score: {:.2})",
                    temporal_score
                ));
            } else {
                let mut sig = osoosi_types::ThreatSignature::new(event.computer.clone());
                sig.confidence = temporal_score;
                sig.add_reason("Einstein Engine: Event rejected/flagged due to temporal paradox.");
                signature = Some(sig);
            }
        }

        // Behavioral baselining: record and detect first-connection anomalies
        let baseline_anomaly = match event.event_id {
            3 => {
                // NetworkConnect
                let proc = event
                    .data
                    .get("Image")
                    .and_then(|i| i.as_str())
                    .and_then(|p| std::path::Path::new(p).file_name())
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown");
                let dest = event
                    .data
                    .get("DestinationIp")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                self.baseline.record_network(&event.computer, proc, dest)
            }
            22 => {
                // DnsQuery
                let proc = event
                    .data
                    .get("Image")
                    .and_then(|i| i.as_str())
                    .and_then(|p| std::path::Path::new(p).file_name())
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown");
                let query = event
                    .data
                    .get("QueryName")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                self.baseline.record_dns(&event.computer, proc, query)
            }
            _ => false,
        };

        if matches!(event.event_id, 22) {
            // DnsQuery
            if let Some(dns_sig) = self.analyze_dns_query_risk(&event).await {
                let take_dns_sig = signature
                    .as_ref()
                    .map(|s| dns_sig.confidence > s.confidence)
                    .unwrap_or(true);
                if take_dns_sig {
                    signature = Some(dns_sig);
                }
            }
        }

        if baseline_anomaly {
            if let Some(ref mut sig) = signature {
                sig.add_reason("Behavioral baseline: first outbound connection/query from this process on this host");
                sig.confidence = sig.confidence.max(0.4);
            } else {
                let mut sig = osoosi_types::ThreatSignature::new(event.computer.clone());
                sig.confidence = 0.4;
                sig.process_name = event
                    .data
                    .get("Image")
                    .and_then(|i| i.as_str())
                    .and_then(|p| std::path::Path::new(p).file_name())
                    .and_then(|n| n.to_str())
                    .map(String::from);
                sig.add_reason("Behavioral baseline: first outbound connection/query from this process on this host");
                signature = Some(sig);
            }
        }

        if signature.is_none() {
            let image_path = event.data.get("Image").and_then(|i| i.as_str());
            let proc = image_path
                .and_then(|p| std::path::Path::new(p).file_name())
                .and_then(|n| n.to_str())
                .map(String::from);
            let cve = event
                .data
                .get("CveId")
                .and_then(|c| c.as_str())
                .map(String::from);
            let model = self.threat_model.read().await;
            let score = model.infer(proc.as_deref(), cve.as_deref(), None, Vec::new());
            if score >= 0.75 {
                let is_fp = self
                    .memory
                    .is_false_positive_pattern(proc.as_deref(), None)
                    .unwrap_or(false);
                let trusted_operational = is_trusted_operational_image(&event, &self.policy.config);

                if is_fp {
                    tracing::debug!(
                        "ML threat model suppressed false positive pattern for process {:?}",
                        proc
                    );
                } else if trusted_operational {
                    // SUPPRESSION: If it's a trusted tool, never emit a standalone ML alarm
                    // regardless of CVE status. A vulnerability is not a behavioral threat.
                    // Note: We use 1.1 because some features can cap at 1.0.
                    if score < 1.1 {
                        tracing::debug!(
                            "ML threat model suppressed hit for trusted binary {:?} (score: {:.2})",
                            image_path,
                            score
                        );
                    } else {
                        let mut sig = osoosi_types::ThreatSignature::new(event.computer.clone());
                        sig.confidence = score;
                        sig.process_name = proc.clone();
                        sig.cve_id = cve.clone();
                        sig.add_reason(format!(
                            "ML threat model: HIGH-CONFIDENCE hit on trusted binary {:?} (score: {:.2})",
                            proc, score
                        ));
                        signature = Some(sig);
                    }
                } else {
                    let mut sig = osoosi_types::ThreatSignature::new(event.computer.clone());
                    sig.confidence = score;
                    sig.process_name = proc.clone();
                    sig.cve_id = cve.clone();
                    sig.add_reason(format!(
                        "ML threat model: process {:?} / CVE {:?} scored {:.2}",
                        proc, cve, score
                    ));
                    signature = Some(sig);
                }
            }
        }

        // --- SECOND-TIER: CAPA Analysis for Unknown Files --- (OPTIMIZED)
        if signature.is_none() {
            if let Some(image_path) = event.data.get("Image").and_then(|v| v.as_str()) {
                let path = std::path::Path::new(image_path);
                // NSRL L1 cache is keyed by SHA-1 (not path), same as NsrlVoter
                let sha1_opt =
                    event
                        .data
                        .get("Hashes")
                        .and_then(|h| h.as_str())
                        .and_then(|hashes| {
                            hashes.split(',').find_map(|p| {
                                let t = p.trim();
                                t.strip_prefix("SHA1=")
                                    .or_else(|| t.strip_prefix("SHA1:"))
                                    .map(str::trim)
                                    .map(|s| s.to_ascii_lowercase())
                            })
                        });
                let is_known = sha1_opt
                    .as_ref()
                    .map(|h| self.nsrl_cache.contains_key(h.as_str()))
                    .unwrap_or(false)
                    || sha1_opt
                        .as_ref()
                        .map(|h| self.memory.is_nsrl_known_good(h).unwrap_or(false))
                        .unwrap_or(false);
                let is_system = osoosi_types::is_system_path(image_path);
                let is_dev_or_skip = osoosi_model::malware::is_ide_or_build_path(image_path)
                    || crate::voters::scanner_skip_path(image_path)
                    || should_skip_file_malware_scan(path);

                if !is_known && !is_system && !is_dev_or_skip {
                    let analyzer = self.static_analyzer.clone();
                    let orch = self.clone();
                    let ev = event.clone();
                    let path_buf = path.to_path_buf();

                    tokio::spawn(async move {
                        match analyzer.analyze_file(&path_buf).await {
                            Ok(Some(static_sig)) => {
                                warn!("Static Intelligence: Identified critical capabilities in unknown file: {:?}", path_buf);
                                if let Some(pid) = ev.data.get("ProcessId").and_then(|v| v.as_u64())
                                {
                                    if let Some(reason) = &static_sig.reason {
                                        for r in reason.split(';') {
                                            orch.correlator.add_static_finding(
                                                pid as u32,
                                                &path_buf.to_string_lossy(),
                                                r.trim(),
                                                static_sig.confidence,
                                            );
                                        }
                                    }
                                }
                                let _ = orch.handle_threat(&ev, static_sig).await;
                            }
                            Ok(None) => debug!(
                                "Static: No suspicious capabilities found for {:?}",
                                path_buf
                            ),
                            Err(e) => error!("Static analysis error for {:?}: {}", path_buf, e),
                        }
                    });
                    return Ok(());
                }
            }
        }

        // --- THIRD-TIER: HollowsHunter Memory Forensics (Reactive to Sysmon ETW) ---
        // Trigger conditions:
        //   1. ProcessAccess (Event ID 10) targeting lsass.exe → credential dumping attempt
        //   2. CreateRemoteThread (Event ID 8) → code injection / process hollowing
        // This is the "Pro Shortcut": we use Sysmon's signed kernel driver as our eyes,
        // and HollowsHunter as our hands to scan the suspect process's memory.
        #[cfg(target_os = "windows")]
        {
            let should_memory_scan = match event.event_id {
                10 => {
                    // ProcessAccess
                    // Check if target is lsass.exe (credential dumping)
                    let target = event
                        .data
                        .get("TargetImage")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    target.to_lowercase().contains("lsass.exe")
                }
                8 => {
                    // CreateRemoteThread
                    // Any remote thread creation is suspicious — scan both source and target
                    true
                }
                25 => {
                    // ProcessTampering (Hollowing / Herpaderping)
                    true
                }
                _ => false,
            };

            if should_memory_scan {
                // Get the target PID for focused scanning
                let target_pid = event
                    .data
                    .get("TargetProcessId")
                    .or_else(|| event.data.get("SourceProcessId"))
                    .or_else(|| event.data.get("ProcessId"))
                    .and_then(|v| {
                        v.as_u64()
                            .map(|n| n as u32)
                            .or_else(|| v.as_str().and_then(|s| s.parse::<u32>().ok()))
                    });

                if let Some(pid) = target_pid {
                    warn!(
                        "MEMORY FORENSICS: Sysmon {:?} triggered native memory scan on PID {}",
                        event.event_id, pid
                    );

                    let computer = event.computer.clone();
                    let target_image = event
                        .data
                        .get("TargetImage")
                        .or_else(|| event.data.get("SourceImage"))
                        .and_then(|v| v.as_str())
                        .and_then(|p| std::path::Path::new(p).file_name())
                        .and_then(|n| n.to_str())
                        .map(String::from);

                    // Run Native Rust MemoryScanner
                    let scanner = osoosi_memory::memory_scanner::MemoryScanner::new();
                    match scanner.scan_process_memory(pid).await {
                        Ok(results) => {
                            if !results.is_empty() {
                                warn!("MEMORY FORENSICS ALERT: Native memory scanner found {} suspicious implants in PID {}",
                                        results.len(), pid);

                                let mut mem_sig = osoosi_types::ThreatSignature::new(computer);
                                mem_sig.confidence = 0.95;
                                mem_sig.process_name = target_image;
                                mem_sig.recommended_action = osoosi_types::ResponseAction::Isolate;
                                mem_sig.add_reason(format!(
                                    "Native Memory Scanner: {} in-memory implants detected",
                                    results.len()
                                ));

                                for res in results.iter().take(5) {
                                    mem_sig.add_reason(format!("Detail: {}", res));
                                }

                                signature = Some(mem_sig);
                            } else {
                                debug!(
                                    "Memory Scanner: PID {} clean — no in-memory implants found.",
                                    pid
                                );
                            }
                        }
                        Err(e) => {
                            debug!("Memory Scanner execution failed for PID {}: {}", pid, e);
                        }
                    }
                }
            }
        }

        if let Some(signature) = signature {
            self.handle_threat(&event, signature).await?;
        }

        Ok(())
    }

    /// Compute alert suppression deduplication key for a ThreatSignature.
    /// Deduplicates by {hash}:{process_name}:{reason_category}.
    pub fn compute_suppression_key(signature: &osoosi_types::ThreatSignature) -> String {
        let hash = signature.hash_blake3.as_deref().unwrap_or("unknown");
        let reason_category = signature
            .reason
            .as_deref()
            .and_then(|r| r.split(':').next())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("generic");
        let proc = signature.process_name.as_deref().unwrap_or("unknown");
        format!("{}:{}:{}", hash, proc, reason_category)
    }
}
