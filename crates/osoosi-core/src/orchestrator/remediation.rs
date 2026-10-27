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
    /// Morphic Hyper-Web: Entangle a suspicious process.
    pub async fn entangle_process(&self, pid: u32, name: &str) {
        let mut engine = self.deception_engine.write().await;
        engine.entangle(pid, name);
        warn!("🕸️  Morphic Entanglement active for {} (PID {})", name, pid);
    }

    /// Report gaslighted telemetry for a process.
    pub async fn report_gaslighted_cpu(&self, pid: u32, real_cpu: f64) -> f64 {
        let engine = self.deception_engine.read().await;
        if let Some(spider) = engine.get_spider(pid) {
            spider.get_telemetry(real_cpu)
        } else {
            real_cpu
        }
    }

    /// Helper to find a PID by process name.
    pub async fn find_pid_by_name(&self, name: &str) -> Option<u32> {
        use sysinfo::System;
        let mut sys = System::new();
        sys.refresh_processes();

        let name_lower = name.to_lowercase();
        for (pid, process) in sys.processes() {
            if process.name().to_lowercase() == name_lower {
                return Some(pid.as_u32());
            }
        }
        None
    }

    /// Confirm a threat and fully entangle it in the Morphic Hyper-Web.
    pub async fn handle_confirm_and_entangle(&self, threat_id: &str) -> anyhow::Result<()> {
        let (gossip_proc, gossip_hash) = self.resolve_and_dismiss_gossip_item(threat_id);
        let source = self.trust.did().to_string();

        let (process_name_opt, hash_opt, file_path_opt) =
            match self.memory.mark_threat_true_positive(threat_id, &source)? {
                Some((p, h, f)) => (p, h, f),
                None => {
                    let proc = gossip_proc.or_else(|| Some(threat_id.to_string()));
                    let hash = gossip_hash;
                    let _ = self.memory.delete_threat_by_id_or_pattern(
                        Some(threat_id),
                        proc.as_deref(),
                        hash.as_deref(),
                    );
                    (proc, hash, None)
                }
            };

        let process_name = process_name_opt.unwrap_or_else(|| "unknown".to_string());
        let hash = hash_opt.unwrap_or_else(|| "unknown".to_string());

        info!(
            "🕸️  Confirming threat {} and initiating Morphic Entanglement...",
            threat_id
        );

        // 2. Try to find the live process to entangle
        if let Some(pid) = self.find_pid_by_name(&process_name).await {
            // Perform Binary Analysis (Spider Eyes)
            match self.spider_eyes.watch_process(pid).await {
                Ok(analysis) => {
                    info!(
                        "🕸️  [SPIDER-EYES] Analysis for {}: \n{}",
                        process_name, analysis
                    );

                    // BROADCAST to mesh: Share the disassembly and intent report
                    let mut sig = osoosi_types::ThreatSignature::new(self.trust.did().to_string());
                    sig.id = format!("analysis-{}", uuid::Uuid::new_v4());
                    sig.process_name = Some(process_name.clone());
                    sig.hash_blake3 = Some(hash.clone());
                    sig.confidence = 1.0;
                    sig.add_reason(analysis);

                    self.broadcast_threat_to_mesh(sig).await;
                    info!(
                        "🕸️  [MESH] Broadcasted binary analysis for {} to all spiders.",
                        process_name
                    );
                }
                Err(e) => {
                    warn!(
                        "🕸️  [SPIDER-EYES] Binary analysis failed for {}: {}",
                        process_name, e
                    );
                }
            }

            self.entangle_process(pid, &process_name).await;
        } else {
            warn!(
                "🕸️  Could not find live process for {}; entanglement pending next spawn.",
                process_name
            );
        }

        // 3. Engage network tarpit (Tarpitting)
        let target = if let Some(path) = file_path_opt {
            path
        } else {
            process_name.clone()
        };
        let _ = crate::firewall::tarpit_process_network(None, Some(&target));

        // 4. Record the action in the audit trail
        self.audit.log(
            "MORPHIC_ENTANGLEMENT",
            serde_json::json!({
                "threat_id": threat_id,
                "process": process_name,
                "hash": hash,
                "action": "entangled"
            }),
        );

        Ok(())
    }

    /// Run an autonomous remediation script in the WASM sandbox.
    /// Performs yara-scanning of all generated files in the workspace.
    pub async fn run_isolated_action(
        &self,
        wasm_bytes: &[u8],
        config: osoosi_sandbox::SandboxConfig,
        taint_labels: std::collections::HashSet<osoosi_types::TaintLabel>,
    ) -> anyhow::Result<osoosi_sandbox::SandboxResult> {
        info!(
            "Running isolated action in WASM sandbox: max_fuel={}",
            config.max_fuel
        );

        let result = self
            .sandbox
            .run_script(wasm_bytes, config.clone(), taint_labels)
            .await?;

        // Register pending approvals in the global queue
        if !result.pending_approvals.is_empty() {
            let mut queue = self.approval_queue.lock().await;
            queue.extend(result.pending_approvals.clone());
        }

        // Post-execution: scan the workspace for malicious payloads (Adaptive Smart Concurrency)
        let workspace_dir = config.workspace_dir.clone();
        let malware_scanner = self.malware_scanner.clone();
        let audit = self.audit.clone();
        let io_sem = self.adaptive.guard.io.clone();

        tokio::spawn(async move {
            let entries: Vec<_> = walkdir::WalkDir::new(&workspace_dir)
                .into_iter()
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().is_file())
                .collect();

            use futures::StreamExt;
            let mut stream = futures::stream::iter(entries)
                .filter(|entry| {
                    let skip = should_skip_file_malware_scan(entry.path());
                    futures::future::ready(!skip)
                })
                .map(|entry| {
                    let scanner = malware_scanner.clone();
                    let sem = io_sem.clone();
                    async move {
                        let _permit = sem.acquire().await.ok();
                        let scan = scanner.scan_file(entry.path()).await;
                        (entry, scan)
                    }
                })
                .buffer_unordered(8); // Max 8 concurrent scans to prevent IO thrashing

            while let Some((entry, scan_result)) = stream.next().await {
                if let Some(scan) = scan_result {
                    if scan.is_malware {
                        warn!(
                            "MALWARE GENERATED IN SANDBOX: {} (type={})",
                            entry.path().display(),
                            scan.malware_type
                        );
                        audit.log(
                            "SANDBOX_MALWARE_DETECTED",
                            serde_json::json!({
                                "file_path": entry.path().to_string_lossy(),
                                "malware_type": scan.malware_type,
                                "confidence": scan.combined_score,
                            }),
                        );
                    }
                }
                // Throttling: Prevent system freeze by yielding during massive workspace scans
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        });

        Ok(result)
    }

    /// Internal helper to handle identified threats (broadcast, audit, remediation, triage).
    pub(crate) async fn handle_threat(
        &self,
        event: &osoosi_types::HostSecurityEvent,
        signature: osoosi_types::ThreatSignature,
    ) -> anyhow::Result<()> {
        use osoosi_types::ResponseAction;
        let mut signature = signature;

        // If high confidence, trigger Burst mode to prioritize telemetry
        if signature.confidence > 0.6 {
            let _ = self.adaptive.trigger_burst_mode(60).await;
        }

        // Enrich signature with binary metadata if available
        if let Some(image_path) = event.data.get("Image").and_then(|v| v.as_str()) {
            if let Some(meta) = osoosi_types::get_pe_metadata(std::path::Path::new(image_path)) {
                signature.is_signed = meta.is_signed;

                // SECONDARY CHECK: WinVerifyTrust for Catalog-Signed binaries (UWP/HxTsr.exe)
                #[cfg(target_os = "windows")]
                if !signature.is_signed {
                    // ... implementation of WinVerifyTrust call ...
                    // If catalog signed, we override is_signed to true
                    signature.is_signed = crate::win_trust::verify_file_signature(image_path);
                }

                if signature.process_name.is_none() {
                    signature.process_name = Some(meta.product_name);
                }
            }
        }

        // Enrich signature with MITRE ATT&CK Framework metadata if missing
        if signature.mitre_technique.is_none() {
            let image = event
                .data
                .get("Image")
                .or_else(|| event.data.get("image"))
                .or_else(|| event.data.get("ImagePath"))
                .and_then(|v| v.as_str())
                .unwrap_or_else(|| signature.process_name.as_deref().unwrap_or(""));
            let cmdline = event
                .data
                .get("CommandLine")
                .or_else(|| event.data.get("command_line"))
                .or_else(|| event.data.get("cmdline"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let reason_str = signature.reason.as_deref().unwrap_or("");
            if let Some((tac, tech, name)) =
                osoosi_policy::mitre_kb::extract_mitre_from_text(reason_str)
            {
                signature.mitre_tactic = Some(tac);
                signature.mitre_technique = Some(tech);
                signature.mitre_technique_name = Some(name);
            } else if let Some((tac, tech, name)) =
                osoosi_policy::mitre_kb::infer_mitre_from_event(event.event_id, image, cmdline)
            {
                signature.mitre_tactic = Some(tac);
                signature.mitre_technique = Some(tech);
                signature.mitre_technique_name = Some(name);
            }
        }

        let suppression_key = Self::compute_suppression_key(&signature);

        let image_path_opt = event
            .data
            .get("Image")
            .or_else(|| event.data.get("TargetFilename"))
            .and_then(|v| v.as_str());
        let Some(adjudicated_sig) = self
            .adjudicate_threat_signature_with_rea_and_voters(
                image_path_opt.map(std::path::Path::new),
                signature,
                Some(event),
            )
            .await
        else {
            return Ok(());
        };
        signature = adjudicated_sig;

        let cooldown = Duration::from_secs(self.policy.config.alert_suppression_secs);
        if let Some(last) = self.alert_suppression_cache.get(&suppression_key) {
            if last.elapsed() < cooldown {
                return Ok(()); // Strong deduplication
            }
        }
        self.alert_suppression_cache
            .insert(suppression_key, Instant::now());

        // 0. Supreme Court: Use P2P mesh as an authority for lower-confidence local alerts.
        // If our local models are unsure (confidence < 0.85), we check if the mesh "Supreme Court"
        // has already ruled on this binary hash.
        if signature.confidence < 0.85 {
            if let Some(hash) = signature.hash_blake3.as_deref() {
                if self.memory.is_hash_known_malicious_fast(hash) {
                    warn!("Supreme Court: Mesh consensus overrides low-confidence local alert for {}. Escalating confidence.", hash);
                    signature.confidence = 0.95;
                    signature.recommended_action = ResponseAction::Isolate;
                    signature.add_reason("Mesh Consensus: Peer nodes have collectively identified this binary as high-risk (Supreme Court verdict).");
                }
            }
        }

        // Forensic Corroboration: Embedded Velociraptor Deep Sweep
        let forensics_cfg = &self.forensics.config;
        let tech_opt = signature.mitre_technique.as_deref();
        let matches_technique = tech_opt
            .map(|tech| {
                forensics_cfg
                    .trigger_techniques
                    .iter()
                    .any(|t| tech.starts_with(t) || t == tech)
            })
            .unwrap_or(false);

        if forensics_cfg.enabled
            && forensics_cfg.auto_investigate
            && signature.confidence >= forensics_cfg.min_trigger_confidence
            && matches_technique
        {
            let target_pid = event
                .data
                .get("ProcessId")
                .or_else(|| event.data.get("TargetProcessId"))
                .or_else(|| event.data.get("SourceProcessId"))
                .and_then(|v| {
                    v.as_u64()
                        .map(|n| n as u32)
                        .or_else(|| v.as_str().and_then(|s| s.parse::<u32>().ok()))
                });
            let target_path = event
                .data
                .get("Image")
                .or_else(|| event.data.get("TargetFilename"))
                .and_then(|v| v.as_str());

            let skip_forensics = target_path
                .or(signature.process_name.as_deref())
                .map(|p| {
                    let p_lc = p.to_ascii_lowercase();
                    p_lc.ends_with("velociraptor.exe")
                        || p_lc.ends_with("conhost.exe")
                        || p_lc.ends_with("sc.exe")
                        || p_lc.ends_with("taskkill.exe")
                        || p_lc.ends_with("netsh.exe")
                        || p_lc.ends_with("osoosi.exe")
                        || p_lc.ends_with("chrome.exe")
                        || p_lc.ends_with("msedge.exe")
                        || p_lc.ends_with("firefox.exe")
                        || p_lc.ends_with("brave.exe")
                })
                .unwrap_or(false);

            if !skip_forensics {
                let forensics_client = self.forensics.clone();
                let audit = self.audit.clone();
                let alert_id = signature
                    .reason
                    .clone()
                    .unwrap_or_else(|| "ALERT".to_string());
                let tech_str = tech_opt.map(String::from);
                let path_str = target_path.map(String::from);

                // Execute forensic sweep
                let report = forensics_client
                    .investigate(
                        target_pid,
                        path_str.as_deref(),
                        Some(&alert_id),
                        tech_str.as_deref(),
                    )
                    .await;

                if report.corroborated {
                    signature.confidence =
                        (signature.confidence + report.confidence_delta).min(1.0);
                    signature.add_reason(format!("Velociraptor Corroboration: {}", report.summary));
                    warn!(
                        "[FORENSICS] Forensic evidence corroborated threat! New confidence: {:.2} (PID: {:?}, Summary: {})",
                        signature.confidence, target_pid, report.summary
                    );
                }

                audit.log(
                    "FORENSIC_INVESTIGATION",
                    serde_json::to_value(&report).unwrap_or_default(),
                );
            }
        }

        // Defer THREAT_DETECTED audit & memory.log_threat until Clef Decision Model noise-suppression gate passes

        if matches!(event.event_id, 22) // DnsQuery
            && crate::firewall::dns_autoblock_enabled()
            && signature.confidence >= crate::firewall::dns_autoblock_min_confidence()
        {
            let query_name = event.data.get("QueryName").and_then(|v| v.as_str());
            let query_results = event.data.get("QueryResults").and_then(|v| v.as_str());
            match crate::firewall::block_dns_destinations(query_name, query_results) {
                Ok(msg) => {
                    warn!("Firewall DNS auto-block applied: {}", msg);
                    self.audit.log(
                        "RESPONSE_ACTION",
                        serde_json::json!({
                            "type": "FirewallDnsBlock",
                            "query_name": query_name,
                            "message": msg
                        }),
                    );
                }
                Err(e) => {
                    warn!("Firewall DNS auto-block skipped/failed: {}", e);
                }
            }
        }

        // 1. Clef Non-Autoregressive Decision Model Evaluation & Noise Suppression Gate
        let mut decision_override: Option<ResponseAction> = None;
        let mut human_escalation_required = false;
        if self.decision_engine.is_enabled() {
            let proc_str = signature.process_name.as_deref().unwrap_or("Unknown");
            let cmd_str = event
                .data
                .get("CommandLine")
                .or_else(|| event.data.get("command_line"))
                .and_then(|v| v.as_str())
                .unwrap_or("None");
            let (san_proc, inj1) = osoosi_types::sanitize_untrusted_log_field(proc_str, 128);
            let (san_cmd, inj2) = osoosi_types::sanitize_untrusted_log_field(cmd_str, 512);
            let injection_flag = inj1 || inj2;
            let fallback_mitre = if signature.mitre_technique.is_none() {
                signature.reason.as_deref().and_then(|r| {
                    if let Some(idx) = r.find("T1") {
                        let sub = &r[idx..];
                        let end_idx = sub
                            .find(|c: char| !c.is_ascii_alphanumeric() && c != '.')
                            .unwrap_or(sub.len());
                        Some(sub[..end_idx].to_string())
                    } else {
                        None
                    }
                })
            } else {
                None
            };
            let tech_str = signature
                .mitre_technique
                .as_deref()
                .or(fallback_mitre.as_deref())
                .unwrap_or("none");
            let reason_str = signature.reason.as_deref().unwrap_or("none");
            let state_text = format!(
                "Target: Incident\nProcess: {}\nCmdLine: {}\nMITRE: {}\nReason: {}\nConfidence: {:.2}\nSigned: {}\nInjectionDetected: {}",
                san_proc, san_cmd, tech_str, reason_str, signature.confidence, signature.is_signed, injection_flag
            );

            match self
                .decision_engine
                .evaluate_security_incident(&state_text)
                .await
            {
                Ok(decision) => {
                    debug!(
                        "[DECISION] Incident evaluated in {:.2}ms via {}: verdict='{}' ({:.2}), action='{}' ({:.2}), human_req={}",
                        decision.latency_ms, decision.provider_used, decision.verdict, decision.verdict_probability,
                        decision.containment_action, decision.action_probability, decision.human_escalation_required
                    );

                    if decision.human_escalation_required {
                        human_escalation_required = true;
                        signature.require_approval = true;
                        signature.action_state = osoosi_types::ActionState::Pending;
                        signature.recommended_action = ResponseAction::Alert;
                    }

                    // 1. Noise Suppression: Suppress benign false-positive noise before mesh broadcast or YARA generation
                    // Reject suppression if prompt injection was detected or if confidence is high (never suppress high-confidence threats)
                    if !injection_flag
                        && decision.verdict == "benign"
                        && decision.verdict_probability >= 0.90
                        && signature.confidence < 0.85
                    {
                        info!(
                            "[DECISION] Benign verdict ({:.2}) from Clef decision model. Suppressing alert.",
                            decision.verdict_probability
                        );
                        self.audit.log(
                            "DECISION_MODEL_SUPPRESSED_NOISE",
                            serde_json::json!({
                                "id": signature.id,
                                "verdict": decision.verdict,
                                "verdict_probability": decision.verdict_probability,
                                "state": state_text,
                                "latency_ms": decision.latency_ms,
                                "provider": decision.provider_used,
                            }),
                        );
                        return Ok(());
                    }

                    // 2. Action Routing: Containment actions
                    if decision.action_probability >= self.decision_engine.min_action_confidence() {
                        let mapped_action = if decision.human_escalation_required {
                            ResponseAction::Alert
                        } else {
                            match decision.containment_action.as_str() {
                                "isolate" | "quarantine" => ResponseAction::Isolate,
                                "tarpit" => ResponseAction::Tarpit,
                                "ghost_tarpit" => ResponseAction::GhostTarpit,
                                "alert" => ResponseAction::Alert,
                                _ => signature.recommended_action,
                            }
                        };

                        if decision.human_escalation_required {
                            signature.require_approval = true;
                            signature.action_state = osoosi_types::ActionState::Pending;
                            signature.recommended_action = ResponseAction::Alert;
                        }

                        self.audit.log(
                            "DECISION_MODEL_ACTION_ROUTED",
                            serde_json::json!({
                                "id": signature.id,
                                "verdict": decision.verdict,
                                "action": decision.containment_action,
                                "action_probability": decision.action_probability,
                                "mapped_action": format!("{:?}", mapped_action),
                                "human_escalation_required": decision.human_escalation_required,
                                "threat_severity": decision.threat_severity,
                                "latency_ms": decision.latency_ms,
                                "provider": decision.provider_used,
                            }),
                        );

                        decision_override = Some(mapped_action);
                    }

                    // 3. Heavy Generative Causal Reasoning Escalation
                    if decision.deep_reasoning_required && self.decision_engine.auto_escalate() {
                        let storyteller = self.storyteller.clone();
                        let audit = self.audit.clone();
                        tokio::spawn(async move {
                            debug!("[DECISION] Auto-escalating incident to background causal reasoning cortex...");
                            let _story = storyteller.summarize_ai(&audit).await;
                        });
                    }
                }
                Err(e) => {
                    warn!("[DECISION] Decision model evaluation error: {}", e);
                }
            }
        }

        warn!(
            "ALARM: Threat identified on node {}: {:?}",
            event.computer, signature
        );

        // Log detection to Audit Trail & Threat Intelligence after REA + Voter + Decision Model verification
        let mut audit_data = serde_json::to_value(&signature)?
            .as_object()
            .cloned()
            .unwrap_or_default();
        if let Some(img) = event.data.get("Image").and_then(|v| v.as_str()) {
            audit_data.insert("image_path".to_string(), serde_json::json!(img));
        }
        self.audit
            .log("THREAT_DETECTED", serde_json::Value::Object(audit_data));
        let _ = self.memory.log_threat(&signature);

        // Auto-generated YARA from high-confidence detections
        if signature.confidence >= 0.8 {
            if let Some(rule) = crate::yara_gen::generate_yara_from_threat(&signature) {
                let _ = self.yara_manager.hot_load_rule(&rule, &signature.id);
                info!(
                    "[YARA] Hot-loaded auto-generated YARA rule for threat '{}'. Engine updated.",
                    signature.id
                );
            }
        }

        // 3. Dispatch Active Response based on Decision Matrix
        let autonomy = osoosi_types::load_autonomy_config();
        let is_lockdown_mode = autonomy.is_strict_lockdown();
        let is_catalog_attack = is_mitre_catalog_attack(&signature, event);
        let is_destructive = is_destructive_mutation(&signature, event);
        let has_mitre_technique = signature
            .mitre_technique
            .as_ref()
            .map(|t| !t.trim().is_empty())
            .unwrap_or(false);

        #[allow(unused_mut)]
        let mut effective_action = if self.is_monitor_only() || human_escalation_required {
            ResponseAction::Alert
        } else if is_lockdown_mode
            && (signature.confidence >= autonomy.action_confidence_threshold
                || is_catalog_attack
                || is_destructive
                || has_mitre_technique)
        {
            // True Zero-Trust Lockdown Mode: ALL MITRE ATT&CK / ATLAS techniques and threats above threshold
            // immediately execute Isolate (Process Tree Kill). Never allow decision_override to downgrade to Alert.
            ResponseAction::Isolate
        } else if (is_destructive || is_catalog_attack) && autonomy.auto_quarantine_malware {
            // Active Enforcement Mode on MITRE catalog or destructive attack:
            // Never allow Clef decision_override = Some(Alert) or single-voter default Alert to downgrade containment.
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
        } else if let Some(clef_act) = decision_override {
            if autonomy.auto_quarantine_malware
                && clef_act == ResponseAction::Alert
                && signature.confidence >= autonomy.action_confidence_threshold
                && signature.recommended_action != ResponseAction::Alert
            {
                signature.recommended_action
            } else {
                clef_act
            }
        } else if signature.confidence >= autonomy.action_confidence_threshold {
            if autonomy.auto_quarantine_malware
                && signature.recommended_action == ResponseAction::Alert
                && has_mitre_technique
            {
                ResponseAction::Isolate
            } else {
                signature.recommended_action
            }
        } else {
            debug!(
                "Threat confidence {:.2} below action threshold {:.2}: downgrading to Alert",
                signature.confidence, autonomy.action_confidence_threshold
            );
            ResponseAction::Alert
        };

        // Strictly enforce Human Escalation Gate (override lockdown or catalog attacks if human escalation required)
        Self::apply_human_escalation_gate(
            &mut signature,
            &mut effective_action,
            human_escalation_required,
        );

        // Corroboration Gate: Cap uncorroborated single-detector destructive actions
        Self::apply_corroboration_gate(
            &mut signature,
            effective_action,
            is_destructive,
            autonomy.action_confidence_threshold,
        );

        // Platform-specific safety check: Validate Windows system files with SFC before isolation.
        #[cfg(target_os = "windows")]
        {
            if effective_action != ResponseAction::Alert {
                if let Some(file_path) = event
                    .data
                    .get("Image")
                    .or_else(|| event.data.get("NewProcessName"))
                    .or_else(|| event.data.get("image"))
                    .or_else(|| event.data.get("ImagePath"))
                    .and_then(|i| i.as_str())
                {
                    let is_active_threat = is_lockdown_mode
                        || is_catalog_attack
                        || is_destructive
                        || has_mitre_technique;
                    // In Lockdown Mode or for administrative LOLBins executing active threats, SFC safety override is disallowed.
                    if !is_lockdown_mode
                        && !crate::system_check::is_administrative_lolbin(file_path)
                        && crate::system_check::validate_file_safety_with_veto(
                            file_path,
                            is_active_threat,
                        )
                        .await
                    {
                        warn!("SFC SAFETY OVERRIDE: File {} verified as clean system binary by Windows SFC. Downgrading action to Alert.", file_path);
                        effective_action = ResponseAction::Alert;
                    }
                }
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

        let raw_f_path = event
            .data
            .get("Image")
            .or_else(|| event.data.get("NewProcessName"))
            .or_else(|| event.data.get("ImagePath"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let f_path = osoosi_policy::engine::normalize_nt_device_path(raw_f_path);

        let cmd_line = event
            .data
            .get("CommandLine")
            .or_else(|| event.data.get("command_line"))
            .or_else(|| event.data.get("cmdline"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let hash_val = signature.hash_blake3.clone().unwrap_or_else(|| {
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
        signature.recommended_action = effective_action;
        if signature.require_approval {
            signature.action_state = osoosi_types::ActionState::Pending;
        } else if effective_action != ResponseAction::Alert {
            signature.action_state = osoosi_types::ActionState::Executed;
        } else {
            signature.action_state = osoosi_types::ActionState::Pending;
        }

        if osoosi_memory::is_consensus_finding_vetoed_or_benign(
            Some(&p_name),
            Some(&f_path),
            signature.reason.as_deref().unwrap_or(""),
        ) {
            let benign_finding = osoosi_types::ConsensusFinding {
                id: signature.id.clone(),
                hash_blake3: hash_val.clone(),
                process_name: Some(p_name.clone()),
                file_path: Some(f_path.clone()),
                verdict: "benign".to_string(),
                confidence: 0.99,
                detector_count: signature.detector_count,
                voters_summary: signature.reason.clone().unwrap_or_default(),
                action_taken: "ignored_and_allowed".to_string(),
                evaluated_at: chrono::Utc::now(),
            };
            let _ = self.memory.record_consensus_finding(&benign_finding);
            let _ = self.memory.mark_hash_clean_ignored(
                &hash_val,
                Some(&p_name),
                Some(&f_path),
                "rea_consensus_veto",
            );
            return Ok(());
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

        // Aligned Messenger: Share verified intelligence with P2P Mesh & Nostr
        self.broadcast_threat_to_mesh(signature.clone()).await;

        // Shield Layer: Verify action safety against Taint/SSRF policies
        let sink = match effective_action {
            ResponseAction::Tarpit => Some(osoosi_types::TaintSink::process_injection()),
            ResponseAction::GhostTarpit | ResponseAction::Deception => {
                Some(osoosi_types::TaintSink::deception())
            }
            ResponseAction::Isolate => Some(osoosi_types::TaintSink::mesh_join()),
            _ => None,
        };

        if let Some(sink) = sink {
            if !self.shield.verify_taint_flow(event, &sink) {
                warn!(
                    "SHIELD BLOCK: Autonomous action {:?} blocked by taint policy",
                    effective_action
                );
                self.audit.log(
                    "SHIELD_BLOCKED",
                    serde_json::json!({
                        "action": format!("{:?}", effective_action),
                        "reason": "Taint violation detected in Shield Layer"
                    }),
                );
                return Ok(());
            }
        }

        // Human-in-the-Loop check: high-impact actions may require approval
        if signature.require_approval
            || signature.action_state == osoosi_types::ActionState::Pending
        {
            info!(
                "Action {:?} requires administrator approval. Queuing for review.",
                effective_action
            );
            self.audit.log(
                "ACTION_PENDING_APPROVAL",
                serde_json::json!({
                    "threat_id": signature.id,
                    "action": format!("{:?}", effective_action)
                }),
            );
        } else {
            self.perform_action(event, &signature, effective_action)
                .await?;
        }

        // LLM triage: add high-confidence threats for agent decision
        if crate::triage::triage_enabled()
            && signature.confidence >= crate::triage::triage_confidence_threshold()
        {
            crate::triage::add_pending(
                &self.triage_store,
                &signature.id,
                signature.clone(),
                event,
                effective_action,
            );
            crate::triage::remove_expired(&self.triage_store, 300);
        }

        // LangGraph Autonomous Defense Swarm trigger: dispatch non-blocking webhook to Ring-1 swarm
        let swarm_cfg = osoosi_types::load_swarm_config();
        if swarm_cfg.enabled
            && swarm_cfg.auto_trigger_on_threat
            && signature.confidence >= swarm_cfg.min_trigger_confidence
        {
            let swarm_service_url = swarm_cfg.service_url.trim_end_matches('/').to_string();
            let incident_target_pid = crate::extract_raw_event_pid(event).unwrap_or(0);
            let incident_target_name = signature
                .process_name
                .clone()
                .unwrap_or_else(|| "unknown.exe".to_string());
            let incident_target_path = event
                .data
                .get("Image")
                .or_else(|| event.data.get("TargetFilename"))
                .or_else(|| event.data.get("ImagePath"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let incident_cmdline = event
                .data
                .get("CommandLine")
                .or_else(|| event.data.get("command_line"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let incident_engine = signature.id.clone();
            let incident_conf = signature.confidence;
            let incident_mitre = signature.mitre_technique.clone();
            let incident_id = format!("INC-{}", signature.id);
            let timeout_duration = std::time::Duration::from_secs(swarm_cfg.timeout_secs.max(2));

            tokio::spawn(async move {
                let payload = serde_json::json!({
                    "incident_id": incident_id,
                    "target_pid": incident_target_pid,
                    "target_process_name": incident_target_name,
                    "target_path": incident_target_path,
                    "command_line": incident_cmdline,
                    "initial_detection_engine": incident_engine,
                    "initial_confidence": incident_conf,
                    "mitre_technique": incident_mitre,
                });

                let client = reqwest::Client::builder().timeout(timeout_duration).build();

                if let Ok(c) = client {
                    let endpoint = format!("{}/api/swarm/investigate", swarm_service_url);
                    match c.post(&endpoint).json(&payload).send().await {
                        Ok(resp) => {
                            debug!(
                                "[SWARM] Dispatched incident to Swarm at {} (status: {})",
                                endpoint,
                                resp.status()
                            );
                        }
                        Err(err) => {
                            debug!(
                                "[SWARM] Swarm service offline or unreachable at {}: {}",
                                endpoint, err
                            );
                        }
                    }
                }
            });
        }

        Ok(())
    }

    pub(crate) fn feedback_file_path(
        process_name: Option<&str>,
        file_path: Option<&str>,
    ) -> Option<String> {
        [file_path, process_name]
            .into_iter()
            .flatten()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .find(|s| {
                let p = std::path::Path::new(s);
                p.is_absolute() && p.exists() && p.is_file()
            })
            .map(ToOwned::to_owned)
    }

    pub(crate) fn blake3_file_hex(path: &str) -> anyhow::Result<String> {
        use std::io::Read;

        let mut file = std::fs::File::open(path)?;
        let mut hasher = blake3::Hasher::new();
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Ok(hasher.finalize().to_hex().to_string())
    }

    /// Mark a threat as false positive: whitelist the hash, clear traps, suppress future alerts.
    pub async fn handle_false_positive(&self, threat_id: &str) -> anyhow::Result<()> {
        let (gossip_proc, gossip_hash) = self.resolve_and_dismiss_gossip_item(threat_id);
        let source = self.trust.did().to_string();
        let (process_name, mut hash_blake3, file_path) =
            match self.memory.mark_threat_false_positive(threat_id, &source)? {
                Some(t) => t,
                None => {
                    let proc = gossip_proc;
                    let hash = gossip_hash;
                    let _ = self.memory.record_false_positive_pattern(
                        proc.as_deref(),
                        hash.as_deref(),
                        &source,
                    );
                    let _ = self.memory.delete_threat_by_id_or_pattern(
                        Some(threat_id),
                        proc.as_deref(),
                        hash.as_deref(),
                    );
                    (proc, hash, None)
                }
            };

        info!(
            "Threat {} marked as false positive. Whitelisting and reverting active response...",
            threat_id
        );

        if hash_blake3.as_deref().unwrap_or("").is_empty() {
            if let Some(path) =
                Self::feedback_file_path(process_name.as_deref(), file_path.as_deref())
            {
                match Self::blake3_file_hex(&path) {
                    Ok(hash) => {
                        info!("[FP] Resolved missing hash for '{}' as {}.", path, hash);
                        hash_blake3 = Some(hash);
                        let _ = self.memory.record_false_positive_pattern(
                            process_name.as_deref().or(Some(path.as_str())),
                            hash_blake3.as_deref(),
                            &source,
                        );
                    }
                    Err(e) => warn!(
                        "[FP] Could not hash '{}' for false-positive allowlist: {}",
                        path, e
                    ),
                }
            }
        }

        // 1. Whitelist the hash in the in-memory NSRL bypass cache so future scans skip it instantly
        if let Some(ref hash) = hash_blake3 {
            if !hash.is_empty() {
                self.nsrl_cache.insert(hash.clone(), true);
                info!(
                    "[FP] Hash {} added to session NSRL bypass cache — will not re-alert.",
                    hash
                );
            }
        }

        // 2. Whitelist the process name in the NSRL bypass cache as well
        if let Some(ref proc) = process_name {
            if !proc.is_empty() {
                self.nsrl_cache.insert(proc.clone(), true);
                let proc_base = std::path::Path::new(proc)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or(proc)
                    .to_ascii_lowercase();
                self.rea_adjudicated_clean_procs.insert(proc_base);
                info!(
                    "[FP] Process '{}' added to session NSRL bypass cache.",
                    proc
                );
            }
        }

        // 3. Revert Deception (Ghost Files / Traps)
        let traps_dir = self.runtime_config.traps_path.as_str();
        let _ = self.response.clear_ghost_files(traps_dir).await;
        info!("[FP] Ghost files cleared from '{}'.", traps_dir);

        self.audit.log(
            "FALSE_POSITIVE_REMEDIATION",
            serde_json::json!({
                "threat_id": threat_id,
                "process_name": process_name,
                "hash_blake3": hash_blake3,
                "file_path": file_path,
                "action": "whitelisted_and_remediated",
            }),
        );

        Ok(())
    }

    /// Record a manual false positive suppression for future detections.
    pub async fn record_manual_false_positive(
        &self,
        process_name: Option<String>,
        hash_blake3: Option<String>,
    ) -> anyhow::Result<()> {
        let source = self.trust.did().to_string();
        info!(
            "[FP] Manual suppression recorded for Process: {:?}, Hash: {:?}",
            process_name, hash_blake3
        );

        // 1. Persist in memory store
        self.memory.record_false_positive_pattern(
            process_name.as_deref(),
            hash_blake3.as_deref(),
            &source,
        )?;

        // 2. Add to session bypass cache for instant skipping
        if let Some(ref hash) = hash_blake3 {
            if !hash.is_empty() {
                self.nsrl_cache.insert(hash.clone(), true);
            }
        }
        if let Some(ref proc) = process_name {
            if !proc.is_empty() {
                self.nsrl_cache.insert(proc.clone(), true);
            }
        }

        let fp_id = hash_blake3
            .as_deref()
            .or(process_name.as_deref())
            .unwrap_or("fp");
        self.decision_engine
            .record_rl_feedback(fp_id, -1.0, "benign");

        self.audit.log(
            "MANUAL_FP_SUBMISSION",
            serde_json::json!({
                "process_name": process_name,
                "hash_blake3": hash_blake3,
                "action": "suppressed",
            }),
        );

        Ok(())
    }

    /// Manually report a true positive threat: creates a threat entry and triggers full entanglement.
    pub async fn handle_manual_true_positive(
        &self,
        process_name: Option<String>,
        file_hash: Option<String>,
    ) -> anyhow::Result<()> {
        let threat_id = format!("manual-{}", uuid::Uuid::new_v4());
        let source = self.trust.did().to_string();
        let name = process_name.as_deref().unwrap_or("manual_threat");

        // 1. Log to audit trail so it appears in recent threats
        self.audit.log(
            "THREAT_DETECTED",
            serde_json::json!({
                "id": threat_id,
                "process_name": name,
                "hash_blake3": file_hash,
                "source_node": source,
                "confidence": 1.0,
                "reason": "Manual analyst report",
                "timestamp": chrono::Utc::now().to_rfc3339()
            }),
        );

        // 2. Insert into memory store so handle_confirm_and_entangle can find it
        self.memory.log_threat(&osoosi_types::ThreatSignature {
            id: threat_id.clone(),
            cve_id: None,
            hash_blake3: file_hash.map(|s| s.to_string()),
            process_name: Some(name.to_string()),
            parent_process: None,
            version: None,
            confidence: 1.0,
            detected_at: chrono::Utc::now(),
            source_node: source.clone(),
            signature: None,
            public_key: None,
            merkle_proof: None,
            recommended_action: osoosi_types::ResponseAction::Isolate,
            reason: Some("Manual analyst report".to_string()),
            predicted_next: None,
            epsilon: None,
            detector_count: 1,
            require_approval: false,
            action_state: osoosi_types::ActionState::Executed,
            is_signed: false,
            mitre_tactic: None,
            mitre_technique: None,
            mitre_technique_name: None,
        })?;

        // 3. Call the confirm and entangle logic
        self.handle_confirm_and_entangle(&threat_id).await
    }

    /// Mark a threat as true positive: reinforce mesh intelligence and begin serious tarpit.
    pub async fn handle_true_positive(&self, threat_id: &str) -> anyhow::Result<()> {
        let source = self.trust.did().to_string();
        match self.memory.mark_threat_true_positive(threat_id, &source)? {
            Some((process_name, hash_blake3, file_path)) => {
                info!(
                    "Threat {} confirmed as TRUE positive. Engaging tarpit and broadcasting...",
                    threat_id
                );

                // 1. Engage the serious network tarpit using the existing QoS helper.
                let tarpit_target =
                    Self::feedback_file_path(process_name.as_deref(), file_path.as_deref())
                        .or_else(|| process_name.clone());
                if let Some(ref target) = tarpit_target {
                    match crate::firewall::tarpit_process_network(None, Some(target)) {
                        Ok(msg) => {
                            warn!("[TP] Serious tarpit engaged: {}", msg);
                            self.audit.log(
                                "RESPONSE_ACTION",
                                serde_json::json!({
                                    "type": "ConfirmedTruePositiveTarpit",
                                    "threat_id": threat_id,
                                    "image": target,
                                    "message": msg
                                }),
                            );
                        }
                        Err(e) => warn!(
                            "[TP] Serious tarpit could not be applied for '{}': {}",
                            target, e
                        ),
                    }
                }

                // 2. Add the hash to the known-malicious bloom filter so future mesh encounters are instantly flagged
                if let Some(ref hash) = hash_blake3 {
                    if !hash.is_empty() {
                        self.memory.mark_hash_known_malicious(hash);
                        info!("[TP] Hash {} added to known-malicious bloom filter.", hash);
                    }
                }

                // 3. Broadcast confirmed threat intelligence to the mesh
                self.audit.log(
                    "TRUE_POSITIVE_CONFIRMED",
                    serde_json::json!({
                        "threat_id": threat_id,
                        "process_name": process_name,
                        "hash_blake3": hash_blake3,
                        "file_path": file_path,
                        "tarpit_target": tarpit_target,
                        "action": "tarpit_engaged_and_intel_broadcast",
                    }),
                );

                let summary = format!(
                    "CONFIRMED THREAT — Analyst Verified (node: {}): id={} proc={:?} hash={:?}. Tarpit engaged.",
                    source, threat_id, process_name, hash_blake3
                );
                let _ = self.broadcast_intelligence(summary).await;

                Ok(())
            }
            None => Err(anyhow::anyhow!(
                "Threat '{}' not found in database",
                threat_id
            )),
        }
    }

    /// Check whether account rollback is permitted for the given user against baseline and protected safelist.
    pub fn is_account_rollback_allowed(&self, username: &str) -> bool {
        is_account_rollback_allowed(username, &self.preexisting_accounts)
    }

    /// Check whether account containment is permitted for the given user against baseline and protected safelist.
    pub fn is_account_containment_allowed(&self, username: &str) -> bool {
        is_account_containment_allowed(username, &self.preexisting_accounts)
    }

    /// Autonomous non-destructive account containment for T1136.001 rogue account creation.
    /// Strictly non-destructive: disables/locks down the account (/active:no, Disable-LocalUser)
    /// preserving forensic evidence, SIDs, and user data rather than deleting it.
    pub fn trigger_account_containment(&self, username: String) {
        self.trigger_account_rollback(username);
    }

    /// Autonomous non-destructive account containment rollback for T1136.001 rogue account creation.
    /// Strictly non-destructive: disables/locks down the account (/active:no, Disable-LocalUser)
    /// preserving forensic evidence, SIDs, and user data rather than deleting it.
    pub fn trigger_account_rollback(&self, username: String) {
        if !self.is_account_containment_allowed(&username) {
            warn!(
                "[SECURITY GUARDRAIL] Autonomous account containment REFUSED for user '{}'. Account is protected, pre-existing, or invalid! Confused deputy attack thwarted.",
                username
            );
            self.audit.log("CONFUSED_DEPUTY_ATTACK_PREVENTED", serde_json::json!({
                "technique": "T1136.001",
                "target_user": username,
                "reason": "Target account is in the protected system safelist, pre-existing baseline, or contains invalid/prohibited characters",
                "action": "containment_refused"
            }));
            return;
        }

        let audit = self.audit.clone();
        let preexisting = self.preexisting_accounts.clone();
        tokio::spawn(async move {
            if !is_account_containment_allowed(&username, &preexisting) {
                warn!(
                    "[SECURITY GUARDRAIL] Autonomous account containment REFUSED for user '{}'. Account is protected, pre-existing, or invalid (inner check)!",
                    username
                );
                audit.log("CONFUSED_DEPUTY_ATTACK_PREVENTED", serde_json::json!({
                    "technique": "T1136.001",
                    "target_user": username,
                    "reason": "Target account is in the protected system safelist, pre-existing baseline, or contains invalid/prohibited characters (inner check)",
                    "action": "containment_refused"
                }));
                return;
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
            #[cfg(target_os = "windows")]
            {
                const CREATE_NO_WINDOW: u32 = 0x08000000;
                let net_bin = osoosi_types::resolve_system_binary("net.exe");

                // Step 1: Check if user exists using native Win32 NetUserGetInfo
                let mut user_exists = win32_user_exists(&username);
                if !user_exists {
                    // Fallback to net.exe user check
                    let mut cmd_net = tokio::process::Command::new(&net_bin);
                    cmd_net.args(["user", &username]);
                    cmd_net.creation_flags(CREATE_NO_WINDOW);
                    if let Ok(out) = cmd_net.output().await {
                        if out.status.success() {
                            user_exists = true;
                        }
                    }
                }

                if !user_exists {
                    info!("[NON_DESTRUCTIVE_ACCOUNT_CONTAINMENT] User account '{}' does not exist in local database (threat mitigated before creation).", username);
                    return;
                }

                // Step 2: Non-destructive account disabling / lockdown via native Win32 NetUserSetInfo (UF_ACCOUNTDISABLE)
                let mut disabled = win32_disable_user(&username);

                // Fallback to net.exe user if NetUserSetInfo returned error
                if !disabled {
                    let net_args = get_account_containment_net_args(&username);
                    let mut cmd_dis_net = tokio::process::Command::new(&net_bin);
                    cmd_dis_net.args(net_args);
                    cmd_dis_net.creation_flags(CREATE_NO_WINDOW);
                    let res = cmd_dis_net.output().await;
                    disabled = matches!(res, Ok(ref output) if output.status.success());
                }

                if disabled {
                    warn!("[NON_DESTRUCTIVE_ACCOUNT_CONTAINMENT] Successfully disabled unauthorized account created by T1136.001: {}", username);
                    audit.log(
                        NON_DESTRUCTIVE_ACCOUNT_CONTAINMENT_EVENT,
                        serde_json::json!({
                            "technique": "T1136.001",
                            "user": username,
                            "status": NON_DESTRUCTIVE_ACCOUNT_CONTAINMENT_STATUS,
                            "method": NON_DESTRUCTIVE_ACCOUNT_CONTAINMENT_METHOD
                        }),
                    );
                } else {
                    warn!("[NON_DESTRUCTIVE_ACCOUNT_CONTAINMENT] Failed to disable unauthorized account '{}'", username);
                    audit.log(
                        NON_DESTRUCTIVE_ACCOUNT_CONTAINMENT_EVENT,
                        serde_json::json!({
                            "technique": "T1136.001",
                            "user": username,
                            "status": "containment_failed",
                            "method": NON_DESTRUCTIVE_ACCOUNT_CONTAINMENT_METHOD
                        }),
                    );
                }
            }
            #[cfg(not(target_os = "windows"))]
            {
                let user_exists = std::fs::read_to_string("/etc/passwd")
                    .map(|content| {
                        content
                            .lines()
                            .any(|line| line.split(':').next() == Some(&username))
                    })
                    .unwrap_or_else(|_| {
                        std::process::Command::new("id")
                            .args(["-u", &username])
                            .output()
                            .map(|o| o.status.success())
                            .unwrap_or(false)
                    });

                if !user_exists {
                    info!("[NON_DESTRUCTIVE_ACCOUNT_CONTAINMENT] User account '{}' does not exist in local database.", username);
                    return;
                }

                #[cfg(target_os = "macos")]
                let (lock_bin, lock_args, method_name) = (
                    "pwpolicy",
                    vec!["-a", username.as_str(), "-disableuser"],
                    "pwpolicy_disableuser",
                );

                #[cfg(not(target_os = "macos"))]
                let (lock_bin, lock_args, method_name) =
                    ("usermod", vec!["-L", username.as_str()], "usermod_lock");

                let mut disabled = tokio::process::Command::new(lock_bin)
                    .args(&lock_args)
                    .output()
                    .await
                    .map(|o| o.status.success())
                    .unwrap_or(false);

                #[cfg(not(target_os = "macos"))]
                if !disabled {
                    disabled = tokio::process::Command::new("passwd")
                        .args(["-l", &username])
                        .output()
                        .await
                        .map(|o| o.status.success())
                        .unwrap_or(false);
                }

                if disabled {
                    warn!("[NON_DESTRUCTIVE_ACCOUNT_CONTAINMENT] Successfully locked unauthorized account: {}", username);
                    audit.log(
                        NON_DESTRUCTIVE_ACCOUNT_CONTAINMENT_EVENT,
                        serde_json::json!({
                            "technique": "T1136.001",
                            "user": username,
                            "status": NON_DESTRUCTIVE_ACCOUNT_CONTAINMENT_STATUS,
                            "method": method_name
                        }),
                    );
                } else {
                    warn!("[NON_DESTRUCTIVE_ACCOUNT_CONTAINMENT] Failed to lock unauthorized account '{}'", username);
                    audit.log(
                        NON_DESTRUCTIVE_ACCOUNT_CONTAINMENT_EVENT,
                        serde_json::json!({
                            "technique": "T1136.001",
                            "user": username,
                            "status": "containment_failed",
                            "method": method_name
                        }),
                    );
                }
            }
        });
    }

    /// Execute the recommended action for a threat, synchronizing with Ring-0 driver and response mitigations.
    pub async fn execute_response_action(
        &self,
        event: &osoosi_types::HostSecurityEvent,
        signature: &osoosi_types::ThreatSignature,
        action: osoosi_types::ResponseAction,
    ) -> anyhow::Result<()> {
        self.perform_action(event, signature, action).await
    }

    /// Execute the recommended action for a threat.
    pub async fn perform_action(
        &self,
        event: &osoosi_types::HostSecurityEvent,
        signature: &osoosi_types::ThreatSignature,
        action: osoosi_types::ResponseAction,
    ) -> anyhow::Result<()> {
        use osoosi_runtime::TarpitManager;
        use osoosi_types::ResponseAction;

        if self.is_monitor_only() && action != ResponseAction::Alert {
            info!(
                "Action: Logged and Alerted (Monitor Mode active — autonomous {:?} suppressed for '{}').",
                action,
                signature.process_name.as_deref().unwrap_or(&signature.id)
            );
            return Ok(());
        }

        match action {
            ResponseAction::Deception => {
                let traps_path = &self.runtime_config.traps_path;
                warn!("Action: Spawning Ghost Files (Deception Traps) in response to discovery behavior.");
                self.response.spawn_ghost_files(traps_path).await?;
                self.audit.log(
                    "RESPONSE_ACTION",
                    serde_json::json!({"type": "GhostFiles", "path": traps_path}),
                );
            }
            ResponseAction::Tarpit => {
                if is_system_critical(event) {
                    debug!(
                        "[SECURITY SAFEGUARD] Tarpit refused: Event targets a SYSTEM CRITICAL or Security Provider binary. Containment skipped."
                    );
                    return Ok(());
                }

                if let Some(pid) = extract_event_pid(event) {
                    let now = std::time::Instant::now();
                    if let Some(last) = RECENT_TARPITTED_PIDS.get(&pid) {
                        if now.duration_since(*last) < std::time::Duration::from_secs(60) {
                            debug!("Tarpit skipped for PID {}: already tarpitted recently (debounce active)", pid);
                            return Ok(());
                        }
                    }
                    RECENT_TARPITTED_PIDS.insert(pid, now);

                    warn!(
                        "Action: Applying Active Resource Tarpit to PID {} (confidence {:.2})",
                        pid, signature.confidence
                    );

                    let tarpit = TarpitManager::new();
                    tarpit.apply_tarpit(pid, 60).await;
                    self.audit.log(
                        "RESPONSE_ACTION",
                        serde_json::json!({"type": "Tarpit", "pid": pid}),
                    );
                } else {
                    debug!("Tarpit requested but no PID extracted from event");
                }
                if let Some(cmd) = event
                    .data
                    .get("CommandLine")
                    .or_else(|| event.data.get("command_line"))
                    .or_else(|| event.data.get("cmdline"))
                    .and_then(|v| v.as_str())
                {
                    if let Some(username) = extract_created_username(cmd) {
                        self.trigger_account_rollback(username);
                    }
                }
                if let Some(msg) =
                    crate::otx_tarpit::try_apply_process_network_qostarpit(event, signature, action)
                {
                    warn!("OTX/Network reactive QoS: {}", msg);
                    self.audit.log(
                        "NETWORK_QOS_TARPIT",
                        crate::otx_tarpit::audit_payload(event, signature, action, &msg),
                    );
                }
            }
            ResponseAction::GhostTarpit => {
                let traps_path = &self.runtime_config.traps_path;
                if is_system_critical(event) {
                    debug!(
                        "[SECURITY SAFEGUARD] Tarpit refused: Event targets a SYSTEM CRITICAL or Security Provider binary. Containment skipped."
                    );
                    return Ok(());
                }

                self.response.spawn_ghost_files(traps_path).await?;
                if let Some(pid) = extract_event_pid(event) {
                    let now = std::time::Instant::now();
                    let debounced = if let Some(last) = RECENT_TARPITTED_PIDS.get(&pid) {
                        now.duration_since(*last) < std::time::Duration::from_secs(120)
                    } else {
                        false
                    };

                    if !debounced {
                        RECENT_TARPITTED_PIDS.insert(pid, now);
                        warn!(
                            "Action: Multi-tier Response (Ghost + Active Tarpit) active for PID {} (confidence {:.2})",
                            pid, signature.confidence
                        );
                        let tarpit = TarpitManager::new();
                        tarpit.apply_tarpit(pid, 120).await;
                        self.audit.log("RESPONSE_ACTION", serde_json::json!({"type": "GhostTarpit", "pid": pid, "ghost_path": traps_path}));
                    } else {
                        debug!("GhostTarpit thread containment skipped for PID {}: already tarpitted recently (debounce active)", pid);
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
                        self.trigger_account_rollback(username);
                    }
                }
                if crate::firewall::autoblock_enabled() {
                    let pid = extract_event_pid(event);
                    let image = event
                        .data
                        .get("Image")
                        .or_else(|| event.data.get("NewProcessName"))
                        .or_else(|| event.data.get("image"))
                        .or_else(|| event.data.get("ImagePath"))
                        .and_then(|i| i.as_str());
                    let is_lolbin = image
                        .map(crate::system_check::is_administrative_lolbin)
                        .unwrap_or(false);
                    if !is_lolbin {
                        match crate::firewall::block_process_network(pid, image) {
                            Ok(msg) => {
                                warn!("Firewall auto-block applied: {}", msg);
                                self.audit.log(
                                    "RESPONSE_ACTION",
                                    serde_json::json!({
                                        "type": "FirewallBlock",
                                        "pid": pid,
                                        "image": image,
                                        "message": msg
                                    }),
                                );
                            }
                            Err(e) => warn!("Firewall auto-block failed: {}", e),
                        }
                    } else {
                        debug!(
                            "Skipping firewall auto-block for administrative LOLBin {:?}",
                            image
                        );
                    }
                }
                if let Some(msg) =
                    crate::otx_tarpit::try_apply_process_network_qostarpit(event, signature, action)
                {
                    warn!("OTX/Network reactive QoS: {}", msg);
                    self.audit.log(
                        "NETWORK_QOS_TARPIT",
                        crate::otx_tarpit::audit_payload(event, signature, action, &msg),
                    );
                }
            }
            ResponseAction::Alert => {
                info!("Action: Logged and Alerted.");
                self.audit
                    .log("RESPONSE_ACTION", serde_json::json!({"type": "Alert"}));
            }
            ResponseAction::Isolate => {
                if is_system_critical(event) {
                    debug!(
                        "[SECURITY SAFEGUARD] Isolate refused: Event targets a SYSTEM CRITICAL or Security Provider binary. Containment skipped."
                    );
                    return Ok(());
                }

                warn!(
                    "Action: Targeted Process Block & Termination (confidence {:.2})",
                    signature.confidence
                );
                self.audit.log("RESPONSE_ACTION", serde_json::json!({"type": "TargetedProcessBlock", "confidence": signature.confidence}));

                if let Some(pid) = extract_event_pid(event) {
                    let image = event
                        .data
                        .get("Image")
                        .or_else(|| event.data.get("NewProcessName"))
                        .or_else(|| event.data.get("image"))
                        .or_else(|| event.data.get("ImagePath"))
                        .and_then(|i| i.as_str());
                    let cmd_line = event
                        .data
                        .get("CommandLine")
                        .or_else(|| event.data.get("command_line"))
                        .or_else(|| event.data.get("cmdline"))
                        .and_then(|c| c.as_str())
                        .unwrap_or("");

                    // Terminate the process tree immediately
                    warn!("Terminating malicious process PID: {}", pid);
                    if let Err(e) = self.remediation.kill_process_tree(pid) {
                        warn!("Failed to terminate process PID {}: {}", pid, e);
                        if crate::blocking_manager::can_terminate_transient_lolbin_or_payload_pid(
                            pid,
                            image.unwrap_or(""),
                            cmd_line,
                        ) {
                            let _ = self
                                .blocking_manager
                                .kill_transient_lolbin_or_payload_pid(
                                    pid,
                                    None,
                                    image.unwrap_or(""),
                                    cmd_line,
                                    signature.reason.as_deref().unwrap_or(""),
                                    osoosi_types::load_autonomy_config().is_strict_lockdown(),
                                )
                                .await;
                        }
                    } else {
                        info!("Successfully terminated process PID: {}", pid);
                    }

                    // Block network access via WFP and kernel driver, unless target is an administrative LOLBin
                    let is_lolbin = image
                        .map(crate::system_check::is_administrative_lolbin)
                        .unwrap_or(false);
                    if !is_lolbin {
                        match crate::firewall::block_process_network(Some(pid), image) {
                            Ok(msg) => {
                                warn!("Targeted firewall block applied: {}", msg);
                                self.audit.log(
                                    "RESPONSE_ACTION",
                                    serde_json::json!({
                                        "type": "FirewallBlock",
                                        "pid": pid,
                                        "image": image,
                                        "message": msg
                                    }),
                                );
                            }
                            Err(e) => warn!("Targeted firewall block failed: {}", e),
                        }

                        // Add image to Ring-0 kernel driver blocklist
                        if let Some(img) = image {
                            if let Some(ref kd) = *self.kernel_driver.read() {
                                let _ = kd.add_blocked_path(img);
                            }
                        }
                    } else {
                        info!(
                            "Administrative LOLBin detected ({:?}); skipping permanent image firewall and kernel driver path block to protect OS integrity.",
                            image
                        );
                    }
                }

                // Contain unauthorized accounts created by T1136.001 (strictly non-destructive)
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
            ResponseAction::MemoryScan => {
                warn!(
                    "Action: Deep Memory Forensics (HollowsHunter) active (confidence {:.2})",
                    signature.confidence
                );
                if let Some(pid) = extract_event_pid(event) {
                    let _ = self.run_hollows_hunter_for_pid(pid).await;
                }
            }
            ResponseAction::RegistryRepair => {
                warn!(
                    "Action: Registry Persistence Remediation active (confidence {:.2})",
                    signature.confidence
                );
                if let Some(image) = event.data.get("Image").and_then(|i| i.as_str()) {
                    match osoosi_repair::registry::RegistryRemediator::remediate_process_persistence(
                        image,
                    ) {
                        Ok(changes) => {
                            info!("Registry remediation complete for {}: {:?}", image, changes);
                            self.audit.log(
                                "RESPONSE_ACTION",
                                serde_json::json!({
                                    "type": "RegistryRepair",
                                    "image": image,
                                    "changes": changes
                                }),
                            );
                        }
                        Err(e) => warn!("Registry remediation failed for {}: {}", image, e),
                    }
                }
            }
        }

        Ok(())
    }

    /// Perform a deep memory scan using native MemoryScanner.
    pub async fn run_hollows_hunter_for_pid(
        &self,
        pid: u32,
    ) -> anyhow::Result<osoosi_types::HollowsHunterResult> {
        info!("Starting native memory scan for PID {}", pid);

        let scanner = osoosi_memory::memory_scanner::MemoryScanner::new();
        let mut res = osoosi_types::HollowsHunterResult {
            pid,
            success: false,
            ..Default::default()
        };

        match scanner.scan_process_memory(pid).await {
            Ok(results) => {
                res.success = true;
                if !results.is_empty() {
                    res.implants_detected = results.len() as u64;
                    for r in results.into_iter().take(10) {
                        res.details.push(r);
                    }
                }
            }
            Err(e) => {
                warn!("Native memory scan failed for PID {}: {}", pid, e);
            }
        }

        self.audit.log(
            "MEMORY_SCAN",
            serde_json::json!({
                "pid": pid,
                "success": res.success,
                "implants": res.implants_detected
            }),
        );

        Ok(res)
    }

    /// Auto-remediate a detected platform security gap on this host.
    pub async fn auto_remediate_security_gap(&self, gap_id: &str) -> serde_json::Value {
        let status = crate::hardened::auto_remediate_security_gap(gap_id);
        let _ = self.memory().save_zone_posture(
            "zone-alpha-mesh",
            status.security_score as i64,
            crate::hardened::TPM_REMEDIATED.load(std::sync::atomic::Ordering::SeqCst),
            crate::hardened::MEMORY_SHIELD_REMEDIATED.load(std::sync::atomic::Ordering::SeqCst),
            crate::hardened::SOFTWARE_EGRESS_REMEDIATED.load(std::sync::atomic::Ordering::SeqCst),
            "TPM 2.0 Anchored · WFP Containment Armed",
            &serde_json::to_string(&status.recommendations).unwrap_or_default(),
        );
        self.audit.log(
            "SECURITY_GAP_REMEDIATED",
            serde_json::json!({
                "gap_id": gap_id,
                "security_score": status.security_score,
            }),
        );
        serde_json::json!({
            "status": "success",
            "security_score": status.security_score,
            "structured_recommendations": status.structured_recommendations,
            "recommendations": status.recommendations,
        })
    }

    /// Get all pending action approvals.
    pub async fn get_pending_approvals(&self) -> Vec<osoosi_sandbox::ApprovalRequest> {
        self.approval_queue.lock().await.clone()
    }

    /// Approve and execute a pending action.
    pub async fn approve_action(&self, threat_id: &str) -> anyhow::Result<()> {
        let mut queue = self.approval_queue.lock().await;
        if let Some(pos) = queue.iter().position(|r| r.id == threat_id) {
            let request = queue.remove(pos);
            info!("Action approved: {} (ID: {})", request.action, threat_id);
            self.decision_engine
                .record_rl_feedback(threat_id, 1.0, &request.action);
            self.policy.update_voter_weights_from_feedback(true, 0.05);
            self.audit.log(
                "ACTION_APPROVED",
                serde_json::json!({"id": threat_id, "action": request.action}),
            );

            // If a corresponding threat is stored in memory, entangle and broadcast to mesh
            if let Ok(threats) = self.memory.get_threats_for_training(100) {
                if let Some(t) = threats.into_iter().find(|t| t.id == threat_id) {
                    if let Some(ref proc_name) = t.process_name {
                        let pid = self.find_pid_by_name(proc_name).await.unwrap_or(0);
                        if pid > 4 {
                            self.entangle_process(pid, proc_name).await;
                        }
                    }
                    self.broadcast_threat_to_mesh(t).await;
                }
            }

            Ok(())
        } else {
            anyhow::bail!("Pending action not found")
        }
    }

    /// Reject a pending action.
    pub async fn reject_action(&self, threat_id: &str) -> anyhow::Result<()> {
        let mut queue = self.approval_queue.lock().await;
        if let Some(pos) = queue.iter().position(|r| r.id == threat_id) {
            let request = queue.remove(pos);
            info!("Action rejected: {} (ID: {})", request.action, threat_id);
            self.decision_engine
                .record_rl_feedback(threat_id, -1.0, "allow");
            self.policy.update_voter_weights_from_feedback(false, 0.05);
            self.audit.log(
                "ACTION_REJECTED",
                serde_json::json!({"id": threat_id, "action": request.action}),
            );
            Ok(())
        } else {
            anyhow::bail!("Pending action not found")
        }
    }
}
