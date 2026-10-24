#![allow(unused_imports)]

use super::*;
use super::types::*;
use crate::causal_graph::*;
use crate::console_defense::*;
use crate::disk_cleanup::*;
use crate::hybrid_runtime::*;
use crate::killchain::*;
use crate::memory_watchdog::*;
use crate::rea::*;
use crate::voters::*;

impl EdrOrchestrator {
    /// Executes a comprehensive 12-sweep active EDR security and host audit using the in-process Siquery relational engine.
    /// Evaluates anomalies across processes, sockets, services, DNS hosts & cache, proxy settings, shares, accounts,
    /// memory maps, ARP MITM poisoning, autoruns/tasks, BYOVD drivers, firewall/defender posture, and shimcache/certs.
    /// In Enforce mode, autonomously contains threats via Clef Decision Model evaluation, process termination,
    /// entanglement, firewall blocking, and P2P/Nostr mesh broadcast.
    pub async fn run_siquery_edr_audit_sweep(&self) -> serde_json::Value {
        let engine = self.siquery_engine.clone();
        let start = std::time::Instant::now();
        let mut anomalies = Vec::new();
        let monitor_only = self.is_monitor_only();

        // --- Sweep 1: Processes & Open Sockets & AI Agent Breakout Check ---
        let proc_count_res = engine.execute_query("SELECT COUNT(*) AS total FROM processes;");
        let total_processes = proc_count_res
            .ok()
            .and_then(|r| {
                r.first()
                    .and_then(|row| row.get("total").and_then(|v| v.as_i64()))
            })
            .unwrap_or(0);

        let sock_count_res =
            engine.execute_query("SELECT COUNT(*) AS total FROM process_open_sockets;");
        let total_sockets = sock_count_res
            .ok()
            .and_then(|r| {
                r.first()
                    .and_then(|row| row.get("total").and_then(|v| v.as_i64()))
            })
            .unwrap_or(0);

        if let Ok(suspicious_procs) = engine.execute_query(
            "SELECT p.pid, p.name, p.path, p.cmdline, s.remote_address, s.remote_port \
             FROM processes p JOIN process_open_sockets s ON p.pid = s.pid \
             WHERE p.cmdline LIKE '%169.254.169.254%' \
                OR p.cmdline LIKE '%\\config\\SAM%' \
                OR p.cmdline LIKE '%comsvcs.dll%' \
                OR p.cmdline LIKE '%MiniDump%' \
             LIMIT 10;",
        ) {
            for row in suspicious_procs {
                let pid = row.get("pid").and_then(|v| v.as_i64()).unwrap_or(0) as u32;
                let name = row
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let cmd = row.get("cmdline").and_then(|v| v.as_str()).unwrap_or("");
                let reason = format!(
                    "Siquery EDR Sweep: Suspicious breakout pattern in process PID {} ({}): {}",
                    pid, name, cmd
                );
                warn!("{}", reason);

                let mut is_benign = false;
                let mut human_escalation_required = false;
                if self.decision_engine.is_enabled() {
                    let (safe_name, inj_n) = osoosi_types::sanitize_untrusted_log_field(name, 128);
                    let (safe_cmd, inj_c) = osoosi_types::sanitize_untrusted_log_field(cmd, 512);
                    let inj = inj_n || inj_c;
                    let incident = format!(
                        "Target: Process\nProcess: {}\nPID: {}\nCmd: {}\nTrigger: Siquery breakout query\nPromptInjectionDetected: {}",
                        safe_name, pid, safe_cmd, inj
                    );
                    if let Ok(dec) = self
                        .decision_engine
                        .evaluate_security_incident(&incident)
                        .await
                    {
                        if dec.human_escalation_required {
                            human_escalation_required = true;
                        } else if !inj
                            && (dec.verdict == "benign" || dec.containment_action == "allow")
                        {
                            is_benign = true;
                        }
                    }
                }

                if !is_benign {
                    let _ =
                        self.memory
                            .log_threat_event("SIQUERY_PROCESS_BREAKOUT_ANOMALY", pid, 0);
                    self.audit.log(
                        "SIQUERY_PROCESS_BREAKOUT",
                        serde_json::json!({
                            "pid": pid,
                            "name": name,
                            "cmdline": cmd,
                            "reason": reason
                        }),
                    );

                    let mut sig = osoosi_types::ThreatSignature::new(self.trust.did().to_string());
                    sig.process_name = Some(name.to_string());
                    sig.confidence = 0.95;
                    if human_escalation_required {
                        sig.recommended_action = osoosi_types::ResponseAction::Alert;
                        sig.action_state = osoosi_types::ActionState::Pending;
                        sig.require_approval = true;
                    } else {
                        sig.recommended_action = osoosi_types::ResponseAction::Isolate;
                    }
                    sig.reason = Some(reason.clone());
                    sig.mitre_tactic = Some("TA0002".to_string());
                    sig.mitre_technique = Some("T1003.001".to_string());
                    sig.mitre_technique_name =
                        Some("OS Credential Dumping: LSASS Memory".to_string());

                    let _ = self.memory.log_threat(&sig);
                    self.record_gossip_threat(&sig, "SIQUERY_PROCESS_BREAKOUT");

                    let nostr = self.nostr_mesh.clone();
                    let sig_c = sig.clone();
                    tokio::spawn(async move {
                        let _ = nostr.broadcast_threat(sig_c).await;
                    });
                    if let Some(ref tx) = *self.mesh_command_tx.lock().await {
                        let _ = tx.try_send(osoosi_wire::MeshCommand::Broadcast(sig.clone()));
                    }

                    if !monitor_only && !human_escalation_required && pid > 4 {
                        info!(
                            "Siquery Active Protection: Terminating & entangling rogue PID {}",
                            pid
                        );
                        let _ = self.blocking_manager.block_by_pid(pid).await;
                        self.entangle_process(pid, name).await;
                    }

                    anomalies.push(serde_json::json!({
                        "sweep": "processes_sockets",
                        "severity": "CRITICAL",
                        "pid": pid,
                        "name": name,
                        "details": reason,
                        "action": if monitor_only || human_escalation_required { "logged_monitored" } else { "terminated_and_entangled" }
                    }));
                }
            }
        }

        // --- Sweep 1B: Local Credential Harvesting & Post-Compromise Process Sweep (No Open Socket Required — Windows & Linux) ---
        if let Ok(cred_procs) = engine.execute_query(
            "SELECT pid, name, path, cmdline FROM processes \
             WHERE cmdline LIKE '%keymgr%' \
                OR cmdline LIKE '%krshowkeymgr%' \
                OR cmdline LIKE '%comsvcs%' \
                OR cmdline LIKE '%mimikatz%' \
                OR cmdline LIKE '%sekurlsa%' \
                OR cmdline LIKE '%procdump%' \
                OR cmdline LIKE '%credwiz%' \
                OR cmdline LIKE '%vaultcmd%' \
                OR cmdline LIKE '%hklm\\sam%' \
                OR cmdline LIKE '%hklm\\security%' \
                OR cmdline LIKE '%ntds.dit%' \
                OR cmdline LIKE '%/etc/shadow%' \
                OR cmdline LIKE '%/etc/gshadow%' \
                OR cmdline LIKE '%mimipenguin%' \
                OR cmdline LIKE '%unshadow%' \
                OR cmdline LIKE '%ld.so.preload%' \
             LIMIT 15;",
        ) {
            let my_pid = std::process::id();
            for proc in cred_procs {
                let pid = proc.get("pid").and_then(|v| v.as_i64()).unwrap_or(0) as u32;
                let name = proc.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let path = proc.get("path").and_then(|v| v.as_str()).unwrap_or("");
                let cmd = proc.get("cmdline").and_then(|v| v.as_str()).unwrap_or("");
                let cmd_lc = cmd.to_lowercase();

                if pid > 4
                    && pid != my_pid
                    && !name.eq_ignore_ascii_case("osoosi.exe")
                    && !name.eq_ignore_ascii_case("osoosi")
                    && !cmd_lc.contains("cargo ")
                    && !cmd_lc.contains("rustc ")
                    && !cmd_lc.contains("git ")
                    && !cmd_lc.contains("rg ")
                    && !cmd_lc.contains("select-string")
                    && !cmd_lc.contains("--type=crashpad-handler")
                    && !cmd_lc.contains("sentryproxy")
                {
                    let reason = format!(
                        "Siquery EDR Sweep 1B: Local credential harvesting / post-compromise activity detected: {} (PID: {}) cmd: {}",
                        name, pid, cmd
                    );
                    warn!("{}", reason);

                    let _ = self.memory.log_threat_event(
                        "SIQUERY_LOCAL_CREDENTIAL_GUARD_ANOMALY",
                        pid,
                        0,
                    );
                    self.audit.log(
                        "SIQUERY_LOCAL_CREDENTIAL_GUARD_INTERCEPT",
                        serde_json::json!({
                            "pid": pid,
                            "name": name,
                            "path": path,
                            "cmdline": cmd,
                            "reason": reason
                        }),
                    );

                    let mut sig = osoosi_types::ThreatSignature::new(self.trust.did().to_string());
                    sig.process_name = Some(name.to_string());
                    sig.confidence = 0.98;
                    sig.recommended_action = osoosi_types::ResponseAction::Isolate;
                    sig.reason = Some(reason.clone());
                    sig.mitre_tactic = Some("TA0006".to_string());
                    sig.mitre_technique = Some("T1003".to_string());
                    sig.mitre_technique_name =
                        Some("OS Credential Dumping / Post-Compromise Harvesting".to_string());

                    let _ = self.memory.log_threat(&sig);
                    self.record_gossip_threat(&sig, "SIQUERY_LOCAL_CREDENTIAL_GUARD_INTERCEPT");

                    let nostr = self.nostr_mesh.clone();
                    let sig_c = sig.clone();
                    tokio::spawn(async move {
                        let _ = nostr.broadcast_threat(sig_c).await;
                    });
                    if let Some(ref tx) = *self.mesh_command_tx.lock().await {
                        let _ = tx.try_send(osoosi_wire::MeshCommand::Broadcast(sig.clone()));
                    }

                    if !monitor_only {
                        info!(
                            "Siquery Credential Guard Active Protection: Terminating & blocking PID {}",
                            pid
                        );
                        let _ = self.remediation.kill_process_tree(pid);
                        let _ = self.blocking_manager.block_by_pid(pid).await;
                    }

                    anomalies.push(serde_json::json!({
                        "sweep": "processes_credentials",
                        "severity": "CRITICAL",
                        "pid": pid,
                        "name": name,
                        "details": reason,
                        "action": if monitor_only { "logged_monitored" } else { "terminated_and_blocked" }
                    }));
                }
            }
        }

        // --- Sweep 2: Service Persistence & Unsigned Path Audit ---
        let serv_count_res = engine.execute_query("SELECT COUNT(*) AS total FROM wmi_services;");
        let total_services = serv_count_res
            .ok()
            .and_then(|r| {
                r.first()
                    .and_then(|row| row.get("total").and_then(|v| v.as_i64()))
            })
            .unwrap_or(0);

        if let Ok(rogue_services) = engine.execute_query(
            "SELECT name, display_name, path_name, start_mode, state, process_id \
             FROM wmi_services \
             WHERE state = 'Running' AND ( \
                 path_name LIKE '%\\AppData\\Local\\Temp\\%' \
                 OR path_name LIKE '%\\Users\\Public\\%' \
                 OR path_name LIKE '%powershell%-enc%' \
                 OR path_name LIKE '%cmd.exe /c%' \
             ) LIMIT 10;",
        ) {
            for svc in rogue_services {
                let name = svc.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let path_name = svc.get("path_name").and_then(|v| v.as_str()).unwrap_or("");
                let clean_path = path_name
                    .trim_matches('"')
                    .split_whitespace()
                    .next()
                    .unwrap_or(path_name);
                let is_signed =
                    crate::win_trust::is_trusted_signed_binary(std::path::Path::new(clean_path));

                if !is_signed {
                    let reason = format!("Siquery EDR Sweep: Untrusted service binary running from suspicious location: {} ({})", name, path_name);
                    warn!("{}", reason);

                    let mut is_benign = false;
                    let mut human_escalation_required = false;
                    if self.decision_engine.is_enabled() {
                        let (safe_name, inj_n) =
                            osoosi_types::sanitize_untrusted_log_field(name, 128);
                        let (safe_path, inj_p) =
                            osoosi_types::sanitize_untrusted_log_field(path_name, 256);
                        let inj = inj_n || inj_p;
                        let incident = format!(
                            "Target: Service\nProcess: {}\nPath: {}\nState: Running\nSigned: false\nPromptInjectionDetected: {}",
                            safe_name, safe_path, inj
                        );
                        if let Ok(dec) = self
                            .decision_engine
                            .evaluate_security_incident(&incident)
                            .await
                        {
                            if dec.human_escalation_required {
                                human_escalation_required = true;
                            } else if !inj
                                && (dec.verdict == "benign" || dec.containment_action == "allow")
                            {
                                is_benign = true;
                            }
                        }
                    }

                    if !is_benign {
                        let _ = self.memory.log_threat_event(
                            "SIQUERY_SERVICE_PERSISTENCE_ANOMALY",
                            0,
                            0,
                        );
                        self.audit.log(
                            "SIQUERY_SERVICE_PERSISTENCE",
                            serde_json::json!({
                                "service": name,
                                "path": path_name,
                                "trusted_signature": false
                            }),
                        );

                        let mut sig =
                            osoosi_types::ThreatSignature::new(self.trust.did().to_string());
                        sig.process_name = Some(name.to_string());
                        sig.confidence = 0.90;
                        if human_escalation_required {
                            sig.recommended_action = osoosi_types::ResponseAction::Alert;
                            sig.action_state = osoosi_types::ActionState::Pending;
                            sig.require_approval = true;
                        } else {
                            sig.recommended_action = osoosi_types::ResponseAction::Isolate;
                        }
                        sig.reason = Some(reason.clone());
                        sig.mitre_tactic = Some("TA0003".to_string());
                        sig.mitre_technique = Some("T1543.003".to_string());
                        sig.mitre_technique_name =
                            Some("Create or Modify System Process: Windows Service".to_string());

                        let _ = self.memory.log_threat(&sig);
                        self.record_gossip_threat(&sig, "SIQUERY_SERVICE_PERSISTENCE");

                        if !monitor_only && !human_escalation_required {
                            let rule = osoosi_types::BlockingRule {
                                path: clean_path.to_string(),
                                kind: osoosi_types::BlockingKind::Executable,
                            };
                            let _ = self.blocking_manager.add_rule(rule).await;
                            let svc_pid =
                                svc.get("process_id").and_then(|v| v.as_i64()).unwrap_or(0) as u32;
                            if svc_pid > 4 {
                                let _ = self.blocking_manager.block_by_pid(svc_pid).await;
                            }
                        }

                        anomalies.push(serde_json::json!({
                            "sweep": "wmi_services",
                            "severity": "HIGH",
                            "name": name,
                            "path": path_name,
                            "details": reason,
                            "action": if monitor_only || human_escalation_required { "logged_monitored" } else { "binary_blocked" }
                        }));
                    }
                }
            }
        }

        // --- Sweep 3: Network Hijacking, MITM Proxy & Hosts Tampering ---
        if let Ok(tampered_hosts) = engine.execute_query(
            "SELECT address, hostnames FROM etc_hosts \
             WHERE address NOT IN ('127.0.0.1', '::1', '255.255.255.255', '0.0.0.0') \
               AND (hostnames LIKE '%microsoft.com%' OR hostnames LIKE '%windowsupdate.com%' OR hostnames LIKE '%github.com%' OR hostnames LIKE '%virustotal.com%') \
             LIMIT 5;"
        ) {
            for row in tampered_hosts {
                let addr = row.get("address").and_then(|v| v.as_str()).unwrap_or("");
                let hostnames = row.get("hostnames").and_then(|v| v.as_str()).unwrap_or("");
                let reason = format!("Siquery EDR Sweep: DNS hosts file redirection detected: {} -> {}", hostnames, addr);
                warn!("{}", reason);

                self.audit.log("SIQUERY_HOSTS_TAMPERING", serde_json::json!({
                    "address": addr,
                    "hostnames": hostnames
                }));
                let mut sig = osoosi_types::ThreatSignature::new(self.trust.did().to_string());
                sig.process_name = Some("etc_hosts".to_string());
                sig.confidence = 0.95;
                sig.recommended_action = osoosi_types::ResponseAction::Isolate;
                sig.reason = Some(reason.clone());
                sig.mitre_tactic = Some("TA0005".to_string());
                sig.mitre_technique = Some("T1565.001".to_string());
                sig.mitre_technique_name = Some("Data Manipulation: Stored Data Manipulation".to_string());
                let _ = self.memory.log_threat(&sig);
                self.record_gossip_threat(&sig, "SIQUERY_HOSTS_TAMPERING");

                anomalies.push(serde_json::json!({
                    "sweep": "etc_hosts",
                    "severity": "CRITICAL",
                    "address": addr,
                    "hostnames": hostnames,
                    "details": reason,
                    "action": "flagged_for_repair"
                }));
            }
        }

        if let Ok(proxies) =
            engine.execute_query("SELECT url, protocol, enabled FROM proxies WHERE enabled = '1';")
        {
            for px in proxies {
                let url = px.get("url").and_then(|v| v.as_str()).unwrap_or("");
                if !url.is_empty()
                    && (url.contains("127.0.0.1:8080")
                        || url.contains(":8888")
                        || url.contains(":9999"))
                {
                    let reason = format!("Siquery EDR Sweep: Suspicious active local intercepting proxy detected: {}", url);
                    warn!("{}", reason);
                    anomalies.push(serde_json::json!({
                        "sweep": "proxies",
                        "severity": "HIGH",
                        "url": url,
                        "details": reason,
                        "action": "alerted"
                    }));
                }
            }
        }

        // --- Sweep 4: Account & Lateral Movement Audit ---
        if let Ok(rogue_shares) = engine.execute_query(
            "SELECT name, path, description, type FROM wmi_shares \
             WHERE name NOT IN ('ADMIN$', 'C$', 'D$', 'E$', 'IPC$', 'print$') \
               AND (path LIKE '%\\Users\\%' OR path LIKE '%\\Windows\\System32%') \
             LIMIT 5;",
        ) {
            for row in rogue_shares {
                let name = row.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let path = row.get("path").and_then(|v| v.as_str()).unwrap_or("");
                let reason = format!("Siquery EDR Sweep: Sensitive system/user directory exposed over SMB share: {} ({})", name, path);
                warn!("{}", reason);
                anomalies.push(serde_json::json!({
                    "sweep": "wmi_shares",
                    "severity": "MEDIUM",
                    "share": name,
                    "path": path,
                    "details": reason,
                    "action": "alerted"
                }));
            }
        }

        if let Ok(rogue_users) = engine.execute_query(
            "SELECT username, description, is_admin FROM user_accounts \
             WHERE is_admin = 1 AND (username LIKE '%test%' OR username LIKE '%temp%' OR username LIKE '%backdoor%' OR username LIKE '%hacker%') \
             LIMIT 5;"
        ) {
            for u in rogue_users {
                let username = u.get("username").and_then(|v| v.as_str()).unwrap_or("");
                let reason = format!("Siquery EDR Sweep: Suspicious administrator account detected: {}", username);
                warn!("{}", reason);
                anomalies.push(serde_json::json!({
                    "sweep": "user_accounts",
                    "severity": "HIGH",
                    "username": username,
                    "details": reason,
                    "action": "alerted"
                }));
            }
        }

        // --- Sweep 5: Host Inventory & Hotfixes Telemetry ---
        let hotfix_count_res = engine.execute_query("SELECT COUNT(*) AS total FROM wmi_hotfixes;");
        let total_hotfixes = hotfix_count_res
            .ok()
            .and_then(|r| {
                r.first()
                    .and_then(|row| row.get("total").and_then(|v| v.as_i64()))
            })
            .unwrap_or(0);

        let drives_count_res =
            engine.execute_query("SELECT COUNT(*) AS total FROM logical_drives;");
        let total_drives = drives_count_res
            .ok()
            .and_then(|r| {
                r.first()
                    .and_then(|row| row.get("total").and_then(|v| v.as_i64()))
            })
            .unwrap_or(0);

        let os_ver_row = engine
            .execute_query("SELECT name, version, build, arch FROM os_version LIMIT 1;")
            .ok()
            .and_then(|mut r| {
                if !r.is_empty() {
                    Some(r.remove(0))
                } else {
                    None
                }
            });
        let sys_info_row = engine.execute_query("SELECT computer_name, cpu_brand, cpu_logical_cores, physical_memory FROM system_info LIMIT 1;").ok().and_then(|mut r| if !r.is_empty() { Some(r.remove(0)) } else { None });
        let uptime_row = engine
            .execute_query("SELECT days, hours, minutes, total_seconds FROM uptime LIMIT 1;")
            .ok()
            .and_then(|mut r| {
                if !r.is_empty() {
                    Some(r.remove(0))
                } else {
                    None
                }
            });
        let tpm_row = engine
            .execute_query(
                "SELECT spec_version, manufacturer_id, manufacturer_name, manufacturer_version, enabled, activated, owned, tpm_present, tpm_ready, device_id FROM tpm_info LIMIT 1;",
            )
            .ok()
            .and_then(|mut r| {
                if !r.is_empty() {
                    Some(r.remove(0))
                } else {
                    None
                }
            });

        // --- Sweep 6: Process Memory Map Module Check ---
        if let Ok(unbacked_mods) = engine.execute_query(
            "SELECT m.pid, p.name, m.path, m.permissions \
             FROM process_memory_map m JOIN processes p ON m.pid = p.pid \
             WHERE m.path LIKE '%\\Temp\\%' OR m.path LIKE '%\\Users\\Public\\%' \
             LIMIT 10;",
        ) {
            for row in unbacked_mods {
                let pid = row.get("pid").and_then(|v| v.as_i64()).unwrap_or(0) as u32;
                let proc_name = row.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let mod_path = row.get("path").and_then(|v| v.as_str()).unwrap_or("");
                let is_signed =
                    crate::win_trust::is_trusted_signed_binary(std::path::Path::new(mod_path));

                if !is_signed {
                    let reason = format!("Siquery EDR Sweep: Process PID {} ({}) loaded unsigned module from temp directory: {}", pid, proc_name, mod_path);
                    warn!("{}", reason);

                    let mut is_benign = false;
                    let mut human_escalation_required = false;
                    if self.decision_engine.is_enabled() {
                        let (safe_proc, inj_p) =
                            osoosi_types::sanitize_untrusted_log_field(proc_name, 128);
                        let (safe_mod, inj_m) =
                            osoosi_types::sanitize_untrusted_log_field(mod_path, 256);
                        let inj = inj_p || inj_m;
                        let incident = format!(
                            "Target: Module\nProcess: {}\nPID: {}\nUnsignedModule: {}\nPromptInjectionDetected: {}",
                            safe_proc, pid, safe_mod, inj
                        );
                        if let Ok(dec) = self
                            .decision_engine
                            .evaluate_security_incident(&incident)
                            .await
                        {
                            if dec.human_escalation_required {
                                human_escalation_required = true;
                            } else if !inj
                                && (dec.verdict == "benign" || dec.containment_action == "allow")
                            {
                                is_benign = true;
                            }
                        }
                    }

                    if !is_benign {
                        let mut sig =
                            osoosi_types::ThreatSignature::new(self.trust.did().to_string());
                        sig.process_name = Some(proc_name.to_string());
                        sig.confidence = 0.90;
                        if human_escalation_required {
                            sig.recommended_action = osoosi_types::ResponseAction::Alert;
                            sig.action_state = osoosi_types::ActionState::Pending;
                            sig.require_approval = true;
                        } else {
                            sig.recommended_action = osoosi_types::ResponseAction::Isolate;
                        }
                        sig.reason = Some(reason.clone());
                        sig.mitre_tactic = Some("TA0005".to_string());
                        sig.mitre_technique = Some("T1055.001".to_string());
                        sig.mitre_technique_name =
                            Some("Process Injection: Dynamic-link Library Injection".to_string());

                        let _ = self.memory.log_threat(&sig);
                        self.record_gossip_threat(&sig, "SIQUERY_MEMORY_MODULE_INJECTION");

                        if !monitor_only && !human_escalation_required && pid > 4 {
                            info!("Siquery Active Protection: Entangling PID {} due to unbacked DLL injection", pid);
                            self.entangle_process(pid, proc_name).await;
                        }

                        anomalies.push(serde_json::json!({
                            "sweep": "process_memory_map",
                            "severity": "HIGH",
                            "pid": pid,
                            "process": proc_name,
                            "module": mod_path,
                            "details": reason,
                            "action": if monitor_only { "logged_monitored" } else { "entangled" }
                        }));
                    }
                }
            }
        }

        // --- Sweep 7: DNS Cache & Resolver Poisoning / Fast-Flux Beaconing Audit ---
        let dns_count_res = engine.execute_query("SELECT COUNT(*) AS total FROM dns_cache;");
        let total_dns_cache = dns_count_res
            .ok()
            .and_then(|r| {
                r.first()
                    .and_then(|row| row.get("total").and_then(|v| v.as_i64()))
            })
            .unwrap_or(0);

        if let Ok(dns_entries) = engine.execute_query(
            "SELECT name, type, data, status FROM dns_cache \
             WHERE name LIKE '%.top' OR name LIKE '%.xyz' OR name LIKE '%.onion' \
                OR name LIKE '%.ngrok%' OR name LIKE '%.tunnel%' \
                OR data LIKE '%169.254.169.254%' \
             LIMIT 15;",
        ) {
            for entry in dns_entries {
                let name = entry.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let data = entry.get("data").and_then(|v| v.as_str()).unwrap_or("");
                let reason = format!("Siquery EDR Sweep: Suspicious DNS Cache resolution / potential C2 beaconing detected: {} -> {}", name, data);
                warn!("{}", reason);

                let mut is_benign = false;
                let mut human_escalation_required = false;
                if self.decision_engine.is_enabled() {
                    let (safe_name, inj_n) = osoosi_types::sanitize_untrusted_log_field(name, 128);
                    let (safe_data, inj_d) = osoosi_types::sanitize_untrusted_log_field(data, 256);
                    let inj = inj_n || inj_d;
                    let incident = format!(
                        "Target: DNS\nProcess: dns_cache\nDNS Query: {}\nResolved Data: {}\nTrigger: Fast-Flux / Cloud Metadata C2\nPromptInjectionDetected: {}",
                        safe_name, safe_data, inj
                    );
                    if let Ok(dec) = self
                        .decision_engine
                        .evaluate_security_incident(&incident)
                        .await
                    {
                        if dec.human_escalation_required {
                            human_escalation_required = true;
                        } else if !inj
                            && (dec.verdict == "benign" || dec.containment_action == "allow")
                        {
                            is_benign = true;
                        }
                    }
                }

                if !is_benign {
                    let _ = self
                        .memory
                        .log_threat_event("SIQUERY_DNS_BEACON_ANOMALY", 0, 0);
                    let mut sig = osoosi_types::ThreatSignature::new(self.trust.did().to_string());
                    sig.process_name = Some("dns_cache".to_string());
                    sig.confidence = 0.88;
                    if human_escalation_required {
                        sig.recommended_action = osoosi_types::ResponseAction::Alert;
                        sig.action_state = osoosi_types::ActionState::Pending;
                        sig.require_approval = true;
                    } else {
                        sig.recommended_action = osoosi_types::ResponseAction::Isolate;
                    }
                    sig.reason = Some(reason.clone());
                    sig.mitre_tactic = Some("TA0011".to_string());
                    sig.mitre_technique = Some("T1071.004".to_string());
                    sig.mitre_technique_name = Some("Application Layer Protocol: DNS".to_string());

                    let _ = self.memory.log_threat(&sig);
                    self.record_gossip_threat(&sig, "SIQUERY_DNS_ANOMALY");

                    if !monitor_only && !human_escalation_required {
                        let _ = crate::firewall::block_dns_destinations(Some(name), Some(data));
                    }

                    anomalies.push(serde_json::json!({
                        "sweep": "dns_cache",
                        "severity": "HIGH",
                        "domain": name,
                        "data": data,
                        "details": reason,
                        "action": if monitor_only { "logged_monitored" } else { "firewall_dns_blocked" }
                    }));
                }
            }
        }

        // --- Sweep 8: ARP Cache & Layer-2 MITM Poisoning Inspection ---
        let arp_count_res = engine.execute_query("SELECT COUNT(*) AS total FROM arp_cache;");
        let total_arp_cache = arp_count_res
            .ok()
            .and_then(|r| {
                r.first()
                    .and_then(|row| row.get("total").and_then(|v| v.as_i64()))
            })
            .unwrap_or(0);

        if let Ok(arp_entries) =
            engine.execute_query("SELECT ip, mac, interface, type FROM arp_cache;")
        {
            let mut mac_to_ips: std::collections::HashMap<String, Vec<String>> =
                std::collections::HashMap::new();
            for row in arp_entries {
                let ip = row
                    .get("ip")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let mac = row
                    .get("mac")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_lowercase();
                if !mac.is_empty()
                    && mac != "ff:ff:ff:ff:ff:ff"
                    && mac != "00:00:00:00:00:00"
                    && !ip.starts_with("224.")
                    && !ip.starts_with("239.")
                    && !ip.ends_with(".255")
                {
                    mac_to_ips.entry(mac).or_default().push(ip);
                }
            }
            for (mac, ips) in mac_to_ips {
                if ips.len() > 1 {
                    let reason = format!("Siquery EDR Sweep: ARP Poisoning / Layer-2 MITM detected! MAC {} claimed by multiple IPs: {:?}", mac, ips);
                    warn!("{}", reason);

                    let _ = self.memory.log_threat_event("SIQUERY_ARP_SPOOF_MITM", 0, 0);
                    let mut sig = osoosi_types::ThreatSignature::new(self.trust.did().to_string());
                    sig.process_name = Some("arp_cache".to_string());
                    sig.confidence = 0.95;
                    sig.recommended_action = osoosi_types::ResponseAction::Isolate;
                    sig.reason = Some(reason.clone());
                    sig.mitre_tactic = Some("TA0006".to_string());
                    sig.mitre_technique = Some("T1557.002".to_string());
                    sig.mitre_technique_name =
                        Some("Adversary-in-the-Middle: ARP Poisoning".to_string());

                    let _ = self.memory.log_threat(&sig);
                    self.record_gossip_threat(&sig, "SIQUERY_ARP_SPOOF_MITM");

                    anomalies.push(serde_json::json!({
                        "sweep": "arp_cache",
                        "severity": "CRITICAL",
                        "mac": mac,
                        "ips": ips,
                        "details": reason,
                        "action": "alerted_and_broadcast"
                    }));
                }
            }
        }

        // --- Sweep 9: Persistence Mechanisms: Autoruns & Scheduled Tasks Audit ---
        let autoruns_count_res = engine.execute_query("SELECT COUNT(*) AS total FROM autoruns;");
        let total_autoruns = autoruns_count_res
            .ok()
            .and_then(|r| {
                r.first()
                    .and_then(|row| row.get("total").and_then(|v| v.as_i64()))
            })
            .unwrap_or(0);

        let tasks_count_res =
            engine.execute_query("SELECT COUNT(*) AS total FROM scheduled_tasks;");
        let total_scheduled_tasks = tasks_count_res
            .ok()
            .and_then(|r| {
                r.first()
                    .and_then(|row| row.get("total").and_then(|v| v.as_i64()))
            })
            .unwrap_or(0);

        if let Ok(suspicious_autoruns) = engine.execute_query(
            "SELECT name, path, location, user FROM autoruns \
             WHERE path LIKE '%\\Temp\\%' OR path LIKE '%\\Users\\Public\\%' \
                OR path LIKE '%powershell%-enc%' OR path LIKE '%wscript%' OR path LIKE '%mshta%' \
             LIMIT 10;",
        ) {
            for row in suspicious_autoruns {
                let name = row.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let path = row.get("path").and_then(|v| v.as_str()).unwrap_or("");
                let location = row.get("location").and_then(|v| v.as_str()).unwrap_or("");
                let reason = format!(
                    "Siquery EDR Sweep: Suspicious persistence autorun entry found in {}: {} -> {}",
                    location, name, path
                );
                warn!("{}", reason);

                let clean_path = path
                    .trim_matches('"')
                    .split_whitespace()
                    .next()
                    .unwrap_or(path);
                let is_signed =
                    crate::win_trust::is_trusted_signed_binary(std::path::Path::new(clean_path));

                if !is_signed {
                    let (san_name, inj1) = osoosi_types::sanitize_untrusted_log_field(name, 128);
                    let (san_path, inj2) = osoosi_types::sanitize_untrusted_log_field(path, 256);
                    let (san_loc, inj3) = osoosi_types::sanitize_untrusted_log_field(location, 128);
                    let inj_flag = inj1 || inj2 || inj3;
                    let mut is_benign = false;
                    let mut human_escalation_required = false;
                    if self.decision_engine.is_enabled() {
                        let incident = format!(
                            "Target: Autorun\nAutorun: {}\nPath: {}\nLocation: {}\nSigned: false\nInjectionDetected: {}",
                            san_name, san_path, san_loc, inj_flag
                        );
                        if let Ok(dec) = self
                            .decision_engine
                            .evaluate_security_incident(&incident)
                            .await
                        {
                            if dec.human_escalation_required {
                                human_escalation_required = true;
                            } else if !inj_flag
                                && (dec.verdict == "benign" || dec.containment_action == "allow")
                            {
                                is_benign = true;
                            }
                        }
                    }

                    if !is_benign {
                        let _ = self
                            .memory
                            .log_threat_event("SIQUERY_AUTORUN_PERSISTENCE", 0, 0);
                        let mut sig =
                            osoosi_types::ThreatSignature::new(self.trust.did().to_string());
                        sig.process_name = Some(name.to_string());
                        sig.confidence = 0.92;
                        if human_escalation_required {
                            sig.recommended_action = osoosi_types::ResponseAction::Alert;
                            sig.action_state = osoosi_types::ActionState::Pending;
                            sig.require_approval = true;
                        } else {
                            sig.recommended_action = osoosi_types::ResponseAction::Isolate;
                        }
                        sig.reason = Some(reason.clone());
                        sig.mitre_tactic = Some("TA0003".to_string());
                        sig.mitre_technique = Some("T1547.001".to_string());
                        sig.mitre_technique_name = Some(
                            "Boot or Logon Autostart Execution: Registry Run Keys".to_string(),
                        );

                        let _ = self.memory.log_threat(&sig);
                        self.record_gossip_threat(&sig, "SIQUERY_AUTORUN_PERSISTENCE");

                        if !monitor_only && !human_escalation_required && !clean_path.is_empty() {
                            let _ = self
                                .blocking_manager
                                .add_rule(osoosi_types::BlockingRule {
                                    path: clean_path.to_string(),
                                    kind: osoosi_types::BlockingKind::Executable,
                                })
                                .await;
                        }

                        anomalies.push(serde_json::json!({
                            "sweep": "autoruns",
                            "severity": "HIGH",
                            "name": name,
                            "path": path,
                            "location": location,
                            "details": reason,
                            "action": if monitor_only || human_escalation_required { "logged_monitored" } else { "binary_blocked" }
                        }));
                    }
                }
            }
        }

        if let Ok(suspicious_tasks) = engine.execute_query(
            "SELECT name, action, state, run_as_user FROM scheduled_tasks \
             WHERE action LIKE '%\\Temp\\%' OR action LIKE '%\\Users\\Public\\%' \
                OR action LIKE '%powershell%' OR action LIKE '%cmd.exe /c%' \
             LIMIT 10;",
        ) {
            for row in suspicious_tasks {
                let name = row.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let action = row.get("action").and_then(|v| v.as_str()).unwrap_or("");
                let user = row
                    .get("run_as_user")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let reason = format!("Siquery EDR Sweep: Suspicious scheduled task detected: {} (RunAs: {}, Action: {})", name, user, action);
                warn!("{}", reason);

                anomalies.push(serde_json::json!({
                    "sweep": "scheduled_tasks",
                    "severity": "HIGH",
                    "name": name,
                    "action_target": action,
                    "run_as_user": user,
                    "details": reason,
                    "action": "alerted"
                }));
            }
        }

        // --- Sweep 10: Kernel Drivers & BYOVD (Bring Your Own Vulnerable Driver) Audit ---
        let drivers_count_res = engine.execute_query("SELECT COUNT(*) AS total FROM drivers;");
        let total_drivers = drivers_count_res
            .ok()
            .and_then(|r| {
                r.first()
                    .and_then(|row| row.get("total").and_then(|v| v.as_i64()))
            })
            .unwrap_or(0);

        if let Ok(suspicious_drivers) = engine.execute_query(
            "SELECT name, display_name, path, status, signed FROM drivers \
             WHERE (status = 'Running' OR status = 'loaded') AND ( \
                 path LIKE '%\\Temp\\%' \
                 OR path LIKE '%\\Users\\Public\\%' \
                 OR name LIKE '%mhyprot%' \
                 OR name LIKE '%gdrv%' \
                 OR name LIKE '%procexp%' \
                 OR name LIKE '%dbutil%' \
                 OR name LIKE '%kprocesshacker%' \
                 OR signed = 'false' \
             ) LIMIT 10;",
        ) {
            for drv in suspicious_drivers {
                let name = drv.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let path = drv.get("path").and_then(|v| v.as_str()).unwrap_or("");
                let clean_path = path
                    .trim_matches('"')
                    .split_whitespace()
                    .next()
                    .unwrap_or(path);
                let is_signed =
                    crate::win_trust::is_trusted_signed_binary(std::path::Path::new(clean_path));

                if !is_signed
                    || name.contains("mhyprot")
                    || name.contains("gdrv")
                    || name.contains("dbutil")
                {
                    let reason = format!("Siquery EDR Sweep: Potentially malicious or BYOVD vulnerable kernel driver detected: {} ({})", name, path);
                    warn!("{}", reason);

                    let (san_name, inj1) = osoosi_types::sanitize_untrusted_log_field(name, 128);
                    let (san_path, inj2) = osoosi_types::sanitize_untrusted_log_field(path, 256);
                    let inj_flag = inj1 || inj2;
                    let mut is_benign = false;
                    let mut human_escalation_required = false;
                    if self.decision_engine.is_enabled() {
                        let incident = format!(
                            "Target: Driver\nDriver: {}\nPath: {}\nBYOVD Risk: true\nSigned: {}\nInjectionDetected: {}",
                            san_name, san_path, is_signed, inj_flag
                        );
                        if let Ok(dec) = self
                            .decision_engine
                            .evaluate_security_incident(&incident)
                            .await
                        {
                            if dec.human_escalation_required {
                                human_escalation_required = true;
                            } else if !inj_flag
                                && (dec.verdict == "benign" || dec.containment_action == "allow")
                            {
                                is_benign = true;
                            }
                        }
                    }

                    if !is_benign {
                        let _ = self
                            .memory
                            .log_threat_event("SIQUERY_BYOVD_KERNEL_DRIVER", 0, 0);
                        let mut sig =
                            osoosi_types::ThreatSignature::new(self.trust.did().to_string());
                        sig.process_name = Some(name.to_string());
                        sig.confidence = 0.96;
                        if human_escalation_required {
                            sig.recommended_action = osoosi_types::ResponseAction::Alert;
                            sig.action_state = osoosi_types::ActionState::Pending;
                            sig.require_approval = true;
                        } else {
                            sig.recommended_action = osoosi_types::ResponseAction::Isolate;
                        }
                        sig.reason = Some(reason.clone());
                        sig.mitre_tactic = Some("TA0004".to_string());
                        sig.mitre_technique = Some("T1068".to_string());
                        sig.mitre_technique_name =
                            Some("Exploitation for Privilege Escalation: BYOVD".to_string());

                        let _ = self.memory.log_threat(&sig);
                        self.record_gossip_threat(&sig, "SIQUERY_BYOVD_KERNEL_DRIVER");

                        if !monitor_only && !human_escalation_required {
                            if let Some(ref kd) = *self.kernel_driver.read() {
                                let _ = kd.add_blocked_path(clean_path);
                            }
                        }

                        anomalies.push(serde_json::json!({
                            "sweep": "drivers",
                            "severity": "CRITICAL",
                            "driver": name,
                            "path": path,
                            "signed": is_signed,
                            "details": reason,
                            "action": if monitor_only || human_escalation_required { "logged_monitored" } else { "kernel_driver_blocked" }
                        }));
                    }
                }
            }
        }

        // --- Sweep 11: Host Defense Posture & Security Tampering Audit ---
        let fw_count_res = engine.execute_query("SELECT COUNT(*) AS total FROM firewall_rules;");
        let total_firewall_rules = fw_count_res
            .ok()
            .and_then(|r| {
                r.first()
                    .and_then(|row| row.get("total").and_then(|v| v.as_i64()))
            })
            .unwrap_or(0);

        if let Ok(rogue_fw) = engine.execute_query(
            "SELECT name, action, direction, protocol, program FROM firewall_rules \
             WHERE action = 'Allow' AND direction = 'Inbound' AND ( \
                 program LIKE '%\\Temp\\%' OR program LIKE '%\\Users\\Public\\%' \
             ) LIMIT 10;",
        ) {
            for row in rogue_fw {
                let name = row.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let prog = row.get("program").and_then(|v| v.as_str()).unwrap_or("");
                let reason = format!("Siquery EDR Sweep: Dangerous inbound firewall rule permitting unbacked binary: {} ({})", name, prog);
                warn!("{}", reason);

                anomalies.push(serde_json::json!({
                    "sweep": "firewall_rules",
                    "severity": "HIGH",
                    "rule": name,
                    "program": prog,
                    "details": reason,
                    "action": "flagged_tampering"
                }));
            }
        }

        if let Ok(defender_rows) = engine.execute_query("SELECT antivirus_enabled, real_time_protection, behavior_monitor, ioav_protection, uac_enabled FROM defender_status LIMIT 1;") {
            if let Some(d) = defender_rows.first() {
                let rtp = d.get("real_time_protection").and_then(|v| v.as_str()).unwrap_or("true");
                let bm = d.get("behavior_monitor").and_then(|v| v.as_str()).unwrap_or("true");
                if rtp == "false" || bm == "false" {
                    let reason = format!("Siquery EDR Sweep: Windows Defender tampering detected! RealTimeProtection: {}, BehaviorMonitor: {}", rtp, bm);
                    warn!("{}", reason);

                    let _ = self.memory.log_threat_event("SIQUERY_DEFENDER_TAMPERED", 0, 0);
                    let mut sig = osoosi_types::ThreatSignature::new(self.trust.did().to_string());
                    sig.process_name = Some("defender_status".to_string());
                    sig.confidence = 0.94;
                    sig.recommended_action = osoosi_types::ResponseAction::Isolate;
                    sig.reason = Some(reason.clone());
                    sig.mitre_tactic = Some("TA0005".to_string());
                    sig.mitre_technique = Some("T1562.001".to_string());
                    sig.mitre_technique_name = Some("Impair Defenses: Disable or Modify Tools".to_string());

                    let _ = self.memory.log_threat(&sig);
                    self.record_gossip_threat(&sig, "SIQUERY_DEFENDER_TAMPERED");

                    anomalies.push(serde_json::json!({
                        "sweep": "defender_status",
                        "severity": "CRITICAL",
                        "real_time_protection": rtp,
                        "behavior_monitor": bm,
                        "details": reason,
                        "action": "tampering_alerted"
                    }));
                }
            }
        }

        // --- Sweep 12: Execution Evidence, Shimcache & Certificate Anomalies ---
        if let Ok(shim_rows) = engine.execute_query(
            "SELECT path, last_modified, execution_flag FROM shimcache \
             WHERE path LIKE '%\\Temp\\%' OR path LIKE '%\\Users\\Public\\%' OR path LIKE '%\\Downloads\\%' \
             LIMIT 15;"
        ) {
            for row in shim_rows {
                let p = row.get("path").and_then(|v| v.as_str()).unwrap_or("");
                let is_signed = crate::win_trust::is_trusted_signed_binary(std::path::Path::new(p));
                if !is_signed && (p.ends_with(".exe") || p.ends_with(".dll")) {
                    let reason = format!("Siquery EDR Sweep: Unsigned binary execution trace identified in Shimcache: {}", p);
                    debug!("{}", reason);
                    anomalies.push(serde_json::json!({
                        "sweep": "shimcache",
                        "severity": "LOW",
                        "path": p,
                        "details": reason,
                        "action": "forensic_recorded"
                    }));
                }
            }
        }

        if let Ok(cert_rows) = engine.execute_query(
            "SELECT store, subject, issuer, valid_to, is_self_signed FROM certificates \
             WHERE store = 'ROOT' AND is_self_signed = 'true' \
               AND subject NOT LIKE '%Microsoft%' AND subject NOT LIKE '%DigiCert%' \
             LIMIT 10;",
        ) {
            for cert in cert_rows {
                let subj = cert.get("subject").and_then(|v| v.as_str()).unwrap_or("");
                let issuer = cert.get("issuer").and_then(|v| v.as_str()).unwrap_or("");
                let reason = format!("Siquery EDR Sweep: Untrusted self-signed root certificate in ROOT store (potential TLS MITM): Subject: {}, Issuer: {}", subj, issuer);
                warn!("{}", reason);

                let _ = self
                    .memory
                    .log_threat_event("SIQUERY_UNTRUSTED_ROOT_CERT", 0, 0);
                anomalies.push(serde_json::json!({
                    "sweep": "certificates",
                    "severity": "HIGH",
                    "subject": subj,
                    "issuer": issuer,
                    "details": reason,
                    "action": "flagged_mitm_cert"
                }));
            }
        }

        let elapsed_ms = start.elapsed().as_millis() as u64;

        let telemetry = serde_json::json!({
            "status": "ok",
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "execution_duration_ms": elapsed_ms,
            "mode": if monitor_only { "monitor" } else { "enforce" },
            "protection_posture": if monitor_only { "Audit · Multi-Table Monitored" } else { "Armed · Active Protection & Containment" },
            "sweeps_executed": 12,
            "tables_monitored": osoosi_agent_anomaly::SiqueryEngine::list_tables().len(),
            "metrics": {
                "processes_count": total_processes,
                "sockets_count": total_sockets,
                "services_count": total_services,
                "hotfixes_count": total_hotfixes,
                "scheduled_tasks_count": total_scheduled_tasks,
                "logical_drives_count": total_drives,
                "dns_cache_count": total_dns_cache,
                "arp_cache_count": total_arp_cache,
                "autoruns_count": total_autoruns,
                "drivers_count": total_drivers,
                "firewall_rules_count": total_firewall_rules,
            },
            "host": {
                "os": os_ver_row,
                "system": sys_info_row,
                "uptime": uptime_row,
                "tpm": tpm_row,
            },
            "anomalies_detected": anomalies.len(),
            "anomalies": anomalies,
        });

        *self.siquery_last_telemetry.write() = Some(telemetry.clone());
        telemetry
    }

}
