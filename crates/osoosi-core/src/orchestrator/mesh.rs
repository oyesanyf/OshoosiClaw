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
    /// Broadcast poisoned payload digest to peer mesh with Hybrid PQC (ML-DSA-65 + Ed25519) and DP perturbed timestamp.
    pub async fn broadcast_poisoned_digest_to_mesh(&self, digest: &str, session_id: &str) {
        let raw_ts = chrono::Utc::now().timestamp();
        let perturbed_ts = osoosi_dp::perturb_timestamp_csprng(raw_ts, 0.5);

        let mut sig = osoosi_types::ThreatSignature::new(self.trust.did().to_string());
        sig.id = format!("canary-poison-{}", &digest[..8.min(digest.len())]);
        sig.confidence = 1.0;
        sig.recommended_action = osoosi_types::ResponseAction::Isolate;
        sig.hash_blake3 = Some(digest.to_string());
        sig.reason = Some(format!(
            "Canary Breach Immunization: Poisoned payload digest {} attributed to breached session {}",
            digest, session_id
        ));
        sig.mitre_tactic = Some("TA0006".to_string());
        sig.mitre_technique = Some("T1552.001".to_string());
        sig.mitre_technique_name = Some("Credentials In Files: Ephemeral Canary Trap".to_string());
        sig.detected_at =
            chrono::DateTime::from_timestamp(perturbed_ts, 0).unwrap_or_else(chrono::Utc::now);

        // Sign with TrustManager Hybrid PQC
        let payload = format!("{}:{}:{}", sig.id, digest, perturbed_ts);
        let pqc_sig = self
            .trust
            .generate_pqc_hybrid_attestation_signature(payload.as_bytes());
        sig.signature = Some(pqc_sig);

        // Record locally and broadcast over mesh command channels
        let _ = self.memory.log_threat(&sig);
        self.record_gossip_threat(&sig, "CANARY_SWARM_IMMUNITY_BROADCAST");

        let nostr = self.nostr_mesh.clone();
        let sig_c = sig.clone();
        tokio::spawn(async move {
            let _ = nostr.broadcast_threat(sig_c).await;
        });
        if let Some(ref tx) = *self.mesh_command_tx.lock().await {
            let _ = tx.try_send(osoosi_wire::MeshCommand::Broadcast(sig));
        }
    }

    pub async fn start_p2p_loop(&self) -> anyhow::Result<Arc<osoosi_wire::JoinGate>> {
        let (tx, rx) = tokio::sync::mpsc::channel(100);

        // Save the command sender so the orchestrator can broadcast messages to the mesh
        {
            let mut mesh_tx = self.mesh_command_tx.lock().await;
            *mesh_tx = Some(tx.clone());
        }

        // Connect policy engine to mesh for automated intel sharing
        let mesh_tx_intel = tx.clone();
        if osoosi_types::resolve_nvd_api_key().is_some() {
            info!("Oshoosi Hybrid: NVD API Key detected. Enhanced rate limits enabled.");
        } else {
            info!("Oshoosi Hybrid: No NVD API Key configured. Mesh will rely on peer-to-peer intelligence to avoid public rate limits.");
        }

        self.policy
            .set_intel_broadcaster(Arc::new(move |intel| {
                let _ =
                    mesh_tx_intel.try_send(osoosi_wire::MeshCommand::BroadcastGlobalIntel(intel));
            }))
            .await;

        let mesh_config = osoosi_types::load_mesh_listen_config();
        let peer_rules = osoosi_types::load_peer_rules_config();
        let autonomy = osoosi_types::load_autonomy_config();

        let join_gate = Arc::new(osoosi_wire::JoinGate::new(
            self.memory.clone(),
            tx,
            autonomy.auto_approve_reputation_threshold,
            peer_rules.clone(),
            mesh_config.master_node_public_key.clone(),
        ));

        // Take the mesh node out of the mutex (it runs its own loop)
        let mesh_node_opt = {
            let mut mesh_guard = self.mesh.lock().await;
            mesh_guard.take()
        };

        if let Some(mesh_node) = mesh_node_opt {
            let orch = self.clone();
            let gate = join_gate.clone();
            let peer_count = self.mesh_peer_count.clone();

            let orch_sig = orch.clone();
            let orch_msg = orch.clone();
            let orch_intel = orch.clone();
            let orch_sample = orch.clone();
            let orch_tarpit = orch.clone();
            let orch_delta = orch.clone();
            let orch_tripwire = orch.clone();
            let orch_skill = orch.clone();
            let orch_shard = orch.clone();
            let gossip_counter = self.mesh_gossip_count_atomic.clone();
            let g1 = gossip_counter.clone();
            let g2 = gossip_counter.clone();
            let g3 = gossip_counter.clone();
            let g4 = gossip_counter.clone();
            let g5 = gossip_counter.clone();
            let g6 = gossip_counter.clone();
            let g7 = gossip_counter.clone();

            tokio::spawn(async move {
                mesh_node
                    .run_loop(
                        gate,
                        rx,
                        Some(peer_count),
                        peer_rules,
                        orch.adaptive(),
                        move |sig| {
                            let my_did = orch_sig.trust.did();
                            if sig.source_node == my_did.id || sig.source_node == my_did.to_string() || sig.source_node == "local" {
                                debug!("Mesh: Suppressed local echo threat from our own node DID ({})", sig.id);
                                return;
                            }
                            if !sig.verify() {
                                debug!("Mesh: Dropped unverified or invalidly signed threat signature {}", sig.id);
                                return;
                            }
                            if sig.confidence < 0.50 {
                                debug!("Mesh: Dropped low-confidence threat {} ({:.2}) from peer", sig.id, sig.confidence);
                                return;
                            }
                            if sig.reason.as_deref().unwrap_or("").contains("Execution Of Non-Existing File") {
                                debug!("Mesh: Dropped non-existing file noise threat {}", sig.id);
                                return;
                            }
                            let proc_clean = sig.process_name.as_deref().unwrap_or("").trim();
                            if proc_clean.is_empty()
                                || proc_clean.eq_ignore_ascii_case("unknown")
                                || proc_clean.eq_ignore_ascii_case("unknown process")
                            {
                                debug!("Mesh: Dropped unknown process threat {} from peer", sig.id);
                                return;
                            }

                            if !orch_sig.mesh_broadcast_debouncer.contains_key(&sig.id) {
                                orch_sig.mesh_broadcast_debouncer.insert(sig.id.clone(), std::time::Instant::now());
                            } else {
                                debug!("Mesh: Suppressed duplicate mesh threat ID {} from peer", sig.id);
                                return;
                            }
                            g1.fetch_add(1, Ordering::Relaxed);
                            info!(
                                "Mesh Intelligence: External threat reported from {}: {:?}",
                                sig.source_node, sig.reason
                            );

                            // Inspect mesh threat frame and verify peer kill-switch veto before marking hashes or persisting
                            let inbound_mesh_verdict = crate::rea::inspect_mesh_threat_frame(
                                "inbound",
                                Some(&sig.source_node),
                                sig.process_name.as_deref().unwrap_or(proc_clean),
                                sig.hash_blake3.as_deref(),
                                None,
                                sig.reason.as_deref(),
                            );
                            if inbound_mesh_verdict.vetoed || !inbound_mesh_verdict.allowed {
                                let veto_reason = inbound_mesh_verdict
                                    .veto_reason
                                    .unwrap_or_else(|| inbound_mesh_verdict.summary.clone());
                                warn!(
                                    "GossipSub [BYZANTINE_KILLSWITCH_VETOED]: Rejected peer threat {} from {}: {}",
                                    sig.id, sig.source_node, veto_reason
                                );
                                orch_sig.audit.log(
                                    "BYZANTINE_KILLSWITCH_VETOED",
                                    serde_json::json!({
                                        "source_node": sig.source_node,
                                        "threat_id": sig.id,
                                        "process_name": sig.process_name,
                                        "hash_blake3": sig.hash_blake3,
                                        "veto_reason": veto_reason,
                                        "rea_seal_blake3": inbound_mesh_verdict.rea_seal_blake3,
                                    }),
                                );
                                return;
                            }
                            if let Some(veto_reason) = crate::rea::veto_peer_kill_switch_candidate(
                                sig.process_name.as_deref().or(Some(proc_clean)),
                                sig.hash_blake3.as_deref(),
                                None,
                                sig.reason.as_deref(),
                            ) {
                                warn!(
                                    "GossipSub [BYZANTINE_KILLSWITCH_VETOED]: Rejected peer threat {} from {}: {}",
                                    sig.id, sig.source_node, veto_reason
                                );
                                orch_sig.audit.log(
                                    "BYZANTINE_KILLSWITCH_VETOED",
                                    serde_json::json!({
                                        "source_node": sig.source_node,
                                        "threat_id": sig.id,
                                        "process_name": sig.process_name,
                                        "hash_blake3": sig.hash_blake3,
                                        "veto_reason": veto_reason,
                                    }),
                                );
                                return;
                            }

                            // Persist mesh threat so it shows in the dashboard
                            if let Err(e) = orch_sig.memory.log_threat(&sig) {
                                if e.to_string().contains("UNIQUE constraint") {
                                    debug!("Mesh threat {} already persisted: {}", sig.id, e);
                                } else {
                                    error!("Failed to persist mesh threat: {}", e);
                                }
                            }
                            // Mark malicious hashes in Bloom filter for fast-path blocking
                            if let Some(ref hash) = sig.hash_blake3 {
                                orch_sig.memory.mark_hash_known_malicious(hash);
                            }
                            // Store in live gossip feed buffer
                            orch_sig.record_gossip_threat(&sig, "MESH_THREAT_RECEIVED");

                            let proc = proc_clean.to_string();
                            let tech = sig.mitre_technique.clone().unwrap_or_else(|| "T1082".to_string());
                            let action = format!("{:?}", sig.recommended_action);
                            let reason_str = sig.reason.as_deref().unwrap_or("").trim();
                            let reason_clean = reason_str.split(';').next().unwrap_or(reason_str).trim();
                            let issue_desc = if reason_clean.is_empty() { "Suspicious Activity" } else { reason_clean };
                            let summary = format!("Peer Threat [{}]: {}: {} ({}) via {}", tech, proc, issue_desc, action, sig.source_node);

                            orch_sig.audit.log(
                                "MESH_THREAT_RECEIVED",
                                serde_json::json!({
                                    "source_node": sig.source_node,
                                    "threat_id": sig.id,
                                    "confidence": sig.confidence,
                                    "process_name": sig.process_name,
                                    "mitre_technique": sig.mitre_technique,
                                    "mitre_technique_name": sig.mitre_technique_name,
                                    "mitre_tactic": sig.mitre_tactic,
                                    "reason": sig.reason,
                                    "action": action,
                                    "action_state": sig.action_state,
                                    "hash": sig.hash_blake3,
                                    "summary": summary,
                                }),
                            );
                        },
                        move |msg| {
                            g2.fetch_add(1, Ordering::Relaxed);
                            // Handle policy consensus messages
                            if let osoosi_types::PolicyConsensusMessage::Vote(ref vote) = msg {
                                let orch_clone = orch_msg.clone();
                                let msg_clone = msg.clone();
                                let voter_id = vote.voter_id.clone();
                                // DashMap: lock-free insert — no async lock needed
                                orch_clone.policy_consensus
                                    .entry(voter_id.clone())
                                    .or_default()
                                    .push(msg_clone);

                                orch_clone.record_gossip_item(osoosi_types::GossipFeedItem {
                                    id: uuid::Uuid::new_v4().to_string(),
                                    event_type: "INTEL_BFT_CONSENSUS".to_string(),
                                    timestamp: chrono::Utc::now().to_rfc3339(),
                                    summary: format!("Policy Consensus vote: Voter {} -> {:?}", vote.voter_id, vote.status),
                                    source_node: vote.voter_id.clone(),
                                    process_name: None,
                                    mitre_technique: None,
                                    mitre_technique_name: None,
                                    mitre_tactic: None,
                                    confidence: 1.0,
                                    severity: "INFO".to_string(),
                                    action: Some("Consensus".to_string()),
                                    status: "ACTIVE".to_string(),
                                    hash_blake3: None,
                                    is_threat: false,
                                });
                            }
                        },
                        move |shard| {
                            g3.fetch_add(1, Ordering::Relaxed);
                            orch_shard.holograph.add_shard(shard.clone());
                            if orch_shard.holograph.should_mirror(&shard.attacker_ip, shard.virtual_port).is_some() {
                                let ghost_mgr = orch_shard.ghost_nodes.clone();
                                let port = shard.virtual_port;
                                tokio::spawn(async move {
                                    ghost_mgr.spawn_ghost_service(port, "Holograph-Mirror").await;
                                });
                            }
                        },
                        move |intel| {
                            g4.fetch_add(1, Ordering::Relaxed);
                            // Global Intel: Persist peer threat intelligence and mark hashes
                            info!(
                                "Mesh Intel: Received global intelligence from {} — {}",
                                intel.source_node, intel.summary
                            );
                            orch_intel.record_gossip_item(osoosi_types::GossipFeedItem {
                                id: uuid::Uuid::new_v4().to_string(),
                                event_type: "MESH_INTEL_RECEIVED".to_string(),
                                timestamp: intel.timestamp.to_rfc3339(),
                                summary: format!("Global Intel from {}: {}", intel.source_node, intel.summary),
                                source_node: intel.source_node.clone(),
                                process_name: None,
                                mitre_technique: None,
                                mitre_technique_name: None,
                                mitre_tactic: None,
                                confidence: intel.priority,
                                severity: if intel.priority >= 0.8 { "CRITICAL".to_string() } else { "INFO".to_string() },
                                action: Some("Intel".to_string()),
                                status: "ACTIVE".to_string(),
                                hash_blake3: None,
                                is_threat: false,
                            });
                            orch_intel.audit.log(
                                "MESH_INTEL_RECEIVED",
                                serde_json::json!({
                                    "source_node": intel.source_node,
                                    "source_url": intel.source_url,
                                    "summary": intel.summary,
                                }),
                            );
                            // If the intel carries a zero-day defense, log it for the repair engine and cache it
                            if let Some(ref defense) = intel.defense {
                                warn!(
                                    "Mesh Intel: Zero-day defense received for {} (severity: {:.2})",
                                    defense.cve_id, defense.severity
                                );
                                if !defense.software_target.is_empty() {
                                    // Cache the shared CVE for product-based lookups
                                    let version = defense.software_version.as_deref().unwrap_or("any");
                                    let _ = orch_intel.memory.insert_cve_cache(&defense.software_target, version, &defense.cve_id, &defense.description);
                                    info!("Mesh Intel: Cached shared CVE {} for product {} v{}", defense.cve_id, defense.software_target, version);
                                }
                            }
                        },
                        move |sample| {
                            g5.fetch_add(1, Ordering::Relaxed);
                            // Malware Sample: Feed into federated threat model for distributed learning
                            info!(
                                "Mesh Sample: Received malware sample from {} (hash: {}, label: {})",
                                sample.source_node, sample.file_hash, sample.label
                            );
                            // Mark the hash as known-malicious in Bloom filter for fast-path detection
                            if sample.label == 0 {
                                orch_sample.memory.mark_hash_known_malicious(&sample.file_hash);
                            }
                            let hshort = &sample.file_hash[..sample.file_hash.len().min(8)];
                            orch_sample.record_gossip_item(osoosi_types::GossipFeedItem {
                                id: uuid::Uuid::new_v4().to_string(),
                                event_type: "MESH_SAMPLE_RECEIVED".to_string(),
                                timestamp: sample.timestamp.to_rfc3339(),
                                summary: format!("Malware Sample from {}: {} (label: {})", sample.source_node, hshort, sample.label),
                                source_node: sample.source_node.clone(),
                                process_name: None,
                                mitre_technique: None,
                                mitre_technique_name: None,
                                mitre_tactic: None,
                                confidence: 0.9,
                                severity: if sample.label == 0 { "HIGH".to_string() } else { "INFO".to_string() },
                                action: Some("MalwareSample".to_string()),
                                status: "ACTIVE".to_string(),
                                hash_blake3: Some(sample.file_hash.clone()),
                                is_threat: sample.label == 0,
                            });
                            orch_sample.audit.log(
                                "MESH_SAMPLE_RECEIVED",
                                serde_json::json!({
                                    "source_node": sample.source_node,
                                    "file_hash": sample.file_hash,
                                    "label": sample.label,
                                    "feature_version": sample.feature_version,
                                }),
                            );
                        },
                        move |tarpit_signal| {
                            g6.fetch_add(1, Ordering::Relaxed);
                            orch_tarpit.record_gossip_item(osoosi_types::GossipFeedItem {
                                id: uuid::Uuid::new_v4().to_string(),
                                event_type: "MESH_TARPIT_APPLIED".to_string(),
                                timestamp: chrono::Utc::now().to_rfc3339(),
                                summary: format!("Mesh Tarpit: IP {} ({})", tarpit_signal.target_ip, tarpit_signal.attack_type),
                                source_node: "mesh".to_string(),
                                process_name: None,
                                mitre_technique: None,
                                mitre_technique_name: None,
                                mitre_tactic: None,
                                confidence: tarpit_signal.confidence,
                                severity: "HIGH".to_string(),
                                action: Some("Tarpit".to_string()),
                                status: "ACTIVE".to_string(),
                                hash_blake3: None,
                                is_threat: true,
                            });
                            // Tarpit Signal: Apply collaborative attacker IP block when peers warn
                            if tarpit_signal.confidence >= 0.5 {
                                warn!(
                                    "Mesh Tarpit: Peer warns about attacker IP {} (confidence: {:.2}, type: {}). Applying local firewall block.",
                                    tarpit_signal.target_ip, tarpit_signal.confidence, tarpit_signal.attack_type
                                );

                                // Block attacker IP at the firewall level (netsh on Windows, iptables on Linux)
                                #[cfg(target_os = "windows")]
                                {
                                    #[allow(unused_imports)]
                                    use std::os::windows::process::CommandExt;
                                    let rule_name = format!("Osoosi-MeshTarpit-{}", tarpit_signal.target_ip.replace(['.', ':'], "-"));
                                    let netsh_bin = osoosi_types::resolve_system_binary("netsh.exe");
                                    let mut cmd1 = std::process::Command::new(&netsh_bin);
                                    cmd1.stdout(std::process::Stdio::null())
                                        .stderr(std::process::Stdio::null());
                                    #[cfg(windows)]
                                    cmd1.creation_flags(0x08000000);
                                    let _ = cmd1
                                        .args([
                                            "advfirewall", "firewall", "add", "rule",
                                            &format!("name={}", rule_name),
                                            "dir=in", "action=block",
                                            &format!("remoteip={}", tarpit_signal.target_ip),
                                            "profile=any",
                                        ])
                                        .status();

                                    let mut cmd2 = std::process::Command::new(&netsh_bin);
                                    cmd2.stdout(std::process::Stdio::null())
                                        .stderr(std::process::Stdio::null());
                                    #[cfg(windows)]
                                    cmd2.creation_flags(0x08000000);
                                    let _ = cmd2
                                        .args([
                                            "advfirewall", "firewall", "add", "rule",
                                            &format!("name={}-out", rule_name),
                                            "dir=out", "action=block",
                                            &format!("remoteip={}", tarpit_signal.target_ip),
                                            "profile=any",
                                        ])
                                        .status();
                                    info!("Mesh Tarpit: Firewall rules applied for attacker IP {}", tarpit_signal.target_ip);
                                }

                                #[cfg(target_os = "linux")]
                                {
                                    let _ = std::process::Command::new("iptables")
                                        .args(["-A", "INPUT", "-s", &tarpit_signal.target_ip, "-j", "DROP"])
                                        .status();
                                    let _ = std::process::Command::new("iptables")
                                        .args(["-A", "OUTPUT", "-d", &tarpit_signal.target_ip, "-j", "DROP"])
                                        .status();
                                    info!("Mesh Tarpit: iptables rules applied for attacker IP {}", tarpit_signal.target_ip);
                                }

                                orch_tarpit.audit.log(
                                    "MESH_TARPIT_APPLIED",
                                    serde_json::json!({
                                        "target_ip": tarpit_signal.target_ip,
                                        "confidence": tarpit_signal.confidence,
                                        "attack_type": tarpit_signal.attack_type,
                                    }),
                                );
                            } else {
                                info!(
                                    "Mesh Tarpit: Low-confidence signal for {} ({:.2}) — logged but not applied.",
                                    tarpit_signal.target_ip, tarpit_signal.confidence
                                );
                            }
                        },
                        |_confidential| {}, // Confidential messages — reserved for future FHE-encrypted comms
                        move |delta| {
                            let orch_clone = orch_delta.clone();
                            tokio::spawn(async move {
                                let mut model = orch_clone.threat_model.write().await;
                                model.merge_delta(&delta);
                            });
                        },
                        move |alert| {
                            let orch_clone = orch_tripwire.clone();
                            tokio::spawn(async move {
                                warn!("Mesh Tripwire: Peer {} triggered a phantom memory trap! Offender: {} ({})", alert.source_node_id, alert.offender.name, alert.offender.blake3_hash);
                                // Mark the hash as malicious so we don't execute it
                                orch_clone.memory.mark_hash_known_malicious(&alert.offender.blake3_hash);

                                orch_clone.audit.log(
                                    "MESH_TRIPWIRE_RECEIVED",
                                    serde_json::json!({
                                        "source_node": alert.source_node_id,
                                        "offender": alert.offender.name,
                                        "hash": alert.offender.blake3_hash,
                                    }),
                                );
                            });
                        },
                        move |knowledge| {
                            g7.fetch_add(1, Ordering::Relaxed);
                            orch_skill.handle_incoming_skill_knowledge(knowledge);
                        },
                    )
                    .await;
            });

            // Start periodic peer announce heartbeat
            let orch_announce = self.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
                    let ann = osoosi_types::PeerAnnounce {
                        source_node: orch_announce.trust.did().to_string(),
                        timestamp: chrono::Utc::now(),
                        is_patched: true, // Placeholder: should check patch engine
                        os_name: "Windows".to_string(),
                        os_version: "10/11".to_string(),
                        os_supported: true,
                        membership_proof: None, // Should be signed by master node if configured
                        attestation: None,
                    };
                    let tx_guard = orch_announce.mesh_command_tx.lock().await;
                    if let Some(ref tx) = *tx_guard {
                        let _ = tx
                            .send(osoosi_wire::MeshCommand::PublishPeerAnnounce(ann))
                            .await;
                    }
                }
            });

            info!("P2P Mesh Network is active (Node: {}).", self.trust.did());
        }

        // --- 2. NOSTR MESH LISTENING (BitChat style) ---
        // Provides a robust, firewall-bypassing secondary intelligence layer.
        let orch_nostr = self.clone();
        self.nostr_mesh
            .start_listening(move |sig| {
                let my_did = orch_nostr.trust.did();
                if sig.source_node == my_did.id
                    || sig.source_node == my_did.to_string()
                    || sig.source_node == "local"
                {
                    debug!(
                        "Nostr: Suppressed local echo threat from our own node DID ({})",
                        sig.id
                    );
                    return;
                }
                if !sig.verify() {
                    debug!(
                        "Nostr: Dropped unverified or invalidly signed threat signature {}",
                        sig.id
                    );
                    return;
                }
                if sig.confidence < 0.50 {
                    debug!(
                        "Nostr: Dropped low-confidence threat {} ({:.2}) from relay",
                        sig.id, sig.confidence
                    );
                    return;
                }
                if sig
                    .reason
                    .as_deref()
                    .unwrap_or("")
                    .contains("Execution Of Non-Existing File")
                {
                    debug!("Nostr: Dropped non-existing file noise threat {}", sig.id);
                    return;
                }
                let proc_clean = sig.process_name.as_deref().unwrap_or("").trim();
                if proc_clean.is_empty()
                    || proc_clean.eq_ignore_ascii_case("unknown")
                    || proc_clean.eq_ignore_ascii_case("unknown process")
                {
                    debug!(
                        "Nostr: Dropped unknown process threat {} from relay",
                        sig.id
                    );
                    return;
                }
                let proc_name_owned = proc_clean.to_string();

                if !orch_nostr.mesh_broadcast_debouncer.contains_key(&sig.id) {
                    orch_nostr
                        .mesh_broadcast_debouncer
                        .insert(sig.id.clone(), std::time::Instant::now());
                } else {
                    debug!(
                        "Nostr: Suppressed duplicate mesh threat ID {} from relay/peer",
                        sig.id
                    );
                    return;
                }
                let orch = orch_nostr.clone();
                tokio::spawn(async move {
                    info!(
                        "BitChat: Decentralized threat received via Nostr relay: {:?} ({})",
                        sig.reason, sig.source_node
                    );

                    // Inspect mesh threat frame and verify peer kill-switch veto before marking hashes or persisting
                    let inbound_mesh_verdict = crate::rea::inspect_mesh_threat_frame(
                        "inbound",
                        Some(&sig.source_node),
                        sig.process_name.as_deref().unwrap_or(&proc_name_owned),
                        sig.hash_blake3.as_deref(),
                        None,
                        sig.reason.as_deref(),
                    );
                    if inbound_mesh_verdict.vetoed || !inbound_mesh_verdict.allowed {
                        let veto_reason = inbound_mesh_verdict
                            .veto_reason
                            .unwrap_or_else(|| inbound_mesh_verdict.summary.clone());
                        warn!(
                            "Nostr [BYZANTINE_KILLSWITCH_VETOED]: Rejected peer threat {} from {}: {}",
                            sig.id, sig.source_node, veto_reason
                        );
                        orch.audit.log(
                            "BYZANTINE_KILLSWITCH_VETOED",
                            serde_json::json!({
                                "source_node": sig.source_node,
                                "threat_id": sig.id,
                                "process_name": sig.process_name,
                                "hash_blake3": sig.hash_blake3,
                                "veto_reason": veto_reason,
                                "rea_seal_blake3": inbound_mesh_verdict.rea_seal_blake3,
                            }),
                        );
                        return;
                    }
                    if let Some(veto_reason) = crate::rea::veto_peer_kill_switch_candidate(
                        sig.process_name.as_deref().or(Some(&proc_name_owned)),
                        sig.hash_blake3.as_deref(),
                        None,
                        sig.reason.as_deref(),
                    ) {
                        warn!(
                            "Nostr [BYZANTINE_KILLSWITCH_VETOED]: Rejected peer threat {} from {}: {}",
                            sig.id, sig.source_node, veto_reason
                        );
                        orch.audit.log(
                            "BYZANTINE_KILLSWITCH_VETOED",
                            serde_json::json!({
                                "source_node": sig.source_node,
                                "threat_id": sig.id,
                                "process_name": sig.process_name,
                                "hash_blake3": sig.hash_blake3,
                                "veto_reason": veto_reason,
                            }),
                        );
                        return;
                    }

                    let _ = orch.memory.upsert_peer_status(&osoosi_types::PeerAnnounce {
                        source_node: sig.source_node.clone(),
                        timestamp: chrono::Utc::now(),
                        is_patched: true,
                        os_name: "Windows".to_string(),
                        os_version: "10/11 (Nostr WAN)".to_string(),
                        os_supported: true,
                        membership_proof: None,
                        attestation: None,
                    });
                    orch.mesh_gossip_count_atomic
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if let Err(e) = orch.memory.log_threat(&sig) {
                        if e.to_string().contains("UNIQUE constraint") {
                            debug!("Nostr threat {} already persisted: {}", sig.id, e);
                        } else {
                            error!("Failed to persist Nostr threat: {}", e);
                        }
                    }
                    if let Some(ref hash) = sig.hash_blake3 {
                        orch.memory.mark_hash_known_malicious(hash);
                    }
                    // Store in live gossip feed buffer
                    orch.record_gossip_threat(&sig, "MESH_THREAT_RECEIVED");

                    let proc = proc_name_owned;
                    let tech = sig
                        .mitre_technique
                        .clone()
                        .unwrap_or_else(|| "T1082".to_string());
                    let action = format!("{:?}", sig.recommended_action);
                    let reason_str = sig.reason.as_deref().unwrap_or("").trim();
                    let reason_clean = reason_str.split(';').next().unwrap_or(reason_str).trim();
                    let issue_desc = if reason_clean.is_empty() {
                        "Suspicious Activity"
                    } else {
                        reason_clean
                    };
                    let summary = format!(
                        "Peer Threat [{}]: {}: {} ({}) via Nostr",
                        tech, proc, issue_desc, action
                    );

                    orch.audit.log(
                        "MESH_THREAT_RECEIVED",
                        serde_json::json!({
                            "source_node": sig.source_node,
                            "threat_id": sig.id,
                            "confidence": sig.confidence,
                            "process_name": sig.process_name,
                            "mitre_technique": sig.mitre_technique,
                            "mitre_technique_name": sig.mitre_technique_name,
                            "mitre_tactic": sig.mitre_tactic,
                            "reason": sig.reason,
                            "action": action,
                            "action_state": sig.action_state,
                            "hash": sig.hash_blake3,
                            "summary": summary,
                        }),
                    );
                });
            })
            .await;

        Ok(join_gate)
    }

    /// Broadcast a tarpit signal to the mesh for a suspected attacker IP.
    pub async fn broadcast_tarpit_signal(
        &self,
        target_ip: String,
        confidence: f32,
        attack_type: String,
    ) -> anyhow::Result<()> {
        let signal = osoosi_wire::TarpitSignal {
            target_ip,
            confidence,
            attack_type,
        };
        if let Some(ref tx) = *self.mesh_command_tx.lock().await {
            let _ = tx
                .send(osoosi_wire::MeshCommand::BroadcastTarpit(signal))
                .await;
        }
        Ok(())
    }

    /// Current mesh peer count (approved peers). Returns 0 when P2P mesh is disabled.
    pub fn mesh_peer_count(&self) -> u32 {
        if !osoosi_types::is_p2p_mesh_enabled() {
            return 0;
        }
        self.mesh_peer_count.load(Ordering::Relaxed)
    }

    pub fn mesh_gossip_count(&self) -> u32 {
        self.mesh_gossip_count_atomic.load(Ordering::Relaxed)
    }

    /// Actively dial a bootstrap or remote mesh peer multiaddr.
    pub async fn dial_mesh_peer(&self, addr: &str) {
        if !osoosi_types::is_p2p_mesh_enabled() {
            debug!(
                "[Mesh] P2P mesh disabled by user; skipping dial to {}",
                addr
            );
            return;
        }
        let tx_guard = self.mesh_command_tx.lock().await;
        if let Some(ref tx) = *tx_guard {
            let _ = tx
                .send(osoosi_wire::MeshCommand::DialMultiaddr(addr.to_string()))
                .await;
        }
    }

    /// Broadcast a detected threat to the P2P wire mesh and Nostr with debouncing and cryptographic signing.
    pub async fn broadcast_threat_to_mesh(&self, mut sig: osoosi_types::ThreatSignature) {
        if !osoosi_types::is_p2p_mesh_enabled() {
            debug!("[Mesh] P2P mesh disabled by user; skipping outbound threat broadcast");
            return;
        }
        let reason_str = sig.reason.as_deref().unwrap_or("");
        let mesh_verdict = crate::rea::global_rea_engine().inspect_and_vet_mesh_frame(
            "outbound",
            Some(&sig.source_node),
            sig.process_name.as_deref().unwrap_or(reason_str),
            sig.hash_blake3.as_deref(),
            None,
            sig.reason.as_deref(),
        );
        if mesh_verdict.vetoed || !mesh_verdict.allowed {
            debug!(
                "[Mesh] Threat suppressed from outbound gossip broadcast by REA/OpenJEV: {}",
                mesh_verdict.summary
            );
            return;
        }
        if reason_str.contains("Veto Trusted Vendor")
            || reason_str.contains("outside the vulnerable")
            || reason_str.contains("CVE None")
            || reason_str.contains("unknown v0.0.0 has known cves")
            || reason_str.contains("cve-2009-2940")
        {
            debug!(
                "[Mesh] Threat suppressed from gossip broadcast (vetoed or non-vulnerable version)"
            );
            return;
        }
        if let Some(ref proc) = sig.process_name {
            if crate::rea::is_rea_benign_system_or_dev_process(proc, sig.reason.as_deref())
                || crate::rea::global_rea_engine()
                    .adjudicate_process_or_binary_alert(Some(proc), None, sig.reason.as_deref())
                    .0
            {
                debug!(
                    "[Mesh] Threat suppressed from gossip broadcast (REA benign system/dev: {})",
                    proc
                );
                return;
            }
            let proc_base = std::path::Path::new(proc)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(proc)
                .to_ascii_lowercase();
            if self.rea_adjudicated_clean_procs.contains(&proc_base)
                || self
                    .memory
                    .is_false_positive_pattern(Some(proc.as_str()), sig.hash_blake3.as_deref())
                    .unwrap_or(false)
                || sig
                    .hash_blake3
                    .as_deref()
                    .map(|h| self.memory.is_hash_clean_ignored(h))
                    .unwrap_or(false)
            {
                debug!(
                    "[Mesh] Threat suppressed from gossip broadcast (clean/FP pattern: {})",
                    proc
                );
                return;
            }
        }

        // 1. Signal-to-noise ratio & Zero-Unknown Invariant:
        if sig.confidence < 0.50 {
            debug!(
                "[Mesh] Threat suppressed from gossip broadcast (confidence < 0.50): {:.2}",
                sig.confidence
            );
            return;
        }
        if sig
            .reason
            .as_deref()
            .unwrap_or("")
            .contains("Execution Of Non-Existing File")
        {
            debug!(
                "[Mesh] Threat suppressed from gossip broadcast (Execution Of Non-Existing File)"
            );
            return;
        }
        let proc_clean = sig.process_name.as_deref().unwrap_or("").trim().to_string();
        let is_unknown_proc = proc_clean.is_empty()
            || proc_clean.eq_ignore_ascii_case("unknown")
            || proc_clean.eq_ignore_ascii_case("unknown process")
            || proc_clean.eq_ignore_ascii_case("system process");
        if is_unknown_proc && sig.reason.as_deref().unwrap_or("").trim().is_empty() {
            debug!("[Mesh] Threat suppressed from gossip broadcast (unknown process with empty reason)");
            return;
        }

        // 2. Debouncing per process hash / threat category / MITRE technique / reason
        let reason_key = sig.reason.as_deref().unwrap_or("generic");
        let debounce_key = format!(
            "{}:{}:{}:{}",
            sig.hash_blake3.as_deref().unwrap_or(&sig.id),
            sig.process_name.as_deref().unwrap_or("proc"),
            sig.mitre_technique.as_deref().unwrap_or("tech"),
            &reason_key[..reason_key.len().min(64)]
        );
        let cooldown = std::time::Duration::from_secs(2);
        if let Some(last) = self.mesh_broadcast_debouncer.get(&debounce_key) {
            if last.elapsed() < cooldown {
                debug!(
                    "[Mesh] Threat broadcast debounced (within 2s cooldown): {}",
                    debounce_key
                );
                return;
            }
        }
        self.mesh_broadcast_debouncer
            .insert(debounce_key, Instant::now());

        // 3. Anonymizer & Differential Privacy (preserve exact confidence without noise distortion)
        if let Some(reason) = sig.reason.as_mut() {
            *reason = self.anonymize_reason(reason);
        }
        sig.confidence = sig.confidence.clamp(0.05, 1.0);

        // 4. Ensure origin node ID is set to this node's DID
        sig.source_node = self.trust.did().id.clone();

        // 5. Cryptographic signature with ed25519 signing key
        if let Err(e) = self.trust.sign_threat(&mut sig) {
            error!(
                "[Mesh] Failed to cryptographically sign ThreatSignature: {}",
                e
            );
            return;
        }

        info!(
            "[Mesh] Broadcasting cryptographically signed threat to mesh: ID={} Proc={:?} MITRE={:?} Conf={:.2}",
            sig.id, sig.process_name, sig.mitre_technique, sig.confidence
        );

        // 6. Broadcast over Wire Mesh (GossipSub topic "osoosi-threats-{zone}")
        let tx_guard = self.mesh_command_tx.lock().await;
        if let Some(ref tx) = *tx_guard {
            let _ = tx
                .send(osoosi_wire::MeshCommand::Broadcast(sig.clone()))
                .await;
            let proof = self.audit.root();
            let _ = tx.try_send(osoosi_wire::MeshCommand::BroadcastAuditProof(proof));
        }

        // 7. Broadcast over Nostr (BitChat style)
        let nostr = self.nostr_mesh.clone();
        let sig_nostr = sig.clone();
        tokio::spawn(async move {
            if let Err(e) = nostr.broadcast_threat(sig_nostr).await {
                debug!("Failed to broadcast threat via Nostr relay: {}", e);
            }
        });

        // 8. Record in local live gossip buffer and audit trail
        self.record_gossip_threat(&sig, "MESH_THREAT_BROADCAST");

        let proc = proc_clean;
        let tech = sig.mitre_technique.as_deref().unwrap_or("T1082");
        let action = format!("{:?}", sig.recommended_action);
        let tech_label = match (&sig.mitre_technique, &sig.mitre_technique_name) {
            (Some(id), Some(name)) if !name.is_empty() => format!("[{} · {}] ", id, name),
            (Some(id), _) => format!("[{}] ", id),
            _ => format!("[{}] ", tech),
        };
        let reason_str = sig.reason.as_deref().unwrap_or("").trim();
        let reason_clean = reason_str.split(';').next().unwrap_or(reason_str).trim();
        let issue_desc = if reason_clean.is_empty() {
            "Suspicious Activity"
        } else {
            reason_clean
        };

        let summary = if !is_unknown_proc {
            format!(
                "Broadcast to Mesh: {}{}: {} — Action: {}",
                tech_label, proc, issue_desc, action
            )
        } else {
            format!(
                "Broadcast to Mesh: {}{} — Action: {}",
                tech_label, issue_desc, action
            )
        };

        self.audit.log(
            "MESH_THREAT_BROADCAST",
            serde_json::json!({
                "source_node": sig.source_node,
                "threat_id": sig.id,
                "confidence": sig.confidence,
                "process_name": sig.process_name,
                "mitre_technique": sig.mitre_technique,
                "mitre_technique_name": sig.mitre_technique_name,
                "mitre_tactic": sig.mitre_tactic,
                "reason": sig.reason,
                "action": action,
                "action_state": sig.action_state,
                "hash": sig.hash_blake3,
                "summary": summary,
            }),
        );
    }

    /// Broadcast intelligence across the mesh network.
    pub async fn broadcast_intelligence(&self, summary: String) -> anyhow::Result<()> {
        if !osoosi_types::is_p2p_mesh_enabled() {
            anyhow::bail!("Peer-to-Peer (P2P) mesh is currently disabled by user policy");
        }
        let mut intel = osoosi_types::GlobalIntelligence {
            source_url: "user_dashboard".to_string(),
            summary: summary.clone(),
            priority: 1.0, // Default to high for manual broadcast
            defense: None,
            timestamp: chrono::Utc::now(),
            source_node: self.trust.did().to_string(),
            merkle_proof: None,
            epsilon: None,
        };

        self.privacy.protect_intel(&mut intel);

        info!("Broadcasting intelligence: {}", summary);
        self.audit.log(
            "INTEL_BROADCAST",
            serde_json::json!({
                "summary": summary,
                "source": "dashboard",
            }),
        );

        if let Some(ref tx) = *self.mesh_command_tx.lock().await {
            tx.send(osoosi_wire::MeshCommand::BroadcastGlobalIntel(intel))
                .await
                .map_err(|e| anyhow::anyhow!("Mesh channel closed: {}", e))
        } else {
            Err(anyhow::anyhow!("Mesh not active"))
        }
    }

    pub async fn start_mesh_with_join_gate(&self) -> anyhow::Result<Arc<JoinGate>> {
        let autonomy = osoosi_types::load_autonomy_config();
        let peer_rules = osoosi_types::load_peer_rules_config();
        let master_node_pk =
            osoosi_types::load_mesh_listen_config_extended().master_node_public_key;
        let (command_tx, command_rx) = tokio::sync::mpsc::channel(32);
        let (peer_threat_tx, mut peer_threat_rx) =
            tokio::sync::mpsc::channel::<osoosi_types::ThreatSignature>(64);
        let join_gate = Arc::new(JoinGate::new(
            self.memory.clone(),
            command_tx.clone(),
            autonomy.auto_approve_reputation_threshold,
            peer_rules.clone(),
            master_node_pk,
        ));

        {
            let mut tx_guard = self.mesh_command_tx.lock().await;
            *tx_guard = Some(command_tx.clone());
        }

        let mesh = {
            let mut guard = self.mesh.lock().await;
            guard
                .take()
                .ok_or_else(|| anyhow::anyhow!("Mesh already started or taken"))?
        };

        let (peer_consensus_tx, mut peer_consensus_rx) =
            tokio::sync::mpsc::channel::<osoosi_types::PolicyConsensusMessage>(64);
        let (ghost_shard_tx, mut ghost_shard_rx) =
            tokio::sync::mpsc::channel::<osoosi_types::GhostShardData>(64);
        let (peer_intel_tx, mut peer_intel_rx) =
            tokio::sync::mpsc::channel::<osoosi_types::GlobalIntelligence>(64);
        let (malware_sample_tx, mut malware_sample_rx) =
            tokio::sync::mpsc::channel::<osoosi_types::MalwareSample>(256);

        let join_gate_clone = join_gate.clone();
        let peer_count = self.mesh_peer_count.clone();
        let peer_tx = peer_threat_tx.clone();
        let cons_tx = peer_consensus_tx.clone();
        let ghost_tx = ghost_shard_tx.clone();
        let intel_tx = peer_intel_tx.clone();
        let sample_tx = malware_sample_tx.clone();
        let autonomy_conf = autonomy.clone();
        let self_clone = self.clone();
        let orch_tripwire = self.clone();
        let adaptive_clone = self.adaptive.clone();
        let gossip_count = self.mesh_gossip_count_atomic.clone();
        let gossip_sig = gossip_count.clone();
        let gossip_cons = gossip_count.clone();
        let gossip_ghost = gossip_count.clone();
        let gossip_intel = gossip_count.clone();
        let gossip_sample = gossip_count.clone();
        let gossip_tarpit = gossip_count.clone();
        let gossip_conf = gossip_count.clone();
        let gossip_delta = gossip_count.clone();
        let gossip_trip = gossip_count.clone();
        let gossip_skill = gossip_count.clone();
        let orch_skill = self.clone();

        let mesh_future = Box::pin(async move {
            mesh.run_loop(
                join_gate_clone,
                command_rx,
                Some(peer_count),
                peer_rules,
                adaptive_clone,
                move |sig| {
                    gossip_sig.fetch_add(1, Ordering::Relaxed);
                    let _ = peer_tx.try_send(sig);
                },
                move |m| {
                    gossip_cons.fetch_add(1, Ordering::Relaxed);
                    let _ = cons_tx.try_send(m);
                },
                move |s| {
                    gossip_ghost.fetch_add(1, Ordering::Relaxed);
                    let _ = ghost_tx.try_send(s);
                },
                move |i| {
                    gossip_intel.fetch_add(1, Ordering::Relaxed);
                    let _ = intel_tx.try_send(i);
                },
                move |s| {
                    gossip_sample.fetch_add(1, Ordering::Relaxed);
                    let _ = sample_tx.try_send(s);
                },
                move |t| {
                    gossip_tarpit.fetch_add(1, Ordering::Relaxed);
                    if t.confidence >= autonomy_conf.action_confidence_threshold {
                        let socket_addr = if let Ok(sa) = t.target_ip.parse::<std::net::SocketAddr>() {
                            Some(sa)
                        } else if let Ok(ip) = t.target_ip.parse::<std::net::IpAddr>() {
                            Some(std::net::SocketAddr::new(ip, 0))
                        } else {
                            None
                        };
                        if let Some(saddr) = socket_addr {
                            let addr = saddr.ip();
                            let is_disallowed = match addr {
                                std::net::IpAddr::V4(ipv4) => {
                                    let oct = ipv4.octets();
                                    ipv4.is_loopback()
                                        || ipv4.is_unspecified()
                                        || ipv4.is_multicast()
                                        || ipv4.is_broadcast()
                                        || oct[0] == 10
                                        || (oct[0] == 172 && (16..=31).contains(&oct[1]))
                                        || (oct[0] == 192 && oct[1] == 168)
                                        || (oct[0] == 169 && oct[1] == 254)
                                }
                                std::net::IpAddr::V6(ipv6) => {
                                    ipv6.is_loopback() || ipv6.is_unspecified() || ipv6.is_multicast()
                                }
                            };
                            if !is_disallowed {
                                let _ = osoosi_wire::apply_socket_tarpit(saddr);
                            } else {
                                debug!("TarpitSignal: Ignored local/private/multicast IP {}", addr);
                            }
                        }
                    }
                },
                move |c| {
                    gossip_conf.fetch_add(1, Ordering::Relaxed);
                    info!("MESH: Received confidential message from peer: {:?}", c);
                },
                move |delta| {
                    gossip_delta.fetch_add(1, Ordering::Relaxed);
                    if let Ok(mut model) = self_clone.threat_model.try_write() {
                        model.merge_delta(&delta);
                    } else {
                        let sc = self_clone.clone();
                        tokio::spawn(async move {
                            let mut model = sc.threat_model.write().await;
                            model.merge_delta(&delta);
                        });
                    }
                },
                move |alert| {
                    gossip_trip.fetch_add(1, Ordering::Relaxed);
                    let self_inner = orch_tripwire.clone();
                    tokio::spawn(async move {
                        warn!("Mesh Tripwire: Peer {} triggered a phantom memory trap! Offender: {} ({})", alert.source_node_id, alert.offender.name, alert.offender.blake3_hash);
                        self_inner.memory.mark_hash_known_malicious(&alert.offender.blake3_hash);
                        self_inner.audit.log(
                            "MESH_TRIPWIRE_RECEIVED",
                            serde_json::json!({
                                "source_node": alert.source_node_id,
                                "offender": alert.offender.name,
                                "hash": alert.offender.blake3_hash,
                            }),
                        );
                    });
                },
                move |knowledge| {
                    gossip_skill.fetch_add(1, Ordering::Relaxed);
                    orch_skill.handle_incoming_skill_knowledge(knowledge);
                },
            )
            .await;
        });
        // Process backlog of pending joins that now meet auto-approval criteria
        let _ = join_gate.auto_approve_backlog();

        tokio::spawn(mesh_future);

        // 6. Periodic Peer Announce (Status broadcast for join rules & Master Node verification)
        let orch_for_announce = self.clone();
        let announce_tx = command_tx.clone();
        tokio::spawn(async move {
            loop {
                match orch_for_announce.get_status_for_announce().await {
                    Ok(status) => {
                        let _ = announce_tx
                            .send(MeshCommand::PublishPeerAnnounce(status))
                            .await;
                    }
                    Err(e) => {
                        tracing::warn!("Failed to generate peer status for announcement: {}", e);
                    }
                }
                tokio::time::sleep(tokio::time::Duration::from_secs(300)).await;
            }
        });

        // Process Ghost Shards: HDS Algorithm Activation
        let holograph_orch = self.holograph.clone();
        tokio::spawn(async move {
            while let Some(shard) = ghost_shard_rx.recv().await {
                holograph_orch.add_shard(shard);
            }
        });

        // Process Global Intelligence: Gossip Sleuth Defense Learning
        let policy_orch = self.policy.clone();
        let audit_orch = self.audit.clone();
        let yara_orch = self.yara_manager.clone();
        tokio::spawn(async move {
            while let Some(intel) = peer_intel_rx.recv().await {
                audit_orch.log(
                    "MESH_INTEL_RECEIVED",
                    serde_json::json!({
                        "summary": format!("Peer intelligence: {}", intel.summary),
                        "source": intel.source_node,
                    }),
                );
                info!(
                    "Gossip: Received intelligence from peer {}: {}",
                    intel.source_node, intel.summary
                );
                if let Some(defense) = intel.defense {
                    info!(
                        "Gossip Learning: Automatically registering new defense rule for {}.",
                        defense.cve_id
                    );
                    // In a real implementation, we would parse defense.learned_rule and add to PolicyEngine
                    policy_orch.register_temporary_rule(
                        &defense.cve_id,
                        &defense.learned_rule,
                        defense.severity,
                    );
                    let _ = yara_orch.hot_load_rule(
                        &defense.learned_rule,
                        &format!("mesh_{}", uuid::Uuid::new_v4()),
                    );
                }
            }
        });

        // Start local Gossip Sleuth: scouting for new threats to share
        let sleuth = Arc::new(crate::gossip::GossipSleuth::new(
            command_tx.clone(),
            self.trust.did().to_string(),
            self.privacy.clone(),
            self.memory.clone(),
        ));
        tokio::spawn(sleuth.start_sleuthing_loop());

        // Process peer consensus: Byzantine-aware BFT + reputation gate (mesh “immune system”).
        let history = self.policy_consensus.clone();
        let memory_consensus = self.memory.clone();
        let join_gate_consensus = join_gate.clone();
        let mesh_peer_count_bft = self.mesh_peer_count.clone();
        tokio::spawn(async move {
            use crate::byzantine::{analyze_policy_consensus, BftConsensusParams};
            let mut bft_validated_once: HashSet<String> = HashSet::new();
            while let Some(msg) = peer_consensus_rx.recv().await {
                let policy_id = match &msg {
                    osoosi_types::PolicyConsensusMessage::Announcement(a) => a.policy_id.clone(),
                    osoosi_types::PolicyConsensusMessage::Vote(v) => v.policy_id.clone(),
                    osoosi_types::PolicyConsensusMessage::Witness(w) => w.policy_id.clone(),
                };
                let snapshot = {
                    // DashMap: lock-free entry mutation
                    let mut entry = history.entry(policy_id.clone()).or_default();
                    entry.push(msg.clone());
                    entry.clone()
                };

                let rep_fn = |vid: &str| {
                    memory_consensus
                        .get_reputation(vid)
                        .ok()
                        .flatten()
                        .map(|r| r.score)
                        .unwrap_or(0.5)
                };
                let params = BftConsensusParams {
                    mesh_peer_hint: Some(mesh_peer_count_bft.load(Ordering::Relaxed).max(1)),
                    ..Default::default()
                };
                let outcome = analyze_policy_consensus(&snapshot, rep_fn, &params);

                if outcome.mesh_validated {
                    if !bft_validated_once.contains(&policy_id) {
                        bft_validated_once.insert(policy_id.clone());
                        info!(
                            "Policy {} mesh-validated (BFT/PoS-weighted): optimal={}/{} voters, critical={}, weighted_opt={:.2}, high_trust={}, pbft_f_max={:?}",
                            policy_id,
                            outcome.optimal_count,
                            outcome.participating_voters,
                            outcome.critical_count,
                            outcome.weighted_optimal_share,
                            outcome.high_trust_endorsement,
                            outcome.pbft_max_faults
                        );
                        let _ = memory_consensus
                            .set_repair_status(&format!("mesh_bft_{}", policy_id), "validated");
                        for vid in &outcome.penalize_critical_voters {
                            if let Err(e) = join_gate_consensus.penalize_peer(
                                vid,
                                "BFT mesh-optimal quorum: dissenting CriticalFailure vote",
                                0.12,
                            ) {
                                warn!("BFT penalize {}: {}", vid, e);
                            }
                        }
                    }
                } else if outcome.witness_resolved {
                    info!(
                        "Policy {} stalemate resolved by witness/tie-breaker to {:?}",
                        policy_id, outcome.winning_status
                    );
                    let _ = memory_consensus.set_repair_status(
                        &format!("mesh_bft_{}", policy_id),
                        "witness_resolved_non_optimal",
                    );
                } else if outcome.stalemate_conflict {
                    warn!(
                        "Policy {} mesh vote STALEMATE (possible Byzantine split): optimal={} critical={} participants={}",
                        policy_id,
                        outcome.optimal_count,
                        outcome.critical_count,
                        outcome.participating_voters
                    );
                }
            }
        });

        // Process peer threats: store in memory, add to model, update gossip feed and audit trail
        let memory_peer = self.memory.clone();
        let model_peer = self.threat_model.clone();
        let self_threat = self.clone();
        tokio::spawn(async move {
            while let Some(sig) = peer_threat_rx.recv().await {
                if !sig.verify() {
                    debug!("PeerThreatRx: Dropped unverified threat {}", sig.id);
                    continue;
                }
                if sig.confidence < 0.50 {
                    debug!("PeerThreatRx: Dropped low-confidence threat {}", sig.id);
                    continue;
                }
                if sig
                    .reason
                    .as_deref()
                    .unwrap_or("")
                    .contains("Execution Of Non-Existing File")
                {
                    debug!(
                        "PeerThreatRx: Dropped non-existing file noise threat {}",
                        sig.id
                    );
                    continue;
                }
                let proc_clean = sig.process_name.as_deref().unwrap_or("").trim();
                if proc_clean.is_empty()
                    || proc_clean.eq_ignore_ascii_case("unknown")
                    || proc_clean.eq_ignore_ascii_case("unknown process")
                {
                    debug!("PeerThreatRx: Dropped unknown process threat {}", sig.id);
                    continue;
                }
                let inbound_mesh_verdict = crate::rea::global_rea_engine()
                    .inspect_and_vet_mesh_frame(
                        "inbound",
                        Some(&sig.source_node),
                        sig.process_name.as_deref().unwrap_or(""),
                        sig.hash_blake3.as_deref(),
                        None,
                        sig.reason.as_deref(),
                    );
                if inbound_mesh_verdict.vetoed || !inbound_mesh_verdict.allowed {
                    let veto_reason = inbound_mesh_verdict
                        .veto_reason
                        .unwrap_or_else(|| inbound_mesh_verdict.summary.clone());
                    warn!(
                        "PeerThreatRx [BYZANTINE_KILLSWITCH_VETOED]: Rejected peer threat {} from {}: {}",
                        sig.id, sig.source_node, veto_reason
                    );
                    self_threat.audit.log(
                        "BYZANTINE_KILLSWITCH_VETOED",
                        serde_json::json!({
                            "source_node": sig.source_node,
                            "threat_id": sig.id,
                            "process_name": sig.process_name,
                            "hash_blake3": sig.hash_blake3,
                            "veto_reason": veto_reason,
                            "rea_seal_blake3": inbound_mesh_verdict.rea_seal_blake3,
                        }),
                    );
                    continue;
                }
                if let Some(veto_reason) = crate::rea::veto_peer_kill_switch_candidate(
                    sig.process_name.as_deref(),
                    sig.hash_blake3.as_deref(),
                    None,
                    sig.reason.as_deref(),
                ) {
                    warn!(
                        "PeerThreatRx [BYZANTINE_KILLSWITCH_VETOED]: Rejected peer threat {} from {}: {}",
                        sig.id, sig.source_node, veto_reason
                    );
                    self_threat.audit.log(
                        "BYZANTINE_KILLSWITCH_VETOED",
                        serde_json::json!({
                            "source_node": sig.source_node,
                            "threat_id": sig.id,
                            "process_name": sig.process_name,
                            "hash_blake3": sig.hash_blake3,
                            "veto_reason": veto_reason,
                        }),
                    );
                    continue;
                }

                if let Err(e) = memory_peer.log_threat(&sig) {
                    if e.to_string().contains("UNIQUE constraint") {
                        debug!("Peer threat {} already stored: {}", sig.id, e);
                    } else {
                        error!("Failed to store peer threat: {}", e);
                    }
                }
                if let Some(ref hash) = sig.hash_blake3 {
                    memory_peer.mark_hash_known_malicious(hash);
                }
                self_threat.record_gossip_threat(&sig, "MESH_THREAT_RECEIVED");

                let proc = proc_clean.to_string();
                let tech = sig
                    .mitre_technique
                    .clone()
                    .unwrap_or_else(|| "T1082".to_string());
                let action = format!("{:?}", sig.recommended_action);
                let reason_str = sig.reason.as_deref().unwrap_or("").trim();
                let reason_clean = reason_str.split(';').next().unwrap_or(reason_str).trim();
                let issue_desc = if reason_clean.is_empty() {
                    "Suspicious Activity"
                } else {
                    reason_clean
                };
                let summary = format!(
                    "Peer Threat [{}]: {}: {} ({}) via {}",
                    tech, proc, issue_desc, action, sig.source_node
                );

                self_threat.audit.log(
                    "MESH_THREAT_RECEIVED",
                    serde_json::json!({
                        "source_node": sig.source_node,
                        "threat_id": sig.id,
                        "confidence": sig.confidence,
                        "process_name": sig.process_name,
                        "mitre_technique": sig.mitre_technique,
                        "mitre_technique_name": sig.mitre_technique_name,
                        "mitre_tactic": sig.mitre_tactic,
                        "reason": sig.reason,
                        "action": action,
                        "summary": summary,
                    }),
                );

                let mut model = model_peer.write().await;
                model.add_training_sample(&sig);
                if sig.confidence >= 0.8 {
                    if let Some(rule) = crate::yara_gen::generate_yara_from_threat(&sig) {
                        if crate::rea::veto_peer_kill_switch_candidate(
                            sig.process_name.as_deref(),
                            sig.hash_blake3.as_deref(),
                            Some(&rule),
                            sig.reason.as_deref(),
                        )
                        .is_none()
                        {
                            let _ = self_threat.yara_manager.hot_load_rule(&rule, &sig.id);
                            info!("[YARA] Hot-loaded auto-generated YARA rule for peer threat '{}'. Engine updated.", sig.id);
                        } else {
                            warn!("[YARA] Suppressed poisoned auto-generated YARA rule for peer threat '{}'", sig.id);
                        }
                    }
                }
            }
        });

        // Process malware samples from mesh: store for distributed EMBER training
        let memory_malware = self.memory.clone();
        tokio::spawn(async move {
            while let Some(sample) = malware_sample_rx.recv().await {
                if let Err(e) = memory_malware.insert_malware_sample(&sample) {
                    error!("Failed to store mesh malware sample: {}", e);
                } else {
                    debug!(
                        "Stored malware sample from {} (hash={}, label={})",
                        sample.source_node,
                        &sample.file_hash[..sample.file_hash.len().min(12)],
                        sample.label
                    );
                }
            }
        });

        Ok(join_gate)
    }

    /// COORDINATOR: Activate Holographic Deception Sharding across the mesh.
    /// Spawns distributed ghost shards to trap an identified attacker.
    pub async fn activate_mesh_hologram(&self, attacker_ip: &str) -> anyhow::Result<()> {
        use std::sync::atomic::Ordering;
        let _peer_count = self.mesh_peer_count.load(Ordering::Relaxed);
        let mesh_members = vec![self.trust.did().to_string()]; // Local node participates

        let ports = vec![22, 80, 443, 3306, 5432];
        for port in ports {
            let owner = osoosi_wire::holograph::HolographEngine::calculate_shard_assignment(
                attacker_ip,
                port,
                &mesh_members,
            );

            let shard = osoosi_types::GhostShardData {
                attacker_ip: attacker_ip.to_string(),
                virtual_port: port,
                deception_type: match port {
                    22 => osoosi_types::DeceptionType::SshDelay,
                    80 | 443 => osoosi_types::DeceptionType::HttpLabyrinth,
                    _ => osoosi_types::DeceptionType::DbSimulation,
                },
                shard_owner: owner,
            };

            self.holograph.add_shard(shard.clone());

            let tx_guard = self.mesh_command_tx.lock().await;
            if let Some(ref tx) = *tx_guard {
                let _ = tx.try_send(osoosi_wire::MeshCommand::BroadcastGhostShard(shard));
            }
        }

        info!(
            "HDS: Holographic Lattice deployed for attacker {}.",
            attacker_ip
        );
        Ok(())
    }
}
