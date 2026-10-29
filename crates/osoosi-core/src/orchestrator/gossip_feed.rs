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
    /// Broadcast a learned WikiSkill pattern across the P2P wire mesh.
    pub async fn broadcast_skill_knowledge(
        &self,
        knowledge: osoosi_wire::SkillKnowledgeBroadcast,
    ) -> anyhow::Result<()> {
        info!(
            "[MESH_SKILL_SYNC] Broadcasting learned skill pattern '{}' for '{}' (v{}) to wire mesh",
            knowledge.pattern_title, knowledge.skill_name, knowledge.version
        );
        self.audit.log(
            "MESH_SKILL_BROADCAST",
            serde_json::json!({
                "skill_name": knowledge.skill_name,
                "version": knowledge.version,
                "pattern_title": knowledge.pattern_title,
                "content_hash": knowledge.content_hash,
                "score": knowledge.score,
                "node_id": knowledge.node_id,
            }),
        );
        if let Some(ref tx) = *self.mesh_command_tx.lock().await {
            let _ = tx
                .send(osoosi_wire::MeshCommand::BroadcastSkillKnowledge(knowledge))
                .await;
        }
        Ok(())
    }

    /// Ingest, validate, and persist peer-discovered WikiSkill patterns into a specified workspace.
    /// Returns `(inbox_path, is_duplicate, blake3_hash)` on success, or an error string on rejection.
    pub fn ingest_skill_knowledge_to_workspace(
        knowledge: &osoosi_wire::SkillKnowledgeBroadcast,
        workspace: &std::path::Path,
    ) -> Result<(std::path::PathBuf, bool, String), String> {
        let trimmed = knowledge.markdown_content.trim();
        if trimmed.is_empty() {
            let msg = format!(
                "Rejected empty skill pattern from peer '{}'",
                knowledge.node_id
            );
            warn!("[MESH_SKILL_SYNC] {}", msg);
            return Err(msg);
        }

        // Cap pattern size to 1MB to prevent resource exhaustion
        if trimmed.len() > 1024 * 1024 {
            let msg = format!(
                "Rejected oversized skill pattern (>1MB) from peer '{}'",
                knowledge.node_id
            );
            warn!("[MESH_SKILL_SYNC] {}", msg);
            return Err(msg);
        }

        if knowledge.content_hash.trim().is_empty() {
            let msg = format!(
                "Rejected skill pattern '{}' from peer '{}': missing content_hash",
                knowledge.pattern_title, knowledge.node_id
            );
            warn!("[MESH_SKILL_SYNC] {}", msg);
            return Err(msg);
        }

        // Validate content hash: calculate BLAKE3 of trimmed markdown
        let calculated_blake3 = blake3::hash(trimmed.as_bytes()).to_hex().to_string();
        let sha256_valid = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(trimmed.as_bytes());
            let sha256_h = hex::encode(hasher.finalize());
            knowledge.content_hash.eq_ignore_ascii_case(&sha256_h)
        };
        let prefix_valid = knowledge.content_hash.len() >= 12
            && knowledge
                .content_hash
                .chars()
                .all(|c| c.is_ascii_hexdigit())
            && calculated_blake3.starts_with(&knowledge.content_hash.to_lowercase());

        let hash_valid = knowledge
            .content_hash
            .eq_ignore_ascii_case(&calculated_blake3)
            || sha256_valid
            || prefix_valid;

        if !hash_valid {
            let msg = format!(
                "Rejecting skill pattern '{}' from peer '{}': content hash mismatch (expected {}, got {})",
                knowledge.pattern_title, knowledge.node_id, knowledge.content_hash, calculated_blake3
            );
            warn!("[MESH_SKILL_SYNC] {}", msg);
            return Err(msg);
        }

        let wiki_dir = workspace.join("wiki");
        let inbox_dir = wiki_dir.join("inbox");
        if let Err(e) = std::fs::create_dir_all(&inbox_dir) {
            let msg = format!(
                "Failed to create wiki inbox directory {:?}: {}",
                inbox_dir, e
            );
            warn!("[MESH_SKILL_SYNC] {}", msg);
            return Err(msg);
        }

        // Always use the strictly verified 64-hex lowercase BLAKE3 hash for the filename.
        // This completely prevents directory traversal and invalid filename attacks.
        let pattern_file = inbox_dir.join(format!("{}.md", calculated_blake3));
        let is_duplicate = pattern_file.is_file();

        if !is_duplicate {
            if let Err(e) = std::fs::write(&pattern_file, &knowledge.markdown_content) {
                let msg = format!("Failed to write pattern to {:?}: {}", pattern_file, e);
                warn!("[MESH_SKILL_SYNC] {}", msg);
                return Err(msg);
            }

            // Append/merge into peer_patterns.md
            let peer_patterns_file = wiki_dir.join("peer_patterns.md");
            let mut entry = String::new();
            if !peer_patterns_file.is_file() {
                entry.push_str("# Peer Learned Patterns\n\nSynchronized via OpenỌ̀ṣọ́ọ̀sì P2P Wire Mesh Gossip.\n\n");
            }

            let clean_title = knowledge.pattern_title.replace('\n', " ").replace('\r', "");
            let clean_node_id = knowledge.node_id.replace(['\n', '\r'], "");
            let clean_skill = knowledge.skill_name.replace(['\n', '\r'], "");
            let clean_ver = knowledge.version.replace(['\n', '\r'], "");

            let sig_line = if let Some(ref s) = knowledge.signature {
                format!("- **Signature**: `{}`\n", s.trim())
            } else {
                String::new()
            };

            entry.push_str(&format!(
                "## [{}] (Peer: {}, Score: {:.2})\n- **Skill**: {} v{}\n- **Hash**: `{}`\n- **Received**: {}\n{}{}\n\n---\n\n",
                clean_title,
                clean_node_id,
                knowledge.score,
                clean_skill,
                clean_ver,
                calculated_blake3,
                knowledge.timestamp.to_rfc3339(),
                sig_line,
                trimmed
            ));

            use std::io::Write;
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&peer_patterns_file)
            {
                let _ = f.write_all(entry.as_bytes());
            }
        }

        Ok((pattern_file, is_duplicate, calculated_blake3))
    }

    /// Process and record peer skill knowledge, resolving workspace from configuration if not specified.
    pub fn process_incoming_skill_knowledge(
        &self,
        knowledge: &osoosi_wire::SkillKnowledgeBroadcast,
        custom_workspace: Option<&std::path::Path>,
    ) -> Result<std::path::PathBuf, String> {
        let resolved_ws = if let Some(ws) = custom_workspace {
            ws.to_path_buf()
        } else {
            let skills_cfg = osoosi_types::config::load_skills_config();
            let ws_path = std::path::Path::new(&skills_cfg.workspace);
            if ws_path.is_absolute() {
                ws_path.to_path_buf()
            } else if let Some(config_path) = osoosi_types::resolve_config_path() {
                if let Some(parent) = config_path.parent() {
                    parent.join(ws_path)
                } else {
                    ws_path.to_path_buf()
                }
            } else {
                ws_path.to_path_buf()
            }
        };

        let (pattern_file, is_duplicate, hash) =
            Self::ingest_skill_knowledge_to_workspace(knowledge, &resolved_ws)?;

        info!(
            "[MESH_SKILL_SYNC] Received learned skill pattern '{}' from peer '{}' (score: {:.2}). Merged into local Wiki inbox.",
            knowledge.pattern_title, knowledge.node_id, knowledge.score
        );
        self.audit.log(
            "MESH_SKILL_SYNC",
            serde_json::json!({
                "pattern_title": knowledge.pattern_title,
                "node_id": knowledge.node_id,
                "score": knowledge.score,
                "skill_name": knowledge.skill_name,
                "version": knowledge.version,
                "content_hash": hash,
                "inbox_path": pattern_file.to_string_lossy(),
                "is_duplicate": is_duplicate,
                "signature": knowledge.signature,
            }),
        );

        self.record_gossip_item(osoosi_types::GossipFeedItem {
            id: uuid::Uuid::new_v4().to_string(),
            event_type: "MESH_SKILL_SYNC".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            summary: format!(
                "Peer Learned Skill: {} (Score: {:.2}) via {}",
                knowledge.pattern_title, knowledge.score, knowledge.node_id
            ),
            source_node: knowledge.node_id.clone(),
            process_name: None,
            mitre_technique: None,
            mitre_technique_name: None,
            mitre_tactic: None,
            confidence: knowledge.score as f32,
            severity: "INFO".to_string(),
            action: Some("SkillSync".to_string()),
            status: "ACTIVE".to_string(),
            hash_blake3: Some(hash),
            is_threat: false,
        });

        Ok(pattern_file)
    }

    /// Ingest, validate, and merge peer-discovered WikiSkill patterns received over the P2P wire mesh.
    pub fn handle_incoming_skill_knowledge(&self, knowledge: osoosi_wire::SkillKnowledgeBroadcast) {
        if let Err(e) = self.process_incoming_skill_knowledge(&knowledge, None) {
            warn!("[MESH_SKILL_SYNC] Ingestion failed: {}", e);
        }
    }

    /// Record an item into the live gossip feed ring buffer.
    pub fn record_gossip_item(&self, item: osoosi_types::GossipFeedItem) {
        let p = item.process_name.as_deref().unwrap_or("");
        if crate::rea::is_rea_benign_system_or_dev_process(p, Some(&item.summary)) {
            return;
        }
        if let Ok(mut buffer) = self.mesh_gossip_feed.write() {
            if buffer.len() >= 200 {
                buffer.pop_back();
            }
            buffer.push_front(item);
        }
    }

    /// Record a ThreatSignature into the live gossip feed ring buffer.
    pub fn record_gossip_threat(&self, sig: &osoosi_types::ThreatSignature, event_type: &str) {
        let item = osoosi_types::GossipFeedItem::from_threat(sig, event_type);
        self.record_gossip_item(item);
    }

    /// Retrieve live and persisted gossip mesh feed items with intelligent sorting and routine chatter pruning.
    pub fn get_gossip_feed(&self, limit: usize) -> Vec<osoosi_types::GossipFeedItem> {
        self.run_autonomous_rea_threat_adjudication();
        let mut items = Vec::new();

        // 1. First get items from the in-memory live gossip ring buffer
        if let Ok(buffer) = self.mesh_gossip_feed.read() {
            for item in buffer.iter() {
                if self.dismissed_gossip_ids.contains(&item.id) {
                    continue;
                }
                if item.status == "FALSE_POSITIVE"
                    || item.status == "REMEDIATED"
                    || item.status == "CLEARED"
                    || item.status == "IGNORED"
                {
                    continue;
                }
                let cand_p = item.process_name.as_deref().unwrap_or("");
                let extracted_p =
                    crate::rea::extract_process_from_summary(&item.summary).unwrap_or(cand_p);
                if crate::rea::is_rea_benign_system_or_dev_process(cand_p, Some(&item.summary))
                    || (!extracted_p.is_empty()
                        && crate::rea::is_rea_benign_system_or_dev_process(
                            extracted_p,
                            Some(&item.summary),
                        ))
                {
                    continue;
                }
                let s_lower = item.summary.to_ascii_lowercase();
                if (s_lower.contains("veto") && s_lower.contains("trusted"))
                    || s_lower.contains("outside the vulnerable")
                    || s_lower.contains("cve none")
                    || s_lower.contains("unknown v0.0.0 has known cves")
                    || s_lower.contains("cve-2009-2940")
                {
                    continue;
                }
                if let Some(ref p) = item.process_name {
                    let b = std::path::Path::new(p)
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or(p)
                        .to_ascii_lowercase();
                    if crate::rea::is_rea_benign_system_or_dev_process(p, Some(&item.summary))
                        || self.rea_adjudicated_clean_procs.contains(&b)
                        || self
                            .memory
                            .is_false_positive_pattern(
                                Some(p.as_str()),
                                item.hash_blake3.as_deref(),
                            )
                            .unwrap_or(false)
                        || item
                            .hash_blake3
                            .as_deref()
                            .map(|h| self.memory.is_hash_clean_ignored(h))
                            .unwrap_or(false)
                    {
                        continue;
                    }
                }
                let is_invalid = item.summary.contains("Unknown Process")
                    || item.summary.contains("Execution Of Non-Existing File")
                    || (item.summary.contains("Suspicious Activity")
                        && item.process_name.is_none())
                    || (item.is_threat && item.confidence < 0.50)
                    || (item.is_threat
                        && item.mitre_technique.as_deref() == Some("T1006")
                        && item
                            .process_name
                            .as_deref()
                            .unwrap_or("unknown")
                            .eq_ignore_ascii_case("unknown"));
                if !is_invalid {
                    items.push(item.clone());
                }
            }
        }

        // 2. If buffer has fewer items than limit (e.g. after fresh restart), backfill from audit entries
        if items.len() < limit {
            let audit_entries = self.audit.get_recent_entries(250);
            let mut seen_ids = std::collections::HashSet::new();
            for item in &items {
                seen_ids.insert(item.id.clone());
            }

            for entry in audit_entries.iter().rev() {
                if entry.event_type == "MESH_THREAT_BROADCAST"
                    || entry.event_type == "MESH_THREAT_RECEIVED"
                    || entry.event_type == "THREAT_DETECTED"
                {
                    let id = entry
                        .data
                        .get("threat_id")
                        .or_else(|| entry.data.get("id"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| format!("audit-{}", entry.timestamp.timestamp_micros()));

                    if seen_ids.contains(&id) || self.dismissed_gossip_ids.contains(&id) {
                        continue;
                    }
                    seen_ids.insert(id.clone());

                    let proc = entry
                        .data
                        .get("process_name")
                        .and_then(|v| v.as_str())
                        .map(String::from);
                    let hash = entry
                        .data
                        .get("hash")
                        .or_else(|| entry.data.get("hash_blake3"))
                        .and_then(|v| v.as_str())
                        .map(String::from);
                    let tech = entry
                        .data
                        .get("mitre_technique")
                        .and_then(|v| v.as_str())
                        .map(String::from);
                    let tech_name = entry
                        .data
                        .get("mitre_technique_name")
                        .and_then(|v| v.as_str())
                        .map(String::from);
                    let tactic = entry
                        .data
                        .get("mitre_tactic")
                        .and_then(|v| v.as_str())
                        .map(String::from);
                    let action = entry
                        .data
                        .get("action")
                        .and_then(|v| v.as_str())
                        .map(String::from);
                    let source = entry
                        .data
                        .get("source_node")
                        .and_then(|v| v.as_str())
                        .unwrap_or("peer")
                        .to_string();
                    let conf = entry
                        .data
                        .get("confidence")
                        .and_then(|v| v.as_f64())
                        .unwrap_or(0.8) as f32;

                    let reason_str = entry
                        .data
                        .get("reason")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .trim();
                    let r_lower = reason_str.to_ascii_lowercase();
                    if (r_lower.contains("veto") && r_lower.contains("trusted"))
                        || r_lower.contains("outside the vulnerable")
                        || r_lower.contains("cve none")
                        || r_lower.contains("execution of non-existing file")
                        || conf < 0.50
                    {
                        continue;
                    }
                    let raw_summary = entry
                        .data
                        .get("summary")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let proc_str = proc.as_deref().unwrap_or("");
                    let extracted_from_sum =
                        crate::rea::extract_process_from_summary(raw_summary).unwrap_or(proc_str);
                    let is_benign_proc = (proc.is_some()
                        && crate::rea::is_rea_benign_system_or_dev_process(
                            proc_str,
                            Some(reason_str),
                        ))
                        || (proc.is_some()
                            && crate::rea::is_rea_benign_system_or_dev_process(
                                proc_str,
                                Some(raw_summary),
                            ))
                        || (!raw_summary.is_empty()
                            && crate::rea::is_rea_benign_system_or_dev_process(
                                raw_summary,
                                Some(raw_summary),
                            ))
                        || (!extracted_from_sum.is_empty()
                            && crate::rea::is_rea_benign_system_or_dev_process(
                                extracted_from_sum,
                                Some(raw_summary),
                            ));
                    if is_benign_proc {
                        continue;
                    }
                    if let Some(ref p) = proc {
                        let b = std::path::Path::new(p)
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or(p)
                            .to_ascii_lowercase();
                        if self.rea_adjudicated_clean_procs.contains(&b)
                            || self
                                .memory
                                .is_false_positive_pattern(Some(p.as_str()), hash.as_deref())
                                .unwrap_or(false)
                            || hash
                                .as_deref()
                                .map(|h| self.memory.is_hash_clean_ignored(h))
                                .unwrap_or(false)
                        {
                            continue;
                        }
                    }
                    let proc_opt = proc.as_deref().filter(|s| {
                        !s.is_empty()
                            && !s.eq_ignore_ascii_case("unknown")
                            && !s.eq_ignore_ascii_case("unknown process")
                            && !s.eq_ignore_ascii_case("system process")
                    });
                    if tech.as_deref() == Some("T1006") && proc_opt.is_none() {
                        continue;
                    }

                    let tech_label = match (tech.as_deref(), tech_name.as_deref()) {
                        (Some(id), Some(name)) if !name.is_empty() => {
                            format!("[{} · {}] ", id, name)
                        }
                        (Some(id), _) => format!("[{}] ", id),
                        _ => String::new(),
                    };
                    let act = action.as_deref().unwrap_or("Enforced");
                    let reason_clean = reason_str.split(';').next().unwrap_or(reason_str).trim();
                    if reason_clean.is_empty() && raw_summary.is_empty() {
                        continue;
                    }
                    let issue_desc = if reason_clean.is_empty() {
                        "Suspicious Activity"
                    } else {
                        reason_clean
                    };

                    let summary = if !raw_summary.is_empty()
                        && !raw_summary.contains("Unknown Process")
                        && !raw_summary.contains("Execution Of Non-Existing File")
                    {
                        raw_summary.to_string()
                    } else if let Some(p) = proc_opt {
                        format!(
                            "Peer Threat: {}{}: {} — Action: {}",
                            tech_label, p, issue_desc, act
                        )
                    } else {
                        format!(
                            "Peer Threat: {}{} — Action: {}",
                            tech_label, issue_desc, act
                        )
                    };

                    if summary.contains("Unknown Process")
                        || summary.contains("Execution Of Non-Existing File")
                        || (summary.contains("Suspicious Activity") && proc_opt.is_none())
                    {
                        continue;
                    }

                    let severity = if conf >= 0.85 || action.as_deref() == Some("Isolate") {
                        "CRITICAL".to_string()
                    } else if conf >= 0.60 || action.as_deref() == Some("Tarpit") {
                        "HIGH".to_string()
                    } else if conf >= 0.40 {
                        "MEDIUM".to_string()
                    } else {
                        "LOW".to_string()
                    };

                    let status = "ACTIVE".to_string();

                    items.push(osoosi_types::GossipFeedItem {
                        id,
                        event_type: entry.event_type.clone(),
                        timestamp: entry.timestamp.to_rfc3339(),
                        summary,
                        source_node: source,
                        process_name: proc,
                        mitre_technique: tech,
                        mitre_technique_name: tech_name,
                        mitre_tactic: tactic,
                        confidence: conf,
                        severity,
                        action,
                        status,
                        hash_blake3: hash,
                        is_threat: true,
                    });

                    if items.len() >= limit {
                        break;
                    }
                }
            }
        }

        // 2.5 Backfill from persistent MemoryStore threats if buffer + audit still has capacity
        if items.len() < limit {
            if let Ok(threats) = self.memory.get_recent_threats(limit) {
                let mut seen_ids: std::collections::HashSet<String> =
                    items.iter().map(|i| i.id.clone()).collect();
                for t in threats {
                    let id = t
                        .get("id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    if id.is_empty()
                        || seen_ids.contains(&id)
                        || self.dismissed_gossip_ids.contains(&id)
                    {
                        continue;
                    }
                    seen_ids.insert(id.clone());

                    let proc = t
                        .get("process_name")
                        .and_then(|v| v.as_str())
                        .map(String::from);
                    let hash = t
                        .get("hash_blake3")
                        .and_then(|v| v.as_str())
                        .map(String::from);
                    let source = t
                        .get("source_node")
                        .and_then(|v| v.as_str())
                        .unwrap_or("peer")
                        .to_string();
                    let conf = t.get("confidence").and_then(|v| v.as_f64()).unwrap_or(0.8) as f32;
                    let ts = t
                        .get("timestamp")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let reason = t.get("reason").and_then(|v| v.as_str()).unwrap_or("");

                    let proc_opt = proc.as_deref().filter(|s| {
                        !s.is_empty()
                            && !s.eq_ignore_ascii_case("unknown")
                            && !s.eq_ignore_ascii_case("unknown process")
                            && !s.eq_ignore_ascii_case("system process")
                    });
                    let r3_lower = reason.to_ascii_lowercase();
                    if conf < 0.50
                        || reason.trim().is_empty()
                        || r3_lower.contains("execution of non-existing file")
                        || (r3_lower.contains("veto") && r3_lower.contains("trusted"))
                        || r3_lower.contains("outside the vulnerable")
                        || r3_lower.contains("cve none")
                    {
                        continue;
                    }
                    let description = t
                        .get("description")
                        .or_else(|| t.get("reason"))
                        .and_then(|v| v.as_str())
                        .unwrap_or(reason);
                    let proc_str = proc.as_deref().unwrap_or("");
                    let extracted_from_desc =
                        crate::rea::extract_process_from_summary(description).unwrap_or(proc_str);
                    let is_benign_proc = (proc.is_some()
                        && crate::rea::is_rea_benign_system_or_dev_process(
                            proc_str,
                            Some(description),
                        ))
                        || (!extracted_from_desc.is_empty()
                            && crate::rea::is_rea_benign_system_or_dev_process(
                                extracted_from_desc,
                                Some(description),
                            ))
                        || crate::rea::is_rea_benign_system_or_dev_process(
                            "<unknown process>",
                            Some(description),
                        );
                    if is_benign_proc {
                        continue;
                    }
                    if let Some(ref p) = proc {
                        let b = std::path::Path::new(p)
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or(p)
                            .to_ascii_lowercase();
                        if self.rea_adjudicated_clean_procs.contains(&b)
                            || self
                                .memory
                                .is_false_positive_pattern(Some(p.as_str()), hash.as_deref())
                                .unwrap_or(false)
                            || hash
                                .as_deref()
                                .map(|h| self.memory.is_hash_clean_ignored(h))
                                .unwrap_or(false)
                        {
                            continue;
                        }
                    }

                    let (tactic, tech, tech_name) =
                        osoosi_policy::mitre_kb::extract_mitre_from_text(reason)
                            .map(|(tac, tec, nam)| (Some(tac), Some(tec), Some(nam)))
                            .unwrap_or((None, None, None));

                    if tech.as_deref() == Some("T1006") && proc_opt.is_none() {
                        continue;
                    }

                    let tech_label = match (tech.as_deref(), tech_name.as_deref()) {
                        (Some(id), Some(name)) if !name.is_empty() => {
                            format!("[{} · {}] ", id, name)
                        }
                        (Some(id), _) => format!("[{}] ", id),
                        _ => String::new(),
                    };
                    let clean_reason = {
                        let first = reason.split(';').next().unwrap_or(reason).trim();
                        if first.is_empty() {
                            continue;
                        } else if first.len() > 90 {
                            format!("{}...", &first[..87])
                        } else {
                            first.to_string()
                        }
                    };
                    let act_str = t
                        .get("action")
                        .or_else(|| t.get("recommended_action"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("Isolated & Terminated");
                    let summary = if let Some(p) = proc_opt {
                        format!(
                            "Peer Threat: {}{}: {} — Action: {}",
                            tech_label, p, clean_reason, act_str
                        )
                    } else {
                        format!(
                            "Peer Threat: {}{} — Action: {}",
                            tech_label, clean_reason, act_str
                        )
                    };
                    if summary.contains("Unknown Process")
                        || summary.contains("Execution Of Non-Existing File")
                        || (summary.contains("Suspicious Activity") && proc_opt.is_none())
                    {
                        continue;
                    }

                    let status = "ACTIVE".to_string();

                    let severity = if conf >= 0.85 {
                        "CRITICAL".to_string()
                    } else if conf >= 0.60 {
                        "HIGH".to_string()
                    } else {
                        "MEDIUM".to_string()
                    };

                    items.push(osoosi_types::GossipFeedItem {
                        id,
                        event_type: "MESH_THREAT_RECEIVED".to_string(),
                        timestamp: if ts.is_empty() {
                            chrono::Utc::now().to_rfc3339()
                        } else {
                            ts
                        },
                        summary,
                        source_node: source,
                        process_name: proc,
                        mitre_technique: tech,
                        mitre_technique_name: tech_name,
                        mitre_tactic: tactic,
                        confidence: conf,
                        severity,
                        action: Some(act_str.to_string()),
                        status,
                        hash_blake3: hash,
                        is_threat: true,
                    });

                    if items.len() >= limit {
                        break;
                    }
                }
            }
        }

        // 3. Intelligent Sorting: Active threats first, then timestamp descending
        items.sort_by(|a, b| {
            let a_prio = if a.is_threat && a.status == "ACTIVE" {
                1
            } else {
                0
            };
            let b_prio = if b.is_threat && b.status == "ACTIVE" {
                1
            } else {
                0
            };
            b_prio
                .cmp(&a_prio)
                .then_with(|| b.timestamp.cmp(&a.timestamp))
        });

        // 4. Prune/deduplicate routine stale heartbeats so active threats stand out
        let mut deduplicated = Vec::new();
        let mut seen_routine = std::collections::HashSet::new();
        let mut seen_threat_keys = std::collections::HashSet::new();

        for item in items {
            if self.dismissed_gossip_ids.contains(&item.id)
                || item.status == "FALSE_POSITIVE"
                || item.status == "REMEDIATED"
                || item.status == "CLEARED"
                || item.status == "IGNORED"
            {
                continue;
            }
            let extracted_p = crate::rea::extract_process_from_summary(&item.summary);
            let check_p = item.process_name.as_deref().or(extracted_p);
            if let Some(p) = check_p {
                if crate::rea::is_rea_benign_system_or_dev_process(p, Some(&item.summary)) {
                    continue;
                }
                let b = std::path::Path::new(p)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or(p)
                    .to_ascii_lowercase();
                if self.rea_adjudicated_clean_procs.contains(&b) {
                    continue;
                }
            }
            let is_invalid = item.summary.contains("Unknown Process")
                || item.summary.contains("Execution Of Non-Existing File")
                || (item.summary.contains("Suspicious Activity") && item.process_name.is_none())
                || (item.is_threat && item.confidence < 0.50)
                || (item.is_threat
                    && item.mitre_technique.as_deref() == Some("T1006")
                    && item
                        .process_name
                        .as_deref()
                        .unwrap_or("unknown")
                        .eq_ignore_ascii_case("unknown"));
            if is_invalid {
                continue;
            }

            if item.event_type == "MESH_HEARTBEAT_ACK" || item.event_type == "CONSENSUS_CLOCK_SYNC"
            {
                let key = format!("{}:{}", item.event_type, item.source_node);
                if seen_routine.contains(&key) {
                    continue;
                }
                seen_routine.insert(key);
            } else if item.is_threat {
                let p_lower = item
                    .process_name
                    .as_deref()
                    .unwrap_or("")
                    .to_ascii_lowercase();
                let tech = item.mitre_technique.as_deref().unwrap_or("");
                let sum_pfx: String = item.summary.chars().take(48).collect();
                let threat_key = format!("{}:{}:{}", p_lower, tech, sum_pfx);
                if seen_threat_keys.contains(&threat_key) {
                    continue;
                }
                seen_threat_keys.insert(threat_key);
            }
            deduplicated.push(item);
            if deduplicated.len() >= limit {
                break;
            }
        }

        deduplicated
    }

    /// Autonomously adjudicate pending candidate threats and live gossip items via REA.
    /// Drops benign toolchain / OS binaries, CVE version-mismatch alerts, and vendor-vetoed threats.
    pub fn run_autonomous_rea_threat_adjudication(&self) -> usize {
        let rea_for_scanner = crate::rea::global_rea_engine();
        let scanner_purged = self
            .malware_scanner
            .purge_false_positive_or_benign_detections(|d| {
                if osoosi_model::malware::is_informational_or_crt_yara_rule(&d.malware_type) {
                    return true;
                }
                if crate::rea::is_rea_benign_system_or_dev_process(
                    &d.file_path,
                    Some(&d.malware_type),
                ) {
                    return true;
                }
                let p = std::path::Path::new(&d.file_path);
                if p.is_file()
                    && (crate::win_trust::is_trusted_signed_binary(p)
                        || crate::rea::verify_dynamic_binary_trust(p))
                {
                    return true;
                }
                let (should_drop, _, _) = rea_for_scanner.adjudicate_process_or_binary_alert(
                    None,
                    Some(&d.file_path),
                    Some(&d.malware_type),
                );
                should_drop
            });

        let now = chrono::Utc::now().timestamp();
        let last = self
            .last_rea_adjudication_ts
            .load(std::sync::atomic::Ordering::Relaxed);
        if now.saturating_sub(last) < 3 {
            return scanner_purged;
        }
        if self
            .last_rea_adjudication_ts
            .compare_exchange(
                last,
                now,
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::Relaxed,
            )
            .is_err()
        {
            return scanner_purged;
        }
        let mut dropped = scanner_purged
            + self
                .memory
                .purge_vetoed_and_false_positive_threats()
                .unwrap_or(0);
        let mut candidates = Vec::new();
        if let Ok(feed) = self.mesh_gossip_feed.read() {
            for item in feed.iter() {
                if !self.dismissed_gossip_ids.contains(&item.id) {
                    candidates.push((
                        item.id.clone(),
                        item.process_name.clone(),
                        item.hash_blake3.clone(),
                        item.summary.clone(),
                    ));
                }
            }
        }
        if let Ok(threats) = self.memory.get_recent_threats(100) {
            for t in threats {
                let id = t
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                if !id.is_empty() && !self.dismissed_gossip_ids.contains(&id) {
                    let proc = t
                        .get("process_name")
                        .and_then(|v| v.as_str())
                        .map(String::from);
                    let hash = t
                        .get("hash_blake3")
                        .and_then(|v| v.as_str())
                        .map(String::from);
                    let reason = t
                        .get("reason")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    candidates.push((id, proc, hash, reason));
                }
            }
        }
        for entry in self.audit.get_recent_entries(100).into_iter().rev() {
            if entry.event_type == "MESH_THREAT_BROADCAST"
                || entry.event_type == "MESH_THREAT_RECEIVED"
                || entry.event_type == "THREAT_DETECTED"
            {
                let id = entry
                    .data
                    .get("threat_id")
                    .or_else(|| entry.data.get("id"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| format!("audit-{}", entry.timestamp.timestamp_micros()));
                if self.dismissed_gossip_ids.contains(&id) {
                    continue;
                }
                let proc = entry
                    .data
                    .get("process_name")
                    .and_then(|v| v.as_str())
                    .map(String::from);
                let hash = entry
                    .data
                    .get("hash")
                    .or_else(|| entry.data.get("hash_blake3"))
                    .and_then(|v| v.as_str())
                    .map(String::from);
                let reason = entry
                    .data
                    .get("reason")
                    .or_else(|| entry.data.get("summary"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                candidates.push((id, proc, hash, reason));
            }
        }

        let rea = crate::rea::global_rea_engine();
        let mut purged_procs = std::collections::HashSet::new();
        let mut disk_probes = 0usize;
        for (id, proc, hash, reason) in candidates {
            let extracted = proc
                .as_deref()
                .or_else(|| crate::rea::extract_process_from_summary(&reason));
            let proc_str = extracted.unwrap_or("").trim();
            let proc_base = if !proc_str.is_empty() {
                Some(
                    std::path::Path::new(proc_str)
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or(proc_str)
                        .to_ascii_lowercase(),
                )
            } else {
                None
            };
            let is_benign_direct = if !proc_str.is_empty() {
                crate::rea::is_rea_benign_system_or_dev_process(proc_str, Some(&reason))
            } else {
                crate::rea::is_rea_benign_system_or_dev_process("<unknown process>", Some(&reason))
            };
            let is_already_clean = is_benign_direct
                || proc_base
                    .as_ref()
                    .map(|b| self.rea_adjudicated_clean_procs.contains(b))
                    .unwrap_or(false);

            if is_already_clean {
                if let Some(ref b) = proc_base {
                    self.rea_adjudicated_clean_procs.insert(b.clone());
                }
                self.dismissed_gossip_ids.insert(id.clone());
                let cand_p = if !proc_str.is_empty() {
                    Some(proc_str)
                } else {
                    proc.as_deref()
                };
                let _ =
                    self.memory
                        .delete_threat_by_id_or_pattern(Some(&id), cand_p, hash.as_deref());
                if let Some(p) = cand_p {
                    if purged_procs.insert(p.to_ascii_lowercase()) {
                        let _ = self.memory.delete_threats_matching_process_substring(p);
                        // Also record a lightweight REA report and ConsensusFinding once per benign process
                        let (_, rea_summary, rea_hash) =
                            rea.adjudicate_process_or_binary_alert(Some(p), None, Some(&reason));
                        let fh = rea_hash
                            .or_else(|| hash.clone())
                            .filter(|h| !h.is_empty())
                            .unwrap_or_else(|| {
                                blake3::hash(format!("rea:adjudicated:clean:{}", p).as_bytes())
                                    .to_hex()
                                    .to_string()
                            });
                        let finding = osoosi_types::ConsensusFinding {
                            id: format!("CONS-BENIGN-{}", &fh[..fh.len().min(12)]),
                            hash_blake3: fh,
                            process_name: Some(p.to_string()),
                            file_path: None,
                            verdict: "benign".to_string(),
                            confidence: 0.01,
                            detector_count: 0,
                            voters_summary: format!(
                                "Veto [REA-Voter + All-Voter Consensus]: {}",
                                rea_summary
                            ),
                            action_taken: "ignored_and_allowed".to_string(),
                            evaluated_at: chrono::Utc::now(),
                        };
                        let _ = self.memory.record_consensus_finding(&finding);
                    }
                }
                dropped += 1;
                continue;
            }

            static REA_PROBED_CANDIDATE_IDS: std::sync::OnceLock<dashmap::DashSet<String>> =
                std::sync::OnceLock::new();
            let probed_set = REA_PROBED_CANDIDATE_IDS.get_or_init(dashmap::DashSet::new);
            if probed_set.contains(&id) {
                continue;
            }
            if disk_probes >= 6 {
                continue;
            }
            disk_probes += 1;
            if probed_set.len() > 4096 {
                probed_set.clear();
            }
            probed_set.insert(id.clone());

            let cand_p = if !proc_str.is_empty() {
                Some(proc_str)
            } else {
                proc.as_deref()
            };
            let (mut should_drop, mut rea_summary, resolved_hash) =
                rea.adjudicate_process_or_binary_alert(cand_p, None, Some(&reason));
            let rea_eval = rea.evaluate_detector_candidate(
                "ThreatIntelligence",
                cand_p.unwrap_or("unknown"),
                &reason,
                0.85,
            );
            if rea_eval.benign_veto {
                should_drop = true;
                rea_summary = rea_eval.explanation.clone();
            }

            if should_drop {
                if let Some(ref b) = proc_base {
                    self.rea_adjudicated_clean_procs.insert(b.clone());
                }
                self.dismissed_gossip_ids.insert(id.clone());
                let final_hash = resolved_hash.as_deref().or(hash.as_deref());
                let _ = self
                    .memory
                    .delete_threat_by_id_or_pattern(Some(&id), cand_p, final_hash);
                if let Some(p) = cand_p {
                    if purged_procs.insert(p.to_ascii_lowercase()) {
                        let _ = self.memory.record_false_positive_pattern(
                            Some(p),
                            final_hash,
                            "autonomous_rea",
                        );
                        let _ = self.memory.delete_threats_matching_process_substring(p);
                        let fh = final_hash
                            .filter(|h| !h.is_empty())
                            .map(|h| h.to_string())
                            .unwrap_or_else(|| {
                                blake3::hash(format!("rea:adjudicated:clean:{}", p).as_bytes())
                                    .to_hex()
                                    .to_string()
                            });
                        let finding = osoosi_types::ConsensusFinding {
                            id: format!("CONS-BENIGN-{}", &fh[..fh.len().min(12)]),
                            hash_blake3: fh,
                            process_name: Some(p.to_string()),
                            file_path: None,
                            verdict: "benign".to_string(),
                            confidence: 0.01,
                            detector_count: 0,
                            voters_summary: format!(
                                "Veto [REA-Voter + All-Voter Consensus]: {}",
                                rea_summary
                            ),
                            action_taken: "ignored_and_allowed".to_string(),
                            evaluated_at: chrono::Utc::now(),
                        };
                        let _ = self.memory.record_consensus_finding(&finding);
                    }
                }
                dropped += 1;
            } else if !id.starts_with("audit-") && !reason.is_empty() {
                let ojev_vote = crate::rea::evaluate_openjev_consensus_vote(
                    cand_p.unwrap_or("unknown"),
                    "ThreatIntelligence",
                    &reason,
                );
                if !reason.contains("[REA-Voter]") {
                    let mut enriched = format!(
                        "{}; {} (verdict={}, seal={})",
                        reason,
                        rea_eval.explanation,
                        rea_eval.verdict,
                        &rea_eval.rea_seal_blake3[..rea_eval.rea_seal_blake3.len().min(16)]
                    );
                    if !reason.contains("[OpenJEV-Voter]") && !ojev_vote.benign_veto {
                        enriched.push_str("; ");
                        enriched.push_str(&ojev_vote.reason);
                    }
                    let _ = self.memory.update_threat_reason(&id, &enriched);
                }
                if let Some(after_file) = reason.split("file=").nth(1) {
                    let fp = after_file
                        .split([';', '|', '\n', '\r'])
                        .next()
                        .unwrap_or("")
                        .trim()
                        .trim_matches('"');
                    if !fp.is_empty() {
                        let fp_buf = std::path::PathBuf::from(fp);
                        if fp_buf.is_file()
                            && !crate::blocking_manager::is_protected_or_benign_system_path(fp)
                        {
                            crate::rea::spawn_autonomous_rea_for_threat(
                                fp_buf,
                                format!("autonomous_rea_threat:{}", id),
                            );
                        }
                    }
                }
            }
        }

        if let Ok(mut buffer) = self.mesh_gossip_feed.write() {
            buffer.retain(|item| {
                if self.dismissed_gossip_ids.contains(&item.id) {
                    return false;
                }
                if item.status == "FALSE_POSITIVE"
                    || item.status == "REMEDIATED"
                    || item.status == "CLEARED"
                    || item.status == "IGNORED"
                {
                    return false;
                }
                if item.summary.contains("Veto Trusted Vendor")
                    || item.summary.contains("outside the vulnerable")
                    || item.summary.contains("CVE None")
                    || item.summary.contains("unknown v0.0.0 has known cves")
                    || item.summary.contains("cve-2009-2940")
                {
                    return false;
                }
                let ext_p = crate::rea::extract_process_from_summary(&item.summary);
                if let Some(p) = item.process_name.as_deref().or(ext_p) {
                    if crate::rea::is_rea_benign_system_or_dev_process(p, Some(&item.summary)) {
                        return false;
                    }
                    let b = std::path::Path::new(p)
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or(p)
                        .to_ascii_lowercase();
                    if self.rea_adjudicated_clean_procs.contains(&b) {
                        return false;
                    }
                }
                true
            });
        }

        let active_threat_ids: std::collections::HashSet<String> = self
            .memory
            .get_recent_threats(100)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|t| t.get("id").and_then(|v| v.as_str()).map(String::from))
            .collect();

        // Purge audit log of false positive threat detection, orphaned approvals, & gossip events
        self.audit.retain_entries(|entry| {
            if entry.event_type == "ACTION_PENDING_APPROVAL" {
                let tid = entry
                    .data
                    .get("threat_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if tid.is_empty()
                    || self.dismissed_gossip_ids.contains(tid)
                    || !active_threat_ids.contains(tid)
                {
                    return false;
                }
            }
            if entry.event_type == "MESH_THREAT_BROADCAST"
                || entry.event_type == "MESH_THREAT_RECEIVED"
                || entry.event_type == "THREAT_DETECTED"
            {
                if let Some(tid) = entry
                    .data
                    .get("threat_id")
                    .or_else(|| entry.data.get("id"))
                    .and_then(|v| v.as_str())
                {
                    if self.dismissed_gossip_ids.contains(tid) {
                        return false;
                    }
                }
                let proc = entry.data.get("process_name").and_then(|v| v.as_str());
                let reason_opt = entry.data.get("reason").and_then(|v| v.as_str());
                let summary_opt = entry
                    .data
                    .get("summary")
                    .or_else(|| entry.data.get("message"))
                    .and_then(|v| v.as_str());
                let combined_reason = match (reason_opt, summary_opt) {
                    (Some(r), Some(s)) if r != s => Some(format!("{} | {}", r, s)),
                    (Some(r), _) => Some(r.to_string()),
                    (None, Some(s)) => Some(s.to_string()),
                    (None, None) => None,
                };
                let summary = combined_reason.as_deref();

                let ext = summary.and_then(crate::rea::extract_process_from_summary);
                let cand_p = proc.or(ext);

                if let Some(p) = cand_p {
                    if crate::rea::is_rea_benign_system_or_dev_process(p, summary) {
                        return false;
                    }
                    let b = std::path::Path::new(p)
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or(p)
                        .to_ascii_lowercase();
                    if self.rea_adjudicated_clean_procs.contains(&b) {
                        return false;
                    }
                } else if let Some(s) = summary {
                    if crate::rea::is_rea_benign_system_or_dev_process("<unknown process>", Some(s))
                    {
                        return false;
                    }
                }
            }
            true
        });

        dropped
    }

    /// Resolve candidate process name and hash for a gossip/threat item, track in `dismissed_gossip_ids`,
    /// and immediately drop matching items from the in-memory gossip buffer.
    pub fn resolve_and_dismiss_gossip_item(
        &self,
        threat_id: &str,
    ) -> (Option<String>, Option<String>) {
        self.dismissed_gossip_ids.insert(threat_id.to_string());
        let mut resolved_proc = None;
        let mut resolved_hash = None;

        if let Ok(mut buffer) = self.mesh_gossip_feed.write() {
            for item in buffer.iter() {
                if item.id == threat_id
                    || item.hash_blake3.as_deref() == Some(threat_id)
                    || item.process_name.as_deref() == Some(threat_id)
                {
                    if resolved_proc.is_none() {
                        resolved_proc = item.process_name.clone();
                    }
                    if resolved_hash.is_none() {
                        resolved_hash = item.hash_blake3.clone();
                    }
                }
            }
            buffer.retain(|item| {
                !(item.id == threat_id
                    || item.hash_blake3.as_deref() == Some(threat_id)
                    || item.process_name.as_deref() == Some(threat_id))
            });
        }

        if resolved_proc.is_none() || resolved_hash.is_none() {
            for entry in self.audit.entries().iter().rev() {
                let e_id = entry
                    .data
                    .get("threat_id")
                    .or_else(|| entry.data.get("id"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| format!("audit-{}", entry.timestamp.timestamp_micros()));
                if e_id == threat_id {
                    if resolved_proc.is_none() {
                        resolved_proc = entry
                            .data
                            .get("process_name")
                            .and_then(|v| v.as_str())
                            .map(String::from);
                    }
                    if resolved_hash.is_none() {
                        resolved_hash = entry
                            .data
                            .get("hash")
                            .or_else(|| entry.data.get("hash_blake3"))
                            .and_then(|v| v.as_str())
                            .map(String::from);
                    }
                    break;
                }
            }
        }

        if resolved_proc.is_some() || resolved_hash.is_some() {
            for entry in self.audit.entries().iter() {
                let e_proc = entry.data.get("process_name").and_then(|v| v.as_str());
                let e_hash = entry
                    .data
                    .get("hash")
                    .or_else(|| entry.data.get("hash_blake3"))
                    .and_then(|v| v.as_str());
                let matches_proc =
                    resolved_proc.as_deref().is_some() && resolved_proc.as_deref() == e_proc;
                let matches_hash =
                    resolved_hash.as_deref().is_some() && resolved_hash.as_deref() == e_hash;
                if matches_proc || matches_hash {
                    let e_id = entry
                        .data
                        .get("threat_id")
                        .or_else(|| entry.data.get("id"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| format!("audit-{}", entry.timestamp.timestamp_micros()));
                    self.dismissed_gossip_ids.insert(e_id);
                }
            }
        }

        (resolved_proc, resolved_hash)
    }

    /// Mark a threat as false positive in the live gossip feed.
    pub fn mark_gossip_false_positive(&self, threat_id: &str) {
        let (proc, hash) = self.resolve_and_dismiss_gossip_item(threat_id);
        let _ = self.memory.record_false_positive_pattern(
            proc.as_deref(),
            hash.as_deref(),
            &self.trust.did().to_string(),
        );
        let _ = self.memory.delete_threat_by_id_or_pattern(
            Some(threat_id),
            proc.as_deref(),
            hash.as_deref(),
        );
    }

    /// Mark a threat as remediated in the live gossip feed.
    pub fn mark_gossip_remediated(&self, threat_id: &str) {
        let (proc, hash) = self.resolve_and_dismiss_gossip_item(threat_id);
        let _ = self.memory.delete_threat_by_id_or_pattern(
            Some(threat_id),
            proc.as_deref(),
            hash.as_deref(),
        );
    }
}
