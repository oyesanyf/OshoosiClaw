//! Attack graph construction from audit trail and policy graph.
//!
//! Builds nodes (hosts, processes, IPs, domains, threats) and edges for visualization.

use osoosi_audit::AuditTrail;
use osoosi_policy::Relationship;
use serde_json::{json, Value};
use std::collections::BTreeSet;

/// Build attack graph as nodes + edges for vis-network / D3.
pub fn build_attack_graph(
    audit: &AuditTrail,
    relationships: &[Relationship],
    threats: &[Value],
    limit: usize,
) -> Value {
    let limit = limit.clamp(1, 500);
    let mut nodes: BTreeSet<String> = BTreeSet::new();
    let mut edges: Vec<Value> = Vec::new();
    let mut node_labels: std::collections::HashMap<String, (String, String)> =
        std::collections::HashMap::new();

    // 1. Add policy graph relationships
    for rel in relationships.iter().take(limit) {
        let src = rel.source.clone();
        let tgt = rel.target.clone();
        nodes.insert(src.clone());
        nodes.insert(tgt.clone());
        node_labels.insert(src.clone(), (rel.source.clone(), "process".to_string()));
        node_labels.insert(tgt.clone(), (rel.target.clone(), "target".to_string()));
        edges.push(json!({
            "from": src,
            "to": tgt,
            "label": rel.interaction_type,
            "title": format!("{} (freq: {})", rel.interaction_type, rel.frequency),
            "causal": true,
            "confidence": 0.8,
        }));
    }

    // 2. Ingest active threats from SQLite memory store
    for threat in threats.iter().take(limit) {
        let id = threat
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let proc_name = threat
            .get("process_name")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or("System");
        let cve_id = threat
            .get("cve_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let confidence = threat
            .get("confidence")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.9);
        let reason = threat
            .get("reason")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let source_node = threat
            .get("source_node")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or("Local Node");
        let file_path = threat
            .get("file_path")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty());

        let threat_node = format!("threat:{}", id);
        let threat_label = if cve_id.is_empty() {
            format!("Threat ({:.0}%)", confidence * 100.0)
        } else {
            format!("{} ({:.0}%)", cve_id, confidence * 100.0)
        };

        nodes.insert(source_node.to_string());
        nodes.insert(proc_name.to_string());
        nodes.insert(threat_node.clone());

        node_labels.insert(
            source_node.to_string(),
            (source_node.to_string(), "host".to_string()),
        );
        node_labels.insert(
            proc_name.to_string(),
            (proc_name.to_string(), "process".to_string()),
        );
        node_labels.insert(
            threat_node.clone(),
            (threat_label, "threat".to_string()),
        );

        edges.push(json!({
            "from": source_node,
            "to": proc_name,
            "label": "spawned",
            "title": format!("{} spawned {}", source_node, proc_name),
        }));

        edges.push(json!({
            "from": proc_name,
            "to": threat_node,
            "label": "detected",
            "title": format!(
                "Threat detected (conf: {:.2}){}",
                confidence,
                if !reason.is_empty() {
                    format!(" — {}", reason)
                } else {
                    String::new()
                }
            ),
            "confidence": confidence,
            "causal": true,
            "reason": if reason.is_empty() { Value::Null } else { json!(reason) },
        }));

        if let Some(fp) = file_path {
            let fname = std::path::Path::new(fp)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(fp);
            let target_node = format!("file:{}", fname);
            nodes.insert(target_node.clone());
            node_labels.insert(
                target_node.clone(),
                (fname.to_string(), "target".to_string()),
            );
            edges.push(json!({
                "from": threat_node,
                "to": target_node,
                "label": "targeted",
                "title": format!("Targeted: {}", fname),
            }));
        }
    }

    // 3. Add audit-derived nodes and edges
    let entries = audit.entries();
    let mut count = 0u32;
    for entry in entries.iter().rev() {
        if count >= limit as u32 {
            break;
        }
        match entry.event_type.as_str() {
            "TELEMETRY_INGESTED" => {
                let ev_data = entry.data.get("data").and_then(|v| v.as_object());
                if let Some(data) = ev_data {
                    let computer = entry
                        .data
                        .get("computer")
                        .and_then(|v| v.as_str())
                        .unwrap_or("host")
                        .to_string();
                    let image = data
                        .get("Image")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let dst_ip = data
                        .get("DestinationIp")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let query = data
                        .get("QueryName")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();

                    let proc_name = if image.is_empty() {
                        "unknown".to_string()
                    } else {
                        std::path::Path::new(&image)
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or(&image)
                            .to_string()
                    };

                    nodes.insert(computer.clone());
                    nodes.insert(proc_name.clone());
                    node_labels.insert(computer.clone(), (computer.clone(), "host".to_string()));
                    node_labels.insert(
                        proc_name.clone(),
                        (proc_name.clone(), "process".to_string()),
                    );

                    if !dst_ip.is_empty() {
                        nodes.insert(dst_ip.clone());
                        node_labels.insert(dst_ip.clone(), (dst_ip.clone(), "ip".to_string()));
                        edges.push(json!({
                            "from": proc_name,
                            "to": dst_ip,
                            "label": "network",
                            "title": "NetworkConnect",
                        }));
                        count += 1;
                    }
                    if !query.is_empty() {
                        let domain = query.trim_end_matches('.').to_string();
                        if !domain.is_empty() {
                            nodes.insert(domain.clone());
                            node_labels
                                .insert(domain.clone(), (domain.clone(), "domain".to_string()));
                            edges.push(json!({
                                "from": proc_name,
                                "to": domain,
                                "label": "dns",
                                "title": "DnsQuery",
                            }));
                            count += 1;
                        }
                    }
                }
            }
            "THREAT_DETECTED" => {
                if let Some(data) = entry.data.as_object() {
                    let proc = data
                        .get("process_name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Threat")
                        .to_string();
                    let cve = data
                        .get("cve_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let conf = data
                        .get("confidence")
                        .and_then(|v| v.as_f64())
                        .unwrap_or(0.0);
                    let threat_id = format!("threat:{}", entry.timestamp.timestamp_millis());
                    let predicted = data
                        .get("predicted_next")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let reason = data.get("reason").and_then(|v| v.as_str()).unwrap_or("");
                    nodes.insert(proc.clone());
                    nodes.insert(threat_id.clone());
                    node_labels.insert(proc.clone(), (proc.clone(), "process".to_string()));
                    node_labels.insert(
                        threat_id.clone(),
                        (
                            format!(
                                "{} ({:.0}%)",
                                if cve.is_empty() { "Threat" } else { &cve },
                                conf * 100.0
                            ),
                            "threat".to_string(),
                        ),
                    );
                    edges.push(json!({
                        "from": proc,
                        "to": threat_id,
                        "label": "detected",
                        "title": format!("Threat detected (conf: {:.2}){}", conf,
                            if !reason.is_empty() { format!(" — {}", reason) } else { String::new() }),
                        "confidence": conf,
                        "causal": true,
                        "reason": if reason.is_empty() { Value::Null } else { json!(reason) },
                        "predicted_next": if predicted.is_empty() { Value::Null } else { json!(predicted) },
                    }));
                    count += 1;
                    // Causal chain: threat -> predicted next step
                    if !predicted.is_empty() {
                        let pred_id = format!("pred:{}", entry.timestamp.timestamp_millis());
                        nodes.insert(pred_id.clone());
                        node_labels.insert(
                            pred_id.clone(),
                            (predicted.clone(), "predicted".to_string()),
                        );
                        edges.push(json!({
                            "from": threat_id,
                            "to": pred_id,
                            "label": "leads_to",
                            "title": format!("Predicted: {}", predicted),
                            "causal": true,
                            "confidence": conf * 0.9,
                        }));
                        count += 1;
                    }
                }
            }
            "RESPONSE_ACTION" => {
                if let Some(data) = entry.data.as_object() {
                    let action = data
                        .get("type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("response")
                        .to_string();
                    let resp_id = format!("resp:{}", entry.timestamp.timestamp_millis());
                    nodes.insert(resp_id.clone());
                    node_labels.insert(resp_id.clone(), (action.clone(), "response".to_string()));
                    if let Some(pid) = data.get("pid").and_then(|v| v.as_u64()) {
                        let proc_node = format!("pid:{}", pid);
                        nodes.insert(proc_node.clone());
                        node_labels.insert(
                            proc_node.clone(),
                            (format!("PID {}", pid), "process".to_string()),
                        );
                        edges.push(json!({
                            "from": proc_node,
                            "to": resp_id,
                            "label": "action",
                            "title": action,
                        }));
                        count += 1;
                    }
                }
            }
            "TELEMETRY_SUMMARY" => {
                let computer = entry.data.get("computer").and_then(|v| v.as_str()).unwrap_or("host");
                let count_val = entry.data.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
                
                let summary_id = format!("summary:{}", entry.timestamp.timestamp_millis());
                nodes.insert(summary_id.clone());
                nodes.insert(computer.to_string());
                node_labels.insert(summary_id.clone(), (format!("{} events", count_val), "host".to_string()));
                node_labels.insert(computer.to_string(), (computer.to_string(), "host".to_string()));
                
                edges.push(json!({
                    "from": computer,
                    "to": summary_id,
                    "label": "activity",
                    "title": format!("Telemetry Summary: {} events scanned", count_val),
                }));
                count += 1;
            }
            "ACTIVITY_BOOT" => {
                let msg = entry.data.get("message").and_then(|v| v.as_str()).unwrap_or("Boot");
                let boot_id = format!("boot:{}", entry.timestamp.timestamp_millis());
                nodes.insert(boot_id.clone());
                node_labels.insert(boot_id.clone(), (msg.to_string(), "response".to_string()));
                count += 1;
            }
            _ => {}
        }
    }

    // 4. Build vis-network nodes array
    let node_list: Vec<Value> = node_labels
        .iter()
        .map(|(id, (label, node_type))| {
            let color = match node_type.as_str() {
                "host" => "#6366f1",
                "process" => "#8b5cf6",
                "ip" => "#f59e0b",
                "domain" => "#ec4899",
                "threat" => "#ef4444",
                "target" => "#f43f5e",
                "response" => "#10b981",
                "predicted" => "#f97316",
                _ => "#94a3b8",
            };
            json!({
                "id": id,
                "label": if label.chars().count() > 24 { format!("{}...", label.chars().take(21).collect::<String>()) } else { label.clone() },
                "title": label,
                "color": color,
                "group": node_type,
            })
        })
        .collect();

    json!({
        "nodes": node_list,
        "edges": edges,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_attack_graph_with_threats() {
        let audit = AuditTrail::new();
        let relationships = vec![];
        let threats = vec![json!({
            "id": "threat-101",
            "process_name": "mimikatz.exe",
            "cve_id": "CVE-2026-9999",
            "confidence": 0.95,
            "reason": "LSASS memory read detected",
            "source_node": "Node-Alpha",
            "file_path": "C:\\Windows\\Temp\\mimikatz.exe",
        })];

        let graph = build_attack_graph(&audit, &relationships, &threats, 10);
        let nodes = graph.get("nodes").and_then(|v| v.as_array()).expect("nodes array");
        let edges = graph.get("edges").and_then(|v| v.as_array()).expect("edges array");

        let node_ids: Vec<&str> = nodes.iter().filter_map(|n| n.get("id").and_then(|v| v.as_str())).collect();
        assert!(node_ids.contains(&"Node-Alpha"));
        assert!(node_ids.contains(&"mimikatz.exe"));
        assert!(node_ids.contains(&"threat:threat-101"));
        assert!(node_ids.contains(&"file:mimikatz.exe"));

        assert_eq!(edges.len(), 3);
        let labels: Vec<&str> = edges.iter().filter_map(|e| e.get("label").and_then(|v| v.as_str())).collect();
        assert!(labels.contains(&"spawned"));
        assert!(labels.contains(&"detected"));
        assert!(labels.contains(&"targeted"));
    }
}

