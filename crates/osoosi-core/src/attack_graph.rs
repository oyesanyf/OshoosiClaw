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

    // 2. Add audit-derived nodes and edges
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
            _ => {}
        }
    }

    // 3. Build vis-network nodes array
    let node_list: Vec<Value> = node_labels
        .iter()
        .map(|(id, (label, node_type))| {
            let color = match node_type.as_str() {
                "host" => "#6366f1",
                "process" => "#8b5cf6",
                "ip" => "#f59e0b",
                "domain" => "#ec4899",
                "threat" => "#ef4444",
                "response" => "#10b981",
                "predicted" => "#f97316",
                _ => "#94a3b8",
            };
            json!({
                "id": id,
                "label": if label.len() > 24 { format!("{}...", &label[..21]) } else { label.clone() },
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
