use axum::{
    extract::ConnectInfo,
    extract::{Path, Query, State},
    routing::{get, post},
    http::HeaderMap,
    Json, Router,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tower_http::services::ServeDir;
use tracing::info;
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::PathBuf;

/// Shared state for dashboard routes. When backend is set, uses real data.
#[derive(Clone)]
pub struct DashboardState {
    pub join_gate: Option<Arc<osoosi_wire::JoinGate>>,
    pub backend: Option<Arc<osoosi_core::EdrOrchestrator>>,
}

#[derive(Debug, Deserialize)]
struct TrafficConversationRequest {
    human_instruction: String,
    traffic_data: String,
}

#[derive(Debug, Deserialize, Default)]
struct AnalyzeCapturedQuery {
    #[serde(default = "default_limit")]
    limit: usize,
}
fn default_limit() -> usize {
    20
}

#[derive(Debug, Deserialize, Default)]
struct AttackGraphQuery {
    #[serde(default = "default_graph_limit")]
    limit: usize,
}
fn default_graph_limit() -> usize {
    100
}

#[derive(Debug, Deserialize)]
struct TriageDecideRequest {
    threat_id: String,
    action: String,
}

#[derive(Debug, Deserialize, Default)]
struct QueryParams {
    #[serde(default)]
    q: String,
}

pub async fn start_dashboard(port: u16) -> anyhow::Result<()> {
    start_dashboard_with_backend(port, None, None).await
}

pub async fn start_dashboard_with_join_gate(
    port: u16,
    join_gate: Option<Arc<osoosi_wire::JoinGate>>,
) -> anyhow::Result<()> {
    start_dashboard_with_backend(port, join_gate, None).await
}

pub async fn start_dashboard_with_backend(
    port: u16,
    join_gate: Option<Arc<osoosi_wire::JoinGate>>,
    backend: Option<Arc<osoosi_core::EdrOrchestrator>>,
) -> anyhow::Result<()> {
    let state = DashboardState { join_gate, backend };

    // Resolve dashboard/dist path — search aggressively
    let mut asset_path = PathBuf::from("dashboard/dist");

    // Allow explicit override via env
    if let Ok(custom) = std::env::var("OSOOSI_DASHBOARD_DIR") {
        let p = PathBuf::from(&custom);
        if p.exists() {
            asset_path = p;
        }
    }

    if !asset_path.exists() {
        // Search from exe location (up to 5 levels: handles target/release/osoosi.exe -> project root)
        if let Ok(exe) = std::env::current_exe() {
            let mut dir = exe.parent().map(|p| p.to_path_buf());
            for _ in 0..5 {
                if let Some(ref d) = dir {
                    let candidate = d.join("dashboard").join("dist");
                    if candidate.exists() {
                        asset_path = candidate;
                        break;
                    }
                    dir = d.parent().map(|p| p.to_path_buf());
                } else {
                    break;
                }
            }
        }
    }

    if !asset_path.exists() {
        // Search from CWD (up to 3 levels)
        if let Ok(cwd) = std::env::current_dir() {
            let mut dir = Some(cwd);
            for _ in 0..3 {
                if let Some(ref d) = dir {
                    let candidate = d.join("dashboard").join("dist");
                    if candidate.exists() {
                        asset_path = candidate;
                        break;
                    }
                    dir = d.parent().map(|p| p.to_path_buf());
                } else {
                    break;
                }
            }
        }
    }

    if asset_path.exists() {
        info!("Dashboard assets found at: {}", asset_path.display());
    } else {
        info!("Dashboard assets NOT found. API endpoints will work but no UI. Set OSOOSI_DASHBOARD_DIR or place files in dashboard/dist/");
    }

    let app = Router::new()
        .route("/api/status", get(get_status))
        .route("/api/threats", get(get_threats))
        .route("/api/mesh-stats", get(get_mesh_stats))
        .route("/api/pending-joins", get(get_pending_joins))
        .route("/api/pending-joins/:peer_id/allow", post(allow_peer))
        .route("/api/pending-joins/:peer_id/deny", post(deny_peer))
        .route("/api/quarantined-peers", get(get_quarantined_peers))
        .route("/api/quarantined-peers/:peer_id/release", post(release_quarantined_peer))
        .route("/api/quarantined-peers/:peer_id/false-positive", post(mark_quarantine_false_positive))
        .route("/api/repair-status", get(get_repair_status))
        .route("/api/backup-status", get(get_backup_status))
        .route("/api/malware-status", get(get_malware_status))
        .route("/api/malware-detections", get(get_malware_detections))
        .route("/api/malware-mesh-samples", get(get_malware_mesh_samples))
        .route("/api/model-training-status", get(get_model_training_status))
        .route("/api/privilege-status", get(get_privilege_status))
        .route("/api/activity", get(get_activity))
        .route("/api/traffic/conversation", post(post_traffic_conversation))
        .route("/api/traffic/analyze-captured", get(get_traffic_analyze_captured))
        .route("/api/attack-graph", get(get_attack_graph))
        .route("/api/agent/context", get(get_agent_context))
        .route("/api/agent/trigger-patch", post(post_agent_trigger_patch))
        .route("/api/triage/decide", post(post_triage_decide))
        .route("/api/query", get(get_query))
        .route("/api/threats/:threat_id/false-positive", post(post_threat_false_positive))
        .route("/api/behavioral/feedback", post(post_behavioral_feedback))
        .route("/api/behavioral/analyze", get(get_behavioral_analyze))
        .route("/api/behavioral/deep-dive", post(post_behavioral_deep_dive))
        .route("/api/consensus", get(get_consensus))
        .route("/api/mesh/broadcast", post(post_mesh_broadcast))
        .with_state(state)
        .fallback_service(ServeDir::new(asset_path));

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("OpenỌ̀ṣọ́ọ̀sì Dashboard listening on {} (local access: http://127.0.0.1:{})", addr, port);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;

    Ok(())
}

async fn get_status(State(state): State<DashboardState>) -> Json<Value> {
    match &state.backend {
        Some(orch) => {
            let did = orch.trust().did().id.clone();
            let uptime = orch.uptime();
            let uptime_str = format_uptime(uptime);
            let (_, _, _, _, pending, _) = orch.repair_status();
            let repair = if pending > 0 { "Monitoring (patches pending)" } else { "Monitoring" };
            let merkle_root = orch.audit().root();
            let chain_verified = orch.audit().verify();
            Json(json!({
                "status": "Healthy",
                "live": true,
                "node_id": did,
                "uptime": uptime_str,
                "repair_engine": repair,
                "merkle_root": if merkle_root.len() > 16 { format!("{}...{}", &merkle_root[..8], &merkle_root[merkle_root.len()-8..]) } else { merkle_root },
                "chain_verified": chain_verified
            }))
        }
        None => Json(json!({
            "status": "Healthy",
            "live": false,
            "node_id": "did:osoosi:... (run agent for live data)",
            "uptime": "—",
            "repair_engine": "Idle",
            "merkle_root": null,
            "chain_verified": false
        })),
    }
}

fn format_uptime(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    }
}

async fn get_pending_joins(State(state): State<DashboardState>) -> Json<Value> {
    match &state.join_gate {
        Some(gate) => match gate.pending_joins() {
            Ok(pending) => Json(serde_json::to_value(&pending).unwrap_or(json!([]))),
            Err(_) => Json(json!([])),
        },
        None => Json(json!([])),
    }
}

async fn allow_peer(
    State(state): State<DashboardState>,
    Path(peer_id): Path<String>,
) -> Json<Value> {
    match &state.join_gate {
        Some(gate) => match gate.allow(&peer_id).await {
            Ok(()) => Json(json!({"ok": true, "message": "Peer approved"})),
            Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
        },
        None => Json(json!({"ok": false, "error": "Join gate not active (run agent with dashboard)"})),
    }
}

async fn deny_peer(
    State(state): State<DashboardState>,
    Path(peer_id): Path<String>,
) -> Json<Value> {
    match &state.join_gate {
        Some(gate) => match gate.deny(&peer_id) {
            Ok(()) => Json(json!({"ok": true, "message": "Peer denied"})),
            Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
        },
        None => Json(json!({"ok": false, "error": "Join gate not active (run agent with dashboard)"})),
    }
}

async fn get_quarantined_peers(State(state): State<DashboardState>) -> Json<Value> {
    match &state.join_gate {
        Some(gate) => match gate.quarantined_peers() {
            Ok(peers) => Json(serde_json::to_value(&peers).unwrap_or(json!([]))),
            Err(_) => Json(json!([])),
        },
        None => Json(json!([])),
    }
}

async fn release_quarantined_peer(
    State(state): State<DashboardState>,
    Path(peer_id): Path<String>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Json<Value> {
    if let Err(msg) = authorize_quarantine_release(remote, &headers) {
        return Json(json!({"ok": false, "error": msg}));
    }
    match &state.join_gate {
        Some(gate) => match gate.release_peer(&peer_id) {
            Ok(()) => Json(json!({"ok": true, "message": "Peer released from quarantine"})),
            Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
        },
        None => Json(json!({"ok": false, "error": "Join gate not active (run agent with dashboard)"})),
    }
}

async fn mark_quarantine_false_positive(
    State(state): State<DashboardState>,
    Path(peer_id): Path<String>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Json<Value> {
    if let Err(msg) = authorize_quarantine_release(remote, &headers) {
        return Json(json!({"ok": false, "error": msg}));
    }
    match &state.join_gate {
        Some(gate) => match gate.mark_false_positive(&peer_id) {
            Ok(()) => Json(json!({"ok": true, "message": "Peer released and marked false positive"})),
            Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
        },
        None => Json(json!({"ok": false, "error": "Join gate not active (run agent with dashboard)"})),
    }
}

fn authorize_quarantine_release(remote: SocketAddr, headers: &HeaderMap) -> Result<(), String> {
    // Default: only local host can release quarantine.
    if remote.ip().is_loopback() {
        return Ok(());
    }

    let cfg = osoosi_types::load_quarantine_admin_config();

    // Optional dedicated admin host mode:
    // - OSOOSI_QUARANTINE_ADMIN_KEY must be set
    // - request header "x-osoosi-quarantine-key" must match
    // - remote IP must be allowlisted in OSOOSI_QUARANTINE_ADMIN_HOSTS
    let key = std::env::var("OSOOSI_QUARANTINE_ADMIN_KEY").unwrap_or_else(|_| cfg.key.clone());
    if key.trim().is_empty() {
        return Err("Forbidden: quarantine release allowed only from localhost".to_string());
    }
    let provided = headers
        .get("x-osoosi-quarantine-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    if provided != key {
        return Err("Unauthorized: invalid quarantine admin key".to_string());
    }

    let allow_hosts = std::env::var("OSOOSI_QUARANTINE_ADMIN_HOSTS")
        .unwrap_or_else(|_| cfg.hosts.join(","));
    let allowed: Vec<String> = allow_hosts
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();
    if allowed.is_empty() {
        return Err("Forbidden: remote quarantine release requires OSOOSI_QUARANTINE_ADMIN_HOSTS".to_string());
    }

    let remote_ip = remote.ip().to_string();
    if !allowed.iter().any(|h| h == &remote_ip) {
        return Err(format!("Forbidden: host {} is not in admin allowlist", remote_ip));
    }

    Ok(())
}

async fn get_threats(State(state): State<DashboardState>) -> Json<Value> {
    match &state.backend {
        Some(orch) => {
            let threats = orch
                .memory()
                .get_recent_threats(20)
                .unwrap_or_default();
            if threats.is_empty() {
                let entries = orch.audit().entries();
                let threat_entries: Vec<Value> = entries
                    .iter()
                    .rev()
                    .filter(|e| e.event_type == "THREAT_DETECTED")
                    .take(20)
                    .filter_map(|e| {
                        let d = e.data.as_object()?;
                        let id = d.get("id")?.as_str().unwrap_or("").to_string();
                        let cve_id = d.get("cve_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                        let process_name = d.get("process_name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                        let type_str: String = if process_name.is_empty() { "Threat".into() } else { process_name };
                        let confidence = d.get("confidence").and_then(|v| v.as_f64()).unwrap_or(0.0);
                        let ts = e.timestamp.to_rfc3339();
                        let source_node = d.get("source_node").and_then(|v| v.as_str()).unwrap_or("").to_string();
                        let reason = d.get("reason").and_then(|v| v.as_str()).unwrap_or("").to_string();
                        let predicted_next = d.get("predicted_next").and_then(|v| v.as_str()).unwrap_or("").to_string();
                        let file_path = d.get("image_path").or(d.get("file_path")).or(d.get("target_path")).and_then(|v| v.as_str()).map(String::from);
                        Some(json!({
                            "id": id,
                            "cve_id": cve_id,
                            "type": type_str,
                            "confidence": confidence,
                            "timestamp": ts,
                            "details": format!("Source: {}", source_node),
                            "source_node": source_node,
                            "file_path": file_path,
                            "reason": if reason.is_empty() { Value::Null } else { json!(reason) },
                            "predicted_next": if predicted_next.is_empty() { Value::Null } else { json!(predicted_next) }
                        }))
                    })
                    .collect();
                Json(Value::Array(threat_entries))
            } else {
                let formatted: Vec<Value> = threats
                    .into_iter()
                    .map(|t| {
                        let obj = t.as_object().cloned().unwrap_or_default();
                        let process_name = obj.get("process_name").and_then(|v| v.as_str()).unwrap_or("Threat");
                        let cve_id = obj.get("cve_id").and_then(|v| v.as_str()).unwrap_or("");
                        let reason = obj.get("reason").and_then(|v| v.as_str());
                        let predicted_next = obj.get("predicted_next").and_then(|v| v.as_str());
                        json!({
                            "id": obj.get("id"),
                            "type": process_name,
                            "cve_id": cve_id,
                            "confidence": obj.get("confidence"),
                            "timestamp": obj.get("timestamp"),
                            "details": format!("{} from {}", process_name, obj.get("source_node").and_then(|v| v.as_str()).unwrap_or("?")),
                            "source_node": obj.get("source_node"),
                            "reason": reason,
                            "predicted_next": predicted_next
                        })
                    })
                    .collect();
                Json(Value::Array(formatted))
            }
        }
        None => Json(json!([])),
    }
}

async fn post_traffic_conversation(
    State(state): State<DashboardState>,
    Json(req): Json<TrafficConversationRequest>,
) -> Json<Value> {
    let human_instruction = req.human_instruction.trim();
    let traffic_data = req.traffic_data.trim();
    if human_instruction.is_empty() || traffic_data.is_empty() {
        return Json(json!({
            "status": "fail",
            "msg": "human_instruction and traffic_data are required"
        }));
    }
    if !traffic_data.contains("<packet>") {
        return Json(json!({
            "status": "fail",
            "msg": "traffic_data must include '<packet>' marker"
        }));
    }

    match &state.backend {
        Some(orch) => {
            let mut out = orch.analyze_traffic_prompt(human_instruction, traffic_data);
            if let Some(obj) = out.as_object_mut() {
                obj.insert("msg".to_string(), json!("success"));
            }
            Json(out)
        }
        None => Json(json!({
            "status": "fail",
            "msg": "backend not active; run agent with dashboard backend"
        })),
    }
}

async fn get_traffic_analyze_captured(
    State(state): State<DashboardState>,
    Query(q): Query<AnalyzeCapturedQuery>,
) -> Json<Value> {
    match &state.backend {
        Some(orch) => Json(orch.analyze_captured_traffic(q.limit)),
        None => Json(json!({
            "status": "fail",
            "msg": "backend not active; run agent with dashboard backend",
            "events_analyzed": 0,
            "findings_count": 0,
            "findings": []
        })),
    }
}

async fn get_attack_graph(
    State(state): State<DashboardState>,
    Query(q): Query<AttackGraphQuery>,
) -> Json<Value> {
    match &state.backend {
        Some(orch) => Json(orch.attack_graph(q.limit)),
        None => Json(json!({ "nodes": [], "edges": [] })),
    }
}

async fn get_repair_status(State(state): State<DashboardState>) -> Json<Value> {
    match &state.backend {
        Some(orch) => {
            let (last_cve, last_state, last_sig, last_at, pending, last_error) = orch.repair_status();
            let remediation_hint = last_error.as_ref().and_then(|e| {
                if e.contains("Insufficient privilege") || e.contains("Administrator") || e.contains("root") {
                    #[cfg(target_os = "windows")]
                    { Some("Restart the agent as Administrator: Right-click terminal → Run as Administrator → run: osoosi-cli start".to_string()) }
                    #[cfg(not(target_os = "windows"))]
                    { Some("Restart the agent as root (e.g. sudo osoosi-cli start) to enable patching.".to_string()) }
                } else {
                    None
                }
            });
            Json(json!({
                "last_cve": last_cve,
                "last_state": last_state,
                "last_sig": last_sig,
                "last_at": last_at,
                "pending_count": pending,
                "last_error": last_error,
                "remediation_hint": remediation_hint,
                "status": if pending > 0 { "patches_pending" } else { "monitoring" }
            }))
        }
        None => Json(json!({
            "last_cve": null,
            "last_state": null,
            "last_sig": null,
            "last_at": null,
            "pending_count": 0,
            "last_error": null,
            "remediation_hint": null,
            "status": "idle"
        })),
    }
}

async fn get_consensus(State(state): State<DashboardState>) -> Json<Value> {
    match &state.backend {
        Some(orch) => {
            let status = orch.policy_consensus_status().await;
            Json(serde_json::to_value(&status).unwrap_or(json!({})))
        }
        None => Json(json!({})),
    }
}

#[derive(Debug, Deserialize)]
struct BroadcastRequest {
    summary: String,
}

async fn post_mesh_broadcast(
    State(state): State<DashboardState>,
    Json(req): Json<BroadcastRequest>,
) -> Json<Value> {
    match &state.backend {
        Some(orch) => match orch.broadcast_intelligence(req.summary).await {
            Ok(()) => Json(json!({ "ok": true })),
            Err(e) => Json(json!({ "ok": false, "error": e.to_string() })),
        },
        None => Json(json!({ "ok": false, "error": "Backend not active" })),
    }
}

async fn get_backup_status(State(state): State<DashboardState>) -> Json<Value> {
    match &state.backend {
        Some(orch) => {
            let (status, message, last_at, target) = orch.backup_status();
            Json(json!({
                "status": status.unwrap_or_else(|| "unknown".to_string()),
                "message": message,
                "last_at": last_at,
                "target": target,
                "live": true
            }))
        }
        None => Json(json!({
            "status": "unknown",
            "message": null,
            "last_at": null,
            "target": null,
            "live": false
        })),
    }
}

async fn get_malware_status(State(state): State<DashboardState>) -> Json<Value> {
    match &state.backend {
        Some(orch) => {
            let scanner = orch.malware_scanner();
            let stats = scanner.stats();
            let clamav_clean_count = orch.audit().entries()
                .iter()
                .filter(|e| e.event_type == "CLAMAV_CLEAN")
                .count();
            Json(json!({
                "total_scanned": stats.total_scanned,
                "total_skipped": stats.total_skipped,
                "total_malware": stats.total_malware,
                "clamav_clean_count": clamav_clean_count,
                "model_loaded": stats.model_loaded,
                "magika_available": stats.magika_available,
                "live": true
            }))
        }
        None => Json(json!({
            "total_scanned": 0,
            "total_skipped": 0,
            "total_malware": 0,
            "clamav_clean_count": 0,
            "model_loaded": false,
            "magika_available": false,
            "live": false
        })),
    }
}

async fn get_malware_detections(State(state): State<DashboardState>) -> Json<Value> {
    match &state.backend {
        Some(orch) => {
            let scanner = orch.malware_scanner();
            let detections = scanner.recent_detections();
            let items: Vec<Value> = detections.iter().take(20).map(|d| {
                json!({
                    "file_path": d.file_path,
                    "file_hash": d.file_hash,
                    "magika_label": d.magika_label,
                    "malware_type": d.malware_type,
                    "ml_score": d.ml_score,
                    "signature_score": d.signature_score,
                    "combined_score": d.combined_score,
                    "evasion": d.evasion_indicators,
                    "yara_available": d.yara_available,
                    "yara_matches": d.yara_matches,
                    "timestamp": d.timestamp,
                })
            }).collect();
            Json(Value::Array(items))
        }
        None => Json(json!([])),
    }
}

async fn get_malware_mesh_samples(State(state): State<DashboardState>) -> Json<Value> {
    match &state.backend {
        Some(orch) => {
            let memory = orch.memory();
            match (memory.malware_sample_count(), memory.get_malware_samples(500)) {
                (Ok(count), Ok(samples)) => Json(json!({
                    "count": count,
                    "samples": samples.iter().take(50).map(|s| json!({
                        "file_hash": &s.file_hash[..s.file_hash.len().min(16)],
                        "source_node": &s.source_node[..s.source_node.len().min(12)],
                        "label": s.label,
                        "feature_version": s.feature_version,
                        "timestamp": s.timestamp.to_rfc3339(),
                    })).collect::<Vec<_>>(),
                    "live": true
                })),
                _ => Json(json!({ "count": 0, "samples": [], "live": true })),
            }
        }
        None => Json(json!({ "count": 0, "samples": [], "live": false })),
    }
}

async fn get_model_training_status(State(state): State<DashboardState>) -> Json<Value> {
    match &state.backend {
        Some(orch) => {
            let (status, last_attempt, last_success, sample_count, feature_count, last_error) =
                orch.model_training_status();
            Json(json!({
                "status": status.unwrap_or_else(|| "unknown".to_string()),
                "last_attempt": last_attempt,
                "last_success": last_success,
                "sample_count": sample_count,
                "feature_count": feature_count,
                "last_error": last_error,
                "live": true
            }))
        }
        None => Json(json!({
            "status": "unknown",
            "last_attempt": null,
            "last_success": null,
            "sample_count": 0,
            "feature_count": 0,
            "last_error": null,
            "live": false
        })),
    }
}

async fn get_privilege_status() -> Json<Value> {
    let status = osoosi_core::privilege::check_privileges();
    Json(json!({
        "platform": status.platform,
        "can_read_events": status.can_read_events,
        "can_apply_patches": status.can_apply_patches,
        "is_elevated": status.is_elevated,
        "details": status.details,
    }))
}

async fn get_activity(State(state): State<DashboardState>) -> Json<Value> {
    match &state.backend {
        Some(orch) => {
            let entries = orch.audit().entries();
            let items: Vec<Value> = entries
                .iter()
                .rev()
                .take(50)
                .map(|e| {
                    let summary = match e.event_type.as_str() {
                        "THREAT_DETECTED" => {
                            let proc = e.data.get("process_name").and_then(|v| v.as_str()).unwrap_or("Threat");
                            let cve = e.data.get("cve_id").and_then(|v| v.as_str()).unwrap_or("");
                            if !cve.is_empty() {
                                format!("{} — {}", proc, cve)
                            } else {
                                format!("Threat: {}", proc)
                            }
                        }
                        "TELEMETRY_INGESTED" => {
                            let ev = e.data.get("event_id").and_then(|v| v.as_i64()).unwrap_or(0);
                            format!("Event {} scanned", ev)
                        }
                        "RESPONSE_ACTION" => {
                            let t = e.data.get("type").and_then(|v| v.as_str()).unwrap_or("Response");
                            format!("Response: {}", t)
                        }
                        "MALWARE_DETECTED" => {
                            let fp = e.data.get("file_path").and_then(|v| v.as_str()).unwrap_or("?");
                            let fname = fp.rsplit(['\\', '/']).next().unwrap_or(fp);
                            let mt = e.data.get("malware_type").and_then(|v| v.as_str()).unwrap_or("?");
                            format!("{} — {}", fname, mt)
                        }
                        "CLAMAV_CLEAN" => {
                            let fp = e.data.get("file_path").and_then(|v| v.as_str()).unwrap_or("?");
                            let fname = fp.rsplit(['\\', '/']).next().unwrap_or(fp);
                            let ctx = e.data.get("context").and_then(|v| v.as_str()).unwrap_or("FileWatcher");
                            format!("ClamAV clean: {} — allowed ({})", fname, ctx)
                        }
                        "BEHAVIORAL_ALERT" => {
                            let sent = e.data.get("sentence").and_then(|v| v.as_str()).unwrap_or("?");
                            let fname = sent.chars().take(60).collect::<String>();
                            let score = e.data.get("score").and_then(|v| v.as_f64()).unwrap_or(0.0);
                            format!("Behavioral: {} (score={:.0}%)", fname, score * 100.0)
                        }
                        "repair" => "Repair Engine".to_string(),
                        _ => e.event_type.clone(),
                    };
                    let mut item = json!({
                        "type": e.event_type,
                        "timestamp": e.timestamp.to_rfc3339(),
                        "summary": summary,
                        "is_threat": e.event_type == "THREAT_DETECTED" || e.event_type == "BEHAVIORAL_ALERT"
                    });
                    if let Some(obj) = item.as_object_mut() {
                        if e.event_type == "MALWARE_DETECTED" || e.event_type == "CLAMAV_CLEAN" || e.event_type == "BEHAVIORAL_ALERT" {
                            if let Some(fp) = e.data.get("file_path").and_then(|v| v.as_str()) {
                                obj.insert("file_path".to_string(), json!(fp));
                            }
                        }
                        if e.event_type == "CLAMAV_CLEAN" {
                            obj.insert("is_clamav_clean".to_string(), json!(true));
                        }
                        if e.event_type == "THREAT_DETECTED" {
                            if let Some(fp) = e.data.get("image_path").or(e.data.get("file_path")).or(e.data.get("target_path")).and_then(|v| v.as_str()) {
                                obj.insert("file_path".to_string(), json!(fp));
                            }
                            if let Some(cve) = e.data.get("cve_id").and_then(|v| v.as_str()) {
                                obj.insert("cve_id".to_string(), json!(cve));
                            }
                        }
                    }
                    item
                })
                .collect();
            Json(Value::Array(items))
        }
        None => Json(json!([])),
    }
}

async fn get_mesh_stats(State(state): State<DashboardState>) -> Json<Value> {
    match &state.backend {
        Some(orch) => {
            let chain_verified = orch.audit().verify();
            Json(json!({
                "peer_count": orch.mesh_peer_count(),
                "trust_verified": chain_verified,
                "live": true
            }))
        }
        None => Json(json!({
            "peer_count": 0,
            "trust_verified": false,
            "live": false
        })),
    }
}

/// Consolidated context for LLM agent: status, pending joins, threats, malware, repair.
async fn get_agent_context(State(state): State<DashboardState>) -> Json<Value> {
    match (&state.backend, &state.join_gate) {
        (Some(orch), Some(gate)) => {
            let (last_cve, last_state, _, last_at, pending, last_error) = orch.repair_status();
            let pending_joins = gate.pending_joins().unwrap_or_default();
            let threats = orch.memory().get_recent_threats(10).unwrap_or_default();
            let detections = orch.malware_scanner().recent_detections();
            let mw_stats = orch.malware_scanner().stats();
            let traffic_events = orch.recent_traffic_events_count(100);
            Json(json!({
                "status": "live",
                "uptime_secs": orch.uptime().as_secs(),
                "peer_count": orch.mesh_peer_count(),
                "pending_joins": pending_joins,
                "repair": {
                    "pending_count": pending,
                    "last_state": last_state,
                    "last_cve": last_cve,
                    "last_at": last_at,
                    "last_error": last_error,
                },
                "traffic_capture": {
                    "available": traffic_events > 0,
                    "recent_events_count": traffic_events,
                    "hint": "Call analyze_captured_traffic to analyze captured Sysmon traffic (no pasting).",
                },
                "threats": threats,
                "malware_detections": detections.iter().map(|d| json!({
                    "file_path": d.file_path,
                    "malware_type": d.malware_type,
                    "combined_score": d.combined_score,
                })).collect::<Vec<_>>(),
                "malware_stats": { "scanned": mw_stats.total_scanned, "skipped": mw_stats.total_skipped, "malware_count": mw_stats.total_malware },
                "consensus_summary": orch.policy_consensus_status().await.iter().map(|(id, msgs)| {
                    let votes = msgs.iter().filter(|m| matches!(m, osoosi_types::PolicyConsensusMessage::Vote(_))).count();
                    json!({ "policy_id": id, "mesh_votes": votes })
                }).collect::<Vec<_>>(),
            }))
        }
        _ => Json(json!({
            "status": "idle",
            "message": "Run agent with dashboard for full context"
        })),
    }
}

/// Mark threat as false positive (federated learning).
async fn post_threat_false_positive(
    State(state): State<DashboardState>,
    Path(threat_id): Path<String>,
) -> Json<Value> {
    match &state.backend {
        Some(orch) => {
            let source = orch.trust().did().id.clone();
            
            // If it's a behavioral threat, we might have the sentence stored in metadata or audit.
            // For now, we mainly mark it in the main threat store.
            match orch.memory().mark_threat_false_positive(&threat_id, &source) {
                Ok(true) => Json(json!({"ok": true, "message": "Threat marked as false positive"})),
                Ok(false) => Json(json!({"ok": false, "error": "Threat not found"})),
                Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
            }
        }
        None => Json(json!({"ok": false, "error": "Backend not running"})),
    }
}

#[derive(Debug, Deserialize)]
struct BehavioralFeedbackRequest {
    sentence: String,
    is_suspicious: bool,
}

/// Explicit behavioral feedback (Continuous Learning).
async fn post_behavioral_feedback(
    State(state): State<DashboardState>,
    Json(req): Json<BehavioralFeedbackRequest>,
) -> Json<Value> {
    match &state.backend {
        Some(orch) => {
            orch.learn_behavior(&req.sentence, req.is_suspicious);
            Json(json!({"ok": true, "message": "Behavioral feedback recorded"}))
        }
        None => Json(json!({"ok": false, "error": "Backend not running"})),
    }
}

#[derive(Debug, Deserialize)]
struct BehavioralAnalyzeParams {
    mode: Option<osoosi_behavioral::AnalysisMode>,
    #[allow(dead_code)]
    count: Option<usize>,
}

async fn get_behavioral_analyze(
    State(state): State<DashboardState>,
    Query(q): Query<BehavioralAnalyzeParams>,
) -> Json<Value> {
    match &state.backend {
        Some(orch) => {
            let mode = q.mode.unwrap_or(osoosi_behavioral::AnalysisMode::Analyze);
            // We need some recent events to analyze.
            let events = vec![]; // Placeholder, we should fetch from audit or log_reader.
            match orch.analyzer().generate_investigative_prompts(mode, &events).await {
                Ok(prompts) => Json(json!({"ok": true, "prompts": prompts})),
                Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
            }
        }
        None => Json(json!({"ok": false, "error": "Backend not running"})),
    }
}

#[derive(Debug, Deserialize)]
struct BehavioralDeepDiveRequest {
    prompt: String,
    #[allow(dead_code)]
    context_samples: Vec<String>,
}

async fn post_behavioral_deep_dive(
    State(state): State<DashboardState>,
    Json(req): Json<BehavioralDeepDiveRequest>,
) -> Json<Value> {
    match &state.backend {
        Some(orch) => {
             // In current BehavioralAnalyzer, Deep Dive doesn't take context_samples directly in method call but in format_events.
             // We'll adapt here to match method signature.
            let events = vec![]; // Placeholder
            match orch.analyzer().perform_deep_analysis(&req.prompt, &events).await {
                Ok(r) => Json(json!({"ok": true, "report": r})),
                Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
            }
        }
        None => Json(json!({"ok": false, "error": "Backend not running"})),
    }
}

async fn get_query(
    State(state): State<DashboardState>,
    Query(params): Query<QueryParams>,
) -> Json<Value> {
    match &state.backend {
        Some(orch) => {
            let results = orch.memory().query_json(&params.q, &[]).unwrap_or_default();
            Json(json!({"ok": true, "results": results}))
        }
        None => Json(json!({"ok": false, "error": "Backend not running"})),
    }
}

async fn post_agent_trigger_patch(
    State(state): State<DashboardState>,
) -> Json<Value> {
    match &state.backend {
        Some(orch) => {
            orch.trigger_patch_discovery();
            Json(json!({"ok": true, "message": "Patch discovery triggered"}))
        }
        None => Json(json!({"ok": false, "error": "Backend not running"})),
    }
}

async fn post_triage_decide(
    State(state): State<DashboardState>,
    Json(req): Json<TriageDecideRequest>,
) -> Json<Value> {
    match &state.backend {
        Some(orch) => {
            use std::str::FromStr;
            let action = match osoosi_types::ResponseAction::from_str(&req.action) {
                Ok(a) => a,
                Err(_) => return Json(json!({"ok": false, "error": "Invalid action"})),
            };
            match orch.triage_decide(&req.threat_id, action).await {
                Ok(result) => Json(json!({"ok": result, "message": if result { format!("Triage action {} applied", req.action) } else { "Threat not found or already triaged".to_string() }})),
                Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
            }
        }
        None => Json(json!({"ok": false, "error": "Backend not running"})),
    }
}
