use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{api_error_json, DashboardState};

#[derive(Debug, Deserialize)]
pub struct TrafficConversationRequest {
    pub human_instruction: String,
    pub traffic_data: String,
}

#[derive(Debug, Deserialize, Default)]
pub struct AnalyzeCapturedQuery {
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_limit() -> usize {
    20
}

pub static LIVE_HAR_CACHE: std::sync::OnceLock<osoosi_core::parking_lot::RwLock<Option<Value>>> =
    std::sync::OnceLock::new();
static HAR_COLLECTOR_STARTED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
static HAR_SWEEP_SEQUENCE: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);
static HAR_REFRESH_MUTEX: std::sync::OnceLock<osoosi_core::parking_lot::Mutex<()>> =
    std::sync::OnceLock::new();

pub fn build_w3c_har_document(entries: &[Value]) -> Value {
    let mut har_entries = Vec::with_capacity(entries.len());
    for entry in entries {
        let started_at = entry.get("started_at").and_then(|v| v.as_str()).unwrap_or_default();
        let method = entry.get("method").and_then(|v| v.as_str()).unwrap_or("GET");
        let url = entry.get("url").and_then(|v| v.as_str()).unwrap_or_default();
        let host = entry.get("host").and_then(|v| v.as_str()).unwrap_or_default();
        let status = entry.get("status").and_then(|v| v.as_i64()).unwrap_or(200);
        let mime_type = entry.get("mime_type").and_then(|v| v.as_str()).unwrap_or("text/html");
        let server_ip = entry.get("server_ip").and_then(|v| v.as_str()).unwrap_or_default();
        let req_bytes = entry.get("request_bytes").and_then(|v| v.as_i64()).unwrap_or(0);
        let resp_bytes = entry.get("response_bytes").and_then(|v| v.as_i64()).unwrap_or(0);
        let duration = entry.get("duration_ms").and_then(|v| v.as_f64()).unwrap_or(10.0);

        har_entries.push(serde_json::json!({
            "startedDateTime": started_at,
            "time": duration,
            "serverIPAddress": server_ip,
            "request": {
                "method": method,
                "url": url,
                "httpVersion": "HTTP/1.1",
                "cookies": [],
                "headers": [
                    { "name": "Host", "value": host },
                    { "name": "User-Agent", "value": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" }
                ],
                "queryString": [],
                "headersSize": -1,
                "bodySize": req_bytes
            },
            "response": {
                "status": status,
                "statusText": if status == 200 { "OK" } else { "Custom" },
                "httpVersion": "HTTP/1.1",
                "cookies": [],
                "headers": [
                    { "name": "Content-Type", "value": mime_type }
                ],
                "content": {
                    "size": resp_bytes,
                    "mimeType": mime_type
                },
                "redirectURL": "",
                "headersSize": -1,
                "bodySize": resp_bytes
            },
            "cache": {},
            "timings": {
                "send": 0,
                "wait": duration,
                "receive": 0
            }
        }));
    }

    serde_json::json!({
        "log": {
            "version": "1.2",
            "creator": {
                "name": "OshoosiClaw HAR Web Traffic Sensor",
                "version": "1.2.0"
            },
            "entries": har_entries
        }
    })
}

/// Sweeps and refreshes the live HAR web traffic cache, persists entries to SQLite and logs/live_web_traffic.har.
pub fn refresh_live_har_cache_now() -> Value {
    let _refresh_guard = HAR_REFRESH_MUTEX
        .get_or_init(|| osoosi_core::parking_lot::Mutex::new(()))
        .lock();
    let engine = osoosi_agent_anomaly::SiqueryEngine::new();
    let mut entries = engine.collect_live_har_entries_fast(400);
    let rea_engine = osoosi_core::rea::global_rea_engine();

    let total_entries = entries.len();
    let mut unique_hosts_set = std::collections::HashSet::new();
    let mut active_sources_set = std::collections::HashSet::new();
    let mut total_bytes = 0u64;
    let mut malicious_count = 0usize;
    let mut suspicious_count = 0usize;
    let mut benign_count = 0usize;
    let mut rea_escalated_count = 0usize;
    let mut rea_vetoed_count = 0usize;

    for e in &mut entries {
        let url = e
            .get("url")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let method = e
            .get("method")
            .and_then(|v| v.as_str())
            .unwrap_or("GET")
            .to_string();
        let status = e.get("status").and_then(|v| v.as_u64()).unwrap_or(200) as u16;
        let mime_type = e
            .get("mime_type")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let source_file = e
            .get("source_file")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let server_ip = e
            .get("server_ip")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let tags = e
            .get("threat_tags")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();

        let rea_har = rea_engine.analyze_har_entry_with_context(
            &source_file,
            &url,
            &method,
            status,
            &mime_type,
            &server_ip,
            &tags,
        );
        if rea_har.rea_voter_decision == "ESCALATE_MALICIOUS" {
            rea_escalated_count += 1;
        } else {
            rea_vetoed_count += 1;
        }

        if let Some(obj) = e.as_object_mut() {
            obj.insert(
                "rea_voter_decision".to_string(),
                json!(rea_har.rea_voter_decision),
            );
            obj.insert(
                "rea_voter_reason".to_string(),
                json!(rea_har.rea_voter_reason),
            );
            obj.insert(
                "openjev_voter_decision".to_string(),
                json!(rea_har.openjev_voter_decision),
            );
            obj.insert(
                "openjev_voter_reason".to_string(),
                json!(rea_har.openjev_voter_reason),
            );
            obj.insert(
                "rea_artifact_class".to_string(),
                json!(rea_har.artifact_class),
            );
            obj.insert(
                "rea_seal_blake3".to_string(),
                json!(rea_har.rea_seal_blake3),
            );
            let cur_score = obj
                .get("threat_score")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            if rea_har.rea_voter_decision == "ESCALATE_MALICIOUS"
                && (rea_har.threat_score as f64) > cur_score
            {
                obj.insert("threat_score".to_string(), json!(rea_har.threat_score));
                obj.insert("verdict".to_string(), json!("malicious"));
            } else if rea_har.rea_voter_decision == "VETO_BENIGN"
                && !tags.contains("SWARM_POISONED_LINEAGE")
                && !tags.contains("DANGEROUS_DOWNLOAD")
                && cur_score < 0.80
            {
                obj.insert("threat_score".to_string(), json!(0.0));
                obj.insert("verdict".to_string(), json!("benign"));
            }
        }

        if let Some(host) = e.get("host").and_then(|v| v.as_str()) {
            if !host.is_empty() {
                unique_hosts_set.insert(host.to_string());
            }
        }
        if let Some(src) = e.get("source_file").and_then(|v| v.as_str()) {
            if !src.is_empty() {
                active_sources_set.insert(src.to_string());
            }
        }
        let req_b = e.get("request_bytes").and_then(|v| v.as_u64()).unwrap_or(0);
        let resp_b = e.get("response_bytes").and_then(|v| v.as_u64()).unwrap_or(0);
        total_bytes += req_b + resp_b;

        let verdict = e.get("verdict").and_then(|v| v.as_str()).unwrap_or("benign");
        let score = e.get("threat_score").and_then(|v| v.as_f64()).unwrap_or(0.0);

        if verdict == "malicious" || score >= 0.8 {
            malicious_count += 1;
        } else if verdict == "suspicious" || (score >= 0.4 && score < 0.8) {
            suspicious_count += 1;
        } else {
            benign_count += 1;
        }
    }

    let sweep_sequence = HAR_SWEEP_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;

    // Persist new entries into database/osoosi.db (keeping latest 1000 rows)
    let db_candidates = [
        std::path::Path::new("database/osoosi.db"),
        std::path::Path::new("target/release/database/osoosi.db"),
        std::path::Path::new("../database/osoosi.db"),
    ];

    for db_path in &db_candidates {
        if let Some(parent) = db_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(conn) = rusqlite::Connection::open(db_path) {
            let _ = conn.busy_timeout(std::time::Duration::from_millis(5000));
            let _ = conn.execute(
                "CREATE TABLE IF NOT EXISTS har_entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_file TEXT,
                    started_at TEXT,
                    method TEXT,
                    url TEXT,
                    host TEXT,
                    status INTEGER,
                    mime_type TEXT,
                    server_ip TEXT,
                    request_bytes INTEGER,
                    response_bytes INTEGER,
                    duration_ms REAL,
                    threat_score REAL,
                    threat_tags TEXT,
                    verdict TEXT,
                    hash_blake3 TEXT
                );",
                [],
            );
            let _ = conn.execute("ALTER TABLE har_entries ADD COLUMN hash_blake3 TEXT DEFAULT '';", []);
            let _ = conn.execute_batch("BEGIN IMMEDIATE; DELETE FROM har_entries;");
            if let Ok(mut insert_stmt) = conn.prepare_cached(
                "INSERT INTO har_entries (source_file, started_at, method, url, host, status, mime_type, server_ip, request_bytes, response_bytes, duration_ms, threat_score, threat_tags, verdict, hash_blake3) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);"
            ) {
                for e in &entries {
                    let _ = insert_stmt.execute(rusqlite::params![
                        e.get("source_file").and_then(|v| v.as_str()).unwrap_or_default(),
                        e.get("started_at").and_then(|v| v.as_str()).unwrap_or_default(),
                        e.get("method").and_then(|v| v.as_str()).unwrap_or("GET"),
                        e.get("url").and_then(|v| v.as_str()).unwrap_or_default(),
                        e.get("host").and_then(|v| v.as_str()).unwrap_or_default(),
                        e.get("status").and_then(|v| v.as_i64()).unwrap_or(200),
                        e.get("mime_type").and_then(|v| v.as_str()).unwrap_or_default(),
                        e.get("server_ip").and_then(|v| v.as_str()).unwrap_or_default(),
                        e.get("request_bytes").and_then(|v| v.as_i64()).unwrap_or(0),
                        e.get("response_bytes").and_then(|v| v.as_i64()).unwrap_or(0),
                        e.get("duration_ms").and_then(|v| v.as_f64()).unwrap_or(0.0),
                        e.get("threat_score").and_then(|v| v.as_f64()).unwrap_or(0.0),
                        e.get("threat_tags").and_then(|v| v.as_str()).unwrap_or_default(),
                        e.get("verdict").and_then(|v| v.as_str()).unwrap_or("benign"),
                        e.get("hash_blake3").and_then(|v| v.as_str()).unwrap_or_default(),
                    ]);
                }
            }
            let _ = conn.execute_batch("COMMIT;");
            break;
        }
    }

    // Write valid W3C HAR 1.2 JSON to logs/live_web_traffic.har
    let _ = std::fs::create_dir_all("logs");
    let har_doc = build_w3c_har_document(&entries);
    if let Ok(har_json) = serde_json::to_string_pretty(&har_doc) {
        let _ = std::fs::write("logs/live_web_traffic.har", har_json);
    }

    let payload = serde_json::json!({
        "status": "ok",
        "continuous_collector_active": true,
        "poll_interval_ms": 3000,
        "last_updated": chrono::Utc::now().to_rfc3339(),
        "sweep_sequence": sweep_sequence,
        "live_har_file": "logs/live_web_traffic.har",
        "count": total_entries,
        "stats": {
            "total_entries": total_entries,
            "unique_hosts": unique_hosts_set.len(),
            "active_sources": active_sources_set.len(),
            "total_bytes": total_bytes,
            "malicious_count": malicious_count,
            "suspicious_count": suspicious_count,
            "benign_count": benign_count,
            "rea_escalated_count": rea_escalated_count,
            "rea_vetoed_count": rea_vetoed_count
        },
        "rea_har_coverage": {
            "rea_voter_active": true,
            "openjev_voter_active": true,
            "inspected_entries": total_entries,
            "rea_escalated_count": rea_escalated_count,
            "rea_vetoed_count": rea_vetoed_count
        },
        "entries": entries
    });

    let cache_lock = LIVE_HAR_CACHE.get_or_init(|| osoosi_core::parking_lot::RwLock::new(None));
    *cache_lock.write() = Some(payload.clone());
    payload
}

pub fn ensure_continuous_har_collector_started() {
    if HAR_COLLECTOR_STARTED
        .compare_exchange(
            false,
            true,
            std::sync::atomic::Ordering::SeqCst,
            std::sync::atomic::Ordering::SeqCst,
        )
        .is_ok()
    {
        std::thread::Builder::new()
            .name("osoosi-har-collector".to_string())
            .spawn(|| {
                let _ = refresh_live_har_cache_now();
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(5));
                    let _ = refresh_live_har_cache_now();
                }
            })
            .expect("failed to spawn osoosi-har-collector background thread");
    }
}

pub async fn post_traffic_conversation(
    State(state): State<DashboardState>,
    Json(req): Json<TrafficConversationRequest>,
) -> Json<Value> {
    let human_instruction = req.human_instruction.trim();
    let traffic_data = req.traffic_data.trim();
    if human_instruction.is_empty() || traffic_data.is_empty() {
        return api_error_json(
            "INVALID_INPUT",
            "human_instruction and traffic_data are required",
            "Provide both human_instruction and traffic_data in the JSON request body.",
        );
    }
    if !traffic_data.contains("<packet>") {
        return api_error_json(
            "MISSING_PACKET_MARKER",
            "traffic_data must include '<packet>' marker",
            "Wrap captured packet data with the '<packet>' delimiter.",
        );
    }

    match &state.backend {
        Some(orch) => {
            let mut out = orch.analyze_traffic_prompt(human_instruction, traffic_data);
            if let Some(obj) = out.as_object_mut() {
                obj.insert("msg".to_string(), json!("success"));
            }
            Json(out)
        }
        None => api_error_json(
            "BACKEND_INACTIVE",
            "backend not active; run agent with dashboard backend",
            "Start the agent daemon with the active orchestrator to analyze captured traffic.",
        ),
    }
}

pub async fn get_traffic_analyze_captured(
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

pub async fn post_har_inspect(
    State(state): State<DashboardState>,
    Json(req): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let label = req
        .get("label")
        .and_then(|v| v.as_str())
        .unwrap_or("API-Stream");
    let har_str = if let Some(p) = req.get("file_path").and_then(|v| v.as_str()) {
        let p_trimmed = p.trim();
        // Path traversal, UNC, NTFS Alternate Data Streams (ADS), and REA Protection Layer 2 validation
        if p_trimmed.contains("..")
            || p_trimmed.starts_with(r"\\")
            || p_trimmed.starts_with("//")
            || osoosi_core::rea::validate_rea_target_path(p_trimmed).is_err()
        {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "status": "error",
                    "message": "Path traversal, UNC paths, device namespaces, or ADS are not permitted in file_path"
                })),
            );
        }
        let colon_indices: Vec<usize> = p_trimmed.match_indices(':').map(|(i, _)| i).collect();
        if colon_indices.len() > 1 || (colon_indices.len() == 1 && colon_indices[0] != 1) {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "status": "error",
                    "message": "NTFS Alternate Data Streams (ADS) or invalid colon usage not permitted in file_path"
                })),
            );
        }
        let lower = p_trimmed.to_ascii_lowercase();
        if !lower.ends_with(".har") && !lower.ends_with(".json") {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "status": "error",
                    "message": "file_path must end with .har or .json"
                })),
            );
        }
        match std::fs::read_to_string(p_trimmed) {
            Ok(content) => content,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "status": "error",
                        "message": format!("Failed to read file_path: {}", e)
                    })),
                );
            }
        }
    } else if let Some(raw) = req
        .get("raw")
        .or_else(|| req.get("har_content"))
        .and_then(|v| v.as_str())
    {
        raw.to_string()
    } else if let Some(har_val) = req.get("har") {
        if har_val.is_string() {
            har_val.as_str().unwrap().to_string()
        } else {
            serde_json::to_string(har_val).unwrap_or_default()
        }
    } else if req.get("log").is_some() {
        serde_json::to_string(&req).unwrap_or_default()
    } else {
        String::new()
    };

    if har_str.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "status": "error",
                "message": "HAR content is required: provide 'har', 'raw', 'file_path', or raw W3C HAR object in JSON body"
            })),
        );
    }

    match osoosi_policy::traffic_adapter::parse_and_inspect_har_json(&har_str, label) {
        Ok(report) => {
            // Deep-inspect the HAR archive with AutonomousReaEngine + OpenJEV-Voter and record in REA investigations
            let rea_engine = osoosi_core::rea::global_rea_engine();
            let rea_har = rea_engine.analyze_har_entry_or_archive(
                label,
                "HAR_ARCHIVE",
                200,
                "application/har+json",
                &har_str,
            );
            let rea_report = osoosi_core::rea::analyze_target_bytes(
                label,
                None,
                har_str.as_bytes(),
                osoosi_core::rea::ReaTargetKind::NetworkCapture,
                Some("har_archive_inspect".to_string()),
            );
            rea_engine.record_report(rea_report.clone());

            if let Some(orch) = &state.backend {
                if report.malicious_entries > 0
                    || report.highest_threat_score >= 0.75
                    || rea_har.rea_voter_decision == "ESCALATE_MALICIOUS"
                {
                    let sec_event = osoosi_types::HostSecurityEvent {
                        source: osoosi_types::HostEventSource::WindowsEventLog,
                        event_id: 77,
                        timestamp: chrono::Utc::now(),
                        computer: orch.trust.did().to_string(),
                        data: serde_json::json!({
                            "TargetFilename": label,
                            "HarContent": har_str,
                            "ReaVoterDecision": rea_har.rea_voter_decision,
                            "OpenJevVoterDecision": rea_har.openjev_voter_decision,
                            "ReaSealBlake3": rea_har.rea_seal_blake3,
                            "EventDescription": format!("Browser HAR Threat: {} malicious entries ({}) [REA: {}]", report.malicious_entries, report.detected_vectors.join(", "), rea_har.rea_voter_reason),
                        }),
                        causal_parent: None,
                    };
                    let orch_clone = orch.clone();
                    tokio::spawn(async move {
                        let _ = orch_clone.process_security_event_internal(sec_event).await;
                    });
                }
            }

            let _ = refresh_live_har_cache_now();

            (
                StatusCode::OK,
                Json(json!({
                    "status": "ok",
                    "total_findings": report.malicious_entries + report.suspicious_entries + rea_har.findings.len(),
                    "report": report,
                    "rea_analysis": rea_har,
                    "rea_report": rea_report
                })),
            )
        }
        Err(err) => (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "status": "error",
                "message": err
            })),
        ),
    }
}

pub async fn get_har_entries(
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Json<Value> {
    ensure_continuous_har_collector_started();

    let cached = {
        let cache_lock = LIVE_HAR_CACHE.get_or_init(|| osoosi_core::parking_lot::RwLock::new(None));
        let read = cache_lock.read();
        read.clone()
    };

    let base_payload = cached.unwrap_or_else(refresh_live_har_cache_now);

    let raw_entries = base_payload
        .get("entries")
        .and_then(|e| e.as_array())
        .cloned()
        .unwrap_or_default();

    let search_term = params.get("search").map(|s| s.to_ascii_lowercase());
    let verdict_filter = params.get("verdict").map(|s| s.to_ascii_lowercase());
    let source_filter = params.get("source").map(|s| s.to_ascii_lowercase());
    let method_filter = params.get("method").map(|s| s.to_ascii_uppercase());
    let limit_param = params.get("limit").and_then(|l| l.parse::<usize>().ok());

    let mut filtered_entries = Vec::with_capacity(raw_entries.len());
    for e in raw_entries {
        if let Some(ref s) = search_term {
            let url = e.get("url").and_then(|v| v.as_str()).unwrap_or_default().to_ascii_lowercase();
            let host = e.get("host").and_then(|v| v.as_str()).unwrap_or_default().to_ascii_lowercase();
            let src = e.get("source_file").and_then(|v| v.as_str()).unwrap_or_default().to_ascii_lowercase();
            let tags = e.get("threat_tags").and_then(|v| v.as_str()).unwrap_or_default().to_ascii_lowercase();
            if !url.contains(s) && !host.contains(s) && !src.contains(s) && !tags.contains(s) {
                continue;
            }
        }
        if let Some(ref v) = verdict_filter {
            let entry_verdict = e.get("verdict").and_then(|val| val.as_str()).unwrap_or_default().to_ascii_lowercase();
            if entry_verdict != *v {
                continue;
            }
        }
        if let Some(ref src) = source_filter {
            let entry_src = e.get("source_file").and_then(|val| val.as_str()).unwrap_or_default().to_ascii_lowercase();
            if !entry_src.contains(src) {
                continue;
            }
        }
        if let Some(ref m) = method_filter {
            let entry_m = e.get("method").and_then(|val| val.as_str()).unwrap_or_default().to_ascii_uppercase();
            if entry_m != *m {
                continue;
            }
        }
        filtered_entries.push(e);
        if let Some(lim) = limit_param {
            if filtered_entries.len() >= lim {
                break;
            }
        }
    }

    let stats = base_payload.get("stats").cloned().unwrap_or_else(|| serde_json::json!({}));
    let sweep_sequence = base_payload.get("sweep_sequence").and_then(|v| v.as_u64()).unwrap_or(0);
    let last_updated = base_payload.get("last_updated").and_then(|v| v.as_str()).unwrap_or_default();

    Json(serde_json::json!({
        "status": "ok",
        "continuous_collector_active": true,
        "poll_interval_ms": 3000,
        "last_updated": last_updated,
        "sweep_sequence": sweep_sequence,
        "live_har_file": "logs/live_web_traffic.har",
        "count": filtered_entries.len(),
        "stats": stats,
        "entries": filtered_entries
    }))
}

pub async fn post_har_refresh() -> Json<Value> {
    let fresh = tokio::task::spawn_blocking(refresh_live_har_cache_now)
        .await
        .unwrap_or_else(|e| {
            serde_json::json!({
                "status": "error",
                "message": format!("Blocking join error: {}", e)
            })
        });
    Json(fresh)
}

pub async fn get_har_export() -> impl IntoResponse {
    let payload = {
        let cache_lock = LIVE_HAR_CACHE.get_or_init(|| osoosi_core::parking_lot::RwLock::new(None));
        let read = cache_lock.read();
        read.clone().unwrap_or_else(refresh_live_har_cache_now)
    };

    let entries = payload
        .get("entries")
        .and_then(|e| e.as_array())
        .cloned()
        .unwrap_or_default();
    let har_doc = build_w3c_har_document(&entries);

    (
        [
            (axum::http::header::CONTENT_TYPE, "application/json"),
            (
                axum::http::header::CONTENT_DISPOSITION,
                r#"attachment; filename="oshoosi_live_web_traffic.har""#,
            ),
        ],
        axum::response::Json(har_doc),
    )
}

/// Mounts all Continuous HAR routes and legacy aliases.
pub fn routes() -> Router<DashboardState> {
    Router::new()
        .route("/api/traffic/conversation", post(post_traffic_conversation))
        .route(
            "/api/traffic/analyze-captured",
            get(get_traffic_analyze_captured),
        )
        .route("/api/har/inspect", post(post_har_inspect))
        .route("/har/inspect", post(post_har_inspect))
        .route("/api/har/entries", get(get_har_entries))
        .route("/har/entries", get(get_har_entries))
        .route("/api/har/refresh", post(post_har_refresh))
        .route("/har/refresh", post(post_har_refresh))
        .route("/api/har/export", get(get_har_export))
        .route("/har/export", get(get_har_export))
}
