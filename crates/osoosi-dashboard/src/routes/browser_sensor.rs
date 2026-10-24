//! Browser DLP sensor endpoints: zero-touch pairing and the HAR ingest stream.
//!
//! The OshoosiClaw Browser DLP Sensor extension (`browser-extension/`) observes outgoing
//! POST/PUT/PATCH bodies and posts them here as W3C HAR 1.2 entries. Entries flow through the
//! same HAR → DLP pipeline (`routes::har_dlp`) as `.har` files and HAR imports.
//!
//! Pairing (no token pasting): the extension calls `POST /api/browser-sensor/pair`; the browser
//! sets the `Origin` header to `chrome-extension://<id>` (or `moz-extension://<uuid>`), which web
//! pages cannot forge. If the origin is allowlisted, the daemon returns a sensor token derived
//! from the dashboard API secret and bound to that origin:
//! `blake3_keyed(derive_key("oshoosiclaw browser-dlp-sensor v1", dashboard_token), origin)`.
//! The sensor token only authorizes HAR submission (write-only telemetry); rotating the
//! dashboard token invalidates it and the extension re-pairs automatically.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use axum::{
    extract::DefaultBodyLimit,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Value};

use crate::routes::har_dlp::{self, HarSourceKind};
use crate::DashboardState;

/// Chromium extension ID derived from the `key` in `browser-extension/manifest.json`.
/// `browser-extension/test/har-capture.test.mjs` verifies the two stay in sync.
pub const DEFAULT_SENSOR_EXTENSION_ID: &str = "mgkckbmpncmidjdkfeamongahgbheocl";
const SENSOR_KEY_CONTEXT: &str = "oshoosiclaw browser-dlp-sensor v1";
/// Maximum HAR batch accepted from the sensor (25 entries x 256 KB bodies + overhead).
pub const MAX_SENSOR_BATCH_BYTES: usize = 8 * 1024 * 1024;
/// How long the ingest endpoint waits for inline verdicts before answering 202.
const INLINE_VERDICT_WAIT: Duration = Duration::from_millis(800);

static PAIRINGS: AtomicU64 = AtomicU64::new(0);
static PAIR_REJECTIONS: AtomicU64 = AtomicU64::new(0);
static BATCHES: AtomicU64 = AtomicU64::new(0);
static ENTRIES: AtomicU64 = AtomicU64::new(0);
static AUTH_FAILURES: AtomicU64 = AtomicU64::new(0);
static LAST_SEEN_UNIX: AtomicU64 = AtomicU64::new(0);

fn is_valid_chromium_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| (b'a'..=b'p').contains(&b))
}

/// Allowlisted extension origins: the built-in sensor ID, plus IDs/origins from
/// `OSOOSI_BROWSER_SENSOR_EXTENSION_IDS`, `OSOOSI_BROWSER_SENSOR_ALLOWED_ORIGINS`, and
/// `config/browser_sensor_origins.txt` (one Chromium ID or full extension origin per line,
/// e.g. the ID of a CRX packed by `scripts/pack_browser_extension.ps1`, or a Firefox
/// `moz-extension://<uuid>` origin shown in about:debugging).
pub fn allowed_sensor_origins() -> Vec<String> {
    let mut out = vec![format!("chrome-extension://{}", DEFAULT_SENSOR_EXTENSION_ID)];
    let mut push = |raw: &str| {
        let item = raw.trim().trim_end_matches('/');
        if item.is_empty() || item.starts_with('#') {
            return;
        }
        let origin = if is_valid_chromium_id(item) {
            format!("chrome-extension://{}", item)
        } else if (item.starts_with("chrome-extension://") || item.starts_with("moz-extension://"))
            && !item[item.find("://").unwrap_or(0) + 3..].contains('/')
        {
            item.to_string()
        } else {
            return;
        };
        if !out.contains(&origin) {
            out.push(origin);
        }
    };
    for var in [
        "OSOOSI_BROWSER_SENSOR_EXTENSION_IDS",
        "OSOOSI_BROWSER_SENSOR_ALLOWED_ORIGINS",
    ] {
        if let Ok(v) = std::env::var(var) {
            for part in v.split([',', ';', ' ']) {
                push(part);
            }
        }
    }
    let file = osoosi_types::resolve_project_root()
        .map(|p| p.join("config").join("browser_sensor_origins.txt"))
        .unwrap_or_else(|| PathBuf::from("config").join("browser_sensor_origins.txt"));
    if let Ok(content) = std::fs::read_to_string(file) {
        for line in content.lines() {
            push(line);
        }
    }
    out
}

/// Derives the origin-bound sensor token from the dashboard API secret.
pub fn sensor_token_for_origin(origin: &str) -> String {
    let secret = crate::get_or_init_dashboard_api_token();
    let key = blake3::derive_key(SENSOR_KEY_CONTEXT, secret.as_bytes());
    blake3::keyed_hash(&key, origin.as_bytes()).to_hex().to_string()
}

fn request_origin(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().trim_end_matches('/').to_string())
        .filter(|s| !s.is_empty())
}

fn bind_all_enabled() -> bool {
    std::env::var("OSOOSI_DASHBOARD_BIND_ALL")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn json_error(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        Json(json!({ "status": "error", "error_code": code, "message": message })),
    )
        .into_response()
}

/// Authorizes a sensor submission. Accepts (a) an allowlisted extension origin with a valid
/// origin-bound sensor token, or (b) the dashboard API token (scripts / enterprise collectors).
/// Comparisons are constant-time.
fn authorize_sensor(headers: &HeaderMap) -> Result<String, Response> {
    let dashboard_token = crate::get_or_init_dashboard_api_token();
    let presented_dashboard = headers
        .get("x-osoosi-token")
        .and_then(|v| v.to_str().ok())
        .or_else(|| {
            headers
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|a| a.strip_prefix("Bearer ").or_else(|| a.strip_prefix("bearer ")))
        });
    if let Some(tok) = presented_dashboard {
        if crate::constant_time_eq_token(tok.trim(), &dashboard_token) {
            return Ok(request_origin(headers).unwrap_or_else(|| "dashboard-token".to_string()));
        }
    }

    let Some(origin) = request_origin(headers) else {
        AUTH_FAILURES.fetch_add(1, Ordering::Relaxed);
        return Err(json_error(
            StatusCode::UNAUTHORIZED,
            "SENSOR_UNAUTHENTICATED",
            "Missing extension Origin and sensor token",
        ));
    };
    if !allowed_sensor_origins().contains(&origin) {
        AUTH_FAILURES.fetch_add(1, Ordering::Relaxed);
        return Err(json_error(
            StatusCode::FORBIDDEN,
            "SENSOR_ORIGIN_NOT_ALLOWED",
            "Origin is not an allowlisted OshoosiClaw browser sensor",
        ));
    }
    let Some(token) = headers
        .get("x-osoosi-sensor-token")
        .and_then(|v| v.to_str().ok())
    else {
        AUTH_FAILURES.fetch_add(1, Ordering::Relaxed);
        return Err(json_error(
            StatusCode::UNAUTHORIZED,
            "SENSOR_UNAUTHENTICATED",
            "Missing X-Osoosi-Sensor-Token (pair via /api/browser-sensor/pair)",
        ));
    };
    if !crate::constant_time_eq_token(token.trim(), &sensor_token_for_origin(&origin)) {
        AUTH_FAILURES.fetch_add(1, Ordering::Relaxed);
        return Err(json_error(
            StatusCode::UNAUTHORIZED,
            "SENSOR_TOKEN_INVALID",
            "Sensor token is invalid or was rotated; re-pair",
        ));
    }
    Ok(origin)
}

/// `POST /api/browser-sensor/pair` — zero-touch, origin-bound pairing.
pub async fn post_sensor_pair(headers: HeaderMap) -> Response {
    if bind_all_enabled() {
        PAIR_REJECTIONS.fetch_add(1, Ordering::Relaxed);
        return json_error(
            StatusCode::FORBIDDEN,
            "PAIRING_DISABLED_BIND_ALL",
            "Automatic sensor pairing is only available when the dashboard listens on loopback",
        );
    }
    let Some(origin) = request_origin(&headers) else {
        PAIR_REJECTIONS.fetch_add(1, Ordering::Relaxed);
        return json_error(StatusCode::FORBIDDEN, "PAIRING_ORIGIN_REQUIRED", "Missing Origin");
    };
    if !allowed_sensor_origins().contains(&origin) {
        PAIR_REJECTIONS.fetch_add(1, Ordering::Relaxed);
        return json_error(
            StatusCode::FORBIDDEN,
            "SENSOR_ORIGIN_NOT_ALLOWED",
            "Origin is not an allowlisted OshoosiClaw browser sensor",
        );
    }
    PAIRINGS.fetch_add(1, Ordering::Relaxed);
    let mut resp = Json(json!({
        "status": "ok",
        "token": sensor_token_for_origin(&origin),
        "origin": origin,
        "ingest_path": "/api/browser-sensor/har",
        "max_batch_bytes": MAX_SENSOR_BATCH_BYTES
    }))
    .into_response();
    if let Ok(v) = header::HeaderValue::from_str(&origin) {
        resp.headers_mut().insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, v);
    }
    resp
}

/// `POST /api/browser-sensor/har` — HAR 1.2 batch from the sensor. Requests are queued into the
/// autonomous HAR→DLP worker (off the async executor); the handler waits up to 800 ms for
/// inline verdicts and otherwise answers `202 Accepted`.
pub async fn post_sensor_har(headers: HeaderMap, Json(doc): Json<Value>) -> Response {
    let origin = match authorize_sensor(&headers) {
        Ok(o) => o,
        Err(resp) => return resp,
    };
    let label = format!("browser-sensor:{}", origin);
    let requests = har_dlp::extract_requests_from_har(&doc, &label, HarSourceKind::BrowserExtension);
    if requests.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            "HAR_EMPTY",
            "HAR document must contain log.entries with request objects",
        );
    }
    BATCHES.fetch_add(1, Ordering::Relaxed);
    ENTRIES.fetch_add(requests.len() as u64, Ordering::Relaxed);
    LAST_SEEN_UNIX.store(chrono::Utc::now().timestamp().max(0) as u64, Ordering::Relaxed);

    // HAR traffic view parity: the policy-engine HAR inspector records summaries the
    // continuous collector shows in the HAR view. Runs on the blocking pool, not awaited.
    let doc_for_view = doc.clone();
    let label_for_view = label.clone();
    tokio::task::spawn_blocking(move || {
        if let Ok(raw) = serde_json::to_string(&doc_for_view) {
            let _ = osoosi_policy::traffic_adapter::parse_and_inspect_har_json(&raw, &label_for_view);
        }
    });

    let (tx, rx) = tokio::sync::oneshot::channel();
    let accepted = har_dlp::enqueue_requests(requests, Some(tx));
    match tokio::time::timeout(INLINE_VERDICT_WAIT, rx).await {
        Ok(Ok(events)) => {
            let verdicts: Vec<Value> = events
                .iter()
                .map(|e| {
                    json!({
                        "id": e.id,
                        "destination_sink": e.destination_sink,
                        "allowed": e.allowed,
                        "authorization_decision": e.authorization_decision,
                        "dlp_response": e.dlp_response,
                        "detected_categories": e.detected_categories,
                        "redactx_validated_categories": e.redactx_validated_categories,
                        "containment": e.containment,
                    })
                })
                .collect();
            (
                StatusCode::OK,
                Json(json!({ "status": "ok", "accepted": accepted, "verdicts": verdicts })),
            )
                .into_response()
        }
        _ => (
            StatusCode::ACCEPTED,
            Json(json!({ "status": "accepted", "accepted": accepted, "verdicts": [] })),
        )
            .into_response(),
    }
}

fn extension_package_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            dirs.push(dir.join("browser-extension"));
        }
    }
    if let Some(root) = osoosi_types::resolve_project_root() {
        dirs.push(root.join("dist").join("browser-extension"));
    }
    dirs.push(PathBuf::from("dist").join("browser-extension"));
    dirs
}

fn serve_package_file(name: &'static str, content_type: &'static str) -> Response {
    for dir in extension_package_dirs() {
        let p = dir.join(name);
        if let Ok(bytes) = std::fs::read(&p) {
            return ([(header::CONTENT_TYPE, content_type)], bytes).into_response();
        }
    }
    json_error(
        StatusCode::NOT_FOUND,
        "SENSOR_PACKAGE_NOT_BUILT",
        "Packed browser sensor not found; run scripts/pack_browser_extension.ps1",
    )
}

/// `GET /browser-sensor/update.xml` — Chromium update manifest for policy force-install.
pub async fn get_sensor_update_xml() -> Response {
    serve_package_file("update.xml", "application/xml")
}

/// `GET /browser-sensor/oshoosi-browser-sensor.crx` — packed extension for force-install.
pub async fn get_sensor_crx() -> Response {
    serve_package_file("oshoosi-browser-sensor.crx", "application/x-chrome-extension")
}

/// Sensor counters for `/api/dlp/status`.
pub fn sensor_status() -> Value {
    json!({
        "default_extension_id": DEFAULT_SENSOR_EXTENSION_ID,
        "allowed_origins": allowed_sensor_origins(),
        "pairings": PAIRINGS.load(Ordering::Relaxed),
        "pair_rejections": PAIR_REJECTIONS.load(Ordering::Relaxed),
        "batches": BATCHES.load(Ordering::Relaxed),
        "entries": ENTRIES.load(Ordering::Relaxed),
        "auth_failures": AUTH_FAILURES.load(Ordering::Relaxed),
        "last_seen_unix": LAST_SEEN_UNIX.load(Ordering::Relaxed),
    })
}

pub async fn get_sensor_status() -> Json<Value> {
    Json(sensor_status())
}

pub fn routes() -> Router<DashboardState> {
    Router::new()
        .route("/api/browser-sensor/pair", post(post_sensor_pair))
        .route(
            "/api/browser-sensor/har",
            post(post_sensor_har).layer(DefaultBodyLimit::max(MAX_SENSOR_BATCH_BYTES)),
        )
        .route("/api/browser-sensor/status", get(get_sensor_status))
        .route("/browser-sensor/update.xml", get(get_sensor_update_xml))
        .route(
            "/browser-sensor/oshoosi-browser-sensor.crx",
            get(get_sensor_crx),
        )
}
