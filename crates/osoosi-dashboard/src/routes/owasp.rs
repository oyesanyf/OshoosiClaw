use axum::{
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::DashboardState;

static GLOBAL_OWASP_HUNTING: once_cell::sync::Lazy<osoosi_owasp_hunting::OwaspHuntingEngine> =
    once_cell::sync::Lazy::new(osoosi_owasp_hunting::OwaspHuntingEngine::new);

pub fn global_owasp_hunting_engine() -> &'static osoosi_owasp_hunting::OwaspHuntingEngine {
    &GLOBAL_OWASP_HUNTING
}

pub async fn get_owasp_hunting_status() -> Json<Value> {
    let engine = global_owasp_hunting_engine();
    let sync = engine.get_sync_status();
    let categories = engine.list_categories();
    Json(json!({
        "status": "ok",
        "feed_sync": sync,
        "categories_count": categories.len(),
        "categories": categories,
    }))
}

pub async fn post_owasp_hunting_sync() -> Json<Value> {
    let sync = tokio::task::spawn_blocking(|| {
        let engine = global_owasp_hunting_engine();
        engine.sync_from_upstream_feed()
    })
    .await
    .unwrap_or_else(|_| global_owasp_hunting_engine().get_sync_status());
    Json(json!({
        "status": "ok",
        "feed_sync": sync,
    }))
}

#[derive(Debug, Deserialize)]
pub struct OwaspExecuteRequest {
    #[serde(default)]
    pub priority_only: bool,
}

pub async fn post_owasp_hunting_execute(payload: Option<Json<OwaspExecuteRequest>>) -> Json<Value> {
    let priority_only = payload.map(|p| p.priority_only).unwrap_or(false);
    let result = tokio::task::spawn_blocking(move || {
        let engine = global_owasp_hunting_engine();
        engine.execute_suite(priority_only)
    })
    .await
    .unwrap_or_else(|_| global_owasp_hunting_engine().execute_suite(true));
    Json(json!({
        "status": "ok",
        "result": result,
    }))
}

/// Mounts all OWASP Threat Hunting routes and legacy aliases.
pub fn routes() -> Router<DashboardState> {
    Router::new()
        .route("/api/owasp-hunting/status", get(get_owasp_hunting_status))
        .route("/owasp-hunting/status", get(get_owasp_hunting_status))
        .route("/api/owasp-hunting/sync", post(post_owasp_hunting_sync))
        .route("/owasp-hunting/sync", post(post_owasp_hunting_sync))
        .route(
            "/api/owasp-hunting/execute",
            post(post_owasp_hunting_execute),
        )
        .route("/owasp-hunting/execute", post(post_owasp_hunting_execute))
}
