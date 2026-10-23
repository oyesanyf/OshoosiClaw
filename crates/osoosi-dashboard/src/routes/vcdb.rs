use axum::{
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Value};

use crate::DashboardState;

pub async fn get_vcdb_status() -> Json<Value> {
    let engine = osoosi_vcdb::global_vcdb_engine();
    let catalog = engine.get_catalog();
    let priors = engine.get_empirical_priors();
    let benchmark = engine.get_timeline_benchmark();
    let crosswalk = engine.get_crosswalk();

    Json(json!({
        "status": "ok",
        "schema_version": catalog.schema_version,
        "catalog_source": catalog.catalog_source,
        "upstream_commit": catalog.upstream_commit,
        "license": catalog.license,
        "total_incidents": catalog.total_incidents,
        "dbir_patterns_count": 9,
        "timeline_benchmark": benchmark,
        "empirical_priors": priors,
        "crosswalk": crosswalk,
    }))
}

pub async fn post_vcdb_sync() -> Json<Value> {
    let res = tokio::task::spawn_blocking(|| {
        let engine = osoosi_vcdb::global_vcdb_engine();
        engine.sync_upstream_feed(None)
    })
    .await
    .unwrap_or_else(|e| Err(e.to_string()));

    match res {
        Ok(msg) => Json(json!({
            "status": "ok",
            "message": msg,
            "upstream_commit": osoosi_vcdb::global_vcdb_engine().get_catalog().upstream_commit,
        })),
        Err(e) => Json(json!({
            "status": "error",
            "message": e,
        })),
    }
}

pub async fn post_vcdb_replay() -> Json<Value> {
    let report = tokio::task::spawn_blocking(|| {
        let engine = osoosi_vcdb::global_vcdb_engine();
        engine.execute_vcdb_replay_suite()
    })
    .await
    .unwrap_or_else(|_| osoosi_vcdb::global_vcdb_engine().execute_vcdb_replay_suite());

    Json(json!({
        "status": "ok",
        "report": report,
    }))
}

/// Mounts all Verizon VCDB VERIS 4-A routes and legacy aliases.
pub fn routes() -> Router<DashboardState> {
    Router::new()
        .route("/api/vcdb/status", get(get_vcdb_status))
        .route("/vcdb/status", get(get_vcdb_status))
        .route("/api/vcdb/sync", post(post_vcdb_sync))
        .route("/vcdb/sync", post(post_vcdb_sync))
        .route("/api/vcdb/replay", post(post_vcdb_replay))
        .route("/vcdb/replay", post(post_vcdb_replay))
}
