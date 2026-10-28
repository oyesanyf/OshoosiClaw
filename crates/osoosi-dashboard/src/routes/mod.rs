pub mod browser_sensor;
pub mod conformal_jailbreak;
pub mod dlp;
pub mod dlp_containment;
pub mod har;
pub mod har_dlp;
pub mod mesh;
pub mod owasp;
pub mod research_ingest;
pub mod skyrl;
pub mod vcdb;
pub mod workflow_guard;

use crate::DashboardState;
use axum::Router;

/// Mounts all modular domain sub-routers onto a single Axum Router<DashboardState>.
/// Guarantees 100% backward compatibility on port 3030 for /api/* and legacy aliases.
pub fn mount_routes() -> Router<DashboardState> {
    Router::new()
        .merge(dlp::routes())
        .merge(dlp_containment::routes())
        .merge(browser_sensor::routes())
        .merge(mesh::routes())
        .merge(har::routes())
        .merge(owasp::routes())
        .merge(vcdb::routes())
        .merge(skyrl::routes())
        .merge(workflow_guard::routes())
        .merge(conformal_jailbreak::routes())
        .merge(research_ingest::routes())
}
