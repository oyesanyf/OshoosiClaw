pub mod dlp;
pub mod har;
pub mod mesh;
pub mod owasp;
pub mod skyrl;
pub mod vcdb;

use axum::Router;
use crate::DashboardState;

/// Mounts all modular domain sub-routers onto a single Axum Router<DashboardState>.
/// Guarantees 100% backward compatibility on port 3030 for /api/* and legacy aliases.
pub fn mount_routes() -> Router<DashboardState> {
    Router::new()
        .merge(dlp::routes())
        .merge(mesh::routes())
        .merge(har::routes())
        .merge(owasp::routes())
        .merge(vcdb::routes())
        .merge(skyrl::routes())
}
