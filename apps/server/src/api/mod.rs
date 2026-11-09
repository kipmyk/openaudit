//! Root HTTP API router assembly and middleware configuration.

pub mod health;
pub mod openapi;
pub mod v1;
pub mod version;

use axum::extract::DefaultBodyLimit;
use axum::routing::get;
use axum::Router;
use std::sync::Arc;
use std::time::Duration;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

use crate::state::AppState;

/// Assembles the complete OpenAudit control plane HTTP application router.
pub fn create_router(state: Arc<AppState>) -> Router {
    let timeout_duration = Duration::from_secs(state.config.request_timeout_secs);
    let max_body_size = state.config.max_body_size_bytes;

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let v1_router = v1::router();

    Router::new()
        // Health & Diagnostics
        .route("/health/live", get(health::liveness_handler))
        .route("/health/ready", get(health::readiness_handler))
        .route("/version", get(version::version_handler))
        .route("/api/v1/capabilities", get(version::capabilities_handler))
        .route("/api/openapi.json", get(openapi::openapi_json_handler))
        // Version 1 API
        .nest("/api/v1", v1_router)
        // Global Middleware
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .layer(tower_http::timeout::TimeoutLayer::new(timeout_duration))
        .layer(DefaultBodyLimit::max(max_body_size))
        .with_state(state)
}
