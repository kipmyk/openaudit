//! Root HTTP API router assembly and middleware configuration.

pub mod health;
pub mod openapi;
pub mod v1;
pub mod version;
pub mod web;

use axum::extract::DefaultBodyLimit;
use axum::routing::get;
use axum::Router;
use std::sync::Arc;
use std::time::Duration;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

use crate::state::AppState;

/// Assembles the complete OpenAudit control plane HTTP application router.
pub fn create_router(state: Arc<AppState>) -> Router {
    let timeout_duration = Duration::from_secs(state.config.request_timeout_secs);
    let max_body_size = state.config.max_body_size_bytes;

    let mut origins = Vec::new();
    for o in &state.config.allowed_origins {
        if let Ok(val) = o.parse::<axum::http::HeaderValue>() {
            origins.push(val);
        }
    }

    let cors = if origins.is_empty() {
        CorsLayer::new()
    } else {
        CorsLayer::new()
            .allow_origin(origins)
            .allow_methods([
                axum::http::Method::GET,
                axum::http::Method::POST,
                axum::http::Method::DELETE,
                axum::http::Method::OPTIONS,
            ])
            .allow_headers([
                axum::http::header::AUTHORIZATION,
                axum::http::header::CONTENT_TYPE,
                axum::http::header::ACCEPT,
            ])
    };

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
        // Web UI Assets & SPA Fallback (Milestone 8)
        .route("/", get(web::index_handler))
        .route("/app.css", get(web::css_handler))
        .route("/app.js", get(web::js_handler))
        .fallback(web::fallback_handler)
        // Global Middleware
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .layer(tower_http::timeout::TimeoutLayer::new(timeout_duration))
        .layer(DefaultBodyLimit::max(max_body_size))
        .with_state(state)
}
