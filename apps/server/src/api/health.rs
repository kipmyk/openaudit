//! Health and readiness verification endpoints.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use std::sync::Arc;

use crate::state::AppState;

/// Health liveness response payload.
#[derive(Debug, Clone, Serialize)]
pub struct LivenessResponse {
    pub status: &'static str,
    pub uptime_secs: u64,
    pub version: &'static str,
}

/// Health readiness response payload.
#[derive(Debug, Clone, Serialize)]
pub struct ReadinessResponse {
    pub status: &'static str,
    pub database: &'static str,
    pub storage_ready: bool,
    pub active_workers: usize,
    pub max_workers: usize,
}

/// `GET /health/live` handler confirming process responsiveness.
pub async fn liveness_handler(State(state): State<Arc<AppState>>) -> Response {
    let uptime = state.uptime_secs();
    (
        StatusCode::OK,
        Json(LivenessResponse {
            status: "ok",
            uptime_secs: uptime,
            version: openaudit_core::version(),
        }),
    )
        .into_response()
}

/// `GET /health/ready` handler confirming backend storage and worker readiness.
pub async fn readiness_handler(State(state): State<Arc<AppState>>) -> Response {
    let storage_ready = state.store.is_healthy();
    let status = if storage_ready { "ready" } else { "degraded" };
    let code = if storage_ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (
        code,
        Json(ReadinessResponse {
            status,
            database: if storage_ready {
                "connected"
            } else {
                "disconnected"
            },
            storage_ready,
            active_workers: state.active_worker_count(),
            max_workers: state.config.max_concurrent_jobs,
        }),
    )
        .into_response()
}
