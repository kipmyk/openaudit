//! Recurring assessment schedule routes.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

use crate::auth::AuthenticatedUser;
use crate::state::AppState;
use crate::store::models::Role;

#[derive(Debug, Deserialize)]
pub struct CreateScheduleRequest {
    pub asset_id: Option<Uuid>,
    pub name: String,
    pub cron_expression: String,
    pub target: String,
    pub assessment_type: String,
    pub profile: Option<String>,
}

/// `POST /api/v1/schedules` - Creates a recurring assessment schedule.
pub async fn create_schedule_handler(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedUser,
    Json(payload): Json<CreateScheduleRequest>,
) -> Response {
    if let Err(res) = auth.require_role(Role::Auditor) {
        return res;
    }

    let name = payload.name.trim();
    let target = payload.target.trim();
    let cron = payload.cron_expression.trim();

    if name.is_empty() || target.is_empty() || cron.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_input",
                "message": "Schedule name, target, and cron expression cannot be empty"
            })),
        )
            .into_response();
    }

    let profile = payload.profile.as_deref().unwrap_or("standard");
    match state.store.create_schedule(
        auth.org_id,
        payload.asset_id,
        name,
        cron,
        target,
        &payload.assessment_type,
        profile,
    ) {
        Ok(schedule) => (StatusCode::CREATED, Json(schedule)).into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "database_error",
                "message": err.to_string()
            })),
        )
            .into_response(),
    }
}

/// `GET /api/v1/schedules` - Lists schedules configured in caller's organization.
pub async fn list_schedules_handler(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedUser,
) -> Response {
    match state.store.list_schedules(auth.org_id) {
        Ok(schedules) => (StatusCode::OK, Json(schedules)).into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "database_error",
                "message": err.to_string()
            })),
        )
            .into_response(),
    }
}
