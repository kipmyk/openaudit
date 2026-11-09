//! Assessment job execution and findings routes.

use axum::extract::{Path, Query, State};
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
pub struct CreateJobRequest {
    pub asset_id: Option<Uuid>,
    pub target: String,
    pub assessment_type: String,
    pub profile: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ListFindingsQuery {
    pub min_severity: Option<String>,
}

/// `POST /api/v1/assessments/jobs` - Dispatches an assessment job asynchronously.
pub async fn create_job_handler(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedUser,
    Json(payload): Json<CreateJobRequest>,
) -> Response {
    if let Err(res) = auth.require_role(Role::Auditor) {
        return res;
    }

    let target = payload.target.trim();
    if target.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_input",
                "message": "Target cannot be empty"
            })),
        )
            .into_response();
    }

    let profile = payload.profile.as_deref().unwrap_or("standard");
    let job = match state
        .store
        .create_job(
            auth.org_id,
            payload.asset_id,
            target,
            &payload.assessment_type,
            profile,
        )
        .await
    {
        Ok(j) => j,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "database_error",
                    "message": err.to_string()
                })),
            )
                .into_response();
        }
    };

    // Submit to background queue
    state.queue.submit_job(job.clone(), state.store.clone());

    (StatusCode::ACCEPTED, Json(job)).into_response()
}

/// `GET /api/v1/assessments/jobs` - Lists recent assessment jobs for caller's organization.
pub async fn list_jobs_handler(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedUser,
) -> Response {
    match state.store.list_jobs(auth.org_id, 100).await {
        Ok(jobs) => (StatusCode::OK, Json(jobs)).into_response(),
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

/// `GET /api/v1/assessments/jobs/:id` - Retrieves job status and execution details.
pub async fn get_job_handler(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedUser,
    Path(id): Path<Uuid>,
) -> Response {
    match state.store.get_job(auth.org_id, id).await {
        Ok(Some(job)) => (StatusCode::OK, Json(job)).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": "not_found",
                "message": "Assessment job not found"
            })),
        )
            .into_response(),
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

/// `POST /api/v1/assessments/jobs/:id/cancel` - Cancels an active or pending job.
pub async fn cancel_job_handler(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedUser,
    Path(id): Path<Uuid>,
) -> Response {
    if let Err(res) = auth.require_role(Role::Auditor) {
        return res;
    }

    match state.store.get_job(auth.org_id, id).await {
        Ok(Some(job)) => {
            if job.status.is_terminal() {
                return (
                    StatusCode::CONFLICT,
                    Json(json!({
                        "error": "already_terminal",
                        "message": format!("Job is already in terminal state '{}'", job.status.as_str())
                    })),
                )
                    .into_response();
            }

            state.queue.cancel_job(id);
            let _ = state
                .store
                .update_job_status(
                    auth.org_id,
                    id,
                    crate::store::models::JobStatus::Cancelled,
                    None,
                    Some("Cancelled by operator request"),
                )
                .await;

            (
                StatusCode::OK,
                Json(json!({
                    "message": "Cancellation request submitted",
                    "job_id": id.to_string()
                })),
            )
                .into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": "not_found",
                "message": "Assessment job not found"
            })),
        )
            .into_response(),
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

/// `GET /api/v1/assessments/jobs/:id/findings` - Lists findings discovered by a specific job.
pub async fn get_job_findings_handler(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedUser,
    Path(id): Path<Uuid>,
) -> Response {
    match state.store.list_findings(auth.org_id, Some(id), None).await {
        Ok(findings) => (StatusCode::OK, Json(findings)).into_response(),
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

/// `GET /api/v1/assessments/findings` - Lists all findings across the organization.
pub async fn list_all_findings_handler(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedUser,
    Query(query): Query<ListFindingsQuery>,
) -> Response {
    match state
        .store
        .list_findings(auth.org_id, None, query.min_severity.as_deref())
        .await
    {
        Ok(findings) => (StatusCode::OK, Json(findings)).into_response(),
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
