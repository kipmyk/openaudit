//! Security posture intelligence, assessment comparison, and historical timeline routes.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

use crate::auth::AuthenticatedUser;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct PostureSummaryQuery {
    pub asset_id: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
pub struct CompareAssessmentsQuery {
    pub base: Uuid,
    pub target: Uuid,
}

#[derive(Debug, Deserialize)]
pub struct AssessmentHistoryQuery {
    pub asset_id: Option<Uuid>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

/// `GET /api/v1/posture/summary` - Retrieves transparent security posture summary metrics.
pub async fn get_posture_summary_handler(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedUser,
    Query(query): Query<PostureSummaryQuery>,
) -> Response {
    match state
        .store
        .get_security_posture_summary(auth.org_id, query.asset_id)
        .await
    {
        Ok(summary) => (StatusCode::OK, Json(summary)).into_response(),
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

/// `GET /api/v1/assessments/compare` - Compares two assessments and reconciles coverage diffs.
pub async fn compare_assessments_handler(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedUser,
    Query(query): Query<CompareAssessmentsQuery>,
) -> Response {
    match state
        .store
        .compare_assessments(auth.org_id, query.base, query.target)
        .await
    {
        Ok(comparison) => (StatusCode::OK, Json(comparison)).into_response(),
        Err(crate::store::StoreError::NotFound(msg)) => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": "not_found",
                "message": msg
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

/// `GET /api/v1/assessments/history` - Returns paginated historical assessment jobs.
pub async fn list_assessment_history_handler(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedUser,
    Query(query): Query<AssessmentHistoryQuery>,
) -> Response {
    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    let offset = query.offset.unwrap_or(0);

    match state
        .store
        .list_assessment_history(auth.org_id, query.asset_id, limit, offset)
        .await
    {
        Ok((jobs, total)) => (
            StatusCode::OK,
            Json(json!({
                "jobs": jobs,
                "total": total,
                "limit": limit,
                "offset": offset
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
