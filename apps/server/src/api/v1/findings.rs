//! Managed security finding lifecycle and remediation tracking routes.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

use crate::auth::AuthenticatedUser;
use crate::state::AppState;
use crate::store::models::{FindingStatus, ResolutionType, Role};

#[derive(Debug, Deserialize)]
pub struct ListManagedFindingsQuery {
    pub asset_id: Option<Uuid>,
    pub status: Option<String>,
    pub severity: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateFindingStatusRequest {
    pub status: String,
    pub resolution_type: Option<String>,
    pub comment: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AssignFindingRequest {
    pub assigned_owner: Option<String>,
    pub due_date: Option<DateTime<Utc>>,
    pub remediation_notes: Option<String>,
}

/// `GET /api/v1/findings` - Lists managed security findings with optional filters.
pub async fn list_managed_findings_handler(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedUser,
    Query(query): Query<ListManagedFindingsQuery>,
) -> Response {
    let status_filter = match query.status.as_deref() {
        Some(s) => match FindingStatus::parse(s) {
            Ok(st) => Some(st),
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "invalid_status",
                        "message": e
                    })),
                )
                    .into_response();
            }
        },
        None => None,
    };

    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    let offset = query.offset.unwrap_or(0);

    match state
        .store
        .list_managed_findings(
            auth.org_id,
            query.asset_id,
            status_filter,
            query.severity.as_deref(),
            limit,
            offset,
        )
        .await
    {
        Ok((findings, total)) => (
            StatusCode::OK,
            Json(json!({
                "findings": findings,
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

/// `GET /api/v1/findings/:id` - Retrieves a single managed finding by ID.
pub async fn get_managed_finding_handler(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedUser,
    Path(id): Path<Uuid>,
) -> Response {
    match state.store.get_managed_finding(auth.org_id, id).await {
        Ok(Some(finding)) => (StatusCode::OK, Json(finding)).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": "not_found",
                "message": format!("Finding '{id}' not found")
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

/// `POST /api/v1/findings/:id/status` - Updates finding lifecycle status and records audit history.
pub async fn update_finding_status_handler(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedUser,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateFindingStatusRequest>,
) -> Response {
    if let Err(res) = auth.require_role(Role::Auditor) {
        return res;
    }

    let new_status = match FindingStatus::parse(&payload.status) {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "invalid_status",
                    "message": e
                })),
            )
                .into_response();
        }
    };

    let resolution_type = match payload.resolution_type.as_deref() {
        Some(r) => match ResolutionType::parse(r) {
            Ok(rt) => Some(rt),
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "invalid_resolution_type",
                        "message": e
                    })),
                )
                    .into_response();
            }
        },
        None => None,
    };

    match state
        .store
        .update_managed_finding_status(
            auth.org_id,
            id,
            Some(auth.user_id),
            new_status,
            resolution_type,
            payload.comment.as_deref(),
        )
        .await
    {
        Ok(updated) => (StatusCode::OK, Json(updated)).into_response(),
        Err(crate::store::StoreError::NotFound(_)) => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": "not_found",
                "message": format!("Finding '{id}' not found")
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

/// `POST /api/v1/findings/:id/assign` - Assigns owner, due date, and remediation notes.
pub async fn assign_finding_owner_handler(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedUser,
    Path(id): Path<Uuid>,
    Json(payload): Json<AssignFindingRequest>,
) -> Response {
    if let Err(res) = auth.require_role(Role::Auditor) {
        return res;
    }

    match state
        .store
        .assign_managed_finding_owner(
            auth.org_id,
            id,
            payload.assigned_owner.as_deref(),
            payload.due_date,
            payload.remediation_notes.as_deref(),
        )
        .await
    {
        Ok(updated) => (StatusCode::OK, Json(updated)).into_response(),
        Err(crate::store::StoreError::NotFound(_)) => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": "not_found",
                "message": format!("Finding '{id}' not found")
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

/// `GET /api/v1/findings/:id/history` - Retrieves the lifecycle transition history of a finding.
pub async fn get_finding_history_handler(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedUser,
    Path(id): Path<Uuid>,
) -> Response {
    match state
        .store
        .get_finding_status_history(auth.org_id, id)
        .await
    {
        Ok(history) => (StatusCode::OK, Json(history)).into_response(),
        Err(crate::store::StoreError::NotFound(_)) => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": "not_found",
                "message": format!("Finding '{id}' not found")
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
