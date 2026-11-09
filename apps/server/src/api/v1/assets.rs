//! Asset inventory management routes.

use axum::extract::{Path, State};
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
pub struct CreateAssetRequest {
    pub name: String,
    pub asset_type: String,
    pub target: String,
    pub criticality: Option<String>,
}

/// `POST /api/v1/assets` - Creates a new asset within caller's organization.
pub async fn create_asset_handler(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedUser,
    Json(payload): Json<CreateAssetRequest>,
) -> Response {
    if let Err(res) = auth.require_role(Role::Auditor) {
        return res;
    }

    let name = payload.name.trim();
    let target = payload.target.trim();
    if name.is_empty() || target.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_input",
                "message": "Asset name and target cannot be empty"
            })),
        )
            .into_response();
    }

    let criticality = payload.criticality.as_deref().unwrap_or("medium");
    match state
        .store
        .create_asset(auth.org_id, name, &payload.asset_type, target, criticality)
    {
        Ok(asset) => (StatusCode::CREATED, Json(asset)).into_response(),
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

/// `GET /api/v1/assets` - Lists assets belonging to caller's organization.
pub async fn list_assets_handler(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedUser,
) -> Response {
    match state.store.list_assets(auth.org_id) {
        Ok(assets) => (StatusCode::OK, Json(assets)).into_response(),
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

/// `GET /api/v1/assets/:id` - Retrieves a specific asset by ID.
pub async fn get_asset_handler(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedUser,
    Path(id): Path<Uuid>,
) -> Response {
    match state.store.get_asset(auth.org_id, id) {
        Ok(Some(asset)) => (StatusCode::OK, Json(asset)).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": "not_found",
                "message": "Asset not found"
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

/// `DELETE /api/v1/assets/:id` - Deletes an asset from caller's organization.
pub async fn delete_asset_handler(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedUser,
    Path(id): Path<Uuid>,
) -> Response {
    if let Err(res) = auth.require_role(Role::Admin) {
        return res;
    }

    match state.store.delete_asset(auth.org_id, id) {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": "not_found",
                "message": "Asset not found"
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
