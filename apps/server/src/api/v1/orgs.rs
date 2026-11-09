//! Tenant organization and user management routes.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

use crate::auth::{hash_password, AuthenticatedUser};
use crate::state::AppState;
use crate::store::models::Role;

#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub email: String,
    pub password: String,
    pub name: String,
    pub role: String,
}

/// `GET /api/v1/organizations/current` - Retrieves caller's tenant organization details.
pub async fn get_current_org_handler(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedUser,
) -> Response {
    match state.store.get_organization(auth.org_id) {
        Ok(Some(org)) => (StatusCode::OK, Json(org)).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": "not_found",
                "message": "Organization not found"
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

/// `GET /api/v1/organizations/users` - Lists users within caller's organization.
pub async fn list_org_users_handler(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedUser,
) -> Response {
    match state.store.list_users(auth.org_id) {
        Ok(users) => (StatusCode::OK, Json(users)).into_response(),
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

/// `POST /api/v1/organizations/users` - Creates a new user in caller's organization (requires Admin).
pub async fn create_org_user_handler(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedUser,
    Json(payload): Json<CreateUserRequest>,
) -> Response {
    if let Err(res) = auth.require_role(Role::Admin) {
        return res;
    }

    let role = match Role::parse(&payload.role) {
        Ok(r) => r,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "invalid_role",
                    "message": err
                })),
            )
                .into_response();
        }
    };

    let p_hash = match hash_password(&payload.password) {
        Ok(h) => h,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "weak_password",
                    "message": err
                })),
            )
                .into_response();
        }
    };

    match state
        .store
        .create_user(auth.org_id, &payload.email, &p_hash, &payload.name, role)
    {
        Ok(user) => (StatusCode::CREATED, Json(user)).into_response(),
        Err(err) => (
            StatusCode::CONFLICT,
            Json(json!({
                "error": "user_creation_failed",
                "message": err.to_string()
            })),
        )
            .into_response(),
    }
}
