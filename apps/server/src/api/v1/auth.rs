//! Authentication API routes.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;

use crate::auth::{hash_password, issue_token, verify_password, AuthenticatedUser};
use crate::state::AppState;
use crate::store::models::Role;

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub user: UserProfile,
}

#[derive(Debug, Serialize)]
pub struct UserProfile {
    pub id: String,
    pub org_id: String,
    pub email: String,
    pub name: String,
    pub role: &'static str,
}

#[derive(Debug, Deserialize)]
pub struct RegisterInitialAdminRequest {
    pub org_name: String,
    pub org_slug: String,
    pub email: String,
    pub password: String,
    pub name: String,
}

/// `POST /api/v1/auth/login` - Authenticates user and issues signed session token.
pub async fn login_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<LoginRequest>,
) -> Response {
    let email = payload.email.trim().to_lowercase();
    let user = match state.store.get_user_by_email(&email) {
        Ok(Some(u)) => u,
        Ok(None) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "invalid_credentials",
                    "message": "Invalid email or password"
                })),
            )
                .into_response();
        }
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "internal_error",
                    "message": format!("Database lookup error: {err}")
                })),
            )
                .into_response();
        }
    };

    if !user.is_active {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "account_disabled",
                "message": "This account is inactive"
            })),
        )
            .into_response();
    }

    match verify_password(&payload.password, &user.password_hash) {
        Ok(true) => (),
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "invalid_credentials",
                    "message": "Invalid email or password"
                })),
            )
                .into_response();
        }
    }

    // Issue token valid for 24 hours (86400 seconds)
    let token = match issue_token(
        user.id,
        user.org_id,
        user.role,
        &user.email,
        86400,
        &state.config.secret_key,
    ) {
        Ok(t) => t,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "token_issuance_failed",
                    "message": format!("Failed to sign authentication token: {err}")
                })),
            )
                .into_response();
        }
    };

    (
        StatusCode::OK,
        Json(LoginResponse {
            token,
            user: UserProfile {
                id: user.id.to_string(),
                org_id: user.org_id.to_string(),
                email: user.email,
                name: user.name,
                role: user.role.as_str(),
            },
        }),
    )
        .into_response()
}

/// `POST /api/v1/auth/bootstrap` - Initializes the first tenant organization and admin user.
pub async fn bootstrap_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RegisterInitialAdminRequest>,
) -> Response {
    let org_slug = payload.org_slug.trim().to_lowercase();
    let org = match state
        .store
        .create_organization(&payload.org_name, &org_slug)
    {
        Ok(o) => o,
        Err(err) => {
            return (
                StatusCode::CONFLICT,
                Json(json!({
                    "error": "organization_conflict",
                    "message": format!("Failed to create organization: {err}")
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
                    "message": format!("Invalid password: {err}")
                })),
            )
                .into_response();
        }
    };

    let user =
        match state
            .store
            .create_user(org.id, &payload.email, &p_hash, &payload.name, Role::Admin)
        {
            Ok(u) => u,
            Err(err) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({
                        "error": "user_creation_failed",
                        "message": format!("Failed to create admin user: {err}")
                    })),
                )
                    .into_response();
            }
        };

    let token = match issue_token(
        user.id,
        user.org_id,
        user.role,
        &user.email,
        86400,
        &state.config.secret_key,
    ) {
        Ok(t) => t,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "token_issuance_failed",
                    "message": err
                })),
            )
                .into_response();
        }
    };

    (
        StatusCode::CREATED,
        Json(LoginResponse {
            token,
            user: UserProfile {
                id: user.id.to_string(),
                org_id: user.org_id.to_string(),
                email: user.email,
                name: user.name,
                role: user.role.as_str(),
            },
        }),
    )
        .into_response()
}

/// `GET /api/v1/auth/me` - Returns caller's profile and tenant context.
pub async fn me_handler(State(state): State<Arc<AppState>>, auth: AuthenticatedUser) -> Response {
    let org = state.store.get_organization(auth.org_id).ok().flatten();

    (
        StatusCode::OK,
        Json(json!({
            "user_id": auth.user_id.to_string(),
            "org_id": auth.org_id.to_string(),
            "email": auth.email,
            "role": auth.role.as_str(),
            "organization": org.map(|o| json!({
                "id": o.id.to_string(),
                "name": o.name,
                "slug": o.slug
            }))
        })),
    )
        .into_response()
}
