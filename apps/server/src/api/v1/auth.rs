//! Authentication API routes.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::Utc;
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

/// `POST /api/v1/auth/login` - Authenticates user and issues signed session token with rate limiting.
pub async fn login_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<LoginRequest>,
) -> Response {
    let email = payload.email.trim().to_lowercase();

    // Check rate limiter to prevent brute-force attacks
    if let Err(remaining_secs) = state.login_limiter.check_allowed(&email) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({
                "error": "too_many_requests",
                "message": format!("Too many failed login attempts. Please retry in {remaining_secs} seconds.")
            })),
        )
            .into_response();
    }

    let user = match state.store.get_user_by_email(&email).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            state.login_limiter.record_failure(&email);
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
        state.login_limiter.record_failure(&email);
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "account_disabled",
                "message": "This account is inactive"
            })),
        )
            .into_response();
    }

    if verify_password(&payload.password, &user.password_hash) == Ok(true) {
        // Password matches: clear failed attempt count
        state.login_limiter.record_success(&email);
    } else {
        state.login_limiter.record_failure(&email);
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "invalid_credentials",
                "message": "Invalid email or password"
            })),
        )
            .into_response();
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
                    "message": err
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

/// `POST /api/v1/auth/bootstrap` - Initializes the first tenant organization and admin user atomically.
pub async fn bootstrap_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RegisterInitialAdminRequest>,
) -> Response {
    let org_slug = payload.org_slug.trim().to_lowercase();
    let email = payload.email.trim().to_lowercase();

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

    // Execute atomic bootstrap transaction
    let (org, user) = match state
        .store
        .bootstrap_admin(&payload.org_name, &org_slug, &payload.name, &email, &p_hash)
        .await
    {
        Ok(res) => res,
        Err(err) => {
            return (
                StatusCode::CONFLICT,
                Json(json!({
                    "error": "bootstrap_conflict",
                    "message": format!("Bootstrap failed: {err}")
                })),
            )
                .into_response();
        }
    };

    let token = match issue_token(
        user.id,
        org.id,
        Role::Admin,
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
                org_id: org.id.to_string(),
                email: user.email,
                name: user.name,
                role: "admin",
            },
        }),
    )
        .into_response()
}

/// `POST /api/v1/auth/logout` - Revokes the current session token.
pub async fn logout_handler(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedUser,
) -> Response {
    let exp = chrono::DateTime::from_timestamp(auth.expires_at, 0).unwrap_or_else(Utc::now);

    match state.store.revoke_token(auth.jti, exp).await {
        Ok(()) => (
            StatusCode::OK,
            Json(json!({
                "message": "Successfully logged out and revoked session token"
            })),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "logout_failed",
                "message": format!("Failed to record token revocation: {err}")
            })),
        )
            .into_response(),
    }
}

/// `GET /api/v1/auth/me` - Returns details of the currently authenticated session.
pub async fn me_handler(State(state): State<Arc<AppState>>, auth: AuthenticatedUser) -> Response {
    let org = state
        .store
        .get_organization(auth.org_id)
        .await
        .ok()
        .flatten();

    (
        StatusCode::OK,
        Json(json!({
            "user_id": auth.user_id.to_string(),
            "org_id": auth.org_id.to_string(),
            "role": auth.role.as_str(),
            "email": auth.email,
            "organization": org.map(|o| json!({
                "id": o.id.to_string(),
                "name": o.name,
                "slug": o.slug,
                "created_at": o.created_at.to_rfc3339()
            }))
        })),
    )
        .into_response()
}
