//! Authentication and authorization extractors and middleware.

use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

use super::token::{verify_token_with_fallbacks, TokenClaims};
use crate::state::AppState;
use crate::store::models::Role;

/// Authenticated user context injected into request handlers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedUser {
    pub jti: Uuid,
    pub user_id: Uuid,
    pub org_id: Uuid,
    pub role: Role,
    pub email: String,
    pub expires_at: i64,
}

impl AuthenticatedUser {
    /// Asserts that the authenticated user holds at least the required role.
    ///
    /// # Errors
    ///
    /// Returns HTTP 403 Forbidden if user lacks sufficient privilege.
    pub fn require_role(&self, minimum_role: Role) -> Result<(), Response> {
        if self.role >= minimum_role {
            Ok(())
        } else {
            Err((
                StatusCode::FORBIDDEN,
                Json(json!({
                    "error": "insufficient_permissions",
                    "message": format!(
                        "Operation requires '{}' role or higher; user has '{}'",
                        minimum_role.as_str(),
                        self.role.as_str()
                    )
                })),
            )
                .into_response())
        }
    }
}

#[axum::async_trait]
impl<S> FromRequestParts<S> for AuthenticatedUser
where
    S: Send + Sync,
    Arc<AppState>: FromRef<S>,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = Arc::<AppState>::from_ref(state);

        let auth_header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .ok_or_else(|| {
                (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({
                        "error": "unauthorized",
                        "message": "Missing 'Authorization: Bearer <token>' header"
                    })),
                )
                    .into_response()
            })?;

        let token_str = auth_header
            .strip_prefix("Bearer ")
            .or_else(|| auth_header.strip_prefix("bearer "))
            .ok_or_else(|| {
                (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({
                        "error": "unauthorized",
                        "message": "Malformed Authorization header; expected 'Bearer <token>'"
                    })),
                )
                    .into_response()
            })?;

        let claims: TokenClaims = verify_token_with_fallbacks(
            token_str.trim(),
            &app_state.config.secret_key,
            &app_state.config.fallback_secret_keys,
        )
        .map_err(|err| {
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "unauthorized",
                    "message": format!("Invalid or expired token: {err}")
                })),
            )
                .into_response()
        })?;

        // Check if token has been explicitly revoked
        if app_state
            .store
            .is_token_revoked(claims.jti)
            .await
            .unwrap_or(false)
        {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "token_revoked",
                    "message": "Authentication token has been revoked"
                })),
            )
                .into_response());
        }

        Ok(Self {
            jti: claims.jti,
            user_id: claims.user_id,
            org_id: claims.org_id,
            role: claims.role,
            email: claims.email,
            expires_at: claims.expires_at,
        })
    }
}
