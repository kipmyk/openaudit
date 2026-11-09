//! Version and capability discovery endpoints.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use std::sync::Arc;

use crate::state::AppState;

/// Version metadata payload.
#[derive(Debug, Clone, Serialize)]
pub struct VersionResponse {
    pub name: &'static str,
    pub version: &'static str,
    pub environment: &'static str,
}

/// Server capabilities payload.
#[derive(Debug, Clone, Serialize)]
pub struct CapabilitiesResponse {
    pub name: &'static str,
    pub version: &'static str,
    pub environment: &'static str,
    pub capabilities: ServerCapabilities,
}

/// Detailed feature flags and supported subsystems.
#[derive(Debug, Clone, Serialize)]
pub struct ServerCapabilities {
    pub local_host_auditing: bool,
    pub network_perimeter_auditing: bool,
    pub d4_attestation: bool,
    pub scheduled_assessments: bool,
    pub tenant_isolation: bool,
    pub rbac_roles: &'static [&'static str],
    pub supported_scan_profiles: &'static [&'static str],
    pub supported_output_formats: &'static [&'static str],
}

/// `GET /version` handler returning service release version.
pub async fn version_handler(State(state): State<Arc<AppState>>) -> Response {
    let env_str = match state.config.environment {
        crate::config::ServerEnvironment::Development => "development",
        crate::config::ServerEnvironment::Test => "test",
        crate::config::ServerEnvironment::Staging => "staging",
        crate::config::ServerEnvironment::Production => "production",
    };

    (
        StatusCode::OK,
        Json(VersionResponse {
            name: "OpenAudit Control Plane",
            version: openaudit_core::version(),
            environment: env_str,
        }),
    )
        .into_response()
}

/// `GET /api/v1/capabilities` handler exposing platform features and contracts.
pub async fn capabilities_handler(State(state): State<Arc<AppState>>) -> Response {
    let env_str = match state.config.environment {
        crate::config::ServerEnvironment::Development => "development",
        crate::config::ServerEnvironment::Test => "test",
        crate::config::ServerEnvironment::Staging => "staging",
        crate::config::ServerEnvironment::Production => "production",
    };

    (
        StatusCode::OK,
        Json(CapabilitiesResponse {
            name: "OpenAudit Control Plane",
            version: openaudit_core::version(),
            environment: env_str,
            capabilities: ServerCapabilities {
                local_host_auditing: true,
                network_perimeter_auditing: true,
                d4_attestation: true,
                scheduled_assessments: true,
                tenant_isolation: true,
                rbac_roles: &["admin", "auditor", "viewer"],
                supported_scan_profiles: &[
                    "baseline",
                    "full",
                    "hardened",
                    "conservative",
                    "standard",
                    "deep",
                ],
                supported_output_formats: &["human", "json", "html", "markdown"],
            },
        }),
    )
        .into_response()
}
