//! OpenAPI 3.1 schema definition and route.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

/// `GET /api/openapi.json` - Exposes OpenAPI 3.1 specification for control plane contracts.
pub async fn openapi_json_handler() -> Response {
    let spec = json!({
        "openapi": "3.1.0",
        "info": {
            "title": "OpenAudit Control Plane API",
            "version": openaudit_core::version(),
            "description": "Authoritative control plane for security posture auditing, fleet asset management, and assessment orchestration."
        },
        "servers": [
            { "url": "/api/v1", "description": "API Version 1" }
        ],
        "paths": {
            "/auth/login": {
                "post": {
                    "summary": "Authenticate user and issue JWT",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["email", "password"],
                                    "properties": {
                                        "email": { "type": "string", "format": "email" },
                                        "password": { "type": "string" }
                                    }
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": { "description": "Authenticated session token issued" },
                        "401": { "description": "Invalid credentials" }
                    }
                }
            },
            "/assets": {
                "get": {
                    "summary": "List tenant assets",
                    "security": [{ "BearerAuth": [] }],
                    "responses": { "200": { "description": "List of assets" } }
                },
                "post": {
                    "summary": "Create new asset",
                    "security": [{ "BearerAuth": [] }],
                    "responses": { "201": { "description": "Asset created" } }
                }
            },
            "/assessments/jobs": {
                "post": {
                    "summary": "Enqueue new assessment job",
                    "security": [{ "BearerAuth": [] }],
                    "responses": { "202": { "description": "Job enqueued" } }
                },
                "get": {
                    "summary": "List assessment jobs",
                    "security": [{ "BearerAuth": [] }],
                    "responses": { "200": { "description": "List of jobs" } }
                }
            },
            "/assessments/findings": {
                "get": {
                    "summary": "List organization security findings",
                    "security": [{ "BearerAuth": [] }],
                    "responses": { "200": { "description": "List of security findings" } }
                }
            },
            "/schedules": {
                "get": {
                    "summary": "List recurring schedules",
                    "security": [{ "BearerAuth": [] }],
                    "responses": { "200": { "description": "List of schedules" } }
                },
                "post": {
                    "summary": "Create recurring schedule",
                    "security": [{ "BearerAuth": [] }],
                    "responses": { "201": { "description": "Schedule created" } }
                }
            }
        },
        "components": {
            "securitySchemes": {
                "BearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "HMAC-SHA256"
                }
            }
        }
    });

    (StatusCode::OK, Json(spec)).into_response()
}
