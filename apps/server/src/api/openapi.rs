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
                        "401": { "description": "Invalid credentials" },
                        "429": { "description": "Rate limit exceeded" }
                    }
                }
            },
            "/auth/logout": {
                "post": {
                    "summary": "Revoke current authentication token",
                    "security": [{ "BearerAuth": [] }],
                    "responses": {
                        "200": { "description": "Session token successfully revoked" },
                        "401": { "description": "Unauthorized" }
                    }
                }
            },
            "/auth/bootstrap": {
                "post": {
                    "summary": "Atomic one-time initial administrator and tenant bootstrap",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["org_name", "org_slug", "email", "password", "name"],
                                    "properties": {
                                        "org_name": { "type": "string" },
                                        "org_slug": { "type": "string" },
                                        "email": { "type": "string", "format": "email" },
                                        "password": { "type": "string" },
                                        "name": { "type": "string" }
                                    }
                                }
                            }
                        }
                    },
                    "responses": {
                        "201": { "description": "Initial administrator registered" },
                        "409": { "description": "Already bootstrapped or organization slug exists" }
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
            },
            "/agents/tokens": {
                "post": {
                    "summary": "Issue one-time agent enrollment token (Admin/Auditor)",
                    "security": [{ "BearerAuth": [] }],
                    "responses": { "201": { "description": "Enrollment token issued" } }
                }
            },
            "/agents": {
                "get": {
                    "summary": "List enrolled agents in tenant fleet",
                    "security": [{ "BearerAuth": [] }],
                    "responses": { "200": { "description": "List of enrolled agents" } }
                }
            },
            "/agent/enroll": {
                "post": {
                    "summary": "Outbound agent enrollment challenge verification",
                    "responses": { "201": { "description": "Agent enrolled and credentials issued" } }
                }
            },
            "/agent/heartbeat": {
                "post": {
                    "summary": "Outbound agent heartbeat and connectivity status",
                    "responses": { "200": { "description": "Heartbeat acknowledged" } }
                }
            },
            "/agent/jobs/poll": {
                "post": {
                    "summary": "Outbound agent job poll and atomic claim",
                    "responses": { "200": { "description": "Next claimable job or null" } }
                }
            },
            "/agent/jobs/{id}/results": {
                "post": {
                    "summary": "Submit structured findings and complete job",
                    "responses": { "200": { "description": "Results recorded" } }
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
