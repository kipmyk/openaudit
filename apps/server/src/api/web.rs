//! Embedded Web UI handlers for the OpenAudit Self-Hosted Control Plane (Milestone 8).

use axum::http::header::{HeaderValue, CONTENT_TYPE};
use axum::http::{StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

const INDEX_HTML: &str = include_str!("../web/index.html");
const APP_CSS: &str = include_str!("../web/app.css");
const APP_JS: &str = include_str!("../web/app.js");

/// Serves the root HTML application document.
pub async fn index_handler() -> Response {
    (
        StatusCode::OK,
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        )],
        INDEX_HTML,
    )
        .into_response()
}

/// Serves the stylesheet for the operator interface.
pub async fn css_handler() -> Response {
    (
        StatusCode::OK,
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/css; charset=utf-8"),
        )],
        APP_CSS,
    )
        .into_response()
}

/// Serves the JavaScript runtime bundle for the operator interface.
pub async fn js_handler() -> Response {
    (
        StatusCode::OK,
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("application/javascript; charset=utf-8"),
        )],
        APP_JS,
    )
        .into_response()
}

/// SPA fallback handler: routes non-API paths to `index.html` and unknown `/api/` paths to 404 JSON.
pub async fn fallback_handler(uri: Uri) -> Response {
    let path = uri.path();
    if path.starts_with("/api/") {
        (
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": "endpoint_not_found",
                "message": format!("The requested API route '{path}' does not exist on this server.")
            })),
        )
            .into_response()
    } else {
        index_handler().await
    }
}
