//! Integration tests for embedded operator web UI and SPA fallback (Milestone 8).

use axum::body::{to_bytes, Body};
use axum::http::{header, Method, Request, StatusCode};
use openaudit_server::api::create_router;
use openaudit_server::config::ServerConfig;
use openaudit_server::orchestration::JobQueue;
use openaudit_server::state::AppState;
use openaudit_server::store::sqlite::SqliteControlPlaneStore;
use std::sync::Arc;
use tower::ServiceExt;

fn create_test_app() -> axum::Router {
    let store = Arc::new(SqliteControlPlaneStore::in_memory().expect("In-memory SQLite failed"));
    let config = ServerConfig {
        secret_key: "m8-web-ui-test-secret-at-least-32-bytes!".into(),
        ..Default::default()
    };
    let queue = JobQueue::new(2);
    let state = Arc::new(AppState::new(config, store, queue));
    create_router(state)
}

#[tokio::test]
async fn test_web_ui_root_serves_html() {
    let app = create_test_app();
    let req = Request::builder()
        .method(Method::GET)
        .uri("/")
        .body(Body::empty())
        .unwrap();

    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap(),
        "text/html; charset=utf-8"
    );

    let bytes = to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let html = String::from_utf8_lossy(&bytes);
    assert!(html.contains("<!DOCTYPE html>"));
    assert!(html.contains("OpenAudit Control Plane"));
    assert!(html.contains("id=\"app-shell\""));
    assert!(html.contains("id=\"view-posture\""));
}

#[tokio::test]
async fn test_web_ui_serves_css_and_js_assets() {
    const APP_IDENTIFIER: &str = "OpenAudit Operator Web Application";
    let app = create_test_app();

    // 1. CSS
    let req_css = Request::builder()
        .method(Method::GET)
        .uri("/app.css")
        .body(Body::empty())
        .unwrap();
    let response_css = app.clone().oneshot(req_css).await.unwrap();
    assert_eq!(response_css.status(), StatusCode::OK);
    assert_eq!(
        response_css
            .headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap(),
        "text/css; charset=utf-8"
    );
    let css_bytes = to_bytes(response_css.into_body(), usize::MAX)
        .await
        .unwrap();
    let css = String::from_utf8_lossy(&css_bytes);
    assert!(css.contains("--bg-app:"));
    assert!(css.contains("kpi-grid"));

    // 2. JS
    let req_js = Request::builder()
        .method(Method::GET)
        .uri("/app.js")
        .body(Body::empty())
        .unwrap();
    let response_js = app.oneshot(req_js).await.unwrap();
    assert_eq!(response_js.status(), StatusCode::OK);
    assert_eq!(
        response_js
            .headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap(),
        "application/javascript; charset=utf-8"
    );
    let js_bytes = to_bytes(response_js.into_body(), usize::MAX).await.unwrap();
    let js = String::from_utf8_lossy(&js_bytes);
    assert!(js.contains(APP_IDENTIFIER));
    assert!(js.contains("loadPostureOverview"));
}

#[tokio::test]
async fn test_web_ui_spa_fallback_and_api_404_routing() {
    let app = create_test_app();

    // 1. SPA fallback for frontend routes (e.g. /findings, /assessments)
    let req_spa = Request::builder()
        .method(Method::GET)
        .uri("/findings")
        .body(Body::empty())
        .unwrap();
    let response_spa = app.clone().oneshot(req_spa).await.unwrap();
    assert_eq!(response_spa.status(), StatusCode::OK);
    assert_eq!(
        response_spa
            .headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap(),
        "text/html; charset=utf-8"
    );

    // 2. Non-existent API route must NOT fallback to HTML; it must return 404 JSON
    let req_api_404 = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/nonexistent_route")
        .body(Body::empty())
        .unwrap();
    let response_api_404 = app.oneshot(req_api_404).await.unwrap();
    assert_eq!(response_api_404.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response_api_404
            .headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap(),
        "application/json"
    );
    let json_bytes = to_bytes(response_api_404.into_body(), usize::MAX)
        .await
        .unwrap();
    let json_str = String::from_utf8_lossy(&json_bytes);
    assert!(json_str.contains("endpoint_not_found"));
}
