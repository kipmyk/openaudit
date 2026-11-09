//! # Control Plane Integration Tests (M5)

#![allow(
    clippy::missing_errors_doc,
    clippy::significant_drop_tightening,
    clippy::too_many_lines,
    clippy::struct_excessive_bools,
    clippy::result_large_err,
    clippy::must_use_candidate,
    clippy::doc_markdown,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::too_many_arguments
)]

use axum::body::{to_bytes, Body};
use axum::http::{header, Method, Request, StatusCode};
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;

use openaudit_server::api::create_router;
use openaudit_server::config::ServerConfig;
use openaudit_server::orchestration::JobQueue;
use openaudit_server::state::AppState;
use openaudit_server::store::models::Role;
use openaudit_server::store::sqlite::SqliteControlPlaneStore;
use openaudit_server::store::ControlPlaneStore;

fn create_test_app() -> (axum::Router, Arc<SqliteControlPlaneStore>, Arc<AppState>) {
    let store = Arc::new(SqliteControlPlaneStore::in_memory().expect("In-memory SQLite failed"));
    let config = ServerConfig {
        secret_key: "test-secret-key-at-least-32-bytes-long!".into(),
        ..Default::default()
    };

    let queue = JobQueue::new(4);
    let state = Arc::new(AppState::new(config, store.clone(), queue));
    let router = create_router(state.clone());

    (router, store, state)
}

async fn json_response(res: axum::response::Response) -> (StatusCode, Value) {
    let status = res.status();
    let bytes = to_bytes(res.into_body(), usize::MAX)
        .await
        .expect("Must read response body");
    let body_str = String::from_utf8_lossy(&bytes);
    let val: Value = serde_json::from_str(&body_str).unwrap_or(Value::Null);
    (status, val)
}

#[tokio::test]
async fn test_m5_1_health_and_capabilities_endpoints() {
    let (app, _, _) = create_test_app();

    // 1. GET /health/live
    let req = Request::builder()
        .uri("/health/live")
        .method(Method::GET)
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    let (status, body) = json_response(res).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");

    // 2. GET /health/ready
    let req = Request::builder()
        .uri("/health/ready")
        .method(Method::GET)
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    let (status, body) = json_response(res).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ready");
    assert_eq!(body["database"], "connected");

    // 3. GET /version
    let req = Request::builder()
        .uri("/version")
        .method(Method::GET)
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    let (status, body) = json_response(res).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["name"], "OpenAudit Control Plane");

    // 4. GET /api/v1/capabilities
    let req = Request::builder()
        .uri("/api/v1/capabilities")
        .method(Method::GET)
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    let (status, body) = json_response(res).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["capabilities"]["local_host_auditing"], true);
    assert_eq!(body["capabilities"]["network_perimeter_auditing"], true);
    assert_eq!(body["capabilities"]["tenant_isolation"], true);
}

#[tokio::test]
async fn test_m5_3_auth_lifecycle_and_rbac_enforcement() {
    let (app, _, _) = create_test_app();

    // 1. Initial bootstrap of tenant org and admin
    let bootstrap_payload = json!({
        "org_name": "Cyber Defense Corp",
        "org_slug": "cyberdef",
        "email": "admin@cyberdef.org",
        "password": "Password123!",
        "name": "Chief Security Officer"
    });
    let req = Request::builder()
        .uri("/api/v1/auth/bootstrap")
        .method(Method::POST)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(bootstrap_payload.to_string()))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    let (status, body) = json_response(res).await;
    assert_eq!(status, StatusCode::CREATED);
    let admin_token = body["token"]
        .as_str()
        .expect("Token must exist")
        .to_string();
    assert_eq!(body["user"]["role"], "admin");

    // 2. Login with valid credentials
    let login_payload = json!({
        "email": "admin@cyberdef.org",
        "password": "Password123!"
    });
    let req = Request::builder()
        .uri("/api/v1/auth/login")
        .method(Method::POST)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(login_payload.to_string()))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    let (status, body) = json_response(res).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["token"].is_string());

    // 3. Login with invalid password fails with 401
    let bad_login = json!({
        "email": "admin@cyberdef.org",
        "password": "WrongPassword!"
    });
    let req = Request::builder()
        .uri("/api/v1/auth/login")
        .method(Method::POST)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(bad_login.to_string()))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // 4. GET /api/v1/auth/me with Admin token
    let req = Request::builder()
        .uri("/api/v1/auth/me")
        .method(Method::GET)
        .header(header::AUTHORIZATION, format!("Bearer {admin_token}"))
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    let (status, body) = json_response(res).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["role"], "admin");
    assert_eq!(body["email"], "admin@cyberdef.org");

    // 5. Create a Viewer user (requires Admin)
    let new_user_payload = json!({
        "email": "auditor@cyberdef.org",
        "password": "AuditorPass123!",
        "name": "Audit Analyst",
        "role": "auditor"
    });
    let req = Request::builder()
        .uri("/api/v1/organizations/users")
        .method(Method::POST)
        .header(header::AUTHORIZATION, format!("Bearer {admin_token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(new_user_payload.to_string()))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);

    // 6. Create a Read-Only Viewer
    let viewer_payload = json!({
        "email": "viewer@cyberdef.org",
        "password": "ViewerPass123!",
        "name": "Compliance Viewer",
        "role": "viewer"
    });
    let req = Request::builder()
        .uri("/api/v1/organizations/users")
        .method(Method::POST)
        .header(header::AUTHORIZATION, format!("Bearer {admin_token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(viewer_payload.to_string()))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);

    // Login as viewer
    let viewer_login = json!({
        "email": "viewer@cyberdef.org",
        "password": "ViewerPass123!"
    });
    let req = Request::builder()
        .uri("/api/v1/auth/login")
        .method(Method::POST)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(viewer_login.to_string()))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    let (_, viewer_body) = json_response(res).await;
    let viewer_token = viewer_body["token"].as_str().unwrap();

    // 7. RBAC Check: Viewer attempting to create an asset MUST be rejected with 403 Forbidden
    let asset_payload = json!({
        "name": "Production Database",
        "asset_type": "database",
        "target": "10.0.1.5",
        "criticality": "high"
    });
    let req = Request::builder()
        .uri("/api/v1/assets")
        .method(Method::POST)
        .header(header::AUTHORIZATION, format!("Bearer {viewer_token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(asset_payload.to_string()))
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "Viewer must not be permitted to create assets"
    );
}

#[tokio::test]
async fn test_m5_2_tenant_isolation_enforcement() {
    let (app, store, state) = create_test_app();

    // Setup Tenant Org 1
    let org1 = store.create_organization("Tenant One", "tenant-1").unwrap();
    let user1 = store
        .create_user(org1.id, "u1@tenant1.com", "hash", "User 1", Role::Admin)
        .unwrap();
    let token1 = openaudit_server::auth::issue_token(
        user1.id,
        org1.id,
        user1.role,
        &user1.email,
        3600,
        &state.config.secret_key,
    )
    .unwrap();

    // Setup Tenant Org 2
    let org2 = store.create_organization("Tenant Two", "tenant-2").unwrap();
    let user2 = store
        .create_user(org2.id, "u2@tenant2.com", "hash", "User 2", Role::Admin)
        .unwrap();
    let token2 = openaudit_server::auth::issue_token(
        user2.id,
        org2.id,
        user2.role,
        &user2.email,
        3600,
        &state.config.secret_key,
    )
    .unwrap();

    // Org 1 creates an asset
    let asset1 = store
        .create_asset(org1.id, "Org1 Server", "linux_host", "10.10.0.1", "high")
        .unwrap();

    // Org 2 tries to GET Org 1's asset by ID -> Expect 404 Not Found (tenant isolated)
    let req = Request::builder()
        .uri(format!("/api/v1/assets/{}", asset1.id))
        .method(Method::GET)
        .header(header::AUTHORIZATION, format!("Bearer {token2}"))
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        res.status(),
        StatusCode::NOT_FOUND,
        "Tenant 2 must not see Tenant 1 asset"
    );

    // Org 1 can retrieve its own asset
    let req = Request::builder()
        .uri(format!("/api/v1/assets/{}", asset1.id))
        .method(Method::GET)
        .header(header::AUTHORIZATION, format!("Bearer {token1}"))
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_m5_4_assessment_orchestration_and_findings() {
    let (app, store, state) = create_test_app();

    let org = store.create_organization("Acme Labs", "acme-labs").unwrap();
    let user = store
        .create_user(org.id, "auditor@acme.com", "hash", "Auditor", Role::Auditor)
        .unwrap();
    let token = openaudit_server::auth::issue_token(
        user.id,
        org.id,
        user.role,
        &user.email,
        3600,
        &state.config.secret_key,
    )
    .unwrap();

    // 1. Submit local host assessment job
    let job_payload = json!({
        "target": "localhost",
        "assessment_type": "local_host",
        "profile": "baseline"
    });
    let req = Request::builder()
        .uri("/api/v1/assessments/jobs")
        .method(Method::POST)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(job_payload.to_string()))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    let (status, body) = json_response(res).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let job_id_str = body["id"].as_str().unwrap();
    let job_id = uuid::Uuid::parse_str(job_id_str).unwrap();

    // Poll until completed (local audit completes within hundreds of milliseconds)
    let mut completed = false;
    for _ in 0..20 {
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        if let Ok(Some(j)) = store.get_job(org.id, job_id) {
            if j.status == openaudit_server::store::models::JobStatus::Completed {
                completed = true;
                break;
            }
        }
    }
    assert!(completed, "Assessment job must transition to Completed");

    // 2. Fetch job findings
    let req = Request::builder()
        .uri(format!("/api/v1/assessments/jobs/{job_id}/findings"))
        .method(Method::GET)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    let (status, body) = json_response(res).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.is_array());

    // 3. GET /api/openapi.json
    let req = Request::builder()
        .uri("/api/openapi.json")
        .method(Method::GET)
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    let (status, body) = json_response(res).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["openapi"], "3.1.0");
    assert!(body["paths"].get("/auth/login").is_some());
}
