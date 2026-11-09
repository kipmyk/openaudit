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
        fallback_secret_keys: vec!["old-rotated-fallback-secret-at-least-32b!".into()],
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
    assert!(body["uptime_secs"].is_number());
    assert_eq!(body["version"], openaudit_core::version());

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
    assert_eq!(body["storage_ready"], true);

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
    assert_eq!(body["version"], openaudit_core::version());

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
    assert_eq!(body["capabilities"]["d4_attestation"], true);
    assert_eq!(body["capabilities"]["tenant_isolation"], true);
}

#[tokio::test]
async fn test_m5_3_auth_lifecycle_and_rbac_enforcement() {
    let (app, _, _) = create_test_app();

    // 1. Bootstrap initial admin
    let bootstrap_payload = json!({
        "org_name": "Cyber Defense Inc",
        "org_slug": "cyberdef",
        "email": "admin@cyberdef.org",
        "password": "SuperSecurePassword123!",
        "name": "Initial Admin"
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
    assert!(body["token"].is_string());
    assert_eq!(body["user"]["role"], "admin");
    assert_eq!(body["user"]["email"], "admin@cyberdef.org");

    let admin_token = body["token"].as_str().unwrap();

    // 2. Reject duplicate bootstrap (conflict)
    let req = Request::builder()
        .uri("/api/v1/auth/bootstrap")
        .method(Method::POST)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(bootstrap_payload.to_string()))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        res.status(),
        StatusCode::CONFLICT,
        "Duplicate bootstrap must be rejected"
    );

    // 3. Login with valid credentials
    let login_payload = json!({
        "email": "admin@cyberdef.org",
        "password": "SuperSecurePassword123!"
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

    // 4. Login with invalid password fails
    let bad_login = json!({
        "email": "admin@cyberdef.org",
        "password": "WrongPassword999!"
    });
    let req = Request::builder()
        .uri("/api/v1/auth/login")
        .method(Method::POST)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(bad_login.to_string()))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // 5. GET /api/v1/auth/me with valid Bearer token
    let req = Request::builder()
        .uri("/api/v1/auth/me")
        .method(Method::GET)
        .header(header::AUTHORIZATION, format!("Bearer {admin_token}"))
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    let (status, body) = json_response(res).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["email"], "admin@cyberdef.org");
    assert_eq!(body["role"], "admin");
    assert_eq!(body["organization"]["slug"], "cyberdef");

    // 6. Admin creates a Viewer user
    let viewer_payload = json!({
        "email": "viewer@cyberdef.org",
        "password": "ViewerPass123!",
        "name": "Audit Observer",
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
async fn test_m5_authentication_hardening_and_revocation() {
    let (app, store, state) = create_test_app();

    let org = store
        .create_organization("Security Corp", "security-corp")
        .await
        .unwrap();
    let user = store
        .create_user(
            org.id,
            "sec@corp.com",
            "argon2id$mockhash",
            "Sec User",
            Role::Admin,
        )
        .await
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

    // Test token works initially
    let req = Request::builder()
        .uri("/api/v1/auth/me")
        .method(Method::GET)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // Call POST /api/v1/auth/logout to revoke token
    let req = Request::builder()
        .uri("/api/v1/auth/logout")
        .method(Method::POST)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // Subsequent call with revoked token MUST be rejected with 401 Unauthorized
    let req = Request::builder()
        .uri("/api/v1/auth/me")
        .method(Method::GET)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        res.status(),
        StatusCode::UNAUTHORIZED,
        "Revoked token must be rejected"
    );

    // Test Login Rate Limiting (5 failed attempts trigger 429)
    for _ in 0..5 {
        state.login_limiter.record_failure("attacker@corp.com");
    }

    let bad_login = json!({
        "email": "attacker@corp.com",
        "password": "Password123!"
    });
    let req = Request::builder()
        .uri("/api/v1/auth/login")
        .method(Method::POST)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(bad_login.to_string()))
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(
        res.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "Exceeded login attempts must receive 429"
    );
}

#[tokio::test]
async fn test_m5_adversarial_cross_tenant_isolation() {
    let (app, store, state) = create_test_app();

    // Setup Tenant Org 1
    let org1 = store
        .create_organization("Tenant Alpha", "tenant-alpha")
        .await
        .unwrap();
    let user1 = store
        .create_user(org1.id, "u1@alpha.com", "hash", "User 1", Role::Admin)
        .await
        .unwrap();
    let _token1 = openaudit_server::auth::issue_token(
        user1.id,
        org1.id,
        user1.role,
        &user1.email,
        3600,
        &state.config.secret_key,
    )
    .unwrap();

    // Setup Tenant Org 2
    let org2 = store
        .create_organization("Tenant Bravo", "tenant-bravo")
        .await
        .unwrap();
    let user2 = store
        .create_user(org2.id, "u2@bravo.com", "hash", "User 2", Role::Admin)
        .await
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
        .create_asset(org1.id, "Alpha Server", "linux_host", "10.10.0.1", "high")
        .await
        .unwrap();

    // Org 2 tries to GET Org 1's asset by ID -> Expect 404 Not Found
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

    // Org 2 tries to DELETE Org 1's asset -> Expect 404 Not Found
    let req = Request::builder()
        .uri(format!("/api/v1/assets/{}", asset1.id))
        .method(Method::DELETE)
        .header(header::AUTHORIZATION, format!("Bearer {token2}"))
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        res.status(),
        StatusCode::NOT_FOUND,
        "Tenant 2 must not be able to delete Tenant 1 asset"
    );

    // Org 1 creates an assessment job
    let job1 = store
        .create_job(
            org1.id,
            Some(asset1.id),
            "10.10.0.1",
            "local_host",
            "standard",
        )
        .await
        .unwrap();

    // Org 2 tries to GET Org 1's job -> Expect 404 Not Found
    let req = Request::builder()
        .uri(format!("/api/v1/assessments/jobs/{}", job1.id))
        .method(Method::GET)
        .header(header::AUTHORIZATION, format!("Bearer {token2}"))
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        res.status(),
        StatusCode::NOT_FOUND,
        "Tenant 2 must not see Tenant 1 job"
    );

    // Org 2 tries to CANCEL Org 1's job -> Expect 404 Not Found
    let req = Request::builder()
        .uri(format!("/api/v1/assessments/jobs/{}/cancel", job1.id))
        .method(Method::POST)
        .header(header::AUTHORIZATION, format!("Bearer {token2}"))
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        res.status(),
        StatusCode::NOT_FOUND,
        "Tenant 2 must not be able to cancel Tenant 1 job"
    );

    // Org 1 creates finding
    let finding1 = openaudit_server::store::models::NewFinding {
        rule_id: "ssh.config".into(),
        severity: "High".into(),
        confidence: "Confirmed".into(),
        title: "Weak SSH".into(),
        endpoint: "10.10.0.1:22".into(),
        evidence: "PasswordAuthentication yes".into(),
        recommendation: "Use keys".into(),
    };
    store
        .create_findings(org1.id, job1.id, &[finding1])
        .await
        .unwrap();

    // Org 2 tries to GET Org 1 findings by job_id -> Expect 404 / empty
    let req = Request::builder()
        .uri(format!("/api/v1/assessments/jobs/{}/findings", job1.id))
        .method(Method::GET)
        .header(header::AUTHORIZATION, format!("Bearer {token2}"))
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    let (_, findings2) = json_response(res).await;
    assert_eq!(
        findings2.as_array().unwrap().len(),
        0,
        "Tenant 2 must not receive Tenant 1 findings"
    );

    // Org 2 lists all findings -> 0 findings returned
    let req = Request::builder()
        .uri("/api/v1/assessments/findings")
        .method(Method::GET)
        .header(header::AUTHORIZATION, format!("Bearer {token2}"))
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    let (_, all_findings2) = json_response(res).await;
    assert_eq!(
        all_findings2.as_array().unwrap().len(),
        0,
        "Tenant 2 list_findings must be isolated"
    );
}

#[tokio::test]
async fn test_m5_4_assessment_orchestration_and_findings() {
    let (app, store, state) = create_test_app();

    let org = store
        .create_organization("Acme Labs", "acme-labs")
        .await
        .unwrap();
    let user = store
        .create_user(org.id, "auditor@acme.com", "hash", "Auditor", Role::Auditor)
        .await
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
        if let Ok(Some(j)) = store.get_job(org.id, job_id).await {
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
    assert!(body["paths"].get("/auth/logout").is_some());
    assert!(body["paths"].get("/auth/bootstrap").is_some());
}
