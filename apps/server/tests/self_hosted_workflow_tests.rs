//! End-to-end self-hosted operator workflow and restart persistence integration test suite (Milestone 8).

#![allow(
    clippy::too_many_lines,
    clippy::similar_names,
    clippy::cast_possible_truncation
)]

use axum::body::{to_bytes, Body};
use axum::http::{header, Method, Request, StatusCode};
use openaudit_server::api::create_router;
use openaudit_server::config::ServerConfig;
use openaudit_server::orchestration::JobQueue;
use openaudit_server::state::AppState;
use openaudit_server::store::sqlite::SqliteControlPlaneStore;
use openaudit_server::store::ControlPlaneStore;
use serde_json::{json, Value};
use std::sync::Arc;
use tempfile::tempdir;
use tower::ServiceExt;
use uuid::Uuid;

async fn json_body(res: axum::response::Response) -> (StatusCode, Value) {
    let status = res.status();
    let bytes = to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let val = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, val)
}

#[tokio::test]
async fn test_m8_complete_self_hosted_workflow_and_restart_persistence() {
    let temp_dir = tempdir().expect("Failed to create temporary directory for self-hosted test");
    let db_path = temp_dir.path().join("openaudit_self_hosted.db");

    let server_secret = "m8-super-secure-production-secret-at-least-32-bytes!".to_string();

    // =========================================================================
    // STEP 1: INITIAL DEPLOYMENT & HEALTH CHECKS
    // =========================================================================
    let store_v1 = Arc::new(
        SqliteControlPlaneStore::open(&db_path).expect("Failed to open SQLite database at path"),
    );
    let config_v1 = ServerConfig {
        secret_key: server_secret.clone(),
        ..Default::default()
    };
    let queue_v1 = JobQueue::new(4);
    let state_v1 = Arc::new(AppState::new(config_v1, store_v1.clone(), queue_v1));
    let app_v1 = create_router(state_v1.clone());

    // 1.1 Liveness check
    let req_live = Request::builder()
        .uri("/health/live")
        .body(Body::empty())
        .unwrap();
    let (st, body) = json_body(app_v1.clone().oneshot(req_live).await.unwrap()).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body["status"], "ok");

    // 1.2 Readiness check
    let req_ready = Request::builder()
        .uri("/health/ready")
        .body(Body::empty())
        .unwrap();
    let (st, body) = json_body(app_v1.clone().oneshot(req_ready).await.unwrap()).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body["status"], "ready");

    // 1.3 Web UI root application
    let req_ui = Request::builder().uri("/").body(Body::empty()).unwrap();
    let res_ui = app_v1.clone().oneshot(req_ui).await.unwrap();
    assert_eq!(res_ui.status(), StatusCode::OK);
    let ui_bytes = to_bytes(res_ui.into_body(), usize::MAX).await.unwrap();
    assert!(String::from_utf8_lossy(&ui_bytes).contains("OpenAudit Control Plane"));

    // 1.4 Unauthenticated request fails-closed
    let req_me_unauth = Request::builder()
        .uri("/api/v1/auth/me")
        .body(Body::empty())
        .unwrap();
    let (st, _) = json_body(app_v1.clone().oneshot(req_me_unauth).await.unwrap()).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);

    // =========================================================================
    // STEP 2: INITIAL ADMINISTRATOR & TENANT BOOTSTRAP
    // =========================================================================
    let req_bootstrap = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/bootstrap")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({
                "org_name": "Acme Defense Operations",
                "org_slug": "acme-defense",
                "name": "Lead Auditor",
                "email": "admin@acme-defense.sec",
                "password": "ProductionAdminPassword2026!"
            })
            .to_string(),
        ))
        .unwrap();
    let (st_boot, body_boot) =
        json_body(app_v1.clone().oneshot(req_bootstrap).await.unwrap()).await;
    assert_eq!(st_boot, StatusCode::CREATED);
    let admin_token = body_boot["token"].as_str().unwrap().to_string();
    let org_id = body_boot["user"]["org_id"].as_str().unwrap().to_string();

    // Second bootstrap attempt MUST be rejected with 409 Conflict
    let req_boot_replay = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/bootstrap")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({
                "org_name": "Attacker Org",
                "org_slug": "attacker",
                "name": "Attacker",
                "email": "attacker@corp.com",
                "password": "Password123!"
            })
            .to_string(),
        ))
        .unwrap();
    let (st_conflict, _) = json_body(app_v1.clone().oneshot(req_boot_replay).await.unwrap()).await;
    assert_eq!(st_conflict, StatusCode::CONFLICT);

    // =========================================================================
    // STEP 3: AUTHENTICATION & RBAC PERMISSIONS
    // =========================================================================
    // Verify admin me
    let req_me = Request::builder()
        .uri("/api/v1/auth/me")
        .header(header::AUTHORIZATION, format!("Bearer {admin_token}"))
        .body(Body::empty())
        .unwrap();
    let (st_me, body_me) = json_body(app_v1.clone().oneshot(req_me).await.unwrap()).await;
    assert_eq!(st_me, StatusCode::OK);
    assert_eq!(body_me["role"], "admin");

    // Admin creates an Auditor user
    let req_create_auditor = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/organizations/users")
        .header(header::AUTHORIZATION, format!("Bearer {admin_token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({
                "name": "Staff Auditor",
                "email": "auditor@acme-defense.sec",
                "password": "AuditorPassword2026!",
                "role": "auditor"
            })
            .to_string(),
        ))
        .unwrap();
    let (st_auditor, _) =
        json_body(app_v1.clone().oneshot(req_create_auditor).await.unwrap()).await;
    assert_eq!(st_auditor, StatusCode::CREATED);

    // Admin creates a Viewer user
    let req_create_viewer = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/organizations/users")
        .header(header::AUTHORIZATION, format!("Bearer {admin_token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({
                "name": "Audit Observer",
                "email": "viewer@acme-defense.sec",
                "password": "ViewerPassword2026!",
                "role": "viewer"
            })
            .to_string(),
        ))
        .unwrap();
    let (st_viewer, _) = json_body(app_v1.clone().oneshot(req_create_viewer).await.unwrap()).await;
    assert_eq!(st_viewer, StatusCode::CREATED);

    // Login as Viewer
    let req_login_viewer = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({
                "email": "viewer@acme-defense.sec",
                "password": "ViewerPassword2026!"
            })
            .to_string(),
        ))
        .unwrap();
    let (st_v_login, b_v_login) =
        json_body(app_v1.clone().oneshot(req_login_viewer).await.unwrap()).await;
    assert_eq!(st_v_login, StatusCode::OK);
    let viewer_token = b_v_login["token"].as_str().unwrap();

    // Viewer attempts to invite a user -> MUST BE FORBIDDEN (403)
    let req_viewer_forbidden = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/organizations/users")
        .header(header::AUTHORIZATION, format!("Bearer {viewer_token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({
                "name": "Hacked",
                "email": "hacked@corp.com",
                "password": "Password123!",
                "role": "admin"
            })
            .to_string(),
        ))
        .unwrap();
    let (st_forbid, _) =
        json_body(app_v1.clone().oneshot(req_viewer_forbidden).await.unwrap()).await;
    assert_eq!(st_forbid, StatusCode::FORBIDDEN);

    // =========================================================================
    // STEP 4: ASSET INVENTORY
    // =========================================================================
    let req_add_asset = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/assets")
        .header(header::AUTHORIZATION, format!("Bearer {admin_token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({
                "name": "Production API Ingress",
                "asset_type": "server",
                "target": "api.acme-defense.sec",
                "criticality": "critical"
            })
            .to_string(),
        ))
        .unwrap();
    let (st_asset, b_asset) = json_body(app_v1.clone().oneshot(req_add_asset).await.unwrap()).await;
    assert_eq!(st_asset, StatusCode::CREATED);
    let asset_id = b_asset["id"].as_str().unwrap().to_string();

    // =========================================================================
    // STEP 5: AGENT ENROLLMENT & LIFECYCLE
    // =========================================================================
    let req_agent_tok = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/agents/tokens")
        .header(header::AUTHORIZATION, format!("Bearer {admin_token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({ "machine_id": "agent-worker-01", "ttl_minutes": 60 }).to_string(),
        ))
        .unwrap();
    let (st_tok, b_tok) = json_body(app_v1.clone().oneshot(req_agent_tok).await.unwrap()).await;
    assert_eq!(st_tok, StatusCode::CREATED);
    let tok_id = b_tok["token_id"].as_str().unwrap();
    let tok_secret = b_tok["token_secret"].as_str().unwrap();
    let nonce = b_tok["challenge_nonce"].as_str().unwrap();

    // Agent enrolls
    let req_enroll = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/agent/enroll")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({
                "token_id": tok_id,
                "token_secret": tok_secret,
                "challenge_response": format!("{}:agent-worker-01", nonce),
                "machine_id": "agent-worker-01",
                "hostname": "worker-01.acme.sec",
                "agent_version": "0.1.0-alpha.0",
                "public_identity": "pure-crypto:agent-worker-01"
            })
            .to_string(),
        ))
        .unwrap();
    let (st_enrolled, b_enrolled) =
        json_body(app_v1.clone().oneshot(req_enroll).await.unwrap()).await;
    assert_eq!(st_enrolled, StatusCode::CREATED);
    let agent_id = b_enrolled["agent_id"].as_str().unwrap().to_string();
    let agent_auth_key = b_enrolled["auth_key"].as_str().unwrap().to_string();

    // Verify agent is registered as active
    let req_ag_get = Request::builder()
        .uri(format!("/api/v1/agents/{agent_id}"))
        .header(header::AUTHORIZATION, format!("Bearer {admin_token}"))
        .body(Body::empty())
        .unwrap();
    let (st_ag, b_ag) = json_body(app_v1.clone().oneshot(req_ag_get).await.unwrap()).await;
    assert_eq!(st_ag, StatusCode::OK);
    assert_eq!(b_ag["status"], "active");

    // Agent sends heartbeat
    let req_hb = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/agent/heartbeat")
        .header("X-Agent-Key", &agent_auth_key)
        .body(Body::empty())
        .unwrap();
    let (st_hb, _) = json_body(app_v1.clone().oneshot(req_hb).await.unwrap()).await;
    assert_eq!(st_hb, StatusCode::OK);

    // =========================================================================
    // STEP 6: ASSESSMENT DISPATCH & EXECUTION (JOB 1: BASELINE)
    // =========================================================================
    let job1 = store_v1
        .create_job(
            Uuid::parse_str(&org_id).unwrap(),
            Some(Uuid::parse_str(&asset_id).unwrap()),
            "api.acme-defense.sec",
            "perimeter",
            "standard",
        )
        .await
        .unwrap();
    let job1_id = job1.id.to_string();

    // Agent claims job 1
    let req_poll = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/agent/jobs/poll")
        .header("X-Agent-Key", &agent_auth_key)
        .body(Body::empty())
        .unwrap();
    let (st_poll, b_poll) = json_body(app_v1.clone().oneshot(req_poll).await.unwrap()).await;
    assert_eq!(st_poll, StatusCode::OK);
    assert_eq!(b_poll["job"]["id"], job1_id);

    // Agent submits results with 2 findings
    let req_results1 = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/v1/agent/jobs/{job1_id}/results"))
        .header("X-Agent-Key", &agent_auth_key)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({
                "summary_json": "{\"evaluated\": [\"tls.cert.expired\", \"http.headers.missing-csp\"]}",
                "findings": [
                    {
                        "rule_id": "tls.cert.expired",
                        "severity": "High",
                        "confidence": "Confirmed",
                        "title": "TLS Certificate Expired",
                        "endpoint": "api.acme-defense.sec:443",
                        "evidence": "NotAfter: 2026-01-01",
                        "recommendation": "Renew leaf certificate"
                    },
                    {
                        "rule_id": "http.headers.missing-csp",
                        "severity": "Medium",
                        "confidence": "Confirmed",
                        "title": "Missing Content-Security-Policy",
                        "endpoint": "api.acme-defense.sec:443",
                        "evidence": "CSP header absent",
                        "recommendation": "Configure strict CSP"
                    }
                ]
            })
            .to_string(),
        ))
        .unwrap();
    let (st_sub1, _) = json_body(app_v1.clone().oneshot(req_results1).await.unwrap()).await;
    assert_eq!(st_sub1, StatusCode::OK);

    // =========================================================================
    // STEP 7: FINDING LIFECYCLE & REMEDIATION MANAGEMENT
    // =========================================================================
    let req_list_f = Request::builder()
        .uri("/api/v1/findings")
        .header(header::AUTHORIZATION, format!("Bearer {admin_token}"))
        .body(Body::empty())
        .unwrap();
    let (st_lf, b_lf) = json_body(app_v1.clone().oneshot(req_list_f).await.unwrap()).await;
    assert_eq!(st_lf, StatusCode::OK);
    let findings_arr = b_lf["findings"].as_array().unwrap();
    assert_eq!(findings_arr.len(), 2);

    let tls_finding = findings_arr
        .iter()
        .find(|f| f["rule_id"] == "tls.cert.expired")
        .unwrap();
    let tls_finding_id = tls_finding["id"].as_str().unwrap();

    // Transition status to in_progress
    let req_status_up = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/v1/findings/{tls_finding_id}/status"))
        .header(header::AUTHORIZATION, format!("Bearer {admin_token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({
                "status": "in_progress",
                "comment": "Certificate renewal request opened with DevOps"
            })
            .to_string(),
        ))
        .unwrap();
    let (st_up, b_up) = json_body(app_v1.clone().oneshot(req_status_up).await.unwrap()).await;
    assert_eq!(st_up, StatusCode::OK);
    assert_eq!(b_up["status"], "in_progress");

    // Assign owner and remediation notes
    let req_assign = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/v1/findings/{tls_finding_id}/assign"))
        .header(header::AUTHORIZATION, format!("Bearer {admin_token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({
                "assigned_owner": "sec-ops@acme.sec",
                "due_date": "2026-12-01T00:00:00Z",
                "remediation_notes": "Automated renewal PR #142 submitted"
            })
            .to_string(),
        ))
        .unwrap();
    let (st_as, b_as) = json_body(app_v1.clone().oneshot(req_assign).await.unwrap()).await;
    assert_eq!(st_as, StatusCode::OK);
    assert_eq!(b_as["assigned_owner"], "sec-ops@acme.sec");

    // =========================================================================
    // STEP 8: FOLLOW-UP ASSESSMENT & COVERAGE-AWARE COMPARISON
    // =========================================================================
    // Job 2: Evaluates tls.cert.expired (remediated!) but omits http.headers.missing-csp
    let job2 = store_v1
        .create_job(
            Uuid::parse_str(&org_id).unwrap(),
            Some(Uuid::parse_str(&asset_id).unwrap()),
            "api.acme-defense.sec",
            "perimeter",
            "tls_only",
        )
        .await
        .unwrap();
    let job2_id = job2.id.to_string();

    // Agent claims job 2
    let req_poll2 = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/agent/jobs/poll")
        .header("X-Agent-Key", &agent_auth_key)
        .body(Body::empty())
        .unwrap();
    let (st_poll2, b_poll2) = json_body(app_v1.clone().oneshot(req_poll2).await.unwrap()).await;
    assert_eq!(st_poll2, StatusCode::OK);
    assert_eq!(b_poll2["job"]["id"], job2_id);

    // Agent submits results for Job 2: zero findings discovered, but rules_evaluated is ["tls.cert.expired"]
    let req_results2 = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/v1/agent/jobs/{job2_id}/results"))
        .header("X-Agent-Key", &agent_auth_key)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({
                "summary_json": "{\"evaluated\": [\"tls.cert.expired\"]}",
                "findings": []
            })
            .to_string(),
        ))
        .unwrap();
    let (st_sub2, _) = json_body(app_v1.clone().oneshot(req_results2).await.unwrap()).await;
    assert_eq!(st_sub2, StatusCode::OK);

    // Coverage-Aware Comparison
    let req_comp = Request::builder()
        .uri(format!(
            "/api/v1/assessments/compare?base={job1_id}&target={job2_id}"
        ))
        .header(header::AUTHORIZATION, format!("Bearer {admin_token}"))
        .body(Body::empty())
        .unwrap();
    let (st_comp, b_comp) = json_body(app_v1.clone().oneshot(req_comp).await.unwrap()).await;
    assert_eq!(st_comp, StatusCode::OK);
    assert_eq!(b_comp["resolved_findings"].as_array().unwrap().len(), 1);
    assert_eq!(b_comp["unverified_omissions"].as_array().unwrap().len(), 1);
    assert_eq!(b_comp["new_findings"].as_array().unwrap().len(), 0);
    assert_eq!(b_comp["coverage_ratio"], 0.5);

    // =========================================================================
    // STEP 9: POSTURE SUMMARY & REPORT EXPORTS
    // =========================================================================
    let req_posture = Request::builder()
        .uri("/api/v1/posture/summary")
        .header(header::AUTHORIZATION, format!("Bearer {admin_token}"))
        .body(Body::empty())
        .unwrap();
    let (st_posture, b_posture) =
        json_body(app_v1.clone().oneshot(req_posture).await.unwrap()).await;
    assert_eq!(st_posture, StatusCode::OK);
    assert_eq!(b_posture["total_assets"], 1);
    assert_eq!(b_posture["assessed_assets"], 1);
    assert_eq!(b_posture["total_active_findings"], 1); // 1 active (CSP), TLS is resolved
    assert_eq!(b_posture["verified_remediations_count"], 1);

    // HTML Export
    let req_html = Request::builder()
        .uri(format!(
            "/api/v1/reports/export?job_id={job1_id}&format=html"
        ))
        .header(header::AUTHORIZATION, format!("Bearer {admin_token}"))
        .body(Body::empty())
        .unwrap();
    let res_html = app_v1.clone().oneshot(req_html).await.unwrap();
    assert_eq!(res_html.status(), StatusCode::OK);
    let html_bytes = to_bytes(res_html.into_body(), usize::MAX).await.unwrap();
    assert!(String::from_utf8_lossy(&html_bytes).contains("OpenAudit"));

    // CSV Export
    let req_csv = Request::builder()
        .uri(format!(
            "/api/v1/reports/export?job_id={job1_id}&format=csv"
        ))
        .header(header::AUTHORIZATION, format!("Bearer {admin_token}"))
        .body(Body::empty())
        .unwrap();
    let res_csv = app_v1.clone().oneshot(req_csv).await.unwrap();
    assert_eq!(res_csv.status(), StatusCode::OK);

    // JSON Export
    let req_json = Request::builder()
        .uri(format!(
            "/api/v1/reports/export?job_id={job1_id}&format=json"
        ))
        .header(header::AUTHORIZATION, format!("Bearer {admin_token}"))
        .body(Body::empty())
        .unwrap();
    let (st_json, b_json) = json_body(app_v1.clone().oneshot(req_json).await.unwrap()).await;
    assert_eq!(st_json, StatusCode::OK);
    assert_eq!(b_json["job"]["target"], "api.acme-defense.sec");
    assert_eq!(b_json["findings"].as_array().unwrap().len(), 2);

    // =========================================================================
    // STEP 10: PERSISTENT STATE ACROSS SERVER RESTARTS
    // =========================================================================
    // Completely drop v1 instances, simulating clean server shutdown
    drop(app_v1);
    drop(state_v1);
    drop(store_v1);

    // Spin up fresh v2 instance pointing to the exact same database file on disk!
    let store_v2 = Arc::new(
        SqliteControlPlaneStore::open(&db_path)
            .expect("Fresh store must successfully open existing SQLite database"),
    );
    let config_v2 = ServerConfig {
        secret_key: server_secret,
        ..Default::default()
    };
    let queue_v2 = JobQueue::new(4);
    let state_v2 = Arc::new(AppState::new(config_v2, store_v2.clone(), queue_v2));
    let app_v2 = create_router(state_v2);

    // 10.1 Verify existing session token still authenticates after restart
    let req_restart_me = Request::builder()
        .uri("/api/v1/auth/me")
        .header(header::AUTHORIZATION, format!("Bearer {admin_token}"))
        .body(Body::empty())
        .unwrap();
    let (st_r_me, b_r_me) = json_body(app_v2.clone().oneshot(req_restart_me).await.unwrap()).await;
    assert_eq!(st_r_me, StatusCode::OK);
    assert_eq!(b_r_me["email"], "admin@acme-defense.sec");

    // 10.2 Verify asset inventory persisted
    let req_restart_assets = Request::builder()
        .uri("/api/v1/assets")
        .header(header::AUTHORIZATION, format!("Bearer {admin_token}"))
        .body(Body::empty())
        .unwrap();
    let (st_r_assets, b_r_assets) =
        json_body(app_v2.clone().oneshot(req_restart_assets).await.unwrap()).await;
    assert_eq!(st_r_assets, StatusCode::OK);
    let assets = b_r_assets.as_array().unwrap();
    assert_eq!(assets.len(), 1);
    assert_eq!(assets[0]["name"], "Production API Ingress");
    assert_eq!(assets[0]["target"], "api.acme-defense.sec");

    // 10.3 Verify finding lifecycle and history persisted
    let req_restart_findings = Request::builder()
        .uri("/api/v1/findings")
        .header(header::AUTHORIZATION, format!("Bearer {admin_token}"))
        .body(Body::empty())
        .unwrap();
    let (st_r_f, b_r_f) =
        json_body(app_v2.clone().oneshot(req_restart_findings).await.unwrap()).await;
    assert_eq!(st_r_f, StatusCode::OK);
    let findings = b_r_f["findings"].as_array().unwrap();
    let tls_f_restart = findings
        .iter()
        .find(|f| f["rule_id"] == "tls.cert.expired")
        .unwrap();
    assert_eq!(tls_f_restart["status"], "resolved"); // Resolved by verified remediation

    // 10.4 Verify posture summary persisted
    let req_restart_posture = Request::builder()
        .uri("/api/v1/posture/summary")
        .header(header::AUTHORIZATION, format!("Bearer {admin_token}"))
        .body(Body::empty())
        .unwrap();
    let (st_r_posture, b_r_posture) =
        json_body(app_v2.clone().oneshot(req_restart_posture).await.unwrap()).await;
    assert_eq!(st_r_posture, StatusCode::OK);
    assert_eq!(b_r_posture["total_assets"], 1);
    assert_eq!(b_r_posture["verified_remediations_count"], 1);

    // =========================================================================
    // STEP 11: TENANT ISOLATION
    // =========================================================================
    // Create Tenant B
    let org_b = store_v2
        .create_organization("Beta Defense", "beta-defense")
        .await
        .unwrap();
    let user_b = store_v2
        .create_user(
            org_b.id,
            "admin@beta-defense.com",
            "mockhash",
            "Beta Admin",
            openaudit_server::store::models::Role::Admin,
        )
        .await
        .unwrap();
    let token_b = openaudit_server::auth::issue_token(
        user_b.id,
        org_b.id,
        user_b.role,
        &user_b.email,
        3600,
        "m8-super-secure-production-secret-at-least-32-bytes!",
    )
    .unwrap();

    // Tenant B attempts to fetch Tenant A's asset -> MUST BE 404
    let req_cross_asset = Request::builder()
        .uri(format!("/api/v1/assets/{asset_id}"))
        .header(header::AUTHORIZATION, format!("Bearer {token_b}"))
        .body(Body::empty())
        .unwrap();
    let (st_cross, _) = json_body(app_v2.clone().oneshot(req_cross_asset).await.unwrap()).await;
    assert_eq!(st_cross, StatusCode::NOT_FOUND);

    // Tenant B attempts to fetch Tenant A's finding -> MUST BE 404
    let req_cross_finding = Request::builder()
        .uri(format!("/api/v1/findings/{tls_finding_id}"))
        .header(header::AUTHORIZATION, format!("Bearer {token_b}"))
        .body(Body::empty())
        .unwrap();
    let (st_cross_f, _) = json_body(app_v2.clone().oneshot(req_cross_finding).await.unwrap()).await;
    assert_eq!(st_cross_f, StatusCode::NOT_FOUND);

    // Verify org_id string is non-empty
    assert!(!org_id.is_empty());
}
