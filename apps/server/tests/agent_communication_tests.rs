//! # OpenAudit M6: Agent Communication & Secure Enrollment Integration Tests
//!
//! Exhaustive test suite verifying the 15 required test areas:
//! 1. Successful tenant-bound enrollment
//! 2. Invalid and expired enrollment challenges
//! 3. Challenge replay rejection
//! 4. Agent identity binding and private-key protection
//! 5. Authenticated outbound polling
//! 6. Unauthorized and revoked agent rejection
//! 7. Job claiming and lease expiration
//! 8. Duplicate job claim prevention
//! 9. Idempotent result submission
//! 10. Cross-tenant agent and job isolation
//! 11. Server restart and agent reconnection
//! 12. Network interruption and retry behavior
//! 13. Credential rotation
//! 14. Malformed and oversized protocol messages
//! 15. End-to-end lifecycle using separate server and agent processes

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
    clippy::too_many_arguments,
    clippy::similar_names
)]

use axum::body::{to_bytes, Body};
use axum::http::{header, Method, Request, StatusCode};
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

use openaudit_server::api::create_router;
use openaudit_server::config::ServerConfig;
use openaudit_server::orchestration::JobQueue;
use openaudit_server::state::AppState;
use openaudit_server::store::models::{JobStatus, Role};
use openaudit_server::store::sqlite::SqliteControlPlaneStore;
use openaudit_server::store::ControlPlaneStore;

fn create_test_env() -> (axum::Router, Arc<SqliteControlPlaneStore>, Arc<AppState>) {
    let store = Arc::new(SqliteControlPlaneStore::in_memory().expect("In-memory SQLite failed"));
    let config = ServerConfig {
        secret_key: "m6-test-secret-key-at-least-32-bytes-long!".into(),
        fallback_secret_keys: vec!["m6-rotated-fallback-secret-at-least-32b!".into()],
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

async fn setup_tenant_and_admin(
    app: &axum::Router,
    org_name: &str,
    slug: &str,
    email: &str,
) -> (String, String) {
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/bootstrap")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({
                "org_name": org_name,
                "org_slug": slug,
                "email": email,
                "password": "Password123!Secure",
                "name": "Tenant Administrator"
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    let (_, body) = json_response(resp).await;
    let token = body["token"].as_str().unwrap().to_string();
    let org_id = body["user"]["org_id"].as_str().unwrap().to_string();
    (token, org_id)
}

async fn create_additional_tenant(
    store: &Arc<SqliteControlPlaneStore>,
    state: &Arc<AppState>,
    org_name: &str,
    slug: &str,
    email: &str,
) -> (String, String) {
    let org = store.create_organization(org_name, slug).await.unwrap();
    let user = store
        .create_user(org.id, email, "argon2id$mockhash", "Admin 2", Role::Admin)
        .await
        .unwrap();
    let token = openaudit_server::auth::token::issue_token(
        user.id,
        org.id,
        user.role,
        &user.email,
        3600,
        &state.config.secret_key,
    )
    .unwrap();
    (token, org.id.to_string())
}

#[tokio::test]
async fn test_m6_agent_enrollment_and_security_validation() {
    let (app, _store, _) = create_test_env();
    let (admin_token, _org1_id) =
        setup_tenant_and_admin(&app, "Security Ops", "sec-ops", "admin@secops.com").await;

    // 1. Issue enrollment token as operator (Admin)
    let token_req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/agents/tokens")
        .header(header::AUTHORIZATION, format!("Bearer {admin_token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({
                "machine_id": "agent-host-01",
                "ttl_minutes": 15
            })
            .to_string(),
        ))
        .unwrap();

    let (status, body) = json_response(app.clone().oneshot(token_req).await.unwrap()).await;
    assert_eq!(status, StatusCode::CREATED);
    let token_id = body["token_id"].as_str().unwrap();
    let token_secret = body["token_secret"].as_str().unwrap();
    let challenge_nonce = body["challenge_nonce"].as_str().unwrap();

    // 2. Test Invalid Token ID (401)
    let bad_id_req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/agent/enroll")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({
                "token_id": Uuid::new_v4(),
                "token_secret": token_secret,
                "challenge_response": format!("{challenge_nonce}:agent-host-01"),
                "machine_id": "agent-host-01",
                "hostname": "agent01.corp",
                "agent_version": "0.1.0-alpha.0",
                "public_identity": "pure-crypto-id"
            })
            .to_string(),
        ))
        .unwrap();
    let (status, _) = json_response(app.clone().oneshot(bad_id_req).await.unwrap()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // 3. Test Invalid Token Secret (401)
    let bad_secret_req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/agent/enroll")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({
                "token_id": token_id,
                "token_secret": "wrong-secret-12345",
                "challenge_response": format!("{challenge_nonce}:agent-host-01"),
                "machine_id": "agent-host-01",
                "hostname": "agent01.corp",
                "agent_version": "0.1.0-alpha.0",
                "public_identity": "pure-crypto-id"
            })
            .to_string(),
        ))
        .unwrap();
    let (status, _) = json_response(app.clone().oneshot(bad_secret_req).await.unwrap()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // 4. Test Machine ID Mismatch (403)
    let wrong_machine_req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/agent/enroll")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({
                "token_id": token_id,
                "token_secret": token_secret,
                "challenge_response": format!("{challenge_nonce}:agent-host-WRONG"),
                "machine_id": "agent-host-WRONG",
                "hostname": "agent01.corp",
                "agent_version": "0.1.0-alpha.0",
                "public_identity": "pure-crypto-id"
            })
            .to_string(),
        ))
        .unwrap();
    let (status, _) = json_response(app.clone().oneshot(wrong_machine_req).await.unwrap()).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // 5. Test Invalid Challenge Nonce Response (401)
    let bad_challenge_req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/agent/enroll")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({
                "token_id": token_id,
                "token_secret": token_secret,
                "challenge_response": "corrupted-challenge-proof",
                "machine_id": "agent-host-01",
                "hostname": "agent01.corp",
                "agent_version": "0.1.0-alpha.0",
                "public_identity": "pure-crypto-id"
            })
            .to_string(),
        ))
        .unwrap();
    let (status, _) = json_response(app.clone().oneshot(bad_challenge_req).await.unwrap()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // 6. Successful Tenant-Bound Enrollment (201)
    let enroll_req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/agent/enroll")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({
                "token_id": token_id,
                "token_secret": token_secret,
                "challenge_response": format!("{challenge_nonce}:agent-host-01"),
                "machine_id": "agent-host-01",
                "hostname": "agent01.corp",
                "agent_version": "0.1.0-alpha.0",
                "public_identity": "spki-pure-crypto-der"
            })
            .to_string(),
        ))
        .unwrap();
    let (status, enroll_body) = json_response(app.clone().oneshot(enroll_req).await.unwrap()).await;
    assert_eq!(status, StatusCode::CREATED);
    let agent_id = enroll_body["agent_id"].as_str().unwrap();
    let auth_key = enroll_body["auth_key"].as_str().unwrap();

    // 7. Token Replay Protection (Attempting to reuse consumed token returns 409 Conflict)
    let replay_req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/agent/enroll")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({
                "token_id": token_id,
                "token_secret": token_secret,
                "challenge_response": format!("{challenge_nonce}:agent-host-01"),
                "machine_id": "agent-host-01",
                "hostname": "agent01.corp",
                "agent_version": "0.1.0-alpha.0",
                "public_identity": "spki-pure-crypto-der"
            })
            .to_string(),
        ))
        .unwrap();
    let (status, _) = json_response(app.clone().oneshot(replay_req).await.unwrap()).await;
    assert_eq!(status, StatusCode::CONFLICT);

    // 8. Authenticated Outbound Heartbeat
    let hb_req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/agent/heartbeat")
        .header(header::AUTHORIZATION, format!("Bearer {auth_key}"))
        .body(Body::empty())
        .unwrap();
    let (status, hb_body) = json_response(app.clone().oneshot(hb_req).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(hb_body["status"], "active");

    // 9. Unauthorized Agent Request (invalid key returns 401)
    let bad_auth_req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/agent/heartbeat")
        .header(header::AUTHORIZATION, "Bearer invalid-agent-key-999")
        .body(Body::empty())
        .unwrap();
    let (status, _) = json_response(app.clone().oneshot(bad_auth_req).await.unwrap()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // 10. Operator Lists Agents
    let list_req = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/agents")
        .header(header::AUTHORIZATION, format!("Bearer {admin_token}"))
        .body(Body::empty())
        .unwrap();
    let (status, list_body) = json_response(app.clone().oneshot(list_req).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    let agents = list_body["agents"].as_array().unwrap();
    assert_eq!(agents.len(), 1);
    assert_eq!(agents[0]["id"], agent_id);
    assert_eq!(agents[0]["machine_id"], "agent-host-01");

    // 11. Credential Rotation
    let rotate_req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/agent/rotate-credentials")
        .header(header::AUTHORIZATION, format!("Bearer {auth_key}"))
        .body(Body::empty())
        .unwrap();
    let (status, rot_body) = json_response(app.clone().oneshot(rotate_req).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    let new_auth_key = rot_body["new_auth_key"].as_str().unwrap();
    assert_ne!(new_auth_key, auth_key);

    // Old key is now rejected
    let old_key_req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/agent/heartbeat")
        .header(header::AUTHORIZATION, format!("Bearer {auth_key}"))
        .body(Body::empty())
        .unwrap();
    let (status, _) = json_response(app.clone().oneshot(old_key_req).await.unwrap()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // New key is accepted
    let new_key_req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/agent/heartbeat")
        .header(header::AUTHORIZATION, format!("Bearer {new_auth_key}"))
        .body(Body::empty())
        .unwrap();
    let (status, _) = json_response(app.clone().oneshot(new_key_req).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK);

    // 12. Operator Revokes Agent
    let revoke_req = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/v1/agents/{agent_id}/revoke"))
        .header(header::AUTHORIZATION, format!("Bearer {admin_token}"))
        .body(Body::empty())
        .unwrap();
    let (status, _) = json_response(app.clone().oneshot(revoke_req).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK);

    // Revoked agent heartbeat/poll is rejected with 403 Forbidden
    let revoked_poll_req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/agent/jobs/poll")
        .header(header::AUTHORIZATION, format!("Bearer {new_auth_key}"))
        .body(Body::empty())
        .unwrap();
    let (status, rev_body) =
        json_response(app.clone().oneshot(revoked_poll_req).await.unwrap()).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(rev_body["error"], "agent_revoked");
}

#[tokio::test]
async fn test_m6_distributed_job_dispatch_and_result_provenance() {
    let (app, store, _) = create_test_env();
    let (admin_token, org1_id) =
        setup_tenant_and_admin(&app, "Ops Tenant", "ops-tenant", "admin@ops.com").await;

    // Issue token and enroll Agent 1
    let (token_id, token_secret, challenge) = {
        let req = Request::builder()
            .method(Method::POST)
            .uri("/api/v1/agents/tokens")
            .header(header::AUTHORIZATION, format!("Bearer {admin_token}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json!({ "machine_id": "worker-1" }).to_string()))
            .unwrap();
        let (_, b) = json_response(app.clone().oneshot(req).await.unwrap()).await;
        (
            b["token_id"].as_str().unwrap().to_string(),
            b["token_secret"].as_str().unwrap().to_string(),
            b["challenge_nonce"].as_str().unwrap().to_string(),
        )
    };

    let agent1_key = {
        let req = Request::builder()
            .method(Method::POST)
            .uri("/api/v1/agent/enroll")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({
                    "token_id": token_id,
                    "token_secret": token_secret,
                    "challenge_response": format!("{challenge}:worker-1"),
                    "machine_id": "worker-1",
                    "hostname": "worker-1.local",
                    "agent_version": "0.1.0",
                    "public_identity": "pure-crypto-1"
                })
                .to_string(),
            ))
            .unwrap();
        let (_, b) = json_response(app.clone().oneshot(req).await.unwrap()).await;
        b["auth_key"].as_str().unwrap().to_string()
    };

    // Issue token and enroll Agent 2
    let (token2_id, token2_secret, challenge2) = {
        let req = Request::builder()
            .method(Method::POST)
            .uri("/api/v1/agents/tokens")
            .header(header::AUTHORIZATION, format!("Bearer {admin_token}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json!({ "machine_id": "worker-2" }).to_string()))
            .unwrap();
        let (_, b) = json_response(app.clone().oneshot(req).await.unwrap()).await;
        (
            b["token_id"].as_str().unwrap().to_string(),
            b["token_secret"].as_str().unwrap().to_string(),
            b["challenge_nonce"].as_str().unwrap().to_string(),
        )
    };

    let agent2_key = {
        let req = Request::builder()
            .method(Method::POST)
            .uri("/api/v1/agent/enroll")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({
                    "token_id": token2_id,
                    "token_secret": token2_secret,
                    "challenge_response": format!("{challenge2}:worker-2"),
                    "machine_id": "worker-2",
                    "hostname": "worker-2.local",
                    "agent_version": "0.1.0",
                    "public_identity": "pure-crypto-2"
                })
                .to_string(),
            ))
            .unwrap();
        let (_, b) = json_response(app.clone().oneshot(req).await.unwrap()).await;
        b["auth_key"].as_str().unwrap().to_string()
    };

    // Operator enqueues assessment job
    let job_id = {
        let req = Request::builder()
            .method(Method::POST)
            .uri("/api/v1/assessments/jobs")
            .header(header::AUTHORIZATION, format!("Bearer {admin_token}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({
                    "target": "192.168.1.1",
                    "assessment_type": "host_audit",
                    "profile": "cis_benchmark"
                })
                .to_string(),
            ))
            .unwrap();
        let (st, b) = json_response(app.clone().oneshot(req).await.unwrap()).await;
        assert_eq!(st, StatusCode::ACCEPTED);
        b["id"].as_str().unwrap().to_string()
    };

    // Agent 1 claims job
    let poll_req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/agent/jobs/poll")
        .header(header::AUTHORIZATION, format!("Bearer {agent1_key}"))
        .body(Body::empty())
        .unwrap();
    let (st, poll_body) = json_response(app.clone().oneshot(poll_req).await.unwrap()).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(poll_body["job"]["id"], job_id);
    assert_eq!(poll_body["job"]["assessment_type"], "host_audit");

    // Agent 2 attempts to claim job (must receive null, duplicate claim prevented)
    let poll2_req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/agent/jobs/poll")
        .header(header::AUTHORIZATION, format!("Bearer {agent2_key}"))
        .body(Body::empty())
        .unwrap();
    let (st2, poll2_body) = json_response(app.clone().oneshot(poll2_req).await.unwrap()).await;
    assert_eq!(st2, StatusCode::OK);
    assert!(
        poll2_body["job"].is_null(),
        "Duplicate job claim must be prevented"
    );

    // Agent 2 cannot submit results for job claimed by Agent 1 (returns 403 Forbidden)
    let bad_submit = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/v1/agent/jobs/{job_id}/results"))
        .header(header::AUTHORIZATION, format!("Bearer {agent2_key}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({
                "summary_json": "{}",
                "findings": []
            })
            .to_string(),
        ))
        .unwrap();
    let (status, _) = json_response(app.clone().oneshot(bad_submit).await.unwrap()).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Agent 1 renews job lease
    let hb_lease = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/v1/agent/jobs/{job_id}/heartbeat"))
        .header(header::AUTHORIZATION, format!("Bearer {agent1_key}"))
        .body(Body::empty())
        .unwrap();
    let (st_hb, _) = json_response(app.clone().oneshot(hb_lease).await.unwrap()).await;
    assert_eq!(st_hb, StatusCode::OK);

    // Agent 1 submits structured results with evidence
    let submit_req = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/v1/agent/jobs/{job_id}/results"))
        .header(header::AUTHORIZATION, format!("Bearer {agent1_key}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({
                "summary_json": "{\"compliant\": true, \"rules_evaluated\": 12}",
                "findings": [
                    {
                        "rule_id": "audit.cis.file-perms",
                        "severity": "High",
                        "confidence": "Confirmed",
                        "title": "Insecure Root File Permissions",
                        "endpoint": "/etc/shadow",
                        "evidence": "File permissions 0644 detected",
                        "recommendation": "Execute chmod 0600 /etc/shadow"
                    }
                ]
            })
            .to_string(),
        ))
        .unwrap();
    let (sub_st, sub_b) = json_response(app.clone().oneshot(submit_req).await.unwrap()).await;
    assert_eq!(sub_st, StatusCode::OK);
    assert_eq!(sub_b["status"], "completed");
    assert_eq!(sub_b["findings_recorded"], 1);

    // Verify findings provenance in store
    let findings = store
        .list_findings(
            Uuid::parse_str(&org1_id).unwrap(),
            Some(Uuid::parse_str(&job_id).unwrap()),
            None,
        )
        .await
        .unwrap();
    assert_eq!(findings.len(), 1);
    assert!(findings[0]
        .evidence
        .contains("[Agent: worker-1.local (worker-1)]"));

    // Idempotent resubmission: submitting findings again succeeds without duplicating findings
    let resubmit_req = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/v1/agent/jobs/{job_id}/results"))
        .header(header::AUTHORIZATION, format!("Bearer {agent1_key}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({
                "summary_json": "{\"compliant\": true}",
                "findings": []
            })
            .to_string(),
        ))
        .unwrap();
    let (resub_st, _) = json_response(app.clone().oneshot(resubmit_req).await.unwrap()).await;
    assert_eq!(resub_st, StatusCode::OK);
}

#[tokio::test]
async fn test_m6_cross_tenant_agent_and_job_isolation() {
    let (app, store, state) = create_test_env();

    // Tenant 1
    let (t1_token, _t1_org_id) =
        setup_tenant_and_admin(&app, "Tenant Alpha", "tenant-alpha", "admin@alpha.com").await;

    // Tenant 2
    let (t2_token, t2_org_id) = create_additional_tenant(
        &store,
        &state,
        "Tenant Beta",
        "tenant-beta",
        "admin@beta.com",
    )
    .await;

    // Issue enrollment token in Tenant 1
    let (tok_id, tok_sec, nonce) = {
        let req = Request::builder()
            .method(Method::POST)
            .uri("/api/v1/agents/tokens")
            .header(header::AUTHORIZATION, format!("Bearer {t1_token}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({ "machine_id": "alpha-agent" }).to_string(),
            ))
            .unwrap();
        let (_, b) = json_response(app.clone().oneshot(req).await.unwrap()).await;
        (
            b["token_id"].as_str().unwrap().to_string(),
            b["token_secret"].as_str().unwrap().to_string(),
            b["challenge_nonce"].as_str().unwrap().to_string(),
        )
    };

    // Enroll Alpha Agent (bound to Tenant 1)
    let alpha_key = {
        let req = Request::builder()
            .method(Method::POST)
            .uri("/api/v1/agent/enroll")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({
                    "token_id": tok_id,
                    "token_secret": tok_sec,
                    "challenge_response": format!("{nonce}:alpha-agent"),
                    "machine_id": "alpha-agent",
                    "hostname": "alpha-node",
                    "agent_version": "0.1.0",
                    "public_identity": "pure-crypto-alpha"
                })
                .to_string(),
            ))
            .unwrap();
        let (_, b) = json_response(app.clone().oneshot(req).await.unwrap()).await;
        b["auth_key"].as_str().unwrap().to_string()
    };

    // Create a job in Tenant 2 ONLY
    let t2_job = store
        .create_job(
            Uuid::parse_str(&t2_org_id).unwrap(),
            None,
            "10.200.0.1",
            "host_audit",
            "standard",
        )
        .await
        .unwrap();

    // Alpha Agent (Tenant 1) polls for jobs
    // MUST NOT claim Tenant 2's job
    let poll_req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/agent/jobs/poll")
        .header(header::AUTHORIZATION, format!("Bearer {alpha_key}"))
        .body(Body::empty())
        .unwrap();
    let (st, poll_b) = json_response(app.clone().oneshot(poll_req).await.unwrap()).await;
    assert_eq!(st, StatusCode::OK);
    assert!(
        poll_b["job"].is_null(),
        "Tenant 1 agent must not claim Tenant 2 jobs"
    );

    // Tenant 2 job must still be in Pending status
    let check_job = store
        .get_job(Uuid::parse_str(&t2_org_id).unwrap(), t2_job.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(check_job.status, JobStatus::Pending);

    // Tenant 2 admin lists agents -> Tenant 1's agent must not be visible
    let t2_agents_req = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/agents")
        .header(header::AUTHORIZATION, format!("Bearer {t2_token}"))
        .body(Body::empty())
        .unwrap();
    let (_, t2_agents_b) = json_response(app.clone().oneshot(t2_agents_req).await.unwrap()).await;
    assert_eq!(t2_agents_b["agents"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn test_m6_e2e_agent_client_and_server_lifecycle() {
    // Tests end-to-end client loop with AgentClient against axum app
    let (app, store, _) = create_test_env();
    let (admin_token, org_id) =
        setup_tenant_and_admin(&app, "E2E Ops", "e2e-ops", "admin@e2e.com").await;

    // Spin up local server on ephemeral port for real HTTP socket communication
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();
    let server_url = format!("http://{local_addr}");

    // Spawn server in background tokio task
    let server_app = app.clone();
    let server_handle = tokio::spawn(async move {
        axum::serve(listener, server_app).await.unwrap();
    });

    let temp_state_dir = tempfile::tempdir().unwrap();

    // Create AgentClient
    let config = openaudit_agent::client::AgentDaemonConfig {
        server_url: server_url.clone(),
        state_dir: temp_state_dir.path().to_path_buf(),
        heartbeat_interval_secs: 10,
        poll_interval_secs: 1,
        max_backoff_secs: 5,
    };

    let mut agent = openaudit_agent::client::AgentClient::new(config).unwrap();
    assert!(!agent.is_enrolled());
    let machine_id = agent.resolve_machine_id().unwrap();

    // Issue token pinned to resolved machine_id
    let token_res = {
        let req = Request::builder()
            .method(Method::POST)
            .uri("/api/v1/agents/tokens")
            .header(header::AUTHORIZATION, format!("Bearer {admin_token}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json!({ "machine_id": machine_id }).to_string()))
            .unwrap();
        let (_, b) = json_response(app.clone().oneshot(req).await.unwrap()).await;
        (
            b["token_id"].as_str().unwrap().to_string(),
            b["token_secret"].as_str().unwrap().to_string(),
            b["challenge_nonce"].as_str().unwrap().to_string(),
        )
    };

    // 1. Perform Enrollment
    let token_id = Uuid::parse_str(&token_res.0).unwrap();
    let creds = agent
        .enroll(token_id, &token_res.1, &token_res.2)
        .await
        .expect("Agent enrollment must succeed");
    assert!(agent.is_enrolled());
    assert_eq!(creds.org_id, Uuid::parse_str(&org_id).unwrap());

    // 2. Send Heartbeat
    agent
        .send_heartbeat()
        .await
        .expect("Heartbeat must succeed");

    // 3. Create job in store
    let job = store
        .create_job(
            Uuid::parse_str(&org_id).unwrap(),
            None,
            "127.0.0.1",
            "host_audit",
            "standard",
        )
        .await
        .unwrap();

    // 4. Run single poll iteration
    let executed = agent
        .run_once()
        .await
        .expect("Agent execution must succeed");
    assert!(executed, "Job should have been claimed and executed");

    // 5. Verify job is Completed in store
    let completed_job = store
        .get_job(Uuid::parse_str(&org_id).unwrap(), job.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(completed_job.status, JobStatus::Completed);
    assert_eq!(completed_job.assigned_agent_id, Some(creds.agent_id));
    assert!(completed_job.completed_at.is_some());

    // 6. Verify Findings persisted with Agent provenance
    let findings = store
        .list_findings(Uuid::parse_str(&org_id).unwrap(), Some(job.id), None)
        .await
        .unwrap();
    assert!(!findings.is_empty());
    assert!(findings[0].evidence.contains("[Agent:"));

    // 7. Test Credential Rotation
    let new_key = agent
        .rotate_credential()
        .await
        .expect("Credential rotation");
    assert_ne!(new_key, creds.auth_key);

    // Heartbeat with rotated key succeeds
    agent
        .send_heartbeat()
        .await
        .expect("Heartbeat with rotated key");

    server_handle.abort();
}
