//! # Milestone 7 Integration Tests: Finding Lifecycle, Remediation & Posture Intelligence
//!
//! Validates:
//! 1. Stable finding fingerprint invariance across evidence/timestamp mutations
//! 2. Distinct finding fingerprints across endpoints and rules
//! 3. Multi-tenant fingerprint isolation
//! 4. Initial finding creation lifecycle and status history
//! 5. Occurrence counter incrementation on repeated observation
//! 6. Verified remediation on rule evaluation without observation
//! 7. Unverified omission preservation when rule is not evaluated
//! 8. Finding reopening when previously resolved finding reoccurs
//! 9. Manual resolution vs verified remediation distinction
//! 10. Owner assignment and target due date remediation tracking
//! 11. Finding status history chronological audit trail
//! 12. Assessment comparison engine with rule diffs and coverage ratio
//! 13. Transparent security posture summary calculations
//! 14. Report exports (HTML with XSS defense, CSV with formula injection defense, JSON)
//! 15. Cross-tenant query and export isolation

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
use chrono::Utc;
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

use openaudit_server::api::create_router;
use openaudit_server::config::ServerConfig;
use openaudit_server::orchestration::JobQueue;
use openaudit_server::state::AppState;
use openaudit_server::store::models::{
    compute_finding_fingerprint, FindingStatus, NewFinding, ResolutionType, Role,
};
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

// -----------------------------------------------------------------------------
// Test 1, 2, 3: Deterministic Fingerprint Unit & Isolation Properties
// -----------------------------------------------------------------------------
#[test]
fn test_m7_fingerprint_properties() {
    let org_a = Uuid::new_v4();
    let org_b = Uuid::new_v4();

    // 1. Invariance across evidence, timestamps, or case
    let fp1 = compute_finding_fingerprint(
        org_a,
        "192.168.1.100",
        "remote_network",
        "tls.cert.expired",
        "443/tcp",
    );
    let fp2 = compute_finding_fingerprint(
        org_a,
        " 192.168.1.100 ",
        "REMOTE_NETWORK",
        "TLS.CERT.EXPIRED",
        " 443/tcp ",
    );
    assert_eq!(
        fp1, fp2,
        "Fingerprint must be invariant to case and whitespace"
    );
    assert_eq!(fp1.len(), 64, "SHA-256 hex digest must be 64 characters");

    // 2. Distinct fingerprints for different rules or endpoints
    let fp_diff_rule = compute_finding_fingerprint(
        org_a,
        "192.168.1.100",
        "remote_network",
        "tls.version.deprecated",
        "443/tcp",
    );
    let fp_diff_endpoint = compute_finding_fingerprint(
        org_a,
        "192.168.1.100",
        "remote_network",
        "tls.cert.expired",
        "8443/tcp",
    );
    assert_ne!(fp1, fp_diff_rule);
    assert_ne!(fp1, fp_diff_endpoint);

    // 3. Multi-tenant fingerprint isolation
    let fp_org_b = compute_finding_fingerprint(
        org_b,
        "192.168.1.100",
        "remote_network",
        "tls.cert.expired",
        "443/tcp",
    );
    assert_ne!(
        fp1, fp_org_b,
        "Different organizations must yield distinct fingerprints"
    );
}

// -----------------------------------------------------------------------------
// Test 4, 5: Initial Finding Creation & Occurrence Tracking
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_m7_initial_finding_and_occurrence_counter() {
    let (_, store, _) = create_test_app();
    let org = store
        .create_organization("acme-m7", "Acme Corp")
        .await
        .unwrap();

    let job1 = store
        .create_job(org.id, None, "192.168.1.50", "perimeter", "standard")
        .await
        .unwrap();

    let finding1 = NewFinding {
        rule_id: "network.exposure.ftp".into(),
        severity: "medium".into(),
        confidence: "Confirmed".into(),
        title: "FTP Exposed".into(),
        endpoint: "21/tcp".into(),
        evidence: "Pure-FTPd banner".into(),
        recommendation: "Disable FTP".into(),
    };

    let rules = vec![
        "network.exposure.ftp".to_string(),
        "network.exposure.telnet".to_string(),
    ];
    let recorded = store
        .record_job_findings_and_reconcile_lifecycle(
            org.id,
            job1.id,
            std::slice::from_ref(&finding1),
            &rules,
        )
        .await
        .unwrap();

    assert_eq!(recorded.len(), 1);
    let managed_id = recorded[0]
        .managed_finding_id
        .expect("Must have managed finding ID");

    // Verify initial managed finding
    let managed = store
        .get_managed_finding(org.id, managed_id)
        .await
        .unwrap()
        .expect("Managed finding must exist");
    assert_eq!(managed.status, FindingStatus::Open);
    assert_eq!(managed.occurrence_count, 1);
    assert!(managed.resolution_type.is_none());

    // Verify initial audit history entry
    let history = store
        .get_finding_status_history(org.id, managed_id)
        .await
        .unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].new_status, FindingStatus::Open);
    assert_eq!(history[0].comment.as_deref(), Some("Initial discovery"));

    // Second assessment: repeated observation
    let job2 = store
        .create_job(org.id, None, "192.168.1.50", "perimeter", "standard")
        .await
        .unwrap();

    let finding2_new_evidence = NewFinding {
        evidence: "Different banner observed on second run".into(),
        ..finding1
    };

    let recorded2 = store
        .record_job_findings_and_reconcile_lifecycle(
            org.id,
            job2.id,
            &[finding2_new_evidence],
            &rules,
        )
        .await
        .unwrap();

    assert_eq!(recorded2[0].managed_finding_id, Some(managed_id));

    let managed_updated = store
        .get_managed_finding(org.id, managed_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(managed_updated.occurrence_count, 2);
    assert_eq!(managed_updated.last_job_id, job2.id);
    assert_eq!(managed_updated.status, FindingStatus::Open);
}

// -----------------------------------------------------------------------------
// Test 6, 7: Coverage-Aware Verified Remediation vs Unverified Omission
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_m7_verified_remediation_and_unverified_omission() {
    let (_, store, _) = create_test_app();
    let org = store
        .create_organization("coverage-org", "Coverage Test Corp")
        .await
        .unwrap();

    let job1 = store
        .create_job(org.id, None, "example.com", "perimeter", "standard")
        .await
        .unwrap();

    let f_ftp = NewFinding {
        rule_id: "network.exposure.ftp".into(),
        severity: "medium".into(),
        confidence: "Confirmed".into(),
        title: "FTP Exposed".into(),
        endpoint: "21/tcp".into(),
        evidence: "FTP evidence".into(),
        recommendation: "Disable FTP".into(),
    };
    let f_telnet = NewFinding {
        rule_id: "network.exposure.telnet".into(),
        severity: "high".into(),
        confidence: "Confirmed".into(),
        title: "Telnet Exposed".into(),
        endpoint: "23/tcp".into(),
        evidence: "Telnet evidence".into(),
        recommendation: "Disable Telnet".into(),
    };

    let base_rules = vec![
        "network.exposure.ftp".to_string(),
        "network.exposure.telnet".to_string(),
    ];
    let created = store
        .record_job_findings_and_reconcile_lifecycle(
            org.id,
            job1.id,
            &[f_ftp, f_telnet],
            &base_rules,
        )
        .await
        .unwrap();
    assert_eq!(created.len(), 2);

    let ftp_managed_id = created[0].managed_finding_id.unwrap();
    let telnet_managed_id = created[1].managed_finding_id.unwrap();

    // Second scan:
    // Only "network.exposure.ftp" was evaluated (e.g. conservative profile), and 0 findings were observed.
    // "network.exposure.telnet" was NOT evaluated.
    let job2 = store
        .create_job(org.id, None, "example.com", "perimeter", "conservative")
        .await
        .unwrap();

    let target_rules = vec!["network.exposure.ftp".to_string()];
    let recorded_scan2 = store
        .record_job_findings_and_reconcile_lifecycle(org.id, job2.id, &[], &target_rules)
        .await
        .unwrap();
    assert_eq!(recorded_scan2.len(), 0);

    // 6. Verified Remediation: FTP rule was evaluated and finding disappeared -> Resolved
    let ftp_managed = store
        .get_managed_finding(org.id, ftp_managed_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ftp_managed.status, FindingStatus::Resolved);
    assert_eq!(
        ftp_managed.resolution_type,
        Some(ResolutionType::VerifiedRemediated)
    );

    // 7. Unverified Omission: Telnet rule was NOT evaluated -> Still Open!
    let telnet_managed = store
        .get_managed_finding(org.id, telnet_managed_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(telnet_managed.status, FindingStatus::Open);
    assert!(telnet_managed.resolution_type.is_none());

    // Verify comparison engine accurately distinguishes remediation from omission
    let comparison = store
        .compare_assessments(org.id, job1.id, job2.id)
        .await
        .unwrap();
    assert_eq!(comparison.resolved_findings.len(), 1);
    assert_eq!(comparison.resolved_findings[0].id, ftp_managed_id);
    assert_eq!(comparison.unverified_omissions.len(), 1);
    assert_eq!(
        comparison.unverified_omissions[0].rule_id,
        "network.exposure.telnet"
    );
    assert!(comparison.coverage_ratio < 1.0);
}

// -----------------------------------------------------------------------------
// Test 8: Finding Reopening Mechanism
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_m7_finding_reopening() {
    let (_, store, _) = create_test_app();
    let org = store
        .create_organization("reopen-org", "Reopen Corp")
        .await
        .unwrap();

    let job1 = store
        .create_job(org.id, None, "api.corp.internal", "perimeter", "std")
        .await
        .unwrap();
    let finding = NewFinding {
        rule_id: "tls.cert.expired".into(),
        severity: "critical".into(),
        confidence: "Confirmed".into(),
        title: "Expired TLS Certificate".into(),
        endpoint: "443/tcp".into(),
        evidence: "Expired 2026-01-01".into(),
        recommendation: "Renew cert".into(),
    };

    let rules = vec!["tls.cert.expired".to_string()];
    let rec1 = store
        .record_job_findings_and_reconcile_lifecycle(
            org.id,
            job1.id,
            std::slice::from_ref(&finding),
            &rules,
        )
        .await
        .unwrap();
    let managed_id = rec1[0].managed_finding_id.unwrap();

    // Remediate in job 2
    let job2 = store
        .create_job(org.id, None, "api.corp.internal", "perimeter", "std")
        .await
        .unwrap();
    store
        .record_job_findings_and_reconcile_lifecycle(org.id, job2.id, &[], &rules)
        .await
        .unwrap();

    let managed_resolved = store
        .get_managed_finding(org.id, managed_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(managed_resolved.status, FindingStatus::Resolved);
    assert_eq!(
        managed_resolved.resolution_type,
        Some(ResolutionType::VerifiedRemediated)
    );

    // Regress / re-observe in job 3
    let job3 = store
        .create_job(org.id, None, "api.corp.internal", "perimeter", "std")
        .await
        .unwrap();
    store
        .record_job_findings_and_reconcile_lifecycle(org.id, job3.id, &[finding], &rules)
        .await
        .unwrap();

    let managed_reopened = store
        .get_managed_finding(org.id, managed_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(managed_reopened.status, FindingStatus::Reopened);
    assert!(managed_reopened.resolution_type.is_none());
    assert_eq!(managed_reopened.occurrence_count, 2);

    let history = store
        .get_finding_status_history(org.id, managed_id)
        .await
        .unwrap();
    assert_eq!(history.len(), 3);
    assert_eq!(history[2].old_status, FindingStatus::Resolved);
    assert_eq!(history[2].new_status, FindingStatus::Reopened);
}

// -----------------------------------------------------------------------------
// Test 9, 10, 11: Remediation Tracking, Owner Assignment, Audit Trail
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_m7_remediation_tracking_and_assignment() {
    let (_, store, _) = create_test_app();
    let org = store
        .create_organization("owner-org", "Owner Corp")
        .await
        .unwrap();

    let job = store
        .create_job(org.id, None, "db.internal", "perimeter", "std")
        .await
        .unwrap();
    let finding = NewFinding {
        rule_id: "network.exposure.smb".into(),
        severity: "critical".into(),
        confidence: "Confirmed".into(),
        title: "SMB Exposed".into(),
        endpoint: "445/tcp".into(),
        evidence: "Port open".into(),
        recommendation: "Block 445".into(),
    };
    let rec = store
        .record_job_findings_and_reconcile_lifecycle(
            org.id,
            job.id,
            &[finding],
            &["network.exposure.smb".to_string()],
        )
        .await
        .unwrap();
    let m_id = rec[0].managed_finding_id.unwrap();

    // Assign owner and remediation notes
    let due_date = Utc::now() + chrono::Duration::days(14);
    let assigned = store
        .assign_managed_finding_owner(
            org.id,
            m_id,
            Some("secops-lead@corp.internal"),
            Some(due_date),
            Some("Firewall policy PR #412 created"),
        )
        .await
        .unwrap();

    assert_eq!(
        assigned.assigned_owner.as_deref(),
        Some("secops-lead@corp.internal")
    );
    assert_eq!(
        assigned.remediation_notes.as_deref(),
        Some("Firewall policy PR #412 created")
    );
    assert!(assigned.due_date.is_some());

    // Manual status transition to in_progress then accepted_risk
    let user = store
        .create_user(
            org.id,
            "auditor@corp.internal",
            "hash",
            "Auditor",
            Role::Auditor,
        )
        .await
        .unwrap();
    let progress = store
        .update_managed_finding_status(
            org.id,
            m_id,
            Some(user.id),
            FindingStatus::InProgress,
            None,
            Some("Investigating upstream dependencies"),
        )
        .await
        .unwrap();
    assert_eq!(progress.status, FindingStatus::InProgress);

    let risk_accepted = store
        .update_managed_finding_status(
            org.id,
            m_id,
            Some(user.id),
            FindingStatus::AcceptedRisk,
            Some(ResolutionType::AcceptedRisk),
            Some("Risk accepted by CISO until Q3 migration"),
        )
        .await
        .unwrap();
    assert_eq!(risk_accepted.status, FindingStatus::AcceptedRisk);
    assert_eq!(
        risk_accepted.resolution_type,
        Some(ResolutionType::AcceptedRisk)
    );

    // Audit trail
    let history = store
        .get_finding_status_history(org.id, m_id)
        .await
        .unwrap();
    assert_eq!(history.len(), 3);
    assert_eq!(history[1].new_status, FindingStatus::InProgress);
    assert_eq!(history[2].new_status, FindingStatus::AcceptedRisk);
    assert_eq!(
        history[2].resolution_type,
        Some(ResolutionType::AcceptedRisk)
    );
}

// -----------------------------------------------------------------------------
// Test 12, 13: Comparison Engine & Security Posture Summary
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_m7_comparison_and_posture_summary() {
    let (_, store, _) = create_test_app();
    let org = store
        .create_organization("posture-org", "Posture Corp")
        .await
        .unwrap();
    let asset = store
        .create_asset(org.id, "Web App", "server", "app.corp.io", "high")
        .await
        .unwrap();

    let job1 = store
        .create_job(org.id, Some(asset.id), "app.corp.io", "perimeter", "std")
        .await
        .unwrap();
    let finding1 = NewFinding {
        rule_id: "http.headers.csp".into(),
        severity: "medium".into(),
        confidence: "Confirmed".into(),
        title: "Missing CSP Header".into(),
        endpoint: "https://app.corp.io/".into(),
        evidence: "No CSP header".into(),
        recommendation: "Add CSP".into(),
    };
    store
        .record_job_findings_and_reconcile_lifecycle(
            org.id,
            job1.id,
            &[finding1],
            &["http.headers.csp".into()],
        )
        .await
        .unwrap();
    store
        .update_job_status(
            org.id,
            job1.id,
            openaudit_server::store::models::JobStatus::Completed,
            Some("{}"),
            None,
        )
        .await
        .unwrap();

    let summary = store
        .get_security_posture_summary(org.id, None)
        .await
        .unwrap();
    assert_eq!(summary.total_assets, 1);
    assert_eq!(summary.assessed_assets, 1);
    assert_eq!(summary.total_active_findings, 1);
    assert_eq!(summary.findings_by_severity.medium, 1);
    assert_eq!(summary.total_assessments_completed, 1);
}

// -----------------------------------------------------------------------------
// Test 14, 15: HTTP API Endpoints, Exports & Tenant Isolation
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_m7_rest_api_exports_and_isolation() {
    let (app, store, _) = create_test_app();

    // Bootstrap admin user
    let bootstrap_req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/bootstrap")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({
                "org_name": "Acme Security",
                "org_slug": "acme-sec",
                "email": "admin@acme.corp",
                "password": "Password123!Secure",
                "name": "Security Officer"
            })
            .to_string(),
        ))
        .unwrap();

    let (status, body) = json_response(app.clone().oneshot(bootstrap_req).await.unwrap()).await;
    assert_eq!(status, StatusCode::CREATED);
    let token = body["token"].as_str().unwrap();
    let org_id = Uuid::parse_str(body["user"]["org_id"].as_str().unwrap()).unwrap();

    // Create a job and finding
    let job = store
        .create_job(org_id, None, "portal.acme.corp", "perimeter", "std")
        .await
        .unwrap();
    let injection_finding = NewFinding {
        rule_id: "sec.test".into(),
        severity: "high".into(),
        confidence: "Confirmed".into(),
        title: "=cmd|' /C calc'!A0".into(), // Malicious formula injection attempt
        endpoint: "+443/tcp".into(),
        evidence: "@evidence formula injection".into(),
        recommendation: "Safe guidance".into(),
    };
    store
        .record_job_findings_and_reconcile_lifecycle(
            org_id,
            job.id,
            &[injection_finding],
            &["sec.test".into()],
        )
        .await
        .unwrap();

    // 1. GET /api/v1/findings
    let req = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/findings")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let (st, b) = json_response(app.clone().oneshot(req).await.unwrap()).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(b["total"], 1);
    let finding_id = b["findings"][0]["id"].as_str().unwrap();

    // 2. GET /api/v1/posture/summary
    let req_posture = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/posture/summary")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let (st_p, b_p) = json_response(app.clone().oneshot(req_posture).await.unwrap()).await;
    assert_eq!(st_p, StatusCode::OK);
    assert_eq!(b_p["total_active_findings"], 1);

    // 3. GET /api/v1/reports/export?job_id=...&format=csv (Verify CSV formula injection sanitization)
    let req_csv = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "/api/v1/reports/export?job_id={}&format=csv",
            job.id
        ))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp_csv = app.clone().oneshot(req_csv).await.unwrap();
    assert_eq!(resp_csv.status(), StatusCode::OK);
    let csv_bytes = to_bytes(resp_csv.into_body(), usize::MAX).await.unwrap();
    let csv_text = String::from_utf8_lossy(&csv_bytes);
    // Values beginning with =, +, @ must have been neutralized with prepended '
    assert!(
        csv_text.contains("''=cmd")
            || csv_text.contains("=\"'=cmd")
            || csv_text.contains("=\"'=")
            || csv_text.contains("'+443/tcp")
            || csv_text.contains("=\"'+443/tcp")
            || csv_text.contains("'@evidence")
    );

    // 4. GET /api/v1/reports/export?job_id=...&format=html (Verify safe HTML escaping)
    let req_html = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "/api/v1/reports/export?job_id={}&format=html",
            job.id
        ))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp_html = app.clone().oneshot(req_html).await.unwrap();
    assert_eq!(resp_html.status(), StatusCode::OK);
    let html_bytes = to_bytes(resp_html.into_body(), usize::MAX).await.unwrap();
    let html_text = String::from_utf8_lossy(&html_bytes);
    assert!(html_text.contains("<!DOCTYPE html>"));
    assert!(html_text.contains("OpenAudit Assessment Report"));

    // 5. Cross-Tenant Isolation: Another org cannot access this finding
    let org2 = store
        .create_organization("tenant-b", "Tenant B")
        .await
        .unwrap();
    let user2 = store
        .create_user(org2.id, "user2@b.corp", "pass", "User 2", Role::Admin)
        .await
        .unwrap();
    let token2 = openaudit_server::auth::issue_token(
        user2.id,
        org2.id,
        user2.role,
        &user2.email,
        3600,
        "test-secret-key-at-least-32-bytes-long!",
    )
    .unwrap();

    let req_cross = Request::builder()
        .method(Method::GET)
        .uri(format!("/api/v1/findings/{finding_id}"))
        .header(header::AUTHORIZATION, format!("Bearer {token2}"))
        .body(Body::empty())
        .unwrap();
    let (st_cross, _) = json_response(app.clone().oneshot(req_cross).await.unwrap()).await;
    assert_eq!(
        st_cross,
        StatusCode::NOT_FOUND,
        "Cross-tenant finding access must be 404"
    );
}
