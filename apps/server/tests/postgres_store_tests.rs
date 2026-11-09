//! # PostgreSQL Persistence Integration Tests (M5)

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
    clippy::similar_names,
    clippy::unnecessary_wraps
)]

use chrono::{Duration, Utc};
use std::env;
use uuid::Uuid;

use openaudit_server::store::models::{AgentStatus, JobStatus, NewFinding, Role};
use openaudit_server::store::postgres::PostgresControlPlaneStore;
use openaudit_server::store::{ControlPlaneStore, StoreError};

fn get_postgres_url() -> Option<String> {
    if let Ok(url) = env::var("TEST_DATABASE_URL") {
        if !url.trim().is_empty() {
            return Some(url);
        }
    }
    // Default local test container URL
    Some("postgres://postgres:postgres@127.0.0.1:5433/openaudit_test".to_string())
}

#[tokio::test]
async fn test_postgres_full_persistence_and_isolation_lifecycle() {
    let Some(pg_url) = get_postgres_url() else {
        eprintln!("Skipping PostgreSQL integration test: no test database URL configured");
        return;
    };

    let store = match PostgresControlPlaneStore::connect(&pg_url).await {
        Ok(s) => s,
        Err(err) => {
            eprintln!("PostgreSQL connection failed ({err}); skipping test if database not active");
            return;
        }
    };

    assert!(store.is_healthy().await, "PostgreSQL store must be healthy");

    // 1. Test migration idempotency
    store.migrate().await.expect("Migration must be idempotent");

    // Clean tables for fresh test run
    if let Ok((pg_client, connection)) =
        tokio_postgres::connect(&pg_url, tokio_postgres::NoTls).await
    {
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let _ = pg_client
            .batch_execute(
                "TRUNCATE TABLE assessment_findings, assessment_jobs, assessment_schedules, assets, agent_enrollment_tokens, enrolled_agents, users, organizations CASCADE;",
            )
            .await;
    }

    let org_suffix = Uuid::new_v4().to_string()[..8].to_string();
    let org_slug = format!("pg-tenant-{org_suffix}");

    // 2. Test Atomic Bootstrap
    let (org1, admin1) = store
        .bootstrap_admin(
            "Postgres Tenant 1",
            &org_slug,
            "PG Admin",
            &format!("admin@{org_slug}.com"),
            "argon2id$mockhash",
        )
        .await
        .expect("Bootstrap must succeed");

    assert_eq!(admin1.role, Role::Admin);
    assert_eq!(org1.slug, org_slug);

    // Duplicate bootstrap must conflict
    let dup_bootstrap = store
        .bootstrap_admin(
            "Duplicate Tenant",
            "duplicate-slug",
            "Dup Admin",
            "dup@admin.com",
            "hash",
        )
        .await;
    assert!(
        matches!(dup_bootstrap, Err(StoreError::Conflict(_))),
        "Duplicate bootstrap must be rejected with Conflict"
    );

    // 3. Create second tenant organization
    let org2_slug = format!("pg-tenant2-{org_suffix}");
    let org2 = store
        .create_organization("Postgres Tenant 2", &org2_slug)
        .await
        .expect("Must create org2");

    // 4. Create assets in Org 1
    let asset1 = store
        .create_asset(org1.id, "Prod DB", "database", "10.0.0.5", "critical")
        .await
        .expect("Must create asset in org1");

    // 5. Test strict tenant isolation on assets
    let isolated_asset = store
        .get_asset(org2.id, asset1.id)
        .await
        .expect("Query must succeed");
    assert_eq!(isolated_asset, None, "Tenant 2 must not see Tenant 1 asset");

    let read_back = store
        .get_asset(org1.id, asset1.id)
        .await
        .expect("Query must succeed")
        .expect("Asset must exist");
    assert_eq!(read_back.name, "Prod DB");

    // 6. Test Assessment Job Orchestration in PostgreSQL
    let job = store
        .create_job(
            org1.id,
            Some(asset1.id),
            "10.0.0.5",
            "remote_network",
            "standard",
        )
        .await
        .expect("Must create job");
    assert_eq!(job.status, JobStatus::Pending);

    // Transition to Running
    store
        .update_job_status(org1.id, job.id, JobStatus::Running, None, None)
        .await
        .expect("Transition to Running must succeed");

    // Transition to Completed
    store
        .update_job_status(
            org1.id,
            job.id,
            JobStatus::Completed,
            Some(r#"{"findings_count": 2}"#),
            None,
        )
        .await
        .expect("Transition to Completed must succeed");

    let completed_job = store
        .get_job(org1.id, job.id)
        .await
        .expect("Get job query must succeed")
        .unwrap();
    assert_eq!(completed_job.status, JobStatus::Completed);
    assert!(completed_job.started_at.is_some());
    assert!(completed_job.completed_at.is_some());

    // Re-transitioning terminal job must fail with Conflict
    let invalid_transition = store
        .update_job_status(org1.id, job.id, JobStatus::Running, None, None)
        .await;
    assert!(
        matches!(invalid_transition, Err(StoreError::Conflict(_))),
        "Terminal job transition must fail with Conflict"
    );

    // 7. Test Findings Persistence & Isolation
    let finding = NewFinding {
        rule_id: "tls.weak-cipher".into(),
        severity: "Medium".into(),
        confidence: "Confirmed".into(),
        title: "Weak Cipher Suite Enabled".into(),
        endpoint: "10.0.0.5:443".into(),
        evidence: "TLS_RSA_WITH_AES_128_CBC_SHA".into(),
        recommendation: "Use TLS 1.3 or modern AEAD suites".into(),
    };
    store
        .create_findings(org1.id, job.id, &[finding])
        .await
        .expect("Must persist findings");

    let findings_org1 = store
        .list_findings(org1.id, Some(job.id), None)
        .await
        .expect("Must list findings");
    assert_eq!(findings_org1.len(), 1);
    assert_eq!(findings_org1[0].rule_id, "tls.weak-cipher");

    let findings_org2 = store
        .list_findings(org2.id, Some(job.id), None)
        .await
        .expect("Query must succeed");
    assert!(
        findings_org2.is_empty(),
        "Tenant 2 must receive zero findings from Tenant 1"
    );

    // 8. Test Schedules & Due Schedule Queries
    let schedule = store
        .create_schedule(
            org1.id,
            Some(asset1.id),
            "Daily Network Audit",
            "0 0 * * *",
            "10.0.0.5",
            "remote_network",
            "standard",
        )
        .await
        .expect("Must create schedule");

    let due = store.get_due_schedules().await.expect("Must query due");
    assert!(due.iter().any(|s| s.id == schedule.id));

    let next_run = Utc::now() + Duration::days(1);
    store
        .update_schedule_run_state(schedule.id, Utc::now(), Some(next_run))
        .await
        .expect("Must update schedule");

    // 9. Test Token Revocation in PostgreSQL
    let jti = Uuid::new_v4();
    let exp = Utc::now() + Duration::hours(2);
    assert!(!store.is_token_revoked(jti).await.unwrap());
    store
        .revoke_token(jti, exp)
        .await
        .expect("Must revoke token");
    assert!(store.is_token_revoked(jti).await.unwrap());

    // 10. Test Interrupted Job Recovery in PostgreSQL
    let interrupted = store
        .create_job(org1.id, None, "10.0.0.9", "local_host", "standard")
        .await
        .expect("Must create job");
    store
        .update_job_status(org1.id, interrupted.id, JobStatus::Running, None, None)
        .await
        .expect("Set to running");

    let recovered_count = store
        .recover_interrupted_jobs()
        .await
        .expect("Recover must succeed");
    assert!(recovered_count >= 1);

    let recovered_job = store
        .get_job(org1.id, interrupted.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(recovered_job.status, JobStatus::Failed);
    assert!(recovered_job
        .error_message
        .as_deref()
        .unwrap()
        .contains("interrupted by server restart"));

    // 11. Test Agent Enrollment and Distributed Dispatch in PostgreSQL
    let token_sec = "pg-token-secret-12345";
    let token = store
        .issue_agent_enrollment_token(
            org1.id,
            token_sec,
            Some("pg-node-01"),
            "nonce-999",
            Utc::now() + Duration::minutes(15),
        )
        .await
        .expect("Must issue token in PG");
    assert_eq!(token.org_id, org1.id);

    store
        .consume_enrollment_token(token.id)
        .await
        .expect("Must consume PG token");
    let replay_err = store.consume_enrollment_token(token.id).await;
    assert!(matches!(replay_err, Err(StoreError::Conflict(_))));

    let auth_hash = "pg_agent_auth_hash_567";
    let agent = store
        .enroll_agent(
            org1.id,
            "pg-node-01",
            "pg-worker.internal",
            "0.1.0-alpha.0",
            auth_hash,
            "spki-der-pg",
            r#"["host_audit","perimeter_scan"]"#,
        )
        .await
        .expect("Must enroll agent in PG");
    assert_eq!(agent.status, AgentStatus::Active);

    let found_agent = store
        .get_agent_by_auth_hash(auth_hash)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found_agent.id, agent.id);

    let pg_job = store
        .create_job(org1.id, None, "10.10.10.1", "host_audit", "standard")
        .await
        .expect("Create PG job");

    let claimed = store
        .claim_next_pending_job(agent.id, org1.id, 60)
        .await
        .expect("Claim PG job")
        .expect("Must claim");
    assert_eq!(claimed.id, pg_job.id);
    assert_eq!(claimed.assigned_agent_id, Some(agent.id));
    assert_eq!(claimed.status, JobStatus::Running);

    let pg_finding = NewFinding {
        rule_id: "pg.audit.rule".into(),
        severity: "High".into(),
        confidence: "Confirmed".into(),
        title: "Postgres Agent Test Finding".into(),
        endpoint: "pg-endpoint".into(),
        evidence: "evidence-1".into(),
        recommendation: "remediate-1".into(),
    };
    store
        .complete_agent_job(
            agent.id,
            pg_job.id,
            org1.id,
            Some(r#"{"success":true}"#),
            &[pg_finding],
        )
        .await
        .expect("Complete agent job in PG");

    let completed_pg_job = store.get_job(org1.id, pg_job.id).await.unwrap().unwrap();
    assert_eq!(completed_pg_job.status, JobStatus::Completed);

    // Test PG Credential Rotation Fallback
    let old_pg_hash = &agent.auth_token_hash;
    let new_pg_hash = "pg-hash-rotated";
    store
        .rotate_agent_credential(agent.id, new_pg_hash)
        .await
        .expect("Rotate PG credential");

    // Old hash still resolves during transition
    let resolved_old = store.get_agent_by_auth_hash(old_pg_hash).await.unwrap();
    assert!(
        resolved_old.is_some(),
        "Old credential should resolve in PG during transition"
    );

    // Heartbeat clears fallback
    store
        .update_agent_heartbeat(agent.id, Utc::now())
        .await
        .expect("Heartbeat clears fallback");
    let resolved_old_after_hb = store.get_agent_by_auth_hash(old_pg_hash).await.unwrap();
    assert!(
        resolved_old_after_hb.is_none(),
        "Old credential must be invalidated after heartbeat in PG"
    );
}
