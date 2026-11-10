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

use openaudit_server::store::models::{
    AgentStatus, FindingStatus, JobStatus, NewFinding, ResolutionType, Role,
};
use openaudit_server::store::postgres::PostgresControlPlaneStore;
use openaudit_server::store::{ControlPlaneStore, StoreError};

fn resolve_postgres_config() -> (String, bool) {
    for var in ["OPENAUDIT_TEST_POSTGRES_URL", "TEST_DATABASE_URL"] {
        if let Ok(url) = env::var(var) {
            let trimmed = url.trim();
            if !trimmed.is_empty() {
                return (trimmed.to_string(), true);
            }
        }
    }
    let require_pg = env::var("OPENAUDIT_REQUIRE_POSTGRES_TESTS")
        .is_ok_and(|v| matches!(v.trim(), "1" | "true" | "TRUE" | "yes"));
    (
        "postgres://postgres:postgres@127.0.0.1:5433/openaudit_test".to_string(),
        require_pg,
    )
}

async fn connect_postgres_store() -> Option<(PostgresControlPlaneStore, String)> {
    let (pg_url, required) = resolve_postgres_config();
    match PostgresControlPlaneStore::connect(&pg_url).await {
        Ok(store) => Some((store, pg_url)),
        Err(err) => {
            assert!(
                !required,
                "PostgreSQL integration test database is required but connection to '{pg_url}' failed: {err}"
            );
            eprintln!("PostgreSQL connection failed ({err}); skipping test because no explicit OPENAUDIT_TEST_POSTGRES_URL was required");
            None
        }
    }
}

static PG_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn truncate_tables(pg_url: &str) {
    if let Ok((pg_client, connection)) =
        tokio_postgres::connect(pg_url, tokio_postgres::NoTls).await
    {
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let _ = pg_client
            .batch_execute(
                "TRUNCATE TABLE assessment_findings, assessment_jobs, assessment_schedules, assets, agent_enrollment_tokens, enrolled_agents, managed_findings, finding_status_history, users, organizations CASCADE;",
            )
            .await;
    }
}

#[tokio::test]
async fn test_postgres_full_persistence_and_isolation_lifecycle() {
    let _lock = PG_TEST_LOCK.lock().await;
    let Some((store, pg_url)) = connect_postgres_store().await else {
        return;
    };

    assert!(store.is_healthy().await, "PostgreSQL store must be healthy");

    // 1. Test migration idempotency
    store.migrate().await.expect("Migration must be idempotent");
    truncate_tables(&pg_url).await;

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
    assert_eq!(
        findings_org2.len(),
        0,
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

#[tokio::test]
async fn test_postgres_m7_finding_lifecycle_and_posture() {
    let _lock = PG_TEST_LOCK.lock().await;
    let Some((store, pg_url)) = connect_postgres_store().await else {
        return;
    };

    // Ensure migration 003 applied
    store
        .migrate()
        .await
        .expect("Migration 003 must be applied in PG");
    truncate_tables(&pg_url).await;

    let org_slug = format!("pg-m7-{}", Uuid::new_v4());
    let org = store
        .create_organization("PG M7 Corp", &org_slug)
        .await
        .unwrap();

    let asset = store
        .create_asset(org.id, "Prod API", "server", "api.prod.pg", "critical")
        .await
        .unwrap();

    let job1 = store
        .create_job(org.id, Some(asset.id), "api.prod.pg", "perimeter", "std")
        .await
        .unwrap();

    let finding_tls = NewFinding {
        rule_id: "tls.cert.expired".into(),
        severity: "critical".into(),
        confidence: "Confirmed".into(),
        title: "Expired Cert".into(),
        endpoint: "443/tcp".into(),
        evidence: "Cert expired yesterday".into(),
        recommendation: "Renew cert".into(),
    };
    let finding_hsts = NewFinding {
        rule_id: "http.headers.hsts".into(),
        severity: "high".into(),
        confidence: "Confirmed".into(),
        title: "Missing HSTS".into(),
        endpoint: "https://api.prod.pg/".into(),
        evidence: "No HSTS header".into(),
        recommendation: "Add Strict-Transport-Security".into(),
    };

    let base_rules = vec![
        "tls.cert.expired".to_string(),
        "http.headers.hsts".to_string(),
    ];
    let created = store
        .record_job_findings_and_reconcile_lifecycle(
            org.id,
            job1.id,
            &[finding_tls.clone(), finding_hsts],
            &base_rules,
        )
        .await
        .unwrap();
    assert_eq!(created.len(), 2);
    let tls_managed_id = created[0].managed_finding_id.unwrap();
    let hsts_managed_id = created[1].managed_finding_id.unwrap();

    // Verify initial managed finding in Postgres
    let managed_tls = store
        .get_managed_finding(org.id, tls_managed_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(managed_tls.status, FindingStatus::Open);
    assert_eq!(managed_tls.occurrence_count, 1);

    // Job 2: verified remediation of TLS, but HSTS was omitted from evaluation
    let job2 = store
        .create_job(
            org.id,
            Some(asset.id),
            "api.prod.pg",
            "perimeter",
            "tls_only",
        )
        .await
        .unwrap();
    let scan2_rules = vec!["tls.cert.expired".to_string()];
    let created2 = store
        .record_job_findings_and_reconcile_lifecycle(org.id, job2.id, &[], &scan2_rules)
        .await
        .unwrap();
    assert_eq!(created2.len(), 0);

    // In Postgres: TLS cert finding is VerifiedRemediated
    let resolved_tls = store
        .get_managed_finding(org.id, tls_managed_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(resolved_tls.status, FindingStatus::Resolved);
    assert_eq!(
        resolved_tls.resolution_type,
        Some(ResolutionType::VerifiedRemediated)
    );

    // In Postgres: HSTS finding remains Open (unverified omission)
    let omitted_hsts = store
        .get_managed_finding(org.id, hsts_managed_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(omitted_hsts.status, FindingStatus::Open);

    // Test Assessment Comparison in Postgres
    let comp = store
        .compare_assessments(org.id, job1.id, job2.id)
        .await
        .unwrap();
    assert_eq!(comp.resolved_findings.len(), 1);
    assert_eq!(comp.unverified_omissions.len(), 1);
    assert!((comp.coverage_ratio - 0.5).abs() < f64::EPSILON);

    // Mark job1 completed to test Posture Summary
    store
        .update_job_status(org.id, job1.id, JobStatus::Completed, Some("{}"), None)
        .await
        .unwrap();

    let summary = store
        .get_security_posture_summary(org.id, Some(asset.id))
        .await
        .unwrap();
    assert_eq!(summary.total_assets, 1);
    assert_eq!(summary.assessed_assets, 1);
    assert_eq!(summary.total_active_findings, 1);
    assert_eq!(summary.verified_remediations_count, 1);
}

#[tokio::test]
async fn test_postgres_m8_bounded_credential_rotation_grace_period() {
    let _lock = PG_TEST_LOCK.lock().await;
    let Some((store, pg_url)) = connect_postgres_store().await else {
        return;
    };

    store
        .migrate()
        .await
        .expect("Migrations must succeed in PG");
    truncate_tables(&pg_url).await;

    let org = store
        .create_organization("PG Rotation Corp", &format!("pg-rot-{}", Uuid::new_v4()))
        .await
        .unwrap();

    let key1_hash = "hash_key_1_original";
    let key2_hash = "hash_key_2_rotated";

    // 1. Enroll agent with initial credential
    let agent = store
        .enroll_agent(
            org.id,
            "pg-worker-01",
            "worker.pg.corp",
            "0.1.0-alpha.0",
            key1_hash,
            "pure-crypto:pg",
            "[\"host_audit\"]",
        )
        .await
        .unwrap();

    // Initial key works
    assert!(store
        .get_agent_by_auth_hash(key1_hash)
        .await
        .unwrap()
        .is_some());

    // 2. Rotate credential: key2 is primary, key1 is previous fallback
    store
        .rotate_agent_credential(agent.id, key2_hash)
        .await
        .unwrap();

    // 3. Within 15-minute grace period: BOTH keys work
    assert!(
        store
            .get_agent_by_auth_hash(key1_hash)
            .await
            .unwrap()
            .is_some(),
        "Fallback key must be accepted within grace period"
    );
    assert!(
        store
            .get_agent_by_auth_hash(key2_hash)
            .await
            .unwrap()
            .is_some(),
        "New key must be accepted"
    );

    // 4. Simulate passage of time past 15-minute grace period (20 minutes ago)
    let (client, connection) = tokio_postgres::connect(&pg_url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });

    client
        .execute(
            "UPDATE enrolled_agents SET updated_at = NOW() - INTERVAL '20 minutes' WHERE id = $1",
            &[&agent.id],
        )
        .await
        .unwrap();

    // 5. Past grace period: fallback key MUST be rejected fail-closed
    assert!(
        store
            .get_agent_by_auth_hash(key1_hash)
            .await
            .unwrap()
            .is_none(),
        "Expired fallback key must be rejected past grace period"
    );

    // 6. Current key continues to work normally
    assert!(
        store
            .get_agent_by_auth_hash(key2_hash)
            .await
            .unwrap()
            .is_some(),
        "Current primary key must remain valid"
    );
}

#[tokio::test]
async fn test_postgres_concurrent_job_claiming_and_transaction_atomicity() {
    let _lock = PG_TEST_LOCK.lock().await;
    let Some((store, pg_url)) = connect_postgres_store().await else {
        return;
    };

    store
        .migrate()
        .await
        .expect("Migrations must succeed in PG");
    truncate_tables(&pg_url).await;

    let org1 = store
        .create_organization(
            "PG Concurrency Org 1",
            &format!("pg-conc-1-{}", Uuid::new_v4()),
        )
        .await
        .unwrap();
    let org2 = store
        .create_organization(
            "PG Concurrency Org 2",
            &format!("pg-conc-2-{}", Uuid::new_v4()),
        )
        .await
        .unwrap();

    // Create 3 pending jobs in Org 1
    let mut expected_job_ids = Vec::new();
    for idx in 0..3 {
        let job = store
            .create_job(
                org1.id,
                None,
                &format!("10.20.0.{idx}"),
                "host_audit",
                "standard",
            )
            .await
            .unwrap();
        expected_job_ids.push(job.id);
    }

    // Enroll 6 agents in Org 1 and 2 agents in Org 2
    let mut org1_agents = Vec::new();
    for idx in 0..6 {
        let agent = store
            .enroll_agent(
                org1.id,
                &format!("org1-worker-{idx}"),
                &format!("w{idx}.org1.pg"),
                "0.1.0-alpha.0",
                &format!("org1_auth_hash_{idx}_{}", Uuid::new_v4()),
                "spki-der-org1",
                "[\"host_audit\"]",
            )
            .await
            .unwrap();
        org1_agents.push(agent);
    }

    let mut org2_agents = Vec::new();
    for idx in 0..2 {
        let agent = store
            .enroll_agent(
                org2.id,
                &format!("org2-worker-{idx}"),
                &format!("w{idx}.org2.pg"),
                "0.1.0-alpha.0",
                &format!("org2_auth_hash_{idx}_{}", Uuid::new_v4()),
                "spki-der-org2",
                "[\"host_audit\"]",
            )
            .await
            .unwrap();
        org2_agents.push(agent);
    }

    // Spawn 8 concurrent claim tasks (6 in Org 1, 2 in Org 2)
    let mut handles = Vec::new();
    for agent in &org1_agents {
        let store_clone = store.clone();
        let agent_id = agent.id;
        let org_id = org1.id;
        handles.push(tokio::spawn(async move {
            (
                org_id,
                agent_id,
                store_clone
                    .claim_next_pending_job(agent_id, org_id, 60)
                    .await
                    .expect("Concurrent claim must not error"),
            )
        }));
    }
    for agent in &org2_agents {
        let store_clone = store.clone();
        let agent_id = agent.id;
        let org_id = org2.id;
        handles.push(tokio::spawn(async move {
            (
                org_id,
                agent_id,
                store_clone
                    .claim_next_pending_job(agent_id, org_id, 60)
                    .await
                    .expect("Concurrent claim must not error"),
            )
        }));
    }

    let mut claimed_jobs = Vec::new();
    for handle in handles {
        let (org_id, agent_id, claimed_opt) = handle.await.unwrap();
        if let Some(claimed) = claimed_opt {
            assert_eq!(org_id, org1.id, "Org 2 agent must never claim Org 1 job");
            assert_eq!(claimed.assigned_agent_id, Some(agent_id));
            claimed_jobs.push((agent_id, claimed.id));
        }
    }

    assert_eq!(
        claimed_jobs.len(),
        3,
        "Exactly 3 of the 6 Org 1 agents must claim the 3 pending jobs without double-claiming"
    );
    let mut unique_ids: Vec<Uuid> = claimed_jobs.iter().map(|(_, jid)| *jid).collect();
    unique_ids.sort();
    expected_job_ids.sort();
    assert_eq!(unique_ids, expected_job_ids);

    // Verify transactional rejection when an unassigned agent or wrong org attempts to complete a claimed job
    let (assigned_agent_id, target_job_id) = claimed_jobs[0];
    let wrong_agent_id = org1_agents
        .iter()
        .find(|a| a.id != assigned_agent_id)
        .unwrap()
        .id;
    let bogus_finding = NewFinding {
        rule_id: "pg.tx.rollback".into(),
        severity: "High".into(),
        confidence: "Confirmed".into(),
        title: "Should Not Persist".into(),
        endpoint: "tx-endpoint".into(),
        evidence: "unauthorized".into(),
        recommendation: "none".into(),
    };

    let unauthorized_complete = store
        .complete_agent_job(
            wrong_agent_id,
            target_job_id,
            org1.id,
            Some(r#"{"tampered":true}"#),
            std::slice::from_ref(&bogus_finding),
        )
        .await;
    assert!(
        unauthorized_complete.is_err(),
        "Unassigned agent completion must fail transactionally"
    );

    let cross_tenant_complete = store
        .complete_agent_job(
            assigned_agent_id,
            target_job_id,
            org2.id,
            Some(r#"{"tampered":true}"#),
            std::slice::from_ref(&bogus_finding),
        )
        .await;
    assert!(
        cross_tenant_complete.is_err(),
        "Cross-tenant completion must fail transactionally"
    );

    // Verify zero findings were persisted from the rejected completion attempts
    let persisted_findings = store
        .list_findings(org1.id, Some(target_job_id), None)
        .await
        .unwrap();
    assert!(
        persisted_findings.is_empty(),
        "Rejected completion transaction must roll back and leave zero findings"
    );
}
