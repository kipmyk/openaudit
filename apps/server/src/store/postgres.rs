//! PostgreSQL persistence backend for OpenAudit control plane.

use chrono::{DateTime, Duration, Utc};
use deadpool_postgres::{Config as PoolConfig, Pool, Runtime};
use tokio_postgres::NoTls;
use uuid::Uuid;

use super::models::{
    AgentEnrollmentToken, AgentStatus, AssessmentFinding, AssessmentJob, AssessmentSchedule, Asset,
    EnrolledAgent, JobStatus, NewFinding, Organization, Role, User,
};
use super::{ControlPlaneStore, StoreError};

const INITIAL_SCHEMA: &str = include_str!("../../migrations/001_initial_schema.sql");
const SCHEMA_MIGRATION_002: &str =
    include_str!("../../migrations/002_agent_enrollment_and_communication.sql");

/// Production PostgreSQL-backed store implementation with connection pooling.
#[derive(Clone, Debug)]
pub struct PostgresControlPlaneStore {
    pool: Pool,
}

impl PostgresControlPlaneStore {
    /// Connects to PostgreSQL, configures the connection pool, and executes pending migrations.
    ///
    /// # Errors
    ///
    /// Returns an error if the database connection fails or migration execution fails.
    pub async fn connect(database_url: &str) -> Result<Self, StoreError> {
        let mut cfg = PoolConfig::new();
        cfg.url = Some(database_url.to_string());

        let pool = cfg
            .create_pool(Some(Runtime::Tokio1), NoTls)
            .map_err(|e| StoreError::Database(format!("Failed to create PostgreSQL pool: {e}")))?;

        let store = Self { pool };
        store.migrate().await?;
        Ok(store)
    }

    /// Executes database migrations idempotently.
    ///
    /// # Errors
    ///
    /// Returns error if schema migration execution fails.
    pub async fn migrate(&self) -> Result<(), StoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StoreError::Database(format!("Pool checkout failed: {e}")))?;

        // Ensure schema_migrations table exists
        client
            .batch_execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    applied_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                );",
            )
            .await
            .map_err(|e| StoreError::Database(format!("Failed to create migrations table: {e}")))?;

        let row = client
            .query_opt(
                "SELECT version FROM schema_migrations WHERE version = $1",
                &[&1i32],
            )
            .await
            .map_err(|e| StoreError::Database(format!("Failed to check migrations: {e}")))?;

        if row.is_none() {
            tracing::info!("Applying PostgreSQL migration 001_initial_schema.sql...");
            client.batch_execute(INITIAL_SCHEMA).await.map_err(|e| {
                StoreError::Database(format!("Migration 001 execution failed: {e}"))
            })?;

            client
                .execute(
                    "INSERT INTO schema_migrations (version) VALUES ($1)",
                    &[&1i32],
                )
                .await
                .map_err(|e| {
                    StoreError::Database(format!("Failed to record migration 001: {e}"))
                })?;
            tracing::info!("PostgreSQL migration 001 applied successfully.");
        }

        let row_m2 = client
            .query_opt(
                "SELECT version FROM schema_migrations WHERE version = $1",
                &[&2i32],
            )
            .await
            .map_err(|e| StoreError::Database(format!("Failed to check migrations: {e}")))?;

        if row_m2.is_none() {
            tracing::info!(
                "Applying PostgreSQL migration 002_agent_enrollment_and_communication.sql..."
            );
            client
                .batch_execute(SCHEMA_MIGRATION_002)
                .await
                .map_err(|e| {
                    StoreError::Database(format!("Migration 002 execution failed: {e}"))
                })?;

            client
                .execute(
                    "INSERT INTO schema_migrations (version) VALUES ($1)",
                    &[&2i32],
                )
                .await
                .map_err(|e| {
                    StoreError::Database(format!("Failed to record migration 002: {e}"))
                })?;
            tracing::info!("PostgreSQL migration 002 applied successfully.");
        }

        Ok(())
    }
}

#[async_trait::async_trait]
impl ControlPlaneStore for PostgresControlPlaneStore {
    async fn is_healthy(&self) -> bool {
        match self.pool.get().await {
            Ok(client) => client.query_one("SELECT 1", &[]).await.is_ok(),
            Err(_) => false,
        }
    }

    async fn bootstrap_admin(
        &self,
        org_name: &str,
        org_slug: &str,
        admin_name: &str,
        admin_email: &str,
        password_hash: &str,
    ) -> Result<(Organization, User), StoreError> {
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let tx = client
            .transaction()
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        // Atomic check: ensure no users exist anywhere in the system
        let count_row = tx
            .query_one("SELECT COUNT(*) FROM users", &[])
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;
        let user_count: i64 = count_row.get(0);
        if user_count > 0 {
            return Err(StoreError::Conflict(
                "Control plane already bootstrapped with existing users".into(),
            ));
        }

        // Check if organization slug exists
        let org_row = tx
            .query_opt("SELECT id FROM organizations WHERE slug = $1", &[&org_slug])
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;
        if org_row.is_some() {
            return Err(StoreError::Conflict(format!(
                "Organization slug '{org_slug}' already exists"
            )));
        }

        let org_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let now = Utc::now();

        tx.execute(
            "INSERT INTO organizations (id, slug, name, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5)",
            &[&org_id, &org_slug, &org_name, &now, &now],
        )
        .await
        .map_err(|e| StoreError::Database(e.to_string()))?;

        tx.execute(
            "INSERT INTO users (id, org_id, email, password_hash, name, role, is_active, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
            &[
                &user_id,
                &org_id,
                &admin_email,
                &password_hash,
                &admin_name,
                &Role::Admin.as_str(),
                &true,
                &now,
                &now,
            ],
        )
        .await
        .map_err(|e| StoreError::Database(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        Ok((
            Organization {
                id: org_id,
                slug: org_slug.to_string(),
                name: org_name.to_string(),
                created_at: now,
                updated_at: now,
            },
            User {
                id: user_id,
                org_id,
                email: admin_email.to_string(),
                password_hash: password_hash.to_string(),
                name: admin_name.to_string(),
                role: Role::Admin,
                is_active: true,
                created_at: now,
                updated_at: now,
            },
        ))
    }

    async fn create_organization(
        &self,
        name: &str,
        slug: &str,
    ) -> Result<Organization, StoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;
        let id = Uuid::new_v4();
        let now = Utc::now();

        client
            .execute(
                "INSERT INTO organizations (id, slug, name, created_at, updated_at)
                 VALUES ($1, $2, $3, $4, $5)",
                &[&id, &slug, &name, &now, &now],
            )
            .await
            .map_err(|e| {
                if e.to_string().contains("unique") || e.to_string().contains("duplicate") {
                    StoreError::Conflict(format!("Organization slug '{slug}' already exists"))
                } else {
                    StoreError::Database(e.to_string())
                }
            })?;

        Ok(Organization {
            id,
            slug: slug.to_string(),
            name: name.to_string(),
            created_at: now,
            updated_at: now,
        })
    }

    async fn get_organization(&self, id: Uuid) -> Result<Option<Organization>, StoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;
        let row = client
            .query_opt(
                "SELECT id, slug, name, created_at, updated_at FROM organizations WHERE id = $1",
                &[&id],
            )
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        Ok(row.map(|r| Organization {
            id: r.get(0),
            slug: r.get(1),
            name: r.get(2),
            created_at: r.get(3),
            updated_at: r.get(4),
        }))
    }

    async fn get_organization_by_slug(
        &self,
        slug: &str,
    ) -> Result<Option<Organization>, StoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;
        let row = client
            .query_opt(
                "SELECT id, slug, name, created_at, updated_at FROM organizations WHERE slug = $1",
                &[&slug],
            )
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        Ok(row.map(|r| Organization {
            id: r.get(0),
            slug: r.get(1),
            name: r.get(2),
            created_at: r.get(3),
            updated_at: r.get(4),
        }))
    }

    async fn create_user(
        &self,
        org_id: Uuid,
        email: &str,
        password_hash: &str,
        name: &str,
        role: Role,
    ) -> Result<User, StoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;
        let id = Uuid::new_v4();
        let now = Utc::now();

        client
            .execute(
                "INSERT INTO users (id, org_id, email, password_hash, name, role, is_active, created_at, updated_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
                &[
                    &id,
                    &org_id,
                    &email,
                    &password_hash,
                    &name,
                    &role.as_str(),
                    &true,
                    &now,
                    &now,
                ],
            )
            .await
            .map_err(|e| {
                if e.to_string().contains("unique") || e.to_string().contains("duplicate") {
                    StoreError::Conflict(format!("User email '{email}' already exists in this organization"))
                } else {
                    StoreError::Database(e.to_string())
                }
            })?;

        Ok(User {
            id,
            org_id,
            email: email.to_string(),
            password_hash: password_hash.to_string(),
            name: name.to_string(),
            role,
            is_active: true,
            created_at: now,
            updated_at: now,
        })
    }

    async fn get_user_by_email(&self, email: &str) -> Result<Option<User>, StoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;
        let row = client
            .query_opt(
                "SELECT id, org_id, email, password_hash, name, role, is_active, created_at, updated_at
                 FROM users WHERE email = $1",
                &[&email],
            )
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        row.map(|r| {
            let role_str: String = r.get(5);
            let role = Role::parse(&role_str).map_err(StoreError::Database)?;
            Ok(User {
                id: r.get(0),
                org_id: r.get(1),
                email: r.get(2),
                password_hash: r.get(3),
                name: r.get(4),
                role,
                is_active: r.get(6),
                created_at: r.get(7),
                updated_at: r.get(8),
            })
        })
        .transpose()
    }

    async fn get_user_by_id(
        &self,
        org_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<User>, StoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;
        let row = client
            .query_opt(
                "SELECT id, org_id, email, password_hash, name, role, is_active, created_at, updated_at
                 FROM users WHERE org_id = $1 AND id = $2",
                &[&org_id, &user_id],
            )
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        row.map(|r| {
            let role_str: String = r.get(5);
            let role = Role::parse(&role_str).map_err(StoreError::Database)?;
            Ok(User {
                id: r.get(0),
                org_id: r.get(1),
                email: r.get(2),
                password_hash: r.get(3),
                name: r.get(4),
                role,
                is_active: r.get(6),
                created_at: r.get(7),
                updated_at: r.get(8),
            })
        })
        .transpose()
    }

    async fn list_users(&self, org_id: Uuid) -> Result<Vec<User>, StoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;
        let rows = client
            .query(
                "SELECT id, org_id, email, password_hash, name, role, is_active, created_at, updated_at
                 FROM users WHERE org_id = $1 ORDER BY created_at ASC",
                &[&org_id],
            )
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let mut users = Vec::with_capacity(rows.len());
        for r in rows {
            let role_str: String = r.get(5);
            let role = Role::parse(&role_str).map_err(StoreError::Database)?;
            users.push(User {
                id: r.get(0),
                org_id: r.get(1),
                email: r.get(2),
                password_hash: r.get(3),
                name: r.get(4),
                role,
                is_active: r.get(6),
                created_at: r.get(7),
                updated_at: r.get(8),
            });
        }
        Ok(users)
    }

    async fn create_asset(
        &self,
        org_id: Uuid,
        name: &str,
        asset_type: &str,
        target: &str,
        criticality: &str,
    ) -> Result<Asset, StoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;
        let id = Uuid::new_v4();
        let now = Utc::now();

        client
            .execute(
                "INSERT INTO assets (id, org_id, name, asset_type, target, criticality, created_at, updated_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                &[&id, &org_id, &name, &asset_type, &target, &criticality, &now, &now],
            )
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        Ok(Asset {
            id,
            org_id,
            name: name.to_string(),
            asset_type: asset_type.to_string(),
            target: target.to_string(),
            criticality: criticality.to_string(),
            created_at: now,
            updated_at: now,
        })
    }

    async fn get_asset(&self, org_id: Uuid, id: Uuid) -> Result<Option<Asset>, StoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;
        let row = client
            .query_opt(
                "SELECT id, org_id, name, asset_type, target, criticality, created_at, updated_at
                 FROM assets WHERE org_id = $1 AND id = $2",
                &[&org_id, &id],
            )
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        Ok(row.map(|r| Asset {
            id: r.get(0),
            org_id: r.get(1),
            name: r.get(2),
            asset_type: r.get(3),
            target: r.get(4),
            criticality: r.get(5),
            created_at: r.get(6),
            updated_at: r.get(7),
        }))
    }

    async fn list_assets(&self, org_id: Uuid) -> Result<Vec<Asset>, StoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;
        let rows = client
            .query(
                "SELECT id, org_id, name, asset_type, target, criticality, created_at, updated_at
                 FROM assets WHERE org_id = $1 ORDER BY created_at DESC",
                &[&org_id],
            )
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let assets = rows
            .into_iter()
            .map(|r| Asset {
                id: r.get(0),
                org_id: r.get(1),
                name: r.get(2),
                asset_type: r.get(3),
                target: r.get(4),
                criticality: r.get(5),
                created_at: r.get(6),
                updated_at: r.get(7),
            })
            .collect();
        Ok(assets)
    }

    async fn delete_asset(&self, org_id: Uuid, id: Uuid) -> Result<bool, StoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;
        let count = client
            .execute(
                "DELETE FROM assets WHERE org_id = $1 AND id = $2",
                &[&org_id, &id],
            )
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        Ok(count > 0)
    }

    async fn create_job(
        &self,
        org_id: Uuid,
        asset_id: Option<Uuid>,
        target: &str,
        assessment_type: &str,
        profile: &str,
    ) -> Result<AssessmentJob, StoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;
        let id = Uuid::new_v4();
        let now = Utc::now();
        let status = JobStatus::Pending;

        client
            .execute(
                "INSERT INTO assessment_jobs (id, org_id, asset_id, target, assessment_type, profile, status, created_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                &[
                    &id,
                    &org_id,
                    &asset_id,
                    &target,
                    &assessment_type,
                    &profile,
                    &status.as_str(),
                    &now,
                ],
            )
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        Ok(AssessmentJob {
            id,
            org_id,
            asset_id,
            target: target.to_string(),
            assessment_type: assessment_type.to_string(),
            profile: profile.to_string(),
            status,
            summary_json: None,
            error_message: None,
            started_at: None,
            completed_at: None,
            created_at: now,
            assigned_agent_id: None,
            lease_expires_at: None,
            execution_source: "server".to_string(),
            rules_subset: None,
        })
    }

    async fn get_job(&self, org_id: Uuid, id: Uuid) -> Result<Option<AssessmentJob>, StoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;
        let row = client
            .query_opt(
                "SELECT id, org_id, asset_id, target, assessment_type, profile, status, summary_json, error_message, started_at, completed_at, created_at, assigned_agent_id, lease_expires_at, execution_source, rules_subset
                 FROM assessment_jobs WHERE org_id = $1 AND id = $2",
                &[&org_id, &id],
            )
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        row.map(|r| {
            let status_str: String = r.get(6);
            let status = JobStatus::parse(&status_str).map_err(StoreError::Database)?;
            Ok(AssessmentJob {
                id: r.get(0),
                org_id: r.get(1),
                asset_id: r.get(2),
                target: r.get(3),
                assessment_type: r.get(4),
                profile: r.get(5),
                status,
                summary_json: r.get(7),
                error_message: r.get(8),
                started_at: r.get(9),
                completed_at: r.get(10),
                created_at: r.get(11),
                assigned_agent_id: r.get(12),
                lease_expires_at: r.get(13),
                execution_source: r.get(14),
                rules_subset: r.get(15),
            })
        })
        .transpose()
    }

    async fn update_job_status(
        &self,
        org_id: Uuid,
        id: Uuid,
        status: JobStatus,
        summary_json: Option<&str>,
        error_message: Option<&str>,
    ) -> Result<(), StoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        // Validate state transitions
        let current_job = self.get_job(org_id, id).await?;
        let current =
            current_job.ok_or_else(|| StoreError::NotFound(format!("Job '{id}' not found")))?;

        if current.status.is_terminal() {
            return Err(StoreError::Conflict(format!(
                "Cannot transition job '{id}' from terminal status '{:?}' to '{:?}'",
                current.status, status
            )));
        }

        let now = Utc::now();

        let count = match status {
            JobStatus::Running => {
                client
                    .execute(
                        "UPDATE assessment_jobs SET status = $1, started_at = $2 WHERE org_id = $3 AND id = $4",
                        &[&status.as_str(), &now, &org_id, &id],
                    )
                    .await
            }
            JobStatus::Completed | JobStatus::Failed | JobStatus::Cancelled => {
                client
                    .execute(
                        "UPDATE assessment_jobs SET status = $1, summary_json = $2, error_message = $3, completed_at = $4 WHERE org_id = $5 AND id = $6",
                        &[&status.as_str(), &summary_json, &error_message, &now, &org_id, &id],
                    )
                    .await
            }
            JobStatus::Pending => {
                client
                    .execute(
                        "UPDATE assessment_jobs SET status = $1 WHERE org_id = $2 AND id = $3",
                        &[&status.as_str(), &org_id, &id],
                    )
                    .await
            }
        }
        .map_err(|e| StoreError::Database(e.to_string()))?;

        if count == 0 {
            return Err(StoreError::NotFound(format!("Job '{id}' not found")));
        }

        Ok(())
    }

    async fn list_jobs(
        &self,
        org_id: Uuid,
        limit: usize,
    ) -> Result<Vec<AssessmentJob>, StoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;
        let limit_i64 = limit as i64;
        let rows = client
            .query(
                "SELECT id, org_id, asset_id, target, assessment_type, profile, status, summary_json, error_message, started_at, completed_at, created_at, assigned_agent_id, lease_expires_at, execution_source, rules_subset
                 FROM assessment_jobs WHERE org_id = $1 ORDER BY created_at DESC LIMIT $2",
                &[&org_id, &limit_i64],
            )
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let mut jobs = Vec::with_capacity(rows.len());
        for r in rows {
            let status_str: String = r.get(6);
            let status = JobStatus::parse(&status_str).map_err(StoreError::Database)?;
            jobs.push(AssessmentJob {
                id: r.get(0),
                org_id: r.get(1),
                asset_id: r.get(2),
                target: r.get(3),
                assessment_type: r.get(4),
                profile: r.get(5),
                status,
                summary_json: r.get(7),
                error_message: r.get(8),
                started_at: r.get(9),
                completed_at: r.get(10),
                created_at: r.get(11),
                assigned_agent_id: r.get(12),
                lease_expires_at: r.get(13),
                execution_source: r.get(14),
                rules_subset: r.get(15),
            });
        }
        Ok(jobs)
    }

    async fn create_findings(
        &self,
        org_id: Uuid,
        job_id: Uuid,
        findings: &[NewFinding],
    ) -> Result<(), StoreError> {
        if findings.is_empty() {
            return Ok(());
        }

        let mut client = self
            .pool
            .get()
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let tx = client
            .transaction()
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let now = Utc::now();
        for f in findings {
            let id = Uuid::new_v4();
            tx.execute(
                "INSERT INTO assessment_findings (id, org_id, job_id, rule_id, severity, confidence, title, endpoint, evidence, remediation, created_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
                &[
                    &id,
                    &org_id,
                    &job_id,
                    &f.rule_id,
                    &f.severity,
                    &f.confidence,
                    &f.title,
                    &f.endpoint,
                    &f.evidence,
                    &f.recommendation,
                    &now,
                ],
            )
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;
        }

        tx.commit()
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;
        Ok(())
    }

    async fn list_findings(
        &self,
        org_id: Uuid,
        job_id: Option<Uuid>,
        min_severity: Option<&str>,
    ) -> Result<Vec<AssessmentFinding>, StoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let rows = match (job_id, min_severity) {
            (Some(jid), Some(sev)) => {
                client
                    .query(
                        "SELECT id, org_id, job_id, rule_id, severity, confidence, title, endpoint, evidence, remediation, created_at
                         FROM assessment_findings WHERE org_id = $1 AND job_id = $2 AND severity = $3 ORDER BY created_at DESC",
                        &[&org_id, &jid, &sev],
                    )
                    .await
            }
            (Some(jid), None) => {
                client
                    .query(
                        "SELECT id, org_id, job_id, rule_id, severity, confidence, title, endpoint, evidence, remediation, created_at
                         FROM assessment_findings WHERE org_id = $1 AND job_id = $2 ORDER BY created_at DESC",
                        &[&org_id, &jid],
                    )
                    .await
            }
            (None, Some(sev)) => {
                client
                    .query(
                        "SELECT id, org_id, job_id, rule_id, severity, confidence, title, endpoint, evidence, remediation, created_at
                         FROM assessment_findings WHERE org_id = $1 AND severity = $2 ORDER BY created_at DESC",
                        &[&org_id, &sev],
                    )
                    .await
            }
            (None, None) => {
                client
                    .query(
                        "SELECT id, org_id, job_id, rule_id, severity, confidence, title, endpoint, evidence, remediation, created_at
                         FROM assessment_findings WHERE org_id = $1 ORDER BY created_at DESC",
                        &[&org_id],
                    )
                    .await
            }
        }
        .map_err(|e| StoreError::Database(e.to_string()))?;

        let findings = rows
            .into_iter()
            .map(|r| AssessmentFinding {
                id: r.get(0),
                org_id: r.get(1),
                job_id: r.get(2),
                rule_id: r.get(3),
                severity: r.get(4),
                confidence: r.get(5),
                title: r.get(6),
                endpoint: r.get(7),
                evidence: r.get(8),
                recommendation: r.get(9),
                created_at: r.get(10),
            })
            .collect();
        Ok(findings)
    }

    async fn create_schedule(
        &self,
        org_id: Uuid,
        asset_id: Option<Uuid>,
        name: &str,
        cron_expression: &str,
        target: &str,
        assessment_type: &str,
        profile: &str,
    ) -> Result<AssessmentSchedule, StoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;
        let id = Uuid::new_v4();
        let now = Utc::now();

        client
            .execute(
                "INSERT INTO assessment_schedules (id, org_id, asset_id, name, cron_expression, target, assessment_type, profile, is_active, created_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
                &[
                    &id,
                    &org_id,
                    &asset_id,
                    &name,
                    &cron_expression,
                    &target,
                    &assessment_type,
                    &profile,
                    &true,
                    &now,
                ],
            )
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        Ok(AssessmentSchedule {
            id,
            org_id,
            asset_id,
            name: name.to_string(),
            cron_expression: cron_expression.to_string(),
            target: target.to_string(),
            assessment_type: assessment_type.to_string(),
            profile: profile.to_string(),
            is_active: true,
            last_run_at: None,
            next_run_at: None,
            created_at: now,
        })
    }

    async fn list_schedules(&self, org_id: Uuid) -> Result<Vec<AssessmentSchedule>, StoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;
        let rows = client
            .query(
                "SELECT id, org_id, asset_id, name, cron_expression, target, assessment_type, profile, is_active, last_run_at, next_run_at, created_at
                 FROM assessment_schedules WHERE org_id = $1 ORDER BY created_at DESC",
                &[&org_id],
            )
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let schedules = rows
            .into_iter()
            .map(|r| AssessmentSchedule {
                id: r.get(0),
                org_id: r.get(1),
                asset_id: r.get(2),
                name: r.get(3),
                cron_expression: r.get(4),
                target: r.get(5),
                assessment_type: r.get(6),
                profile: r.get(7),
                is_active: r.get(8),
                last_run_at: r.get(9),
                next_run_at: r.get(10),
                created_at: r.get(11),
            })
            .collect();
        Ok(schedules)
    }

    async fn get_due_schedules(&self) -> Result<Vec<AssessmentSchedule>, StoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;
        let now = Utc::now();
        let rows = client
            .query(
                "SELECT id, org_id, asset_id, name, cron_expression, target, assessment_type, profile, is_active, last_run_at, next_run_at, created_at
                 FROM assessment_schedules
                 WHERE is_active = TRUE AND (next_run_at IS NULL OR next_run_at <= $1)
                 ORDER BY created_at ASC",
                &[&now],
            )
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let schedules = rows
            .into_iter()
            .map(|r| AssessmentSchedule {
                id: r.get(0),
                org_id: r.get(1),
                asset_id: r.get(2),
                name: r.get(3),
                cron_expression: r.get(4),
                target: r.get(5),
                assessment_type: r.get(6),
                profile: r.get(7),
                is_active: r.get(8),
                last_run_at: r.get(9),
                next_run_at: r.get(10),
                created_at: r.get(11),
            })
            .collect();
        Ok(schedules)
    }

    async fn update_schedule_run_state(
        &self,
        schedule_id: Uuid,
        last_run: DateTime<Utc>,
        next_run: Option<DateTime<Utc>>,
    ) -> Result<(), StoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;
        client
            .execute(
                "UPDATE assessment_schedules SET last_run_at = $1, next_run_at = $2 WHERE id = $3",
                &[&last_run, &next_run, &schedule_id],
            )
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        Ok(())
    }

    async fn revoke_token(&self, jti: Uuid, expires_at: DateTime<Utc>) -> Result<(), StoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;
        let now = Utc::now();

        client
            .execute(
                "INSERT INTO revoked_tokens (jti, expires_at, revoked_at) VALUES ($1, $2, $3)
                 ON CONFLICT (jti) DO NOTHING",
                &[&jti, &expires_at, &now],
            )
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        Ok(())
    }

    async fn is_token_revoked(&self, jti: Uuid) -> Result<bool, StoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;
        let row = client
            .query_opt("SELECT 1 FROM revoked_tokens WHERE jti = $1", &[&jti])
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        Ok(row.is_some())
    }

    async fn clean_expired_revocations(&self) -> Result<usize, StoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;
        let now = Utc::now();
        let count = client
            .execute("DELETE FROM revoked_tokens WHERE expires_at < $1", &[&now])
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        Ok(count as usize)
    }

    async fn recover_interrupted_jobs(&self) -> Result<usize, StoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;
        let now = Utc::now();
        let count = client
            .execute(
                "UPDATE assessment_jobs SET status = 'failed', error_message = 'Job execution interrupted by server restart/shutdown', completed_at = $1 WHERE status = 'running'",
                &[&now],
            )
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        Ok(count as usize)
    }

    async fn issue_agent_enrollment_token(
        &self,
        org_id: Uuid,
        token_secret: &str,
        machine_id: Option<&str>,
        challenge_nonce: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<AgentEnrollmentToken, StoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let id = Uuid::new_v4();
        let now = Utc::now();

        client
            .execute(
                "INSERT INTO agent_enrollment_tokens (id, org_id, token_secret, machine_id, challenge_nonce, expires_at, created_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)",
                &[
                    &id,
                    &org_id,
                    &token_secret,
                    &machine_id,
                    &challenge_nonce,
                    &expires_at,
                    &now,
                ],
            )
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        Ok(AgentEnrollmentToken {
            id,
            org_id,
            token_secret: token_secret.to_string(),
            machine_id: machine_id.map(ToString::to_string),
            challenge_nonce: challenge_nonce.to_string(),
            expires_at,
            used_at: None,
            created_at: now,
        })
    }

    async fn get_agent_enrollment_token(
        &self,
        token_id: Uuid,
    ) -> Result<Option<AgentEnrollmentToken>, StoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let row = client
            .query_opt(
                "SELECT id, org_id, token_secret, machine_id, challenge_nonce, expires_at, used_at, created_at
                 FROM agent_enrollment_tokens WHERE id = $1",
                &[&token_id],
            )
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        Ok(row.map(|r| AgentEnrollmentToken {
            id: r.get(0),
            org_id: r.get(1),
            token_secret: r.get(2),
            machine_id: r.get(3),
            challenge_nonce: r.get(4),
            expires_at: r.get(5),
            used_at: r.get(6),
            created_at: r.get(7),
        }))
    }

    async fn consume_enrollment_token(&self, token_id: Uuid) -> Result<(), StoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let rows = client
            .execute(
                "UPDATE agent_enrollment_tokens
                 SET used_at = CURRENT_TIMESTAMP
                 WHERE id = $1 AND used_at IS NULL AND expires_at > CURRENT_TIMESTAMP",
                &[&token_id],
            )
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        if rows == 0 {
            return Err(StoreError::Conflict(
                "Enrollment token is invalid, expired, or already used".to_string(),
            ));
        }

        Ok(())
    }

    async fn enroll_agent(
        &self,
        org_id: Uuid,
        machine_id: &str,
        hostname: &str,
        agent_version: &str,
        auth_token_hash: &str,
        public_identity: &str,
        capabilities: &str,
    ) -> Result<EnrolledAgent, StoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let now = Utc::now();
        let fresh_id = Uuid::new_v4();

        let row = client
            .query_one(
                "INSERT INTO enrolled_agents (id, org_id, machine_id, hostname, agent_version, status, auth_token_hash, public_identity, capabilities, last_seen_at, enrolled_at, created_at, updated_at)
                 VALUES ($1, $2, $3, $4, $5, 'active', $6, $7, $8, $9, $9, $9, $9)
                 ON CONFLICT (org_id, machine_id) DO UPDATE
                 SET hostname = EXCLUDED.hostname,
                     agent_version = EXCLUDED.agent_version,
                     status = 'active',
                     auth_token_hash = EXCLUDED.auth_token_hash,
                     public_identity = EXCLUDED.public_identity,
                     capabilities = EXCLUDED.capabilities,
                     last_seen_at = EXCLUDED.last_seen_at,
                     enrolled_at = EXCLUDED.enrolled_at,
                     revoked_at = NULL,
                     updated_at = EXCLUDED.updated_at
                 RETURNING id, org_id, machine_id, hostname, agent_version, status, auth_token_hash, public_identity, capabilities, last_seen_at, enrolled_at, revoked_at, created_at, updated_at",
                &[
                    &fresh_id,
                    &org_id,
                    &machine_id,
                    &hostname,
                    &agent_version,
                    &auth_token_hash,
                    &public_identity,
                    &capabilities,
                    &now,
                ],
            )
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let status_str: String = row.get(5);
        let status = AgentStatus::parse(&status_str).map_err(StoreError::Database)?;

        Ok(EnrolledAgent {
            id: row.get(0),
            org_id: row.get(1),
            machine_id: row.get(2),
            hostname: row.get(3),
            agent_version: row.get(4),
            status,
            auth_token_hash: row.get(6),
            public_identity: row.get(7),
            capabilities: row.get(8),
            last_seen_at: row.get(9),
            enrolled_at: row.get(10),
            revoked_at: row.get(11),
            created_at: row.get(12),
            updated_at: row.get(13),
        })
    }

    async fn get_agent_by_id(
        &self,
        org_id: Uuid,
        agent_id: Uuid,
    ) -> Result<Option<EnrolledAgent>, StoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let row = client
            .query_opt(
                "SELECT id, org_id, machine_id, hostname, agent_version, status, auth_token_hash, public_identity, capabilities, last_seen_at, enrolled_at, revoked_at, created_at, updated_at
                 FROM enrolled_agents WHERE org_id = $1 AND id = $2",
                &[&org_id, &agent_id],
            )
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        row.map(|r| {
            let status_str: String = r.get(5);
            let status = AgentStatus::parse(&status_str).map_err(StoreError::Database)?;
            Ok(EnrolledAgent {
                id: r.get(0),
                org_id: r.get(1),
                machine_id: r.get(2),
                hostname: r.get(3),
                agent_version: r.get(4),
                status,
                auth_token_hash: r.get(6),
                public_identity: r.get(7),
                capabilities: r.get(8),
                last_seen_at: r.get(9),
                enrolled_at: r.get(10),
                revoked_at: r.get(11),
                created_at: r.get(12),
                updated_at: r.get(13),
            })
        })
        .transpose()
    }

    async fn get_agent_by_auth_hash(
        &self,
        auth_token_hash: &str,
    ) -> Result<Option<EnrolledAgent>, StoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let row = client
            .query_opt(
                "SELECT id, org_id, machine_id, hostname, agent_version, status, auth_token_hash, public_identity, capabilities, last_seen_at, enrolled_at, revoked_at, created_at, updated_at
                 FROM enrolled_agents WHERE auth_token_hash = $1",
                &[&auth_token_hash],
            )
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        row.map(|r| {
            let status_str: String = r.get(5);
            let status = AgentStatus::parse(&status_str).map_err(StoreError::Database)?;
            Ok(EnrolledAgent {
                id: r.get(0),
                org_id: r.get(1),
                machine_id: r.get(2),
                hostname: r.get(3),
                agent_version: r.get(4),
                status,
                auth_token_hash: r.get(6),
                public_identity: r.get(7),
                capabilities: r.get(8),
                last_seen_at: r.get(9),
                enrolled_at: r.get(10),
                revoked_at: r.get(11),
                created_at: r.get(12),
                updated_at: r.get(13),
            })
        })
        .transpose()
    }

    async fn list_agents(&self, org_id: Uuid) -> Result<Vec<EnrolledAgent>, StoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let rows = client
            .query(
                "SELECT id, org_id, machine_id, hostname, agent_version, status, auth_token_hash, public_identity, capabilities, last_seen_at, enrolled_at, revoked_at, created_at, updated_at
                 FROM enrolled_agents WHERE org_id = $1 ORDER BY enrolled_at DESC",
                &[&org_id],
            )
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let mut agents = Vec::with_capacity(rows.len());
        for r in rows {
            let status_str: String = r.get(5);
            let status = AgentStatus::parse(&status_str).map_err(StoreError::Database)?;
            agents.push(EnrolledAgent {
                id: r.get(0),
                org_id: r.get(1),
                machine_id: r.get(2),
                hostname: r.get(3),
                agent_version: r.get(4),
                status,
                auth_token_hash: r.get(6),
                public_identity: r.get(7),
                capabilities: r.get(8),
                last_seen_at: r.get(9),
                enrolled_at: r.get(10),
                revoked_at: r.get(11),
                created_at: r.get(12),
                updated_at: r.get(13),
            });
        }
        Ok(agents)
    }

    async fn update_agent_status(
        &self,
        org_id: Uuid,
        agent_id: Uuid,
        status: AgentStatus,
    ) -> Result<(), StoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let rows = client
            .execute(
                "UPDATE enrolled_agents
                 SET status = $1,
                     revoked_at = CASE WHEN $1 = 'revoked' THEN CURRENT_TIMESTAMP ELSE revoked_at END,
                     updated_at = CURRENT_TIMESTAMP
                 WHERE org_id = $2 AND id = $3",
                &[&status.as_str(), &org_id, &agent_id],
            )
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        if rows == 0 {
            return Err(StoreError::NotFound(format!("Agent {agent_id} not found")));
        }

        Ok(())
    }

    async fn update_agent_heartbeat(
        &self,
        agent_id: Uuid,
        last_seen_at: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        client
            .execute(
                "UPDATE enrolled_agents
                 SET last_seen_at = $1,
                     updated_at = CURRENT_TIMESTAMP
                 WHERE id = $2",
                &[&last_seen_at, &agent_id],
            )
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        Ok(())
    }

    async fn rotate_agent_credential(
        &self,
        agent_id: Uuid,
        new_auth_hash: &str,
    ) -> Result<(), StoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let rows = client
            .execute(
                "UPDATE enrolled_agents
                 SET auth_token_hash = $1,
                     updated_at = CURRENT_TIMESTAMP
                 WHERE id = $2 AND status = 'active'",
                &[&new_auth_hash, &agent_id],
            )
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        if rows == 0 {
            return Err(StoreError::NotFound(format!(
                "Active agent {agent_id} not found for credential rotation"
            )));
        }

        Ok(())
    }

    async fn claim_next_pending_job(
        &self,
        agent_id: Uuid,
        org_id: Uuid,
        lease_duration_secs: i64,
    ) -> Result<Option<AssessmentJob>, StoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let expires_at = Utc::now() + Duration::seconds(lease_duration_secs);

        let row = client
            .query_opt(
                "UPDATE assessment_jobs
                 SET status = 'running',
                     assigned_agent_id = $1,
                     execution_source = 'agent',
                     started_at = COALESCE(started_at, CURRENT_TIMESTAMP),
                     lease_expires_at = $3
                 WHERE id = (
                     SELECT id FROM assessment_jobs
                     WHERE org_id = $2
                       AND (
                           status = 'pending'
                           OR (status = 'running' AND lease_expires_at IS NOT NULL AND lease_expires_at < CURRENT_TIMESTAMP)
                       )
                     ORDER BY created_at ASC
                     FOR UPDATE SKIP LOCKED
                     LIMIT 1
                 )
                 RETURNING id, org_id, asset_id, target, assessment_type, profile, status,
                           summary_json, error_message, started_at, completed_at, created_at,
                           assigned_agent_id, lease_expires_at, execution_source, rules_subset",
                &[&agent_id, &org_id, &expires_at],
            )
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        row.map(|r| {
            let status_str: String = r.get(6);
            let status = JobStatus::parse(&status_str).map_err(StoreError::Database)?;
            Ok(AssessmentJob {
                id: r.get(0),
                org_id: r.get(1),
                asset_id: r.get(2),
                target: r.get(3),
                assessment_type: r.get(4),
                profile: r.get(5),
                status,
                summary_json: r.get(7),
                error_message: r.get(8),
                started_at: r.get(9),
                completed_at: r.get(10),
                created_at: r.get(11),
                assigned_agent_id: r.get(12),
                lease_expires_at: r.get(13),
                execution_source: r.get(14),
                rules_subset: r.get(15),
            })
        })
        .transpose()
    }

    async fn renew_job_lease(
        &self,
        agent_id: Uuid,
        job_id: Uuid,
        lease_duration_secs: i64,
    ) -> Result<bool, StoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let expires_at = Utc::now() + Duration::seconds(lease_duration_secs);

        let modified = client
            .execute(
                "UPDATE assessment_jobs
                 SET lease_expires_at = $3
                 WHERE id = $1 AND assigned_agent_id = $2 AND status = 'running'",
                &[&job_id, &agent_id, &expires_at],
            )
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        Ok(modified > 0)
    }

    async fn complete_agent_job(
        &self,
        agent_id: Uuid,
        job_id: Uuid,
        org_id: Uuid,
        summary_json: Option<&str>,
        findings: &[NewFinding],
    ) -> Result<(), StoreError> {
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let tx = client
            .transaction()
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        // 1. Verify job is currently assigned to this agent and running
        let row = tx
            .query_opt(
                "SELECT id, status, assigned_agent_id, org_id
                 FROM assessment_jobs
                 WHERE id = $1 AND org_id = $2
                 FOR UPDATE",
                &[&job_id, &org_id],
            )
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let Some(job_row) = row else {
            return Err(StoreError::NotFound(format!("Job {job_id} not found")));
        };

        let current_status: String = job_row.get(1);
        let assigned_agent: Option<Uuid> = job_row.get(2);

        if assigned_agent != Some(agent_id) {
            return Err(StoreError::Unauthorized(format!(
                "Job {job_id} is not assigned to agent {agent_id}"
            )));
        }

        if current_status == "completed" {
            // Idempotent duplicate submission: acknowledge without duplicating
            return Ok(());
        }

        if current_status != "running" {
            return Err(StoreError::Conflict(format!(
                "Job {job_id} is in status '{current_status}', not 'running'"
            )));
        }

        // 2. Insert findings
        let now = Utc::now();
        for f in findings {
            let finding_id = Uuid::new_v4();
            tx.execute(
                "INSERT INTO assessment_findings (id, org_id, job_id, rule_id, severity, confidence, title, endpoint, evidence, remediation, created_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
                &[
                    &finding_id,
                    &org_id,
                    &job_id,
                    &f.rule_id,
                    &f.severity,
                    &f.confidence,
                    &f.title,
                    &f.endpoint,
                    &f.evidence,
                    &f.recommendation,
                    &now,
                ],
            )
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;
        }

        // 3. Mark job completed
        tx.execute(
            "UPDATE assessment_jobs
             SET status = 'completed',
                 summary_json = $1,
                 completed_at = $2,
                 lease_expires_at = NULL
             WHERE id = $3",
            &[&summary_json, &now, &job_id],
        )
        .await
        .map_err(|e| StoreError::Database(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        Ok(())
    }

    async fn fail_agent_job(
        &self,
        agent_id: Uuid,
        job_id: Uuid,
        org_id: Uuid,
        error_message: &str,
    ) -> Result<(), StoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let now = Utc::now();
        let rows = client
            .execute(
                "UPDATE assessment_jobs
                 SET status = 'failed',
                     error_message = $1,
                     completed_at = $2,
                     lease_expires_at = NULL
                 WHERE id = $3 AND org_id = $4 AND assigned_agent_id = $5 AND status = 'running'",
                &[&error_message, &now, &job_id, &org_id, &agent_id],
            )
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        if rows == 0 {
            return Err(StoreError::Conflict(format!(
                "Job {job_id} cannot be marked failed (not running or not assigned to agent {agent_id})"
            )));
        }

        Ok(())
    }
}
