//! PostgreSQL persistence backend for OpenAudit control plane.

use chrono::{DateTime, Duration, Utc};
use deadpool_postgres::{Config as PoolConfig, Pool, Runtime};
use tokio_postgres::NoTls;
use uuid::Uuid;

use super::models::{
    compute_finding_fingerprint, AgentEnrollmentToken, AgentStatus, AssessmentComparison,
    AssessmentFinding, AssessmentJob, AssessmentSchedule, Asset, EnrolledAgent, FindingStatus,
    FindingStatusHistory, JobStatus, ManagedFinding, NewFinding, Organization, ResolutionType,
    Role, SecurityPostureSummary, SeverityBreakdown, SeverityChange, StatusBreakdown, User,
};
use super::{ControlPlaneStore, StoreError};

const INITIAL_SCHEMA: &str = include_str!("../../migrations/001_initial_schema.sql");
const SCHEMA_MIGRATION_002: &str =
    include_str!("../../migrations/002_agent_enrollment_and_communication.sql");
const SCHEMA_MIGRATION_003: &str =
    include_str!("../../migrations/003_finding_lifecycle_and_posture.sql");

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

        let row_m3 = client
            .query_opt(
                "SELECT version FROM schema_migrations WHERE version = $1",
                &[&3i32],
            )
            .await
            .map_err(|e| StoreError::Database(format!("Failed to check migrations: {e}")))?;

        if row_m3.is_none() {
            tracing::info!(
                "Applying PostgreSQL migration 003_finding_lifecycle_and_posture.sql..."
            );
            client
                .batch_execute(SCHEMA_MIGRATION_003)
                .await
                .map_err(|e| {
                    StoreError::Database(format!("Migration 003 execution failed: {e}"))
                })?;

            client
                .execute(
                    "INSERT INTO schema_migrations (version) VALUES ($1)",
                    &[&3i32],
                )
                .await
                .map_err(|e| {
                    StoreError::Database(format!("Failed to record migration 003: {e}"))
                })?;
            tracing::info!("PostgreSQL migration 003 applied successfully.");
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
            rules_evaluated: None,
            engine_version: "0.1.0-alpha.0".to_string(),
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
                "SELECT id, org_id, asset_id, target, assessment_type, profile, status, summary_json, error_message, started_at, completed_at, created_at, assigned_agent_id, lease_expires_at, execution_source, rules_subset, rules_evaluated, engine_version
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
                rules_evaluated: r.get(16),
                engine_version: r
                    .get::<_, Option<String>>(17)
                    .unwrap_or_else(|| "0.1.0-alpha.0".to_string()),
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
                "SELECT id, org_id, asset_id, target, assessment_type, profile, status, summary_json, error_message, started_at, completed_at, created_at, assigned_agent_id, lease_expires_at, execution_source, rules_subset, rules_evaluated, engine_version
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
                rules_evaluated: r.get(16),
                engine_version: r
                    .get::<_, Option<String>>(17)
                    .unwrap_or_else(|| "0.1.0-alpha.0".to_string()),
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
                        "SELECT id, org_id, job_id, rule_id, severity, confidence, title, endpoint, evidence, remediation, created_at, fingerprint, managed_finding_id
                         FROM assessment_findings WHERE org_id = $1 AND job_id = $2 AND severity = $3 ORDER BY created_at DESC",
                        &[&org_id, &jid, &sev],
                    )
                    .await
            }
            (Some(jid), None) => {
                client
                    .query(
                        "SELECT id, org_id, job_id, rule_id, severity, confidence, title, endpoint, evidence, remediation, created_at, fingerprint, managed_finding_id
                         FROM assessment_findings WHERE org_id = $1 AND job_id = $2 ORDER BY created_at DESC",
                        &[&org_id, &jid],
                    )
                    .await
            }
            (None, Some(sev)) => {
                client
                    .query(
                        "SELECT id, org_id, job_id, rule_id, severity, confidence, title, endpoint, evidence, remediation, created_at, fingerprint, managed_finding_id
                         FROM assessment_findings WHERE org_id = $1 AND severity = $2 ORDER BY created_at DESC",
                        &[&org_id, &sev],
                    )
                    .await
            }
            (None, None) => {
                client
                    .query(
                        "SELECT id, org_id, job_id, rule_id, severity, confidence, title, endpoint, evidence, remediation, created_at, fingerprint, managed_finding_id
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
                fingerprint: r.get(11),
                managed_finding_id: r.get(12),
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
                 FROM enrolled_agents
                 WHERE auth_token_hash = $1 OR previous_auth_token_hash = $1
                 ORDER BY CASE WHEN auth_token_hash = $1 THEN 0 ELSE 1 END
                 LIMIT 1",
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
                     previous_auth_token_hash = NULL,
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
                 SET previous_auth_token_hash = auth_token_hash,
                     auth_token_hash = $1,
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
                           assigned_agent_id, lease_expires_at, execution_source, rules_subset,
                           rules_evaluated, engine_version",
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
                rules_evaluated: r.get(16),
                engine_version: r
                    .get::<_, Option<String>>(17)
                    .unwrap_or_else(|| "0.1.0-alpha.0".to_string()),
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

    // --- Finding Lifecycle, Remediation & Posture (M7) ---
    async fn record_job_findings_and_reconcile_lifecycle(
        &self,
        org_id: Uuid,
        job_id: Uuid,
        findings: &[NewFinding],
        rules_evaluated: &[String],
    ) -> Result<Vec<AssessmentFinding>, StoreError> {
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let tx = client
            .transaction()
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        // 1. Fetch job to know asset_id, target, and domain
        let job_row = tx
            .query_opt(
                "SELECT asset_id, target, assessment_type FROM assessment_jobs WHERE org_id = $1 AND id = $2",
                &[&org_id, &job_id],
            )
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let Some(row) = job_row else {
            return Err(StoreError::NotFound(format!("Job '{job_id}' not found")));
        };

        let asset_id: Option<Uuid> = row.get(0);
        let target: String = row.get(1);
        let assessment_type: String = row.get(2);

        let target_or_asset = asset_id.map_or_else(|| target.clone(), |u| u.to_string());
        let domain = assessment_type.clone();
        let now = Utc::now();

        // 2. Update job's rules_evaluated and engine_version
        let rules_eval_json = serde_json::to_string(rules_evaluated)
            .map_err(|e| StoreError::Database(format!("JSON serialize error: {e}")))?;
        tx.execute(
            "UPDATE assessment_jobs SET rules_evaluated = $1, engine_version = $2 WHERE id = $3 AND org_id = $4",
            &[&rules_eval_json, &"0.1.0-alpha.0", &job_id, &org_id],
        )
        .await
        .map_err(|e| StoreError::Database(e.to_string()))?;

        // 3. Insert/update findings & managed findings
        let mut created_findings = Vec::with_capacity(findings.len());
        let mut observed_fps = std::collections::HashSet::new();

        for f in findings {
            let fp = compute_finding_fingerprint(
                org_id,
                &target_or_asset,
                &domain,
                &f.rule_id,
                &f.endpoint,
            );
            observed_fps.insert(fp.clone());

            let existing = tx
                .query_opt(
                    "SELECT id, status FROM managed_findings WHERE org_id = $1 AND fingerprint = $2",
                    &[&org_id, &fp],
                )
                .await
                .map_err(|e| StoreError::Database(e.to_string()))?;

            let managed_id = if let Some(m_row) = existing {
                let m_id: Uuid = m_row.get(0);
                let status_str: String = m_row.get(1);
                let old_status = FindingStatus::parse(&status_str).map_err(StoreError::Database)?;

                if old_status == FindingStatus::Resolved {
                    // Reopen the finding
                    tx.execute(
                        "UPDATE managed_findings
                         SET status = 'reopened', resolution_type = NULL, last_observed_at = $1, last_job_id = $2,
                             occurrence_count = occurrence_count + 1, severity = $3, confidence = $4, title = $5, updated_at = $1
                         WHERE id = $6",
                        &[&now, &job_id, &f.severity, &f.confidence, &f.title, &m_id],
                    )
                    .await
                    .map_err(|e| StoreError::Database(e.to_string()))?;

                    let hist_id = Uuid::new_v4();
                    tx.execute(
                        "INSERT INTO finding_status_history (id, finding_id, old_status, new_status, resolution_type, changed_by_user_id, job_id, comment, created_at)
                         VALUES ($1, $2, 'resolved', 'reopened', NULL, NULL, $3, 'Reopened: observed in subsequent assessment', $4)",
                        &[&hist_id, &m_id, &job_id, &now],
                    )
                    .await
                    .map_err(|e| StoreError::Database(e.to_string()))?;
                } else {
                    tx.execute(
                        "UPDATE managed_findings
                         SET last_observed_at = $1, last_job_id = $2, occurrence_count = occurrence_count + 1,
                             severity = $3, confidence = $4, title = $5, updated_at = $1
                         WHERE id = $6",
                        &[&now, &job_id, &f.severity, &f.confidence, &f.title, &m_id],
                    )
                    .await
                    .map_err(|e| StoreError::Database(e.to_string()))?;
                }
                m_id
            } else {
                let m_id = Uuid::new_v4();
                tx.execute(
                    "INSERT INTO managed_findings (
                        id, org_id, asset_id, fingerprint, rule_id, domain, endpoint, title, severity, confidence,
                        status, resolution_type, first_observed_at, last_observed_at, first_job_id, last_job_id,
                        occurrence_count, assigned_owner, due_date, remediation_notes, created_at, updated_at
                    ) VALUES (
                        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                        'open', NULL, $11, $11, $12, $12,
                        1, NULL, NULL, NULL, $11, $11
                    )",
                    &[
                        &m_id,
                        &org_id,
                        &asset_id,
                        &fp,
                        &f.rule_id,
                        &domain,
                        &f.endpoint,
                        &f.title,
                        &f.severity,
                        &f.confidence,
                        &now,
                        &job_id,
                    ],
                )
                .await
                .map_err(|e| StoreError::Database(e.to_string()))?;

                let hist_id = Uuid::new_v4();
                tx.execute(
                    "INSERT INTO finding_status_history (id, finding_id, old_status, new_status, resolution_type, changed_by_user_id, job_id, comment, created_at)
                     VALUES ($1, $2, 'open', 'open', NULL, NULL, $3, 'Initial discovery', $4)",
                    &[&hist_id, &m_id, &job_id, &now],
                )
                .await
                .map_err(|e| StoreError::Database(e.to_string()))?;

                m_id
            };

            let finding_id = Uuid::new_v4();
            tx.execute(
                "INSERT INTO assessment_findings (
                    id, org_id, job_id, rule_id, severity, confidence, title, endpoint, evidence, remediation, created_at, fingerprint, managed_finding_id
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
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
                    &fp,
                    &managed_id,
                ],
            )
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

            created_findings.push(AssessmentFinding {
                id: finding_id,
                org_id,
                job_id,
                rule_id: f.rule_id.clone(),
                severity: f.severity.clone(),
                confidence: f.confidence.clone(),
                title: f.title.clone(),
                endpoint: f.endpoint.clone(),
                evidence: f.evidence.clone(),
                recommendation: f.recommendation.clone(),
                created_at: now,
                fingerprint: Some(fp),
                managed_finding_id: Some(managed_id),
            });
        }

        // 4. Reconcile missing findings for verified remediation:
        let active_rows = tx
            .query(
                "SELECT id, fingerprint, rule_id, status FROM managed_findings
                 WHERE org_id = $1 AND domain = $2
                   AND (
                       (asset_id IS NOT NULL AND asset_id = $3)
                       OR (asset_id IS NULL AND $3 IS NULL)
                   )
                   AND status IN ('open', 'acknowledged', 'in_progress', 'reopened')",
                &[&org_id, &domain, &asset_id],
            )
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        for r in active_rows {
            let m_id: Uuid = r.get(0);
            let fp: String = r.get(1);
            let r_id: String = r.get(2);
            let status_str: String = r.get(3);

            if rules_evaluated.iter().any(|re| re == &r_id) && !observed_fps.contains(&fp) {
                tx.execute(
                    "UPDATE managed_findings
                     SET status = 'resolved', resolution_type = 'verified_remediated', updated_at = $1
                     WHERE id = $2",
                    &[&now, &m_id],
                )
                .await
                .map_err(|e| StoreError::Database(e.to_string()))?;

                let hist_id = Uuid::new_v4();
                tx.execute(
                    "INSERT INTO finding_status_history (id, finding_id, old_status, new_status, resolution_type, changed_by_user_id, job_id, comment, created_at)
                     VALUES ($1, $2, $3, 'resolved', 'verified_remediated', NULL, $4, 'Verified remediated: rule was evaluated and finding was not observed', $5)",
                    &[&hist_id, &m_id, &status_str, &job_id, &now],
                )
                .await
                .map_err(|e| StoreError::Database(e.to_string()))?;
            }
        }

        tx.commit()
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        Ok(created_findings)
    }

    async fn get_managed_finding(
        &self,
        org_id: Uuid,
        finding_id: Uuid,
    ) -> Result<Option<ManagedFinding>, StoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let row = client
            .query_opt(
                "SELECT id, org_id, asset_id, fingerprint, rule_id, domain, endpoint, title,
                        severity, confidence, status, resolution_type, first_observed_at,
                        last_observed_at, first_job_id, last_job_id, occurrence_count,
                        assigned_owner, due_date, remediation_notes, created_at, updated_at
                 FROM managed_findings WHERE org_id = $1 AND id = $2",
                &[&org_id, &finding_id],
            )
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let Some(r) = row else {
            return Ok(None);
        };

        let status_str: String = r.get(10);
        let status = FindingStatus::parse(&status_str).map_err(StoreError::Database)?;
        let res_ty_str: Option<String> = r.get(11);
        let resolution_type = res_ty_str
            .as_deref()
            .map(ResolutionType::parse)
            .transpose()
            .map_err(StoreError::Database)?;

        Ok(Some(ManagedFinding {
            id: r.get(0),
            org_id: r.get(1),
            asset_id: r.get(2),
            fingerprint: r.get(3),
            rule_id: r.get(4),
            domain: r.get(5),
            endpoint: r.get(6),
            title: r.get(7),
            severity: r.get(8),
            confidence: r.get(9),
            status,
            resolution_type,
            first_observed_at: r.get(12),
            last_observed_at: r.get(13),
            first_job_id: r.get(14),
            last_job_id: r.get(15),
            occurrence_count: r.get(16),
            assigned_owner: r.get(17),
            due_date: r.get(18),
            remediation_notes: r.get(19),
            created_at: r.get(20),
            updated_at: r.get(21),
        }))
    }

    async fn list_managed_findings(
        &self,
        org_id: Uuid,
        asset_id: Option<Uuid>,
        status: Option<FindingStatus>,
        severity: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<(Vec<ManagedFinding>, usize), StoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let status_str = status.map(|s| s.as_str().to_string());
        let sev_str = severity.map(str::to_lowercase);
        let limit_i64 = limit as i64;
        let offset_i64 = offset as i64;

        let count_row = client
            .query_one(
                "SELECT COUNT(*) FROM managed_findings
                 WHERE org_id = $1
                   AND ($2::uuid IS NULL OR asset_id = $2)
                   AND ($3::varchar IS NULL OR status = $3)
                   AND ($4::varchar IS NULL OR LOWER(severity) = $4)",
                &[&org_id, &asset_id, &status_str, &sev_str],
            )
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let total_count: i64 = count_row.get(0);

        let rows = client
            .query(
                "SELECT id, org_id, asset_id, fingerprint, rule_id, domain, endpoint, title,
                        severity, confidence, status, resolution_type, first_observed_at,
                        last_observed_at, first_job_id, last_job_id, occurrence_count,
                        assigned_owner, due_date, remediation_notes, created_at, updated_at
                 FROM managed_findings
                 WHERE org_id = $1
                   AND ($2::uuid IS NULL OR asset_id = $2)
                   AND ($3::varchar IS NULL OR status = $3)
                   AND ($4::varchar IS NULL OR LOWER(severity) = $4)
                 ORDER BY last_observed_at DESC, created_at DESC
                 LIMIT $5 OFFSET $6",
                &[
                    &org_id,
                    &asset_id,
                    &status_str,
                    &sev_str,
                    &limit_i64,
                    &offset_i64,
                ],
            )
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let mut findings = Vec::with_capacity(rows.len());
        for r in rows {
            let status_parsed_str: String = r.get(10);
            let status_val =
                FindingStatus::parse(&status_parsed_str).map_err(StoreError::Database)?;
            let res_ty_str: Option<String> = r.get(11);
            let resolution_type = res_ty_str
                .as_deref()
                .map(ResolutionType::parse)
                .transpose()
                .map_err(StoreError::Database)?;

            findings.push(ManagedFinding {
                id: r.get(0),
                org_id: r.get(1),
                asset_id: r.get(2),
                fingerprint: r.get(3),
                rule_id: r.get(4),
                domain: r.get(5),
                endpoint: r.get(6),
                title: r.get(7),
                severity: r.get(8),
                confidence: r.get(9),
                status: status_val,
                resolution_type,
                first_observed_at: r.get(12),
                last_observed_at: r.get(13),
                first_job_id: r.get(14),
                last_job_id: r.get(15),
                occurrence_count: r.get(16),
                assigned_owner: r.get(17),
                due_date: r.get(18),
                remediation_notes: r.get(19),
                created_at: r.get(20),
                updated_at: r.get(21),
            });
        }

        Ok((findings, total_count as usize))
    }

    async fn update_managed_finding_status(
        &self,
        org_id: Uuid,
        finding_id: Uuid,
        user_id: Option<Uuid>,
        new_status: FindingStatus,
        resolution_type: Option<ResolutionType>,
        comment: Option<&str>,
    ) -> Result<ManagedFinding, StoreError> {
        let existing = self
            .get_managed_finding(org_id, finding_id)
            .await?
            .ok_or_else(|| {
                StoreError::NotFound(format!("Managed finding '{finding_id}' not found"))
            })?;

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
        let res_str = resolution_type.map(ResolutionType::as_str);

        tx.execute(
            "UPDATE managed_findings
             SET status = $1, resolution_type = $2, updated_at = $3
             WHERE id = $4 AND org_id = $5",
            &[&new_status.as_str(), &res_str, &now, &finding_id, &org_id],
        )
        .await
        .map_err(|e| StoreError::Database(e.to_string()))?;

        let hist_id = Uuid::new_v4();
        tx.execute(
            "INSERT INTO finding_status_history (
                id, finding_id, old_status, new_status, resolution_type, changed_by_user_id, job_id, comment, created_at
            ) VALUES ($1, $2, $3, $4, $5, $6, NULL, $7, $8)",
            &[
                &hist_id,
                &finding_id,
                &existing.status.as_str(),
                &new_status.as_str(),
                &res_str,
                &user_id,
                &comment,
                &now,
            ],
        )
        .await
        .map_err(|e| StoreError::Database(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let updated = self
            .get_managed_finding(org_id, finding_id)
            .await?
            .ok_or_else(|| {
                StoreError::NotFound(format!("Managed finding '{finding_id}' not found"))
            })?;

        Ok(updated)
    }

    async fn assign_managed_finding_owner(
        &self,
        org_id: Uuid,
        finding_id: Uuid,
        assigned_owner: Option<&str>,
        due_date: Option<DateTime<Utc>>,
        remediation_notes: Option<&str>,
    ) -> Result<ManagedFinding, StoreError> {
        let _existing = self
            .get_managed_finding(org_id, finding_id)
            .await?
            .ok_or_else(|| {
                StoreError::NotFound(format!("Managed finding '{finding_id}' not found"))
            })?;

        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let now = Utc::now();
        client
            .execute(
                "UPDATE managed_findings
                 SET assigned_owner = $1, due_date = $2, remediation_notes = $3, updated_at = $4
                 WHERE id = $5 AND org_id = $6",
                &[
                    &assigned_owner,
                    &due_date,
                    &remediation_notes,
                    &now,
                    &finding_id,
                    &org_id,
                ],
            )
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let updated = self
            .get_managed_finding(org_id, finding_id)
            .await?
            .ok_or_else(|| {
                StoreError::NotFound(format!("Managed finding '{finding_id}' not found"))
            })?;

        Ok(updated)
    }

    async fn get_finding_status_history(
        &self,
        org_id: Uuid,
        finding_id: Uuid,
    ) -> Result<Vec<FindingStatusHistory>, StoreError> {
        let _finding = self
            .get_managed_finding(org_id, finding_id)
            .await?
            .ok_or_else(|| {
                StoreError::NotFound(format!("Managed finding '{finding_id}' not found"))
            })?;

        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let rows = client
            .query(
                "SELECT id, finding_id, old_status, new_status, resolution_type, changed_by_user_id, job_id, comment, created_at
                 FROM finding_status_history WHERE finding_id = $1 ORDER BY created_at ASC",
                &[&finding_id],
            )
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let mut history = Vec::with_capacity(rows.len());
        for r in rows {
            let old_st: String = r.get(2);
            let new_st: String = r.get(3);
            let res_ty: Option<String> = r.get(4);

            history.push(FindingStatusHistory {
                id: r.get(0),
                finding_id: r.get(1),
                old_status: FindingStatus::parse(&old_st).map_err(StoreError::Database)?,
                new_status: FindingStatus::parse(&new_st).map_err(StoreError::Database)?,
                resolution_type: res_ty
                    .as_deref()
                    .map(ResolutionType::parse)
                    .transpose()
                    .map_err(StoreError::Database)?,
                changed_by_user_id: r.get(5),
                job_id: r.get(6),
                comment: r.get(7),
                created_at: r.get(8),
            });
        }

        Ok(history)
    }

    async fn compare_assessments(
        &self,
        org_id: Uuid,
        base_job_id: Uuid,
        target_job_id: Uuid,
    ) -> Result<AssessmentComparison, StoreError> {
        let base_job = self
            .get_job(org_id, base_job_id)
            .await?
            .ok_or_else(|| StoreError::NotFound(format!("Base job '{base_job_id}' not found")))?;

        let target_job = self.get_job(org_id, target_job_id).await?.ok_or_else(|| {
            StoreError::NotFound(format!("Target job '{target_job_id}' not found"))
        })?;

        let base_rules_evaluated: Vec<String> = base_job
            .rules_evaluated
            .as_deref()
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or_default();

        let target_rules_evaluated: Vec<String> = target_job
            .rules_evaluated
            .as_deref()
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or_default();

        let mut rules_added = Vec::new();
        for r in &target_rules_evaluated {
            if !base_rules_evaluated.contains(r) {
                rules_added.push(r.clone());
            }
        }

        let mut rules_removed = Vec::new();
        for r in &base_rules_evaluated {
            if !target_rules_evaluated.contains(r) {
                rules_removed.push(r.clone());
            }
        }

        let coverage_ratio = if base_rules_evaluated.is_empty() {
            1.0
        } else {
            let common_rules = base_rules_evaluated
                .iter()
                .filter(|r| target_rules_evaluated.contains(r))
                .count();
            common_rules as f64 / base_rules_evaluated.len() as f64
        };

        let coverage_notes = if coverage_ratio >= 1.0 {
            "Full rule coverage verified relative to base assessment.".to_string()
        } else {
            format!(
                "Coverage dropped to {:.1}%: {} rule(s) evaluated in base were omitted in target assessment.",
                coverage_ratio * 100.0,
                rules_removed.len()
            )
        };

        let base_findings = self.list_findings(org_id, Some(base_job_id), None).await?;
        let target_findings = self
            .list_findings(org_id, Some(target_job_id), None)
            .await?;

        let base_map: std::collections::HashMap<String, &AssessmentFinding> = base_findings
            .iter()
            .filter_map(|f| f.fingerprint.as_ref().map(|fp| (fp.clone(), f)))
            .collect();

        let target_map: std::collections::HashMap<String, &AssessmentFinding> = target_findings
            .iter()
            .filter_map(|f| f.fingerprint.as_ref().map(|fp| (fp.clone(), f)))
            .collect();

        let mut new_findings = Vec::new();
        let mut reopened_findings = Vec::new();
        let mut persistent_findings = Vec::new();
        let mut severity_changes = Vec::new();

        for tf in &target_findings {
            let Some(ref tf_fp) = tf.fingerprint else {
                new_findings.push(tf.clone());
                continue;
            };

            if let Some(bf) = base_map.get(tf_fp) {
                persistent_findings.push(tf.clone());
                if bf.severity != tf.severity {
                    severity_changes.push(SeverityChange {
                        fingerprint: tf_fp.clone(),
                        rule_id: tf.rule_id.clone(),
                        endpoint: tf.endpoint.clone(),
                        base_severity: bf.severity.clone(),
                        target_severity: tf.severity.clone(),
                    });
                }
            } else {
                let is_reopened = if let Some(m_id) = tf.managed_finding_id {
                    if let Ok(Some(mf)) = self.get_managed_finding(org_id, m_id).await {
                        mf.status == FindingStatus::Reopened || mf.occurrence_count > 1
                    } else {
                        false
                    }
                } else {
                    false
                };

                if is_reopened {
                    reopened_findings.push(tf.clone());
                } else {
                    new_findings.push(tf.clone());
                }
            }
        }

        let mut resolved_findings = Vec::new();
        let mut unverified_omissions = Vec::new();

        for bf in &base_findings {
            let Some(ref bf_fp) = bf.fingerprint else {
                continue;
            };

            if !target_map.contains_key(bf_fp) {
                if target_rules_evaluated.contains(&bf.rule_id) {
                    if let Some(m_id) = bf.managed_finding_id {
                        if let Ok(Some(mf)) = self.get_managed_finding(org_id, m_id).await {
                            resolved_findings.push(mf);
                        }
                    }
                } else {
                    unverified_omissions.push(bf.clone());
                }
            }
        }

        Ok(AssessmentComparison {
            base_job_id,
            target_job_id,
            asset_id: target_job.asset_id,
            target: target_job.target,
            base_created_at: base_job.created_at,
            target_created_at: target_job.created_at,
            base_rules_evaluated,
            target_rules_evaluated,
            rules_added,
            rules_removed,
            coverage_ratio,
            coverage_notes,
            new_findings,
            persistent_findings,
            resolved_findings,
            unverified_omissions,
            reopened_findings,
            severity_changes,
        })
    }

    async fn get_security_posture_summary(
        &self,
        org_id: Uuid,
        asset_id: Option<Uuid>,
    ) -> Result<SecurityPostureSummary, StoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        // Total assets
        let count_row = client
            .query_one(
                "SELECT COUNT(*) FROM assets WHERE org_id = $1 AND ($2::uuid IS NULL OR id = $2)",
                &[&org_id, &asset_id],
            )
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;
        let total_assets: i64 = count_row.get(0);

        // Assessed assets
        let assessed_row = client
            .query_one(
                "SELECT COUNT(DISTINCT asset_id) FROM assessment_jobs
                 WHERE org_id = $1 AND ($2::uuid IS NULL OR asset_id = $2) AND status = 'completed'",
                &[&org_id, &asset_id],
            )
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;
        let assessed_assets: i64 = assessed_row.get(0);

        // Stale assets: completed > 30 days ago or created > 30 days ago with 0 completed assessments
        let thirty_days_ago = Utc::now() - Duration::days(30);
        let stale_row = client
            .query_one(
                "SELECT COUNT(*) FROM (
                    SELECT a.id
                    FROM assets a
                    LEFT JOIN assessment_jobs j ON j.asset_id = a.id AND j.status = 'completed'
                    WHERE a.org_id = $1 AND ($2::uuid IS NULL OR a.id = $2)
                    GROUP BY a.id
                    HAVING (MAX(j.completed_at) IS NOT NULL AND MAX(j.completed_at) < $3)
                        OR (MAX(j.completed_at) IS NULL AND a.created_at < $3)
                ) t",
                &[&org_id, &asset_id, &thirty_days_ago],
            )
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;
        let stale_assets: i64 = stale_row.get(0);

        // Managed findings counts
        let mut sev_breakdown = SeverityBreakdown::default();
        let mut status_breakdown = StatusBreakdown::default();
        let mut verified_remediations_count = 0;
        let mut manual_resolutions_count = 0;
        let mut accepted_risks_count = 0;
        let mut total_active_findings = 0;

        let rows = client
            .query(
                "SELECT severity, status, resolution_type FROM managed_findings
                 WHERE org_id = $1 AND ($2::uuid IS NULL OR asset_id = $2)",
                &[&org_id, &asset_id],
            )
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        for r in rows {
            let sev: String = r.get(0);
            let st_str: String = r.get(1);
            let res_ty: Option<String> = r.get(2);
            let status = FindingStatus::parse(&st_str).unwrap_or(FindingStatus::Open);

            match status {
                FindingStatus::Open => status_breakdown.open += 1,
                FindingStatus::Acknowledged => status_breakdown.acknowledged += 1,
                FindingStatus::InProgress => status_breakdown.in_progress += 1,
                FindingStatus::Resolved => status_breakdown.resolved += 1,
                FindingStatus::AcceptedRisk => status_breakdown.accepted_risk += 1,
                FindingStatus::Reopened => status_breakdown.reopened += 1,
            }

            if status != FindingStatus::Resolved && status != FindingStatus::AcceptedRisk {
                total_active_findings += 1;
                match sev.to_lowercase().as_str() {
                    "critical" => sev_breakdown.critical += 1,
                    "high" => sev_breakdown.high += 1,
                    "medium" => sev_breakdown.medium += 1,
                    "low" => sev_breakdown.low += 1,
                    _ => sev_breakdown.info += 1,
                }
            }

            if status == FindingStatus::AcceptedRisk {
                accepted_risks_count += 1;
            }

            if let Some(res) = res_ty {
                if res == "verified_remediated" {
                    verified_remediations_count += 1;
                } else if res == "manually_resolved" {
                    manual_resolutions_count += 1;
                }
            }
        }

        // Assessment job statistics
        let comp_row = client
            .query_one(
                "SELECT COUNT(*) FROM assessment_jobs WHERE org_id = $1 AND ($2::uuid IS NULL OR asset_id = $2) AND status = 'completed'",
                &[&org_id, &asset_id],
            )
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;
        let completed_count: i64 = comp_row.get(0);

        let fail_row = client
            .query_one(
                "SELECT COUNT(*) FROM assessment_jobs WHERE org_id = $1 AND ($2::uuid IS NULL OR asset_id = $2) AND status = 'failed'",
                &[&org_id, &asset_id],
            )
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;
        let failed_count: i64 = fail_row.get(0);

        Ok(SecurityPostureSummary {
            org_id,
            calculated_at: Utc::now(),
            total_assets: total_assets as usize,
            assessed_assets: assessed_assets as usize,
            stale_assets: stale_assets as usize,
            total_active_findings,
            findings_by_severity: sev_breakdown,
            findings_by_status: status_breakdown,
            verified_remediations_count,
            manual_resolutions_count,
            accepted_risks_count,
            total_assessments_completed: completed_count as usize,
            total_assessments_failed: failed_count as usize,
        })
    }

    async fn list_assessment_history(
        &self,
        org_id: Uuid,
        asset_id: Option<Uuid>,
        limit: usize,
        offset: usize,
    ) -> Result<(Vec<AssessmentJob>, usize), StoreError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let count_row = client
            .query_one(
                "SELECT COUNT(*) FROM assessment_jobs WHERE org_id = $1 AND ($2::uuid IS NULL OR asset_id = $2)",
                &[&org_id, &asset_id],
            )
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;
        let total_count: i64 = count_row.get(0);

        let limit_i64 = limit as i64;
        let offset_i64 = offset as i64;

        let rows = client
            .query(
                "SELECT id, org_id, asset_id, target, assessment_type, profile, status, summary_json, error_message, started_at, completed_at, created_at, assigned_agent_id, lease_expires_at, execution_source, rules_subset, rules_evaluated, engine_version
                 FROM assessment_jobs
                 WHERE org_id = $1 AND ($2::uuid IS NULL OR asset_id = $2)
                 ORDER BY created_at DESC
                 LIMIT $3 OFFSET $4",
                &[&org_id, &asset_id, &limit_i64, &offset_i64],
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
                rules_evaluated: r.get(16),
                engine_version: r
                    .get::<_, Option<String>>(17)
                    .unwrap_or_else(|| "0.1.0-alpha.0".to_string()),
            });
        }

        Ok((jobs, total_count as usize))
    }
}
