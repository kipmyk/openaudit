//! SQLite control-plane storage implementation for local self-hosting and deterministic testing.

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::sync::Mutex;
use uuid::Uuid;

use super::models::{
    AgentEnrollmentToken, AgentStatus, AssessmentFinding, AssessmentJob, AssessmentSchedule, Asset,
    EnrolledAgent, JobStatus, NewFinding, Organization, Role, User,
};
use super::{ControlPlaneStore, StoreError};

/// SQLite-backed store with automatic schema migrations.
pub struct SqliteControlPlaneStore {
    conn: Mutex<Connection>,
}

impl std::fmt::Debug for SqliteControlPlaneStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqliteControlPlaneStore")
            .finish_non_exhaustive()
    }
}

impl SqliteControlPlaneStore {
    /// Opens or creates a SQLite store at `path` and runs pending migrations.
    ///
    /// # Errors
    ///
    /// Returns an error if the database connection cannot be opened or migrated.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let conn = Connection::open(path)
            .map_err(|e| StoreError::Database(format!("failed to open sqlite database: {e}")))?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.migrate()?;
        Ok(store)
    }

    /// Creates an in-memory SQLite store for isolated unit and integration testing.
    ///
    /// # Errors
    ///
    /// Returns an error if the in-memory database fails to initialize.
    pub fn in_memory() -> Result<Self, StoreError> {
        let conn = Connection::open_in_memory()
            .map_err(|e| StoreError::Database(format!("failed to open in-memory sqlite: {e}")))?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.migrate()?;
        Ok(store)
    }

    /// Executes database schema migrations.
    fn migrate(&self) -> Result<(), StoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StoreError::Database(format!("lock poisoned: {e}")))?;

        conn.execute_batch(
            "
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS organizations (
                id TEXT PRIMARY KEY,
                slug TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                org_id TEXT NOT NULL,
                email TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                name TEXT NOT NULL,
                role TEXT NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(org_id, email),
                FOREIGN KEY(org_id) REFERENCES organizations(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS assets (
                id TEXT PRIMARY KEY,
                org_id TEXT NOT NULL,
                name TEXT NOT NULL,
                asset_type TEXT NOT NULL,
                target TEXT NOT NULL,
                criticality TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(org_id) REFERENCES organizations(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS assessment_jobs (
                id TEXT PRIMARY KEY,
                org_id TEXT NOT NULL,
                asset_id TEXT,
                target TEXT NOT NULL,
                assessment_type TEXT NOT NULL,
                profile TEXT NOT NULL,
                status TEXT NOT NULL,
                summary_json TEXT,
                error_message TEXT,
                started_at TEXT,
                completed_at TEXT,
                created_at TEXT NOT NULL,
                assigned_agent_id TEXT,
                lease_expires_at TEXT,
                execution_source TEXT NOT NULL DEFAULT 'server',
                rules_subset TEXT,
                FOREIGN KEY(org_id) REFERENCES organizations(id) ON DELETE CASCADE,
                FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE SET NULL,
                FOREIGN KEY(assigned_agent_id) REFERENCES enrolled_agents(id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS assessment_findings (
                id TEXT PRIMARY KEY,
                org_id TEXT NOT NULL,
                job_id TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence TEXT NOT NULL,
                title TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                evidence TEXT NOT NULL,
                remediation TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(org_id) REFERENCES organizations(id) ON DELETE CASCADE,
                FOREIGN KEY(job_id) REFERENCES assessment_jobs(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS assessment_schedules (
                id TEXT PRIMARY KEY,
                org_id TEXT NOT NULL,
                asset_id TEXT,
                name TEXT NOT NULL,
                cron_expression TEXT NOT NULL,
                target TEXT NOT NULL,
                assessment_type TEXT NOT NULL,
                profile TEXT NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1,
                last_run_at TEXT,
                next_run_at TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(org_id) REFERENCES organizations(id) ON DELETE CASCADE,
                FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE SET NULL
            );

            CREATE INDEX IF NOT EXISTS idx_users_org ON users(org_id);
            CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
            CREATE INDEX IF NOT EXISTS idx_assets_org_target ON assets(org_id, target);
            CREATE INDEX IF NOT EXISTS idx_jobs_org_status ON assessment_jobs(org_id, status);
            CREATE INDEX IF NOT EXISTS idx_findings_org_job ON assessment_findings(org_id, job_id);
            CREATE INDEX IF NOT EXISTS idx_schedules_org ON assessment_schedules(org_id, is_active);

            CREATE TABLE IF NOT EXISTS revoked_tokens (
                jti TEXT PRIMARY KEY,
                expires_at TEXT NOT NULL,
                revoked_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_revoked_tokens_exp ON revoked_tokens(expires_at);

            CREATE TABLE IF NOT EXISTS agent_enrollment_tokens (
                id TEXT PRIMARY KEY,
                org_id TEXT NOT NULL,
                token_secret TEXT NOT NULL,
                machine_id TEXT,
                challenge_nonce TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                used_at TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(org_id) REFERENCES organizations(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS enrolled_agents (
                id TEXT PRIMARY KEY,
                org_id TEXT NOT NULL,
                machine_id TEXT NOT NULL,
                hostname TEXT NOT NULL,
                agent_version TEXT NOT NULL,
                status TEXT NOT NULL,
                auth_token_hash TEXT NOT NULL,
                previous_auth_token_hash TEXT,
                public_identity TEXT NOT NULL,
                capabilities TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                enrolled_at TEXT NOT NULL,
                revoked_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(org_id, machine_id),
                FOREIGN KEY(org_id) REFERENCES organizations(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_agents_org_status ON enrolled_agents(org_id, status);
            CREATE INDEX IF NOT EXISTS idx_agents_auth_hash ON enrolled_agents(auth_token_hash);
            CREATE INDEX IF NOT EXISTS idx_agents_prev_auth_hash ON enrolled_agents(previous_auth_token_hash);
            CREATE INDEX IF NOT EXISTS idx_agent_tokens_lookup ON agent_enrollment_tokens(id, expires_at);
            ",
        )
        .map_err(|e| StoreError::Database(format!("schema migration failed: {e}")))?;

        // Ensure columns exist on pre-existing assessment_jobs tables
        let _ = conn.execute(
            "ALTER TABLE assessment_jobs ADD COLUMN assigned_agent_id TEXT",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE assessment_jobs ADD COLUMN lease_expires_at TEXT",
            [],
        );
        let _ = conn.execute("ALTER TABLE assessment_jobs ADD COLUMN execution_source TEXT NOT NULL DEFAULT 'server'", []);
        let _ = conn.execute(
            "ALTER TABLE assessment_jobs ADD COLUMN rules_subset TEXT",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE enrolled_agents ADD COLUMN previous_auth_token_hash TEXT",
            [],
        );

        Ok(())
    }
}

#[async_trait::async_trait]
impl ControlPlaneStore for SqliteControlPlaneStore {
    async fn is_healthy(&self) -> bool {
        self.conn
            .lock()
            .map(|c| c.query_row("SELECT 1", [], |_| Ok(())).is_ok())
            .unwrap_or(false)
    }

    async fn bootstrap_admin(
        &self,
        org_name: &str,
        org_slug: &str,
        admin_name: &str,
        admin_email: &str,
        password_hash: &str,
    ) -> Result<(Organization, User), StoreError> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let tx = conn
            .transaction()
            .map_err(|e| StoreError::Database(e.to_string()))?;

        // Atomic check: ensure no users exist anywhere in the system
        let user_count: i64 = tx
            .query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))
            .map_err(|e| StoreError::Database(e.to_string()))?;

        if user_count > 0 {
            return Err(StoreError::Conflict(
                "Control plane already bootstrapped with existing users".into(),
            ));
        }

        let org_exists: bool = tx
            .query_row(
                "SELECT 1 FROM organizations WHERE slug = ?1",
                params![org_slug],
                |_| Ok(()),
            )
            .optional()
            .map_err(|e| StoreError::Database(e.to_string()))?
            .is_some();

        if org_exists {
            return Err(StoreError::Conflict(format!(
                "Organization slug '{org_slug}' already exists"
            )));
        }

        let org_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let now = Utc::now();
        let now_str = now.to_rfc3339();

        tx.execute(
            "INSERT INTO organizations (id, slug, name, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![org_id.to_string(), org_slug, org_name, now_str, now_str],
        )
        .map_err(|e| StoreError::Database(e.to_string()))?;

        tx.execute(
            "INSERT INTO users (id, org_id, email, password_hash, name, role, is_active, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                user_id.to_string(),
                org_id.to_string(),
                admin_email,
                password_hash,
                admin_name,
                Role::Admin.as_str(),
                1,
                now_str,
                now_str,
            ],
        )
        .map_err(|e| StoreError::Database(e.to_string()))?;

        tx.commit()
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
        let conn = self
            .conn
            .lock()
            .map_err(|e| StoreError::Database(e.to_string()))?;
        let id = Uuid::new_v4();
        let now = Utc::now();
        let now_str = now.to_rfc3339();

        conn.execute(
            "INSERT INTO organizations (id, slug, name, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![id.to_string(), slug, name, now_str, now_str],
        )
        .map_err(|e| {
            if e.to_string().contains("UNIQUE constraint failed") {
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
        let conn = self
            .conn
            .lock()
            .map_err(|e| StoreError::Database(e.to_string()))?;
        let mut stmt = conn
            .prepare(
                "SELECT id, slug, name, created_at, updated_at FROM organizations WHERE id = ?1",
            )
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let res = stmt
            .query_row(params![id.to_string()], |row| {
                let id_str: String = row.get(0)?;
                let slug: String = row.get(1)?;
                let name: String = row.get(2)?;
                let created_str: String = row.get(3)?;
                let updated_str: String = row.get(4)?;
                Ok((id_str, slug, name, created_str, updated_str))
            })
            .optional()
            .map_err(|e| StoreError::Database(e.to_string()))?;

        match res {
            Some((id_str, slug, name, c_str, u_str)) => Ok(Some(Organization {
                id: Uuid::parse_str(&id_str).map_err(|e| StoreError::Database(e.to_string()))?,
                slug,
                name,
                created_at: DateTime::parse_from_rfc3339(&c_str)
                    .map(|d| d.with_timezone(&Utc))
                    .map_err(|e| StoreError::Database(e.to_string()))?,
                updated_at: DateTime::parse_from_rfc3339(&u_str)
                    .map(|d| d.with_timezone(&Utc))
                    .map_err(|e| StoreError::Database(e.to_string()))?,
            })),
            None => Ok(None),
        }
    }

    async fn get_organization_by_slug(
        &self,
        slug: &str,
    ) -> Result<Option<Organization>, StoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StoreError::Database(e.to_string()))?;
        let mut stmt = conn
            .prepare(
                "SELECT id, slug, name, created_at, updated_at FROM organizations WHERE slug = ?1",
            )
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let res = stmt
            .query_row(params![slug], |row| {
                let id_str: String = row.get(0)?;
                let slug: String = row.get(1)?;
                let name: String = row.get(2)?;
                let created_str: String = row.get(3)?;
                let updated_str: String = row.get(4)?;
                Ok((id_str, slug, name, created_str, updated_str))
            })
            .optional()
            .map_err(|e| StoreError::Database(e.to_string()))?;

        match res {
            Some((id_str, slug, name, c_str, u_str)) => Ok(Some(Organization {
                id: Uuid::parse_str(&id_str).map_err(|e| StoreError::Database(e.to_string()))?,
                slug,
                name,
                created_at: DateTime::parse_from_rfc3339(&c_str)
                    .map(|d| d.with_timezone(&Utc))
                    .map_err(|e| StoreError::Database(e.to_string()))?,
                updated_at: DateTime::parse_from_rfc3339(&u_str)
                    .map(|d| d.with_timezone(&Utc))
                    .map_err(|e| StoreError::Database(e.to_string()))?,
            })),
            None => Ok(None),
        }
    }

    async fn create_user(
        &self,
        org_id: Uuid,
        email: &str,
        password_hash: &str,
        name: &str,
        role: Role,
    ) -> Result<User, StoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StoreError::Database(e.to_string()))?;
        let id = Uuid::new_v4();
        let now = Utc::now();
        let now_str = now.to_rfc3339();

        conn.execute(
            "INSERT INTO users (id, org_id, email, password_hash, name, role, is_active, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, ?7, ?8)",
            params![
                id.to_string(),
                org_id.to_string(),
                email.to_lowercase(),
                password_hash,
                name,
                role.as_str(),
                now_str,
                now_str,
            ],
        )
        .map_err(|e| {
            if e.to_string().contains("UNIQUE constraint failed") {
                StoreError::Conflict(format!("User email '{email}' already exists in this organization"))
            } else {
                StoreError::Database(e.to_string())
            }
        })?;

        Ok(User {
            id,
            org_id,
            email: email.to_lowercase(),
            password_hash: password_hash.to_string(),
            name: name.to_string(),
            role,
            is_active: true,
            created_at: now,
            updated_at: now,
        })
    }

    async fn get_user_by_email(&self, email: &str) -> Result<Option<User>, StoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StoreError::Database(e.to_string()))?;
        let mut stmt = conn
            .prepare(
                "SELECT id, org_id, email, password_hash, name, role, is_active, created_at, updated_at
                 FROM users WHERE email = ?1",
            )
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let res = stmt
            .query_row(params![email.to_lowercase()], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)? != 0,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                ))
            })
            .optional()
            .map_err(|e| StoreError::Database(e.to_string()))?;

        match res {
            Some((id_str, org_str, email, p_hash, name, role_str, active, c_str, u_str)) => {
                let role = Role::parse(&role_str).map_err(StoreError::Database)?;
                Ok(Some(User {
                    id: Uuid::parse_str(&id_str)
                        .map_err(|e| StoreError::Database(e.to_string()))?,
                    org_id: Uuid::parse_str(&org_str)
                        .map_err(|e| StoreError::Database(e.to_string()))?,
                    email,
                    password_hash: p_hash,
                    name,
                    role,
                    is_active: active,
                    created_at: DateTime::parse_from_rfc3339(&c_str)
                        .map(|d| d.with_timezone(&Utc))
                        .map_err(|e| StoreError::Database(e.to_string()))?,
                    updated_at: DateTime::parse_from_rfc3339(&u_str)
                        .map(|d| d.with_timezone(&Utc))
                        .map_err(|e| StoreError::Database(e.to_string()))?,
                }))
            }
            None => Ok(None),
        }
    }

    async fn get_user_by_id(
        &self,
        org_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<User>, StoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StoreError::Database(e.to_string()))?;
        let mut stmt = conn
            .prepare(
                "SELECT id, org_id, email, password_hash, name, role, is_active, created_at, updated_at
                 FROM users WHERE org_id = ?1 AND id = ?2",
            )
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let res = stmt
            .query_row(params![org_id.to_string(), user_id.to_string()], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)? != 0,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                ))
            })
            .optional()
            .map_err(|e| StoreError::Database(e.to_string()))?;

        match res {
            Some((id_str, org_str, email, p_hash, name, role_str, active, c_str, u_str)) => {
                let role = Role::parse(&role_str).map_err(StoreError::Database)?;
                Ok(Some(User {
                    id: Uuid::parse_str(&id_str)
                        .map_err(|e| StoreError::Database(e.to_string()))?,
                    org_id: Uuid::parse_str(&org_str)
                        .map_err(|e| StoreError::Database(e.to_string()))?,
                    email,
                    password_hash: p_hash,
                    name,
                    role,
                    is_active: active,
                    created_at: DateTime::parse_from_rfc3339(&c_str)
                        .map(|d| d.with_timezone(&Utc))
                        .map_err(|e| StoreError::Database(e.to_string()))?,
                    updated_at: DateTime::parse_from_rfc3339(&u_str)
                        .map(|d| d.with_timezone(&Utc))
                        .map_err(|e| StoreError::Database(e.to_string()))?,
                }))
            }
            None => Ok(None),
        }
    }

    async fn list_users(&self, org_id: Uuid) -> Result<Vec<User>, StoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StoreError::Database(e.to_string()))?;
        let mut stmt = conn
            .prepare(
                "SELECT id, org_id, email, password_hash, name, role, is_active, created_at, updated_at
                 FROM users WHERE org_id = ?1 ORDER BY created_at ASC",
            )
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let rows = stmt
            .query_map(params![org_id.to_string()], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)? != 0,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                ))
            })
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let mut users = Vec::new();
        for r in rows {
            let (id_str, org_str, email, p_hash, name, role_str, active, c_str, u_str) =
                r.map_err(|e| StoreError::Database(e.to_string()))?;
            let role = Role::parse(&role_str).map_err(StoreError::Database)?;
            users.push(User {
                id: Uuid::parse_str(&id_str).map_err(|e| StoreError::Database(e.to_string()))?,
                org_id: Uuid::parse_str(&org_str)
                    .map_err(|e| StoreError::Database(e.to_string()))?,
                email,
                password_hash: p_hash,
                name,
                role,
                is_active: active,
                created_at: DateTime::parse_from_rfc3339(&c_str)
                    .map(|d| d.with_timezone(&Utc))
                    .map_err(|e| StoreError::Database(e.to_string()))?,
                updated_at: DateTime::parse_from_rfc3339(&u_str)
                    .map(|d| d.with_timezone(&Utc))
                    .map_err(|e| StoreError::Database(e.to_string()))?,
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
        let conn = self
            .conn
            .lock()
            .map_err(|e| StoreError::Database(e.to_string()))?;
        let id = Uuid::new_v4();
        let now = Utc::now();
        let now_str = now.to_rfc3339();

        conn.execute(
            "INSERT INTO assets (id, org_id, name, asset_type, target, criticality, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                id.to_string(),
                org_id.to_string(),
                name,
                asset_type,
                target,
                criticality,
                now_str,
                now_str,
            ],
        )
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
        let conn = self
            .conn
            .lock()
            .map_err(|e| StoreError::Database(e.to_string()))?;
        let mut stmt = conn
            .prepare(
                "SELECT id, org_id, name, asset_type, target, criticality, created_at, updated_at
                 FROM assets WHERE org_id = ?1 AND id = ?2",
            )
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let res = stmt
            .query_row(params![org_id.to_string(), id.to_string()], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                ))
            })
            .optional()
            .map_err(|e| StoreError::Database(e.to_string()))?;

        match res {
            Some((id_str, org_str, name, a_type, target, crit, c_str, u_str)) => Ok(Some(Asset {
                id: Uuid::parse_str(&id_str).map_err(|e| StoreError::Database(e.to_string()))?,
                org_id: Uuid::parse_str(&org_str)
                    .map_err(|e| StoreError::Database(e.to_string()))?,
                name,
                asset_type: a_type,
                target,
                criticality: crit,
                created_at: DateTime::parse_from_rfc3339(&c_str)
                    .map(|d| d.with_timezone(&Utc))
                    .map_err(|e| StoreError::Database(e.to_string()))?,
                updated_at: DateTime::parse_from_rfc3339(&u_str)
                    .map(|d| d.with_timezone(&Utc))
                    .map_err(|e| StoreError::Database(e.to_string()))?,
            })),
            None => Ok(None),
        }
    }

    async fn list_assets(&self, org_id: Uuid) -> Result<Vec<Asset>, StoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StoreError::Database(e.to_string()))?;
        let mut stmt = conn
            .prepare(
                "SELECT id, org_id, name, asset_type, target, criticality, created_at, updated_at
                 FROM assets WHERE org_id = ?1 ORDER BY created_at DESC",
            )
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let rows = stmt
            .query_map(params![org_id.to_string()], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                ))
            })
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let mut assets = Vec::new();
        for r in rows {
            let (id_str, org_str, name, a_type, target, crit, c_str, u_str) =
                r.map_err(|e| StoreError::Database(e.to_string()))?;
            assets.push(Asset {
                id: Uuid::parse_str(&id_str).map_err(|e| StoreError::Database(e.to_string()))?,
                org_id: Uuid::parse_str(&org_str)
                    .map_err(|e| StoreError::Database(e.to_string()))?,
                name,
                asset_type: a_type,
                target,
                criticality: crit,
                created_at: DateTime::parse_from_rfc3339(&c_str)
                    .map(|d| d.with_timezone(&Utc))
                    .map_err(|e| StoreError::Database(e.to_string()))?,
                updated_at: DateTime::parse_from_rfc3339(&u_str)
                    .map(|d| d.with_timezone(&Utc))
                    .map_err(|e| StoreError::Database(e.to_string()))?,
            });
        }
        Ok(assets)
    }

    async fn delete_asset(&self, org_id: Uuid, id: Uuid) -> Result<bool, StoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StoreError::Database(e.to_string()))?;
        let count = conn
            .execute(
                "DELETE FROM assets WHERE org_id = ?1 AND id = ?2",
                params![org_id.to_string(), id.to_string()],
            )
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
        let conn = self
            .conn
            .lock()
            .map_err(|e| StoreError::Database(e.to_string()))?;
        let id = Uuid::new_v4();
        let now = Utc::now();
        let now_str = now.to_rfc3339();

        conn.execute(
            "INSERT INTO assessment_jobs
             (id, org_id, asset_id, target, assessment_type, profile, status, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                id.to_string(),
                org_id.to_string(),
                asset_id.map(|u| u.to_string()),
                target,
                assessment_type,
                profile,
                JobStatus::Pending.as_str(),
                now_str,
            ],
        )
        .map_err(|e| StoreError::Database(e.to_string()))?;

        Ok(AssessmentJob {
            id,
            org_id,
            asset_id,
            target: target.to_string(),
            assessment_type: assessment_type.to_string(),
            profile: profile.to_string(),
            status: JobStatus::Pending,
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
        let conn = self
            .conn
            .lock()
            .map_err(|e| StoreError::Database(e.to_string()))?;
        let mut stmt = conn
            .prepare(
                "SELECT id, org_id, asset_id, target, assessment_type, profile, status,
                        summary_json, error_message, started_at, completed_at, created_at,
                        assigned_agent_id, lease_expires_at, execution_source, rules_subset
                 FROM assessment_jobs WHERE org_id = ?1 AND id = ?2",
            )
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let res = stmt
            .query_row(params![org_id.to_string(), id.to_string()], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, Option<String>>(9)?,
                    row.get::<_, Option<String>>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, Option<String>>(12)?,
                    row.get::<_, Option<String>>(13)?,
                    row.get::<_, Option<String>>(14)?,
                    row.get::<_, Option<String>>(15)?,
                ))
            })
            .optional()
            .map_err(|e| StoreError::Database(e.to_string()))?;

        match res {
            Some((
                id_str,
                org_str,
                asset_opt,
                target,
                a_type,
                prof,
                status_str,
                sum_opt,
                err_opt,
                start_opt,
                end_opt,
                created_str,
                agent_opt,
                lease_opt,
                source_opt,
                rules_opt,
            )) => {
                let status = JobStatus::parse(&status_str).map_err(StoreError::Database)?;
                Ok(Some(AssessmentJob {
                    id: Uuid::parse_str(&id_str)
                        .map_err(|e| StoreError::Database(e.to_string()))?,
                    org_id: Uuid::parse_str(&org_str)
                        .map_err(|e| StoreError::Database(e.to_string()))?,
                    asset_id: asset_opt
                        .map(|s| Uuid::parse_str(&s))
                        .transpose()
                        .map_err(|e| StoreError::Database(e.to_string()))?,
                    target,
                    assessment_type: a_type,
                    profile: prof,
                    status,
                    summary_json: sum_opt,
                    error_message: err_opt,
                    started_at: start_opt
                        .map(|s| {
                            DateTime::parse_from_rfc3339(&s)
                                .map(|d| d.with_timezone(&Utc))
                                .map_err(|e| StoreError::Database(e.to_string()))
                        })
                        .transpose()?,
                    completed_at: end_opt
                        .map(|s| {
                            DateTime::parse_from_rfc3339(&s)
                                .map(|d| d.with_timezone(&Utc))
                                .map_err(|e| StoreError::Database(e.to_string()))
                        })
                        .transpose()?,
                    created_at: DateTime::parse_from_rfc3339(&created_str)
                        .map(|d| d.with_timezone(&Utc))
                        .map_err(|e| StoreError::Database(e.to_string()))?,
                    assigned_agent_id: agent_opt
                        .map(|s| Uuid::parse_str(&s))
                        .transpose()
                        .map_err(|e| StoreError::Database(e.to_string()))?,
                    lease_expires_at: lease_opt
                        .map(|s| {
                            DateTime::parse_from_rfc3339(&s)
                                .map(|d| d.with_timezone(&Utc))
                                .map_err(|e| StoreError::Database(e.to_string()))
                        })
                        .transpose()?,
                    execution_source: source_opt.unwrap_or_else(|| "server".to_string()),
                    rules_subset: rules_opt,
                }))
            }
            None => Ok(None),
        }
    }

    async fn update_job_status(
        &self,
        org_id: Uuid,
        id: Uuid,
        status: JobStatus,
        summary_json: Option<&str>,
        error_message: Option<&str>,
    ) -> Result<(), StoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StoreError::Database(e.to_string()))?;

        // Validate state transitions
        let current_status: Option<String> = conn
            .query_row(
                "SELECT status FROM assessment_jobs WHERE org_id = ?1 AND id = ?2",
                params![org_id.to_string(), id.to_string()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let current_str =
            current_status.ok_or_else(|| StoreError::NotFound(format!("Job '{id}' not found")))?;
        let current = JobStatus::parse(&current_str).map_err(StoreError::Database)?;

        if current.is_terminal() {
            return Err(StoreError::Conflict(format!(
                "Cannot transition job '{id}' from terminal status '{current:?}' to '{status:?}'"
            )));
        }

        let now_str = Utc::now().to_rfc3339();

        let sql = match status {
            JobStatus::Running => {
                "UPDATE assessment_jobs SET status = ?1, started_at = ?2 WHERE org_id = ?3 AND id = ?4"
            }
            JobStatus::Completed | JobStatus::Failed | JobStatus::Cancelled => {
                "UPDATE assessment_jobs SET status = ?1, summary_json = ?2, error_message = ?3, completed_at = ?4 WHERE org_id = ?5 AND id = ?6"
            }
            JobStatus::Pending => {
                "UPDATE assessment_jobs SET status = ?1 WHERE org_id = ?2 AND id = ?3"
            }
        };

        let count = match status {
            JobStatus::Running => conn
                .execute(
                    sql,
                    params![status.as_str(), now_str, org_id.to_string(), id.to_string()],
                )
                .map_err(|e| StoreError::Database(e.to_string()))?,
            JobStatus::Completed | JobStatus::Failed | JobStatus::Cancelled => conn
                .execute(
                    sql,
                    params![
                        status.as_str(),
                        summary_json,
                        error_message,
                        now_str,
                        org_id.to_string(),
                        id.to_string()
                    ],
                )
                .map_err(|e| StoreError::Database(e.to_string()))?,
            JobStatus::Pending => conn
                .execute(
                    sql,
                    params![status.as_str(), org_id.to_string(), id.to_string()],
                )
                .map_err(|e| StoreError::Database(e.to_string()))?,
        };

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
        let conn = self
            .conn
            .lock()
            .map_err(|e| StoreError::Database(e.to_string()))?;
        let mut stmt = conn
            .prepare(
                "SELECT id, org_id, asset_id, target, assessment_type, profile, status,
                        summary_json, error_message, started_at, completed_at, created_at,
                        assigned_agent_id, lease_expires_at, execution_source, rules_subset
                 FROM assessment_jobs WHERE org_id = ?1 ORDER BY created_at DESC LIMIT ?2",
            )
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let rows = stmt
            .query_map(params![org_id.to_string(), limit as i64], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, Option<String>>(9)?,
                    row.get::<_, Option<String>>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, Option<String>>(12)?,
                    row.get::<_, Option<String>>(13)?,
                    row.get::<_, Option<String>>(14)?,
                    row.get::<_, Option<String>>(15)?,
                ))
            })
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let mut jobs = Vec::new();
        for r in rows {
            let (
                id_str,
                org_str,
                asset_opt,
                target,
                a_type,
                prof,
                status_str,
                sum_opt,
                err_opt,
                start_opt,
                end_opt,
                created_str,
                agent_opt,
                lease_opt,
                source_opt,
                rules_opt,
            ) = r.map_err(|e| StoreError::Database(e.to_string()))?;
            let status = JobStatus::parse(&status_str).map_err(StoreError::Database)?;
            jobs.push(AssessmentJob {
                id: Uuid::parse_str(&id_str).map_err(|e| StoreError::Database(e.to_string()))?,
                org_id: Uuid::parse_str(&org_str)
                    .map_err(|e| StoreError::Database(e.to_string()))?,
                asset_id: asset_opt
                    .map(|s| Uuid::parse_str(&s))
                    .transpose()
                    .map_err(|e| StoreError::Database(e.to_string()))?,
                target,
                assessment_type: a_type,
                profile: prof,
                status,
                summary_json: sum_opt,
                error_message: err_opt,
                started_at: start_opt
                    .map(|s| {
                        DateTime::parse_from_rfc3339(&s)
                            .map(|d| d.with_timezone(&Utc))
                            .map_err(|e| StoreError::Database(e.to_string()))
                    })
                    .transpose()?,
                completed_at: end_opt
                    .map(|s| {
                        DateTime::parse_from_rfc3339(&s)
                            .map(|d| d.with_timezone(&Utc))
                            .map_err(|e| StoreError::Database(e.to_string()))
                    })
                    .transpose()?,
                created_at: DateTime::parse_from_rfc3339(&created_str)
                    .map(|d| d.with_timezone(&Utc))
                    .map_err(|e| StoreError::Database(e.to_string()))?,
                assigned_agent_id: agent_opt
                    .map(|s| Uuid::parse_str(&s))
                    .transpose()
                    .map_err(|e| StoreError::Database(e.to_string()))?,
                lease_expires_at: lease_opt
                    .map(|s| {
                        DateTime::parse_from_rfc3339(&s)
                            .map(|d| d.with_timezone(&Utc))
                            .map_err(|e| StoreError::Database(e.to_string()))
                    })
                    .transpose()?,
                execution_source: source_opt.unwrap_or_else(|| "server".to_string()),
                rules_subset: rules_opt,
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
        let mut conn = self
            .conn
            .lock()
            .map_err(|e| StoreError::Database(e.to_string()))?;
        let tx = conn
            .transaction()
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let now_str = Utc::now().to_rfc3339();
        for f in findings {
            let id = Uuid::new_v4();
            tx.execute(
                "INSERT INTO assessment_findings
                 (id, org_id, job_id, rule_id, severity, confidence, title, endpoint, evidence, remediation, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    id.to_string(),
                    org_id.to_string(),
                    job_id.to_string(),
                    f.rule_id,
                    f.severity,
                    f.confidence,
                    f.title,
                    f.endpoint,
                    f.evidence,
                    f.recommendation,
                    now_str,
                ],
            )
            .map_err(|e| StoreError::Database(e.to_string()))?;
        }

        tx.commit()
            .map_err(|e| StoreError::Database(e.to_string()))?;
        Ok(())
    }

    async fn list_findings(
        &self,
        org_id: Uuid,
        job_id: Option<Uuid>,
        min_severity: Option<&str>,
    ) -> Result<Vec<AssessmentFinding>, StoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let sql = match (job_id, min_severity) {
            (Some(_), Some(_)) => {
                "SELECT id, org_id, job_id, rule_id, severity, confidence, title, endpoint, evidence, remediation, created_at
                 FROM assessment_findings WHERE org_id = ?1 AND job_id = ?2 AND severity = ?3 ORDER BY created_at DESC"
            }
            (Some(_), None) => {
                "SELECT id, org_id, job_id, rule_id, severity, confidence, title, endpoint, evidence, remediation, created_at
                 FROM assessment_findings WHERE org_id = ?1 AND job_id = ?2 ORDER BY created_at DESC"
            }
            (None, Some(_)) => {
                "SELECT id, org_id, job_id, rule_id, severity, confidence, title, endpoint, evidence, remediation, created_at
                 FROM assessment_findings WHERE org_id = ?1 AND severity = ?2 ORDER BY created_at DESC"
            }
            (None, None) => {
                "SELECT id, org_id, job_id, rule_id, severity, confidence, title, endpoint, evidence, remediation, created_at
                 FROM assessment_findings WHERE org_id = ?1 ORDER BY created_at DESC"
            }
        };

        let mut stmt = conn
            .prepare(sql)
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let map_row = |row: &rusqlite::Row| -> Result<AssessmentFinding, rusqlite::Error> {
            let id_str: String = row.get(0)?;
            let org_str: String = row.get(1)?;
            let job_str: String = row.get(2)?;
            let rule_id: String = row.get(3)?;
            let severity: String = row.get(4)?;
            let confidence: String = row.get(5)?;
            let title: String = row.get(6)?;
            let endpoint: String = row.get(7)?;
            let evidence: String = row.get(8)?;
            let recommendation: String = row.get(9)?;
            let created_str: String = row.get(10)?;

            let id = Uuid::parse_str(&id_str).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                )
            })?;
            let org_id = Uuid::parse_str(&org_str).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    1,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                )
            })?;
            let job_id = Uuid::parse_str(&job_str).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    2,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                )
            })?;
            let created_at = DateTime::parse_from_rfc3339(&created_str)
                .map(|d| d.with_timezone(&Utc))
                .map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        10,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    )
                })?;

            Ok(AssessmentFinding {
                id,
                org_id,
                job_id,
                rule_id,
                severity,
                confidence,
                title,
                endpoint,
                evidence,
                recommendation,
                created_at,
            })
        };

        let mut findings = Vec::new();
        match (job_id, min_severity) {
            (Some(j), Some(s)) => {
                let rows = stmt
                    .query_map(params![org_id.to_string(), j.to_string(), s], map_row)
                    .map_err(|e| StoreError::Database(e.to_string()))?;
                for r in rows {
                    findings.push(r.map_err(|e| StoreError::Database(e.to_string()))?);
                }
            }
            (Some(j), None) => {
                let rows = stmt
                    .query_map(params![org_id.to_string(), j.to_string()], map_row)
                    .map_err(|e| StoreError::Database(e.to_string()))?;
                for r in rows {
                    findings.push(r.map_err(|e| StoreError::Database(e.to_string()))?);
                }
            }
            (None, Some(s)) => {
                let rows = stmt
                    .query_map(params![org_id.to_string(), s], map_row)
                    .map_err(|e| StoreError::Database(e.to_string()))?;
                for r in rows {
                    findings.push(r.map_err(|e| StoreError::Database(e.to_string()))?);
                }
            }
            (None, None) => {
                let rows = stmt
                    .query_map(params![org_id.to_string()], map_row)
                    .map_err(|e| StoreError::Database(e.to_string()))?;
                for r in rows {
                    findings.push(r.map_err(|e| StoreError::Database(e.to_string()))?);
                }
            }
        }
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
        let conn = self
            .conn
            .lock()
            .map_err(|e| StoreError::Database(e.to_string()))?;
        let id = Uuid::new_v4();
        let now = Utc::now();
        let now_str = now.to_rfc3339();

        conn.execute(
            "INSERT INTO assessment_schedules
             (id, org_id, asset_id, name, cron_expression, target, assessment_type, profile, is_active, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1, ?9)",
            params![
                id.to_string(),
                org_id.to_string(),
                asset_id.map(|u| u.to_string()),
                name,
                cron_expression,
                target,
                assessment_type,
                profile,
                now_str,
            ],
        )
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
        let conn = self
            .conn
            .lock()
            .map_err(|e| StoreError::Database(e.to_string()))?;
        let mut stmt = conn
            .prepare(
                "SELECT id, org_id, asset_id, name, cron_expression, target, assessment_type, profile, is_active, last_run_at, next_run_at, created_at
                 FROM assessment_schedules WHERE org_id = ?1 ORDER BY created_at DESC",
            )
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let rows = stmt
            .query_map(params![org_id.to_string()], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, i64>(8)? != 0,
                    row.get::<_, Option<String>>(9)?,
                    row.get::<_, Option<String>>(10)?,
                    row.get::<_, String>(11)?,
                ))
            })
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let mut schedules = Vec::new();
        for r in rows {
            let (
                id_str,
                org_str,
                asset_opt,
                name,
                cron,
                target,
                a_type,
                prof,
                active,
                last_opt,
                next_opt,
                created_str,
            ) = r.map_err(|e| StoreError::Database(e.to_string()))?;
            schedules.push(AssessmentSchedule {
                id: Uuid::parse_str(&id_str).map_err(|e| StoreError::Database(e.to_string()))?,
                org_id: Uuid::parse_str(&org_str)
                    .map_err(|e| StoreError::Database(e.to_string()))?,
                asset_id: asset_opt
                    .map(|s| Uuid::parse_str(&s))
                    .transpose()
                    .map_err(|e| StoreError::Database(e.to_string()))?,
                name,
                cron_expression: cron,
                target,
                assessment_type: a_type,
                profile: prof,
                is_active: active,
                last_run_at: last_opt
                    .map(|s| {
                        DateTime::parse_from_rfc3339(&s)
                            .map(|d| d.with_timezone(&Utc))
                            .map_err(|e| StoreError::Database(e.to_string()))
                    })
                    .transpose()?,
                next_run_at: next_opt
                    .map(|s| {
                        DateTime::parse_from_rfc3339(&s)
                            .map(|d| d.with_timezone(&Utc))
                            .map_err(|e| StoreError::Database(e.to_string()))
                    })
                    .transpose()?,
                created_at: DateTime::parse_from_rfc3339(&created_str)
                    .map(|d| d.with_timezone(&Utc))
                    .map_err(|e| StoreError::Database(e.to_string()))?,
            });
        }
        Ok(schedules)
    }

    async fn get_due_schedules(&self) -> Result<Vec<AssessmentSchedule>, StoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StoreError::Database(e.to_string()))?;
        let now_str = Utc::now().to_rfc3339();
        let mut stmt = conn
            .prepare(
                "SELECT id, org_id, asset_id, name, cron_expression, target, assessment_type, profile, is_active, last_run_at, next_run_at, created_at
                 FROM assessment_schedules
                 WHERE is_active = 1 AND (next_run_at IS NULL OR next_run_at <= ?1)",
            )
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let rows = stmt
            .query_map(params![now_str], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, i64>(8)? != 0,
                    row.get::<_, Option<String>>(9)?,
                    row.get::<_, Option<String>>(10)?,
                    row.get::<_, String>(11)?,
                ))
            })
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let mut schedules = Vec::new();
        for r in rows {
            let (
                id_str,
                org_str,
                asset_opt,
                name,
                cron,
                target,
                a_type,
                prof,
                active,
                last_opt,
                next_opt,
                created_str,
            ) = r.map_err(|e| StoreError::Database(e.to_string()))?;
            schedules.push(AssessmentSchedule {
                id: Uuid::parse_str(&id_str).map_err(|e| StoreError::Database(e.to_string()))?,
                org_id: Uuid::parse_str(&org_str)
                    .map_err(|e| StoreError::Database(e.to_string()))?,
                asset_id: asset_opt
                    .map(|s| Uuid::parse_str(&s))
                    .transpose()
                    .map_err(|e| StoreError::Database(e.to_string()))?,
                name,
                cron_expression: cron,
                target,
                assessment_type: a_type,
                profile: prof,
                is_active: active,
                last_run_at: last_opt
                    .map(|s| {
                        DateTime::parse_from_rfc3339(&s)
                            .map(|d| d.with_timezone(&Utc))
                            .map_err(|e| StoreError::Database(e.to_string()))
                    })
                    .transpose()?,
                next_run_at: next_opt
                    .map(|s| {
                        DateTime::parse_from_rfc3339(&s)
                            .map(|d| d.with_timezone(&Utc))
                            .map_err(|e| StoreError::Database(e.to_string()))
                    })
                    .transpose()?,
                created_at: DateTime::parse_from_rfc3339(&created_str)
                    .map(|d| d.with_timezone(&Utc))
                    .map_err(|e| StoreError::Database(e.to_string()))?,
            });
        }
        Ok(schedules)
    }

    async fn update_schedule_run_state(
        &self,
        schedule_id: Uuid,
        last_run: DateTime<Utc>,
        next_run: Option<DateTime<Utc>>,
    ) -> Result<(), StoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StoreError::Database(e.to_string()))?;
        conn.execute(
            "UPDATE assessment_schedules SET last_run_at = ?1, next_run_at = ?2 WHERE id = ?3",
            params![
                last_run.to_rfc3339(),
                next_run.map(|d| d.to_rfc3339()),
                schedule_id.to_string(),
            ],
        )
        .map_err(|e| StoreError::Database(e.to_string()))?;
        Ok(())
    }

    async fn revoke_token(&self, jti: Uuid, expires_at: DateTime<Utc>) -> Result<(), StoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StoreError::Database(e.to_string()))?;
        let now_str = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT OR IGNORE INTO revoked_tokens (jti, expires_at, revoked_at) VALUES (?1, ?2, ?3)",
            params![jti.to_string(), expires_at.to_rfc3339(), now_str],
        )
        .map_err(|e| StoreError::Database(e.to_string()))?;
        Ok(())
    }

    async fn is_token_revoked(&self, jti: Uuid) -> Result<bool, StoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StoreError::Database(e.to_string()))?;
        let exists = conn
            .query_row(
                "SELECT 1 FROM revoked_tokens WHERE jti = ?1",
                params![jti.to_string()],
                |_| Ok(()),
            )
            .optional()
            .map_err(|e| StoreError::Database(e.to_string()))?
            .is_some();
        Ok(exists)
    }

    async fn clean_expired_revocations(&self) -> Result<usize, StoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StoreError::Database(e.to_string()))?;
        let now_str = Utc::now().to_rfc3339();
        let count = conn
            .execute(
                "DELETE FROM revoked_tokens WHERE expires_at < ?1",
                params![now_str],
            )
            .map_err(|e| StoreError::Database(e.to_string()))?;
        Ok(count)
    }

    async fn recover_interrupted_jobs(&self) -> Result<usize, StoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StoreError::Database(e.to_string()))?;
        let now_str = Utc::now().to_rfc3339();
        let count = conn
            .execute(
                "UPDATE assessment_jobs SET status = 'failed', error_message = 'Job execution interrupted by server restart/shutdown', completed_at = ?1 WHERE status = 'running'",
                params![now_str],
            )
            .map_err(|e| StoreError::Database(e.to_string()))?;
        Ok(count)
    }

    async fn issue_agent_enrollment_token(
        &self,
        org_id: Uuid,
        token_secret: &str,
        machine_id: Option<&str>,
        challenge_nonce: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<AgentEnrollmentToken, StoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let id = Uuid::new_v4();
        let now = Utc::now();

        conn.execute(
            "INSERT INTO agent_enrollment_tokens (id, org_id, token_secret, machine_id, challenge_nonce, expires_at, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                id.to_string(),
                org_id.to_string(),
                token_secret,
                machine_id,
                challenge_nonce,
                expires_at.to_rfc3339(),
                now.to_rfc3339(),
            ],
        )
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
        let conn = self
            .conn
            .lock()
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let mut stmt = conn
            .prepare(
                "SELECT id, org_id, token_secret, machine_id, challenge_nonce, expires_at, used_at, created_at
                 FROM agent_enrollment_tokens WHERE id = ?1",
            )
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let row = stmt
            .query_row(params![token_id.to_string()], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Option<String>>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, Option<String>>(6)?,
                    r.get::<_, String>(7)?,
                ))
            })
            .optional()
            .map_err(|e| StoreError::Database(e.to_string()))?;

        row.map(
            |(id_str, org_str, secret, machine, nonce, exp_str, used_str, created_str)| {
                Ok(AgentEnrollmentToken {
                    id: Uuid::parse_str(&id_str)
                        .map_err(|e| StoreError::Database(e.to_string()))?,
                    org_id: Uuid::parse_str(&org_str)
                        .map_err(|e| StoreError::Database(e.to_string()))?,
                    token_secret: secret,
                    machine_id: machine,
                    challenge_nonce: nonce,
                    expires_at: DateTime::parse_from_rfc3339(&exp_str)
                        .map(|d| d.with_timezone(&Utc))
                        .map_err(|e| StoreError::Database(e.to_string()))?,
                    used_at: used_str
                        .map(|s| {
                            DateTime::parse_from_rfc3339(&s)
                                .map(|d| d.with_timezone(&Utc))
                                .map_err(|e| StoreError::Database(e.to_string()))
                        })
                        .transpose()?,
                    created_at: DateTime::parse_from_rfc3339(&created_str)
                        .map(|d| d.with_timezone(&Utc))
                        .map_err(|e| StoreError::Database(e.to_string()))?,
                })
            },
        )
        .transpose()
    }

    async fn consume_enrollment_token(&self, token_id: Uuid) -> Result<(), StoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let now_str = Utc::now().to_rfc3339();
        let rows = conn
            .execute(
                "UPDATE agent_enrollment_tokens
                 SET used_at = ?1
                 WHERE id = ?2 AND used_at IS NULL AND expires_at > ?1",
                params![now_str, token_id.to_string()],
            )
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
        let conn = self
            .conn
            .lock()
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let now = Utc::now();
        let now_str = now.to_rfc3339();
        let fresh_id = Uuid::new_v4().to_string();

        conn.execute(
            "INSERT INTO enrolled_agents (id, org_id, machine_id, hostname, agent_version, status, auth_token_hash, public_identity, capabilities, last_seen_at, enrolled_at, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 'active', ?6, ?7, ?8, ?9, ?9, ?9, ?9)
             ON CONFLICT(org_id, machine_id) DO UPDATE SET
                 hostname = excluded.hostname,
                 agent_version = excluded.agent_version,
                 status = 'active',
                 auth_token_hash = excluded.auth_token_hash,
                 public_identity = excluded.public_identity,
                 capabilities = excluded.capabilities,
                 last_seen_at = excluded.last_seen_at,
                 enrolled_at = excluded.enrolled_at,
                 revoked_at = NULL,
                 updated_at = excluded.updated_at",
            params![
                fresh_id,
                org_id.to_string(),
                machine_id,
                hostname,
                agent_version,
                auth_token_hash,
                public_identity,
                capabilities,
                now_str,
            ],
        )
        .map_err(|e| StoreError::Database(e.to_string()))?;

        // Retrieve the enrolled record
        let mut stmt = conn
            .prepare(
                "SELECT id, org_id, machine_id, hostname, agent_version, status, auth_token_hash, public_identity, capabilities, last_seen_at, enrolled_at, revoked_at, created_at, updated_at
                 FROM enrolled_agents WHERE org_id = ?1 AND machine_id = ?2",
            )
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let r = stmt
            .query_row(params![org_id.to_string(), machine_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, Option<String>>(11)?,
                    row.get::<_, String>(12)?,
                    row.get::<_, String>(13)?,
                ))
            })
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let status = AgentStatus::parse(&r.5).map_err(StoreError::Database)?;

        Ok(EnrolledAgent {
            id: Uuid::parse_str(&r.0).map_err(|e| StoreError::Database(e.to_string()))?,
            org_id: Uuid::parse_str(&r.1).map_err(|e| StoreError::Database(e.to_string()))?,
            machine_id: r.2,
            hostname: r.3,
            agent_version: r.4,
            status,
            auth_token_hash: r.6,
            public_identity: r.7,
            capabilities: r.8,
            last_seen_at: DateTime::parse_from_rfc3339(&r.9)
                .map(|d| d.with_timezone(&Utc))
                .map_err(|e| StoreError::Database(e.to_string()))?,
            enrolled_at: DateTime::parse_from_rfc3339(&r.10)
                .map(|d| d.with_timezone(&Utc))
                .map_err(|e| StoreError::Database(e.to_string()))?,
            revoked_at: r
                .11
                .map(|s| {
                    DateTime::parse_from_rfc3339(&s)
                        .map(|d| d.with_timezone(&Utc))
                        .map_err(|e| StoreError::Database(e.to_string()))
                })
                .transpose()?,
            created_at: DateTime::parse_from_rfc3339(&r.12)
                .map(|d| d.with_timezone(&Utc))
                .map_err(|e| StoreError::Database(e.to_string()))?,
            updated_at: DateTime::parse_from_rfc3339(&r.13)
                .map(|d| d.with_timezone(&Utc))
                .map_err(|e| StoreError::Database(e.to_string()))?,
        })
    }

    async fn get_agent_by_id(
        &self,
        org_id: Uuid,
        agent_id: Uuid,
    ) -> Result<Option<EnrolledAgent>, StoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let mut stmt = conn
            .prepare(
                "SELECT id, org_id, machine_id, hostname, agent_version, status, auth_token_hash, public_identity, capabilities, last_seen_at, enrolled_at, revoked_at, created_at, updated_at
                 FROM enrolled_agents WHERE org_id = ?1 AND id = ?2",
            )
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let row = stmt
            .query_row(params![org_id.to_string(), agent_id.to_string()], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, String>(6)?,
                    r.get::<_, String>(7)?,
                    r.get::<_, String>(8)?,
                    r.get::<_, String>(9)?,
                    r.get::<_, String>(10)?,
                    r.get::<_, Option<String>>(11)?,
                    r.get::<_, String>(12)?,
                    r.get::<_, String>(13)?,
                ))
            })
            .optional()
            .map_err(|e| StoreError::Database(e.to_string()))?;

        row.map(|r| {
            let status = AgentStatus::parse(&r.5).map_err(StoreError::Database)?;
            Ok(EnrolledAgent {
                id: Uuid::parse_str(&r.0).map_err(|e| StoreError::Database(e.to_string()))?,
                org_id: Uuid::parse_str(&r.1).map_err(|e| StoreError::Database(e.to_string()))?,
                machine_id: r.2,
                hostname: r.3,
                agent_version: r.4,
                status,
                auth_token_hash: r.6,
                public_identity: r.7,
                capabilities: r.8,
                last_seen_at: DateTime::parse_from_rfc3339(&r.9)
                    .map(|d| d.with_timezone(&Utc))
                    .map_err(|e| StoreError::Database(e.to_string()))?,
                enrolled_at: DateTime::parse_from_rfc3339(&r.10)
                    .map(|d| d.with_timezone(&Utc))
                    .map_err(|e| StoreError::Database(e.to_string()))?,
                revoked_at: r
                    .11
                    .map(|s| {
                        DateTime::parse_from_rfc3339(&s)
                            .map(|d| d.with_timezone(&Utc))
                            .map_err(|e| StoreError::Database(e.to_string()))
                    })
                    .transpose()?,
                created_at: DateTime::parse_from_rfc3339(&r.12)
                    .map(|d| d.with_timezone(&Utc))
                    .map_err(|e| StoreError::Database(e.to_string()))?,
                updated_at: DateTime::parse_from_rfc3339(&r.13)
                    .map(|d| d.with_timezone(&Utc))
                    .map_err(|e| StoreError::Database(e.to_string()))?,
            })
        })
        .transpose()
    }

    async fn get_agent_by_auth_hash(
        &self,
        auth_token_hash: &str,
    ) -> Result<Option<EnrolledAgent>, StoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let mut stmt = conn
            .prepare(
                "SELECT id, org_id, machine_id, hostname, agent_version, status, auth_token_hash, public_identity, capabilities, last_seen_at, enrolled_at, revoked_at, created_at, updated_at
                 FROM enrolled_agents
                 WHERE auth_token_hash = ?1 OR previous_auth_token_hash = ?1
                 ORDER BY CASE WHEN auth_token_hash = ?1 THEN 0 ELSE 1 END
                 LIMIT 1",
            )
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let row = stmt
            .query_row(params![auth_token_hash], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, String>(6)?,
                    r.get::<_, String>(7)?,
                    r.get::<_, String>(8)?,
                    r.get::<_, String>(9)?,
                    r.get::<_, String>(10)?,
                    r.get::<_, Option<String>>(11)?,
                    r.get::<_, String>(12)?,
                    r.get::<_, String>(13)?,
                ))
            })
            .optional()
            .map_err(|e| StoreError::Database(e.to_string()))?;

        row.map(|r| {
            let status = AgentStatus::parse(&r.5).map_err(StoreError::Database)?;
            Ok(EnrolledAgent {
                id: Uuid::parse_str(&r.0).map_err(|e| StoreError::Database(e.to_string()))?,
                org_id: Uuid::parse_str(&r.1).map_err(|e| StoreError::Database(e.to_string()))?,
                machine_id: r.2,
                hostname: r.3,
                agent_version: r.4,
                status,
                auth_token_hash: r.6,
                public_identity: r.7,
                capabilities: r.8,
                last_seen_at: DateTime::parse_from_rfc3339(&r.9)
                    .map(|d| d.with_timezone(&Utc))
                    .map_err(|e| StoreError::Database(e.to_string()))?,
                enrolled_at: DateTime::parse_from_rfc3339(&r.10)
                    .map(|d| d.with_timezone(&Utc))
                    .map_err(|e| StoreError::Database(e.to_string()))?,
                revoked_at: r
                    .11
                    .map(|s| {
                        DateTime::parse_from_rfc3339(&s)
                            .map(|d| d.with_timezone(&Utc))
                            .map_err(|e| StoreError::Database(e.to_string()))
                    })
                    .transpose()?,
                created_at: DateTime::parse_from_rfc3339(&r.12)
                    .map(|d| d.with_timezone(&Utc))
                    .map_err(|e| StoreError::Database(e.to_string()))?,
                updated_at: DateTime::parse_from_rfc3339(&r.13)
                    .map(|d| d.with_timezone(&Utc))
                    .map_err(|e| StoreError::Database(e.to_string()))?,
            })
        })
        .transpose()
    }

    async fn list_agents(&self, org_id: Uuid) -> Result<Vec<EnrolledAgent>, StoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let mut stmt = conn
            .prepare(
                "SELECT id, org_id, machine_id, hostname, agent_version, status, auth_token_hash, public_identity, capabilities, last_seen_at, enrolled_at, revoked_at, created_at, updated_at
                 FROM enrolled_agents WHERE org_id = ?1 ORDER BY enrolled_at DESC",
            )
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let rows = stmt
            .query_map(params![org_id.to_string()], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, String>(6)?,
                    r.get::<_, String>(7)?,
                    r.get::<_, String>(8)?,
                    r.get::<_, String>(9)?,
                    r.get::<_, String>(10)?,
                    r.get::<_, Option<String>>(11)?,
                    r.get::<_, String>(12)?,
                    r.get::<_, String>(13)?,
                ))
            })
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let mut agents = Vec::new();
        for row in rows {
            let r = row.map_err(|e| StoreError::Database(e.to_string()))?;
            let status = AgentStatus::parse(&r.5).map_err(StoreError::Database)?;
            agents.push(EnrolledAgent {
                id: Uuid::parse_str(&r.0).map_err(|e| StoreError::Database(e.to_string()))?,
                org_id: Uuid::parse_str(&r.1).map_err(|e| StoreError::Database(e.to_string()))?,
                machine_id: r.2,
                hostname: r.3,
                agent_version: r.4,
                status,
                auth_token_hash: r.6,
                public_identity: r.7,
                capabilities: r.8,
                last_seen_at: DateTime::parse_from_rfc3339(&r.9)
                    .map(|d| d.with_timezone(&Utc))
                    .map_err(|e| StoreError::Database(e.to_string()))?,
                enrolled_at: DateTime::parse_from_rfc3339(&r.10)
                    .map(|d| d.with_timezone(&Utc))
                    .map_err(|e| StoreError::Database(e.to_string()))?,
                revoked_at: r
                    .11
                    .map(|s| {
                        DateTime::parse_from_rfc3339(&s)
                            .map(|d| d.with_timezone(&Utc))
                            .map_err(|e| StoreError::Database(e.to_string()))
                    })
                    .transpose()?,
                created_at: DateTime::parse_from_rfc3339(&r.12)
                    .map(|d| d.with_timezone(&Utc))
                    .map_err(|e| StoreError::Database(e.to_string()))?,
                updated_at: DateTime::parse_from_rfc3339(&r.13)
                    .map(|d| d.with_timezone(&Utc))
                    .map_err(|e| StoreError::Database(e.to_string()))?,
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
        let conn = self
            .conn
            .lock()
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let now_str = Utc::now().to_rfc3339();
        let revoked_str = if status == AgentStatus::Revoked {
            Some(now_str.clone())
        } else {
            None
        };

        let rows = conn
            .execute(
                "UPDATE enrolled_agents
                 SET status = ?1,
                     revoked_at = COALESCE(?2, revoked_at),
                     updated_at = ?3
                 WHERE org_id = ?4 AND id = ?5",
                params![
                    status.as_str(),
                    revoked_str,
                    now_str,
                    org_id.to_string(),
                    agent_id.to_string(),
                ],
            )
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
        let conn = self
            .conn
            .lock()
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let now_str = last_seen_at.to_rfc3339();
        conn.execute(
            "UPDATE enrolled_agents
             SET last_seen_at = ?1,
                 previous_auth_token_hash = NULL,
                 updated_at = ?1
             WHERE id = ?2",
            params![now_str, agent_id.to_string()],
        )
        .map_err(|e| StoreError::Database(e.to_string()))?;

        Ok(())
    }

    async fn rotate_agent_credential(
        &self,
        agent_id: Uuid,
        new_auth_hash: &str,
    ) -> Result<(), StoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let now_str = Utc::now().to_rfc3339();
        let rows = conn
            .execute(
                "UPDATE enrolled_agents
                 SET previous_auth_token_hash = auth_token_hash,
                     auth_token_hash = ?1,
                     updated_at = ?2
                 WHERE id = ?3 AND status = 'active'",
                params![new_auth_hash, now_str, agent_id.to_string()],
            )
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
        let job_id_res: Result<Option<Uuid>, StoreError> = {
            let conn = self
                .conn
                .lock()
                .map_err(|e| StoreError::Database(e.to_string()))?;

            let now = Utc::now();
            let now_str = now.to_rfc3339();
            let lease_expiry = now + chrono::Duration::seconds(lease_duration_secs);
            let lease_expiry_str = lease_expiry.to_rfc3339();

            // 1. Find oldest claimable job
            let mut stmt = conn
                .prepare(
                    "SELECT id
                     FROM assessment_jobs
                     WHERE org_id = ?1
                       AND (
                           status = 'pending'
                           OR (status = 'running' AND lease_expires_at IS NOT NULL AND lease_expires_at < ?2)
                       )
                     ORDER BY created_at ASC
                     LIMIT 1",
                )
                .map_err(|e| StoreError::Database(e.to_string()))?;

            let candidate_id: Option<String> = stmt
                .query_row(params![org_id.to_string(), now_str], |row| row.get(0))
                .optional()
                .map_err(|e| StoreError::Database(e.to_string()))?;

            let Some(job_id_str) = candidate_id else {
                return Ok(None);
            };

            // 2. Atomically claim the job
            let rows = conn
                .execute(
                    "UPDATE assessment_jobs
                     SET status = 'running',
                         assigned_agent_id = ?1,
                         execution_source = 'agent',
                         started_at = COALESCE(started_at, ?2),
                         lease_expires_at = ?3
                     WHERE id = ?4",
                    params![agent_id.to_string(), now_str, lease_expiry_str, job_id_str,],
                )
                .map_err(|e| StoreError::Database(e.to_string()))?;

            if rows == 0 {
                return Ok(None);
            }

            let parsed_job_id =
                Uuid::parse_str(&job_id_str).map_err(|e| StoreError::Database(e.to_string()))?;

            Ok(Some(parsed_job_id))
        };

        if let Some(parsed_job_id) = job_id_res? {
            self.get_job(org_id, parsed_job_id).await
        } else {
            Ok(None)
        }
    }

    async fn renew_job_lease(
        &self,
        agent_id: Uuid,
        job_id: Uuid,
        lease_duration_secs: i64,
    ) -> Result<bool, StoreError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let now = Utc::now();
        let lease_expiry = now + chrono::Duration::seconds(lease_duration_secs);
        let lease_expiry_str = lease_expiry.to_rfc3339();

        let modified = conn
            .execute(
                "UPDATE assessment_jobs
                 SET lease_expires_at = ?1
                 WHERE id = ?2 AND assigned_agent_id = ?3 AND status = 'running'",
                params![lease_expiry_str, job_id.to_string(), agent_id.to_string(),],
            )
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
        let mut conn = self
            .conn
            .lock()
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let tx = conn
            .transaction()
            .map_err(|e| StoreError::Database(e.to_string()))?;

        // 1. Verify job is currently assigned to this agent and running
        let mut stmt = tx
            .prepare(
                "SELECT status, assigned_agent_id
                 FROM assessment_jobs
                 WHERE id = ?1 AND org_id = ?2",
            )
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let row: Option<(String, Option<String>)> = stmt
            .query_row(params![job_id.to_string(), org_id.to_string()], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .optional()
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let Some((current_status, assigned_agent_opt)) = row else {
            return Err(StoreError::NotFound(format!("Job {job_id} not found")));
        };

        if assigned_agent_opt.as_deref() != Some(&agent_id.to_string()) {
            return Err(StoreError::Unauthorized(format!(
                "Job {job_id} is not assigned to agent {agent_id}"
            )));
        }

        if current_status == "completed" {
            // Idempotent duplicate submission
            return Ok(());
        }

        if current_status != "running" {
            return Err(StoreError::Conflict(format!(
                "Job {job_id} is in status '{current_status}', not 'running'"
            )));
        }

        drop(stmt);

        // 2. Insert findings
        let now_str = Utc::now().to_rfc3339();
        for f in findings {
            let finding_id = Uuid::new_v4().to_string();
            tx.execute(
                "INSERT INTO assessment_findings (id, org_id, job_id, rule_id, severity, confidence, title, endpoint, evidence, remediation, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    finding_id,
                    org_id.to_string(),
                    job_id.to_string(),
                    f.rule_id,
                    f.severity,
                    f.confidence,
                    f.title,
                    f.endpoint,
                    f.evidence,
                    f.recommendation,
                    now_str,
                ],
            )
            .map_err(|e| StoreError::Database(e.to_string()))?;
        }

        // 3. Mark job completed
        tx.execute(
            "UPDATE assessment_jobs
             SET status = 'completed',
                 summary_json = ?1,
                 completed_at = ?2,
                 lease_expires_at = NULL
             WHERE id = ?3",
            params![summary_json, now_str, job_id.to_string()],
        )
        .map_err(|e| StoreError::Database(e.to_string()))?;

        tx.commit()
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
        let conn = self
            .conn
            .lock()
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let now_str = Utc::now().to_rfc3339();
        let rows = conn
            .execute(
                "UPDATE assessment_jobs
                 SET status = 'failed',
                     error_message = ?1,
                     completed_at = ?2,
                     lease_expires_at = NULL
                 WHERE id = ?3 AND org_id = ?4 AND assigned_agent_id = ?5 AND status = 'running'",
                params![
                    error_message,
                    now_str,
                    job_id.to_string(),
                    org_id.to_string(),
                    agent_id.to_string(),
                ],
            )
            .map_err(|e| StoreError::Database(e.to_string()))?;

        if rows == 0 {
            return Err(StoreError::Conflict(format!(
                "Job {job_id} cannot be marked failed (not running or not assigned to agent {agent_id})"
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_sqlite_tenant_isolation_and_lifecycle() {
        let store = SqliteControlPlaneStore::in_memory().expect("Must initialize in-memory SQLite");
        assert!(store.is_healthy().await);

        // Create Org 1 and Org 2
        let org1 = store
            .create_organization("Acme Corp", "acme")
            .await
            .expect("Must create org1");
        let org2 = store
            .create_organization("Beta Ltd", "beta")
            .await
            .expect("Must create org2");

        // Create assets in Org 1
        let asset1 = store
            .create_asset(org1.id, "Web Server", "linux_host", "192.168.1.10", "high")
            .await
            .expect("Must create asset in org1");

        // Verify Org 2 cannot read Org 1's asset (strict tenant isolation)
        let isolated = store
            .get_asset(org2.id, asset1.id)
            .await
            .expect("Query must succeed");
        assert_eq!(isolated, None, "Org 2 must not see Org 1 asset");

        // Org 1 can read its own asset
        let read_back = store
            .get_asset(org1.id, asset1.id)
            .await
            .expect("Query must succeed")
            .expect("Asset must exist");
        assert_eq!(read_back.name, "Web Server");

        // Create user in Org 1
        let user1 = store
            .create_user(
                org1.id,
                "alice@acme.com",
                "argon2id$mockhash",
                "Alice Admin",
                Role::Admin,
            )
            .await
            .expect("Must create user");
        assert_eq!(user1.role, Role::Admin);

        // Conflict when creating same user in same org
        let conflict = store
            .create_user(
                org1.id,
                "alice@acme.com",
                "argon2id$mockhash",
                "Alice Duplicate",
                Role::Viewer,
            )
            .await;
        assert!(matches!(conflict, Err(StoreError::Conflict(_))));

        // Create Job in Org 1
        let job = store
            .create_job(
                org1.id,
                Some(asset1.id),
                "192.168.1.10",
                "local_host",
                "baseline",
            )
            .await
            .expect("Must create job");
        assert_eq!(job.status, JobStatus::Pending);

        // Update Job to Running, then Completed
        store
            .update_job_status(org1.id, job.id, JobStatus::Running, None, None)
            .await
            .expect("Update must succeed");
        store
            .update_job_status(
                org1.id,
                job.id,
                JobStatus::Completed,
                Some(r#"{"findings_count": 1}"#),
                None,
            )
            .await
            .expect("Update must succeed");

        let updated_job = store
            .get_job(org1.id, job.id)
            .await
            .expect("Job must exist")
            .unwrap();
        assert_eq!(updated_job.status, JobStatus::Completed);
        assert!(updated_job.started_at.is_some());
        assert!(updated_job.completed_at.is_some());

        // Enforce valid state transition: completed terminal job cannot be transitioned again
        let conflict_transition = store
            .update_job_status(org1.id, job.id, JobStatus::Running, None, None)
            .await;
        assert!(matches!(conflict_transition, Err(StoreError::Conflict(_))));

        // Create Finding for Job
        let finding = NewFinding {
            rule_id: "linux.ssh.root-login".into(),
            severity: "High".into(),
            confidence: "Confirmed".into(),
            title: "SSH Root Login Permitted".into(),
            endpoint: "192.168.1.10:22".into(),
            evidence: "PermitRootLogin yes".into(),
            recommendation: "Disable PermitRootLogin".into(),
        };
        store
            .create_findings(org1.id, job.id, &[finding])
            .await
            .expect("Must persist finding");

        let findings = store
            .list_findings(org1.id, Some(job.id), None)
            .await
            .expect("List findings must succeed");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "linux.ssh.root-login");

        // Org 2 cannot see Org 1 findings
        let isolated_findings = store
            .list_findings(org2.id, Some(job.id), None)
            .await
            .expect("List findings query must succeed");
        assert!(isolated_findings.is_empty());

        // Test Token Revocation
        let jti = Uuid::new_v4();
        let exp = Utc::now() + chrono::Duration::hours(1);
        assert!(!store.is_token_revoked(jti).await.unwrap());
        store
            .revoke_token(jti, exp)
            .await
            .expect("Must revoke token");
        assert!(store.is_token_revoked(jti).await.unwrap());

        // Test Interrupted Job Recovery
        let interrupted_job = store
            .create_job(org1.id, None, "127.0.0.1", "local_host", "default")
            .await
            .expect("Must create job");
        store
            .update_job_status(org1.id, interrupted_job.id, JobStatus::Running, None, None)
            .await
            .expect("Must set to running");

        let recovered = store
            .recover_interrupted_jobs()
            .await
            .expect("Must recover");
        assert!(recovered >= 1);

        let recovered_job = store
            .get_job(org1.id, interrupted_job.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(recovered_job.status, JobStatus::Failed);
        assert!(recovered_job
            .error_message
            .as_deref()
            .unwrap()
            .contains("interrupted by server restart"));
    }

    #[tokio::test]
    async fn test_sqlite_agent_lifecycle_and_dispatch() {
        let store = SqliteControlPlaneStore::in_memory().expect("in-memory db");
        let (org, _) = store
            .bootstrap_admin(
                "Agent Corp",
                "agent-corp",
                "Admin",
                "admin@agentcorp.com",
                "hash",
            )
            .await
            .unwrap();

        // 1. Issue one-time enrollment token
        let token_secret = "secret-token-1234567890abcdef";
        let challenge = "nonce-123456";
        let expires = Utc::now() + chrono::Duration::minutes(10);
        let token = store
            .issue_agent_enrollment_token(org.id, token_secret, Some("node-01"), challenge, expires)
            .await
            .expect("Must issue token");

        assert_eq!(token.org_id, org.id);
        assert_eq!(token.machine_id.as_deref(), Some("node-01"));

        let fetched_token = store
            .get_agent_enrollment_token(token.id)
            .await
            .unwrap()
            .expect("Token exists");
        assert_eq!(fetched_token.token_secret, token_secret);

        // Consume token
        store
            .consume_enrollment_token(token.id)
            .await
            .expect("Must consume");

        // Double consume must fail
        let double_consume = store.consume_enrollment_token(token.id).await;
        assert!(matches!(double_consume, Err(StoreError::Conflict(_))));

        // 2. Enroll Agent
        let auth_hash = "agent_auth_hash_abcdef";
        let agent = store
            .enroll_agent(
                org.id,
                "node-01",
                "worker-node-1.corp.internal",
                "0.1.0-alpha.0",
                auth_hash,
                "spki-der-hex-1234",
                r#"["host_audit","perimeter_scan"]"#,
            )
            .await
            .expect("Must enroll agent");

        assert_eq!(agent.status, AgentStatus::Active);
        assert_eq!(agent.machine_id, "node-01");

        // Lookup by ID and by Auth Hash
        let by_id = store
            .get_agent_by_id(org.id, agent.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(by_id.hostname, "worker-node-1.corp.internal");

        let by_hash = store
            .get_agent_by_auth_hash(auth_hash)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(by_hash.id, agent.id);

        // List agents
        let agents = store.list_agents(org.id).await.unwrap();
        assert_eq!(agents.len(), 1);

        // Update heartbeat
        let heartbeat_time = Utc::now();
        store
            .update_agent_heartbeat(agent.id, heartbeat_time)
            .await
            .unwrap();

        // Rotate credential
        let new_hash = "rotated_auth_hash_987654";
        store
            .rotate_agent_credential(agent.id, new_hash)
            .await
            .unwrap();
        // During transition before heartbeat confirmation, previous key still resolves
        assert!(store
            .get_agent_by_auth_hash(auth_hash)
            .await
            .unwrap()
            .is_some());
        assert!(store
            .get_agent_by_auth_hash(new_hash)
            .await
            .unwrap()
            .is_some());

        // Heartbeat confirms new key and clears previous fallback
        store
            .update_agent_heartbeat(agent.id, Utc::now())
            .await
            .unwrap();
        assert!(store
            .get_agent_by_auth_hash(auth_hash)
            .await
            .unwrap()
            .is_none());

        // 3. Job Claiming and Dispatch
        let job = store
            .create_job(org.id, None, "10.0.0.1", "host_audit", "cis_level_1")
            .await
            .unwrap();

        // Agent 1 claims job
        let claimed = store
            .claim_next_pending_job(agent.id, org.id, 60)
            .await
            .unwrap()
            .expect("Job should be claimed");

        assert_eq!(claimed.id, job.id);
        assert_eq!(claimed.status, JobStatus::Running);
        assert_eq!(claimed.assigned_agent_id, Some(agent.id));
        assert!(claimed.lease_expires_at.is_some());

        // Second agent cannot claim the same job (no other pending jobs)
        let other_agent_id = Uuid::new_v4();
        let second_claim = store
            .claim_next_pending_job(other_agent_id, org.id, 60)
            .await
            .unwrap();
        assert!(second_claim.is_none(), "No pending jobs available");

        // Renew lease
        let renewed = store.renew_job_lease(agent.id, job.id, 120).await.unwrap();
        assert!(renewed);

        // 4. Complete Agent Job
        let findings = vec![NewFinding {
            rule_id: "agent.audit.file-perms".into(),
            severity: "Medium".into(),
            confidence: "Confirmed".into(),
            title: "Insecure File Permissions".into(),
            endpoint: "/etc/shadow".into(),
            evidence: "Permissions 0644".into(),
            recommendation: "chmod 0600".into(),
        }];

        store
            .complete_agent_job(
                agent.id,
                job.id,
                org.id,
                Some(r#"{"compliant": false}"#),
                &findings,
            )
            .await
            .expect("Complete job must succeed");

        let completed_job = store.get_job(org.id, job.id).await.unwrap().unwrap();
        assert_eq!(completed_job.status, JobStatus::Completed);
        assert!(completed_job.completed_at.is_some());

        let job_findings = store
            .list_findings(org.id, Some(job.id), None)
            .await
            .unwrap();
        assert_eq!(job_findings.len(), 1);

        // Idempotent completion does not fail
        store
            .complete_agent_job(
                agent.id,
                job.id,
                org.id,
                Some(r#"{"compliant": false}"#),
                &findings,
            )
            .await
            .expect("Duplicate complete must be idempotent");

        // Revoke agent
        store
            .update_agent_status(org.id, agent.id, AgentStatus::Revoked)
            .await
            .unwrap();
        let revoked = store
            .get_agent_by_id(org.id, agent.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(revoked.status, AgentStatus::Revoked);
        assert!(revoked.revoked_at.is_some());

        // 5. Test credential rotation fallback and transition invalidation
        let active_agent = store
            .enroll_agent(
                org.id,
                "agent-rot-test",
                "rot-host",
                "1.0.0",
                "hash_initial_key",
                "pk_test",
                "[]",
            )
            .await
            .unwrap();

        let old_hash = "hash_initial_key";
        let new_hash = "hash_rotated_key";
        store
            .rotate_agent_credential(active_agent.id, new_hash)
            .await
            .unwrap();

        // Old key resolves during transition window
        let resolved_old = store.get_agent_by_auth_hash(old_hash).await.unwrap();
        assert!(
            resolved_old.is_some(),
            "Previous key must resolve during transition"
        );

        // New key also resolves
        let resolved_new = store.get_agent_by_auth_hash(new_hash).await.unwrap();
        assert_eq!(resolved_new.unwrap().id, active_agent.id);

        // Heartbeat with new key clears transitional key
        store
            .update_agent_heartbeat(active_agent.id, Utc::now())
            .await
            .unwrap();
        let resolved_old_after_hb = store.get_agent_by_auth_hash(old_hash).await.unwrap();
        assert!(
            resolved_old_after_hb.is_none(),
            "Previous key must be invalidated after heartbeat"
        );

        // 6. Test reclaimed job rejection for stale agents
        let stale_job = store
            .create_job(org.id, None, "10.0.0.99", "host_audit", "standard")
            .await
            .unwrap();
        store
            .claim_next_pending_job(active_agent.id, org.id, 60)
            .await
            .unwrap();

        // Force lease expiration
        let past = Utc::now() - chrono::Duration::seconds(10);
        store
            .conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE assessment_jobs SET lease_expires_at = ?1 WHERE id = ?2",
                params![past.to_rfc3339(), stale_job.id.to_string()],
            )
            .unwrap();

        // Second agent reclaims the expired job
        let second_agent = store
            .enroll_agent(
                org.id,
                "agent-02",
                "host-02",
                "1.0.0",
                "hash_agent2",
                "pk_agent2",
                "[]",
            )
            .await
            .unwrap();
        let reclaimed = store
            .claim_next_pending_job(second_agent.id, org.id, 60)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reclaimed.id, stale_job.id);
        assert_eq!(reclaimed.assigned_agent_id, Some(second_agent.id));

        // Stale active_agent attempts to submit results -> MUST be rejected with Unauthorized
        let stale_submit = store
            .complete_agent_job(active_agent.id, stale_job.id, org.id, None, &findings)
            .await;
        assert!(
            matches!(stale_submit, Err(StoreError::Unauthorized(_))),
            "Stale agent submission must be rejected when job is reclaimed"
        );
    }
}
