//! SQLite control-plane storage implementation for local self-hosting and deterministic testing.

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::sync::Mutex;
use uuid::Uuid;

use super::models::{
    AssessmentFinding, AssessmentJob, AssessmentSchedule, Asset, JobStatus, NewFinding,
    Organization, Role, User,
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
                FOREIGN KEY(org_id) REFERENCES organizations(id) ON DELETE CASCADE,
                FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE SET NULL
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
            ",
        )
        .map_err(|e| StoreError::Database(format!("schema migration failed: {e}")))?;

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
                        summary_json, error_message, started_at, completed_at, created_at
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
                        summary_json, error_message, started_at, completed_at, created_at
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
}
