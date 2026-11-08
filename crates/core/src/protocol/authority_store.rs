//! Persistent `SQLite` Write-Ahead Logging (WAL) durable Authority store.
//!
//! Provides atomic, multi-connection, and crash-resilient storage for enrollment tokens
//! and cryptographically verified machine registrations under OpenAudit M3 Dimension 4.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rusqlite::{params, Connection, TransactionBehavior};

use crate::protocol::error::ProtocolError;
use crate::protocol::traits::{AuthorityStore, IssuedTokenRecord, KeyMetadata, VerifiedEnrollment};
use crate::protocol::types::{
    CatalogVersion, ChallengeNonce, CounterValue, EnrollmentGeneration, EnrollmentTokenId,
    LifecycleId, MachineId, SrkName, TimestampNs, TransactionId,
};

/// Current authority store schema version.
pub const CURRENT_SCHEMA_VERSION: i64 = 1;

/// Durable `SQLite`-backed implementation of [`AuthorityStore`].
///
/// # Concurrency & Durability
/// - Configured in `SQLite` Write-Ahead Logging (WAL) mode with full synchronous durability
///   (`PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL;`).
/// - Relies on database-level `PRIMARY KEY` constraints and `BEGIN IMMEDIATE` transactions
///   to ensure atomic token consumption and registration insertion across concurrent
///   OS processes sharing the database file on a local filesystem.
/// - Fails closed on database corruption, constraint violations, or storage failures.
pub struct SqliteAuthorityStore {
    conn: Mutex<Connection>,
    path: PathBuf,
}

impl fmt::Debug for SqliteAuthorityStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SqliteAuthorityStore")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl SqliteAuthorityStore {
    /// Opens or initializes a `SQLite` durable authority store at `path`.
    ///
    /// # Errors
    /// Returns [`ProtocolError::StorageUnavailable`] if the database cannot be opened,
    /// fails an integrity check, or has an incompatible future schema version.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, ProtocolError> {
        let path_buf = path.as_ref().to_path_buf();

        let mut conn = Connection::open(&path_buf).map_err(|err| {
            ProtocolError::StorageUnavailable(format!(
                "failed to open SQLite database at '{}': {err}",
                path_buf.display()
            ))
        })?;

        // 1. Configure busy timeout to handle concurrent writers
        conn.busy_timeout(std::time::Duration::from_millis(5000))
            .map_err(|err| {
                ProtocolError::StorageUnavailable(format!(
                    "failed to configure busy timeout: {err}"
                ))
            })?;

        // 2. Validate database integrity if existing (fail-closed, never silently overwrite)
        Self::run_integrity_check(&conn, &path_buf)?;

        // 3. Configure WAL mode and synchronous settings (FULL durability for security enrollments)
        let journal_mode: String = conn
            .query_row("PRAGMA journal_mode = WAL;", [], |row| row.get(0))
            .map_err(|err| {
                ProtocolError::StorageUnavailable(format!("failed to set WAL mode: {err}"))
            })?;

        if !journal_mode.eq_ignore_ascii_case("wal") {
            return Err(ProtocolError::StorageUnavailable(format!(
                "failed to enable WAL journal mode: observed mode '{journal_mode}'"
            )));
        }

        conn.execute_batch(
            "PRAGMA synchronous = FULL;
             PRAGMA foreign_keys = ON;",
        )
        .map_err(|err| {
            ProtocolError::StorageUnavailable(format!("failed to configure SQLite pragmas: {err}"))
        })?;

        // 4. Run schema migration
        Self::apply_migrations(&mut conn)?;

        Ok(Self {
            conn: Mutex::new(conn),
            path: path_buf,
        })
    }

    /// Returns the filesystem path to the underlying `SQLite` database.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the effective `(journal_mode, synchronous_level)` pragmas for this store connection.
    ///
    /// # Errors
    /// Returns [`ProtocolError::StorageUnavailable`] if pragma query fails.
    #[allow(clippy::significant_drop_tightening)]
    pub fn query_pragmas(&self) -> Result<(String, i64), ProtocolError> {
        let conn = self.conn.lock().map_err(|_| {
            ProtocolError::StorageUnavailable("sqlite connection mutex poisoned".to_string())
        })?;

        let mode: String = conn
            .query_row("PRAGMA journal_mode;", [], |row| row.get(0))
            .map_err(|err| {
                ProtocolError::StorageUnavailable(format!("failed to query journal_mode: {err}"))
            })?;

        let sync: i64 = conn
            .query_row("PRAGMA synchronous;", [], |row| row.get(0))
            .map_err(|err| {
                ProtocolError::StorageUnavailable(format!("failed to query synchronous: {err}"))
            })?;

        Ok((mode, sync))
    }

    /// Returns the currently applied database schema version recorded in `authority_schema_migrations`.
    ///
    /// # Errors
    /// Returns [`ProtocolError::StorageUnavailable`] if query fails.
    #[allow(clippy::significant_drop_tightening)]
    pub fn schema_version(&self) -> Result<i64, ProtocolError> {
        let conn = self.conn.lock().map_err(|_| {
            ProtocolError::StorageUnavailable("sqlite connection mutex poisoned".to_string())
        })?;

        let version: i64 = conn
            .query_row(
                "SELECT COALESCE(MAX(version), 0) FROM authority_schema_migrations;",
                [],
                |row| row.get(0),
            )
            .map_err(|err| {
                ProtocolError::StorageUnavailable(format!("failed to query schema version: {err}"))
            })?;

        Ok(version)
    }

    /// Verifies database file integrity using `PRAGMA quick_check`.
    fn run_integrity_check(conn: &Connection, path: &Path) -> Result<(), ProtocolError> {
        let mut stmt = conn.prepare("PRAGMA quick_check;").map_err(|err| {
            ProtocolError::StorageUnavailable(format!("integrity check prep failed: {err}"))
        })?;

        let mut rows = stmt.query([]).map_err(|err| {
            ProtocolError::StorageUnavailable(format!("integrity check query failed: {err}"))
        })?;

        if let Some(row) = rows.next().map_err(|err| {
            ProtocolError::StorageUnavailable(format!("integrity check row error: {err}"))
        })? {
            let status: String = row.get(0).map_err(|err| {
                ProtocolError::StorageUnavailable(format!("integrity read error: {err}"))
            })?;
            if status != "ok" {
                return Err(ProtocolError::StorageUnavailable(format!(
                    "SQLite corruption detected at '{}': {status}",
                    path.display()
                )));
            }
        }
        Ok(())
    }

    /// Initializes schema or upgrades migration version within an immediate transaction.
    fn apply_migrations(conn: &mut Connection) -> Result<(), ProtocolError> {
        // Table: authority_schema_migrations
        conn.execute(
            "CREATE TABLE IF NOT EXISTS authority_schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at_nanos INTEGER NOT NULL
            );",
            [],
        )
        .map_err(|err| {
            ProtocolError::StorageUnavailable(format!(
                "failed to create authority_schema_migrations: {err}"
            ))
        })?;

        let current_version: i64 = conn
            .query_row(
                "SELECT COALESCE(MAX(version), 0) FROM authority_schema_migrations;",
                [],
                |row| row.get(0),
            )
            .map_err(|err| {
                ProtocolError::StorageUnavailable(format!("failed to read schema version: {err}"))
            })?;

        if current_version > CURRENT_SCHEMA_VERSION {
            return Err(ProtocolError::StorageUnavailable(format!(
                "incompatible schema version {current_version} (maximum supported {CURRENT_SCHEMA_VERSION})"
            )));
        }

        if current_version < 1 {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|err| {
                    ProtocolError::StorageUnavailable(format!(
                        "failed to begin migration transaction: {err}"
                    ))
                })?;

            tx.execute_batch(
                "CREATE TABLE IF NOT EXISTS enrollment_tokens (
                    token_id BLOB PRIMARY KEY,
                    machine_id BLOB NOT NULL,
                    expected_nonce BLOB NOT NULL,
                    expected_generation INTEGER NOT NULL,
                    expires_at_nanos INTEGER NOT NULL,
                    consumed INTEGER NOT NULL DEFAULT 0,
                    consumed_at_nanos INTEGER
                );

                CREATE INDEX IF NOT EXISTS idx_enrollment_tokens_machine
                    ON enrollment_tokens (machine_id);

                CREATE TABLE IF NOT EXISTS registered_machines (
                    machine_id BLOB PRIMARY KEY,
                    token_id BLOB NOT NULL,
                    tx_id BLOB NOT NULL,
                    lifecycle_id BLOB NOT NULL,
                    name_srk BLOB NOT NULL,
                    generation INTEGER NOT NULL,
                    counter_base INTEGER NOT NULL,
                    catalog_base INTEGER NOT NULL,
                    key_type TEXT NOT NULL,
                    key_modulus_bits INTEGER,
                    key_exponent INTEGER,
                    key_curve_name TEXT,
                    ek_pub_spki_der BLOB NOT NULL,
                    enrolled_at_nanos INTEGER NOT NULL,
                    FOREIGN KEY (token_id) REFERENCES enrollment_tokens (token_id)
                );

                INSERT INTO authority_schema_migrations (version, applied_at_nanos)
                    VALUES (1, 0);",
            )
            .map_err(|err| {
                ProtocolError::StorageUnavailable(format!(
                    "failed to apply authority schema version 1: {err}"
                ))
            })?;

            tx.commit().map_err(|err| {
                ProtocolError::StorageUnavailable(format!(
                    "failed to commit authority migration transaction: {err}"
                ))
            })?;
        }

        Ok(())
    }
}

impl AuthorityStore for SqliteAuthorityStore {
    #[allow(clippy::significant_drop_tightening)]
    fn insert_token(&self, token: &IssuedTokenRecord) -> Result<(), ProtocolError> {
        let conn = self.conn.lock().map_err(|_| {
            ProtocolError::StorageUnavailable("sqlite connection mutex poisoned".to_string())
        })?;

        conn.execute(
            "INSERT INTO enrollment_tokens (
                token_id, machine_id, expected_nonce, expected_generation,
                expires_at_nanos, consumed, consumed_at_nanos
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7);",
            params![
                token.token_id.as_bytes().as_slice(),
                token.machine_id.as_bytes().as_slice(),
                token.expected_nonce.as_bytes().as_slice(),
                i64::from(token.expected_generation.as_u32()),
                token.expires_at.as_nanos(),
                i64::from(token.consumed),
                Option::<i64>::None,
            ],
        )
        .map_err(|err| {
            ProtocolError::StorageUnavailable(format!(
                "failed to insert enrollment token '{}': {err}",
                token.token_id
            ))
        })?;

        Ok(())
    }

    #[allow(clippy::significant_drop_tightening)]
    fn get_token(
        &self,
        token_id: &EnrollmentTokenId,
    ) -> Result<Option<IssuedTokenRecord>, ProtocolError> {
        let conn = self.conn.lock().map_err(|_| {
            ProtocolError::StorageUnavailable("sqlite connection mutex poisoned".to_string())
        })?;

        let mut stmt = conn
            .prepare(
                "SELECT token_id, machine_id, expected_nonce, expected_generation,
                        expires_at_nanos, consumed
                 FROM enrollment_tokens WHERE token_id = ?1;",
            )
            .map_err(|err| {
                ProtocolError::StorageUnavailable(format!("failed to prepare token query: {err}"))
            })?;

        let mut rows = stmt
            .query(params![token_id.as_bytes().as_slice()])
            .map_err(|err| {
                ProtocolError::StorageUnavailable(format!("token query failed: {err}"))
            })?;

        if let Some(row) = rows.next().map_err(|err| {
            ProtocolError::StorageUnavailable(format!("token row read error: {err}"))
        })? {
            let tid_bytes: Vec<u8> = row
                .get(0)
                .map_err(|e| ProtocolError::StorageUnavailable(e.to_string()))?;
            let mid_bytes: Vec<u8> = row
                .get(1)
                .map_err(|e| ProtocolError::StorageUnavailable(e.to_string()))?;
            let nonce_bytes: Vec<u8> = row
                .get(2)
                .map_err(|e| ProtocolError::StorageUnavailable(e.to_string()))?;
            let gen_raw: i64 = row
                .get(3)
                .map_err(|e| ProtocolError::StorageUnavailable(e.to_string()))?;
            let exp_nanos: i64 = row
                .get(4)
                .map_err(|e| ProtocolError::StorageUnavailable(e.to_string()))?;
            let consumed_raw: i64 = row
                .get(5)
                .map_err(|e| ProtocolError::StorageUnavailable(e.to_string()))?;

            let tid_arr: [u8; 16] = tid_bytes.try_into().map_err(|_| {
                ProtocolError::StorageUnavailable("corrupted token_id byte length".to_string())
            })?;
            let mid_arr: [u8; 16] = mid_bytes.try_into().map_err(|_| {
                ProtocolError::StorageUnavailable("corrupted machine_id byte length".to_string())
            })?;
            let nonce_arr: [u8; 32] = nonce_bytes.try_into().map_err(|_| {
                ProtocolError::StorageUnavailable(
                    "corrupted expected_nonce byte length".to_string(),
                )
            })?;
            let gen_u32 = u32::try_from(gen_raw).map_err(|_| {
                ProtocolError::StorageUnavailable("generation overflowed u32".to_string())
            })?;

            Ok(Some(IssuedTokenRecord {
                token_id: EnrollmentTokenId::from_bytes(tid_arr),
                machine_id: MachineId::from_bytes(mid_arr),
                expected_nonce: ChallengeNonce::from_bytes(nonce_arr),
                expected_generation: EnrollmentGeneration::from_u32(gen_u32),
                expires_at: TimestampNs::from_nanos(exp_nanos),
                consumed: consumed_raw != 0,
            }))
        } else {
            Ok(None)
        }
    }

    #[allow(
        clippy::too_many_lines,
        clippy::significant_drop_tightening,
        clippy::type_complexity
    )]
    fn commit_enrollment(
        &self,
        token_id: &EnrollmentTokenId,
        now: TimestampNs,
        registration: &VerifiedEnrollment,
    ) -> Result<(), ProtocolError> {
        let mut conn = self.conn.lock().map_err(|_| {
            ProtocolError::StorageUnavailable("sqlite connection mutex poisoned".to_string())
        })?;

        // Explicit IMMEDIATE transaction for atomic token consumption and registration commit
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|err| {
                ProtocolError::StorageUnavailable(format!(
                    "failed to begin immediate enrollment transaction: {err}"
                ))
            })?;

        // 1. Re-check token existence and status under write lock
        let token_data: Option<(Vec<u8>, Vec<u8>, i64, i64, i64)> = {
            let mut stmt = tx
                .prepare(
                    "SELECT machine_id, expected_nonce, expected_generation, expires_at_nanos, consumed
                     FROM enrollment_tokens WHERE token_id = ?1;",
                )
                .map_err(|err| {
                    ProtocolError::StorageUnavailable(format!("token check prep failed: {err}"))
                })?;

            let mut rows = stmt
                .query(params![token_id.as_bytes().as_slice()])
                .map_err(|err| {
                    ProtocolError::StorageUnavailable(format!("token check query failed: {err}"))
                })?;

            if let Some(r) = rows.next().map_err(|err| {
                ProtocolError::StorageUnavailable(format!("token check row fetch failed: {err}"))
            })? {
                Some((
                    r.get(0)
                        .map_err(|e| ProtocolError::StorageUnavailable(e.to_string()))?,
                    r.get(1)
                        .map_err(|e| ProtocolError::StorageUnavailable(e.to_string()))?,
                    r.get(2)
                        .map_err(|e| ProtocolError::StorageUnavailable(e.to_string()))?,
                    r.get(3)
                        .map_err(|e| ProtocolError::StorageUnavailable(e.to_string()))?,
                    r.get(4)
                        .map_err(|e| ProtocolError::StorageUnavailable(e.to_string()))?,
                ))
            } else {
                None
            }
        };

        let (mid_bytes, nonce_bytes, gen_raw, exp_nanos, consumed_raw) =
            token_data.ok_or_else(|| {
                ProtocolError::CryptoError(format!(
                    "enrollment token '{token_id}' not found in authority registry"
                ))
            })?;

        if consumed_raw != 0 {
            return Err(ProtocolError::CryptoError(format!(
                "enrollment token '{token_id}' has already been consumed"
            )));
        }

        if now.as_nanos() > exp_nanos {
            return Err(ProtocolError::CryptoError(format!(
                "enrollment token '{token_id}' has expired at {exp_nanos} (now: {})",
                now.as_nanos()
            )));
        }

        // Verify identity bindings
        if mid_bytes.as_slice() != registration.machine_id.as_bytes().as_slice() {
            return Err(ProtocolError::CryptoError(format!(
                "machine identity mismatch: transcript specifies '{}'",
                registration.machine_id
            )));
        }

        let gen_u32 = u32::try_from(gen_raw).map_err(|_| {
            ProtocolError::StorageUnavailable("generation overflowed u32".to_string())
        })?;
        if gen_u32 != registration.generation.as_u32() {
            return Err(ProtocolError::CryptoError(format!(
                "enrollment generation mismatch: transcript specifies '{}', token authorized '{}'",
                registration.generation.as_u32(),
                gen_u32
            )));
        }

        let _ = nonce_bytes; // ChallengeNonce asserted before transaction

        // 2. Mark token as consumed
        let rows_affected = tx
            .execute(
                "UPDATE enrollment_tokens
                 SET consumed = 1, consumed_at_nanos = ?1
                 WHERE token_id = ?2 AND consumed = 0;",
                params![now.as_nanos(), token_id.as_bytes().as_slice()],
            )
            .map_err(|err| {
                ProtocolError::StorageUnavailable(format!("failed to consume token: {err}"))
            })?;

        if rows_affected != 1 {
            return Err(ProtocolError::CryptoError(format!(
                "enrollment token '{token_id}' has already been consumed concurrently"
            )));
        }

        // 3. Insert machine registration record (fails if duplicate machine_id exists)
        let (key_type, modulus_bits, exponent, curve_name) = match &registration.key_metadata {
            KeyMetadata::Rsa {
                modulus_bits,
                public_exponent,
            } => (
                "rsa",
                Some(i64::try_from(*modulus_bits).map_err(|_| {
                    ProtocolError::StorageUnavailable("modulus_bits overflowed i64".to_string())
                })?),
                Some(i64::try_from(*public_exponent).map_err(|_| {
                    ProtocolError::StorageUnavailable("public_exponent overflowed i64".to_string())
                })?),
                None::<String>,
            ),
            KeyMetadata::Ecc { curve_name } => ("ecc", None, None, Some((*curve_name).to_string())),
        };

        let counter_i64 = i64::try_from(registration.counter_base.as_u64()).map_err(|_| {
            ProtocolError::StorageUnavailable("counter_base overflowed i64".to_string())
        })?;
        let catalog_i64 = i64::try_from(registration.catalog_base.as_u64()).map_err(|_| {
            ProtocolError::StorageUnavailable("catalog_base overflowed i64".to_string())
        })?;

        tx.execute(
            "INSERT INTO registered_machines (
                machine_id, token_id, tx_id, lifecycle_id, name_srk,
                generation, counter_base, catalog_base,
                key_type, key_modulus_bits, key_exponent, key_curve_name,
                ek_pub_spki_der, enrolled_at_nanos
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14);",
            params![
                registration.machine_id.as_bytes().as_slice(),
                registration.token_id.as_bytes().as_slice(),
                registration.tx_id.as_bytes().as_slice(),
                registration.lifecycle_id.as_bytes().as_slice(),
                registration.name_srk.as_bytes().as_slice(),
                i64::from(registration.generation.as_u32()),
                counter_i64,
                catalog_i64,
                key_type,
                modulus_bits,
                exponent,
                curve_name,
                registration.ek_pub_spki_der.as_slice(),
                registration.enrolled_at.as_nanos(),
            ],
        )
        .map_err(|err| {
            // Note: tx is dropped without commit, automatically rolling back token consumption!
            ProtocolError::StorageUnavailable(format!(
                "machine registration insert failed (machine '{}' may already be registered): {err}",
                registration.machine_id
            ))
        })?;

        // 4. Commit atomic transaction
        tx.commit().map_err(|err| {
            ProtocolError::StorageUnavailable(format!(
                "failed to commit enrollment transaction: {err}"
            ))
        })?;

        Ok(())
    }

    #[allow(clippy::too_many_lines, clippy::significant_drop_tightening)]
    fn get_registered_machine(
        &self,
        machine_id: &MachineId,
    ) -> Result<Option<VerifiedEnrollment>, ProtocolError> {
        let conn = self.conn.lock().map_err(|_| {
            ProtocolError::StorageUnavailable("sqlite connection mutex poisoned".to_string())
        })?;

        let mut stmt = conn
            .prepare(
                "SELECT machine_id, token_id, tx_id, lifecycle_id, name_srk,
                        generation, counter_base, catalog_base,
                        key_type, key_modulus_bits, key_exponent, key_curve_name,
                        ek_pub_spki_der, enrolled_at_nanos
                 FROM registered_machines WHERE machine_id = ?1;",
            )
            .map_err(|err| {
                ProtocolError::StorageUnavailable(format!(
                    "failed to prepare registered machine query: {err}"
                ))
            })?;

        let mut rows = stmt
            .query(params![machine_id.as_bytes().as_slice()])
            .map_err(|err| {
                ProtocolError::StorageUnavailable(format!("machine query failed: {err}"))
            })?;

        if let Some(row) = rows.next().map_err(|err| {
            ProtocolError::StorageUnavailable(format!("machine row read error: {err}"))
        })? {
            let mid_bytes: Vec<u8> = row
                .get(0)
                .map_err(|e| ProtocolError::StorageUnavailable(e.to_string()))?;
            let tid_bytes: Vec<u8> = row
                .get(1)
                .map_err(|e| ProtocolError::StorageUnavailable(e.to_string()))?;
            let tx_bytes: Vec<u8> = row
                .get(2)
                .map_err(|e| ProtocolError::StorageUnavailable(e.to_string()))?;
            let life_bytes: Vec<u8> = row
                .get(3)
                .map_err(|e| ProtocolError::StorageUnavailable(e.to_string()))?;
            let srk_bytes: Vec<u8> = row
                .get(4)
                .map_err(|e| ProtocolError::StorageUnavailable(e.to_string()))?;
            let gen_raw: i64 = row
                .get(5)
                .map_err(|e| ProtocolError::StorageUnavailable(e.to_string()))?;
            let counter_raw: i64 = row
                .get(6)
                .map_err(|e| ProtocolError::StorageUnavailable(e.to_string()))?;
            let catalog_raw: i64 = row
                .get(7)
                .map_err(|e| ProtocolError::StorageUnavailable(e.to_string()))?;
            let key_type: String = row
                .get(8)
                .map_err(|e| ProtocolError::StorageUnavailable(e.to_string()))?;
            let modulus_bits: Option<i64> = row
                .get(9)
                .map_err(|e| ProtocolError::StorageUnavailable(e.to_string()))?;
            let exponent: Option<i64> = row
                .get(10)
                .map_err(|e| ProtocolError::StorageUnavailable(e.to_string()))?;
            let curve_name: Option<String> = row
                .get(11)
                .map_err(|e| ProtocolError::StorageUnavailable(e.to_string()))?;
            let ek_pub_der: Vec<u8> = row
                .get(12)
                .map_err(|e| ProtocolError::StorageUnavailable(e.to_string()))?;
            let enrolled_nanos: i64 = row
                .get(13)
                .map_err(|e| ProtocolError::StorageUnavailable(e.to_string()))?;

            let mid_arr: [u8; 16] = mid_bytes.try_into().map_err(|_| {
                ProtocolError::StorageUnavailable("corrupted machine_id length".to_string())
            })?;
            let tid_arr: [u8; 16] = tid_bytes.try_into().map_err(|_| {
                ProtocolError::StorageUnavailable("corrupted token_id length".to_string())
            })?;
            let tx_arr: [u8; 16] = tx_bytes.try_into().map_err(|_| {
                ProtocolError::StorageUnavailable("corrupted tx_id length".to_string())
            })?;
            let life_arr: [u8; 32] = life_bytes.try_into().map_err(|_| {
                ProtocolError::StorageUnavailable("corrupted lifecycle_id length".to_string())
            })?;
            let srk_arr: [u8; 34] = srk_bytes.try_into().map_err(|_| {
                ProtocolError::StorageUnavailable("corrupted srk_name length".to_string())
            })?;

            let gen_u32 = u32::try_from(gen_raw).map_err(|_| {
                ProtocolError::StorageUnavailable("generation overflowed u32".to_string())
            })?;
            let counter_u64 = u64::try_from(counter_raw).map_err(|_| {
                ProtocolError::StorageUnavailable("counter_base negative".to_string())
            })?;
            let catalog_u64 = u64::try_from(catalog_raw).map_err(|_| {
                ProtocolError::StorageUnavailable("catalog_base negative".to_string())
            })?;

            let key_metadata = match key_type.as_str() {
                "rsa" => {
                    let bits = modulus_bits.ok_or_else(|| {
                        ProtocolError::StorageUnavailable("missing rsa modulus_bits".to_string())
                    })?;
                    let exp = exponent.ok_or_else(|| {
                        ProtocolError::StorageUnavailable("missing rsa exponent".to_string())
                    })?;
                    KeyMetadata::Rsa {
                        modulus_bits: usize::try_from(bits).map_err(|_| {
                            ProtocolError::StorageUnavailable("invalid modulus bits".to_string())
                        })?,
                        public_exponent: u64::try_from(exp).map_err(|_| {
                            ProtocolError::StorageUnavailable("invalid exponent".to_string())
                        })?,
                    }
                }
                "ecc" => {
                    let curve = curve_name.ok_or_else(|| {
                        ProtocolError::StorageUnavailable("missing ecc curve_name".to_string())
                    })?;
                    let static_curve: &'static str = match curve.as_str() {
                        "secp256r1" => "secp256r1",
                        "secp384r1" => "secp384r1",
                        "secp521r1" => "secp521r1",
                        _ => Box::leak(curve.into_boxed_str()),
                    };
                    KeyMetadata::Ecc {
                        curve_name: static_curve,
                    }
                }
                other => {
                    return Err(ProtocolError::StorageUnavailable(format!(
                        "unknown key_type '{other}' in registered_machines"
                    )))
                }
            };

            Ok(Some(VerifiedEnrollment {
                machine_id: MachineId::from_bytes(mid_arr),
                token_id: EnrollmentTokenId::from_bytes(tid_arr),
                tx_id: TransactionId::from_bytes(tx_arr),
                lifecycle_id: LifecycleId::from_bytes(life_arr),
                name_srk: SrkName::from_bytes(srk_arr),
                generation: EnrollmentGeneration::from_u32(gen_u32),
                counter_base: CounterValue::from_u64(counter_u64),
                catalog_base: CatalogVersion::from_u64(catalog_u64),
                key_metadata,
                ek_pub_spki_der: ek_pub_der,
                enrolled_at: TimestampNs::from_nanos(enrolled_nanos),
            }))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::process::{Command, Stdio};
    use std::thread;
    use tempfile::tempdir;

    fn make_test_token(machine_id: MachineId) -> IssuedTokenRecord {
        IssuedTokenRecord {
            token_id: EnrollmentTokenId::new(),
            machine_id,
            expected_nonce: ChallengeNonce::from_bytes([0x42; 32]),
            expected_generation: EnrollmentGeneration::from_u32(1),
            expires_at: TimestampNs::from_nanos(2_000_000_000),
            consumed: false,
        }
    }

    fn make_test_registration(
        machine_id: MachineId,
        token_id: EnrollmentTokenId,
    ) -> VerifiedEnrollment {
        VerifiedEnrollment {
            machine_id,
            token_id,
            tx_id: TransactionId::new(),
            lifecycle_id: LifecycleId::from_bytes([0x77; 32]),
            name_srk: SrkName::from_bytes([0x88; 34]),
            generation: EnrollmentGeneration::from_u32(1),
            counter_base: CounterValue::from_u64(10),
            catalog_base: CatalogVersion::from_u64(2),
            key_metadata: KeyMetadata::Rsa {
                modulus_bits: 2048,
                public_exponent: 65537,
            },
            ek_pub_spki_der: vec![0x30, 0x82, 0x01, 0x22, 0xAA, 0xBB],
            enrolled_at: TimestampNs::from_nanos(1_000_000_000),
        }
    }

    #[test]
    fn test_token_persistence_across_reconstruction() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("authority.db");
        let token = make_test_token(MachineId::new());

        // 1. Insert token in first instance
        {
            let store = SqliteAuthorityStore::open(&db_path).unwrap();
            store.insert_token(&token).unwrap();
            let retrieved = store.get_token(&token.token_id).unwrap().unwrap();
            assert_eq!(retrieved, token);
        }

        // 2. Drop and reconstruct store from disk
        {
            let store = SqliteAuthorityStore::open(&db_path).unwrap();
            let retrieved = store.get_token(&token.token_id).unwrap().unwrap();
            assert_eq!(retrieved, token);
            assert!(!retrieved.consumed);
        }
    }

    #[test]
    fn test_registered_machine_persistence_across_reconstruction() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("authority.db");
        let machine_id = MachineId::new();
        let token = make_test_token(machine_id);
        let reg = make_test_registration(machine_id, token.token_id);
        let now = TimestampNs::from_nanos(1_000_000_000);

        // 1. Commit enrollment
        {
            let store = SqliteAuthorityStore::open(&db_path).unwrap();
            store.insert_token(&token).unwrap();
            store.commit_enrollment(&token.token_id, now, &reg).unwrap();
            let stored = store.get_registered_machine(&machine_id).unwrap().unwrap();
            assert_eq!(stored.machine_id, machine_id);
            assert_eq!(stored.key_metadata, reg.key_metadata);
            assert_eq!(stored.ek_pub_spki_der, reg.ek_pub_spki_der);
        }

        // 2. Reconstruct from disk and verify persistence
        {
            let store = SqliteAuthorityStore::open(&db_path).unwrap();
            let stored = store.get_registered_machine(&machine_id).unwrap().unwrap();
            assert_eq!(stored.machine_id, machine_id);
            assert_eq!(stored.token_id, token.token_id);
            assert_eq!(stored.tx_id, reg.tx_id);
            assert_eq!(stored.lifecycle_id, reg.lifecycle_id);
            assert_eq!(stored.name_srk, reg.name_srk);
            assert_eq!(stored.generation, reg.generation);
            assert_eq!(stored.counter_base, reg.counter_base);
            assert_eq!(stored.catalog_base, reg.catalog_base);
            assert_eq!(stored.key_metadata, reg.key_metadata);
            assert_eq!(stored.ek_pub_spki_der, reg.ek_pub_spki_der);
            assert_eq!(stored.enrolled_at, reg.enrolled_at);

            let token_after = store.get_token(&token.token_id).unwrap().unwrap();
            assert!(token_after.consumed);
        }
    }

    #[test]
    fn test_expired_token_rejection() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("authority.db");
        let store = SqliteAuthorityStore::open(&db_path).unwrap();

        let machine_id = MachineId::new();
        let mut token = make_test_token(machine_id);
        token.expires_at = TimestampNs::from_nanos(1_000_000_000);
        store.insert_token(&token).unwrap();

        let reg = make_test_registration(machine_id, token.token_id);
        let now_expired = TimestampNs::from_nanos(1_000_000_001);

        let res = store.commit_enrollment(&token.token_id, now_expired, &reg);
        assert!(matches!(res, Err(ProtocolError::CryptoError(msg)) if msg.contains("expired")));

        // Token must remain unconsumed in DB
        let token_db = store.get_token(&token.token_id).unwrap().unwrap();
        assert!(!token_db.consumed);
    }

    #[test]
    fn test_unknown_and_already_consumed_token_rejection() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("authority.db");
        let store = SqliteAuthorityStore::open(&db_path).unwrap();

        let machine_id = MachineId::new();
        let unknown_token_id = EnrollmentTokenId::new();
        let reg = make_test_registration(machine_id, unknown_token_id);
        let now = TimestampNs::from_nanos(1_000_000_000);

        // Unknown token fails closed
        let res_unknown = store.commit_enrollment(&unknown_token_id, now, &reg);
        assert!(
            matches!(res_unknown, Err(ProtocolError::CryptoError(msg)) if msg.contains("not found"))
        );

        // Consume valid token
        let token = make_test_token(machine_id);
        store.insert_token(&token).unwrap();
        let reg_valid = make_test_registration(machine_id, token.token_id);
        store
            .commit_enrollment(&token.token_id, now, &reg_valid)
            .unwrap();

        // Second consumption attempt fails closed
        let res_duplicate = store.commit_enrollment(&token.token_id, now, &reg_valid);
        assert!(
            matches!(res_duplicate, Err(ProtocolError::CryptoError(msg)) if msg.contains("already been consumed"))
        );
    }

    #[test]
    fn test_registration_failure_rolls_back_token_consumption() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("authority.db");
        let store = SqliteAuthorityStore::open(&db_path).unwrap();

        let machine_id = MachineId::new();
        let token1 = make_test_token(machine_id);
        let reg1 = make_test_registration(machine_id, token1.token_id);
        let now = TimestampNs::from_nanos(1_000_000_000);

        // 1. Initial valid enrollment succeeds
        store.insert_token(&token1).unwrap();
        store
            .commit_enrollment(&token1.token_id, now, &reg1)
            .unwrap();

        // 2. Second token issued for same machine
        let token2 = make_test_token(machine_id);
        store.insert_token(&token2).unwrap();
        let reg2 = make_test_registration(machine_id, token2.token_id);

        // 3. Attempting to commit enrollment with token2 triggers PRIMARY KEY constraint violation
        let res_dupe = store.commit_enrollment(&token2.token_id, now, &reg2);
        assert!(
            matches!(res_dupe, Err(ProtocolError::StorageUnavailable(msg)) if msg.contains("machine registration insert failed"))
        );

        // 4. CRITICAL ATOMICITY CHECK: token2 MUST REMAIN UNCONSUMED because the transaction rolled back!
        let token2_db = store.get_token(&token2.token_id).unwrap().unwrap();
        assert!(
            !token2_db.consumed,
            "failed registration insert MUST roll back token consumption!"
        );
    }

    #[test]
    fn test_concurrent_duplicate_enrollment_separate_connections() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("authority.db");
        let init_store = SqliteAuthorityStore::open(&db_path).unwrap();

        let machine_id = MachineId::new();
        let token = make_test_token(machine_id);
        init_store.insert_token(&token).unwrap();
        drop(init_store);

        let token_id = token.token_id;
        let now = TimestampNs::from_nanos(1_000_000_000);

        let mut handles = Vec::new();
        for _ in 0..8 {
            let path_clone = db_path.clone();
            handles.push(thread::spawn(move || {
                let store = SqliteAuthorityStore::open(&path_clone).unwrap();
                let reg = make_test_registration(machine_id, token_id);
                store.commit_enrollment(&token_id, now, &reg)
            }));
        }

        let mut successes = 0;
        let mut rejections = 0;
        for handle in handles {
            match handle.join().unwrap() {
                Ok(()) => successes += 1,
                Err(_) => rejections += 1,
            }
        }

        assert_eq!(
            successes, 1,
            "exactly one connection must successfully consume the token"
        );
        assert_eq!(
            rejections, 7,
            "seven concurrent connections must be rejected"
        );

        let verify_store = SqliteAuthorityStore::open(&db_path).unwrap();
        let token_db = verify_store.get_token(&token_id).unwrap().unwrap();
        assert!(token_db.consumed);
    }

    #[test]
    fn test_authority_child_process_worker_entry_point() {
        let Ok(mode) = std::env::var("OPENAUDIT_AUTHORITY_CHILD_MODE") else {
            return;
        };
        let db_path =
            std::env::var("OPENAUDIT_AUTHORITY_DB_PATH").expect("OPENAUDIT_AUTHORITY_DB_PATH");
        let store = SqliteAuthorityStore::open(&db_path).expect("open store in child");

        if mode == "race_enrollment" {
            let token_id_str = std::env::var("OPENAUDIT_TOKEN_ID").expect("OPENAUDIT_TOKEN_ID");
            let token_id = EnrollmentTokenId::parse(&token_id_str).expect("parse token_id");
            let machine_id_str =
                std::env::var("OPENAUDIT_MACHINE_ID").expect("OPENAUDIT_MACHINE_ID");
            let machine_id = MachineId::parse(&machine_id_str).expect("parse machine_id");
            let now = TimestampNs::from_nanos(1_000_000_000);

            let reg = make_test_registration(machine_id, token_id);
            if store.commit_enrollment(&token_id, now, &reg).is_ok() {
                println!("CHILD_ENROLLMENT_SUCCESS");
                let _ = std::io::stdout().flush();
                std::process::exit(0);
            } else {
                println!("CHILD_ENROLLMENT_REJECTED");
                let _ = std::io::stdout().flush();
                std::process::exit(42);
            }
        }
    }

    #[test]
    fn test_cross_process_duplicate_enrollment() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("authority.db");
        let store = SqliteAuthorityStore::open(&db_path).unwrap();

        let machine_id = MachineId::new();
        let token = make_test_token(machine_id);
        store.insert_token(&token).unwrap();
        drop(store);

        let token_str = token.token_id.to_string();
        let mach_str = machine_id.to_string();

        let mut child1 = Command::new(std::env::current_exe().unwrap())
            .args([
                "protocol::authority_store::tests::test_authority_child_process_worker_entry_point",
                "--exact",
                "--nocapture",
            ])
            .env("OPENAUDIT_AUTHORITY_CHILD_MODE", "race_enrollment")
            .env("OPENAUDIT_AUTHORITY_DB_PATH", db_path.to_str().unwrap())
            .env("OPENAUDIT_TOKEN_ID", &token_str)
            .env("OPENAUDIT_MACHINE_ID", &mach_str)
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn child 1");

        let mut child2 = Command::new(std::env::current_exe().unwrap())
            .args([
                "protocol::authority_store::tests::test_authority_child_process_worker_entry_point",
                "--exact",
                "--nocapture",
            ])
            .env("OPENAUDIT_AUTHORITY_CHILD_MODE", "race_enrollment")
            .env("OPENAUDIT_AUTHORITY_DB_PATH", db_path.to_str().unwrap())
            .env("OPENAUDIT_TOKEN_ID", &token_str)
            .env("OPENAUDIT_MACHINE_ID", &mach_str)
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn child 2");

        let status1 = child1.wait().expect("wait child 1");
        let status2 = child2.wait().expect("wait child 2");

        let codes = [status1.code().unwrap_or(-1), status2.code().unwrap_or(-1)];
        assert!(
            codes == [0, 42] || codes == [42, 0],
            "cross-process mutual exclusion must allow exactly one winner (0) and one rejected (42); observed codes {codes:?}"
        );

        let verify_store = SqliteAuthorityStore::open(&db_path).unwrap();
        let token_db = verify_store.get_token(&token.token_id).unwrap().unwrap();
        assert!(token_db.consumed);
        assert!(verify_store
            .get_registered_machine(&machine_id)
            .unwrap()
            .is_some());
    }

    #[test]
    fn test_database_corruption_and_unavailable_fails_closed() {
        let dir = tempdir().unwrap();
        let corrupt_path = dir.path().join("corrupted.db");
        std::fs::write(&corrupt_path, b"not a valid sqlite database file").unwrap();

        let res = SqliteAuthorityStore::open(&corrupt_path);
        assert!(
            matches!(res, Err(ProtocolError::StorageUnavailable(msg)) if msg.contains("SQLite corruption detected") || msg.contains("file is not a database"))
        );
    }

    #[test]
    fn test_schema_migration_and_query_pragmas() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("authority.db");
        let store = SqliteAuthorityStore::open(&db_path).unwrap();

        assert_eq!(store.schema_version().unwrap(), CURRENT_SCHEMA_VERSION);
        let (mode, sync) = store.query_pragmas().unwrap();
        assert_eq!(mode.to_lowercase(), "wal");
        assert_eq!(sync, 2); // PRAGMA synchronous = FULL
    }
}
