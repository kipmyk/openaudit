//! Persistent `SQLite` Write-Ahead Logging (WAL) durable replay store.
//!
//! Provides atomic, multi-connection, and crash-resilient replay protection
//! for client requests under Dimension 4 outbox retrieval.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rusqlite::{params, Connection, ErrorCode, TransactionBehavior};

use crate::protocol::error::ProtocolError;
use crate::protocol::traits::ReplayStore;
use crate::protocol::types::{MachineId, RequestId, TimestampNs};

/// Current database schema version.
pub const CURRENT_SCHEMA_VERSION: i64 = 1;

/// Durable `SQLite`-backed implementation of [`ReplayStore`].
///
/// # Concurrency & Durability
/// - Configured in `SQLite` Write-Ahead Logging (WAL) mode with full synchronous durability
///   (`PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL;`).
/// - Relies on database-level `PRIMARY KEY (machine_id, req_id)` constraints and
///   `BEGIN IMMEDIATE` transactions to prevent duplicate insertions across
///   concurrent OS processes and distinct database connections.
/// - Fails closed on database corruption, schema divergence, or storage failure.
pub struct SqliteReplayStore {
    conn: Mutex<Connection>,
    path: PathBuf,
}

impl fmt::Debug for SqliteReplayStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SqliteReplayStore")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl SqliteReplayStore {
    /// Opens or initializes a `SQLite` durable replay store at `path`.
    ///
    /// # Errors
    /// - Returns [`ProtocolError::StorageUnavailable`] if the database cannot be opened,
    ///   fails an integrity check, or has an incompatible future schema version.
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

        // 3. Configure WAL mode and synchronous settings (FULL durability for security replay protection)
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
    /// - `journal_mode`: Returns the `SQLite` journal mode (expected `"wal"`).
    /// - `synchronous_level`: Returns the `SQLite` synchronous level (expected `2` for `FULL`).
    ///
    /// # Errors
    /// Returns [`ProtocolError::StorageUnavailable`] if the pragma query fails.
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

    /// Returns the currently applied database schema version recorded in `schema_migrations`.
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
                "SELECT COALESCE(MAX(version), 0) FROM schema_migrations;",
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
        // Table: schema_migrations
        conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at_nanos INTEGER NOT NULL
            );",
            [],
        )
        .map_err(|err| {
            ProtocolError::StorageUnavailable(format!("failed to create schema_migrations: {err}"))
        })?;

        let current_version: i64 = conn
            .query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_migrations;",
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
            // Apply version 1 migration inside an explicit immediate transaction
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|err| {
                    ProtocolError::StorageUnavailable(format!(
                        "failed to begin migration transaction: {err}"
                    ))
                })?;

            tx.execute_batch(
                "CREATE TABLE replay_cache (
                    machine_id BLOB NOT NULL,
                    req_id BLOB NOT NULL,
                    t_req_nanos INTEGER NOT NULL,
                    expires_at_nanos INTEGER NOT NULL,
                    consumed_at_nanos INTEGER NOT NULL,
                    PRIMARY KEY (machine_id, req_id)
                );
                CREATE INDEX idx_replay_cache_expires
                    ON replay_cache (expires_at_nanos);
                INSERT INTO schema_migrations (version, applied_at_nanos)
                    VALUES (1, 0);",
            )
            .map_err(|err| {
                ProtocolError::StorageUnavailable(format!(
                    "failed to apply schema version 1: {err}"
                ))
            })?;

            tx.commit().map_err(|err| {
                ProtocolError::StorageUnavailable(format!(
                    "failed to commit migration transaction: {err}"
                ))
            })?;
        }

        Ok(())
    }

    /// Prunes expired replay records whose `expires_at_nanos` is less than or equal to `now`.
    ///
    /// # Exact Boundary Semantics
    /// For a record with expiration timestamp `E = expires_at_nanos`:
    /// - At `now = E - 1`: Record is active and NOT pruned (0 deleted).
    /// - At `now = E`: Record has reached its expiry and IS pruned (deleted).
    /// - At `now = E + 1`: Record has exceeded its expiry and IS pruned (deleted).
    ///
    /// # Security Invariant
    /// Because `E = T_req + 120s` and the request acceptance window is `+/- 60s`,
    /// any record eligible for pruning (`now >= E`) corresponds to a request whose
    /// timestamp `T_req` is at least 120 seconds in the past (`now - T_req >= 120s`).
    /// Even with maximum negative clock skew, such a request could never pass the
    /// 60-second acceptance check (`diff > 60s`). Thus, no request can be pruned
    /// while still potentially acceptable.
    ///
    /// # Errors
    /// Returns [`ProtocolError::StorageUnavailable`] if database execution fails.
    #[allow(clippy::significant_drop_tightening)]
    pub fn prune_expired(&self, now: TimestampNs) -> Result<usize, ProtocolError> {
        let conn = self.conn.lock().map_err(|_| {
            ProtocolError::StorageUnavailable("sqlite connection mutex poisoned".to_string())
        })?;

        let deleted = conn
            .execute(
                "DELETE FROM replay_cache WHERE expires_at_nanos <= ?1;",
                params![now.as_nanos()],
            )
            .map_err(|err| {
                ProtocolError::StorageUnavailable(format!("failed to prune expired records: {err}"))
            })?;

        Ok(deleted)
    }

    /// Returns the total count of consumed replay records in storage.
    ///
    /// # Errors
    /// Returns [`ProtocolError::StorageUnavailable`] if query fails.
    #[allow(clippy::significant_drop_tightening)]
    pub fn record_count(&self) -> Result<usize, ProtocolError> {
        let conn = self.conn.lock().map_err(|_| {
            ProtocolError::StorageUnavailable("sqlite connection mutex poisoned".to_string())
        })?;

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM replay_cache;", [], |row| row.get(0))
            .map_err(|err| {
                ProtocolError::StorageUnavailable(format!("failed to count replay records: {err}"))
            })?;

        usize::try_from(count).map_err(|_| {
            ProtocolError::StorageUnavailable("negative or overflow record count".to_string())
        })
    }
}

impl ReplayStore for SqliteReplayStore {
    #[allow(clippy::significant_drop_tightening)]
    fn check_and_consume(
        &self,
        machine_id: &MachineId,
        req_id: &RequestId,
        t_req: TimestampNs,
        expires_at: TimestampNs,
    ) -> Result<(), ProtocolError> {
        let mut conn = self.conn.lock().map_err(|_| {
            ProtocolError::StorageUnavailable("sqlite connection mutex poisoned".to_string())
        })?;

        // Atomic check-and-consume transaction using BEGIN IMMEDIATE
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|err| {
                ProtocolError::StorageUnavailable(format!(
                    "failed to begin immediate transaction: {err}"
                ))
            })?;

        let insert_res = tx.execute(
            "INSERT INTO replay_cache (
                machine_id, req_id, t_req_nanos, expires_at_nanos, consumed_at_nanos
            ) VALUES (?1, ?2, ?3, ?4, ?5);",
            params![
                machine_id.as_bytes().as_slice(),
                req_id.as_bytes().as_slice(),
                t_req.as_nanos(),
                expires_at.as_nanos(),
                t_req.as_nanos(),
            ],
        );

        match insert_res {
            Ok(_) => {
                tx.commit().map_err(|err| {
                    ProtocolError::StorageUnavailable(format!(
                        "failed to commit transaction: {err}"
                    ))
                })?;
                Ok(())
            }
            Err(rusqlite::Error::SqliteFailure(err, _))
                if err.code == ErrorCode::ConstraintViolation =>
            {
                // Unique constraint violated: request already consumed
                Err(ProtocolError::ReplayDetected {
                    req_id: req_id.to_string(),
                    machine_id: machine_id.to_string(),
                })
            }
            Err(err) => Err(ProtocolError::StorageUnavailable(format!(
                "failed to insert replay record: {err}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;
    use tempfile::NamedTempFile;

    use crate::protocol::crypto::{compute_hmac_sha256, RustCryptoMacVerifier};
    use crate::protocol::trust::UnverifiedRetrievalRequest;
    use crate::protocol::types::{RetrievalMessage, SharedSecret, TransactionId};

    #[test]
    fn test_sqlite_pragmas_wal_and_synchronous_full() {
        let temp_file = NamedTempFile::new().expect("temp file creation");
        let store = SqliteReplayStore::open(temp_file.path()).expect("store open");

        let (mode, sync) = store.query_pragmas().expect("query pragmas");
        assert_eq!(
            mode.to_lowercase(),
            "wal",
            "effective journal_mode must be WAL"
        );
        assert_eq!(
            sync, 2,
            "effective synchronous level must be 2 (FULL durability)"
        );
    }

    #[test]
    fn test_sqlite_first_request_accepted_and_duplicate_rejected() {
        let temp_file = NamedTempFile::new().expect("temp file creation");
        let store = SqliteReplayStore::open(temp_file.path()).expect("store open");

        let mach_id = MachineId::new();
        let req_id = RequestId::new();
        let t_req = TimestampNs::from_nanos(1_700_000_000_000_000_000);
        let expires_at = TimestampNs::from_nanos(1_700_000_120_000_000_000);

        // 1. First submission succeeds
        let res1 = store.check_and_consume(&mach_id, &req_id, t_req, expires_at);
        assert!(res1.is_ok(), "first submission must succeed");

        // 2. Duplicate submission fails with ReplayDetected
        let res2 = store.check_and_consume(&mach_id, &req_id, t_req, expires_at);
        match res2 {
            Err(ProtocolError::ReplayDetected {
                req_id: err_req,
                machine_id: err_mach,
            }) => {
                assert_eq!(err_req, req_id.to_string());
                assert_eq!(err_mach, mach_id.to_string());
            }
            other => panic!("expected ReplayDetected error, observed {other:?}"),
        }

        assert_eq!(store.record_count().unwrap(), 1);
    }

    #[test]
    fn test_sqlite_different_request_ids_accepted() {
        let temp_file = NamedTempFile::new().expect("temp file creation");
        let store = SqliteReplayStore::open(temp_file.path()).expect("store open");

        let mach_id = MachineId::new();
        let req_id_1 = RequestId::new();
        let req_id_2 = RequestId::new();
        let t_req = TimestampNs::from_nanos(1_700_000_000_000_000_000);
        let expires_at = TimestampNs::from_nanos(1_700_000_120_000_000_000);

        assert!(store
            .check_and_consume(&mach_id, &req_id_1, t_req, expires_at)
            .is_ok());
        assert!(store
            .check_and_consume(&mach_id, &req_id_2, t_req, expires_at)
            .is_ok());
        assert_eq!(store.record_count().unwrap(), 2);
    }

    #[test]
    fn test_invalid_hmac_does_not_consume_request_id() {
        let temp_file = NamedTempFile::new().expect("temp file creation");
        let store = SqliteReplayStore::open(temp_file.path()).expect("store open");
        let mac_verifier = RustCryptoMacVerifier;
        let secret = SharedSecret::from_bytes([0x42; 32]);

        let msg = RetrievalMessage {
            machine_id: MachineId::new(),
            tx_id: TransactionId::new(),
            req_id: RequestId::new(),
            t_req: TimestampNs::from_nanos(1_700_000_000_000_000_000),
        };
        let raw = msg.serialize_canonical();

        // Client supplies invalid HMAC tag
        let unverified_bad = UnverifiedRetrievalRequest::new(raw.to_vec(), [0xff; 32]);
        let t_auth = TimestampNs::from_nanos(1_700_000_005_000_000_000);

        let err = unverified_bad
            .verify(&mac_verifier, &secret, t_auth)
            .unwrap_err();
        assert_eq!(err, ProtocolError::InvalidHmacProof);

        // Verify storage was never touched
        assert_eq!(store.record_count().unwrap(), 0);

        // Subsequent valid submission with the same request ID succeeds and is consumed
        let valid_tag = compute_hmac_sha256(&secret, &raw);
        let unverified_good = UnverifiedRetrievalRequest::new(raw.to_vec(), valid_tag);
        let verified = unverified_good
            .verify(&mac_verifier, &secret, t_auth)
            .expect("valid verify");

        assert!(store
            .check_and_consume(
                &verified.message.machine_id,
                &verified.message.req_id,
                verified.message.t_req,
                verified.expires_at
            )
            .is_ok());
        assert_eq!(store.record_count().unwrap(), 1);
    }

    #[test]
    fn test_stale_request_does_not_consume_request_id() {
        let temp_file = NamedTempFile::new().expect("temp file creation");
        let store = SqliteReplayStore::open(temp_file.path()).expect("store open");
        let verifier = RustCryptoMacVerifier;
        let secret = SharedSecret::from_bytes([0x42; 32]);

        let t_req = TimestampNs::from_nanos(1_700_000_000_000_000_000);
        let msg = RetrievalMessage {
            machine_id: MachineId::new(),
            tx_id: TransactionId::new(),
            req_id: RequestId::new(),
            t_req,
        };
        let raw = msg.serialize_canonical();
        let proof = compute_hmac_sha256(&secret, &raw);

        // Authority evaluation time is 61 seconds ahead (exceeds +/- 60s window)
        let t_auth_stale = TimestampNs::from_nanos(1_700_000_061_000_000_001);
        let unverified = UnverifiedRetrievalRequest::new(raw.to_vec(), proof);

        let err = unverified
            .verify(&verifier, &secret, t_auth_stale)
            .unwrap_err();
        assert!(matches!(err, ProtocolError::TimestampOutOfBounds { .. }));

        // Storage was not touched
        assert_eq!(store.record_count().unwrap(), 0);
    }

    #[test]
    fn test_concurrent_duplicate_submissions_result_in_exactly_one_success() {
        let temp_file = NamedTempFile::new().expect("temp file creation");
        let db_path = temp_file.path().to_path_buf();

        // Initialize store once to establish schema
        {
            let _init = SqliteReplayStore::open(&db_path).expect("init open");
        }

        let num_threads = 10;
        let barrier = Arc::new(Barrier::new(num_threads));

        let mach_id = MachineId::new();
        let req_id = RequestId::new();
        let t_req = TimestampNs::from_nanos(1_700_000_000_000_000_000);
        let expires_at = TimestampNs::from_nanos(1_700_000_120_000_000_000);

        let mut handles = Vec::new();

        for _ in 0..num_threads {
            let barrier_clone = Arc::clone(&barrier);
            let path_clone = db_path.clone();

            let handle = thread::spawn(move || {
                // Open distinct connection to the exact same database file
                let store =
                    SqliteReplayStore::open(&path_clone).expect("open connection in thread");
                barrier_clone.wait();
                store.check_and_consume(&mach_id, &req_id, t_req, expires_at)
            });

            handles.push(handle);
        }

        let mut successes = 0;
        let mut replays = 0;

        for h in handles {
            match h.join().unwrap() {
                Ok(()) => successes += 1,
                Err(ProtocolError::ReplayDetected { .. }) => replays += 1,
                Err(other) => panic!("unexpected error during concurrent insert: {other:?}"),
            }
        }

        assert_eq!(successes, 1, "exactly one concurrent thread must succeed");
        assert_eq!(
            replays,
            num_threads - 1,
            "all other threads must observe ReplayDetected"
        );

        let verify_store = SqliteReplayStore::open(&db_path).expect("open verification store");
        assert_eq!(verify_store.record_count().unwrap(), 1);
    }

    #[test]
    fn test_restart_persistence_survives_process_closure() {
        let temp_file = NamedTempFile::new().expect("temp file creation");
        let db_path = temp_file.path().to_path_buf();

        let mach_id = MachineId::new();
        let req_id = RequestId::new();
        let t_req = TimestampNs::from_nanos(1_700_000_000_000_000_000);
        let expires_at = TimestampNs::from_nanos(1_700_000_120_000_000_000);

        // Instance 1: commit record
        {
            let store1 = SqliteReplayStore::open(&db_path).expect("store1 open");
            assert!(store1
                .check_and_consume(&mach_id, &req_id, t_req, expires_at)
                .is_ok());
            assert_eq!(store1.record_count().unwrap(), 1);
        } // store1 dropped and connection closed

        // Instance 2: reopen same file
        {
            let store2 = SqliteReplayStore::open(&db_path).expect("store2 reopen");
            assert_eq!(store2.record_count().unwrap(), 1);

            // Replay must be detected after reopen
            let res = store2.check_and_consume(&mach_id, &req_id, t_req, expires_at);
            assert!(matches!(res, Err(ProtocolError::ReplayDetected { .. })));
        }
    }

    #[test]
    fn test_exact_retention_boundary_and_pruning() {
        let temp_file = NamedTempFile::new().expect("temp file creation");
        let store = SqliteReplayStore::open(temp_file.path()).expect("store open");

        let mach_id = MachineId::new();
        let req_id = RequestId::new();
        let t_req = TimestampNs::from_nanos(1_700_000_000_000_000_000);
        // Expiry is exactly T_req + 120s
        let expires_at = TimestampNs::from_nanos(1_700_000_120_000_000_000);

        assert!(store
            .check_and_consume(&mach_id, &req_id, t_req, expires_at)
            .is_ok());
        assert_eq!(store.record_count().unwrap(), 1);

        // Invariant check: Pruning at T_req + 60s (latest valid acceptance window) must NOT delete record
        let t_60s = TimestampNs::from_nanos(1_700_000_060_000_000_000);
        assert_eq!(store.prune_expired(t_60s).unwrap(), 0);
        assert_eq!(store.record_count().unwrap(), 1);

        // Boundary 1: Pruning at expires_at - 1ns (record remains active, 0 deleted)
        let t_before_expiry = TimestampNs::from_nanos(1_700_000_119_999_999_999);
        assert_eq!(store.prune_expired(t_before_expiry).unwrap(), 0);
        assert_eq!(store.record_count().unwrap(), 1);

        // Boundary 2: Pruning at exact expires_at (record reached expiry, 1 deleted)
        assert_eq!(store.prune_expired(expires_at).unwrap(), 1);
        assert_eq!(store.record_count().unwrap(), 0);

        // Boundary 3: Pruning at expires_at + 1ns on a fresh record
        let req_id_2 = RequestId::new();
        assert!(store
            .check_and_consume(&mach_id, &req_id_2, t_req, expires_at)
            .is_ok());
        assert_eq!(store.record_count().unwrap(), 1);

        let t_after_expiry = TimestampNs::from_nanos(1_700_000_120_000_000_001);
        assert_eq!(store.prune_expired(t_after_expiry).unwrap(), 1);
        assert_eq!(store.record_count().unwrap(), 0);
    }

    #[test]
    fn test_corrupt_database_fails_closed_without_silent_recreation() {
        let temp_file = NamedTempFile::new().expect("temp file creation");
        let db_path = temp_file.path().to_path_buf();

        // Write corrupt garbage to database file
        std::fs::write(&db_path, b"GARBAGE-SQLITE-HEADER-CORRUPTION-NOT-A-DATABASE").unwrap();

        let open_res = SqliteReplayStore::open(&db_path);
        match open_res {
            Err(ProtocolError::StorageUnavailable(msg)) => {
                assert!(
                    msg.contains("failed") || msg.contains("SQLite") || msg.contains("integrity"),
                    "{msg}"
                );
            }
            other => {
                panic!("corrupt database must fail closed with StorageUnavailable, got {other:?}")
            }
        }

        // Verify file was NOT wiped or recreated
        let contents = std::fs::read(&db_path).unwrap();
        assert_eq!(contents, b"GARBAGE-SQLITE-HEADER-CORRUPTION-NOT-A-DATABASE");
    }

    #[test]
    fn test_schema_migration_fresh_database_applies_current_version() {
        let temp_file = NamedTempFile::new().expect("temp file creation");
        let store = SqliteReplayStore::open(temp_file.path()).expect("store open");

        assert_eq!(
            store.schema_version().unwrap(),
            CURRENT_SCHEMA_VERSION,
            "fresh database must apply current schema version"
        );
        assert_eq!(store.record_count().unwrap(), 0);
    }

    #[test]
    fn test_schema_migration_upgrade_from_older_supported_version() {
        let temp_file = NamedTempFile::new().expect("temp file creation");
        let db_path = temp_file.path().to_path_buf();

        // Create database manually with schema_migrations at version 0
        {
            let conn = Connection::open(&db_path).unwrap();
            conn.execute_batch(
                "CREATE TABLE schema_migrations (
                    version INTEGER PRIMARY KEY,
                    applied_at_nanos INTEGER NOT NULL
                );
                INSERT INTO schema_migrations (version, applied_at_nanos) VALUES (0, 0);",
            )
            .unwrap();
        }

        // Open with SqliteReplayStore: must upgrade cleanly from 0 to 1
        let store = SqliteReplayStore::open(&db_path).expect("open and upgrade");
        assert_eq!(store.schema_version().unwrap(), CURRENT_SCHEMA_VERSION);

        // Verify replay cache table is created and operational
        let mach_id = MachineId::new();
        let req_id = RequestId::new();
        let t_req = TimestampNs::from_nanos(1_700_000_000_000_000_000);
        let expires_at = TimestampNs::from_nanos(1_700_000_120_000_000_000);

        assert!(store
            .check_and_consume(&mach_id, &req_id, t_req, expires_at)
            .is_ok());
        assert_eq!(store.record_count().unwrap(), 1);
    }

    #[test]
    fn test_schema_version_future_fails_closed() {
        let temp_file = NamedTempFile::new().expect("temp file creation");
        let db_path = temp_file.path().to_path_buf();

        // Initialize database and insert incompatible schema version 999
        {
            let conn = Connection::open(&db_path).unwrap();
            conn.execute_batch(
                "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at_nanos INTEGER NOT NULL);
                 INSERT INTO schema_migrations VALUES (999, 100);",
            ).unwrap();
        }

        let open_res = SqliteReplayStore::open(&db_path);
        match open_res {
            Err(ProtocolError::StorageUnavailable(msg)) => {
                assert!(msg.contains("incompatible schema version 999"), "{msg}");
            }
            other => panic!("future schema version must fail closed, got {other:?}"),
        }
    }

    #[test]
    fn test_failed_migration_rolls_back_without_leaving_partial_state() {
        let temp_file = NamedTempFile::new().expect("temp file creation");
        let db_path = temp_file.path().to_path_buf();

        // Create an incompatible table replay_cache missing columns, which will fail migration 1
        {
            let conn = Connection::open(&db_path).unwrap();
            conn.execute_batch(
                "CREATE TABLE schema_migrations (
                    version INTEGER PRIMARY KEY,
                    applied_at_nanos INTEGER NOT NULL
                );
                CREATE TABLE replay_cache (incompatible_column INTEGER PRIMARY KEY);",
            )
            .unwrap();
        }

        // Open must fail closed
        let open_res = SqliteReplayStore::open(&db_path);
        assert!(matches!(
            open_res,
            Err(ProtocolError::StorageUnavailable(_))
        ));

        // Verify schema_migrations does NOT contain version 1
        let conn = Connection::open(&db_path).unwrap();
        let max_v: i64 = conn
            .query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_migrations;",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            max_v, 0,
            "failed migration must roll back and not record version 1"
        );
    }

    #[test]
    fn test_transaction_failure_rolls_back_without_consuming_request_id() {
        let temp_file = NamedTempFile::new().expect("temp file creation");
        let store = SqliteReplayStore::open(temp_file.path()).expect("store open");

        let mach_id = MachineId::new();
        let req_id = RequestId::new();
        let t_req = TimestampNs::from_nanos(1_700_000_000_000_000_000);
        let expires_at = TimestampNs::from_nanos(1_700_000_120_000_000_000);

        // Simulate a transaction failure/abort using a raw connection to the same file
        {
            let mut raw_conn = Connection::open(store.path()).unwrap();
            let tx = raw_conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            tx.execute(
                "INSERT INTO replay_cache (
                    machine_id, req_id, t_req_nanos, expires_at_nanos, consumed_at_nanos
                ) VALUES (?1, ?2, ?3, ?4, ?5);",
                params![
                    mach_id.as_bytes().as_slice(),
                    req_id.as_bytes().as_slice(),
                    t_req.as_nanos(),
                    expires_at.as_nanos(),
                    t_req.as_nanos(),
                ],
            )
            .unwrap();
            // Roll back the transaction
            tx.rollback().unwrap();
        }

        // Request was NOT consumed because transaction was rolled back
        assert_eq!(store.record_count().unwrap(), 0);

        // Now the store can successfully consume the exact same request ID
        let res = store.check_and_consume(&mach_id, &req_id, t_req, expires_at);
        assert!(
            res.is_ok(),
            "request ID must remain unconsumed after transaction rollback"
        );
        assert_eq!(store.record_count().unwrap(), 1);

        // Immediate replay of the now-committed record is rejected
        let res_dup = store.check_and_consume(&mach_id, &req_id, t_req, expires_at);
        assert!(matches!(res_dup, Err(ProtocolError::ReplayDetected { .. })));
    }

    #[test]
    fn test_unavailable_path_fails_closed() {
        let bad_path = "/nonexistent/invalid/directory/path/replay.db";
        let open_res = SqliteReplayStore::open(bad_path);
        assert!(matches!(
            open_res,
            Err(ProtocolError::StorageUnavailable(_))
        ));
    }

    #[test]
    fn test_lock_contention_handled_safely() {
        let temp_file = NamedTempFile::new().expect("temp file creation");
        let db_path = temp_file.path().to_path_buf();

        let store = SqliteReplayStore::open(&db_path).expect("store open");
        let mach_id = MachineId::new();
        let req_id = RequestId::new();
        let t_req = TimestampNs::from_nanos(1_700_000_000_000_000_000);
        let expires_at = TimestampNs::from_nanos(1_700_000_120_000_000_000);

        // Open a secondary raw connection that acquires an exclusive write lock
        let mut raw_conn = Connection::open(&db_path).expect("raw connection open");
        raw_conn
            .busy_timeout(std::time::Duration::from_millis(5000))
            .unwrap();

        // Lock database exclusively in background thread, hold for 150ms, then commit
        let raw_handle = thread::spawn(move || {
            let tx = raw_conn
                .transaction_with_behavior(TransactionBehavior::Exclusive)
                .unwrap();
            thread::sleep(std::time::Duration::from_millis(150));
            tx.commit().unwrap();
        });

        // store.check_and_consume will contend for the write lock, wait via busy_timeout, and succeed
        let consume_res = store.check_and_consume(&mach_id, &req_id, t_req, expires_at);
        assert!(
            consume_res.is_ok(),
            "must succeed after waiting for lock release"
        );

        raw_handle.join().unwrap();
        assert_eq!(store.record_count().unwrap(), 1);
    }
}
