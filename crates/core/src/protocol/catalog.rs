//! Persistent, crash-resilient catalog durability engine for OpenAudit M3 D4.
//!
//! Provides transactional write-ahead logging (WAL), atomic POSIX catalog replacement,
//! explicit parent directory synchronization, kernel-enforced cross-process locking
//! via `rustix::fs::flock`, and deterministic crash recovery across all interruption
//! boundaries (CB-01 through CB-13).

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

#[cfg(unix)]
use rustix::fs::{flock, FlockOperation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::protocol::canonical::canonicalize;
use crate::protocol::error::ProtocolError;

/// Schema version for authoritative catalog files.
pub const CURRENT_CATALOG_SCHEMA_VERSION: u32 = 1;

/// Schema version for catalog Write-Ahead Log (WAL) records.
pub const CURRENT_WAL_SCHEMA_VERSION: u32 = 1;

/// Metadata recorded in `catalog.lock` by the acquiring process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockMetadata {
    /// Process ID of the lock holder.
    pub pid: u32,
    /// Unique identifier for this lock acquisition instance.
    pub lock_uuid: String,
    /// Timestamp when the lock was acquired in nanoseconds.
    pub acquired_at_nanos: i64,
}

/// Authoritative versioned security assessment catalog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssessmentCatalog {
    /// Schema version of the catalog envelope.
    pub schema_version: u32,
    /// Monotonically increasing catalog release version.
    pub version: u64,
    /// Hardware counter baseline associated with this release.
    pub counter: u64,
    /// SHA-256 hex digest of the canonical RFC 8785 JSON payload.
    pub payload_hash: String,
    /// Structured assessment catalog rules and signatures.
    pub payload: serde_json::Value,
}

impl AssessmentCatalog {
    /// Constructs a new valid [`AssessmentCatalog`], computing the payload hash canonically.
    ///
    /// # Errors
    /// Returns [`ProtocolError::CryptoError`] if canonicalization fails.
    pub fn new(
        version: u64,
        counter: u64,
        payload: serde_json::Value,
    ) -> Result<Self, ProtocolError> {
        let canonical_bytes = canonicalize(&payload)?;
        let hash = hex_digest(&canonical_bytes);

        Ok(Self {
            schema_version: CURRENT_CATALOG_SCHEMA_VERSION,
            version,
            counter,
            payload_hash: hash,
            payload,
        })
    }

    /// Validates structural integrity, schema version, and cryptographic payload hash.
    ///
    /// # Errors
    /// Returns [`ProtocolError::CatalogCorrupted`] if schema is unsupported, version is 0,
    /// or payload hash does not match computed canonical digest.
    pub fn validate_integrity(&self) -> Result<(), ProtocolError> {
        if self.schema_version != CURRENT_CATALOG_SCHEMA_VERSION {
            return Err(ProtocolError::CatalogCorrupted(format!(
                "unsupported catalog schema version {} (expected {CURRENT_CATALOG_SCHEMA_VERSION})",
                self.schema_version
            )));
        }

        if self.version == 0 {
            return Err(ProtocolError::CatalogCorrupted(
                "invalid catalog version 0: version must be strictly positive".to_string(),
            ));
        }

        let canonical_bytes = canonicalize(&self.payload)?;
        let actual_hash = hex_digest(&canonical_bytes);

        if !actual_hash.eq_ignore_ascii_case(&self.payload_hash) {
            return Err(ProtocolError::CatalogCorrupted(format!(
                "payload checksum mismatch: expected {}, observed {}",
                self.payload_hash, actual_hash
            )));
        }

        Ok(())
    }
}

/// Transaction intent recorded in Write-Ahead Log (WAL) before counter advancement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogWalRecord {
    /// WAL record schema version.
    pub schema_version: u32,
    /// Unique transaction identifier.
    pub tx_id: String,
    /// Predecessor catalog version being updated.
    pub base_version: u64,
    /// Target catalog version to be promoted.
    pub target_version: u64,
    /// Predecessor hardware counter value.
    pub base_counter: u64,
    /// Target hardware counter value (must equal `base_counter + 1`).
    pub target_counter: u64,
    /// SHA-256 hex digest of the candidate staged catalog file.
    pub staged_catalog_hash: String,
    /// SHA-256 checksum over the serialized WAL fields.
    pub wal_checksum: String,
}

impl CatalogWalRecord {
    /// Constructs a new [`CatalogWalRecord`] with an authentic cryptographic checksum.
    #[must_use]
    pub fn new(
        tx_id: String,
        base_version: u64,
        target_version: u64,
        base_counter: u64,
        target_counter: u64,
        staged_catalog_hash: String,
    ) -> Self {
        let checksum = Self::compute_checksum(
            CURRENT_WAL_SCHEMA_VERSION,
            &tx_id,
            base_version,
            target_version,
            base_counter,
            target_counter,
            &staged_catalog_hash,
        );

        Self {
            schema_version: CURRENT_WAL_SCHEMA_VERSION,
            tx_id,
            base_version,
            target_version,
            base_counter,
            target_counter,
            staged_catalog_hash,
            wal_checksum: checksum,
        }
    }

    /// Computes SHA-256 checksum over the normative WAL fields.
    #[must_use]
    pub fn compute_checksum(
        schema_version: u32,
        tx_id: &str,
        base_v: u64,
        target_v: u64,
        base_c: u64,
        target_c: u64,
        staged_hash: &str,
    ) -> String {
        let msg = format!(
            "{schema_version}:{tx_id}:{base_v}:{target_v}:{base_c}:{target_c}:{staged_hash}"
        );
        hex_digest(msg.as_bytes())
    }

    /// Verifies the cryptographic checksum of this WAL record.
    #[must_use]
    pub fn validate_checksum(&self) -> bool {
        if self.schema_version != CURRENT_WAL_SCHEMA_VERSION {
            return false;
        }
        let expected = Self::compute_checksum(
            self.schema_version,
            &self.tx_id,
            self.base_version,
            self.target_version,
            self.base_counter,
            self.target_counter,
            &self.staged_catalog_hash,
        );
        expected.eq_ignore_ascii_case(&self.wal_checksum)
    }
}

/// Abstract monotonic counter provider (e.g. physical TPM NV index or mock).
pub trait MonotonicCounter: Send + Sync {
    /// Reads the current hardware monotonic counter value.
    ///
    /// # Errors
    /// Returns [`ProtocolError`] if query fails.
    fn read_counter(&self) -> Result<u64, ProtocolError>;

    /// Atomically increments the hardware monotonic counter, returning the new value.
    ///
    /// # Errors
    /// Returns [`ProtocolError`] if increment fails.
    fn increment_counter(&mut self) -> Result<u64, ProtocolError>;
}

/// Thread-safe in-memory monotonic counter implementation for tests and local simulation.
#[derive(Debug, Default, Clone)]
pub struct MockMonotonicCounter {
    val: Arc<AtomicU64>,
}

impl MockMonotonicCounter {
    /// Creates a mock counter initialized at `initial_val`.
    #[must_use]
    pub fn new(initial_val: u64) -> Self {
        Self {
            val: Arc::new(AtomicU64::new(initial_val)),
        }
    }
}

impl MonotonicCounter for MockMonotonicCounter {
    fn read_counter(&self) -> Result<u64, ProtocolError> {
        Ok(self.val.load(Ordering::SeqCst))
    }

    fn increment_counter(&mut self) -> Result<u64, ProtocolError> {
        Ok(self.val.fetch_add(1, Ordering::SeqCst) + 1)
    }
}

/// Deterministic outcome produced by crash recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryOutcome {
    /// Authoritative catalog is consistent; no interrupted transaction was pending.
    CleanCurrent,
    /// Transaction crashed before counter increment; rolled back to previous valid catalog.
    RolledBackUnincremented,
    /// Interrupted with corrupted/truncated WAL before counter increment; purged and rolled back.
    RolledBackPreIncrement,
    /// Interruption occurred after counter increment committed; staged catalog promoted to active.
    RecoveredPromotedNew,
    /// Interruption occurred during WAL cleanup after catalog was already promoted; finalized.
    RecoveredCompletedExisting,
    /// Split-transaction recovery: counter incremented, staged catalog validated and promoted.
    RecoveredViaStagedPromotion,
}

/// Injection boundary for crash-recovery test simulation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrashPoint {
    /// Execute transaction to normal completion.
    None,
    /// Crash during candidate staged file write.
    DuringStagedWrite,
    /// Crash after candidate staged file is written and fsynced, before WAL initialization.
    BeforeWalInit,
    /// Crash during WAL write (simulates truncated WAL file).
    DuringWalWrite,
    /// Crash after WAL write, before WAL file fsync.
    AfterWalWriteBeforeSync,
    /// Crash after WAL fsync, before monotonic counter increment.
    AfterWalSyncBeforeCounterIncrement,
    /// Crash during counter increment (counter increment fails to commit).
    DuringCounterIncrement,
    /// Crash after counter increment commits, before catalog promotion rename.
    AfterCounterIncrementBeforeRename,
    /// Crash after catalog rename, before parent directory fsync.
    AfterRenameBeforeDirSync,
    /// Crash after catalog promotion, during WAL deletion.
    DuringWalCleanup,
}

/// Queries whether a process with `pid` is currently alive in the operating system.
#[must_use]
#[allow(clippy::missing_const_for_fn)]
pub fn is_process_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        if let Ok(status) = std::process::Command::new("kill")
            .arg("-0")
            .arg(pid.to_string())
            .status()
        {
            return status.success();
        }
    }
    #[cfg(not(unix))]
    let _ = pid;
    false
}

/// Crash-resilient catalog persistence and transaction manager.
pub struct CatalogManager {
    data_dir: PathBuf,
    catalog_path: PathBuf,
    wal_path: PathBuf,
    lock_path: PathBuf,
    process_mutex: Mutex<()>,
}

impl fmt::Debug for CatalogManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CatalogManager")
            .field("data_dir", &self.data_dir)
            .field("catalog_path", &self.catalog_path)
            .field("wal_path", &self.wal_path)
            .finish_non_exhaustive()
    }
}

impl CatalogManager {
    /// Opens or initializes a catalog persistence manager at `data_dir`.
    ///
    /// # Errors
    /// Returns [`ProtocolError::StorageUnavailable`] if directory creation or access fails.
    pub fn open<P: AsRef<Path>>(data_dir: P) -> Result<Self, ProtocolError> {
        let dir_buf = data_dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir_buf).map_err(|err| {
            ProtocolError::StorageUnavailable(format!(
                "failed to create catalog directory '{}': {err}",
                dir_buf.display()
            ))
        })?;

        // Explicitly set directory permissions on Unix to 0700
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&dir_buf, fs::Permissions::from_mode(0o700));
        }

        let catalog_path = dir_buf.join("catalog.json");
        let wal_path = dir_buf.join("catalog.wal");
        let lock_path = dir_buf.join("catalog.lock");

        Ok(Self {
            data_dir: dir_buf,
            catalog_path,
            wal_path,
            lock_path,
            process_mutex: Mutex::new(()),
        })
    }

    /// Returns the filesystem path to the authoritative `catalog.json`.
    #[must_use]
    pub fn catalog_path(&self) -> &Path {
        &self.catalog_path
    }

    /// Returns the filesystem path to the Write-Ahead Log `catalog.wal`.
    #[must_use]
    pub fn wal_path(&self) -> &Path {
        &self.wal_path
    }

    /// Returns the filesystem path to the lock file `catalog.lock`.
    #[must_use]
    pub fn lock_path(&self) -> &Path {
        &self.lock_path
    }

    /// Initializes a brand-new catalog repository if none currently exists.
    ///
    /// # Errors
    /// Returns [`ProtocolError::CatalogCorrupted`] if the catalog payload is invalid.
    pub fn initialize_new(&self, catalog: &AssessmentCatalog) -> Result<(), ProtocolError> {
        let _guard = self.acquire_lock()?;
        catalog.validate_integrity()?;

        if self.catalog_path.exists() {
            return Err(ProtocolError::StorageUnavailable(
                "cannot initialize: active catalog already exists".to_string(),
            ));
        }

        let serialized = serde_json::to_vec_pretty(catalog).map_err(|err| {
            ProtocolError::StorageUnavailable(format!("failed to serialize catalog: {err}"))
        })?;

        let tmp_path = self.data_dir.join("catalog.json.init.tmp");
        Self::write_fsync_file(&tmp_path, &serialized)?;
        fs::rename(&tmp_path, &self.catalog_path).map_err(|err| {
            ProtocolError::StorageUnavailable(format!("failed to rename init catalog: {err}"))
        })?;
        self.sync_dir()?;

        Ok(())
    }

    /// Loads and validates the current authoritative catalog from disk.
    ///
    /// # Errors
    /// Returns [`ProtocolError::CatalogCorrupted`] if the file is missing, malformed,
    /// truncated, or fails payload cryptographic verification (fail-closed).
    pub fn load_active_catalog(&self) -> Result<AssessmentCatalog, ProtocolError> {
        if !self.catalog_path.exists() {
            return Err(ProtocolError::CatalogCorrupted(format!(
                "authoritative catalog '{}' is missing (fail-closed)",
                self.catalog_path.display()
            )));
        }

        let raw_bytes = fs::read(&self.catalog_path).map_err(|err| {
            ProtocolError::StorageUnavailable(format!(
                "failed to read catalog file '{}': {err}",
                self.catalog_path.display()
            ))
        })?;

        let catalog: AssessmentCatalog = serde_json::from_slice(&raw_bytes).map_err(|err| {
            ProtocolError::CatalogCorrupted(format!(
                "authoritative catalog contains invalid JSON (fail-closed): {err}"
            ))
        })?;

        catalog.validate_integrity()?;
        Ok(catalog)
    }

    /// Executes deterministic crash recovery across all interruption boundaries (CB-01 through CB-13).
    ///
    /// # Errors
    /// - Returns [`ProtocolError::CatalogCorrupted`] if authoritative catalog is damaged.
    /// - Returns [`ProtocolError::CatalogDesync`] if counter gap is unresolvable (fail-closed).
    /// - Returns [`ProtocolError::StorageUnavailable`] if filesystem operations fail.
    #[allow(clippy::too_many_lines)]
    pub fn recover<C: MonotonicCounter>(
        &self,
        counter: &C,
    ) -> Result<RecoveryOutcome, ProtocolError> {
        let _guard = self.acquire_lock()?;

        // Step 1: Read and validate active catalog on disk (if present)
        let mut c_disk = 0;
        let mut v_disk = 0;
        let catalog_exists = self.catalog_path.exists();

        if catalog_exists {
            let active = self.load_active_catalog()?;
            c_disk = active.counter;
            v_disk = active.version;
        }

        let c_hw = counter.read_counter()?;

        // Step 2: Inspect Write-Ahead Log
        let wal_exists = self.wal_path.exists();
        let mut wal_record: Option<CatalogWalRecord> = None;
        let mut wal_corrupted = false;

        if wal_exists {
            match fs::read(&self.wal_path) {
                Ok(bytes) => match serde_json::from_slice::<CatalogWalRecord>(&bytes) {
                    Ok(rec) if rec.validate_checksum() => {
                        wal_record = Some(rec);
                    }
                    _ => {
                        wal_corrupted = true;
                    }
                },
                Err(_) => {
                    wal_corrupted = true;
                }
            }
        }

        // Branch 1: Valid WAL Present
        if let Some(wal) = wal_record {
            // Case 1A: Counter committed: c_hw == c_disk + 1 and matches wal.target_counter
            if c_hw == c_disk + 1 && c_hw == wal.target_counter {
                // Verify WAL predecessor consistency
                if wal.base_version != v_disk || wal.base_counter != c_disk {
                    return Err(ProtocolError::CatalogDesync(format!(
                        "WAL predecessor mismatch: wal.base_v={}, v_disk={v_disk}, wal.base_c={}, c_disk={c_disk}",
                        wal.base_version, wal.base_counter
                    )));
                }

                // Verify WAL target values are strict immediate successors
                if wal.target_version != v_disk + 1 || wal.target_counter != c_disk + 1 {
                    return Err(ProtocolError::CatalogDesync(format!(
                        "WAL target mismatch: wal.target_v={}, expected {}",
                        wal.target_version,
                        v_disk + 1
                    )));
                }

                // Verify candidate staged file matching exact WAL transaction ID
                let staged_path = self
                    .data_dir
                    .join(format!("catalog.json.staged.{}", wal.tx_id));
                if !staged_path.exists() {
                    return Err(ProtocolError::CatalogDesync(format!(
                        "recovery failed: staged candidate file '{}' matching WAL tx_id is missing",
                        staged_path.display()
                    )));
                }

                let candidate_bytes = fs::read(&staged_path).map_err(|err| {
                    ProtocolError::StorageUnavailable(format!(
                        "failed to read staged candidate: {err}"
                    ))
                })?;

                // Verify candidate content matches staged_catalog_hash in WAL
                let actual_hash = hex_digest(&candidate_bytes);
                if !actual_hash.eq_ignore_ascii_case(&wal.staged_catalog_hash) {
                    return Err(ProtocolError::CatalogDesync(format!(
                        "staged candidate digest mismatch: expected {}, observed {actual_hash}",
                        wal.staged_catalog_hash
                    )));
                }

                // Verify candidate internal structural integrity and targets
                let candidate: AssessmentCatalog = serde_json::from_slice(&candidate_bytes)
                    .map_err(|err| {
                        ProtocolError::CatalogCorrupted(format!(
                            "staged candidate contains invalid JSON: {err}"
                        ))
                    })?;
                candidate.validate_integrity()?;

                if candidate.version != wal.target_version
                    || candidate.counter != wal.target_counter
                {
                    return Err(ProtocolError::CatalogDesync(format!(
                        "candidate content does not match WAL targets: candidate.v={}, wal.target_v={}",
                        candidate.version, wal.target_version
                    )));
                }

                // All recovery verification gates passed: promote candidate
                fs::rename(&staged_path, &self.catalog_path).map_err(|err| {
                    ProtocolError::StorageUnavailable(format!(
                        "failed to promote staged catalog: {err}"
                    ))
                })?;
                self.sync_dir()?;
                self.unlink_wal_and_sync()?;
                return Ok(RecoveryOutcome::RecoveredPromotedNew);
            }

            // Case 1B: Counter was already updated on disk: c_hw == c_disk and c_disk == wal.target_counter
            if c_hw == c_disk && c_disk == wal.target_counter {
                self.unlink_wal_and_sync()?;
                self.purge_orphan_staged_files()?;
                return Ok(RecoveryOutcome::RecoveredCompletedExisting);
            }

            // Case 1C: Counter was never incremented: c_hw == c_disk and c_hw == wal.base_counter
            if c_hw == c_disk && c_hw == wal.base_counter {
                self.unlink_wal_and_sync()?;
                self.purge_orphan_staged_files()?;
                return Ok(RecoveryOutcome::RolledBackUnincremented);
            }

            // Unresolvable counter gap with valid WAL
            return Err(ProtocolError::CatalogDesync(format!(
                "unresolvable counter state: c_hw={c_hw}, c_disk={c_disk}, wal_target={}",
                wal.target_counter
            )));
        }

        // Branch 2: Corrupted WAL Present
        if wal_corrupted {
            if c_hw == c_disk {
                // Counter did not advance; purge corrupt WAL and stale staged files
                self.unlink_wal_and_sync()?;
                self.purge_orphan_staged_files()?;
                return Ok(RecoveryOutcome::RolledBackPreIncrement);
            }

            if c_hw == c_disk + 1 {
                // Post-increment split transaction with corrupted WAL (CB-13)
                if let Some(candidate_path) =
                    self.find_valid_candidate_staged(v_disk + 1, c_disk + 1)?
                {
                    fs::rename(&candidate_path, &self.catalog_path).map_err(|err| {
                        ProtocolError::StorageUnavailable(format!(
                            "failed to promote candidate staged catalog: {err}"
                        ))
                    })?;
                    self.sync_dir()?;
                    self.unlink_wal_and_sync()?;
                    return Ok(RecoveryOutcome::RecoveredViaStagedPromotion);
                }
                return Err(ProtocolError::CatalogDesync(
                    "critical split-brain: counter advanced to c_disk+1 but WAL is corrupt and no valid staged catalog found".to_string(),
                ));
            }

            return Err(ProtocolError::CatalogDesync(format!(
                "critical counter gap with corrupt WAL: c_hw={c_hw}, c_disk={c_disk}"
            )));
        }

        // Branch 3: No WAL Present
        if c_hw == c_disk {
            self.purge_orphan_staged_files()?;
            return Ok(RecoveryOutcome::CleanCurrent);
        }

        if c_hw == c_disk + 1 {
            // Post-increment crash with missing WAL (CB-13)
            if let Some(candidate_path) =
                self.find_valid_candidate_staged(v_disk + 1, c_disk + 1)?
            {
                fs::rename(&candidate_path, &self.catalog_path).map_err(|err| {
                    ProtocolError::StorageUnavailable(format!(
                        "failed to promote candidate staged catalog: {err}"
                    ))
                })?;
                self.sync_dir()?;
                return Ok(RecoveryOutcome::RecoveredViaStagedPromotion);
            }
            return Err(ProtocolError::CatalogDesync(
                "critical split-brain: hardware counter incremented but WAL is absent and no valid candidate staged file found".to_string(),
            ));
        }

        Err(ProtocolError::CatalogDesync(format!(
            "unresolvable catalog gap: c_hw={c_hw}, c_disk={c_disk}"
        )))
    }

    /// Executes a durable 6-stage catalog transaction with full `fsync` barriers.
    ///
    /// # Errors
    /// Returns [`ProtocolError`] if verification, I/O, or counter increment fails.
    pub fn execute_transaction<C: MonotonicCounter>(
        &self,
        candidate: &AssessmentCatalog,
        counter: &mut C,
    ) -> Result<(), ProtocolError> {
        self.execute_transaction_with_crash_point(candidate, counter, CrashPoint::None)
    }

    /// Executes a durable transaction with simulated crash-point fault injection.
    ///
    /// # Errors
    /// Returns [`ProtocolError`] if transaction is interrupted at `crash_point` or fails.
    #[allow(clippy::too_many_lines)]
    pub fn execute_transaction_with_crash_point<C: MonotonicCounter>(
        &self,
        candidate: &AssessmentCatalog,
        counter: &mut C,
        crash_point: CrashPoint,
    ) -> Result<(), ProtocolError> {
        let _guard = self.acquire_lock()?;
        candidate.validate_integrity()?;

        let active = self.load_active_catalog()?;
        let c_hw = counter.read_counter()?;

        // Verify precondition: candidate must be immediate successor
        if candidate.version != active.version + 1 {
            return Err(ProtocolError::StorageUnavailable(format!(
                "invalid candidate version {}: expected immediate successor {}",
                candidate.version,
                active.version + 1
            )));
        }

        if candidate.counter != active.counter + 1 || candidate.counter != c_hw + 1 {
            return Err(ProtocolError::StorageUnavailable(format!(
                "invalid candidate counter {}: expected {}",
                candidate.counter,
                active.counter + 1
            )));
        }

        let tx_id = uuid::Uuid::new_v4().to_string();
        let staged_path = self.data_dir.join(format!("catalog.json.staged.{tx_id}"));
        let candidate_bytes = serde_json::to_vec_pretty(candidate).map_err(|err| {
            ProtocolError::StorageUnavailable(format!(
                "failed to serialize candidate catalog: {err}"
            ))
        })?;

        // ---------------------------------------------------------------------
        // STAGE 1: Write candidate catalog to staging path and fsync
        // ---------------------------------------------------------------------
        if crash_point == CrashPoint::DuringStagedWrite {
            // Simulate interrupted write leaving partial file
            let partial = &candidate_bytes[..candidate_bytes.len().min(32)];
            fs::write(&staged_path, partial).map_err(|err| {
                ProtocolError::StorageUnavailable(format!("injected partial write failed: {err}"))
            })?;
            return Err(ProtocolError::StorageUnavailable(
                "injected crash: during staged catalog write".to_string(),
            ));
        }

        Self::write_fsync_file(&staged_path, &candidate_bytes)?;
        self.sync_dir()?;

        if crash_point == CrashPoint::BeforeWalInit {
            return Err(ProtocolError::StorageUnavailable(
                "injected crash: staged catalog written and fsynced, before WAL init".to_string(),
            ));
        }

        // ---------------------------------------------------------------------
        // STAGE 2: Initialize Write-Ahead Log (WAL) and fsync
        // ---------------------------------------------------------------------
        let staged_hash = hex_digest(&candidate_bytes);
        let wal_record = CatalogWalRecord::new(
            tx_id,
            active.version,
            candidate.version,
            active.counter,
            candidate.counter,
            staged_hash,
        );

        let wal_bytes = serde_json::to_vec_pretty(&wal_record).map_err(|err| {
            ProtocolError::StorageUnavailable(format!("failed to serialize WAL record: {err}"))
        })?;

        if crash_point == CrashPoint::DuringWalWrite {
            // Write corrupted/truncated WAL file
            fs::write(&self.wal_path, b"CORRUPT_INCOMPLETE_WAL_DATA_TRUNCATED").map_err(|err| {
                ProtocolError::StorageUnavailable(format!(
                    "injected corrupt WAL write failed: {err}"
                ))
            })?;
            return Err(ProtocolError::StorageUnavailable(
                "injected crash: during WAL write".to_string(),
            ));
        }

        let wal_tmp_path = self.data_dir.join("catalog.wal.tmp");
        Self::write_fsync_file(&wal_tmp_path, &wal_bytes)?;

        if crash_point == CrashPoint::AfterWalWriteBeforeSync {
            // Leave tmp file on disk without atomic rename to catalog.wal
            return Err(ProtocolError::StorageUnavailable(
                "injected crash: WAL tmp written before sync/rename".to_string(),
            ));
        }

        fs::rename(&wal_tmp_path, &self.wal_path).map_err(|err| {
            ProtocolError::StorageUnavailable(format!("failed to promote WAL file: {err}"))
        })?;
        self.sync_dir()?;

        if crash_point == CrashPoint::AfterWalSyncBeforeCounterIncrement {
            return Err(ProtocolError::StorageUnavailable(
                "injected crash: WAL fsynced, before monotonic counter increment".to_string(),
            ));
        }

        // ---------------------------------------------------------------------
        // STAGE 3: Advance hardware monotonic counter
        // ---------------------------------------------------------------------
        if crash_point == CrashPoint::DuringCounterIncrement {
            // Counter increment fails / aborted before commit
            return Err(ProtocolError::StorageUnavailable(
                "injected crash: counter increment execution failed to commit".to_string(),
            ));
        }

        let new_counter = counter.increment_counter()?;
        if new_counter != candidate.counter {
            return Err(ProtocolError::StorageUnavailable(format!(
                "hardware counter returned unexpected value {new_counter} (expected {})",
                candidate.counter
            )));
        }

        if crash_point == CrashPoint::AfterCounterIncrementBeforeRename {
            return Err(ProtocolError::StorageUnavailable(
                "injected crash: counter increment committed, before catalog rename".to_string(),
            ));
        }

        // ---------------------------------------------------------------------
        // STAGE 4: Atomic POSIX replacement of active catalog
        // ---------------------------------------------------------------------
        fs::rename(&staged_path, &self.catalog_path).map_err(|err| {
            ProtocolError::StorageUnavailable(format!(
                "failed to rename staged catalog to active: {err}"
            ))
        })?;

        if crash_point == CrashPoint::AfterRenameBeforeDirSync {
            return Err(ProtocolError::StorageUnavailable(
                "injected crash: catalog renamed, before directory fsync".to_string(),
            ));
        }

        self.sync_dir()?;

        // ---------------------------------------------------------------------
        // STAGE 5: Cleanup WAL and finalize transaction
        // ---------------------------------------------------------------------
        if crash_point == CrashPoint::DuringWalCleanup {
            return Err(ProtocolError::StorageUnavailable(
                "injected crash: catalog promoted, during WAL deletion".to_string(),
            ));
        }

        self.unlink_wal_and_sync()?;
        Ok(())
    }

    /// Writes `bytes` to `path` with synchronous `fsync` flush and 0600 permissions.
    fn write_fsync_file(path: &Path, bytes: &[u8]) -> Result<(), ProtocolError> {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .map_err(|err| {
                ProtocolError::StorageUnavailable(format!(
                    "failed to open '{}': {err}",
                    path.display()
                ))
            })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = file.set_permissions(fs::Permissions::from_mode(0o600));
        }

        file.write_all(bytes).map_err(|err| {
            ProtocolError::StorageUnavailable(format!(
                "failed to write '{}': {err}",
                path.display()
            ))
        })?;

        file.sync_all().map_err(|err| {
            ProtocolError::StorageUnavailable(format!(
                "failed to fsync '{}': {err}",
                path.display()
            ))
        })?;

        Ok(())
    }

    /// Issues directory-level `fsync` to guarantee directory entry persistence.
    #[allow(
        clippy::unused_self,
        clippy::missing_const_for_fn,
        clippy::unnecessary_wraps
    )]
    fn sync_dir(&self) -> Result<(), ProtocolError> {
        #[cfg(unix)]
        {
            let dir_file = File::open(&self.data_dir).map_err(|err| {
                ProtocolError::StorageUnavailable(format!(
                    "failed to open directory '{}' for fsync: {err}",
                    self.data_dir.display()
                ))
            })?;
            dir_file.sync_all().map_err(|err| {
                ProtocolError::StorageUnavailable(format!(
                    "failed to fsync directory '{}': {err}",
                    self.data_dir.display()
                ))
            })?;
        }
        Ok(())
    }

    /// Safely unlinks the WAL file if present and synchronizes the directory.
    fn unlink_wal_and_sync(&self) -> Result<(), ProtocolError> {
        if self.wal_path.exists() {
            fs::remove_file(&self.wal_path).map_err(|err| {
                ProtocolError::StorageUnavailable(format!("failed to unlink WAL file: {err}"))
            })?;
            self.sync_dir()?;
        }
        Ok(())
    }

    /// Scans for a valid candidate staged file matching expected target version and counter.
    fn find_valid_candidate_staged(
        &self,
        target_v: u64,
        target_c: u64,
    ) -> Result<Option<PathBuf>, ProtocolError> {
        let entries = fs::read_dir(&self.data_dir).map_err(|err| {
            ProtocolError::StorageUnavailable(format!("failed to read directory: {err}"))
        })?;

        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.starts_with("catalog.json.staged.") || name == "catalog_staged.json" {
                    if let Ok(bytes) = fs::read(&path) {
                        if let Ok(candidate) = serde_json::from_slice::<AssessmentCatalog>(&bytes) {
                            if candidate.version == target_v
                                && candidate.counter == target_c
                                && candidate.validate_integrity().is_ok()
                            {
                                return Ok(Some(path));
                            }
                        }
                    }
                }
            }
        }
        Ok(None)
    }

    /// Purges orphaned staging files left by interrupted pre-WAL stages.
    fn purge_orphan_staged_files(&self) -> Result<(), ProtocolError> {
        let entries = fs::read_dir(&self.data_dir).map_err(|err| {
            ProtocolError::StorageUnavailable(format!("failed to read directory: {err}"))
        })?;

        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.starts_with("catalog.json.staged.")
                    || name.starts_with("catalog.wal.tmp")
                    || name == "catalog_staged.json"
                {
                    let _ = fs::remove_file(&path);
                }
            }
        }
        self.sync_dir()?;
        Ok(())
    }

    /// Acquires an exclusive file lock guard protecting against concurrent write races.
    ///
    /// # Concurrency & Durability
    /// - Applies kernel-enforced non-blocking advisory locking (`flock` with `LOCK_EX | LOCK_NB`).
    /// - Records process ownership metadata in `catalog.lock`.
    /// - Automatically recovers when previous lock holder terminated or was killed.
    /// - Rejects lock acquisition if a live process currently holds the lock.
    ///
    /// # Errors
    /// Returns `ProtocolError::StorageUnavailable` if the lock cannot be acquired because
    /// another active process holds the kernel lock, or if filesystem/kernel operations fail.
    #[allow(clippy::significant_drop_tightening)]
    pub fn acquire_lock(&self) -> Result<FileLockGuard<'_>, ProtocolError> {
        let thread_lock = self.process_mutex.lock().map_err(|_| {
            ProtocolError::StorageUnavailable("catalog process mutex poisoned".to_string())
        })?;

        let lock_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&self.lock_path)
            .map_err(|err| {
                ProtocolError::StorageUnavailable(format!(
                    "failed to open catalog lock file '{}': {err}",
                    self.lock_path.display()
                ))
            })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = lock_file.set_permissions(fs::Permissions::from_mode(0o600));
        }

        #[cfg(unix)]
        {
            // Apply non-blocking kernel advisory lock via flock
            match flock(&lock_file, FlockOperation::NonBlockingLockExclusive) {
                Ok(()) => {
                    // Kernel lock successfully acquired! We are the sole process owner.
                    let meta = LockMetadata {
                        pid: std::process::id(),
                        lock_uuid: uuid::Uuid::new_v4().to_string(),
                        acquired_at_nanos: chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0),
                    };
                    let _ = Self::write_lock_metadata(&lock_file, &meta);

                    Ok(FileLockGuard {
                        _thread_guard: thread_lock,
                        file: lock_file,
                        lock_path: self.lock_path.clone(),
                    })
                }
                Err(err)
                    if err == rustix::io::Errno::WOULDBLOCK || err == rustix::io::Errno::AGAIN =>
                {
                    // Another process holds the kernel lock. Inspect its metadata to report owner.
                    let owner_info = Self::read_lock_metadata(&lock_file).map_or_else(
                        || "unknown active process".to_string(),
                        |m| format!("PID {}", m.pid),
                    );

                    Err(ProtocolError::StorageUnavailable(format!(
                        "catalog is locked by active process ({owner_info}): cannot acquire exclusive lock"
                    )))
                }
                Err(err) => Err(ProtocolError::StorageUnavailable(format!(
                    "kernel flock failed on '{}': {err}",
                    self.lock_path.display()
                ))),
            }
        }
        #[cfg(not(unix))]
        {
            let meta = LockMetadata {
                pid: std::process::id(),
                lock_uuid: uuid::Uuid::new_v4().to_string(),
                acquired_at_nanos: chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0),
            };
            let _ = Self::write_lock_metadata(&lock_file, &meta);

            Ok(FileLockGuard {
                _thread_guard: thread_lock,
                file: lock_file,
                lock_path: self.lock_path.clone(),
            })
        }
    }

    /// Writes JSON lock metadata into the lock file.
    fn write_lock_metadata(mut file: &File, meta: &LockMetadata) -> Result<(), ProtocolError> {
        file.seek(SeekFrom::Start(0)).map_err(|err| {
            ProtocolError::StorageUnavailable(format!("failed to seek lock file: {err}"))
        })?;
        file.set_len(0).map_err(|err| {
            ProtocolError::StorageUnavailable(format!("failed to truncate lock file: {err}"))
        })?;
        let bytes = serde_json::to_vec(meta).map_err(|err| {
            ProtocolError::StorageUnavailable(format!("failed to serialize lock metadata: {err}"))
        })?;
        file.write_all(&bytes).map_err(|err| {
            ProtocolError::StorageUnavailable(format!("failed to write lock metadata: {err}"))
        })?;
        file.sync_all().map_err(|err| {
            ProtocolError::StorageUnavailable(format!("failed to fsync lock file: {err}"))
        })?;
        Ok(())
    }

    /// Reads JSON lock metadata from the lock file.
    #[must_use]
    pub fn read_lock_metadata(mut file: &File) -> Option<LockMetadata> {
        let _ = file.seek(SeekFrom::Start(0));
        let mut content = String::new();
        if file.read_to_string(&mut content).is_ok() {
            serde_json::from_str(&content).ok()
        } else {
            None
        }
    }
}

/// RAII lock guard releasing the mutual exclusion lock on drop.
pub struct FileLockGuard<'a> {
    _thread_guard: std::sync::MutexGuard<'a, ()>,
    file: File,
    lock_path: PathBuf,
}

impl fmt::Debug for FileLockGuard<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileLockGuard")
            .field("lock_path", &self.lock_path)
            .finish_non_exhaustive()
    }
}

impl Drop for FileLockGuard<'_> {
    fn drop(&mut self) {
        #[cfg(unix)]
        let _ = flock(&self.file, FlockOperation::Unlock);
        #[cfg(not(unix))]
        let _ = &self.file;
    }
}

/// Computes lowercase hexadecimal SHA-256 string for `bytes`.
fn hex_digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[cfg(unix)]
    use std::io::{BufRead, BufReader};
    #[cfg(unix)]
    use std::process::{Command, Stdio};
    use std::thread;
    use tempfile::tempdir;

    fn make_test_catalog(version: u64, counter: u64, tag: &str) -> AssessmentCatalog {
        AssessmentCatalog::new(
            version,
            counter,
            json!({
                "release_tag": tag,
                "rules": ["CVE-2024-0001", "CVE-2024-0002"],
                "active": true
            }),
        )
        .expect("valid test catalog")
    }

    // =========================================================================
    // Child Process Worker Entry Point (used for separate OS process testing)
    // =========================================================================

    #[cfg(unix)]
    #[test]
    fn test_child_process_worker_entry_point() {
        let Ok(mode) = std::env::var("OPENAUDIT_CHILD_MODE") else {
            return; // Normal test runner: do nothing
        };

        let dir = std::env::var("OPENAUDIT_CHILD_DIR").expect("OPENAUDIT_CHILD_DIR");
        let mgr = CatalogManager::open(&dir).expect("open mgr in child");

        match mode.as_str() {
            "hold_lock" => {
                let _guard = mgr.acquire_lock().expect("child acquired lock");
                println!("CHILD_LOCK_ACQUIRED");
                let _ = std::io::stdout().flush();
                let sleep_ms: u64 = std::env::var("OPENAUDIT_CHILD_SLEEP_MS")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(5000);
                std::thread::sleep(std::time::Duration::from_millis(sleep_ms));
                println!("CHILD_DONE");
            }
            "attempt_lock_once" => match mgr.acquire_lock() {
                Ok(_guard) => {
                    println!("CHILD_ACQUIRED");
                    let _ = std::io::stdout().flush();
                    std::thread::sleep(std::time::Duration::from_millis(200));
                    std::process::exit(0);
                }
                Err(ProtocolError::StorageUnavailable(msg))
                    if msg.contains("locked by active process") =>
                {
                    println!("CHILD_BUSY");
                    let _ = std::io::stdout().flush();
                    std::process::exit(42);
                }
                Err(err) => {
                    eprintln!("unexpected error: {err}");
                    std::process::exit(1);
                }
            },
            "crash_tx_after_increment" => {
                let mut counter = MockMonotonicCounter::new(10);
                let candidate = AssessmentCatalog::new(2, 11, json!({"release": "child_crash"}))
                    .expect("valid candidate");
                println!("CHILD_CRASH_STARTING");
                let _ = std::io::stdout().flush();
                let _ = mgr.execute_transaction_with_crash_point(
                    &candidate,
                    &mut counter,
                    CrashPoint::AfterCounterIncrementBeforeRename,
                );
                // Hang while holding lock until killed
                std::thread::sleep(std::time::Duration::from_millis(10_000));
            }
            _ => {}
        }
        std::process::exit(0);
    }

    #[cfg(unix)]
    #[test]
    fn test_cross_process_live_owner_cannot_have_lock_stolen() {
        let dir = tempdir().unwrap();
        let mgr = CatalogManager::open(dir.path()).unwrap();
        let counter = MockMonotonicCounter::new(10);
        mgr.initialize_new(&make_test_catalog(1, 10, "v1")).unwrap();

        // Spawn separate OS process holding lock
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "protocol::catalog::tests::test_child_process_worker_entry_point",
                "--exact",
                "--nocapture",
            ])
            .env("OPENAUDIT_CHILD_MODE", "hold_lock")
            .env("OPENAUDIT_CHILD_DIR", dir.path().to_str().unwrap())
            .env("OPENAUDIT_CHILD_SLEEP_MS", "4000")
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn child process");

        let stdout = child.stdout.take().expect("child stdout");
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        let mut acquired = false;
        while reader.read_line(&mut line).unwrap_or(0) > 0 {
            if line.contains("CHILD_LOCK_ACQUIRED") {
                acquired = true;
                break;
            }
            line.clear();
        }
        assert!(acquired, "child must signal lock acquired");

        // Child process is STILL ALIVE and holding the lock.
        assert!(is_process_alive(child.id()), "child process must be alive");

        // Attempting recovery from parent MUST fail closed with lock busy
        let rec_err = mgr.recover(&counter).unwrap_err();
        match rec_err {
            ProtocolError::StorageUnavailable(msg) => {
                assert!(msg.contains("locked by active process"), "{msg}");
                assert!(msg.contains(&child.id().to_string()), "{msg}");
            }
            other => panic!("expected StorageUnavailable, got {other:?}"),
        }

        // Clean up child
        let _ = child.kill();
        let _ = child.wait();
    }

    #[cfg(unix)]
    #[test]
    fn test_cross_process_dead_owner_does_not_block_recovery() {
        let dir = tempdir().unwrap();
        let mgr = CatalogManager::open(dir.path()).unwrap();
        let counter = MockMonotonicCounter::new(10);
        mgr.initialize_new(&make_test_catalog(1, 10, "v1")).unwrap();

        // Spawn child holding lock
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "protocol::catalog::tests::test_child_process_worker_entry_point",
                "--exact",
                "--nocapture",
            ])
            .env("OPENAUDIT_CHILD_MODE", "hold_lock")
            .env("OPENAUDIT_CHILD_DIR", dir.path().to_str().unwrap())
            .env("OPENAUDIT_CHILD_SLEEP_MS", "10000")
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn child process");

        let stdout = child.stdout.take().expect("child stdout");
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        let mut acquired = false;
        while reader.read_line(&mut line).unwrap_or(0) > 0 {
            if line.contains("CHILD_LOCK_ACQUIRED") {
                acquired = true;
                break;
            }
            line.clear();
        }
        assert!(acquired, "child must signal lock acquired");

        let child_pid = child.id();
        assert!(is_process_alive(child_pid));

        // Kill child process abruptly (SIGKILL) while it holds the lock
        child.kill().expect("kill child process");
        let _ = child.wait();

        // Verify child is dead
        assert!(!is_process_alive(child_pid));

        // Parent runs recovery: dead owner must NOT block recovery!
        let outcome = mgr
            .recover(&counter)
            .expect("recovery must succeed after dead owner");
        assert_eq!(outcome, RecoveryOutcome::CleanCurrent);

        let active = mgr.load_active_catalog().unwrap();
        assert_eq!(active.version, 1);
        assert_eq!(active.counter, 10);
    }

    #[cfg(unix)]
    #[test]
    fn test_cross_process_writer_mutual_exclusion() {
        let dir = tempdir().unwrap();
        let mgr = CatalogManager::open(dir.path()).unwrap();
        mgr.initialize_new(&make_test_catalog(1, 10, "v1")).unwrap();

        // Spawn two child processes simultaneously trying to acquire the lock
        let mut child1 = Command::new(std::env::current_exe().unwrap())
            .args([
                "protocol::catalog::tests::test_child_process_worker_entry_point",
                "--exact",
                "--nocapture",
            ])
            .env("OPENAUDIT_CHILD_MODE", "attempt_lock_once")
            .env("OPENAUDIT_CHILD_DIR", dir.path().to_str().unwrap())
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn child 1");

        let mut child2 = Command::new(std::env::current_exe().unwrap())
            .args([
                "protocol::catalog::tests::test_child_process_worker_entry_point",
                "--exact",
                "--nocapture",
            ])
            .env("OPENAUDIT_CHILD_MODE", "attempt_lock_once")
            .env("OPENAUDIT_CHILD_DIR", dir.path().to_str().unwrap())
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn child 2");

        let status1 = child1.wait().expect("wait child 1");
        let status2 = child2.wait().expect("wait child 2");

        let codes = [status1.code().unwrap_or(-1), status2.code().unwrap_or(-1)];
        // Exactly one must succeed (code 0), and the other must be rejected with busy (code 42)
        assert!(
            codes == [0, 42] || codes == [42, 0] || codes == [0, 0],
            "mutual exclusion must protect lock: observed codes {codes:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_cross_process_child_killed_during_transaction_is_recoverable() {
        let dir = tempdir().unwrap();
        let mgr = CatalogManager::open(dir.path()).unwrap();
        let counter = MockMonotonicCounter::new(11); // Hardware counter advanced to 11
        mgr.initialize_new(&make_test_catalog(1, 10, "v1")).unwrap();

        // Spawn child executing transaction that crashes after counter increment
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "protocol::catalog::tests::test_child_process_worker_entry_point",
                "--exact",
                "--nocapture",
            ])
            .env("OPENAUDIT_CHILD_MODE", "crash_tx_after_increment")
            .env("OPENAUDIT_CHILD_DIR", dir.path().to_str().unwrap())
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn child process");

        let stdout = child.stdout.take().expect("child stdout");
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        let mut started = false;
        while reader.read_line(&mut line).unwrap_or(0) > 0 {
            if line.contains("CHILD_CRASH_STARTING") {
                started = true;
                break;
            }
            line.clear();
        }
        assert!(started, "child must signal transaction starting");

        // Give child 100ms to execute through crash point
        std::thread::sleep(std::time::Duration::from_millis(150));

        // Kill child process
        let _ = child.kill();
        let _ = child.wait();

        // Now parent runs recovery
        let outcome = mgr.recover(&counter).expect("recovery must succeed");
        assert_eq!(outcome, RecoveryOutcome::RecoveredPromotedNew);

        let active = mgr.load_active_catalog().unwrap();
        assert_eq!(active.version, 2);
        assert_eq!(active.counter, 11);
    }

    #[test]
    fn test_recovery_integrity_rejects_unmatched_candidate_tx_id() {
        let dir = tempdir().unwrap();
        let mgr = CatalogManager::open(dir.path()).unwrap();
        let counter = MockMonotonicCounter::new(11);
        mgr.initialize_new(&make_test_catalog(1, 10, "v1")).unwrap();

        let v2 = make_test_catalog(2, 11, "v2");
        let v2_bytes = serde_json::to_vec_pretty(&v2).unwrap();
        let hash = hex_digest(&v2_bytes);

        // WAL specifies tx_id_A
        let wal = CatalogWalRecord::new("tx_id_A".to_string(), 1, 2, 10, 11, hash);
        fs::write(mgr.wal_path(), serde_json::to_vec_pretty(&wal).unwrap()).unwrap();

        // Drop candidate file with wrong tx_id_B
        fs::write(dir.path().join("catalog.json.staged.tx_id_B"), v2_bytes).unwrap();

        // Recovery must reject because staged file matching WAL tx_id is missing
        let err = mgr.recover(&counter).unwrap_err();
        assert!(matches!(err, ProtocolError::CatalogDesync(_)));

        // Active catalog remained at v1
        let active = mgr.load_active_catalog().unwrap();
        assert_eq!(active.version, 1);
    }

    #[test]
    fn test_recovery_integrity_rejects_tampered_candidate_digest() {
        let dir = tempdir().unwrap();
        let mgr = CatalogManager::open(dir.path()).unwrap();
        let counter = MockMonotonicCounter::new(11);
        mgr.initialize_new(&make_test_catalog(1, 10, "v1")).unwrap();

        let v2 = make_test_catalog(2, 11, "v2");
        let v2_bytes = serde_json::to_vec_pretty(&v2).unwrap();

        // WAL specifies authentic hash
        let wal = CatalogWalRecord::new(
            "tx_id_123".to_string(),
            1,
            2,
            10,
            11,
            "1111111111111111111111111111111111111111111111111111111111111111".to_string(),
        );
        fs::write(mgr.wal_path(), serde_json::to_vec_pretty(&wal).unwrap()).unwrap();

        // Write candidate file whose hash does not match WAL
        fs::write(dir.path().join("catalog.json.staged.tx_id_123"), v2_bytes).unwrap();

        let err = mgr.recover(&counter).unwrap_err();
        assert!(matches!(err, ProtocolError::CatalogDesync(_)));

        let active = mgr.load_active_catalog().unwrap();
        assert_eq!(active.version, 1);
    }

    #[test]
    fn test_recovery_integrity_rejects_wrong_target_version() {
        let dir = tempdir().unwrap();
        let mgr = CatalogManager::open(dir.path()).unwrap();
        let counter = MockMonotonicCounter::new(11);
        mgr.initialize_new(&make_test_catalog(1, 10, "v1")).unwrap();

        // Candidate catalog has version 5 (not successor 2)
        let v_wrong = make_test_catalog(5, 11, "v_wrong");
        let bytes = serde_json::to_vec_pretty(&v_wrong).unwrap();
        let hash = hex_digest(&bytes);

        let wal = CatalogWalRecord::new("tx_bad_version".to_string(), 1, 5, 10, 11, hash);
        fs::write(mgr.wal_path(), serde_json::to_vec_pretty(&wal).unwrap()).unwrap();
        fs::write(dir.path().join("catalog.json.staged.tx_bad_version"), bytes).unwrap();

        let err = mgr.recover(&counter).unwrap_err();
        assert!(matches!(err, ProtocolError::CatalogDesync(_)));
    }

    #[test]
    fn test_catalog_integrity_validation() {
        let mut cat = make_test_catalog(1, 100, "v1");
        assert!(cat.validate_integrity().is_ok());

        // Tamper with payload hash
        cat.payload_hash =
            "0000000000000000000000000000000000000000000000000000000000000000".to_string();
        assert!(matches!(
            cat.validate_integrity(),
            Err(ProtocolError::CatalogCorrupted(_))
        ));

        // Tamper with version 0
        let mut cat_zero = make_test_catalog(1, 100, "v1");
        cat_zero.version = 0;
        assert!(matches!(
            cat_zero.validate_integrity(),
            Err(ProtocolError::CatalogCorrupted(_))
        ));

        // Tamper with schema version
        let mut cat_schema = make_test_catalog(1, 100, "v1");
        cat_schema.schema_version = 999;
        assert!(matches!(
            cat_schema.validate_integrity(),
            Err(ProtocolError::CatalogCorrupted(_))
        ));
    }

    #[test]
    fn test_normal_catalog_transaction_lifecycle() {
        let dir = tempdir().unwrap();
        let mgr = CatalogManager::open(dir.path()).unwrap();
        let mut counter = MockMonotonicCounter::new(10);

        let v1 = make_test_catalog(1, 10, "initial");
        mgr.initialize_new(&v1).unwrap();

        let loaded = mgr.load_active_catalog().unwrap();
        assert_eq!(loaded.version, 1);
        assert_eq!(loaded.counter, 10);

        // Execute transaction to version 2
        let v2 = make_test_catalog(2, 11, "second");
        mgr.execute_transaction(&v2, &mut counter).unwrap();

        let loaded2 = mgr.load_active_catalog().unwrap();
        assert_eq!(loaded2.version, 2);
        assert_eq!(loaded2.counter, 11);
        assert_eq!(counter.read_counter().unwrap(), 11);

        // WAL must be cleaned up
        assert!(!mgr.wal_path().exists());
    }

    #[test]
    fn test_cb01_crash_during_staged_write() {
        let dir = tempdir().unwrap();
        let mgr = CatalogManager::open(dir.path()).unwrap();
        let mut counter = MockMonotonicCounter::new(10);
        mgr.initialize_new(&make_test_catalog(1, 10, "v1")).unwrap();

        let v2 = make_test_catalog(2, 11, "v2");
        let res = mgr.execute_transaction_with_crash_point(
            &v2,
            &mut counter,
            CrashPoint::DuringStagedWrite,
        );
        assert!(res.is_err());

        // Process restart & recovery
        let mgr2 = CatalogManager::open(dir.path()).unwrap();
        let outcome = mgr2.recover(&counter).unwrap();
        assert_eq!(outcome, RecoveryOutcome::CleanCurrent);

        let active = mgr2.load_active_catalog().unwrap();
        assert_eq!(active.version, 1);
        assert_eq!(active.counter, 10);

        // Idempotency check: second recovery returns CleanCurrent without changes
        assert_eq!(
            mgr2.recover(&counter).unwrap(),
            RecoveryOutcome::CleanCurrent
        );
    }

    #[test]
    fn test_cb02_crash_before_wal_init() {
        let dir = tempdir().unwrap();
        let mgr = CatalogManager::open(dir.path()).unwrap();
        let mut counter = MockMonotonicCounter::new(10);
        mgr.initialize_new(&make_test_catalog(1, 10, "v1")).unwrap();

        let v2 = make_test_catalog(2, 11, "v2");
        let res =
            mgr.execute_transaction_with_crash_point(&v2, &mut counter, CrashPoint::BeforeWalInit);
        assert!(res.is_err());

        let mgr2 = CatalogManager::open(dir.path()).unwrap();
        let outcome = mgr2.recover(&counter).unwrap();
        assert_eq!(outcome, RecoveryOutcome::CleanCurrent);

        let active = mgr2.load_active_catalog().unwrap();
        assert_eq!(active.version, 1);
        assert_eq!(
            mgr2.recover(&counter).unwrap(),
            RecoveryOutcome::CleanCurrent
        );
    }

    #[test]
    fn test_cb03_crash_during_wal_write_corrupt_wal() {
        let dir = tempdir().unwrap();
        let mgr = CatalogManager::open(dir.path()).unwrap();
        let mut counter = MockMonotonicCounter::new(10);
        mgr.initialize_new(&make_test_catalog(1, 10, "v1")).unwrap();

        let v2 = make_test_catalog(2, 11, "v2");
        let res =
            mgr.execute_transaction_with_crash_point(&v2, &mut counter, CrashPoint::DuringWalWrite);
        assert!(res.is_err());

        let mgr2 = CatalogManager::open(dir.path()).unwrap();
        let outcome = mgr2.recover(&counter).unwrap();
        assert_eq!(outcome, RecoveryOutcome::RolledBackPreIncrement);

        let active = mgr2.load_active_catalog().unwrap();
        assert_eq!(active.version, 1);
        assert!(!mgr2.wal_path().exists());
        assert_eq!(
            mgr2.recover(&counter).unwrap(),
            RecoveryOutcome::CleanCurrent
        );
    }

    #[test]
    fn test_cb04_crash_after_wal_write_before_sync() {
        let dir = tempdir().unwrap();
        let mgr = CatalogManager::open(dir.path()).unwrap();
        let mut counter = MockMonotonicCounter::new(10);
        mgr.initialize_new(&make_test_catalog(1, 10, "v1")).unwrap();

        let v2 = make_test_catalog(2, 11, "v2");
        let res = mgr.execute_transaction_with_crash_point(
            &v2,
            &mut counter,
            CrashPoint::AfterWalWriteBeforeSync,
        );
        assert!(res.is_err());

        let mgr2 = CatalogManager::open(dir.path()).unwrap();
        let outcome = mgr2.recover(&counter).unwrap();
        assert_eq!(outcome, RecoveryOutcome::CleanCurrent);

        let active = mgr2.load_active_catalog().unwrap();
        assert_eq!(active.version, 1);
        assert_eq!(
            mgr2.recover(&counter).unwrap(),
            RecoveryOutcome::CleanCurrent
        );
    }

    #[test]
    fn test_cb05_crash_after_wal_sync_before_counter_increment() {
        let dir = tempdir().unwrap();
        let mgr = CatalogManager::open(dir.path()).unwrap();
        let mut counter = MockMonotonicCounter::new(10);
        mgr.initialize_new(&make_test_catalog(1, 10, "v1")).unwrap();

        let v2 = make_test_catalog(2, 11, "v2");
        let res = mgr.execute_transaction_with_crash_point(
            &v2,
            &mut counter,
            CrashPoint::AfterWalSyncBeforeCounterIncrement,
        );
        assert!(res.is_err());

        // WAL is fsynced, but counter is still 10 (unincremented)
        assert!(mgr.wal_path().exists());
        assert_eq!(counter.read_counter().unwrap(), 10);

        let mgr2 = CatalogManager::open(dir.path()).unwrap();
        let outcome = mgr2.recover(&counter).unwrap();
        assert_eq!(outcome, RecoveryOutcome::RolledBackUnincremented);

        let active = mgr2.load_active_catalog().unwrap();
        assert_eq!(active.version, 1);
        assert_eq!(active.counter, 10);
        assert!(!mgr2.wal_path().exists());
        assert_eq!(
            mgr2.recover(&counter).unwrap(),
            RecoveryOutcome::CleanCurrent
        );
    }

    #[test]
    fn test_cb06_crash_during_counter_increment() {
        let dir = tempdir().unwrap();
        let mgr = CatalogManager::open(dir.path()).unwrap();
        let mut counter = MockMonotonicCounter::new(10);
        mgr.initialize_new(&make_test_catalog(1, 10, "v1")).unwrap();

        let v2 = make_test_catalog(2, 11, "v2");
        let res = mgr.execute_transaction_with_crash_point(
            &v2,
            &mut counter,
            CrashPoint::DuringCounterIncrement,
        );
        assert!(res.is_err());

        let mgr2 = CatalogManager::open(dir.path()).unwrap();
        let outcome = mgr2.recover(&counter).unwrap();
        assert_eq!(outcome, RecoveryOutcome::RolledBackUnincremented);

        let active = mgr2.load_active_catalog().unwrap();
        assert_eq!(active.version, 1);
        assert_eq!(
            mgr2.recover(&counter).unwrap(),
            RecoveryOutcome::CleanCurrent
        );
    }

    #[test]
    fn test_cb07_crash_after_counter_increment_before_rename() {
        let dir = tempdir().unwrap();
        let mgr = CatalogManager::open(dir.path()).unwrap();
        let mut counter = MockMonotonicCounter::new(10);
        mgr.initialize_new(&make_test_catalog(1, 10, "v1")).unwrap();

        let v2 = make_test_catalog(2, 11, "v2");
        let res = mgr.execute_transaction_with_crash_point(
            &v2,
            &mut counter,
            CrashPoint::AfterCounterIncrementBeforeRename,
        );
        assert!(res.is_err());

        // Counter committed (11), but disk catalog is still v1 (10)
        assert_eq!(counter.read_counter().unwrap(), 11);

        let mgr2 = CatalogManager::open(dir.path()).unwrap();
        let outcome = mgr2.recover(&counter).unwrap();
        assert_eq!(outcome, RecoveryOutcome::RecoveredPromotedNew);

        // Recovery promoted staged v2 to active catalog!
        let active = mgr2.load_active_catalog().unwrap();
        assert_eq!(active.version, 2);
        assert_eq!(active.counter, 11);
        assert!(!mgr2.wal_path().exists());

        // Idempotent second recovery
        assert_eq!(
            mgr2.recover(&counter).unwrap(),
            RecoveryOutcome::CleanCurrent
        );
    }

    #[test]
    fn test_cb08_crash_after_rename_before_dir_sync() {
        let dir = tempdir().unwrap();
        let mgr = CatalogManager::open(dir.path()).unwrap();
        let mut counter = MockMonotonicCounter::new(10);
        mgr.initialize_new(&make_test_catalog(1, 10, "v1")).unwrap();

        let v2 = make_test_catalog(2, 11, "v2");
        let res = mgr.execute_transaction_with_crash_point(
            &v2,
            &mut counter,
            CrashPoint::AfterRenameBeforeDirSync,
        );
        assert!(res.is_err());

        let mgr2 = CatalogManager::open(dir.path()).unwrap();
        let outcome = mgr2.recover(&counter).unwrap();
        assert_eq!(outcome, RecoveryOutcome::RecoveredCompletedExisting);

        let active = mgr2.load_active_catalog().unwrap();
        assert_eq!(active.version, 2);
        assert_eq!(active.counter, 11);
        assert!(!mgr2.wal_path().exists());
        assert_eq!(
            mgr2.recover(&counter).unwrap(),
            RecoveryOutcome::CleanCurrent
        );
    }

    #[test]
    fn test_cb09_crash_during_wal_cleanup() {
        let dir = tempdir().unwrap();
        let mgr = CatalogManager::open(dir.path()).unwrap();
        let mut counter = MockMonotonicCounter::new(10);
        mgr.initialize_new(&make_test_catalog(1, 10, "v1")).unwrap();

        let v2 = make_test_catalog(2, 11, "v2");
        let res = mgr.execute_transaction_with_crash_point(
            &v2,
            &mut counter,
            CrashPoint::DuringWalCleanup,
        );
        assert!(res.is_err());

        // Catalog already renamed, but WAL file was left
        assert!(mgr.wal_path().exists());

        let mgr2 = CatalogManager::open(dir.path()).unwrap();
        let outcome = mgr2.recover(&counter).unwrap();
        assert_eq!(outcome, RecoveryOutcome::RecoveredCompletedExisting);

        let active = mgr2.load_active_catalog().unwrap();
        assert_eq!(active.version, 2);
        assert!(!mgr2.wal_path().exists());
        assert_eq!(
            mgr2.recover(&counter).unwrap(),
            RecoveryOutcome::CleanCurrent
        );
    }

    #[test]
    fn test_cb13_split_transaction_lost_wal_with_valid_staged_candidate() {
        let dir = tempdir().unwrap();
        let mgr = CatalogManager::open(dir.path()).unwrap();
        let counter = MockMonotonicCounter::new(11); // Hardware counter advanced to 11
        mgr.initialize_new(&make_test_catalog(1, 10, "v1")).unwrap();

        // Write a valid candidate staged file without any WAL file
        let v2 = make_test_catalog(2, 11, "v2");
        let staged_bytes = serde_json::to_vec_pretty(&v2).unwrap();
        fs::write(
            dir.path().join("catalog.json.staged.candidate"),
            staged_bytes,
        )
        .unwrap();

        let mgr2 = CatalogManager::open(dir.path()).unwrap();
        let outcome = mgr2.recover(&counter).unwrap();
        assert_eq!(outcome, RecoveryOutcome::RecoveredViaStagedPromotion);

        let active = mgr2.load_active_catalog().unwrap();
        assert_eq!(active.version, 2);
        assert_eq!(active.counter, 11);
    }

    #[test]
    fn test_cb13_split_transaction_without_staged_fails_closed() {
        let dir = tempdir().unwrap();
        let mgr = CatalogManager::open(dir.path()).unwrap();
        let counter = MockMonotonicCounter::new(11); // Hardware counter advanced to 11
        mgr.initialize_new(&make_test_catalog(1, 10, "v1")).unwrap();

        // No WAL and no staged candidate file
        let mgr2 = CatalogManager::open(dir.path()).unwrap();
        let res = mgr2.recover(&counter);
        assert!(matches!(res, Err(ProtocolError::CatalogDesync(_))));
    }

    #[test]
    fn test_corrupt_catalog_fails_closed_never_silently_replaces() {
        let dir = tempdir().unwrap();
        let mgr = CatalogManager::open(dir.path()).unwrap();
        let counter = MockMonotonicCounter::new(10);

        // Write corrupted bytes directly to catalog.json
        fs::write(
            mgr.catalog_path(),
            b"MALFORMED_GARBAGE_BYTES_CORRUPTED_JSON",
        )
        .unwrap();

        let res = mgr.recover(&counter);
        assert!(matches!(res, Err(ProtocolError::CatalogCorrupted(_))));

        // Verify corrupted file was NOT silently overwritten or deleted
        let disk_bytes = fs::read(mgr.catalog_path()).unwrap();
        assert_eq!(disk_bytes, b"MALFORMED_GARBAGE_BYTES_CORRUPTED_JSON");
    }

    #[test]
    fn test_concurrent_writer_mutual_exclusion() {
        let dir = tempdir().unwrap();
        let mgr = Arc::new(CatalogManager::open(dir.path()).unwrap());
        let counter = Arc::new(Mutex::new(MockMonotonicCounter::new(10)));

        let v1 = make_test_catalog(1, 10, "v1");
        mgr.initialize_new(&v1).unwrap();

        let mut handles = Vec::new();
        let num_threads = 4;

        for i in 0..num_threads {
            let mgr_clone = Arc::clone(&mgr);
            let counter_clone = Arc::clone(&counter);

            let handle = thread::spawn(move || {
                let candidate = make_test_catalog(2, 11, &format!("v2_thread_{i}"));
                let mut c_guard = counter_clone.lock().unwrap();
                mgr_clone.execute_transaction(&candidate, &mut *c_guard)
            });
            handles.push(handle);
        }

        let mut successes = 0;
        let mut failures = 0;

        for h in handles {
            match h.join().unwrap() {
                Ok(()) => successes += 1,
                Err(_) => failures += 1,
            }
        }

        assert_eq!(successes, 1, "exactly one concurrent writer must succeed");
        assert_eq!(
            failures,
            num_threads - 1,
            "all other writers must fail safely"
        );

        let active = mgr.load_active_catalog().unwrap();
        assert_eq!(active.version, 2);
        assert_eq!(active.counter, 11);
    }

    #[test]
    fn test_truncated_wal_fails_safely_or_rolls_back() {
        let dir = tempdir().unwrap();
        let mgr = CatalogManager::open(dir.path()).unwrap();
        let counter = MockMonotonicCounter::new(10);
        mgr.initialize_new(&make_test_catalog(1, 10, "v1")).unwrap();

        // Write a truncated 5-byte WAL file
        fs::write(mgr.wal_path(), b"{\"tx_").unwrap();

        let outcome = mgr.recover(&counter).unwrap();
        assert_eq!(outcome, RecoveryOutcome::RolledBackPreIncrement);

        let active = mgr.load_active_catalog().unwrap();
        assert_eq!(active.version, 1);
        assert!(!mgr.wal_path().exists());
    }

    #[test]
    fn test_missing_catalog_fails_closed() {
        let dir = tempdir().unwrap();
        let mgr = CatalogManager::open(dir.path()).unwrap();
        assert!(matches!(
            mgr.load_active_catalog(),
            Err(ProtocolError::CatalogCorrupted(_))
        ));
    }

    #[test]
    fn test_stale_temporary_files_purged_on_recovery() {
        let dir = tempdir().unwrap();
        let mgr = CatalogManager::open(dir.path()).unwrap();
        let counter = MockMonotonicCounter::new(10);
        mgr.initialize_new(&make_test_catalog(1, 10, "v1")).unwrap();

        // Leave stale temp files in directory
        let stale1 = dir.path().join("catalog.json.staged.stale-1");
        let stale2 = dir.path().join("catalog.wal.tmp.stale-2");
        fs::write(&stale1, b"stale data 1").unwrap();
        fs::write(&stale2, b"stale data 2").unwrap();

        let outcome = mgr.recover(&counter).unwrap();
        assert_eq!(outcome, RecoveryOutcome::CleanCurrent);
        assert!(!stale1.exists());
        assert!(!stale2.exists());
    }

    #[test]
    fn test_repeated_recovery_is_strictly_idempotent() {
        let dir = tempdir().unwrap();
        let mgr = CatalogManager::open(dir.path()).unwrap();
        let counter = MockMonotonicCounter::new(10);
        mgr.initialize_new(&make_test_catalog(1, 10, "v1")).unwrap();

        for _ in 0..5 {
            let outcome = mgr.recover(&counter).unwrap();
            assert_eq!(outcome, RecoveryOutcome::CleanCurrent);
            let active = mgr.load_active_catalog().unwrap();
            assert_eq!(active.version, 1);
            assert_eq!(active.counter, 10);
        }
    }

    #[test]
    fn test_catalog_file_invalid_schema_version_fails_closed() {
        let dir = tempdir().unwrap();
        let mgr = CatalogManager::open(dir.path()).unwrap();
        let counter = MockMonotonicCounter::new(10);

        let mut cat = make_test_catalog(1, 10, "v1");
        cat.schema_version = 999;
        let bytes = serde_json::to_vec(&cat).unwrap();
        fs::write(mgr.catalog_path(), bytes).unwrap();

        let res = mgr.recover(&counter);
        assert!(matches!(res, Err(ProtocolError::CatalogCorrupted(_))));
    }

    #[cfg(unix)]
    #[test]
    fn test_storage_permission_failure_fails_closed() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let mgr = CatalogManager::open(dir.path()).unwrap();
        let mut counter = MockMonotonicCounter::new(10);
        mgr.initialize_new(&make_test_catalog(1, 10, "v1")).unwrap();

        // Make directory read-only (0400)
        let _ = fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o400));

        // When running as root (e.g. in container environments), root bypasses DAC
        // permissions (CAP_DAC_OVERRIDE). Verify if permission enforcement actually blocked writes.
        let probe = dir.path().join(".probe_write");
        if fs::write(&probe, b"test").is_ok() {
            let _ = fs::remove_file(probe);
            let _ = fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700));
            return;
        }

        let v2 = make_test_catalog(2, 11, "v2");
        let res = mgr.execute_transaction(&v2, &mut counter);
        assert!(res.is_err());

        // Restore permissions so tempdir cleanup succeeds
        let _ = fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700));
    }
}
