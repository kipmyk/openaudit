//! Authority orchestration service for OpenAudit M3 D4.
//!
//! Provides the central authority-side workflow coordinating:
//! 1. Single-use challenge nonce and enrollment token issuance and atomic consumption.
//! 2. Canonical enrollment transcript validation and SPKI parameter verification.
//! 3. Cryptographic outbox retrieval validation preserving exact security ordering
//!    (timestamp skew check -> HMAC proof verification -> atomic `SQLite` WAL replay consumption).
//! 4. Assessment catalog update durability transactions and monotonic counter synchronization.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::protocol::catalog::{
    AssessmentCatalog, CatalogManager, MonotonicCounter, RecoveryOutcome,
};
use crate::protocol::crypto::{RustCryptoMacVerifier, RustCryptoSpkiValidator};
use crate::protocol::error::ProtocolError;
use crate::protocol::traits::{KeyMetadata, MacVerifier, ReplayStore, SpkiValidator};
use crate::protocol::trust::{
    UnverifiedRetrievalRequest, VerifiedRetrievalRequest, MAX_CLOCK_SKEW_NANOS,
};
use crate::protocol::types::{
    CatalogVersion, ChallengeNonce, CounterValue, EnrollmentGeneration, EnrollmentTokenId,
    EnrollmentTranscript, LifecycleId, MachineId, SharedSecret, SrkName, TimestampNs,
    TransactionId,
};

/// Record representing an issued, single-use enrollment authorization token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedTokenRecord {
    /// Unique identifier for the enrollment token.
    pub token_id: EnrollmentTokenId,
    /// Targeted machine identifier authorized to consume this token.
    pub machine_id: MachineId,
    /// Expected cryptographic challenge nonce issued to the node.
    pub expected_nonce: ChallengeNonce,
    /// Expected enrollment generation for this machine.
    pub expected_generation: EnrollmentGeneration,
    /// Absolute expiration timestamp for this token in Unix nanoseconds.
    pub expires_at: TimestampNs,
    /// Whether this token has been consumed by a verified enrollment.
    pub consumed: bool,
}

/// Cryptographically verified and registered machine enrollment record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedEnrollment {
    /// Monitored machine hardware identifier.
    pub machine_id: MachineId,
    /// Consumed enrollment authorization token identifier.
    pub token_id: EnrollmentTokenId,
    /// Authority transaction identifier.
    pub tx_id: TransactionId,
    /// TPM NV lifecycle random identifier.
    pub lifecycle_id: LifecycleId,
    /// TPM Storage Root Key Name.
    pub name_srk: SrkName,
    /// Machine enrollment generation.
    pub generation: EnrollmentGeneration,
    /// Initial hardware counter baseline.
    pub counter_base: CounterValue,
    /// Initial catalog version baseline.
    pub catalog_base: CatalogVersion,
    /// Validated public key metadata.
    pub key_metadata: KeyMetadata,
    /// Timestamp at which enrollment was verified.
    pub enrolled_at: TimestampNs,
}

/// High-level Authority service orchestrating OpenAudit attestation and outbox retrieval.
pub struct AuthorityService {
    replay_store: Arc<dyn ReplayStore>,
    catalog_manager: Arc<CatalogManager>,
    mac_verifier: RustCryptoMacVerifier,
    spki_validator: RustCryptoSpkiValidator,
    tokens: Mutex<HashMap<EnrollmentTokenId, IssuedTokenRecord>>,
    registered_machines: Mutex<HashMap<MachineId, VerifiedEnrollment>>,
}

impl std::fmt::Debug for AuthorityService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthorityService")
            .field("replay_store", &self.replay_store)
            .field("catalog_manager", &self.catalog_manager)
            .finish_non_exhaustive()
    }
}

impl AuthorityService {
    /// Creates a new Authority service backed by `replay_store` and `catalog_manager`.
    #[must_use]
    pub fn new(replay_store: Arc<dyn ReplayStore>, catalog_manager: Arc<CatalogManager>) -> Self {
        Self {
            replay_store,
            catalog_manager,
            mac_verifier: RustCryptoMacVerifier,
            spki_validator: RustCryptoSpkiValidator,
            tokens: Mutex::new(HashMap::new()),
            registered_machines: Mutex::new(HashMap::new()),
        }
    }

    /// Issues a fresh single-use enrollment authorization token for `machine_id`.
    ///
    /// # Errors
    /// Returns [`ProtocolError`] if timestamp calculations overflow.
    #[allow(clippy::significant_drop_tightening)]
    pub fn issue_enrollment_token(
        &self,
        machine_id: MachineId,
        expected_nonce: ChallengeNonce,
        expected_generation: EnrollmentGeneration,
        ttl_nanos: u64,
        now: TimestampNs,
    ) -> Result<IssuedTokenRecord, ProtocolError> {
        let ttl_i64 = i64::try_from(ttl_nanos).map_err(|_| {
            ProtocolError::CryptoError("TTL conversion to i64 overflowed".to_string())
        })?;
        let expires_nanos = now.as_nanos().checked_add(ttl_i64).ok_or_else(|| {
            ProtocolError::CryptoError("token expiry calculation overflowed".to_string())
        })?;

        let record = IssuedTokenRecord {
            token_id: EnrollmentTokenId::new(),
            machine_id,
            expected_nonce,
            expected_generation,
            expires_at: TimestampNs::from_nanos(expires_nanos),
            consumed: false,
        };

        let mut tokens = self.tokens.lock().map_err(|_| {
            ProtocolError::StorageUnavailable("authority tokens lock poisoned".to_string())
        })?;
        tokens.insert(record.token_id, record.clone());

        Ok(record)
    }

    /// Processes and verifies a machine enrollment transcript.
    ///
    /// # Normative Execution Sequence:
    /// 1. Inspects token existence, expiration, and non-consumed status.
    /// 2. Asserts challenge nonce, machine identity, and generation match token.
    /// 3. Validates transcript timestamps (issued within skew, not expired, within token expiry).
    /// 4. Validates hardware counter and catalog baseline consistency ($\ge 1$).
    /// 5. Validates Endorsement Key SPKI DER structure and parameters.
    /// 6. Verifies HMAC-SHA256 signature under `secret`.
    /// 7. Atomically transitions token state to `consumed = true`.
    /// 8. Commits machine registration.
    ///
    /// # Errors
    /// Returns [`ProtocolError`] if any validation or cryptographic check fails.
    #[allow(clippy::significant_drop_tightening, clippy::too_many_lines)]
    pub fn process_enrollment(
        &self,
        transcript: &EnrollmentTranscript,
        proof: &[u8; 32],
        secret: &SharedSecret,
        now: TimestampNs,
    ) -> Result<VerifiedEnrollment, ProtocolError> {
        // 1. Inspect token state under lock
        let mut tokens = self.tokens.lock().map_err(|_| {
            ProtocolError::StorageUnavailable("authority tokens lock poisoned".to_string())
        })?;

        let token = tokens.get_mut(&transcript.token_id).ok_or_else(|| {
            ProtocolError::CryptoError(format!(
                "enrollment token '{}' not found in authority registry",
                transcript.token_id
            ))
        })?;

        if token.consumed {
            return Err(ProtocolError::CryptoError(format!(
                "enrollment token '{}' has already been consumed",
                transcript.token_id
            )));
        }

        if now.as_nanos() > token.expires_at.as_nanos() {
            return Err(ProtocolError::CryptoError(format!(
                "enrollment token '{}' has expired at {} (now: {})",
                transcript.token_id,
                token.expires_at.as_nanos(),
                now.as_nanos()
            )));
        }

        // 2. Assert identity bindings match token
        if transcript.nonce_auth != token.expected_nonce {
            return Err(ProtocolError::CryptoError(
                "challenge nonce mismatch in enrollment transcript".to_string(),
            ));
        }

        if transcript.machine_id != token.machine_id {
            return Err(ProtocolError::CryptoError(format!(
                "machine identity mismatch: transcript specifies '{}', token authorized '{}'",
                transcript.machine_id, token.machine_id
            )));
        }

        if transcript.generation_mach != token.expected_generation {
            return Err(ProtocolError::CryptoError(format!(
                "enrollment generation mismatch: transcript specifies '{}', token authorized '{}'",
                transcript.generation_mach.as_u32(),
                token.expected_generation.as_u32()
            )));
        }

        // 3. Validate transcript timestamps
        let issued_nanos = transcript.timestamp_issued.as_nanos();
        let expires_nanos = transcript.timestamp_expires.as_nanos();
        let now_nanos = now.as_nanos();

        let max_skew_i64 = i64::try_from(MAX_CLOCK_SKEW_NANOS).map_err(|_| {
            ProtocolError::CryptoError(
                "MAX_CLOCK_SKEW_NANOS conversion to i64 overflowed".to_string(),
            )
        })?;
        let max_future_nanos = now_nanos.saturating_add(max_skew_i64);
        if issued_nanos > max_future_nanos {
            return Err(ProtocolError::CryptoError(format!(
                "transcript issued timestamp {issued_nanos} is in the future beyond permitted clock skew (now: {now_nanos})"
            )));
        }

        if now_nanos > expires_nanos {
            return Err(ProtocolError::CryptoError(format!(
                "transcript has expired: expired at {expires_nanos}, current time {now_nanos}"
            )));
        }

        if expires_nanos > token.expires_at.as_nanos() {
            return Err(ProtocolError::CryptoError(format!(
                "transcript expiration {} exceeds token authorization window {}",
                expires_nanos,
                token.expires_at.as_nanos()
            )));
        }

        // 4. Validate counter and catalog baselines
        if transcript.counter_base.as_u64() == 0 {
            return Err(ProtocolError::CryptoError(
                "counter baseline must be non-zero (minimum 1)".to_string(),
            ));
        }

        if transcript.catalog_base.as_u64() == 0 {
            return Err(ProtocolError::CryptoError(
                "catalog baseline version must be non-zero (minimum 1)".to_string(),
            ));
        }

        // 5. Validate SPKI DER structure & key parameters
        let key_metadata = self.spki_validator.validate_spki_der(&transcript.ek_pub)?;

        // 6. Cryptographically verify HMAC-SHA256 transcript proof
        let canonical_bytes = transcript.serialize_canonical()?;
        self.mac_verifier
            .verify_hmac_sha256(secret, &canonical_bytes, proof)?;

        // 7. Atomic token consumption (mark consumed only after all checks pass)
        token.consumed = true;

        // 8. Commit machine registration
        let registration = VerifiedEnrollment {
            machine_id: transcript.machine_id,
            token_id: transcript.token_id,
            tx_id: transcript.tx_id,
            lifecycle_id: transcript.lifecycle_id,
            name_srk: transcript.name_srk,
            generation: transcript.generation_mach,
            counter_base: transcript.counter_base,
            catalog_base: transcript.catalog_base,
            key_metadata,
            enrolled_at: now,
        };

        let mut registered = self.registered_machines.lock().map_err(|_| {
            ProtocolError::StorageUnavailable("registered machines lock poisoned".to_string())
        })?;
        registered.insert(registration.machine_id, registration.clone());

        Ok(registration)
    }

    /// Queries whether `machine_id` is currently registered with the authority.
    ///
    /// # Errors
    /// Returns [`ProtocolError`] if mutex is poisoned.
    pub fn get_registered_machine(
        &self,
        machine_id: &MachineId,
    ) -> Result<Option<VerifiedEnrollment>, ProtocolError> {
        let registered = self.registered_machines.lock().map_err(|_| {
            ProtocolError::StorageUnavailable("registered machines lock poisoned".to_string())
        })?;
        Ok(registered.get(machine_id).cloned())
    }

    /// Processes an untrusted cryptographic outbox retrieval request.
    ///
    /// # Security Invariant (Preserved Execution Ordering):
    /// 1. Verifies timestamp skew ($|T_{\text{auth}} - T_{\text{req}}| \le 60\,\text{s}$). Rejects out-of-skew requests before touching storage.
    /// 2. Verifies cryptographic HMAC-SHA256 proof before touching storage.
    /// 3. Executes atomic check-and-consume via [`ReplayStore::check_and_consume`].
    ///
    /// # Errors
    /// Returns [`ProtocolError`] on skew error, invalid HMAC, replay detection, or storage failure.
    pub fn process_retrieval(
        &self,
        request: &UnverifiedRetrievalRequest,
        secret: &SharedSecret,
        now: TimestampNs,
    ) -> Result<VerifiedRetrievalRequest, ProtocolError> {
        // Step 1 & 2: Non-stateful layout, clock skew, and HMAC verification
        let verified = request.verify(&self.mac_verifier, secret, now)?;

        // Step 3: Atomic check-and-consume write transaction in ReplayStore
        self.replay_store.check_and_consume(
            &verified.message.machine_id,
            &verified.message.req_id,
            verified.message.t_req,
            verified.expires_at,
        )?;

        Ok(verified)
    }

    /// Coordinates a durable assessment catalog update transaction synchronized with `counter`.
    ///
    /// # Errors
    /// Returns [`ProtocolError`] if catalog write, fsync, or counter increment fails.
    pub fn execute_catalog_update(
        &self,
        candidate: &AssessmentCatalog,
        counter: &mut impl MonotonicCounter,
    ) -> Result<(), ProtocolError> {
        self.catalog_manager.execute_transaction(candidate, counter)
    }

    /// Reconciles the authoritative catalog against the hardware monotonic counter across CB-01 through CB-13.
    ///
    /// # Errors
    /// Returns [`ProtocolError::CatalogDesync`] if counter desynchronization is detected.
    pub fn recover_catalog(
        &self,
        counter: &impl MonotonicCounter,
    ) -> Result<RecoveryOutcome, ProtocolError> {
        self.catalog_manager.recover(counter)
    }

    /// Loads the currently active authoritative catalog from disk.
    ///
    /// # Errors
    /// Returns [`ProtocolError`] if catalog cannot be read or validated.
    pub fn load_active_catalog(&self) -> Result<AssessmentCatalog, ProtocolError> {
        self.catalog_manager.load_active_catalog()
    }
}
