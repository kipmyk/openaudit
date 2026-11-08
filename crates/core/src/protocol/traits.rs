//! Cryptographic, validation, and storage trait contracts for OpenAudit M3 D4.

use crate::protocol::error::ProtocolError;
use crate::protocol::types::{
    CatalogVersion, ChallengeNonce, CounterValue, EnrollmentGeneration, EnrollmentTokenId,
    LifecycleId, MachineId, RequestId, SharedSecret, SrkName, TimestampNs, TransactionId,
};

/// Abstract trait for SHA-256 cryptographic hashing.
pub trait CryptoHasher: Send + Sync + std::fmt::Debug {
    /// Computes the 32-byte SHA-256 digest of `data`.
    fn digest_sha256(&self, data: &[u8]) -> [u8; 32];
}

/// Abstract trait for message authentication code (HMAC-SHA256) verification.
pub trait MacVerifier: Send + Sync + std::fmt::Debug {
    /// Verifies that `tag` is a valid HMAC-SHA256 signature for `message` under `secret`.
    ///
    /// # Errors
    /// Returns [`ProtocolError::InvalidHmacProof`] if verification fails.
    fn verify_hmac_sha256(
        &self,
        secret: &SharedSecret,
        message: &[u8],
        tag: &[u8; 32],
    ) -> Result<(), ProtocolError>;
}

/// Abstract trait for X.509 SPKI DER public key parsing and validation.
pub trait SpkiValidator: Send + Sync + std::fmt::Debug {
    /// Validates the structural ASN.1 DER encoding and extracts key parameters.
    ///
    /// # Errors
    /// Returns [`ProtocolError::MalformedDerKey`] if key format is unsupported or invalid.
    fn validate_spki_der(&self, der: &[u8]) -> Result<KeyMetadata, ProtocolError>;
}

/// Public key algorithm family and parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyMetadata {
    /// RSA key with modulus bit length.
    Rsa {
        /// Modulus size in bits (must be >= 2048 for production).
        modulus_bits: usize,
        /// Public exponent value.
        public_exponent: u64,
    },
    /// Elliptic curve key.
    Ecc {
        /// Curve identifier name (e.g. "secp256r1").
        curve_name: &'static str,
    },
}

/// Abstract trait for atomic replay storage.
pub trait ReplayStore: Send + Sync + std::fmt::Debug {
    /// Atomically checks whether `(machine_id, req_id)` has already been consumed.
    /// If not consumed, atomically commits the record with an expiry timestamp.
    ///
    /// # Errors
    /// - Returns [`ProtocolError::ReplayDetected`] if already consumed.
    /// - Returns [`ProtocolError::StorageUnavailable`] if storage fails (fail-closed).
    fn check_and_consume(
        &self,
        machine_id: &MachineId,
        req_id: &RequestId,
        t_req: TimestampNs,
        expires_at: TimestampNs,
    ) -> Result<(), ProtocolError>;
}

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
    /// Full Endorsement Key SPKI DER binary representation.
    pub ek_pub_spki_der: Vec<u8>,
    /// Timestamp at which enrollment was verified.
    pub enrolled_at: TimestampNs,
}

/// Abstract trait for durable Authority storage handling enrollment tokens and machine registrations.
pub trait AuthorityStore: Send + Sync + std::fmt::Debug {
    /// Persists a newly issued enrollment authorization token.
    ///
    /// # Errors
    /// Returns [`ProtocolError::StorageUnavailable`] if storage fails.
    fn insert_token(&self, token: &IssuedTokenRecord) -> Result<(), ProtocolError>;

    /// Looks up an issued enrollment token by its identifier.
    ///
    /// # Errors
    /// Returns [`ProtocolError::StorageUnavailable`] if storage query fails.
    fn get_token(
        &self,
        token_id: &EnrollmentTokenId,
    ) -> Result<Option<IssuedTokenRecord>, ProtocolError>;

    /// Atomically validates token state, marks the token as consumed, and registers the verified machine.
    ///
    /// # Atomic Guarantees
    /// Executes within an immediate database transaction:
    /// 1. Re-verifies token existence, identity matching (`expected_nonce`, `expected_generation`),
    ///    unconsumed status, and non-expiration.
    /// 2. Sets `consumed = 1` and `consumed_at = now`.
    /// 3. Inserts the `registration` into registered machines.
    /// 4. Commits both operations atomically.
    ///
    /// If any database constraint (such as duplicate `machine_id`) fails or a validation fails,
    /// the transaction is rolled back and the token remains unconsumed.
    ///
    /// # Errors
    /// - Returns [`ProtocolError::CryptoError`] if the token is not found, already consumed, expired,
    ///   or identity bindings do not match.
    /// - Returns [`ProtocolError::StorageUnavailable`] if database execution fails or constraint is violated.
    fn commit_enrollment(
        &self,
        token_id: &EnrollmentTokenId,
        now: TimestampNs,
        registration: &VerifiedEnrollment,
    ) -> Result<(), ProtocolError>;

    /// Queries whether a machine is registered, returning its verified enrollment record.
    ///
    /// # Errors
    /// Returns [`ProtocolError::StorageUnavailable`] if storage query fails.
    fn get_registered_machine(
        &self,
        machine_id: &MachineId,
    ) -> Result<Option<VerifiedEnrollment>, ProtocolError>;
}
