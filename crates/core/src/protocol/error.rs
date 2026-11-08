//! Typed protocol and cryptographic error definitions for OpenAudit M3 D4.

use thiserror::Error;

/// Errors arising within the OpenAudit M3 D4 protocol, enrollment, and retrieval workflows.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum ProtocolError {
    /// Payload byte length did not match the strict fixed-width specification.
    #[error("invalid payload length: expected {expected} bytes, observed {actual} bytes")]
    InvalidLength {
        /// Expected byte width.
        expected: usize,
        /// Actual observed byte width.
        actual: usize,
    },

    /// Domain separator did not match the expected canonical ASCII string.
    #[error("invalid domain separator: expected {expected:?}, observed {actual:?}")]
    InvalidDomainSeparator {
        /// Expected domain separator byte slice.
        expected: &'static [u8],
        /// Observed domain separator bytes.
        actual: Vec<u8>,
    },

    /// Request timestamp fell outside the permitted +/- 60s window.
    #[error("timestamp out of bounds: skew of {skew_nanos} ns exceeds maximum window of {max_window_nanos} ns")]
    TimestampOutOfBounds {
        /// Observed absolute skew in nanoseconds.
        skew_nanos: u64,
        /// Maximum allowable window in nanoseconds.
        max_window_nanos: u64,
    },

    /// Cryptographic HMAC-SHA256 proof verification failed.
    #[error("invalid HMAC proof: signature does not authenticate the canonical payload")]
    InvalidHmacProof,

    /// Request identifier has already been consumed within the cache TTL.
    #[error("replay detected: request identifier '{req_id}' has already been consumed for machine '{machine_id}'")]
    ReplayDetected {
        /// Consumed request identifier.
        req_id: String,
        /// Monitored machine identifier.
        machine_id: String,
    },

    /// Replay protection storage is unavailable, locked, or corrupted (fail-closed).
    #[error("replay storage unavailable (fail-closed): {0}")]
    StorageUnavailable(String),

    /// Public key DER payload failed structural or cryptographic validation.
    #[error("malformed DER public key fixture: {0}")]
    MalformedDerKey(String),

    /// Machine state or lifecycle mismatch enforces quarantine.
    #[error("quarantine enforced: {0}")]
    QuarantineEnforced(String),

    /// Missing or corrupted authorization secret.
    #[error("authorization secret error: {0}")]
    SecretError(String),

    /// Cryptographic hashing or primitive operation failure.
    #[error("cryptographic primitive error: {0}")]
    CryptoError(String),

    /// Authoritative catalog file is corrupted, malformed, or failed checksum validation.
    #[error("catalog corrupted (fail-closed): {0}")]
    CatalogCorrupted(String),

    /// Catalog and hardware monotonic counter are in an unresolvable desynchronized state.
    #[error("catalog desynchronization detected (fail-closed): {0}")]
    CatalogDesync(String),

    /// TPM command, connection, or hardware security operation failed.
    #[error("TPM hardware security error (fail-closed): {0}")]
    TpmError(String),
}
