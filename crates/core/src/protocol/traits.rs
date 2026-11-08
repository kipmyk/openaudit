//! Cryptographic, validation, and storage trait contracts for OpenAudit M3 D4.

use crate::protocol::error::ProtocolError;
use crate::protocol::types::{MachineId, RequestId, SharedSecret, TimestampNs};

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
