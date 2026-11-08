//! Explicit trust boundaries and state transition gates for OpenAudit M3 D4.
//!
//! Enforces that untrusted wire inputs must cross validation gates before
//! reaching internal state machines or consuming replay nonces.

use crate::protocol::error::ProtocolError;
use crate::protocol::traits::MacVerifier;
use crate::protocol::types::{RetrievalMessage, SharedSecret, TimestampNs};

/// Maximum allowable clock skew in nanoseconds (+/- 60 seconds).
pub const MAX_CLOCK_SKEW_NANOS: u64 = 60 * 1_000_000_000;

/// Replay cache retention TTL in nanoseconds (120 seconds).
pub const REPLAY_CACHE_TTL_NANOS: u64 = 120 * 1_000_000_000;

/// Untrusted retrieval request as received directly from the network wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnverifiedRetrievalRequest {
    /// Raw unparsed payload bytes (expected to be 89 bytes).
    pub raw_payload: Vec<u8>,
    /// Client-supplied HMAC-SHA256 authorization proof (32 bytes).
    pub proof: [u8; 32],
}

/// Cryptographically authenticated and timestamp-validated retrieval request.
///
/// Guaranteed by type construction to have satisfied:
/// 1. Exact 89-byte binary layout and 33-byte domain separator validation.
/// 2. Timestamp within +/- 60s of authority evaluation time.
/// 3. Valid HMAC-SHA256 signature authenticating the payload under the machine secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRetrievalRequest {
    /// Validated structured retrieval message.
    pub message: RetrievalMessage,
    /// Absolute expiration timestamp for replay caching.
    pub expires_at: TimestampNs,
}

impl UnverifiedRetrievalRequest {
    /// Constructs a new unverified request from wire bytes.
    #[must_use]
    pub const fn new(raw_payload: Vec<u8>, proof: [u8; 32]) -> Self {
        Self { raw_payload, proof }
    }

    /// Verifies the request across all non-stateful security gates.
    ///
    /// # Security Invariant
    /// Cryptographic HMAC verification occurs *before* touching or updating
    /// replay storage, preventing unauthenticated denial-of-service cache exhaustion.
    ///
    /// # Errors
    /// - Returns [`ProtocolError::InvalidLength`] if payload is not 89 bytes.
    /// - Returns [`ProtocolError::InvalidDomainSeparator`] if domain mismatch.
    /// - Returns [`ProtocolError::TimestampOutOfBounds`] if $|T_{\text{req}} - T_{\text{auth}}| > 60\,\text{s}$.
    /// - Returns [`ProtocolError::InvalidHmacProof`] if HMAC does not match.
    pub fn verify<V: MacVerifier>(
        &self,
        verifier: &V,
        secret: &SharedSecret,
        t_auth: TimestampNs,
    ) -> Result<VerifiedRetrievalRequest, ProtocolError> {
        // 1. Parse & validate fixed-width binary layout (89 bytes)
        let message = RetrievalMessage::parse_canonical(&self.raw_payload)?;

        // 2. Validate timestamp window (+/- 60 seconds) using i128 intermediates to prevent overflow
        let t_req_128 = i128::from(message.t_req.as_nanos());
        let t_auth_128 = i128::from(t_auth.as_nanos());
        let diff_128 = (t_req_128 - t_auth_128).unsigned_abs();
        let max_skew_128 = u128::from(MAX_CLOCK_SKEW_NANOS);

        if diff_128 > max_skew_128 {
            return Err(ProtocolError::TimestampOutOfBounds {
                skew_nanos: u64::try_from(diff_128).unwrap_or(u64::MAX),
                max_window_nanos: MAX_CLOCK_SKEW_NANOS,
            });
        }

        // 3. Verify cryptographic HMAC-SHA256 proof
        verifier.verify_hmac_sha256(secret, &self.raw_payload, &self.proof)?;

        // 4. Calculate cache expiry timestamp (T_req + 120s) using checked arithmetic
        let ttl_nanos = i64::try_from(REPLAY_CACHE_TTL_NANOS).map_err(|_| {
            ProtocolError::CryptoError("TTL conversion to i64 overflowed".to_string())
        })?;
        let expires_nanos = message
            .t_req
            .as_nanos()
            .checked_add(ttl_nanos)
            .ok_or_else(|| {
                ProtocolError::CryptoError(format!(
                    "timestamp overflow: expiry calculation for t_req {} + ttl {} exceeds i64::MAX",
                    message.t_req.as_nanos(),
                    ttl_nanos
                ))
            })?;
        let expires_at = TimestampNs::from_nanos(expires_nanos);

        Ok(VerifiedRetrievalRequest {
            message,
            expires_at,
        })
    }
}
