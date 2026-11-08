//! Strongly typed domain identifiers and wire contract structures for OpenAudit M3 D4.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

use crate::protocol::error::ProtocolError;

macro_rules! define_protocol_id {
    ($name:ident, $doc:expr) => {
        #[doc = $doc]
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            /// Generates a new random `UUIDv4` identifier.
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }

            /// Wraps an existing [`Uuid`].
            #[must_use]
            pub const fn from_uuid(uuid: Uuid) -> Self {
                Self(uuid)
            }

            /// Returns the binary big-endian (RFC 4122 network byte order) 16-byte representation.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 16] {
                self.0.as_bytes()
            }

            /// Constructs from a 16-byte big-endian (RFC 4122 network byte order) array.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; 16]) -> Self {
                Self(Uuid::from_bytes(bytes))
            }

            /// Returns a reference to the inner [`Uuid`].
            #[must_use]
            pub const fn as_uuid(&self) -> &Uuid {
                &self.0
            }

            /// Consumes `self` and returns the inner [`Uuid`].
            #[must_use]
            pub const fn into_uuid(self) -> Uuid {
                self.0
            }

            /// Parses a UUID string into this typed identifier.
            ///
            /// # Errors
            /// Returns [`ProtocolError::MalformedDerKey`] or similar if `s` is invalid.
            pub fn parse(s: &str) -> Result<Self, ProtocolError> {
                Uuid::parse_str(s)
                    .map(Self)
                    .map_err(|err| ProtocolError::CryptoError(format!("invalid uuid '{s}': {err}")))
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl FromStr for $name {
            type Err = ProtocolError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::parse(s)
            }
        }

        impl From<Uuid> for $name {
            fn from(uuid: Uuid) -> Self {
                Self(uuid)
            }
        }

        impl From<$name> for Uuid {
            fn from(id: $name) -> Self {
                id.0
            }
        }
    };
}

define_protocol_id!(
    MachineId,
    "Unique identifier for an audited machine hardware instance."
);
define_protocol_id!(
    EnrollmentTokenId,
    "Single-use enrollment authorization token identifier."
);
define_protocol_id!(
    TransactionId,
    "Authority transaction identifier binding enrollment to state changes."
);
define_protocol_id!(
    RequestId,
    "Fresh, single-use client request identifier used to defeat outbox replay."
);

/// High-entropy 256-bit random value written to TPM NV index `0x01800002`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LifecycleId(pub [u8; 32]);

impl LifecycleId {
    /// Constructs a `LifecycleId` from a 32-byte array.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the underlying 32-byte array.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Exact 34-byte TPM Name of the Storage Root Key (`0x000B` + 32-byte SHA-256 public hash).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SrkName(pub [u8; 34]);

impl SrkName {
    /// Constructs an `SrkName` from a 34-byte array.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 34]) -> Self {
        Self(bytes)
    }

    /// Returns the underlying 34-byte array.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 34] {
        &self.0
    }
}

/// Cryptographic 256-bit challenge nonce issued by the Authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChallengeNonce(pub [u8; 32]);

impl ChallengeNonce {
    /// Constructs a `ChallengeNonce` from a 32-byte array.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the underlying 32-byte array.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Shared 256-bit cryptographic secret established during credential activation.
///
/// # Security Invariant
/// To prevent accidental exposure in logs, memory dumps, or formatting streams,
/// this type does NOT implement [`Copy`] or [`Clone`], and its [`fmt::Debug`]
/// implementation redacts the secret material.
#[derive(PartialEq, Eq)]
pub struct SharedSecret(pub [u8; 32]);

impl SharedSecret {
    /// Constructs a `SharedSecret` from a 32-byte array.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the underlying 32-byte array.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SharedSecret([REDACTED])")
    }
}

/// Signed 64-bit integer timestamp in Unix nanoseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TimestampNs(pub i64);

impl TimestampNs {
    /// Constructs a `TimestampNs` from raw nanoseconds.
    #[must_use]
    pub const fn from_nanos(nanos: i64) -> Self {
        Self(nanos)
    }

    /// Returns the raw nanoseconds value.
    #[must_use]
    pub const fn as_nanos(&self) -> i64 {
        self.0
    }
}

/// Unsigned 64-bit monotonic counter value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CounterValue(pub u64);

impl CounterValue {
    /// Constructs a `CounterValue` from raw counter u64.
    #[must_use]
    pub const fn from_u64(val: u64) -> Self {
        Self(val)
    }

    /// Returns the raw u64 counter.
    #[must_use]
    pub const fn as_u64(&self) -> u64 {
        self.0
    }
}

/// Unsigned 64-bit catalog release version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CatalogVersion(pub u64);

impl CatalogVersion {
    /// Constructs a `CatalogVersion`.
    #[must_use]
    pub const fn from_u64(val: u64) -> Self {
        Self(val)
    }

    /// Returns the raw version.
    #[must_use]
    pub const fn as_u64(&self) -> u64 {
        self.0
    }
}

/// Unsigned 32-bit machine enrollment generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EnrollmentGeneration(pub u32);

impl EnrollmentGeneration {
    /// Constructs an `EnrollmentGeneration`.
    #[must_use]
    pub const fn from_u32(val: u32) -> Self {
        Self(val)
    }

    /// Returns the raw generation.
    #[must_use]
    pub const fn as_u32(&self) -> u32 {
        self.0
    }
}

/// Canonical domain separator for Machine Enrollment Attestation (exact 20 bytes).
pub const OPENAUDIT_MEA_DOMAIN_V1_24: &[u8; 20] = b"OPENAUDIT-MEA-V1.24\0";

/// Canonical domain separator for Outbox Retrieval (exact 33 bytes).
pub const OPENAUDIT_OUTBOX_RETRIEVAL_DOMAIN_V1_24: &[u8; 33] =
    b"OPENAUDIT-OUTBOX-RETRIEVAL-V1.24\0";

/// Fixed-width binary message layout for Outbox Retrieval (exactly 89 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetrievalMessage {
    /// Target machine identifier.
    pub machine_id: MachineId,
    /// Enrollment transaction identifier.
    pub tx_id: TransactionId,
    /// Fresh, single-use request identifier.
    pub req_id: RequestId,
    /// Client request timestamp in Unix nanoseconds.
    pub t_req: TimestampNs,
}

impl RetrievalMessage {
    /// Total fixed width of canonical retrieval message in octets.
    pub const SERIALIZED_LEN: usize = 89;

    /// Serializes the retrieval message into its exact 89-byte canonical binary format.
    #[must_use]
    pub fn serialize_canonical(&self) -> [u8; Self::SERIALIZED_LEN] {
        let mut out = [0u8; Self::SERIALIZED_LEN];
        // 1. domain_separator (33 bytes)
        out[0..33].copy_from_slice(OPENAUDIT_OUTBOX_RETRIEVAL_DOMAIN_V1_24);
        // 2. uuid_mach (16 bytes)
        out[33..49].copy_from_slice(self.machine_id.as_bytes());
        // 3. tx_id (16 bytes)
        out[49..65].copy_from_slice(self.tx_id.as_bytes());
        // 4. req_id (16 bytes)
        out[65..81].copy_from_slice(self.req_id.as_bytes());
        // 5. t_req (8 bytes, big-endian i64)
        out[81..89].copy_from_slice(&self.t_req.as_nanos().to_be_bytes());
        out
    }

    /// Parses an 89-byte canonical binary retrieval payload.
    ///
    /// # Errors
    /// Returns [`ProtocolError::InvalidLength`] or [`ProtocolError::InvalidDomainSeparator`].
    pub fn parse_canonical(slice: &[u8]) -> Result<Self, ProtocolError> {
        if slice.len() != Self::SERIALIZED_LEN {
            return Err(ProtocolError::InvalidLength {
                expected: Self::SERIALIZED_LEN,
                actual: slice.len(),
            });
        }
        if &slice[0..33] != OPENAUDIT_OUTBOX_RETRIEVAL_DOMAIN_V1_24 {
            return Err(ProtocolError::InvalidDomainSeparator {
                expected: OPENAUDIT_OUTBOX_RETRIEVAL_DOMAIN_V1_24,
                actual: slice[0..33].to_vec(),
            });
        }

        let mut mach_bytes = [0u8; 16];
        mach_bytes.copy_from_slice(&slice[33..49]);
        let mut tx_bytes = [0u8; 16];
        tx_bytes.copy_from_slice(&slice[49..65]);
        let mut req_bytes = [0u8; 16];
        req_bytes.copy_from_slice(&slice[65..81]);
        let mut time_bytes = [0u8; 8];
        time_bytes.copy_from_slice(&slice[81..89]);

        Ok(Self {
            machine_id: MachineId::from_bytes(mach_bytes),
            tx_id: TransactionId::from_bytes(tx_bytes),
            req_id: RequestId::from_bytes(req_bytes),
            t_req: TimestampNs::from_nanos(i64::from_be_bytes(time_bytes)),
        })
    }
}

/// Canonical 14-element Machine Enrollment Attestation transcript.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentTranscript {
    /// Fresh authority challenge nonce (32 bytes).
    pub nonce_auth: ChallengeNonce,
    /// Single-use enrollment token ID (16 bytes).
    pub token_id: EnrollmentTokenId,
    /// Authority transaction ID (16 bytes).
    pub tx_id: TransactionId,
    /// Monitored machine hardware identity (16 bytes).
    pub machine_id: MachineId,
    /// Canonical DER-encoded Endorsement Key public key (`N` bytes).
    pub ek_pub: Vec<u8>,
    /// SRK TPM Name (34 bytes).
    pub name_srk: SrkName,
    /// NV lifecycle random identifier (32 bytes).
    pub lifecycle_id: LifecycleId,
    /// Per-machine enrollment generation (4 bytes).
    pub generation_mach: EnrollmentGeneration,
    /// Initial hardware counter baseline (8 bytes).
    pub counter_base: CounterValue,
    /// Catalog baseline version (8 bytes).
    pub catalog_base: CatalogVersion,
    /// Issuance timestamp in Unix nanoseconds (8 bytes).
    pub timestamp_issued: TimestampNs,
    /// Expiration timestamp in Unix nanoseconds (8 bytes).
    pub timestamp_expires: TimestampNs,
}

impl EnrollmentTranscript {
    /// Fixed overhead of non-variable fields: 204 octets.
    pub const FIXED_OVERHEAD_LEN: usize = 204;

    /// Serializes transcript contiguously as 14 strictly ordered elements.
    /// Length is exactly `204 + ek_pub.len()` bytes.
    ///
    /// # Errors
    /// Returns [`ProtocolError::InvalidLength`] if `ek_pub.len()` exceeds `u16::MAX` (65,535 bytes).
    pub fn serialize_canonical(&self) -> Result<Vec<u8>, ProtocolError> {
        let ek_len =
            u16::try_from(self.ek_pub.len()).map_err(|_| ProtocolError::InvalidLength {
                expected: usize::from(u16::MAX),
                actual: self.ek_pub.len(),
            })?;
        let total_len = Self::FIXED_OVERHEAD_LEN
            .checked_add(self.ek_pub.len())
            .ok_or(ProtocolError::InvalidLength {
                expected: usize::MAX,
                actual: self.ek_pub.len(),
            })?;
        let mut out = Vec::with_capacity(total_len);

        // 1. domain_separator (20 bytes)
        out.extend_from_slice(OPENAUDIT_MEA_DOMAIN_V1_24);
        // 2. nonce_auth (32 bytes)
        out.extend_from_slice(self.nonce_auth.as_bytes());
        // 3. token_id (16 bytes)
        out.extend_from_slice(self.token_id.as_bytes());
        // 4. tx_id (16 bytes)
        out.extend_from_slice(self.tx_id.as_bytes());
        // 5. uuid_mach (16 bytes)
        out.extend_from_slice(self.machine_id.as_bytes());
        // 6. ek_pub_len (2 bytes, big-endian u16)
        out.extend_from_slice(&ek_len.to_be_bytes());
        // 7. ek_pub (N bytes)
        out.extend_from_slice(&self.ek_pub);
        // 8. name_srk (34 bytes)
        out.extend_from_slice(self.name_srk.as_bytes());
        // 9. lifecycle_id (32 bytes)
        out.extend_from_slice(self.lifecycle_id.as_bytes());
        // 10. generation_mach (4 bytes, big-endian u32)
        out.extend_from_slice(&self.generation_mach.as_u32().to_be_bytes());
        // 11. counter_base (8 bytes, big-endian u64)
        out.extend_from_slice(&self.counter_base.as_u64().to_be_bytes());
        // 12. catalog_base (8 bytes, big-endian u64)
        out.extend_from_slice(&self.catalog_base.as_u64().to_be_bytes());
        // 13. timestamp_issued (8 bytes, big-endian i64)
        out.extend_from_slice(&self.timestamp_issued.as_nanos().to_be_bytes());
        // 14. timestamp_expires (8 bytes, big-endian i64)
        out.extend_from_slice(&self.timestamp_expires.as_nanos().to_be_bytes());

        debug_assert_eq!(out.len(), total_len);
        Ok(out)
    }

    /// Parses a canonical binary Machine Enrollment Attestation transcript.
    ///
    /// # Errors
    /// Returns [`ProtocolError::InvalidLength`] or [`ProtocolError::InvalidDomainSeparator`]
    /// if the wire encoding is malformed or truncated.
    pub fn parse_canonical(slice: &[u8]) -> Result<Self, ProtocolError> {
        if slice.len() < Self::FIXED_OVERHEAD_LEN {
            return Err(ProtocolError::InvalidLength {
                expected: Self::FIXED_OVERHEAD_LEN,
                actual: slice.len(),
            });
        }
        if &slice[0..20] != OPENAUDIT_MEA_DOMAIN_V1_24 {
            return Err(ProtocolError::InvalidDomainSeparator {
                expected: OPENAUDIT_MEA_DOMAIN_V1_24,
                actual: slice[0..20].to_vec(),
            });
        }

        let mut nonce_bytes = [0u8; 32];
        nonce_bytes.copy_from_slice(&slice[20..52]);

        let mut token_bytes = [0u8; 16];
        token_bytes.copy_from_slice(&slice[52..68]);

        let mut tx_bytes = [0u8; 16];
        tx_bytes.copy_from_slice(&slice[68..84]);

        let mut mach_bytes = [0u8; 16];
        mach_bytes.copy_from_slice(&slice[84..100]);

        let mut ek_len_bytes = [0u8; 2];
        ek_len_bytes.copy_from_slice(&slice[100..102]);
        let ek_len = usize::from(u16::from_be_bytes(ek_len_bytes));

        let expected_total =
            Self::FIXED_OVERHEAD_LEN
                .checked_add(ek_len)
                .ok_or(ProtocolError::InvalidLength {
                    expected: usize::MAX,
                    actual: slice.len(),
                })?;

        if slice.len() != expected_total {
            return Err(ProtocolError::InvalidLength {
                expected: expected_total,
                actual: slice.len(),
            });
        }

        let ek_pub_end = 102 + ek_len;
        let ek_pub = slice[102..ek_pub_end].to_vec();

        let mut srk_bytes = [0u8; 34];
        srk_bytes.copy_from_slice(&slice[ek_pub_end..ek_pub_end + 34]);

        let mut lifecycle_bytes = [0u8; 32];
        lifecycle_bytes.copy_from_slice(&slice[ek_pub_end + 34..ek_pub_end + 66]);

        let mut gen_bytes = [0u8; 4];
        gen_bytes.copy_from_slice(&slice[ek_pub_end + 66..ek_pub_end + 70]);

        let mut counter_bytes = [0u8; 8];
        counter_bytes.copy_from_slice(&slice[ek_pub_end + 70..ek_pub_end + 78]);

        let mut cat_bytes = [0u8; 8];
        cat_bytes.copy_from_slice(&slice[ek_pub_end + 78..ek_pub_end + 86]);

        let mut issued_bytes = [0u8; 8];
        issued_bytes.copy_from_slice(&slice[ek_pub_end + 86..ek_pub_end + 94]);

        let mut expires_bytes = [0u8; 8];
        expires_bytes.copy_from_slice(&slice[ek_pub_end + 94..ek_pub_end + 102]);

        Ok(Self {
            nonce_auth: ChallengeNonce::from_bytes(nonce_bytes),
            token_id: EnrollmentTokenId::from_bytes(token_bytes),
            tx_id: TransactionId::from_bytes(tx_bytes),
            machine_id: MachineId::from_bytes(mach_bytes),
            ek_pub,
            name_srk: SrkName::from_bytes(srk_bytes),
            lifecycle_id: LifecycleId::from_bytes(lifecycle_bytes),
            generation_mach: EnrollmentGeneration::from_u32(u32::from_be_bytes(gen_bytes)),
            counter_base: CounterValue::from_u64(u64::from_be_bytes(counter_bytes)),
            catalog_base: CatalogVersion::from_u64(u64::from_be_bytes(cat_bytes)),
            timestamp_issued: TimestampNs::from_nanos(i64::from_be_bytes(issued_bytes)),
            timestamp_expires: TimestampNs::from_nanos(i64::from_be_bytes(expires_bytes)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shared_secret_redacted_debug() {
        let raw_secret = [
            0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44,
            0x33, 0x22, 0x11, 0x00,
        ];
        let secret = SharedSecret::from_bytes(raw_secret);

        let debug_str = format!("{secret:?}");
        assert_eq!(debug_str, "SharedSecret([REDACTED])");

        // Confirm none of the actual raw bytes appear anywhere in the string
        assert!(!debug_str.contains("deadbeef"));
        assert!(!debug_str.contains("222")); // 0xde = 222
        assert!(!debug_str.contains("173")); // 0xad = 173
    }
}
