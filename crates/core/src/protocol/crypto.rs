//! Concrete `RustCrypto` cryptographic primitives for OpenAudit M3 D4.
//!
//! Implements:
//! - SHA-256 digest computation via [`sha2`].
//! - HMAC-SHA256 generation and constant-time verification via [`hmac`].
//! - Strict X.509 `SubjectPublicKeyInfo` (SPKI) DER structural parsing and
//!   cryptographic validation for RSA and ECC P-256 keys.

use der::asn1::ObjectIdentifier;
use der::{Decode, Tagged};
use hmac::{Hmac, Mac};
use rsa::pkcs1::RsaPublicKey as Pkcs1RsaPublicKey;
use sha2::{Digest, Sha256};
use spki::SubjectPublicKeyInfoRef;

use crate::protocol::error::ProtocolError;
use crate::protocol::traits::{CryptoHasher, KeyMetadata, MacVerifier, SpkiValidator};
use crate::protocol::types::SharedSecret;

/// Type alias for HMAC-SHA256.
pub type HmacSha256 = Hmac<Sha256>;

/// OID for `rsaEncryption`: `1.2.840.113549.1.1.1` (RFC 3279).
pub const RSA_ENCRYPTION_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

/// OID for `id-ecPublicKey`: `1.2.840.10045.2.1` (RFC 5480).
pub const ID_EC_PUBLIC_KEY_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");

/// OID for `secp256r1` / NIST P-256 curve: `1.2.840.10045.3.1.7` (RFC 5480).
pub const SECP256R1_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

/// Pure Rust implementation of [`CryptoHasher`] using [`Sha256`].
#[derive(Debug, Default, Clone, Copy)]
pub struct RustCryptoHasher;

impl CryptoHasher for RustCryptoHasher {
    fn digest_sha256(&self, data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }
}

/// Pure Rust implementation of [`MacVerifier`] using [`HmacSha256`].
#[derive(Debug, Default, Clone, Copy)]
pub struct RustCryptoMacVerifier;

impl MacVerifier for RustCryptoMacVerifier {
    fn verify_hmac_sha256(
        &self,
        secret: &SharedSecret,
        message: &[u8],
        tag: &[u8; 32],
    ) -> Result<(), ProtocolError> {
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).map_err(|err| {
            ProtocolError::CryptoError(format!("HMAC key initialization failed: {err}"))
        })?;
        mac.update(message);
        mac.verify_slice(tag)
            .map_err(|_| ProtocolError::InvalidHmacProof)
    }
}

/// Computes an HMAC-SHA256 tag over `message` using `secret`.
///
/// # Panics
/// Panics if the internal `HmacSha256` fails to initialize (guaranteed unreachable for 32-byte keys).
#[must_use]
pub fn compute_hmac_sha256(secret: &SharedSecret, message: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .expect("SharedSecret is 32 bytes and always valid for HMAC-SHA256");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

/// Computes a standalone SHA-256 digest over `data`.
#[must_use]
pub fn compute_sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Pure Rust implementation of [`SpkiValidator`].
///
/// Validates:
/// 1. Structural ASN.1 DER `SubjectPublicKeyInfo` framing.
/// 2. Algorithm OID matching `rsaEncryption` or `id-ecPublicKey`.
/// 3. For RSA:
///    - Modulus size >= 2048 bits.
///    - Public exponent is odd and >= 3.
/// 4. For ECC:
///    - Named curve is strictly `secp256r1`.
///    - Public point is valid, on-curve, and not point-at-infinity.
#[derive(Debug, Default, Clone, Copy)]
pub struct RustCryptoSpkiValidator;

impl SpkiValidator for RustCryptoSpkiValidator {
    fn validate_spki_der(&self, der: &[u8]) -> Result<KeyMetadata, ProtocolError> {
        // 1. Parse outer SubjectPublicKeyInfo
        let spki = SubjectPublicKeyInfoRef::try_from(der).map_err(|err| {
            ProtocolError::MalformedDerKey(format!("invalid SPKI DER structure: {err}"))
        })?;

        let alg_oid = spki.algorithm.oid;

        // 2. Algorithm-specific validation
        if alg_oid == RSA_ENCRYPTION_OID {
            Self::validate_rsa_spki(&spki)
        } else if alg_oid == ID_EC_PUBLIC_KEY_OID {
            Self::validate_ecc_spki(&spki)
        } else {
            Err(ProtocolError::MalformedDerKey(format!(
                "unsupported algorithm OID: {alg_oid}"
            )))
        }
    }
}

impl RustCryptoSpkiValidator {
    fn validate_rsa_spki(spki: &SubjectPublicKeyInfoRef<'_>) -> Result<KeyMetadata, ProtocolError> {
        // RFC 3279 § 2.3.1: RSA AlgorithmIdentifier parameters MUST be present and MUST be ASN.1 NULL
        let params = spki.algorithm.parameters.ok_or_else(|| {
            ProtocolError::MalformedDerKey(
                "missing RSA algorithm parameters (expected NULL)".to_string(),
            )
        })?;
        if params.tag() != der::Tag::Null {
            return Err(ProtocolError::MalformedDerKey(format!(
                "invalid RSA algorithm parameter tag {:?} (must be NULL)",
                params.tag()
            )));
        }

        // Verify BIT STRING unused bits are zero
        if spki.subject_public_key.unused_bits() != 0 {
            return Err(ProtocolError::MalformedDerKey(format!(
                "RSA public key BIT STRING contains non-zero unused bits ({})",
                spki.subject_public_key.unused_bits()
            )));
        }

        // RSA Public Key parsing (PKCS#1 RSAPublicKey inside BIT STRING)
        let key_bytes = spki.subject_public_key.raw_bytes();
        let rsa_pk = Pkcs1RsaPublicKey::from_der(key_bytes).map_err(|err| {
            ProtocolError::MalformedDerKey(format!("invalid PKCS#1 RSA key inside SPKI: {err}"))
        })?;

        // Modulus inspection: strip all leading zero padding bytes
        let mut effective_bytes = rsa_pk.modulus.as_bytes();
        while let Some((&0, rest)) = effective_bytes.split_first() {
            effective_bytes = rest;
        }
        if effective_bytes.is_empty() {
            return Err(ProtocolError::MalformedDerKey(
                "RSA modulus is zero".to_string(),
            ));
        }

        // Calculate exact bit length from leading significant bit of MSB
        let msb_bits = 8 - (effective_bytes[0].leading_zeros() as usize);
        let remaining_bits = (effective_bytes.len() - 1).checked_mul(8).ok_or_else(|| {
            ProtocolError::MalformedDerKey("RSA modulus bit length overflow".to_string())
        })?;
        let modulus_bits = remaining_bits + msb_bits;

        if modulus_bits < 2048 {
            return Err(ProtocolError::MalformedDerKey(format!(
                "RSA modulus too small: {modulus_bits} bits (minimum 2048 required)"
            )));
        }

        // RSA modulus N = p * q must be an odd composite number
        if effective_bytes.last().is_none_or(|b| b % 2 == 0) {
            return Err(ProtocolError::MalformedDerKey(
                "RSA modulus is even (composite of 2)".to_string(),
            ));
        }

        // Exponent inspection
        let exp_bytes = rsa_pk.public_exponent.as_bytes();
        let mut effective_exp = exp_bytes;
        while let Some((&0, rest)) = effective_exp.split_first() {
            effective_exp = rest;
        }
        if effective_exp.is_empty() || effective_exp.len() > 8 {
            return Err(ProtocolError::MalformedDerKey(
                "RSA public exponent exceeds 64 bits or is zero".to_string(),
            ));
        }
        let mut exp_arr = [0u8; 8];
        exp_arr[8 - effective_exp.len()..].copy_from_slice(effective_exp);
        let public_exponent = u64::from_be_bytes(exp_arr);

        if public_exponent < 3 || public_exponent % 2 == 0 {
            return Err(ProtocolError::MalformedDerKey(format!(
                "invalid RSA public exponent: {public_exponent} (must be odd and >= 3)"
            )));
        }

        Ok(KeyMetadata::Rsa {
            modulus_bits,
            public_exponent,
        })
    }

    fn validate_ecc_spki(spki: &SubjectPublicKeyInfoRef<'_>) -> Result<KeyMetadata, ProtocolError> {
        // RFC 5480 § 2.2: Verify BIT STRING unused bits are strictly zero
        if spki.subject_public_key.unused_bits() != 0 {
            return Err(ProtocolError::MalformedDerKey(format!(
                "ECC public key BIT STRING contains non-zero unused bits ({})",
                spki.subject_public_key.unused_bits()
            )));
        }

        // RFC 5480 § 2.1.1: Parameters MUST be namedCurve ObjectIdentifier
        let params = spki.algorithm.parameters.ok_or_else(|| {
            ProtocolError::MalformedDerKey("missing ECC algorithm parameters".to_string())
        })?;

        if params.tag() != der::Tag::ObjectIdentifier {
            return Err(ProtocolError::MalformedDerKey(format!(
                "invalid ECC parameter tag {:?} (must be namedCurve ObjectIdentifier)",
                params.tag()
            )));
        }

        let curve_oid = params.decode_as::<ObjectIdentifier>().map_err(|err| {
            ProtocolError::MalformedDerKey(format!("invalid ECC curve OID parameter: {err}"))
        })?;

        if curve_oid != SECP256R1_OID {
            return Err(ProtocolError::MalformedDerKey(format!(
                "unsupported ECC curve OID '{curve_oid}' (only secp256r1 is permitted)"
            )));
        }

        let key_bytes = spki.subject_public_key.raw_bytes();

        // Cryptographic on-curve validation using p256
        let _pub_key = p256::PublicKey::from_sec1_bytes(key_bytes).map_err(|err| {
            ProtocolError::MalformedDerKey(format!(
                "invalid SEC1 elliptic curve point on secp256r1: {err}"
            ))
        })?;

        Ok(KeyMetadata::Ecc {
            curve_name: "secp256r1",
        })
    }
}
