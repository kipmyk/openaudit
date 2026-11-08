//! # OpenAudit Protocol & Cryptographic Contracts (Dimension 4)
//!
//! Provides the foundational domain types, strongly-typed identifiers,
//! error representations, fixed-width wire layouts, and explicit trust boundaries
//! governing machine enrollment attestation and cryptographic outbox retrieval.

pub mod agent;
pub mod authority;
pub mod authority_store;
pub mod canonical;
pub mod catalog;
pub mod crypto;
pub mod error;
pub mod replay;
pub mod tls;
pub mod tpm;
pub mod traits;
pub mod trust;
pub mod types;

pub use agent::{AgentAttestationClient, AgentCredentials};
pub use authority::AuthorityService;
pub use authority_store::SqliteAuthorityStore;
pub use traits::{AuthorityStore, IssuedTokenRecord, VerifiedEnrollment};

pub use canonical::{
    canonicalize, canonicalize_value, validate_safe_integers, MAX_SAFE_INTEGER, MIN_SAFE_INTEGER,
};
pub use catalog::{
    AssessmentCatalog, CatalogManager, CatalogWalRecord, CrashPoint, MockMonotonicCounter,
    MonotonicCounter, RecoveryOutcome, CURRENT_CATALOG_SCHEMA_VERSION, CURRENT_WAL_SCHEMA_VERSION,
};
pub use crypto::{
    compute_hmac_sha256, compute_sha256, HmacSha256, RustCryptoHasher, RustCryptoMacVerifier,
    RustCryptoSpkiValidator, ID_EC_PUBLIC_KEY_OID, RSA_ENCRYPTION_OID, SECP256R1_OID,
};
pub use error::ProtocolError;
pub use replay::{SqliteReplayStore, CURRENT_SCHEMA_VERSION};
pub use tls::{
    build_tls13_client_config, build_tls13_server_config, dispatch_authority_request,
    load_certificates_from_file, load_private_key_from_file, parse_certificates_from_pem,
    parse_private_key_from_pem, read_framed, write_framed, TlsClientTransport, TlsProtocolRequest,
    TlsProtocolResponse, MAX_FRAMED_MESSAGE_BYTES,
};
pub use tpm::{
    resolve_tpm_device_path, DeviceTransport, NvPublicInfo, ProvisioningState, TpmClient,
    TpmCounterConfig, TpmMonotonicCounter, TpmProvisioningManager, TpmTransport,
    UnixSocketTransport, DEFAULT_LINUX_TPM_RM_PATH, DEFAULT_NV_COUNTER_INDEX,
    DEFAULT_NV_LIFECYCLE_INDEX, FALLBACK_LINUX_TPM_RAW_PATH, NV_COUNTER_ATTRIBUTES,
    NV_LIFECYCLE_ATTRIBUTES,
};
pub use traits::{CryptoHasher, KeyMetadata, MacVerifier, ReplayStore, SpkiValidator};
pub use trust::{
    UnverifiedRetrievalRequest, VerifiedRetrievalRequest, MAX_CLOCK_SKEW_NANOS,
    REPLAY_CACHE_TTL_NANOS,
};
pub use types::{
    CatalogVersion, ChallengeNonce, CounterValue, EnrollmentGeneration, EnrollmentTokenId,
    EnrollmentTranscript, LifecycleId, MachineId, RequestId, RetrievalMessage, SharedSecret,
    SrkName, TimestampNs, TransactionId, OPENAUDIT_MEA_DOMAIN_V1_24,
    OPENAUDIT_OUTBOX_RETRIEVAL_DOMAIN_V1_24,
};

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex byte"))
            .collect()
    }

    fn decode_hex_32(s: &str) -> [u8; 32] {
        decode_hex(s).try_into().expect("expected 32 hex bytes")
    }

    fn decode_hex_34(s: &str) -> [u8; 34] {
        decode_hex(s).try_into().expect("expected 34 hex bytes")
    }

    #[test]
    fn test_domain_separator_exact_widths() {
        assert_eq!(OPENAUDIT_MEA_DOMAIN_V1_24.len(), 20);
        assert_eq!(OPENAUDIT_OUTBOX_RETRIEVAL_DOMAIN_V1_24.len(), 33);
        assert_eq!(b"OPENAUDIT".len(), 9, "OPENAUDIT must be 9 ASCII octets");
    }

    #[test]
    fn test_retrieval_message_serialization_and_parsing_roundtrip() {
        let msg = RetrievalMessage {
            machine_id: MachineId::new(),
            tx_id: TransactionId::new(),
            req_id: RequestId::new(),
            t_req: TimestampNs::from_nanos(1_700_000_000_000_000_000),
        };

        let raw = msg.serialize_canonical();
        assert_eq!(
            raw.len(),
            89,
            "Canonical retrieval message must be exactly 89 bytes"
        );

        let parsed = RetrievalMessage::parse_canonical(&raw).expect("must parse valid 89B message");
        assert_eq!(msg, parsed);
    }

    #[test]
    fn test_retrieval_message_truncated_length_rejected() {
        let msg = RetrievalMessage {
            machine_id: MachineId::new(),
            tx_id: TransactionId::new(),
            req_id: RequestId::new(),
            t_req: TimestampNs::from_nanos(1_700_000_000_000_000_000),
        };
        let raw = msg.serialize_canonical();

        // Truncate to 88 bytes
        let truncated = &raw[..88];
        let err = RetrievalMessage::parse_canonical(truncated).unwrap_err();
        assert_eq!(
            err,
            ProtocolError::InvalidLength {
                expected: 89,
                actual: 88
            }
        );
    }

    #[test]
    fn test_retrieval_message_invalid_domain_separator_rejected() {
        let mut raw = [0u8; 89];
        raw[0..33].copy_from_slice(b"WRONG-DOMAIN-SEPARATOR-PADDING--\0");
        let err = RetrievalMessage::parse_canonical(&raw).unwrap_err();
        match err {
            ProtocolError::InvalidDomainSeparator { expected, actual } => {
                assert_eq!(expected, OPENAUDIT_OUTBOX_RETRIEVAL_DOMAIN_V1_24);
                assert_eq!(actual, raw[0..33].to_vec());
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn test_enrollment_transcript_fixed_overhead() {
        let transcript = EnrollmentTranscript {
            nonce_auth: ChallengeNonce([0x11; 32]),
            token_id: EnrollmentTokenId::new(),
            tx_id: TransactionId::new(),
            machine_id: MachineId::new(),
            ek_pub: vec![0x30, 0x82, 0x01, 0x22], // 4 bytes dummy key
            name_srk: SrkName([0x22; 34]),
            lifecycle_id: LifecycleId([0x33; 32]),
            generation_mach: EnrollmentGeneration::from_u32(1),
            counter_base: CounterValue::from_u64(42),
            catalog_base: CatalogVersion::from_u64(10),
            timestamp_issued: TimestampNs::from_nanos(1_700_000_000_000_000_000),
            timestamp_expires: TimestampNs::from_nanos(1_700_000_300_000_000_000),
        };

        let serialized = transcript
            .serialize_canonical()
            .expect("valid transcript serialization");
        assert_eq!(
            serialized.len(),
            204 + 4,
            "Serialized transcript must be exactly 204 fixed + N bytes"
        );

        let parsed = EnrollmentTranscript::parse_canonical(&serialized)
            .expect("must parse canonical transcript");
        assert_eq!(transcript, parsed);
    }

    #[test]
    fn test_trust_gate_timestamp_out_of_bounds() {
        let msg = RetrievalMessage {
            machine_id: MachineId::new(),
            tx_id: TransactionId::new(),
            req_id: RequestId::new(),
            t_req: TimestampNs::from_nanos(1_700_000_000_000_000_000),
        };
        let raw = msg.serialize_canonical();
        let unverified = UnverifiedRetrievalRequest::new(raw.to_vec(), [0x00; 32]);

        let verifier = RustCryptoMacVerifier;
        let secret = SharedSecret([0xaa; 32]);

        // Evaluate at T_req + 75 seconds (exceeds 60s limit)
        let t_auth_late = TimestampNs::from_nanos(1_700_000_075_000_000_000);
        let err = unverified
            .verify(&verifier, &secret, t_auth_late)
            .unwrap_err();

        match err {
            ProtocolError::TimestampOutOfBounds {
                skew_nanos,
                max_window_nanos,
            } => {
                assert_eq!(skew_nanos, 75_000_000_000);
                assert_eq!(max_window_nanos, 60_000_000_000);
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn test_trust_gate_invalid_hmac_rejected() {
        let msg = RetrievalMessage {
            machine_id: MachineId::new(),
            tx_id: TransactionId::new(),
            req_id: RequestId::new(),
            t_req: TimestampNs::from_nanos(1_700_000_000_000_000_000),
        };
        let raw = msg.serialize_canonical();
        let unverified = UnverifiedRetrievalRequest::new(raw.to_vec(), [0xff; 32]); // wrong tag

        let verifier = RustCryptoMacVerifier;
        let secret = SharedSecret([0xaa; 32]);

        let t_auth_valid = TimestampNs::from_nanos(1_700_000_010_000_000_000); // 10s skew (valid)
        let err = unverified
            .verify(&verifier, &secret, t_auth_valid)
            .unwrap_err();

        assert_eq!(err, ProtocolError::InvalidHmacProof);
    }

    #[test]
    fn test_trust_gate_valid_request_produces_verified_request_with_ttl() {
        let msg = RetrievalMessage {
            machine_id: MachineId::new(),
            tx_id: TransactionId::new(),
            req_id: RequestId::new(),
            t_req: TimestampNs::from_nanos(1_700_000_000_000_000_000),
        };
        let raw = msg.serialize_canonical();
        let secret = SharedSecret([0xaa; 32]);
        let valid_tag = compute_hmac_sha256(&secret, &raw);

        let unverified = UnverifiedRetrievalRequest::new(raw.to_vec(), valid_tag);
        let mac_verifier = RustCryptoMacVerifier;

        let t_auth = TimestampNs::from_nanos(1_700_000_005_000_000_000); // 5s skew
        let verified = unverified
            .verify(&mac_verifier, &secret, t_auth)
            .expect("must pass all gates");

        assert_eq!(verified.message, msg);
        // Expiry must be t_req + 120s
        assert_eq!(verified.expires_at.as_nanos(), 1_700_000_120_000_000_000);
    }

    // =========================================================================
    // Cryptographic Test Vectors (v1.24 Specification Vectors 1, 2, and 3)
    // =========================================================================

    #[test]
    fn test_cryptographic_vector_1_rsa2048() {
        let secret = SharedSecret(decode_hex_32(
            "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
        ));
        let nonce = ChallengeNonce(decode_hex_32(
            "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
        ));
        let token_id = EnrollmentTokenId::parse("11111111-2222-3333-4444-555555555555").unwrap();
        let tx_id = TransactionId::parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
        let machine_id = MachineId::parse("99999999-8888-7777-6666-555555555555").unwrap();
        let ek_pub_hex = "30820122300d06092a864886f70d01010105000382010f003082010a0282010100d4b8a2e1f4094a97b21a3e6c8d7f0b5ed4b8a2e1f4094a97b21a3e6c8d7f0b5ed4b8a2e1f4094a97b21a3e6c8d7f0b5ed4b8a2e1f4094a97b21a3e6c8d7f0b5ed4b8a2e1f4094a97b21a3e6c8d7f0b5ed4b8a2e1f4094a97b21a3e6c8d7f0b5ed4b8a2e1f4094a97b21a3e6c8d7f0b5ed4b8a2e1f4094a97b21a3e6c8d7f0b5ed4b8a2e1f4094a97b21a3e6c8d7f0b5ed4b8a2e1f4094a97b21a3e6c8d7f0b5ed4b8a2e1f4094a97b21a3e6c8d7f0b5ed4b8a2e1f4094a97b21a3e6c8d7f0b5ed4b8a2e1f4094a97b21a3e6c8d7f0b5ed4b8a2e1f4094a97b21a3e6c8d7f0b5ed4b8a2e1f4094a97b21a3e6c8d7f0b5ed4b8a2e1f4094a97b21a3e6c8d7f0b5f0203010001";
        let ek_pub = decode_hex(ek_pub_hex);
        assert_eq!(ek_pub.len(), 294, "Vector 1 EK pub DER must be 294 bytes");

        // Validate SPKI structure & cryptography
        let spki_validator = RustCryptoSpkiValidator;
        let meta = spki_validator
            .validate_spki_der(&ek_pub)
            .expect("Vector 1 must be valid SPKI RSA key");
        assert_eq!(
            meta,
            KeyMetadata::Rsa {
                modulus_bits: 2048,
                public_exponent: 65537
            }
        );

        let name_srk = SrkName(decode_hex_34(
            "000b98687a71842813589b917578ec6b5e0c52bbbc0b2c1f93f6b7c9aa029f6db805",
        ));
        let lifecycle_id = LifecycleId(decode_hex_32(
            "ffffffffffffffffffffffffffffffff00000000000000000000000000000001",
        ));

        let transcript = EnrollmentTranscript {
            nonce_auth: nonce,
            token_id,
            tx_id,
            machine_id,
            ek_pub,
            name_srk,
            lifecycle_id,
            generation_mach: EnrollmentGeneration::from_u32(1),
            counter_base: CounterValue::from_u64(42),
            catalog_base: CatalogVersion::from_u64(1),
            timestamp_issued: TimestampNs::from_nanos(1_700_000_000_000_000_000),
            timestamp_expires: TimestampNs::from_nanos(1_700_000_300_000_000_000),
        };

        let serialized = transcript.serialize_canonical().unwrap();
        assert_eq!(
            serialized.len(),
            498,
            "Vector 1 serialized length must be 498 bytes (204 + 294)"
        );

        // Digest check
        let digest = compute_sha256(&serialized);
        let expected_digest =
            decode_hex_32("09e366765e837e41652a4ed6ef146f06ce557c8c8ed89b752909640939b6421d");
        assert_eq!(digest, expected_digest, "Vector 1 SHA-256 digest mismatch");

        // Enrollment Proof HMAC check
        let hmac_tag = compute_hmac_sha256(&secret, &serialized);
        let expected_hmac =
            decode_hex_32("579450609b3a166ce946ed15602c1ef8ce216bbc5f1e064a881ea62eb56638ac");
        assert_eq!(hmac_tag, expected_hmac, "Vector 1 Enrollment HMAC mismatch");

        // Retrieval Proof check
        let ret_msg = RetrievalMessage {
            machine_id,
            tx_id,
            req_id: RequestId::parse("77777777-6666-5555-4444-333333333333").unwrap(),
            t_req: TimestampNs::from_nanos(1_700_000_100_000_000_000),
        };
        let ret_bytes = ret_msg.serialize_canonical();
        assert_eq!(ret_bytes.len(), 89);
        let ret_proof = compute_hmac_sha256(&secret, &ret_bytes);
        let expected_ret_proof =
            decode_hex_32("99aef0de9502d7f977b97e660aff92398bd652642cbd86dea817ced66d78180a");
        assert_eq!(
            ret_proof, expected_ret_proof,
            "Vector 1 Retrieval HMAC mismatch"
        );

        // Constant-time verifier check
        let verifier = RustCryptoMacVerifier;
        assert!(verifier
            .verify_hmac_sha256(&secret, &ret_bytes, &expected_ret_proof)
            .is_ok());
    }

    #[test]
    fn test_cryptographic_vector_2_rsa2048_reenrollment() {
        let secret = SharedSecret(decode_hex_32(
            "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0",
        ));
        let nonce = ChallengeNonce(decode_hex_32(
            "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
        ));
        let token_id = EnrollmentTokenId::parse("22222222-3333-4444-5555-666666666666").unwrap();
        let tx_id = TransactionId::parse("bbbbbbbb-cccc-dddd-eeee-ffffffffffff").unwrap();
        let machine_id = MachineId::parse("99999999-8888-7777-6666-555555555555").unwrap();
        let ek_pub_hex = "30820122300d06092a864886f70d01010105000382010f003082010a0282010100bbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899ab0203010001";
        let ek_pub = decode_hex(ek_pub_hex);
        assert_eq!(ek_pub.len(), 294);

        let spki_validator = RustCryptoSpkiValidator;
        let meta = spki_validator
            .validate_spki_der(&ek_pub)
            .expect("Vector 2 must be valid SPKI RSA key");
        assert_eq!(
            meta,
            KeyMetadata::Rsa {
                modulus_bits: 2048,
                public_exponent: 65537
            }
        );

        let name_srk = SrkName(decode_hex_34(
            "000b98687a71842813589b917578ec6b5e0c52bbbc0b2c1f93f6b7c9aa029f6db805",
        ));
        let lifecycle_id = LifecycleId(decode_hex_32(
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee11111111111111111111111111111112",
        ));

        let transcript = EnrollmentTranscript {
            nonce_auth: nonce,
            token_id,
            tx_id,
            machine_id,
            ek_pub,
            name_srk,
            lifecycle_id,
            generation_mach: EnrollmentGeneration::from_u32(2),
            counter_base: CounterValue::from_u64(1050),
            catalog_base: CatalogVersion::from_u64(500),
            timestamp_issued: TimestampNs::from_nanos(1_700_100_000_000_000_000),
            timestamp_expires: TimestampNs::from_nanos(1_700_100_300_000_000_000),
        };

        let serialized = transcript.serialize_canonical().unwrap();
        assert_eq!(serialized.len(), 498);

        let digest = compute_sha256(&serialized);
        let expected_digest =
            decode_hex_32("aa73acf76b7361d3f7d5f4f4975a7b10182217b5c6f99fd8d74607275db432ff");
        assert_eq!(digest, expected_digest, "Vector 2 SHA-256 digest mismatch");

        let hmac_tag = compute_hmac_sha256(&secret, &serialized);
        let expected_hmac =
            decode_hex_32("a609c11b70e277152f097bc35cf37bc13c8468bebc0ca535a89ba631e2d64f15");
        assert_eq!(hmac_tag, expected_hmac, "Vector 2 Enrollment HMAC mismatch");

        // Retrieval Proof check
        let ret_msg = RetrievalMessage {
            machine_id,
            tx_id,
            req_id: RequestId::parse("88888888-7777-6666-5555-444444444444").unwrap(),
            t_req: TimestampNs::from_nanos(1_700_100_100_000_000_000),
        };
        let ret_bytes = ret_msg.serialize_canonical();
        let ret_proof = compute_hmac_sha256(&secret, &ret_bytes);
        let expected_ret_proof =
            decode_hex_32("b9a5553ba11d4808d4add8e095898f37006caf0e8e526128551ca7e92d58e905");
        assert_eq!(
            ret_proof, expected_ret_proof,
            "Vector 2 Retrieval HMAC mismatch"
        );
    }

    #[test]
    fn test_cryptographic_vector_3_ecc_p256() {
        let secret = SharedSecret(decode_hex_32(
            "4a5b6c7d8e9f00112233445566778899aabbccddeeff00112233445566778899",
        ));
        let nonce = ChallengeNonce(decode_hex_32(
            "a5a5a5a55a5a5a5aa5a5a5a55a5a5a5aa5a5a5a55a5a5a5aa5a5a5a55a5a5a5a",
        ));
        let token_id = EnrollmentTokenId::parse("33333333-4444-5555-6666-777777777777").unwrap();
        let tx_id = TransactionId::parse("cccccccc-dddd-eeee-ffff-000000000000").unwrap();
        let machine_id = MachineId::parse("12345678-1234-5678-1234-567812345678").unwrap();
        let ek_pub_hex = "3059301306072a8648ce3d020106082a8648ce3d030107034200046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
        let ek_pub = decode_hex(ek_pub_hex);
        assert_eq!(ek_pub.len(), 91, "Vector 3 EK pub DER must be 91 bytes");

        // Validate SPKI ECC structure & cryptographic on-curve check
        let spki_validator = RustCryptoSpkiValidator;
        let meta = spki_validator
            .validate_spki_der(&ek_pub)
            .expect("Vector 3 must be valid ECC P-256 key");
        assert_eq!(
            meta,
            KeyMetadata::Ecc {
                curve_name: "secp256r1"
            }
        );

        let name_srk = SrkName(decode_hex_34(
            "000baabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
        ));
        let lifecycle_id = LifecycleId(decode_hex_32(
            "0000000011111111222222223333333344444444555555556666666677777777",
        ));

        let transcript = EnrollmentTranscript {
            nonce_auth: nonce,
            token_id,
            tx_id,
            machine_id,
            ek_pub,
            name_srk,
            lifecycle_id,
            generation_mach: EnrollmentGeneration::from_u32(7),
            counter_base: CounterValue::from_u64(987_654),
            catalog_base: CatalogVersion::from_u64(24_000),
            timestamp_issued: TimestampNs::from_nanos(1_705_000_000_000_000_000),
            timestamp_expires: TimestampNs::from_nanos(1_705_000_300_000_000_000),
        };

        let serialized = transcript.serialize_canonical().unwrap();
        assert_eq!(
            serialized.len(),
            295,
            "Vector 3 serialized length must be 295 bytes (204 + 91)"
        );

        let digest = compute_sha256(&serialized);
        let expected_digest =
            decode_hex_32("c2bda31e3fbe357218d26e008c30f04c357a1e3a3be869fa0db5c8518f7dcc5b");
        assert_eq!(digest, expected_digest, "Vector 3 SHA-256 digest mismatch");

        let hmac_tag = compute_hmac_sha256(&secret, &serialized);
        let expected_hmac =
            decode_hex_32("47d74d942684f88f5aa348a0dd9c3c5f2e4ffff20b187258dc6564da3afe7c1b");
        assert_eq!(hmac_tag, expected_hmac, "Vector 3 Enrollment HMAC mismatch");

        // Retrieval Proof check
        let ret_msg = RetrievalMessage {
            machine_id,
            tx_id,
            req_id: RequestId::parse("99999999-0000-1111-2222-333333333333").unwrap(),
            t_req: TimestampNs::from_nanos(1_705_000_100_000_000_000),
        };
        let ret_bytes = ret_msg.serialize_canonical();
        let ret_proof = compute_hmac_sha256(&secret, &ret_bytes);
        let expected_ret_proof =
            decode_hex_32("10bf4df8eed7646e3ad5b8c9d672243383e6444a6948ea56a620cfd32531cf59");
        assert_eq!(
            ret_proof, expected_ret_proof,
            "Vector 3 Retrieval HMAC mismatch"
        );
    }

    #[test]
    fn test_spki_validation_negative_cases() {
        let validator = RustCryptoSpkiValidator;

        // 1. Truncated DER
        let truncated = vec![0x30, 0x59, 0x30];
        let err1 = validator.validate_spki_der(&truncated).unwrap_err();
        assert!(matches!(err1, ProtocolError::MalformedDerKey(_)));

        // 2. Off-curve ECC point (Vector 3 with last byte modified)
        let mut off_curve = decode_hex("3059301306072a8648ce3d020106082a8648ce3d030107034200046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");
        let last_idx = off_curve.len() - 1;
        off_curve[last_idx] ^= 0x01; // Corrupt coordinate
        let err2 = validator.validate_spki_der(&off_curve).unwrap_err();
        assert!(matches!(err2, ProtocolError::MalformedDerKey(_)));

        // 3. Unsupported Algorithm OID (Ed25519 OID 1.3.101.112: 302a300506032b6570032100...)
        let ed25519_spki = decode_hex("302a300506032b65700321000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
        let err3 = validator.validate_spki_der(&ed25519_spki).unwrap_err();
        assert!(matches!(err3, ProtocolError::MalformedDerKey(_)));
    }

    #[test]
    fn test_rsa_modulus_2047_vs_2048_and_invalid_cases() {
        let validator = RustCryptoSpkiValidator;

        // Valid Vector 1 SPKI DER
        let v1_der = decode_hex("30820122300d06092a864886f70d01010105000382010f003082010a0282010100d4b8a2e1f4094a97b21a3e6c8d7f0b5ed4b8a2e1f4094a97b21a3e6c8d7f0b5ed4b8a2e1f4094a97b21a3e6c8d7f0b5ed4b8a2e1f4094a97b21a3e6c8d7f0b5ed4b8a2e1f4094a97b21a3e6c8d7f0b5ed4b8a2e1f4094a97b21a3e6c8d7f0b5ed4b8a2e1f4094a97b21a3e6c8d7f0b5ed4b8a2e1f4094a97b21a3e6c8d7f0b5ed4b8a2e1f4094a97b21a3e6c8d7f0b5ed4b8a2e1f4094a97b21a3e6c8d7f0b5ed4b8a2e1f4094a97b21a3e6c8d7f0b5ed4b8a2e1f4094a97b21a3e6c8d7f0b5ed4b8a2e1f4094a97b21a3e6c8d7f0b5ed4b8a2e1f4094a97b21a3e6c8d7f0b5ed4b8a2e1f4094a97b21a3e6c8d7f0b5ed4b8a2e1f4094a97b21a3e6c8d7f0b5f0203010001");
        assert!(validator.validate_spki_der(&v1_der).is_ok());

        // 1. Modulus with 2047 bits:
        // A valid 2047-bit RSA key where MSB is 0x7f (7 bits in MSB + 255*8 = 2047 bits).
        let v1_2047 = decode_hex("30820121300d06092a864886f70d01010105000382010e0030820109028201007faaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa010203010001");
        let err_2047 = validator.validate_spki_der(&v1_2047).unwrap_err();
        match err_2047 {
            ProtocolError::MalformedDerKey(msg) => {
                assert!(
                    msg.contains("2047 bits"),
                    "expected 2047 bits error, got: {msg}"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }

        // 2. Modulus that is even (composite of 2)
        // Modulus ends at byte 288 (index 288). In v1_der, byte 288 is 0x5f (odd).
        // Change it to 0x5e (even).
        let mut v1_even = v1_der.clone();
        v1_even[288] = 0x5e;
        let err_even = validator.validate_spki_der(&v1_even).unwrap_err();
        match err_even {
            ProtocolError::MalformedDerKey(msg) => {
                assert!(
                    msg.contains("even"),
                    "expected even modulus error, got: {msg}"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }

        // 3. RSA parameters must be NULL (RFC 3279 § 2.3.1).
        // In v1_der, bytes 17..19 are 0x05 0x00 (ASN.1 NULL).
        // Corrupt tag to 0x02 (INTEGER).
        let mut v1_bad_params = v1_der.clone();
        v1_bad_params[17] = 0x02;
        let err_params = validator.validate_spki_der(&v1_bad_params).unwrap_err();
        assert!(matches!(err_params, ProtocolError::MalformedDerKey(_)));

        // 4. Non-zero unused bits in BIT STRING.
        // Byte 23 in v1_der is 0x00 (unused bits).
        // Change to 0x03.
        let mut v1_bad_unused = v1_der;
        v1_bad_unused[23] = 0x03;
        let err_unused = validator.validate_spki_der(&v1_bad_unused).unwrap_err();
        assert!(matches!(err_unused, ProtocolError::MalformedDerKey(_)));
    }

    #[test]
    fn test_timestamp_exact_boundaries_and_i64_extremes() {
        let msg = RetrievalMessage {
            machine_id: MachineId::new(),
            tx_id: TransactionId::new(),
            req_id: RequestId::new(),
            t_req: TimestampNs::from_nanos(1_700_000_000_000_000_000),
        };
        let raw = msg.serialize_canonical();
        let secret = SharedSecret([0xaa; 32]);
        let valid_tag = compute_hmac_sha256(&secret, &raw);
        let unverified = UnverifiedRetrievalRequest::new(raw.to_vec(), valid_tag);
        let verifier = RustCryptoMacVerifier;

        let t_req = msg.t_req.as_nanos();

        // Exact +60s boundary (60,000,000,000 ns): Must PASS
        let t_plus_60 = TimestampNs::from_nanos(t_req + 60_000_000_000);
        assert!(unverified.verify(&verifier, &secret, t_plus_60).is_ok());

        // Exact -60s boundary (-60,000,000,000 ns): Must PASS
        let t_minus_60 = TimestampNs::from_nanos(t_req - 60_000_000_000);
        assert!(unverified.verify(&verifier, &secret, t_minus_60).is_ok());

        // +60s + 1ns: Must FAIL
        let t_plus_60_1 = TimestampNs::from_nanos(t_req + 60_000_000_001);
        let err_plus = unverified
            .verify(&verifier, &secret, t_plus_60_1)
            .unwrap_err();
        assert!(matches!(
            err_plus,
            ProtocolError::TimestampOutOfBounds {
                skew_nanos: 60_000_000_001,
                ..
            }
        ));

        // -60s - 1ns: Must FAIL
        let t_minus_60_1 = TimestampNs::from_nanos(t_req - 60_000_000_001);
        let err_minus = unverified
            .verify(&verifier, &secret, t_minus_60_1)
            .unwrap_err();
        assert!(matches!(
            err_minus,
            ProtocolError::TimestampOutOfBounds {
                skew_nanos: 60_000_000_001,
                ..
            }
        ));

        // i64 Extreme: t_req = i64::MAX, t_auth = i64::MIN (Must not panic, must detect skew)
        let extreme_msg = RetrievalMessage {
            machine_id: MachineId::new(),
            tx_id: TransactionId::new(),
            req_id: RequestId::new(),
            t_req: TimestampNs::from_nanos(i64::MAX),
        };
        let raw_extreme = extreme_msg.serialize_canonical();
        let tag_extreme = compute_hmac_sha256(&secret, &raw_extreme);
        let unverified_extreme = UnverifiedRetrievalRequest::new(raw_extreme.to_vec(), tag_extreme);
        let err_extreme = unverified_extreme
            .verify(&verifier, &secret, TimestampNs::from_nanos(i64::MIN))
            .unwrap_err();
        assert!(matches!(
            err_extreme,
            ProtocolError::TimestampOutOfBounds { .. }
        ));

        // Expiry overflow: t_req = i64::MAX - 10, t_auth = i64::MAX - 10 (skew = 0)
        // t_req + 120s overflows i64::MAX
        let overflow_msg = RetrievalMessage {
            machine_id: MachineId::new(),
            tx_id: TransactionId::new(),
            req_id: RequestId::new(),
            t_req: TimestampNs::from_nanos(i64::MAX - 10),
        };
        let raw_overflow = overflow_msg.serialize_canonical();
        let tag_overflow = compute_hmac_sha256(&secret, &raw_overflow);
        let unverified_overflow =
            UnverifiedRetrievalRequest::new(raw_overflow.to_vec(), tag_overflow);
        let err_overflow = unverified_overflow
            .verify(&verifier, &secret, TimestampNs::from_nanos(i64::MAX - 10))
            .unwrap_err();
        assert!(matches!(err_overflow, ProtocolError::CryptoError(_)));
    }
}
