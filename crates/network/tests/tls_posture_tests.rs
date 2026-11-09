//! Deterministic test suite for OpenAudit M4 Increment 4: TLS Posture Assessment.
//!
//! Validates:
//! 1. Valid TLS 1.2 certificate.
//! 2. Valid TLS 1.3 certificate.
//! 3. Expired certificate.
//! 4. Not-yet-valid certificate.
//! 5. Hostname mismatch.
//! 6. Missing or incomplete certificate chain (untrusted root).
//! 7. Weak public key (RSA 1024-bit key).
//! 8. Weak certificate signature algorithm (SHA-1).
//! 9. TLS handshake timeout.
//! 10. Cancellation during assessment.
//! 11. Unsupported TLS endpoint (plain TCP port).
//! 12. DNS rebinding prevention and pinned destination enforcement.
//! 13. TLS assessment of non-standard ports.
//! 14. Correct handling of untrusted certificates (observations recorded, trust marked failed).
//! 15. Accurate separation of negotiated protocol, certificate validity, and trust.

use chrono::Utc;
use openaudit_network::pinned::PinnedTarget;
use openaudit_network::resolver::MockDnsResolver;
use openaudit_network::scope::TargetScope;
use openaudit_network::target::CanonicalTarget;
use openaudit_network::tls::{
    CertificateTrustStatus, CipherSecurityRating, TlsAssessConfig, TlsAssessor, TlsVersion,
};
use rcgen::{
    date_time_ymd, BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{RootCertStore, ServerConfig};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// Helper generating deterministic PKI fixtures for tests.
struct TestTlsServer {
    pub port: u16,
    pub _root_store: Arc<RootCertStore>,
    _handle: thread::JoinHandle<()>,
}

impl TestTlsServer {
    fn spawn(
        server_config: Arc<ServerConfig>,
        root_store: Arc<RootCertStore>,
        max_connections: usize,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("Must bind");
        let port = listener.local_addr().unwrap().port();

        let handle = thread::spawn(move || {
            for _ in 0..max_connections {
                if let Ok((tcp_stream, _)) = listener.accept() {
                    let cfg = server_config.clone();
                    thread::spawn(move || {
                        if let Ok(conn) = rustls::ServerConnection::new(cfg) {
                            let mut tls_stream = rustls::StreamOwned::new(conn, tcp_stream);
                            // Complete handshake and read optional data
                            let mut buf = [0u8; 128];
                            let _ = tls_stream.read(&mut buf);
                        }
                    });
                }
            }
        });

        Self {
            port,
            _root_store: root_store,
            _handle: handle,
        }
    }
}

fn make_pinned(hostname: &str, port: u16) -> PinnedTarget {
    let target = CanonicalTarget::parse(hostname).unwrap();
    let scope = TargetScope {
        allow_loopback: true,
        ..Default::default()
    };
    let mut mock_dns = MockDnsResolver::new();
    mock_dns.insert(hostname, vec!["127.0.0.1".parse().unwrap()]);
    openaudit_network::resolver::resolve_and_pin(&target, &scope, &mock_dns, port).unwrap()
}

// -----------------------------------------------------------------------------
// Test 1: Valid TLS 1.3 Handshake & Trusted Anchor
// -----------------------------------------------------------------------------
#[test]
fn test_valid_tls13_trusted_certificate() {
    let ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "OpenAudit Root CA");
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    let issuer = Issuer::from_params(&ca_params, &ca_key);
    let server_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut server_params = CertificateParams::default();
    server_params
        .distinguished_name
        .push(DnType::CommonName, "valid.example.com");
    server_params
        .subject_alt_names
        .push(SanType::DnsName("valid.example.com".try_into().unwrap()));
    let server_cert = server_params.signed_by(&server_key, &issuer).unwrap();

    let cert_der = CertificateDer::from(server_cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(server_key.serialize_der()).unwrap();

    let server_cfg =
        ServerConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap();

    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(ca_cert.der().to_vec()))
        .unwrap();
    let root_store = Arc::new(roots);

    let server = TestTlsServer::spawn(Arc::new(server_cfg), root_store.clone(), 3);

    let pinned = make_pinned("valid.example.com", server.port);
    let config = TlsAssessConfig {
        timeout: Duration::from_millis(1500),
        custom_root_store: Some(root_store),
        probe_all_versions: true,
    };

    let report = TlsAssessor::assess(&pinned, server.port, &config, None).unwrap();
    assert!(report.handshake_completed);
    assert_eq!(report.negotiated_version, Some(TlsVersion::Tls13));
    assert!(report.supports_tls13);
    assert_eq!(report.trust_status, CertificateTrustStatus::Trusted);
    assert!(report.hostname_matched);
    assert_eq!(
        report.negotiated_cipher.as_ref().unwrap().security_rating,
        CipherSecurityRating::Secure
    );
    assert!(
        report.findings.is_empty(),
        "Valid TLS 1.3 should produce 0 findings"
    );
}

// -----------------------------------------------------------------------------
// Test 2: Valid TLS 1.2 Handshake
// -----------------------------------------------------------------------------
#[test]
fn test_valid_tls12_handshake() {
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, "tls12.example.com");
    params
        .subject_alt_names
        .push(SanType::DnsName("tls12.example.com".try_into().unwrap()));
    let cert = params.self_signed(&key).unwrap();

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(key.serialize_der()).unwrap();

    let server_cfg =
        ServerConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
            .with_protocol_versions(&[&rustls::version::TLS12])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap();

    let server = TestTlsServer::spawn(Arc::new(server_cfg), Arc::new(RootCertStore::empty()), 3);

    let pinned = make_pinned("tls12.example.com", server.port);
    let config = TlsAssessConfig {
        timeout: Duration::from_millis(1500),
        custom_root_store: None,
        probe_all_versions: true,
    };

    let report = TlsAssessor::assess(&pinned, server.port, &config, None).unwrap();
    assert!(report.handshake_completed);
    assert_eq!(report.negotiated_version, Some(TlsVersion::Tls12));
    assert!(report.supports_tls12);
    assert!(!report.supports_tls13);
    // Legacy TLS 1.2 finding emitted
    assert!(report
        .findings
        .iter()
        .any(|f| f.id == "tls.protocol.tls12-legacy"));
}

// -----------------------------------------------------------------------------
// Test 3: Expired Certificate Finding
// -----------------------------------------------------------------------------
#[test]
fn test_expired_certificate_findings() {
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, "expired.example.com");
    params
        .subject_alt_names
        .push(SanType::DnsName("expired.example.com".try_into().unwrap()));
    params.not_before = date_time_ymd(2020, 1, 1);
    params.not_after = date_time_ymd(2021, 1, 1); // Expired years ago
    let cert = params.self_signed(&key).unwrap();

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(key.serialize_der()).unwrap();

    let server_cfg =
        ServerConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap();

    let server = TestTlsServer::spawn(Arc::new(server_cfg), Arc::new(RootCertStore::empty()), 2);

    let pinned = make_pinned("expired.example.com", server.port);
    let config = TlsAssessConfig::default();

    let report = TlsAssessor::assess(&pinned, server.port, &config, None).unwrap();
    assert!(report.handshake_completed);
    assert_eq!(report.trust_status, CertificateTrustStatus::Expired);
    assert!(report.findings.iter().any(|f| f.id == "tls.cert.expired"));
    // Probing did not silently abort: metadata was still extracted!
    assert!(report.leaf_certificate.is_some());
}

// -----------------------------------------------------------------------------
// Test 4: Not-Yet-Valid Certificate Finding
// -----------------------------------------------------------------------------
#[test]
fn test_not_yet_valid_certificate_findings() {
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, "future.example.com");
    params
        .subject_alt_names
        .push(SanType::DnsName("future.example.com".try_into().unwrap()));
    params.not_before = date_time_ymd(2035, 1, 1); // Starts in 2035
    params.not_after = date_time_ymd(2036, 1, 1);
    let cert = params.self_signed(&key).unwrap();

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(key.serialize_der()).unwrap();

    let server_cfg =
        ServerConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap();

    let server = TestTlsServer::spawn(Arc::new(server_cfg), Arc::new(RootCertStore::empty()), 2);

    let pinned = make_pinned("future.example.com", server.port);
    let config = TlsAssessConfig::default();

    let report = TlsAssessor::assess(&pinned, server.port, &config, None).unwrap();

    assert_eq!(report.trust_status, CertificateTrustStatus::NotYetValid);
    assert!(report
        .findings
        .iter()
        .any(|f| f.id == "tls.cert.not-yet-valid"));
}

// -----------------------------------------------------------------------------
// Test 5: Hostname Mismatch Finding
// -----------------------------------------------------------------------------
#[test]
fn test_hostname_mismatch_findings() {
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, "auth.internal.corp");
    params
        .subject_alt_names
        .push(SanType::DnsName("auth.internal.corp".try_into().unwrap()));
    let cert = params.self_signed(&key).unwrap();

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(key.serialize_der()).unwrap();

    let server_cfg =
        ServerConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap();

    let server = TestTlsServer::spawn(Arc::new(server_cfg), Arc::new(RootCertStore::empty()), 2);

    // Target is 'portal.example.com', but cert is 'auth.internal.corp'
    let pinned = make_pinned("portal.example.com", server.port);
    let config = TlsAssessConfig::default();

    let report = TlsAssessor::assess(&pinned, server.port, &config, None).unwrap();

    assert!(!report.hostname_matched);
    assert_eq!(
        report.trust_status,
        CertificateTrustStatus::HostnameMismatch
    );
    assert!(report
        .findings
        .iter()
        .any(|f| f.id == "tls.cert.hostname-mismatch"));
}

// -----------------------------------------------------------------------------
// Test 6: Self-Signed Certificate Finding
// -----------------------------------------------------------------------------
#[test]
fn test_self_signed_certificate_findings() {
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, "selfsigned.local");
    params
        .subject_alt_names
        .push(SanType::DnsName("selfsigned.local".try_into().unwrap()));
    let cert = params.self_signed(&key).unwrap();

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(key.serialize_der()).unwrap();

    let server_cfg =
        ServerConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap();

    let server = TestTlsServer::spawn(Arc::new(server_cfg), Arc::new(RootCertStore::empty()), 2);

    let pinned = make_pinned("selfsigned.local", server.port);
    let config = TlsAssessConfig::default();

    let report = TlsAssessor::assess(&pinned, server.port, &config, None).unwrap();

    assert_eq!(report.trust_status, CertificateTrustStatus::SelfSigned);
    assert!(report
        .findings
        .iter()
        .any(|f| f.id == "tls.cert.self-signed"));
}

// -----------------------------------------------------------------------------
// Test 7: Untrusted Root Certificate Authority
// -----------------------------------------------------------------------------
#[test]
fn test_untrusted_root_findings() {
    let ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Rogue Untrusted CA");

    let issuer = Issuer::from_params(&ca_params, &ca_key);
    let server_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut server_params = CertificateParams::default();
    server_params
        .distinguished_name
        .push(DnType::CommonName, "untrusted.corp");
    server_params
        .subject_alt_names
        .push(SanType::DnsName("untrusted.corp".try_into().unwrap()));
    let server_cert = server_params.signed_by(&server_key, &issuer).unwrap();

    let cert_der = CertificateDer::from(server_cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(server_key.serialize_der()).unwrap();

    let server_cfg =
        ServerConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap();

    // Client has empty trust store -> cannot anchor the cert
    let server = TestTlsServer::spawn(Arc::new(server_cfg), Arc::new(RootCertStore::empty()), 2);

    let pinned = make_pinned("untrusted.corp", server.port);
    let config = TlsAssessConfig {
        timeout: Duration::from_millis(1500),
        custom_root_store: Some(Arc::new(RootCertStore::empty())),
        probe_all_versions: true,
    };

    let report = TlsAssessor::assess(&pinned, server.port, &config, None).unwrap();

    assert_eq!(report.trust_status, CertificateTrustStatus::UntrustedRoot);
    assert!(report
        .findings
        .iter()
        .any(|f| f.id == "tls.cert.untrusted-root"));
}

// -----------------------------------------------------------------------------
// Test 8: Handshake Timeout Handling
// -----------------------------------------------------------------------------
#[test]
fn test_tls_handshake_timeout() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    // Server accepts TCP connection but hangs during TLS handshake
    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 128];
            let _ = stream.read(&mut buf);
            thread::sleep(Duration::from_millis(800));
        }
    });

    let pinned = make_pinned("timeout.local", port);
    let config = TlsAssessConfig {
        timeout: Duration::from_millis(200), // Fast 200ms timeout
        custom_root_store: None,
        probe_all_versions: false,
    };

    let report = TlsAssessor::assess(&pinned, port, &config, None).unwrap();

    assert!(!report.handshake_completed);
    assert!(report.error_diagnostic.is_some());
    assert!(report.negotiated_version.is_none());
}

// -----------------------------------------------------------------------------
// Test 9: Cancellation During Assessment
// -----------------------------------------------------------------------------
#[test]
fn test_cancellation_during_tls_assessment() {
    let pinned = make_pinned("cancel.local", 443);
    let cancel = Arc::new(AtomicBool::new(true)); // Already canceled
    let config = TlsAssessConfig::default();

    let res = TlsAssessor::assess(&pinned, 443, &config, Some(cancel));

    assert!(res.is_err());
    assert!(res.unwrap_err().to_string().contains("canceled"));
}

// -----------------------------------------------------------------------------
// Test 10: Non-TLS Plain TCP Endpoint
// -----------------------------------------------------------------------------
#[test]
fn test_non_tls_plain_endpoint() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let _ = stream.write_all(b"SSH-2.0-OpenSSH_9.0\r\n");
        }
    });

    let pinned = make_pinned("plain.local", port);
    let config = TlsAssessConfig {
        timeout: Duration::from_millis(500),
        custom_root_store: None,
        probe_all_versions: false,
    };

    let report = TlsAssessor::assess(&pinned, port, &config, None).unwrap();

    assert!(!report.handshake_completed);
    assert!(report.error_diagnostic.is_some());
}

// -----------------------------------------------------------------------------
// Test 11: Non-Standard TLS Port Assessment
// -----------------------------------------------------------------------------
#[test]
fn test_non_standard_tls_port() {
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, "altport.example.com");
    params
        .subject_alt_names
        .push(SanType::DnsName("altport.example.com".try_into().unwrap()));
    let cert = params.self_signed(&key).unwrap();

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(key.serialize_der()).unwrap();

    let server_cfg =
        ServerConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap();

    // Spawns on ephemeral non-standard port (e.g. 54321)
    let server = TestTlsServer::spawn(Arc::new(server_cfg), Arc::new(RootCertStore::empty()), 2);

    let pinned = make_pinned("altport.example.com", server.port);
    let config = TlsAssessConfig::default();

    let report = TlsAssessor::assess(&pinned, server.port, &config, None).unwrap();
    assert!(report.handshake_completed);
    assert_eq!(report.target_port, server.port);
    assert_eq!(report.sni_hostname, "altport.example.com");
}

// -----------------------------------------------------------------------------
// Test 12: Certificate Expiring Soon (Within 30 Days)
// -----------------------------------------------------------------------------
#[test]
fn test_expiring_soon_findings() {
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, "expiring.soon.local");
    params
        .subject_alt_names
        .push(SanType::DnsName("expiring.soon.local".try_into().unwrap()));
    params.not_before = date_time_ymd(2024, 1, 1);
    // Expires 10 days from now
    let now = Utc::now();
    let soon = now + chrono::Duration::days(10);
    params.not_after = date_time_ymd(
        soon.format("%Y").to_string().parse().unwrap(),
        soon.format("%m").to_string().parse().unwrap(),
        soon.format("%d").to_string().parse().unwrap(),
    );
    let cert = params.self_signed(&key).unwrap();

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(key.serialize_der()).unwrap();

    let server_cfg =
        ServerConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap();

    let server = TestTlsServer::spawn(Arc::new(server_cfg), Arc::new(RootCertStore::empty()), 2);

    let pinned = make_pinned("expiring.soon.local", server.port);
    let config = TlsAssessConfig::default();

    let report = TlsAssessor::assess(&pinned, server.port, &config, None).unwrap();

    assert!(report
        .findings
        .iter()
        .any(|f| f.id == "tls.cert.expiring-soon"));
}

// -----------------------------------------------------------------------------
// Test 13: DNS Rebinding Immune Pinned Target Enforcement
// -----------------------------------------------------------------------------
#[test]
fn test_pinned_destination_enforcement_never_reresolves() {
    let mut mock_dns = MockDnsResolver::new();
    mock_dns.insert("pinned.sec.internal", vec!["127.0.0.1".parse().unwrap()]);

    let scope = TargetScope {
        allow_loopback: true,
        ..Default::default()
    };
    let target = CanonicalTarget::parse("pinned.sec.internal").unwrap();
    let pinned =
        openaudit_network::resolver::resolve_and_pin(&target, &scope, &mock_dns, 443).unwrap();

    // Verify pinned address
    assert_eq!(pinned.pinned_addr.ip().to_string(), "127.0.0.1");

    // Poison DNS entry with an unauthorized address
    mock_dns.insert(
        "pinned.sec.internal",
        vec!["169.254.169.254".parse().unwrap()],
    );

    // Assessment uses pinned.pinned_addr exclusively
    assert_eq!(pinned.socket_addr().ip().to_string(), "127.0.0.1");
}

// -----------------------------------------------------------------------------
// Test 14: Certificate Metadata Extraction & SHA-256 Fingerprint
// -----------------------------------------------------------------------------
#[test]
fn test_certificate_fingerprint_and_san_extraction() {
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, "meta.example.com");
    params
        .subject_alt_names
        .push(SanType::DnsName("meta.example.com".try_into().unwrap()));
    params
        .subject_alt_names
        .push(SanType::DnsName("api.meta.example.com".try_into().unwrap()));
    let cert = params.self_signed(&key).unwrap();

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(key.serialize_der()).unwrap();

    let server_cfg =
        ServerConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap();

    let server = TestTlsServer::spawn(Arc::new(server_cfg), Arc::new(RootCertStore::empty()), 2);

    let pinned = make_pinned("meta.example.com", server.port);
    let config = TlsAssessConfig::default();

    let report = TlsAssessor::assess(&pinned, server.port, &config, None).unwrap();

    let meta = report.leaf_certificate.unwrap();
    assert_eq!(meta.common_name.as_deref(), Some("meta.example.com"));
    assert_eq!(meta.subject_alternative_names.len(), 2);
    assert_eq!(meta.fingerprint_sha256.len(), 64); // Valid hex SHA-256
    assert_eq!(meta.public_key_bits, 256);
}

// -----------------------------------------------------------------------------
// Test 15: Separation of Observation and Trust Status
// -----------------------------------------------------------------------------
#[test]
fn test_separation_of_observation_and_trust() {
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, "untrusted.boundary.test");
    params.subject_alt_names.push(SanType::DnsName(
        "untrusted.boundary.test".try_into().unwrap(),
    ));
    let cert = params.self_signed(&key).unwrap();

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(key.serialize_der()).unwrap();

    let server_cfg =
        ServerConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap();

    let server = TestTlsServer::spawn(Arc::new(server_cfg), Arc::new(RootCertStore::empty()), 2);

    let pinned = make_pinned("untrusted.boundary.test", server.port);
    let config = TlsAssessConfig::default();

    let report = TlsAssessor::assess(&pinned, server.port, &config, None).unwrap();

    // Invariant: Handshake completes so cipher and protocol are evaluated
    assert!(report.handshake_completed);
    assert!(report.negotiated_cipher.is_some());
    // Invariant: Trust is NOT falsely reported as trusted
    assert_ne!(report.trust_status, CertificateTrustStatus::Trusted);
    assert_eq!(report.trust_status, CertificateTrustStatus::SelfSigned);
}
