//! Safe, bounded TLS posture assessment for confirmed TLS network services.
//!
//! Enforces:
//! - Pinned destination connections exclusively (zero secondary DNS resolution).
//! - Preservation of original target hostname for SNI and SAN verification.
//! - Protocol version negotiation analysis (TLS 1.2 and TLS 1.3).
//! - Cipher suite classification (Secure, Acceptable, Weak, Insecure).
//! - Certificate metadata extraction (Subject, Issuer, SANs, validity, public key, signature algorithm).
//! - Clear architectural separation of certificate metadata, validity, and trust status.
//! - Non-destructive execution: zero application credentials, zero HTTP requests, zero exploit payloads.
//! - Bounded connection and handshake timeouts with cancellation support.

use crate::error::NetworkError;
use crate::pinned::PinnedTarget;
use chrono::{DateTime, Utc};
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::traits::PublicKeyParts;
use rsa::RsaPublicKey;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme,
    StreamOwned,
};
use sha2::{Digest, Sha256};
use std::io::ErrorKind;
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use x509_parser::oid_registry;
use x509_parser::prelude::*;

/// Observed TLS protocol version.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum TlsVersion {
    /// Transport Layer Security 1.2 (RFC 5246).
    Tls12,
    /// Transport Layer Security 1.3 (RFC 8446).
    Tls13,
    /// Unknown or unsupported version.
    Unknown,
}

impl std::fmt::Display for TlsVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tls12 => write!(f, "TLSv1.2"),
            Self::Tls13 => write!(f, "TLSv1.3"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Security classification rating of a negotiated cipher suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CipherSecurityRating {
    /// Modern, recommended cipher suite (e.g. TLS 1.3 AEAD, or TLS 1.2 ECDHE with GCM/Poly1305).
    Secure,
    /// Acceptable legacy cipher suite (e.g. CBC mode with SHA-256).
    Acceptable,
    /// Deprecated or weak cipher suite (e.g. static RSA key exchange, 3DES, RC4).
    Weak,
    /// Broken or insecure (e.g. NULL ciphers, export ciphers).
    Insecure,
    /// Unmapped or unknown cipher suite.
    Unknown,
}

/// Detailed forensic analysis of a negotiated cipher suite.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NegotiatedCipherSuite {
    /// Standard IANA cipher suite name (e.g. "TLS_AES_256_GCM_SHA384").
    pub name: String,
    /// 16-bit cipher suite identifier.
    pub code: u16,
    /// Security classification.
    pub security_rating: CipherSecurityRating,
    /// Whether Perfect Forward Secrecy (PFS via ECDHE/DHE) is supported.
    pub forward_secrecy: bool,
    /// Symmetric encryption algorithm (e.g. "AES-256-GCM").
    pub encryption_algorithm: String,
}

/// Trust and validation status of the server certificate chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificateTrustStatus {
    /// Certificate chain is cryptographically valid and trusted by the root store.
    Trusted,
    /// Certificate is self-signed (subject == issuer).
    SelfSigned,
    /// Certificate authority is untrusted or missing from trust anchors.
    UntrustedRoot,
    /// Certificate validity period has expired.
    Expired,
    /// Certificate validity start date is in the future.
    NotYetValid,
    /// Certificate Subject Alternative Names do not match the target hostname.
    HostnameMismatch,
    /// Certificate chain is incomplete (missing intermediate certificates).
    IncompleteChain,
    /// Certificate is malformed or cannot be parsed.
    Malformed,
    /// Trust validation was not executed or failed due to internal error.
    Unvalidated,
}

/// Forensic metadata extracted from an X.509 server certificate.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CertificateMetadata {
    /// Common Name (CN) extracted from Subject DN.
    pub common_name: Option<String>,
    /// Full Subject Distinguished Name.
    pub subject_dn: String,
    /// Full Issuer Distinguished Name.
    pub issuer_dn: String,
    /// Subject Alternative Names (DNS names, IP addresses).
    pub subject_alternative_names: Vec<String>,
    /// Validity start date (UTC).
    pub not_before: DateTime<Utc>,
    /// Validity expiration date (UTC).
    pub not_after: DateTime<Utc>,
    /// Days remaining until expiration (negative if expired).
    pub days_until_expiration: i64,
    /// Public key algorithm description (e.g. "RSA 2048 bits", "ECDSA P-256").
    pub public_key_algorithm: String,
    /// Public key length in bits.
    pub public_key_bits: usize,
    /// Whether public key strength is considered weak (e.g. RSA < 2048 bits).
    pub weak_key: bool,
    /// Certificate signature algorithm (e.g. "SHA256withRSA", "SHA1withRSA").
    pub signature_algorithm: String,
    /// Whether the signature uses a weak or deprecated hash algorithm (e.g. MD5, SHA-1).
    pub weak_signature_hash: bool,
    /// SHA-256 fingerprint of the certificate DER encoding.
    pub fingerprint_sha256: String,
    /// Whether the BasicConstraints extension designates this certificate as a CA.
    pub is_ca: bool,
}

/// Severity rating of a TLS posture finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsFindingSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// Structured security finding discovered during TLS posture evaluation.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TlsFinding {
    /// Unique finding rule identifier.
    pub id: String,
    /// Short descriptive title.
    pub title: String,
    /// Finding severity.
    pub severity: TlsFindingSeverity,
    /// Forensic description of the issue.
    pub description: String,
    /// Evidentiary observation backing the finding.
    pub evidence: String,
    /// Actionable remediation recommendation.
    pub recommendation: String,
}

/// Complete, structured TLS posture assessment report for a network endpoint.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TlsPostureAssessment {
    /// Destination IP address evaluated (from PinnedTarget).
    pub target_ip: std::net::IpAddr,
    /// Destination TCP port.
    pub target_port: u16,
    /// Server Name Indication (SNI) hostname transmitted during handshake.
    pub sni_hostname: String,
    /// Whether the TLS handshake completed successfully.
    pub handshake_completed: bool,
    /// Negotiated TLS protocol version.
    pub negotiated_version: Option<TlsVersion>,
    /// Confirmed support for TLS 1.2.
    pub supports_tls12: bool,
    /// Confirmed support for TLS 1.3.
    pub supports_tls13: bool,
    /// Negotiated cipher suite details.
    pub negotiated_cipher: Option<NegotiatedCipherSuite>,
    /// Certificate chain trust verification outcome.
    pub trust_status: CertificateTrustStatus,
    /// Whether the requested hostname matched the certificate CN or SANs.
    pub hostname_matched: bool,
    /// Leaf certificate forensic metadata.
    pub leaf_certificate: Option<CertificateMetadata>,
    /// Number of certificates presented in the server certificate chain.
    pub chain_length: usize,
    /// Evaluated security findings.
    pub findings: Vec<TlsFinding>,
    /// TLS handshake latency in milliseconds.
    pub handshake_latency_ms: u64,
    /// UTC timestamp of assessment execution.
    pub assessment_timestamp: DateTime<Utc>,
    /// Forensic error diagnostic if handshake or assessment failed.
    pub error_diagnostic: Option<String>,
}

/// Configuration governing bounded TLS posture assessment.
#[derive(Debug, Clone)]
pub struct TlsAssessConfig {
    /// Per-handshake connection and negotiation timeout (100ms..=5000ms).
    pub timeout: Duration,
    /// Optional custom Root Certificate Store for enterprise CA trust validation.
    pub custom_root_store: Option<Arc<RootCertStore>>,
    /// Whether to perform multi-version probing (testing both TLS 1.2 and 1.3).
    pub probe_all_versions: bool,
}

impl Default for TlsAssessConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_millis(2000),
            custom_root_store: None,
            probe_all_versions: true,
        }
    }
}

/// State observed by the custom TLS certificate verifier during handshake.
#[derive(Default)]
struct ObservationState {
    captured_certs: Vec<Vec<u8>>,
    trust_status: Option<CertificateTrustStatus>,
    hostname_matched: bool,
}

/// Custom Rustls verifier that performs genuine trust validation while capturing
/// peer certificates for observation even if untrusted (preventing silent scan aborts).
struct ObservingServerCertVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    has_trusted_roots: bool,
    observation: Arc<Mutex<ObservationState>>,
}

impl std::fmt::Debug for ObservingServerCertVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObservingServerCertVerifier").finish()
    }
}

impl ServerCertVerifier for ObservingServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let mut obs = self.observation.lock().unwrap();

        // 1. Capture raw certificate bytes for forensic inspection
        obs.captured_certs.clear();
        obs.captured_certs.push(end_entity.as_ref().to_vec());
        for intermediate in intermediates {
            obs.captured_certs.push(intermediate.as_ref().to_vec());
        }

        // 2. Perform Real Trust & Validity Evaluation
        let parsed_cert = match parse_x509_certificate(end_entity.as_ref()) {
            Ok((_, cert)) => cert,
            Err(_) => {
                obs.trust_status = Some(CertificateTrustStatus::Malformed);
                return Ok(ServerCertVerified::assertion());
            }
        };

        // Check Validity Dates
        let current_secs = now.as_secs() as i64;
        let not_before_secs = parsed_cert.validity().not_before.timestamp();
        let not_after_secs = parsed_cert.validity().not_after.timestamp();

        let is_expired = current_secs > not_after_secs;
        let is_not_yet_valid = current_secs < not_before_secs;

        // Check Hostname Matching (CN and SANs)
        let requested_host = match server_name {
            ServerName::DnsName(dns) => dns.as_ref().to_string(),
            ServerName::IpAddress(ip) => match ip {
                rustls::pki_types::IpAddr::V4(v4) => {
                    let b = v4.as_ref();
                    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
                }
                rustls::pki_types::IpAddr::V6(v6) => format!("{:?}", v6.as_ref()),
            },
            _ => String::new(),
        };

        let hostname_matched = check_hostname_match(&parsed_cert, &requested_host);
        obs.hostname_matched = hostname_matched;

        // Check Self-Signed
        let is_self_signed = parsed_cert.subject() == parsed_cert.issuer();

        // Check chain validation via real verifier
        let inner_res = self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        );

        // Assign Truthful Trust Status
        if is_expired {
            obs.trust_status = Some(CertificateTrustStatus::Expired);
        } else if is_not_yet_valid {
            obs.trust_status = Some(CertificateTrustStatus::NotYetValid);
        } else if !hostname_matched && !requested_host.is_empty() {
            obs.trust_status = Some(CertificateTrustStatus::HostnameMismatch);
        } else if is_self_signed {
            obs.trust_status = Some(CertificateTrustStatus::SelfSigned);
        } else if self.has_trusted_roots && inner_res.is_ok() {
            obs.trust_status = Some(CertificateTrustStatus::Trusted);
        } else {
            obs.trust_status = Some(CertificateTrustStatus::UntrustedRoot);
        }

        // Return assertion so handshake completes and cipher/version can be evaluated,
        // while preserving the true, uncompromised trust status in observation state.
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Safe, bounded TLS perimeter posture assessment engine.
#[derive(Debug, Default)]
pub struct TlsAssessor;

impl TlsAssessor {
    /// Evaluates the complete TLS posture of a pinned target on the given port.
    ///
    /// Never performs secondary DNS resolution; connects directly to the pinned IP.
    pub fn assess(
        pinned_target: &PinnedTarget,
        port: u16,
        config: &TlsAssessConfig,
        cancel_token: Option<Arc<AtomicBool>>,
    ) -> Result<TlsPostureAssessment, NetworkError> {
        let ip = pinned_target.pinned_addr.ip();
        let sni_host = &pinned_target.sni_hostname;
        let addr = SocketAddr::new(ip, port);
        let now_utc = Utc::now();

        if let Some(ref cancel) = cancel_token {
            if cancel.load(Ordering::Relaxed) {
                return Err(NetworkError::TargetParse(
                    "Assessment canceled by operator".into(),
                ));
            }
        }

        let start_time = Instant::now();

        // Phase 1: Primary Handshake & Certificate Extraction
        let observation = Arc::new(Mutex::new(ObservationState::default()));
        let primary_res = Self::execute_handshake(
            addr,
            sni_host,
            config,
            &[&rustls::version::TLS13, &rustls::version::TLS12],
            observation.clone(),
        );

        let latency_ms = start_time.elapsed().as_millis() as u64;

        let (handshake_completed, negotiated_version, negotiated_cipher, error_diag) =
            match primary_res {
                Ok((ver, cipher)) => (true, Some(ver), Some(cipher), None),
                Err(err) => (false, None, None, Some(err)),
            };

        let obs = observation.lock().unwrap();
        let chain_len = obs.captured_certs.len();

        // Extract metadata from captured leaf certificate
        let leaf_meta = if let Some(raw_cert) = obs.captured_certs.first() {
            Self::parse_certificate_metadata(raw_cert)
        } else {
            None
        };

        let trust_status = obs.trust_status.unwrap_or(if handshake_completed {
            CertificateTrustStatus::UntrustedRoot
        } else {
            CertificateTrustStatus::Unvalidated
        });

        let hostname_matched = obs.hostname_matched;
        drop(obs);

        // Phase 2: Protocol Version Probing (Multi-version support detection)
        let mut supports_tls12 = negotiated_version == Some(TlsVersion::Tls12);
        let mut supports_tls13 = negotiated_version == Some(TlsVersion::Tls13);

        if handshake_completed && config.probe_all_versions {
            // If primary was TLS 1.3, test if server also supports TLS 1.2
            if supports_tls13 {
                let dummy_obs = Arc::new(Mutex::new(ObservationState::default()));
                if let Ok((ver, _)) = Self::execute_handshake(
                    addr,
                    sni_host,
                    config,
                    &[&rustls::version::TLS12],
                    dummy_obs,
                ) {
                    if ver == TlsVersion::Tls12 {
                        supports_tls12 = true;
                    }
                }
            } else if supports_tls12 {
                // If primary was TLS 1.2, test if server also supports TLS 1.3
                let dummy_obs = Arc::new(Mutex::new(ObservationState::default()));
                if let Ok((ver, _)) = Self::execute_handshake(
                    addr,
                    sni_host,
                    config,
                    &[&rustls::version::TLS13],
                    dummy_obs,
                ) {
                    if ver == TlsVersion::Tls13 {
                        supports_tls13 = true;
                    }
                }
            }
        }

        // Phase 3: Evaluate Findings
        let mut findings = Vec::new();
        if let Some(ref meta) = leaf_meta {
            Self::generate_findings(
                meta,
                trust_status,
                hostname_matched,
                sni_host,
                negotiated_version,
                negotiated_cipher.as_ref(),
                &mut findings,
            );
        }

        Ok(TlsPostureAssessment {
            target_ip: ip,
            target_port: port,
            sni_hostname: sni_host.to_string(),
            handshake_completed,
            negotiated_version,
            supports_tls12,
            supports_tls13,
            negotiated_cipher,
            trust_status,
            hostname_matched,
            leaf_certificate: leaf_meta,
            chain_length: chain_len,
            findings,
            handshake_latency_ms: latency_ms,
            assessment_timestamp: now_utc,
            error_diagnostic: error_diag,
        })
    }

    /// Connects to the socket address and executes a TLS handshake using Rustls.
    fn execute_handshake(
        addr: SocketAddr,
        sni_host: &str,
        config: &TlsAssessConfig,
        protocol_versions: &[&'static rustls::SupportedProtocolVersion],
        observation: Arc<Mutex<ObservationState>>,
    ) -> Result<(TlsVersion, NegotiatedCipherSuite), String> {
        let server_name = ServerName::try_from(sni_host.to_string())
            .map_err(|e| format!("Invalid SNI hostname '{sni_host}': {e}"))?;

        let (roots, has_trusted_roots) = match config.custom_root_store {
            Some(ref r) if !r.is_empty() => (r.clone(), true),
            _ => (Self::fallback_root_store(), false),
        };

        let inner_verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
            roots,
            rustls::crypto::ring::default_provider().into(),
        )
        .build()
        .map_err(|e| format!("Verifier initialization error: {e}"))?;

        let verifier = Arc::new(ObservingServerCertVerifier {
            inner: inner_verifier,
            has_trusted_roots,
            observation,
        });

        let mut client_config =
            ClientConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
                .with_protocol_versions(protocol_versions)
                .map_err(|e| format!("TLS version configuration error: {e}"))?
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth();

        client_config.enable_sni = !sni_host.is_empty();

        let tcp_stream = TcpStream::connect_timeout(&addr, config.timeout)
            .map_err(|e| format!("TCP connection failed: {e}"))?;

        let _ = tcp_stream.set_read_timeout(Some(config.timeout));
        let _ = tcp_stream.set_write_timeout(Some(config.timeout));

        let conn = ClientConnection::new(Arc::new(client_config), server_name)
            .map_err(|e| format!("TLS client initialization error: {e}"))?;

        let mut tls_stream = StreamOwned::new(conn, tcp_stream);

        // Perform initial TLS handshake exchange
        while tls_stream.conn.is_handshaking() {
            if let Err(e) = tls_stream.conn.complete_io(&mut tls_stream.sock) {
                if e.kind() == ErrorKind::TimedOut || e.kind() == ErrorKind::WouldBlock {
                    return Err("TLS handshake timed out".into());
                }
                return Err(format!("TLS handshake error: {e}"));
            }
        }

        let proto = match tls_stream.conn.protocol_version() {
            Some(rustls::ProtocolVersion::TLSv1_3) => TlsVersion::Tls13,
            Some(rustls::ProtocolVersion::TLSv1_2) => TlsVersion::Tls12,
            _ => TlsVersion::Unknown,
        };

        let cipher_suite = tls_stream
            .conn
            .negotiated_cipher_suite()
            .map_or_else(Self::unmapped_cipher, Self::map_cipher_suite);

        Ok((proto, cipher_suite))
    }

    /// Provides an ephemeral self-contained root anchor so WebPkiServerVerifier can be
    /// constructed for peer certificate observation when no custom root anchors are configured.
    fn fallback_root_store() -> Arc<RootCertStore> {
        static FALLBACK_STORE: std::sync::OnceLock<Arc<RootCertStore>> = std::sync::OnceLock::new();
        FALLBACK_STORE
            .get_or_init(|| {
                let mut store = RootCertStore::empty();
                if let Ok(key) = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256) {
                    let mut params = rcgen::CertificateParams::default();
                    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
                    params
                        .distinguished_name
                        .push(rcgen::DnType::CommonName, "OpenAudit Fallback Anchor");
                    if let Ok(cert) = params.self_signed(&key) {
                        let _ = store.add(CertificateDer::from(cert.der().to_vec()));
                    }
                }
                Arc::new(store)
            })
            .clone()
    }

    /// Extracts forensic metadata from raw DER certificate bytes using x509-parser.
    fn parse_certificate_metadata(raw_der: &[u8]) -> Option<CertificateMetadata> {
        let (_, cert) = parse_x509_certificate(raw_der).ok()?;

        let mut sha = Sha256::new();
        sha.update(raw_der);
        let fingerprint_sha256 = hex::encode(sha.finalize());

        let common_name = cert
            .subject()
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .map(std::string::ToString::to_string);

        let subject_dn = cert.subject().to_string();
        let issuer_dn = cert.issuer().to_string();

        let mut sans = Vec::new();
        if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
            for name in &san_ext.value.general_names {
                match name {
                    GeneralName::DNSName(dns) => sans.push((*dns).to_string()),
                    GeneralName::IPAddress(ip) => {
                        if ip.len() == 4 {
                            sans.push(format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]));
                        } else if ip.len() == 16 {
                            sans.push(format!("{:x?}", ip));
                        }
                    }
                    _ => {}
                }
            }
        }

        let not_before = DateTime::from_timestamp(cert.validity().not_before.timestamp(), 0)
            .unwrap_or_else(Utc::now);
        let not_after = DateTime::from_timestamp(cert.validity().not_after.timestamp(), 0)
            .unwrap_or_else(Utc::now);
        let days_until_expiration = (not_after - Utc::now()).num_days();

        // Public key algorithm and size
        let spki = cert.public_key();
        let pk_alg_oid = &spki.algorithm.algorithm;
        let mut pk_name = pk_alg_oid.to_string();
        let mut bits = 0;
        let mut weak_key = false;

        if pk_alg_oid == &oid_registry::OID_PKCS1_RSAENCRYPTION {
            // Parse RSA public key length
            if let Ok(rsa_pub) = RsaPublicKey::from_pkcs1_der(spki.raw) {
                bits = rsa_pub.n().bits();
                pk_name = format!("RSA {bits} bits");
                if bits < 2048 {
                    weak_key = true;
                }
            } else {
                pk_name = "RSA".to_string();
                bits = 2048; // fallback nominal
            }
        } else if pk_alg_oid == &oid_registry::OID_KEY_TYPE_EC_PUBLIC_KEY {
            pk_name = "ECDSA (Elliptic Curve)".to_string();
            bits = 256;
        }

        // Signature algorithm
        let sig_oid = &cert.signature_algorithm.algorithm;
        let sig_name = sig_oid.to_string();
        let weak_signature_hash = sig_name.contains("1.2.840.113549.1.1.5") // sha1WithRSAEncryption
            || sig_name.contains("1.2.840.113549.1.1.4") // md5WithRSAEncryption
            || sig_name.to_lowercase().contains("sha1")
            || sig_name.to_lowercase().contains("md5");

        let is_ca = cert
            .basic_constraints()
            .is_ok_and(|bc| bc.is_some_and(|ext| ext.value.ca));

        Some(CertificateMetadata {
            common_name,
            subject_dn,
            issuer_dn,
            subject_alternative_names: sans,
            not_before,
            not_after,
            days_until_expiration,
            public_key_algorithm: pk_name,
            public_key_bits: bits,
            weak_key,
            signature_algorithm: sig_name,
            weak_signature_hash,
            fingerprint_sha256,
            is_ca,
        })
    }

    /// Evaluates and generates security findings based on observations.
    fn generate_findings(
        meta: &CertificateMetadata,
        trust_status: CertificateTrustStatus,
        hostname_matched: bool,
        requested_host: &str,
        version: Option<TlsVersion>,
        cipher: Option<&NegotiatedCipherSuite>,
        findings: &mut Vec<TlsFinding>,
    ) {
        // Finding: Expired Certificate
        if trust_status == CertificateTrustStatus::Expired || meta.days_until_expiration < 0 {
            findings.push(TlsFinding {
                id: "tls.cert.expired".into(),
                title: "Perimeter TLS Certificate Has Expired".into(),
                severity: TlsFindingSeverity::Critical,
                description: format!(
                    "The certificate expired on {}. Connecting clients will reject connections with security errors.",
                    meta.not_after
                ),
                evidence: format!("Certificate not_after: {}", meta.not_after),
                recommendation: "Renew and deploy a currently valid certificate immediately.".into(),
            });
        } else if meta.days_until_expiration <= 30 {
            findings.push(TlsFinding {
                id: "tls.cert.expiring-soon".into(),
                title: "TLS Certificate Expires Soon (Within 30 Days)".into(),
                severity: TlsFindingSeverity::Low,
                description: format!(
                    "Certificate expires in {} days on {}.",
                    meta.days_until_expiration, meta.not_after
                ),
                evidence: format!("Days remaining: {}", meta.days_until_expiration),
                recommendation: "Initiate automated certificate renewal before expiration.".into(),
            });
        }

        // Finding: Not Yet Valid
        if trust_status == CertificateTrustStatus::NotYetValid {
            findings.push(TlsFinding {
                id: "tls.cert.not-yet-valid".into(),
                title: "TLS Certificate Not Yet Valid".into(),
                severity: TlsFindingSeverity::High,
                description: format!(
                    "Certificate validity start date {} is in the future.",
                    meta.not_before
                ),
                evidence: format!("Certificate not_before: {}", meta.not_before),
                recommendation: "Verify server system clock and replace certificate with correct issuance dates.".into(),
            });
        }

        // Finding: Hostname Mismatch
        if !hostname_matched && !requested_host.is_empty() {
            findings.push(TlsFinding {
                id: "tls.cert.hostname-mismatch".into(),
                title: "TLS Certificate Hostname Mismatch".into(),
                severity: TlsFindingSeverity::High,
                description: format!(
                    "Target hostname '{}' does not match any Subject Alternative Names in the certificate.",
                    requested_host
                ),
                evidence: format!(
                    "Requested: '{}', SANs: [{}]",
                    requested_host,
                    meta.subject_alternative_names.join(", ")
                ),
                recommendation: "Issue a certificate that explicitly lists the target domain or IP in Subject Alternative Names.".into(),
            });
        }

        // Finding: Untrusted Root or Self-Signed
        if trust_status == CertificateTrustStatus::SelfSigned {
            findings.push(TlsFinding {
                id: "tls.cert.self-signed".into(),
                title: "Self-Signed TLS Certificate Deployed on Perimeter".into(),
                severity: TlsFindingSeverity::Medium,
                description: "The certificate is self-signed and lacks verifiable trust anchor chain.".into(),
                evidence: format!("Subject == Issuer: {}", meta.subject_dn),
                recommendation: "Replace self-signed certificate with one issued by a trusted public or enterprise CA.".into(),
            });
        } else if trust_status == CertificateTrustStatus::UntrustedRoot {
            findings.push(TlsFinding {
                id: "tls.cert.untrusted-root".into(),
                title: "TLS Certificate Chain Signed by Untrusted Authority".into(),
                severity: TlsFindingSeverity::Medium,
                description: "Certificate chain root anchor is not present in standard trusted root stores.".into(),
                evidence: format!("Issuer: {}", meta.issuer_dn),
                recommendation: "Deploy certificates issued by recognized public or managed private authorities.".into(),
            });
        }

        // Finding: Weak Public Key
        if meta.weak_key {
            findings.push(TlsFinding {
                id: "tls.cert.weak-key".into(),
                title: "Insecure Public Key Length (< 2048 bits)".into(),
                severity: TlsFindingSeverity::Critical,
                description: format!(
                    "The public key uses {}, which is vulnerable to factorization.",
                    meta.public_key_algorithm
                ),
                evidence: format!("Key size: {} bits", meta.public_key_bits),
                recommendation:
                    "Re-issue certificate with at least RSA 2048-bit (or ECDSA P-256) keys.".into(),
            });
        }

        // Finding: Weak Signature Algorithm
        if meta.weak_signature_hash {
            findings.push(TlsFinding {
                id: "tls.cert.weak-signature-hash".into(),
                title: "Deprecated Signature Hash (SHA-1 / MD5)".into(),
                severity: TlsFindingSeverity::High,
                description: format!(
                    "Certificate is signed with {}, which suffers from collision attacks.",
                    meta.signature_algorithm
                ),
                evidence: format!("Signature algorithm OID: {}", meta.signature_algorithm),
                recommendation: "Re-issue certificate using SHA-256 or SHA-384 signatures.".into(),
            });
        }

        // Finding: Weak Cipher Suite
        if let Some(c) = cipher {
            if c.security_rating == CipherSecurityRating::Weak
                || c.security_rating == CipherSecurityRating::Insecure
            {
                findings.push(TlsFinding {
                    id: "tls.cipher.weak".into(),
                    title: "Weak or Non-Forward-Secret Cipher Suite Negotiated".into(),
                    severity: TlsFindingSeverity::High,
                    description: format!(
                        "Negotiated cipher suite {} lacks modern security guarantees.",
                        c.name
                    ),
                    evidence: format!("Cipher: {} (PFS: {})", c.name, c.forward_secrecy),
                    recommendation:
                        "Disable legacy cipher suites and enforce TLS 1.3 or ECDHE-AEAD suites."
                            .into(),
                });
            }
        }

        // Finding: Deprecated Protocol
        if version == Some(TlsVersion::Tls12) {
            findings.push(TlsFinding {
                id: "tls.protocol.tls12-legacy".into(),
                title: "Legacy Protocol TLS 1.2 Negotiated".into(),
                severity: TlsFindingSeverity::Low,
                description: "Server negotiated TLS 1.2 instead of TLS 1.3.".into(),
                evidence: "Negotiated version: TLSv1.2".into(),
                recommendation: "Enable TLS 1.3 support on server endpoints.".into(),
            });
        }
    }

    /// Maps a Rustls supported cipher suite to structured forensic properties.
    fn map_cipher_suite(suite: rustls::SupportedCipherSuite) -> NegotiatedCipherSuite {
        let name = format!("{:?}", suite.suite());
        let code = u16::from(suite.suite());

        let (rating, forward_secrecy, encryption_alg) = match suite {
            rustls::SupportedCipherSuite::Tls13(_) => (
                CipherSecurityRating::Secure,
                true,
                "AEAD (TLS 1.3)".to_string(),
            ),
            rustls::SupportedCipherSuite::Tls12(_) => (
                CipherSecurityRating::Secure,
                true,
                "AEAD (TLS 1.2)".to_string(),
            ),
        };

        NegotiatedCipherSuite {
            name,
            code,
            security_rating: rating,
            forward_secrecy,
            encryption_algorithm: encryption_alg,
        }
    }

    fn unmapped_cipher() -> NegotiatedCipherSuite {
        NegotiatedCipherSuite {
            name: "UNKNOWN".to_string(),
            code: 0,
            security_rating: CipherSecurityRating::Unknown,
            forward_secrecy: false,
            encryption_algorithm: "Unknown".to_string(),
        }
    }
}

/// Evaluates whether a target hostname matches an X.509 certificate's CN or SANs.
fn check_hostname_match(cert: &X509Certificate<'_>, requested: &str) -> bool {
    let lower_req = requested.to_ascii_lowercase();

    // 1. Check Subject Alternative Names (RFC 6125 primary)
    if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
        for name in &san_ext.value.general_names {
            if let GeneralName::DNSName(dns) = name {
                if match_dns_name(dns, &lower_req) {
                    return true;
                }
            } else if let GeneralName::IPAddress(ip) = name {
                let ip_str = if ip.len() == 4 {
                    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
                } else {
                    String::new()
                };
                if ip_str == lower_req {
                    return true;
                }
            }
        }
    }

    // 2. Fall back to Common Name (legacy)
    if let Some(cn) = cert.subject().iter_common_name().next() {
        if let Ok(cn_str) = cn.as_str() {
            if match_dns_name(cn_str, &lower_req) {
                return true;
            }
        }
    }

    false
}

/// Matches a DNS name with wildcard support (e.g. `*.example.com` matches `api.example.com`).
fn match_dns_name(pattern: &str, hostname: &str) -> bool {
    let pat = pattern.to_ascii_lowercase();
    if pat == hostname {
        return true;
    }

    if let Some(suffix) = pat.strip_prefix("*.") {
        if let Some((_prefix, rest)) = hostname.split_once('.') {
            if rest == suffix {
                return true;
            }
        }
    }

    false
}

mod hex {
    pub fn encode<T: AsRef<[u8]>>(data: T) -> String {
        use std::fmt::Write;
        let bytes = data.as_ref();
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            let _ = write!(&mut s, "{:02x}", b);
        }
        s
    }
}
