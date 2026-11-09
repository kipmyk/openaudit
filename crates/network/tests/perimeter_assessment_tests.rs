//! End-to-end integration tests for the unified perimeter assessment engine.

use openaudit_network::assessment::{PerimeterAssessConfig, PerimeterAssessor};
use openaudit_network::resolver::MockDnsResolver;
use openaudit_network::scanner::PortStatus;
use openaudit_network::scope::{IpCidr, TargetScope};
use openaudit_network::service::IdentifiedProtocol;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, SanType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

struct LocalTestServers {
    pub http_port: u16,
    pub https_port: u16,
    pub ssh_port: u16,
    pub closed_port: u16,
}

impl LocalTestServers {
    fn spawn() -> Self {
        // 1. HTTP Server
        let http_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let http_port = http_listener.local_addr().unwrap().port();
        thread::spawn(move || {
            for _ in 0..10 {
                if let Ok((mut stream, _)) = http_listener.accept() {
                    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
                    let mut buf = [0u8; 1024];
                    if let Ok(n) = stream.read(&mut buf) {
                        if n > 0 {
                            let resp = "HTTP/1.1 200 OK\r\n\
                                        Server: nginx/1.22.1\r\n\
                                        Content-Type: text/html\r\n\
                                        Connection: close\r\n\r\n\
                                        <html><body>Hello</body></html>";
                            let _ = stream.write_all(resp.as_bytes());
                            let _ = stream.flush();
                        }
                    }
                }
            }
        });

        // 2. HTTPS Server
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, "localhost");
        params
            .subject_alt_names
            .push(SanType::DnsName("localhost".try_into().unwrap()));
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

        let https_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let https_port = https_listener.local_addr().unwrap().port();
        let cfg = Arc::new(server_cfg);
        thread::spawn(move || {
            for _ in 0..10 {
                if let Ok((tcp_stream, _)) = https_listener.accept() {
                    let c = cfg.clone();
                    thread::spawn(move || {
                        if let Ok(conn) = rustls::ServerConnection::new(c) {
                            let mut tls_stream = rustls::StreamOwned::new(conn, tcp_stream);
                            let mut buf = [0u8; 1024];
                            if let Ok(n) = tls_stream.read(&mut buf) {
                                if n > 0 {
                                    let resp = "HTTP/1.1 200 OK\r\n\
                                                Strict-Transport-Security: max-age=31536000\r\n\
                                                Content-Security-Policy: default-src 'self'\r\n\
                                                X-Content-Type-Options: nosniff\r\n\
                                                Connection: close\r\n\r\n";
                                    let _ = tls_stream.write_all(resp.as_bytes());
                                    let _ = tls_stream.flush();
                                }
                            }
                        }
                    });
                }
            }
        });

        // 3. SSH Server (emits SSH banner passively)
        let ssh_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let ssh_port = ssh_listener.local_addr().unwrap().port();
        thread::spawn(move || {
            for _ in 0..10 {
                if let Ok((mut stream, _)) = ssh_listener.accept() {
                    let banner = "SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu3\r\n";
                    let _ = stream.write_all(banner.as_bytes());
                    let _ = stream.flush();
                }
            }
        });

        // 4. Closed Port (bind and immediately drop)
        let closed_port = {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };

        Self {
            http_port,
            https_port,
            ssh_port,
            closed_port,
        }
    }
}

#[test]
fn test_full_integrated_perimeter_workflow() {
    let servers = LocalTestServers::spawn();

    let mut mock_dns = MockDnsResolver::new();
    mock_dns.insert("perimeter.local", vec!["127.0.0.1".parse().unwrap()]);

    let scope = TargetScope {
        allow_loopback: true,
        ..Default::default()
    };

    let ports = vec![
        servers.http_port,
        servers.https_port,
        servers.ssh_port,
        servers.closed_port,
    ];

    let mut config = PerimeterAssessConfig::default();
    config.tcp_config.timeout = Duration::from_millis(500);
    config.service_config.probe_timeout = Duration::from_millis(500);
    config.tls_config.timeout = Duration::from_millis(1000);
    config.http_config.connect_timeout = Duration::from_millis(500);
    config.http_config.read_timeout = Duration::from_millis(500);

    let report =
        PerimeterAssessor::assess("perimeter.local", &ports, &scope, &mock_dns, &config, None)
            .expect("Must produce complete perimeter assessment report");

    assert_eq!(report.canonical_host, "perimeter.local");
    assert_eq!(report.pinned_ip, "127.0.0.1");
    assert_eq!(report.ports_scanned, 4);
    assert_eq!(report.open_ports_count, 3);

    // Verify endpoint discovery
    let http_ep = report
        .endpoints
        .iter()
        .find(|e| e.port == servers.http_port)
        .expect("HTTP endpoint must be present");
    assert_eq!(http_ep.status, PortStatus::Open);
    assert_eq!(http_ep.protocol, IdentifiedProtocol::Http);

    let https_ep = report
        .endpoints
        .iter()
        .find(|e| e.port == servers.https_port)
        .expect("HTTPS endpoint must be present");
    assert_eq!(https_ep.status, PortStatus::Open);

    let ssh_ep = report
        .endpoints
        .iter()
        .find(|e| e.port == servers.ssh_port)
        .expect("SSH endpoint must be present");
    assert_eq!(ssh_ep.status, PortStatus::Open);
    assert_eq!(ssh_ep.protocol, IdentifiedProtocol::Ssh);

    let closed_ep = report
        .endpoints
        .iter()
        .find(|e| e.port == servers.closed_port)
        .expect("Closed port must be present");
    assert_ne!(closed_ep.status, PortStatus::Open);

    // Verify TLS assessment ran
    assert!(report.tls_assessment.is_some());

    // Verify HTTP assessment ran
    assert!(report.http_assessment.is_some());

    // Verify unified findings collection
    assert!(!report.findings.is_empty());

    // Verify architectural disclaimer
    assert!(report
        .architecture_disclaimer
        .contains("Critical Architectural Distinction"));
}

#[test]
fn test_ssrf_prohibited_metadata_endpoint_fails_closed() {
    let mock_dns = MockDnsResolver::new();
    let scope = TargetScope {
        allow_loopback: true,
        ..Default::default()
    };
    let config = PerimeterAssessConfig::default();

    let res = PerimeterAssessor::assess(
        "169.254.169.254",
        &[80, 443],
        &scope,
        &mock_dns,
        &config,
        None,
    );

    assert!(res.is_err());
    let err_str = res.err().unwrap().to_string();
    assert!(err_str.contains("SSRF violation") || err_str.contains("prohibited"));
}

#[test]
fn test_unauthorized_private_cidr_rejected_fail_closed() {
    let mock_dns = MockDnsResolver::new();
    let scope = TargetScope {
        allow_public: true,
        authorized_cidrs: vec![IpCidr::parse("10.10.0.0/16").unwrap()],
        ..Default::default()
    };
    let config = PerimeterAssessConfig::default();

    // 10.20.1.1 is outside the authorized 10.10.0.0/16 CIDR
    let res = PerimeterAssessor::assess("10.20.1.1", &[80, 443], &scope, &mock_dns, &config, None);

    assert!(res.is_err());
    let err_str = res.err().unwrap().to_string();
    assert!(
        err_str.contains("outside explicitly authorized CIDR") || err_str.contains("prohibited")
    );
}

#[test]
fn test_cancellation_during_perimeter_assessment() {
    let cancel = Arc::new(AtomicBool::new(true)); // Pre-tripped
    let mock_dns = MockDnsResolver::new();
    let scope = TargetScope::default();
    let config = PerimeterAssessConfig::default();

    let res = PerimeterAssessor::assess(
        "example.com",
        &[80, 443],
        &scope,
        &mock_dns,
        &config,
        Some(cancel),
    );

    assert!(res.is_err());
}
