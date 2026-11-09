//! Deterministic integration tests for HTTP security posture assessment.
//!
//! Verifies:
//! - Plaintext HTTP and TLS-encrypted HTTPS assessment.
//! - HTTP-to-HTTPS redirect validation.
//! - Missing security header detection (HSTS, CSP, XCTO, XFO, Referrer-Policy, Permissions-Policy).
//! - Cookie security flag evaluation (Secure, HttpOnly, SameSite).
//! - Server and framework version disclosure findings.
//! - SSRF and redirect boundary enforcement (rejecting metadata and unauthorized private CIDRs).
//! - Redirect loop and hop limit handling.
//! - Host header preservation and zero secondary DNS re-resolution.
//! - Cooperative cancellation and bounded memory limits.

use openaudit_network::http::{HttpAssessConfig, HttpFindingSeverity, HttpPostureAssessor};
use openaudit_network::pinned::PinnedTarget;
use openaudit_network::resolver::MockDnsResolver;
use openaudit_network::scope::TargetScope;
use openaudit_network::target::CanonicalTarget;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, SanType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// Lightweight local test HTTP server.
struct TestHttpServer {
    pub port: u16,
    _handle: thread::JoinHandle<()>,
}

impl TestHttpServer {
    fn spawn<F>(handler: F, max_requests: usize) -> Self
    where
        F: Fn(&str) -> String + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").expect("Must bind HTTP test listener");
        let port = listener.local_addr().unwrap().port();
        let handler = Arc::new(handler);

        let handle = thread::spawn(move || {
            for _ in 0..max_requests {
                if let Ok((mut stream, _)) = listener.accept() {
                    let h = handler.clone();
                    thread::spawn(move || {
                        let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
                        let mut buf = [0u8; 4096];
                        if let Ok(n) = stream.read(&mut buf) {
                            if n > 0 {
                                let req = String::from_utf8_lossy(&buf[..n]);
                                let resp = h(&req);
                                let _ = stream.write_all(resp.as_bytes());
                                let _ = stream.flush();
                            }
                        }
                    });
                }
            }
        });

        Self {
            port,
            _handle: handle,
        }
    }
}

/// Lightweight local test HTTPS server.
struct TestHttpsServer {
    pub port: u16,
    _handle: thread::JoinHandle<()>,
}

impl TestHttpsServer {
    fn spawn<F>(handler: F, max_requests: usize) -> Self
    where
        F: Fn(&str) -> String + Send + Sync + 'static,
    {
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

        let listener = TcpListener::bind("127.0.0.1:0").expect("Must bind HTTPS test listener");
        let port = listener.local_addr().unwrap().port();
        let cfg = Arc::new(server_cfg);
        let handler = Arc::new(handler);

        let handle = thread::spawn(move || {
            for _ in 0..max_requests {
                if let Ok((tcp_stream, _)) = listener.accept() {
                    let c = cfg.clone();
                    let h = handler.clone();
                    thread::spawn(move || {
                        if let Ok(conn) = rustls::ServerConnection::new(c) {
                            let mut tls_stream = rustls::StreamOwned::new(conn, tcp_stream);
                            let mut buf = [0u8; 4096];
                            if let Ok(n) = tls_stream.read(&mut buf) {
                                if n > 0 {
                                    let req = String::from_utf8_lossy(&buf[..n]);
                                    let resp = h(&req);
                                    let _ = tls_stream.write_all(resp.as_bytes());
                                    let _ = tls_stream.flush();
                                }
                            }
                        }
                    });
                }
            }
        });

        Self {
            port,
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
// Test 1: Full Security Headers Baseline
// -----------------------------------------------------------------------------
#[test]
fn test_http_endpoint_assessment_basic_headers() {
    let server = TestHttpServer::spawn(
        |_req| {
            "HTTP/1.1 200 OK\r\n\
             Content-Type: text/html\r\n\
             Content-Security-Policy: default-src 'self'\r\n\
             X-Content-Type-Options: nosniff\r\n\
             X-Frame-Options: DENY\r\n\
             Referrer-Policy: strict-origin-when-cross-origin\r\n\
             Permissions-Policy: geolocation=()\r\n\
             Connection: close\r\n\r\n\
             <html><body>OK</body></html>"
                .to_string()
        },
        3,
    );

    let pinned = make_pinned("test.local", server.port);
    let scope = TargetScope {
        allow_loopback: true,
        ..Default::default()
    };
    let mock_dns = MockDnsResolver::new();
    let config = HttpAssessConfig {
        probe_https: false,
        ..Default::default()
    };

    let report =
        HttpPostureAssessor::assess(&pinned, server.port, None, &scope, &mock_dns, &config, None)
            .expect("Must assess HTTP");

    assert!(report.csp_present);
    assert!(report.x_content_type_options_nosniff);
    assert_eq!(report.x_frame_options.as_deref(), Some("DENY"));
    assert_eq!(
        report.referrer_policy.as_deref(),
        Some("strict-origin-when-cross-origin")
    );
    assert_eq!(report.permissions_policy.as_deref(), Some("geolocation=()"));
    assert!(!report.server_version_disclosed);
}

// -----------------------------------------------------------------------------
// Test 2: HTTPS Endpoint with HSTS and CSP
// -----------------------------------------------------------------------------
#[test]
fn test_https_endpoint_assessment_hsts_and_csp() {
    let server = TestHttpsServer::spawn(
        |_req| {
            "HTTP/1.1 200 OK\r\n\
             Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\r\n\
             Content-Security-Policy: default-src 'self'\r\n\
             X-Content-Type-Options: nosniff\r\n\
             Connection: close\r\n\r\n"
                .to_string()
        },
        3,
    );

    let pinned = make_pinned("localhost", 80);
    let scope = TargetScope {
        allow_loopback: true,
        ..Default::default()
    };
    let mock_dns = MockDnsResolver::new();
    let config = HttpAssessConfig {
        probe_https: true,
        ..Default::default()
    };

    let report = HttpPostureAssessor::assess(
        &pinned,
        80, // Non-existent HTTP port will fail gracefully
        Some(server.port),
        &scope,
        &mock_dns,
        &config,
        None,
    )
    .expect("Must assess HTTPS");

    assert!(report.https_available);
    assert!(report.hsts_enabled);
    assert!(report.hsts_include_subdomains);
    assert!(report.hsts_preload);
    assert!(report.csp_present);
}

// -----------------------------------------------------------------------------
// Test 3: HTTP-to-HTTPS Redirect
// -----------------------------------------------------------------------------
#[test]
fn test_http_to_https_redirect_enforced() {
    let https_server = TestHttpsServer::spawn(
        |_req| {
            "HTTP/1.1 200 OK\r\n\
             Strict-Transport-Security: max-age=31536000\r\n\
             Connection: close\r\n\r\n"
                .to_string()
        },
        3,
    );

    let https_port = https_server.port;
    let http_server = TestHttpServer::spawn(
        move |_req| {
            format!(
                "HTTP/1.1 301 Moved Permanently\r\n\
                 Location: https://localhost:{https_port}/\r\n\
                 Connection: close\r\n\r\n"
            )
        },
        3,
    );

    let pinned = make_pinned("localhost", http_server.port);
    let scope = TargetScope {
        allow_loopback: true,
        ..Default::default()
    };
    let mock_dns = MockDnsResolver::new();
    let config = HttpAssessConfig {
        probe_https: false, // Redirect following will test HTTPS
        ..Default::default()
    };

    let report = HttpPostureAssessor::assess(
        &pinned,
        http_server.port,
        None,
        &scope,
        &mock_dns,
        &config,
        None,
    )
    .expect("Must follow redirect");

    assert!(report.http_to_https_redirect);
    assert!(report.final_url.starts_with("https://"));
}

// -----------------------------------------------------------------------------
// Test 4: Missing Security Headers Trigger Specific Findings
// -----------------------------------------------------------------------------
#[test]
fn test_missing_security_headers_produce_findings() {
    let server = TestHttpServer::spawn(
        |_req| {
            "HTTP/1.1 200 OK\r\n\
             Content-Type: text/plain\r\n\
             Connection: close\r\n\r\n\
             Hello World"
                .to_string()
        },
        2,
    );

    let pinned = make_pinned("insecure.local", server.port);
    let scope = TargetScope {
        allow_loopback: true,
        ..Default::default()
    };
    let mock_dns = MockDnsResolver::new();
    let config = HttpAssessConfig {
        probe_https: false,
        ..Default::default()
    };

    let report =
        HttpPostureAssessor::assess(&pinned, server.port, None, &scope, &mock_dns, &config, None)
            .unwrap();

    let finding_ids: Vec<&str> = report.findings.iter().map(|f| f.id.as_str()).collect();
    assert!(finding_ids.contains(&"http.headers.missing-csp"));
    assert!(finding_ids.contains(&"http.headers.missing-x-content-type-options"));
    assert!(finding_ids.contains(&"http.headers.missing-x-frame-options"));
    assert!(finding_ids.contains(&"http.headers.missing-referrer-policy"));
    assert!(finding_ids.contains(&"http.headers.missing-permissions-policy"));
}

// -----------------------------------------------------------------------------
// Test 5: HSTS Short Duration & Missing subDomains
// -----------------------------------------------------------------------------
#[test]
fn test_hsts_short_duration_and_missing_subdomains() {
    let server = TestHttpsServer::spawn(
        |_req| {
            "HTTP/1.1 200 OK\r\n\
             Strict-Transport-Security: max-age=86400\r\n\
             Connection: close\r\n\r\n"
                .to_string()
        },
        2,
    );

    let pinned = make_pinned("localhost", 80);
    let scope = TargetScope {
        allow_loopback: true,
        ..Default::default()
    };
    let mock_dns = MockDnsResolver::new();
    let config = HttpAssessConfig::default();

    let report = HttpPostureAssessor::assess(
        &pinned,
        80,
        Some(server.port),
        &scope,
        &mock_dns,
        &config,
        None,
    )
    .unwrap();

    let finding_ids: Vec<&str> = report.findings.iter().map(|f| f.id.as_str()).collect();
    assert!(finding_ids.contains(&"http.headers.hsts-short-duration"));
    assert!(finding_ids.contains(&"http.headers.hsts-missing-subdomains"));
}

// -----------------------------------------------------------------------------
// Test 6: CSP Unsafe Directives Finding
// -----------------------------------------------------------------------------
#[test]
fn test_csp_unsafe_inline_and_eval_findings() {
    let server = TestHttpServer::spawn(
        |_req| {
            "HTTP/1.1 200 OK\r\n\
             Content-Security-Policy: default-src 'self' 'unsafe-inline' 'unsafe-eval'\r\n\
             Connection: close\r\n\r\n"
                .to_string()
        },
        2,
    );

    let pinned = make_pinned("unsafe.csp.local", server.port);
    let scope = TargetScope {
        allow_loopback: true,
        ..Default::default()
    };
    let mock_dns = MockDnsResolver::new();
    let config = HttpAssessConfig {
        probe_https: false,
        ..Default::default()
    };

    let report =
        HttpPostureAssessor::assess(&pinned, server.port, None, &scope, &mock_dns, &config, None)
            .unwrap();

    let finding_ids: Vec<&str> = report.findings.iter().map(|f| f.id.as_str()).collect();
    assert!(finding_ids.contains(&"http.headers.csp-unsafe"));
}

// -----------------------------------------------------------------------------
// Test 7: Server and Framework Version Disclosure
// -----------------------------------------------------------------------------
#[test]
fn test_server_and_framework_version_disclosure() {
    let server = TestHttpServer::spawn(
        |_req| {
            "HTTP/1.1 200 OK\r\n\
             Server: Apache/2.4.52 (Ubuntu)\r\n\
             X-Powered-By: PHP/8.1.2\r\n\
             Connection: close\r\n\r\n"
                .to_string()
        },
        2,
    );

    let pinned = make_pinned("version.disclosure.local", server.port);
    let scope = TargetScope {
        allow_loopback: true,
        ..Default::default()
    };
    let mock_dns = MockDnsResolver::new();
    let config = HttpAssessConfig {
        probe_https: false,
        ..Default::default()
    };

    let report =
        HttpPostureAssessor::assess(&pinned, server.port, None, &scope, &mock_dns, &config, None)
            .unwrap();

    assert!(report.server_version_disclosed);
    assert_eq!(
        report.server_header.as_deref(),
        Some("Apache/2.4.52 (Ubuntu)")
    );

    let finding_ids: Vec<&str> = report.findings.iter().map(|f| f.id.as_str()).collect();
    assert!(finding_ids.contains(&"http.server.version-disclosed"));
    assert!(finding_ids.contains(&"http.framework.version-disclosed"));
}

// -----------------------------------------------------------------------------
// Test 8: Cookie Security Attributes Inspection
// -----------------------------------------------------------------------------
#[test]
fn test_cookie_security_attributes_inspection() {
    let server = TestHttpsServer::spawn(
        |_req| {
            "HTTP/1.1 200 OK\r\n\
             Set-Cookie: session_id=abc123456; Path=/\r\n\
             Set-Cookie: tracking=active; Secure; HttpOnly; SameSite=Strict\r\n\
             Connection: close\r\n\r\n"
                .to_string()
        },
        2,
    );

    let pinned = make_pinned("localhost", 80);
    let scope = TargetScope {
        allow_loopback: true,
        ..Default::default()
    };
    let mock_dns = MockDnsResolver::new();
    let config = HttpAssessConfig::default();

    let report = HttpPostureAssessor::assess(
        &pinned,
        80,
        Some(server.port),
        &scope,
        &mock_dns,
        &config,
        None,
    )
    .unwrap();

    assert_eq!(report.observed_cookies.len(), 2);

    let finding_ids: Vec<&str> = report.findings.iter().map(|f| f.id.as_str()).collect();
    assert!(finding_ids.contains(&"http.cookie.missing-secure"));
    assert!(finding_ids.contains(&"http.cookie.missing-httponly"));
    assert!(finding_ids.contains(&"http.cookie.missing-samesite"));
}

// -----------------------------------------------------------------------------
// Test 9: Redirect Loop Detected
// -----------------------------------------------------------------------------
#[test]
fn test_redirect_loop_detected() {
    let server = TestHttpServer::spawn(
        |req| {
            if req.contains("GET /loop2") || req.contains("HEAD /loop2") {
                "HTTP/1.1 302 Found\r\nLocation: /loop1\r\nConnection: close\r\n\r\n".to_string()
            } else {
                "HTTP/1.1 302 Found\r\nLocation: /loop2\r\nConnection: close\r\n\r\n".to_string()
            }
        },
        5,
    );

    let pinned = make_pinned("loop.local", server.port);
    let scope = TargetScope {
        allow_loopback: true,
        ..Default::default()
    };
    let mock_dns = MockDnsResolver::new();
    let config = HttpAssessConfig {
        probe_https: false,
        max_redirects: 5,
        ..Default::default()
    };

    let report =
        HttpPostureAssessor::assess(&pinned, server.port, None, &scope, &mock_dns, &config, None)
            .unwrap();

    let finding_ids: Vec<&str> = report.findings.iter().map(|f| f.id.as_str()).collect();
    assert!(finding_ids.contains(&"http.redirect.loop-detected"));
}

// -----------------------------------------------------------------------------
// Test 10: Redirect Limit Exceeded
// -----------------------------------------------------------------------------
#[test]
fn test_redirect_limit_exceeded() {
    let server = TestHttpServer::spawn(
        |req| {
            // Find current count
            if let Some(pos) = req.find("/step") {
                let num_char = req.as_bytes()[pos + 5];
                let next_num = (num_char - b'0') + 1;
                format!(
                    "HTTP/1.1 302 Found\r\nLocation: /step{next_num}\r\nConnection: close\r\n\r\n"
                )
            } else {
                "HTTP/1.1 302 Found\r\nLocation: /step1\r\nConnection: close\r\n\r\n".to_string()
            }
        },
        10,
    );

    let pinned = make_pinned("limit.local", server.port);
    let scope = TargetScope {
        allow_loopback: true,
        ..Default::default()
    };
    let mock_dns = MockDnsResolver::new();
    let config = HttpAssessConfig {
        probe_https: false,
        max_redirects: 2,
        ..Default::default()
    };

    let report =
        HttpPostureAssessor::assess(&pinned, server.port, None, &scope, &mock_dns, &config, None)
            .unwrap();

    let finding_ids: Vec<&str> = report.findings.iter().map(|f| f.id.as_str()).collect();
    assert!(finding_ids.contains(&"http.redirect.limit-exceeded"));
}

// -----------------------------------------------------------------------------
// Test 11: Unauthorized Redirect SSRF Blocked (Cloud Metadata & Private)
// -----------------------------------------------------------------------------
#[test]
fn test_unauthorized_redirect_ssrf_blocked() {
    let server = TestHttpServer::spawn(
        |_req| {
            "HTTP/1.1 302 Found\r\n\
             Location: http://169.254.169.254/latest/meta-data/\r\n\
             Connection: close\r\n\r\n"
                .to_string()
        },
        2,
    );

    let pinned = make_pinned("ssrf.test.local", server.port);
    let scope = TargetScope {
        allow_loopback: true,
        ..Default::default()
    };
    let mock_dns = MockDnsResolver::new();
    let config = HttpAssessConfig {
        probe_https: false,
        ..Default::default()
    };

    let report =
        HttpPostureAssessor::assess(&pinned, server.port, None, &scope, &mock_dns, &config, None)
            .unwrap();

    let ssrf_finding = report
        .findings
        .iter()
        .find(|f| f.id == "http.redirect.ssrf-blocked")
        .expect("Must produce SSRF blocked finding");

    assert_eq!(ssrf_finding.severity, HttpFindingSeverity::High);
    assert!(ssrf_finding.evidence.contains("169.254.169.254"));
}

// -----------------------------------------------------------------------------
// Test 12: Oversized Response Bounded Safely
// -----------------------------------------------------------------------------
#[test]
fn test_oversized_response_bounded_safely() {
    let server = TestHttpServer::spawn(
        |_req| {
            let huge_padding = "X-Padding: ".to_string() + &"A".repeat(20_000) + "\r\n";
            format!("HTTP/1.1 200 OK\r\n{huge_padding}Connection: close\r\n\r\n")
        },
        2,
    );

    let pinned = make_pinned("oversized.local", server.port);
    let scope = TargetScope {
        allow_loopback: true,
        ..Default::default()
    };
    let mock_dns = MockDnsResolver::new();
    let config = HttpAssessConfig {
        probe_https: false,
        max_response_headers_bytes: 4096, // Strictly bound to 4KB
        ..Default::default()
    };

    let report =
        HttpPostureAssessor::assess(&pinned, server.port, None, &scope, &mock_dns, &config, None);

    // Must return without hanging or crashing
    assert!(report.is_ok());
}

// -----------------------------------------------------------------------------
// Test 13: Malformed HTTP Response Handled Gracefully
// -----------------------------------------------------------------------------
#[test]
fn test_malformed_http_response_handled_gracefully() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let _ = stream.write_all(b"\x00\xff\xfe\x01\x02\x03\r\n\r\n");
            let _ = stream.flush();
        }
    });

    let pinned = make_pinned("malformed.local", port);
    let scope = TargetScope {
        allow_loopback: true,
        ..Default::default()
    };
    let mock_dns = MockDnsResolver::new();
    let config = HttpAssessConfig {
        probe_https: false,
        ..Default::default()
    };

    let report = HttpPostureAssessor::assess(&pinned, port, None, &scope, &mock_dns, &config, None);

    assert!(report.is_ok());
}

// -----------------------------------------------------------------------------
// Test 14: Cancellation Token Stops Assessment Immediately
// -----------------------------------------------------------------------------
#[test]
fn test_cancellation_during_http_assessment() {
    let cancel = AtomicBool::new(true); // Pre-tripped cancellation
    let pinned = make_pinned("cancel.local", 80);
    let scope = TargetScope::default();
    let mock_dns = MockDnsResolver::new();
    let config = HttpAssessConfig::default();

    let res =
        HttpPostureAssessor::assess(&pinned, 80, None, &scope, &mock_dns, &config, Some(&cancel));

    assert!(res.is_err());
}

// -----------------------------------------------------------------------------
// Test 15: Hostname Preserved in Host Header
// -----------------------------------------------------------------------------
#[test]
fn test_hostname_preserved_in_host_header() {
    let server = TestHttpServer::spawn(
        |req| {
            if req.contains("Host: my.vhost.internal") {
                "HTTP/1.1 200 OK\r\nX-Host-Match: true\r\nConnection: close\r\n\r\n".to_string()
            } else {
                "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n".to_string()
            }
        },
        2,
    );

    let pinned = make_pinned("my.vhost.internal", server.port);
    let scope = TargetScope {
        allow_loopback: true,
        ..Default::default()
    };
    let mock_dns = MockDnsResolver::new();
    let config = HttpAssessConfig {
        probe_https: false,
        ..Default::default()
    };

    let report =
        HttpPostureAssessor::assess(&pinned, server.port, None, &scope, &mock_dns, &config, None)
            .unwrap();

    let resp = report.responses.first().expect("Must have response");
    assert_eq!(resp.status_code, 200);
    assert_eq!(resp.header("x-host-match"), Some("true"));
}

// -----------------------------------------------------------------------------
// Test 16: Zero Secondary DNS Resolution and Pinned IP Enforcement
// -----------------------------------------------------------------------------
#[test]
fn test_pinned_ip_enforcement_never_reresolves() {
    let server = TestHttpServer::spawn(
        |_req| "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n".to_string(),
        2,
    );

    let mut mock_dns = MockDnsResolver::new();
    mock_dns.insert("pinned.http.local", vec!["127.0.0.1".parse().unwrap()]);

    let scope = TargetScope {
        allow_loopback: true,
        ..Default::default()
    };
    let target = CanonicalTarget::parse("pinned.http.local").unwrap();
    let pinned =
        openaudit_network::resolver::resolve_and_pin(&target, &scope, &mock_dns, server.port)
            .unwrap();

    assert_eq!(pinned.pinned_addr.ip().to_string(), "127.0.0.1");

    // Poison DNS resolver cache with an unauthorized or invalid IP
    mock_dns.insert(
        "pinned.http.local",
        vec!["169.254.169.254".parse().unwrap()],
    );

    // HttpPostureAssessor exclusively connects to pinned.pinned_addr
    let config = HttpAssessConfig {
        probe_https: false,
        ..Default::default()
    };
    let report =
        HttpPostureAssessor::assess(&pinned, server.port, None, &scope, &mock_dns, &config, None)
            .unwrap();

    assert_eq!(report.responses.first().unwrap().status_code, 200);
}
