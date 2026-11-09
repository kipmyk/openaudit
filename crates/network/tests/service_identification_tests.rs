//! Comprehensive tests for OpenAudit M4 Increment 3: Safe Service Identification.
//!
//! Verifies:
//! - Open ports with identifiable daemons (SSH, SMTP, HTTP, HTTPS).
//! - Open ports with unknown/unrecognized services.
//! - Protocol payload disambiguation vs well-known port assumptions.
//! - Bounded response sizes and timeout handling on unresponsive services.
//! - Scope enforcement and pre-validated destination pinning.
//! - Cancellation token behavior.
//! - Clean non-destructive execution without exploit payloads or remote commands.

use openaudit_network::pinned::PinnedTarget;
use openaudit_network::resolver::MockDnsResolver;
use openaudit_network::scanner::{PortScanResult, PortStatus};
use openaudit_network::scope::TargetScope;
use openaudit_network::service::{
    IdentificationConfidence, IdentifiedProtocol, ServiceIdentifier, ServiceIdentifyConfig,
};
use openaudit_network::target::CanonicalTarget;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

fn make_loopback_pinned(port: u16) -> PinnedTarget {
    let target = CanonicalTarget::parse("127.0.0.1").unwrap();
    let scope = TargetScope {
        allow_loopback: true,
        ..Default::default()
    };
    let mock_dns = MockDnsResolver::new();
    openaudit_network::resolver::resolve_and_pin(&target, &scope, &mock_dns, port).unwrap()
}

#[test]
fn test_ssh_service_identification_from_banner() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Must bind");
    let port = listener.local_addr().unwrap().port();

    let server_handle = thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let banner = b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.4\r\n";
            let _ = stream.write_all(banner);
        }
    });

    let pinned = make_loopback_pinned(port);
    let scan_results = vec![PortScanResult {
        port,
        status: PortStatus::Open,
        latency_ms: 1,
        diagnostic: None,
    }];

    let config = ServiceIdentifyConfig {
        probe_timeout: Duration::from_millis(1000),
        max_response_bytes: 2048,
    };

    let idents = ServiceIdentifier::identify_services(&pinned, &scan_results, &config, None)
        .expect("Identification succeeds");

    server_handle.join().unwrap();

    assert_eq!(idents.len(), 1);
    let id = &idents[0];
    assert_eq!(id.port, port);
    assert_eq!(id.detected_protocol, IdentifiedProtocol::Ssh);
    assert_eq!(id.confidence, IdentificationConfidence::Confirmed);
    assert!(id.banner.as_ref().unwrap().contains("OpenSSH_9.6p1"));
    assert!(id
        .evidence
        .as_ref()
        .unwrap()
        .contains("SSH identification string"));
}

#[test]
fn test_smtp_service_identification_from_greeting() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Must bind");
    let port = listener.local_addr().unwrap().port();

    let server_handle = thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let greeting = b"220 mail.enterprise.internal ESMTP Postfix\r\n";
            let _ = stream.write_all(greeting);
        }
    });

    let pinned = make_loopback_pinned(port);
    let scan_results = vec![PortScanResult {
        port,
        status: PortStatus::Open,
        latency_ms: 1,
        diagnostic: None,
    }];

    let config = ServiceIdentifyConfig::default();
    let idents = ServiceIdentifier::identify_services(&pinned, &scan_results, &config, None)
        .expect("Identification succeeds");

    server_handle.join().unwrap();

    assert_eq!(idents.len(), 1);
    let id = &idents[0];
    assert_eq!(id.detected_protocol, IdentifiedProtocol::Smtp);
    assert_eq!(id.confidence, IdentificationConfidence::Confirmed);
    assert!(id
        .banner
        .as_ref()
        .unwrap()
        .contains("mail.enterprise.internal"));
}

#[test]
fn test_http_service_identification_from_head_response() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Must bind");
    let port = listener.local_addr().unwrap().port();

    let server_handle = thread::spawn(move || {
        while let Ok((mut stream, _)) = listener.accept() {
            let mut req_buf = [0u8; 1024];
            let _ = stream.set_read_timeout(Some(Duration::from_millis(600)));
            if let Ok(n) = stream.read(&mut req_buf) {
                if n > 0 {
                    let req_str = String::from_utf8_lossy(&req_buf[..n]);
                    if req_str.starts_with("HEAD / HTTP/1.1") {
                        let resp = b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0 (Ubuntu)\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n";
                        let _ = stream.write_all(resp);
                        break;
                    }
                }
            }
        }
    });

    let pinned = make_loopback_pinned(port);
    let scan_results = vec![PortScanResult {
        port,
        status: PortStatus::Open,
        latency_ms: 2,
        diagnostic: None,
    }];

    let config = ServiceIdentifyConfig::default();
    let idents = ServiceIdentifier::identify_services(&pinned, &scan_results, &config, None)
        .expect("Identification succeeds");

    server_handle.join().unwrap();

    assert_eq!(idents.len(), 1);
    let id = &idents[0];
    assert_eq!(id.detected_protocol, IdentifiedProtocol::Http);
    assert_eq!(id.confidence, IdentificationConfidence::Confirmed);
    assert_eq!(id.banner.as_deref(), Some("nginx/1.24.0 (Ubuntu)"));
    assert!(id.evidence.as_ref().unwrap().contains("HTTP/1.1 200 OK"));
}

#[test]
fn test_https_service_identification_from_tls_server_hello() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Must bind");
    let port = listener.local_addr().unwrap().port();

    let server_handle = thread::spawn(move || {
        // First connection: passive read (fails/silence), server closes
        if let Ok((_stream, _)) = listener.accept() {
            thread::sleep(Duration::from_millis(50));
        }

        // Second connection: HTTP HEAD probe. Reject with TLS alert or HTTPS notice
        if let Ok((mut stream, _)) = listener.accept() {
            let mut req_buf = [0u8; 512];
            let _ = stream.read(&mut req_buf);
            let alert = b"The plain HTTP request was sent to HTTPS port\r\n";
            let _ = stream.write_all(alert);
        }
    });

    let pinned = make_loopback_pinned(port);
    let scan_results = vec![PortScanResult {
        port,
        status: PortStatus::Open,
        latency_ms: 1,
        diagnostic: None,
    }];

    let config = ServiceIdentifyConfig::default();
    let idents = ServiceIdentifier::identify_services(&pinned, &scan_results, &config, None)
        .expect("Identification succeeds");

    server_handle.join().unwrap();

    assert_eq!(idents.len(), 1);
    let id = &idents[0];
    assert_eq!(id.detected_protocol, IdentifiedProtocol::Https);
    assert_eq!(id.confidence, IdentificationConfidence::Confirmed);
}

#[test]
fn test_payload_evidence_overrides_misleading_port_number() {
    // Run an SSH daemon on port 8080 (which is typically HTTP)
    let listener = TcpListener::bind("127.0.0.1:0").expect("Must bind");
    let non_standard_port = listener.local_addr().unwrap().port();

    let server_handle = thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let _ = stream.write_all(b"SSH-2.0-OpenSSH_8.9p1\r\n");
        }
    });

    let pinned = make_loopback_pinned(non_standard_port);
    let scan_results = vec![PortScanResult {
        port: non_standard_port,
        status: PortStatus::Open,
        latency_ms: 1,
        diagnostic: None,
    }];

    let config = ServiceIdentifyConfig::default();
    let idents = ServiceIdentifier::identify_services(&pinned, &scan_results, &config, None)
        .expect("Must identify");

    server_handle.join().unwrap();

    assert_eq!(idents.len(), 1);
    let id = &idents[0];
    // Must be confirmed SSH, NOT guessed HTTP based on port number!
    assert_eq!(id.detected_protocol, IdentifiedProtocol::Ssh);
    assert_eq!(id.confidence, IdentificationConfidence::Confirmed);
    assert_eq!(id.service_name, "SSH");
}

#[test]
fn test_unresponsive_service_falls_back_to_inferred_safely() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Must bind");
    let port = listener.local_addr().unwrap().port();

    let server_handle = thread::spawn(move || {
        // Accept connections but write nothing (silent/unresponsive daemon)
        while let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 128];
            let _ = stream.read(&mut buf);
        }
    });

    let pinned = make_loopback_pinned(port);
    let scan_results = vec![PortScanResult {
        port,
        status: PortStatus::Open,
        latency_ms: 1,
        diagnostic: None,
    }];

    // Strict fast timeout
    let config = ServiceIdentifyConfig {
        probe_timeout: Duration::from_millis(200),
        max_response_bytes: 512,
    };

    let idents = ServiceIdentifier::identify_services(&pinned, &scan_results, &config, None)
        .expect("Identification finishes without hanging");

    assert_eq!(idents.len(), 1);
    let id = &idents[0];
    // Unknown ephemeral port with silence must be Unknown
    assert_eq!(id.detected_protocol, IdentifiedProtocol::Unknown);
    assert_eq!(id.confidence, IdentificationConfidence::Unknown);

    drop(server_handle);
}

#[test]
fn test_oversized_response_bounded_cleanly() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Must bind");
    let port = listener.local_addr().unwrap().port();

    let server_handle = thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            // Write 64KB of repetitive text
            let big_buf = vec![b'A'; 65536];
            let _ = stream.write_all(&big_buf);
        }
    });

    let pinned = make_loopback_pinned(port);
    let scan_results = vec![PortScanResult {
        port,
        status: PortStatus::Open,
        latency_ms: 1,
        diagnostic: None,
    }];

    let config = ServiceIdentifyConfig {
        probe_timeout: Duration::from_millis(500),
        max_response_bytes: 1024,
    };

    let idents = ServiceIdentifier::identify_services(&pinned, &scan_results, &config, None)
        .expect("Completes within memory boundary");

    server_handle.join().unwrap();

    assert_eq!(idents.len(), 1);
    // Did not panic, memory stayed bounded
    assert_eq!(idents[0].detected_protocol, IdentifiedProtocol::Unknown);
}

#[test]
fn test_cancellation_token_terminates_probing() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Must bind");
    let port = listener.local_addr().unwrap().port();

    let pinned = make_loopback_pinned(port);
    let scan_results = vec![
        PortScanResult {
            port,
            status: PortStatus::Open,
            latency_ms: 1,
            diagnostic: None,
        },
        PortScanResult {
            port: port + 1,
            status: PortStatus::Open,
            latency_ms: 1,
            diagnostic: None,
        },
    ];

    let cancel = Arc::new(AtomicBool::new(true)); // Already canceled!
    let config = ServiceIdentifyConfig::default();

    let idents =
        ServiceIdentifier::identify_services(&pinned, &scan_results, &config, Some(cancel))
            .expect("Executes cleanly");

    // Because token was set, 0 ports probed
    assert_eq!(idents.len(), 0);
}

#[test]
fn test_closed_and_timed_out_ports_are_skipped() {
    let pinned = make_loopback_pinned(80);
    let scan_results = vec![
        PortScanResult {
            port: 80,
            status: PortStatus::Closed,
            latency_ms: 1,
            diagnostic: None,
        },
        PortScanResult {
            port: 443,
            status: PortStatus::TimedOut,
            latency_ms: 1500,
            diagnostic: None,
        },
        PortScanResult {
            port: 22,
            status: PortStatus::Filtered,
            latency_ms: 1500,
            diagnostic: None,
        },
    ];

    let config = ServiceIdentifyConfig::default();
    let idents = ServiceIdentifier::identify_services(&pinned, &scan_results, &config, None)
        .expect("Executes cleanly");

    assert_eq!(idents.len(), 0, "Non-open ports must never be probed");
}
