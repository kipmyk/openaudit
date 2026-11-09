//! Safe, bounded protocol and service identification for confirmed open TCP ports.
//!
//! Enforces:
//! - Strictly bounded to confirmed open ports (`PortStatus::Open`).
//! - Non-destructive, minimal protocol handshakes (zero exploit payloads, zero commands).
//! - Conservative banner grabbing with strict read timeouts and maximum buffer size (2048 bytes).
//! - Explicit separation of verified detected protocol vs inferred well-known service.
//! - Evidentiary backing and confidence scoring (`Confirmed`, `Likely`, `Inferred`, `Unknown`).
//! - Preserves unknown services as `Unknown` rather than guessing.
//! - Direct communication using pre-validated `PinnedTarget` socket addresses (no secondary DNS lookups).

use crate::error::NetworkError;
use crate::pinned::PinnedTarget;
use crate::scanner::{PortScanResult, PortStatus};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Verified network protocol detected via handshake, response signature, or banner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentifiedProtocol {
    /// Hypertext Transfer Protocol (RFC 9112).
    Http,
    /// HTTP over TLS / SSL (RFC 8446 / RFC 2818).
    Https,
    /// Secure Shell Protocol (RFC 4253).
    Ssh,
    /// Simple Mail Transfer Protocol (RFC 5321).
    Smtp,
    /// Domain Name System over TCP (RFC 1035 / RFC 7766).
    Dns,
    /// Unidentified or proprietary protocol.
    Unknown,
}

/// Confidence level of the service identification.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum IdentificationConfidence {
    /// Unknown protocol or unverified port.
    Unknown = 0,
    /// Inferred solely from standard IANA port number without payload verification.
    Inferred = 1,
    /// Likely matching protocol characteristics with high probability.
    Likely = 2,
    /// Confirmed via unambiguous protocol handshake, banner, or response signature.
    Confirmed = 3,
}

/// Structured forensic record for a service identified on an open port.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ServiceIdentification {
    /// The probed TCP port number.
    pub port: u16,
    /// The verified detected protocol (or `Unknown` if no signature matched).
    pub detected_protocol: IdentifiedProtocol,
    /// Descriptive service classification (e.g. "HTTP", "OpenSSH", "PostgreSQL (Inferred)").
    pub service_name: String,
    /// Evidentiary confidence level.
    pub confidence: IdentificationConfidence,
    /// Forensic evidence text backing the identification (e.g. HTTP status line, SSH identification string).
    pub evidence: Option<String>,
    /// Extracted server software banner or version token (if cleanly observable, e.g. "nginx/1.24.0").
    pub banner: Option<String>,
}

/// Configuration governing safe, bounded service identification.
#[derive(Debug, Clone)]
pub struct ServiceIdentifyConfig {
    /// Timeout for initial passive banner read and active probe handshakes (100ms..=5000ms).
    pub probe_timeout: Duration,
    /// Maximum response bytes to read from a service (bounds memory and prevents stream exhaustion).
    pub max_response_bytes: usize,
}

impl Default for ServiceIdentifyConfig {
    fn default() -> Self {
        Self {
            probe_timeout: Duration::from_millis(1500),
            max_response_bytes: 2048,
        }
    }
}

/// Safe service identification engine.
#[derive(Debug, Default)]
pub struct ServiceIdentifier;

impl ServiceIdentifier {
    /// Identifies services on confirmed open ports using conservative protocol probes.
    ///
    /// Skips any ports that are not `PortStatus::Open`.
    pub fn identify_services(
        pinned_target: &PinnedTarget,
        scan_results: &[PortScanResult],
        config: &ServiceIdentifyConfig,
        cancel_token: Option<Arc<AtomicBool>>,
    ) -> Result<Vec<ServiceIdentification>, NetworkError> {
        let ip = pinned_target.pinned_addr.ip();
        let sni = &pinned_target.sni_hostname;
        let mut identifications = Vec::new();

        for res in scan_results {
            if res.status != PortStatus::Open {
                continue;
            }

            if let Some(ref cancel) = cancel_token {
                if cancel.load(Ordering::Relaxed) {
                    break;
                }
            }

            let addr = SocketAddr::new(ip, res.port);
            let ident = Self::probe_single_port(addr, res.port, sni, config);
            identifications.push(ident);
        }

        Ok(identifications)
    }

    /// Safely probes a single confirmed open port.
    pub fn probe_single_port(
        addr: SocketAddr,
        port: u16,
        sni_host: &str,
        config: &ServiceIdentifyConfig,
    ) -> ServiceIdentification {
        // Phase 1: Passive Banner Inspection (Safe for SSH, SMTP, FTP)
        // Many enterprise daemons send an identification banner immediately upon connection acceptance.
        if let Ok(mut stream) = TcpStream::connect_timeout(&addr, config.probe_timeout) {
            let _ = stream.set_read_timeout(Some(Duration::from_millis(400)));
            let mut buf = vec![0u8; config.max_response_bytes];

            if let Ok(n) = stream.read(&mut buf) {
                if n > 0 {
                    let slice = &buf[..n];
                    if let Some(ident) = Self::evaluate_passive_banner(port, slice) {
                        return ident;
                    }
                }
            }
        }

        // Phase 2: Conservative HTTP Probe (RFC 9112 HEAD Request)
        // If passive read yielded nothing, test if the port accepts HTTP.
        if let Some(ident) = Self::probe_http(addr, port, sni_host, config) {
            return ident;
        }

        // Phase 3: Minimal TLS ClientHello Probe
        // Test if the port speaks TLS (HTTPS, SMTPS, IMAPS).
        if let Some(ident) = Self::probe_tls(addr, port, sni_host, config) {
            return ident;
        }

        // Phase 4: Inferred Service by Well-Known Port
        // If payload probing was indeterminate, fall back to explicit Inferred classification.
        Self::infer_by_well_known_port(port)
    }

    /// Evaluates passive banner bytes received without sending application data.
    fn evaluate_passive_banner(port: u16, data: &[u8]) -> Option<ServiceIdentification> {
        let text = String::from_utf8_lossy(data);
        let first_line = text.lines().next().unwrap_or("").trim();

        // 1. SSH Server Identification String (RFC 4253 §4.2: "SSH-protoversion-softwareversion comments")
        if first_line.starts_with("SSH-2.0-") || first_line.starts_with("SSH-1.99-") {
            return Some(ServiceIdentification {
                port,
                detected_protocol: IdentifiedProtocol::Ssh,
                service_name: "SSH".to_string(),
                confidence: IdentificationConfidence::Confirmed,
                evidence: Some(format!("SSH identification string: {first_line}")),
                banner: Some(first_line.to_string()),
            });
        }

        // 2. SMTP Server Greeting (RFC 5321 §3.1: "220 <domain> Simple Mail Transfer Service Ready")
        if first_line.starts_with("220 ") || first_line.starts_with("220-") {
            return Some(ServiceIdentification {
                port,
                detected_protocol: IdentifiedProtocol::Smtp,
                service_name: "SMTP".to_string(),
                confidence: IdentificationConfidence::Confirmed,
                evidence: Some(format!("SMTP 220 banner greeting: {first_line}")),
                banner: Some(first_line.to_string()),
            });
        }

        // 3. FTP Server Greeting (RFC 959: "220 ...")
        if port == 21 && (first_line.starts_with("220 ") || first_line.starts_with("220-")) {
            return Some(ServiceIdentification {
                port,
                detected_protocol: IdentifiedProtocol::Unknown,
                service_name: "FTP".to_string(),
                confidence: IdentificationConfidence::Likely,
                evidence: Some(format!("FTP greeting line: {first_line}")),
                banner: Some(first_line.to_string()),
            });
        }

        None
    }

    /// Sends a minimal, RFC 9112 compliant HTTP HEAD probe and inspects the response.
    fn probe_http(
        addr: SocketAddr,
        port: u16,
        sni_host: &str,
        config: &ServiceIdentifyConfig,
    ) -> Option<ServiceIdentification> {
        let mut stream = TcpStream::connect_timeout(&addr, config.probe_timeout).ok()?;
        let _ = stream.set_read_timeout(Some(config.probe_timeout));
        let _ = stream.set_write_timeout(Some(config.probe_timeout));

        // Minimal, non-destructive HEAD probe with explicit Connection: close
        let probe = format!(
            "HEAD / HTTP/1.1\r\nHost: {sni_host}\r\nUser-Agent: OpenAudit-Network/0.1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        );

        if stream.write_all(probe.as_bytes()).is_err() {
            return None;
        }

        let mut buf = vec![0u8; config.max_response_bytes];
        let n = stream.read(&mut buf).ok()?;
        if n == 0 {
            return None;
        }

        let response_text = String::from_utf8_lossy(&buf[..n]);
        let first_line = response_text.lines().next().unwrap_or("").trim();

        // Check for valid HTTP status line (RFC 9112 §3: "HTTP-version SP status-code SP [reason-phrase]")
        if first_line.starts_with("HTTP/1.0 ")
            || first_line.starts_with("HTTP/1.1 ")
            || first_line.starts_with("HTTP/2 ")
        {
            // Extract Server header if present
            let mut server_banner = None;
            for line in response_text.lines() {
                if let Some(val) = line.strip_prefix("Server: ") {
                    server_banner = Some(val.trim().to_string());
                    break;
                } else if let Some(val) = line.strip_prefix("server: ") {
                    server_banner = Some(val.trim().to_string());
                    break;
                }
            }

            return Some(ServiceIdentification {
                port,
                detected_protocol: IdentifiedProtocol::Http,
                service_name: "HTTP".to_string(),
                confidence: IdentificationConfidence::Confirmed,
                evidence: Some(format!("HTTP status line: {first_line}")),
                banner: server_banner,
            });
        }

        // Check if plain HTTP probe was rejected by a TLS-only port (e.g. HTTP 400 Bad Request to HTTPS)
        if response_text.contains("The plain HTTP request was sent to HTTPS port")
            || response_text.contains("Client sent an HTTP request to an HTTPS server")
            || (buf.len() >= 3 && buf[0] == 0x15 && buf[1] == 0x03)
        // TLS Alert Record
        {
            return Some(ServiceIdentification {
                port,
                detected_protocol: IdentifiedProtocol::Https,
                service_name: "HTTPS (TLS)".to_string(),
                confidence: IdentificationConfidence::Confirmed,
                evidence: Some("TLS listener rejected unencrypted HTTP probe".to_string()),
                banner: None,
            });
        }

        None
    }

    /// Sends a minimal, valid TLS ClientHello probe and inspects the response for a TLS ServerHello record.
    fn probe_tls(
        addr: SocketAddr,
        port: u16,
        sni_host: &str,
        config: &ServiceIdentifyConfig,
    ) -> Option<ServiceIdentification> {
        let mut stream = TcpStream::connect_timeout(&addr, config.probe_timeout).ok()?;
        let _ = stream.set_read_timeout(Some(config.probe_timeout));
        let _ = stream.set_write_timeout(Some(config.probe_timeout));

        let client_hello = build_minimal_tls_client_hello(sni_host);
        if stream.write_all(&client_hello).is_err() {
            return None;
        }

        let mut header = [0u8; 5];
        if stream.read_exact(&mut header).is_err() {
            return None;
        }

        // TLS Record Header:
        // Byte 0: ContentType (0x16 = Handshake, 0x15 = Alert)
        // Bytes 1-2: Legacy Version (0x0301 = TLS 1.0, 0x0303 = TLS 1.2/1.3)
        // Bytes 3-4: Length
        if (header[0] == 0x16 || header[0] == 0x15) && header[1] == 0x03 {
            let version_str = match header[2] {
                1 => "TLS 1.0",
                2 => "TLS 1.1",
                3 => "TLS 1.2 / 1.3",
                _ => "TLS Unknown",
            };

            return Some(ServiceIdentification {
                port,
                detected_protocol: IdentifiedProtocol::Https,
                service_name: "HTTPS (TLS)".to_string(),
                confidence: IdentificationConfidence::Confirmed,
                evidence: Some(format!("TLS ServerHello handshake record ({version_str})")),
                banner: None,
            });
        }

        None
    }

    /// Classifies an unverified port solely by its standard IANA well-known assignment.
    fn infer_by_well_known_port(port: u16) -> ServiceIdentification {
        let (name, protocol, confidence) = match port {
            80 => (
                "HTTP (Unverified)",
                IdentifiedProtocol::Http,
                IdentificationConfidence::Inferred,
            ),
            443 => (
                "HTTPS (Unverified)",
                IdentifiedProtocol::Https,
                IdentificationConfidence::Inferred,
            ),
            22 => (
                "SSH (Unverified)",
                IdentifiedProtocol::Ssh,
                IdentificationConfidence::Inferred,
            ),
            25 => (
                "SMTP (Unverified)",
                IdentifiedProtocol::Smtp,
                IdentificationConfidence::Inferred,
            ),
            53 => (
                "DNS (Unverified)",
                IdentifiedProtocol::Dns,
                IdentificationConfidence::Inferred,
            ),
            21 => (
                "FTP (Unverified)",
                IdentifiedProtocol::Unknown,
                IdentificationConfidence::Inferred,
            ),
            3306 => (
                "MySQL (Inferred)",
                IdentifiedProtocol::Unknown,
                IdentificationConfidence::Inferred,
            ),
            5432 => (
                "PostgreSQL (Inferred)",
                IdentifiedProtocol::Unknown,
                IdentificationConfidence::Inferred,
            ),
            6379 => (
                "Redis (Inferred)",
                IdentifiedProtocol::Unknown,
                IdentificationConfidence::Inferred,
            ),
            8080 => (
                "HTTP-Proxy (Inferred)",
                IdentifiedProtocol::Http,
                IdentificationConfidence::Inferred,
            ),
            8443 => (
                "HTTPS-Alt (Inferred)",
                IdentifiedProtocol::Https,
                IdentificationConfidence::Inferred,
            ),
            _ => (
                "Unknown Service",
                IdentifiedProtocol::Unknown,
                IdentificationConfidence::Unknown,
            ),
        };

        ServiceIdentification {
            port,
            detected_protocol: protocol,
            service_name: name.to_string(),
            confidence,
            evidence: None,
            banner: None,
        }
    }
}

/// Constructs a minimal, RFC-compliant TLS 1.2/1.3 ClientHello containing the SNI extension.
fn build_minimal_tls_client_hello(sni_host: &str) -> Vec<u8> {
    let mut extensions = Vec::new();

    // SNI Extension (Type 0x0000)
    let host_bytes = sni_host.as_bytes();
    if !host_bytes.is_empty() {
        let mut sni_ext = Vec::new();
        // Server Name list length
        let list_len = (host_bytes.len() + 3) as u16;
        sni_ext.extend_from_slice(&list_len.to_be_bytes());
        // NameType: host_name (0)
        sni_ext.push(0);
        // Host name length
        let name_len = host_bytes.len() as u16;
        sni_ext.extend_from_slice(&name_len.to_be_bytes());
        sni_ext.extend_from_slice(host_bytes);

        // Extension header
        extensions.extend_from_slice(&0u16.to_be_bytes()); // Type 0 (SNI)
        let ext_len = sni_ext.len() as u16;
        extensions.extend_from_slice(&ext_len.to_be_bytes());
        extensions.extend_from_slice(&sni_ext);
    }

    // Handshake Body
    let mut handshake = Vec::new();
    // Protocol Version: TLS 1.2 (0x0303)
    handshake.extend_from_slice(&[0x03, 0x03]);
    // Client Random (32 bytes)
    handshake.extend_from_slice(&[0x42; 32]);
    // Session ID length: 0
    handshake.push(0);
    // Cipher Suites Length: 4 bytes (TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
    handshake.extend_from_slice(&[0x00, 0x04]);
    handshake.extend_from_slice(&[0xc0, 0x2f]); // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    handshake.extend_from_slice(&[0x00, 0xff]); // TLS_EMPTY_RENEGOTIATION_INFO_SCSV
                                                // Compression Methods: 1 byte (null compression)
    handshake.extend_from_slice(&[0x01, 0x00]);

    // Extensions Length & Extensions
    let ext_len = extensions.len() as u16;
    handshake.extend_from_slice(&ext_len.to_be_bytes());
    handshake.extend_from_slice(&extensions);

    // Handshake Message Header: Type (0x01 = ClientHello) + 3-byte Length
    let mut msg = Vec::new();
    msg.push(0x01); // ClientHello
    let hs_len = handshake.len() as u32;
    msg.push((hs_len >> 16) as u8);
    msg.push((hs_len >> 8) as u8);
    msg.push(hs_len as u8);
    msg.extend_from_slice(&handshake);

    // TLS Record Header: 0x16 (Handshake), 0x0301 (Legacy TLS 1.0 record version), 2-byte length
    let mut record = Vec::new();
    record.push(0x16);
    record.extend_from_slice(&[0x03, 0x01]);
    let rec_len = msg.len() as u16;
    record.extend_from_slice(&rec_len.to_be_bytes());
    record.extend_from_slice(&msg);

    record
}
