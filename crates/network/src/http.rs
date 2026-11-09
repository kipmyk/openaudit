//! Bounded, SSRF-safe HTTP and HTTPS security posture assessment.
//!
//! Evaluates:
//! - HTTPS availability and HTTP-to-HTTPS redirect enforcement.
//! - Security response headers (HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy).
//! - Server and application framework version disclosure (Server, X-Powered-By).
//! - Cookie security flags (Secure, HttpOnly, SameSite).
//! - Redirect validation with strict hop limits, loop detection, and SSRF prevention.
//!
//! Guarantees:
//! - Connects exclusively to previously validated, pinned socket addresses (`PinnedTarget`).
//! - Preserves original hostname for HTTP `Host` headers and TLS SNI.
//! - Never performs secondary unvalidated DNS resolution.
//! - Non-destructive, bounded probing (HEAD preferred, GET with bounded response bodies).
//! - Fully cooperative cancellation support via `AtomicBool`.

use crate::error::NetworkError;
use crate::pinned::PinnedTarget;
use crate::redirect::RedirectValidator;
use crate::resolver::DnsResolver;
use crate::scope::TargetScope;
use chrono::{DateTime, Utc};
use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Configuration parameters for HTTP security posture evaluation.
#[derive(Debug, Clone)]
pub struct HttpAssessConfig {
    /// Socket connection timeout for TCP and TLS handshakes.
    pub connect_timeout: Duration,
    /// Read timeout for HTTP socket read operations.
    pub read_timeout: Duration,
    /// Maximum response header bytes to read before cutting off (default: 16 KB).
    pub max_response_headers_bytes: usize,
    /// Maximum response body bytes to read for body inspection (default: 64 KB).
    pub max_response_body_bytes: usize,
    /// Maximum redirect hops to follow (default: 5).
    pub max_redirects: usize,
    /// Custom root certificates for HTTPS verification.
    pub custom_root_store: Option<Arc<RootCertStore>>,
    /// User-Agent header value sent in requests.
    pub user_agent: String,
    /// Whether to assess the HTTPS port in addition to HTTP (default: true).
    pub probe_https: bool,
}

impl Default for HttpAssessConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_millis(2000),
            read_timeout: Duration::from_millis(2000),
            max_response_headers_bytes: 16 * 1024,
            max_response_body_bytes: 64 * 1024,
            max_redirects: 5,
            custom_root_store: None,
            user_agent: "OpenAudit-Network/0.1.0 (+https://openaudit.internal)".to_string(),
            probe_https: true,
        }
    }
}

/// A parsed HTTP cookie observed in a Set-Cookie response header.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HttpCookie {
    /// Name of the cookie.
    pub name: String,
    /// Value of the cookie.
    pub value: String,
    /// Whether the `Secure` attribute is present.
    pub has_secure: bool,
    /// Whether the `HttpOnly` attribute is present.
    pub has_httponly: bool,
    /// Value of the `SameSite` attribute (e.g. "Strict", "Lax", "None"), if present.
    pub same_site: Option<String>,
    /// Value of the `Path` attribute, if present.
    pub path: Option<String>,
    /// Value of the `Domain` attribute, if present.
    pub domain: Option<String>,
}

impl HttpCookie {
    /// Parses a raw Set-Cookie header value into a structured `HttpCookie`.
    pub fn parse(raw: &str) -> Option<Self> {
        let mut parts = raw.split(';');
        let name_value = parts.next()?.trim();
        let (name, value) = match name_value.split_once('=') {
            Some((n, v)) => (n.trim().to_string(), v.trim().to_string()),
            None => (name_value.to_string(), String::new()),
        };

        if name.is_empty() {
            return None;
        }

        let mut has_secure = false;
        let mut has_httponly = false;
        let mut same_site = None;
        let mut path = None;
        let mut domain = None;

        for part in parts {
            let trimmed = part.trim();
            if trimmed.is_empty() {
                continue;
            }

            if trimmed.eq_ignore_ascii_case("secure") {
                has_secure = true;
            } else if trimmed.eq_ignore_ascii_case("httponly") {
                has_httponly = true;
            } else if let Some((k, v)) = trimmed.split_once('=') {
                let k_trim = k.trim();
                let v_trim = v.trim();
                if k_trim.eq_ignore_ascii_case("samesite") {
                    same_site = Some(v_trim.to_string());
                } else if k_trim.eq_ignore_ascii_case("path") {
                    path = Some(v_trim.to_string());
                } else if k_trim.eq_ignore_ascii_case("domain") {
                    domain = Some(v_trim.to_string());
                }
            }
        }

        Some(Self {
            name,
            value,
            has_secure,
            has_httponly,
            same_site,
            path,
            domain,
        })
    }
}

/// An observed snapshot of an individual HTTP request and response round-trip.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HttpResponseSnapshot {
    /// Full request URL evaluated.
    pub url: String,
    /// Whether TLS was negotiated for this request.
    pub is_tls: bool,
    /// HTTP status code (e.g. 200, 301, 404).
    pub status_code: u16,
    /// HTTP protocol version string (e.g. "HTTP/1.1").
    pub http_version: String,
    /// Observed response headers preserving case and order.
    pub headers: Vec<(String, String)>,
    /// Optional bounded preview of the response body, if requested.
    pub body_preview: Option<String>,
    /// Response latency in milliseconds.
    pub latency_ms: u64,
}

impl HttpResponseSnapshot {
    /// Returns the first value matching the header name (case-insensitive).
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Returns all values matching the header name (case-insensitive).
    #[must_use]
    pub fn headers_matching(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .collect()
    }
}

/// Severity classification for HTTP security posture findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HttpFindingSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// Structured security finding discovered during HTTP posture assessment.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HttpFinding {
    /// Stable finding rule identifier.
    pub id: String,
    /// Severity rating.
    pub severity: HttpFindingSeverity,
    /// Assessment confidence ("Confirmed", "Likely", "Tentative").
    pub confidence: String,
    /// Human-readable title describing the finding.
    pub title: String,
    /// Specific affected endpoint or URL.
    pub endpoint: String,
    /// Concrete evidence observed in response headers or network attributes.
    pub evidence: String,
    /// Actionable remediation recommendation.
    pub recommendation: String,
    /// Timestamp when finding was identified.
    pub timestamp: DateTime<Utc>,
}

/// Comprehensive results from an HTTP security posture assessment.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HttpPostureAssessment {
    /// Canonical hostname or IP of the assessed target.
    pub target_host: String,
    /// Port used for plaintext HTTP evaluation.
    pub http_port: u16,
    /// Port used for HTTPS evaluation, if configured.
    pub https_port: Option<u16>,
    /// Initial URL requested.
    pub initial_url: String,
    /// Final URL after following safe redirects.
    pub final_url: String,
    /// Complete sequence of URLs visited during redirection.
    pub redirect_chain: Vec<String>,
    /// Whether the HTTPS endpoint was reachable and responded.
    pub https_available: bool,
    /// Whether plaintext HTTP requests are automatically redirected to HTTPS.
    pub http_to_https_redirect: bool,
    /// Whether HSTS is configured.
    pub hsts_enabled: bool,
    /// Whether HSTS includes the `includeSubDomains` directive.
    pub hsts_include_subdomains: bool,
    /// Whether HSTS includes the `preload` directive.
    pub hsts_preload: bool,
    /// Whether a Content-Security-Policy header is present.
    pub csp_present: bool,
    /// Whether `X-Content-Type-Options: nosniff` is enforced.
    pub x_content_type_options_nosniff: bool,
    /// Value of `X-Frame-Options` header, if present.
    pub x_frame_options: Option<String>,
    /// Value of `Referrer-Policy` header, if present.
    pub referrer_policy: Option<String>,
    /// Value of `Permissions-Policy` header, if present.
    pub permissions_policy: Option<String>,
    /// Disclosed server banner from `Server` header, if present.
    pub server_header: Option<String>,
    /// Whether the `Server` header disclosed a specific software version number.
    pub server_version_disclosed: bool,
    /// All unique cookies observed across assessment responses.
    pub observed_cookies: Vec<HttpCookie>,
    /// Structured findings discovered during assessment.
    pub findings: Vec<HttpFinding>,
    /// Diagnostic snapshots of individual HTTP exchanges.
    pub responses: Vec<HttpResponseSnapshot>,
    /// Timestamp when assessment completed.
    pub assessment_timestamp: DateTime<Utc>,
    /// Diagnostic error details if assessment was degraded or partially failed.
    pub error_diagnostic: Option<String>,
}

/// Permissive verifier used exclusively for HTTPS observation during HTTP assessment.
/// Ensures headers and cookies can be assessed even when test servers use self-signed certs.
struct ObservationCertVerifier;

impl std::fmt::Debug for ObservationCertVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObservationCertVerifier").finish()
    }
}

impl ServerCertVerifier for ObservationCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

/// Internal representation of parsed HTTP response bytes.
struct ParsedHttpResponse {
    status_code: u16,
    proto: String,
    headers: Vec<(String, String)>,
    body_preview: Option<String>,
}

/// Production-oriented HTTP security posture assessment engine.
#[derive(Debug, Default)]
pub struct HttpPostureAssessor;

impl HttpPostureAssessor {
    /// Assesses HTTP and HTTPS posture of a pinned target without performing secondary DNS lookups.
    pub fn assess<R: DnsResolver>(
        pinned: &PinnedTarget,
        http_port: u16,
        https_port: Option<u16>,
        scope: &TargetScope,
        resolver: &R,
        config: &HttpAssessConfig,
        cancel_token: Option<&AtomicBool>,
    ) -> Result<HttpPostureAssessment, NetworkError> {
        let now_utc = Utc::now();
        let target_host = pinned.sni_hostname.clone();

        let initial_url = format!("http://{}:{}/", pinned.sni_hostname, http_port);
        let mut redirect_chain = vec![initial_url.clone()];
        let mut responses = Vec::new();
        let mut findings = Vec::new();
        let mut observed_cookies = Vec::new();
        let mut error_diag = None;

        let mut http_to_https_redirect = false;
        let mut https_available = false;

        let redirect_validator = RedirectValidator::with_max_hops(config.max_redirects);

        // ---------------------------------------------------------------------
        // Phase 1: Assess Plaintext HTTP Endpoint & Redirection Behavior
        // ---------------------------------------------------------------------
        if let Some(cancel) = cancel_token {
            if cancel.load(Ordering::Relaxed) {
                return Err(NetworkError::TargetParse(
                    "Assessment canceled by operator".into(),
                ));
            }
        }

        let mut current_pinned = pinned.clone();
        // Override port to specified http_port
        current_pinned.pinned_addr = SocketAddr::new(pinned.pinned_addr.ip(), http_port);
        let mut current_url = initial_url.clone();
        let mut current_scheme = "http";
        let mut current_port = http_port;
        let mut current_path = "/".to_string();

        let mut hop_count = 0;

        loop {
            if let Some(cancel) = cancel_token {
                if cancel.load(Ordering::Relaxed) {
                    break;
                }
            }

            let is_tls = current_scheme == "https";
            let req_res = Self::execute_single_request(
                &current_pinned,
                current_port,
                &current_path,
                is_tls,
                config,
            );

            match req_res {
                Ok(snapshot) => {
                    let status = snapshot.status_code;

                    // Extract cookies
                    for raw_cookie in snapshot.headers_matching("set-cookie") {
                        if let Some(parsed) = HttpCookie::parse(raw_cookie) {
                            if !observed_cookies.contains(&parsed) {
                                observed_cookies.push(parsed);
                            }
                        }
                    }

                    responses.push(snapshot.clone());

                    // Check for redirection (301, 302, 303, 307, 308)
                    if (300..=399).contains(&status) {
                        if let Some(location) = snapshot.header("location") {
                            // Check if this is an HTTP-to-HTTPS redirect
                            if current_scheme == "http" && location.starts_with("https://") {
                                http_to_https_redirect = true;
                            }

                            hop_count += 1;
                            if hop_count > config.max_redirects {
                                findings.push(HttpFinding {
                                    id: "http.redirect.limit-exceeded".into(),
                                    severity: HttpFindingSeverity::Low,
                                    confidence: "Confirmed".into(),
                                    title: "Redirect Hop Limit Exceeded".into(),
                                    endpoint: current_url.clone(),
                                    evidence: format!(
                                        "Exceeded limit of {} redirects at destination: {location}",
                                        config.max_redirects
                                    ),
                                    recommendation:
                                        "Review redirect chains and eliminate unnecessary hops."
                                            .into(),
                                    timestamp: now_utc,
                                });
                                break;
                            }

                            // Validate redirect against scope using RedirectValidator
                            match redirect_validator.validate_redirect(
                                hop_count,
                                location,
                                &current_pinned,
                                scope,
                                resolver,
                            ) {
                                Ok(next_pinned) => {
                                    let next_url = if location.starts_with('/') {
                                        format!(
                                            "{}://{}:{}{}",
                                            current_scheme,
                                            current_pinned.sni_hostname,
                                            current_port,
                                            location
                                        )
                                    } else {
                                        location.to_string()
                                    };

                                    if redirect_chain.contains(&next_url) {
                                        findings.push(HttpFinding {
                                            id: "http.redirect.loop-detected".into(),
                                            severity: HttpFindingSeverity::Medium,
                                            confidence: "Confirmed".into(),
                                            title: "Circular Redirect Loop Detected".into(),
                                            endpoint: current_url.clone(),
                                            evidence: format!(
                                                "Destination '{next_url}' was already visited in redirect chain."
                                            ),
                                            recommendation:
                                                "Fix web server configuration to eliminate circular redirection."
                                                    .into(),
                                            timestamp: now_utc,
                                        });
                                        break;
                                    }

                                    redirect_chain.push(next_url.clone());
                                    current_url = next_url;

                                    if location.starts_with("https://") {
                                        current_scheme = "https";
                                        current_port = next_pinned.pinned_addr.port();
                                    } else if location.starts_with("http://") {
                                        current_scheme = "http";
                                        current_port = next_pinned.pinned_addr.port();
                                    }

                                    // Extract path
                                    current_path = Self::extract_path_from_url(&current_url);
                                    current_pinned = next_pinned;
                                    continue;
                                }
                                Err(NetworkError::RedirectViolation(msg))
                                    if msg.contains("Redirect hop limit exceeded") =>
                                {
                                    findings.push(HttpFinding {
                                        id: "http.redirect.limit-exceeded".into(),
                                        severity: HttpFindingSeverity::Low,
                                        confidence: "Confirmed".into(),
                                        title: "Redirect Hop Limit Exceeded".into(),
                                        endpoint: current_url.clone(),
                                        evidence: format!(
                                            "Exceeded limit of {} redirects at destination: {location}",
                                            config.max_redirects
                                        ),
                                        recommendation:
                                            "Review redirect chains and eliminate unnecessary hops."
                                                .into(),
                                        timestamp: now_utc,
                                    });
                                    break;
                                }
                                Err(e) => {
                                    findings.push(HttpFinding {
                                        id: "http.redirect.ssrf-blocked".into(),
                                        severity: HttpFindingSeverity::High,
                                        confidence: "Confirmed".into(),
                                        title: "Redirect to Unauthorized Destination Blocked"
                                            .into(),
                                        endpoint: current_url.clone(),
                                        evidence: format!(
                                            "Server attempted redirect to prohibited target '{location}': {e}"
                                        ),
                                        recommendation:
                                            "Ensure web applications do not redirect users to internal, unvalidated addresses."
                                                .into(),
                                        timestamp: now_utc,
                                    });
                                    break;
                                }
                            }
                        } else {
                            break;
                        }
                    } else {
                        // Non-redirect response on HTTP
                        if current_scheme == "http" && status == 200 {
                            findings.push(HttpFinding {
                                id: "http.redirect.plain-to-https-missing".into(),
                                severity: HttpFindingSeverity::Medium,
                                confidence: "Confirmed".into(),
                                title: "Plaintext HTTP Endpoint Missing HTTPS Redirection".into(),
                                endpoint: current_url.clone(),
                                evidence: format!(
                                    "HTTP port {http_port} served 200 OK without redirecting to HTTPS."
                                ),
                                recommendation:
                                    "Configure web server to redirect all HTTP requests to HTTPS with 301 Moved Permanently."
                                        .into(),
                                timestamp: now_utc,
                            });
                        }
                        break;
                    }
                }
                Err(err) => {
                    error_diag = Some(format!("HTTP request failed: {err}"));
                    break;
                }
            }
        }

        // ---------------------------------------------------------------------
        // Phase 2: Assess HTTPS Endpoint Directly
        // ---------------------------------------------------------------------
        let https_target_port = https_port.unwrap_or(443);
        let canceled = cancel_token.is_some_and(|c| c.load(Ordering::Relaxed));
        if config.probe_https && !canceled {
            let mut https_pinned = pinned.clone();
            https_pinned.pinned_addr = SocketAddr::new(pinned.pinned_addr.ip(), https_target_port);

            let https_url = format!(
                "https://{}:{}/",
                https_pinned.sni_hostname, https_target_port
            );

            match Self::execute_single_request(&https_pinned, https_target_port, "/", true, config)
            {
                Ok(snapshot) => {
                    https_available = true;

                    // Extract cookies from HTTPS response
                    for raw_cookie in snapshot.headers_matching("set-cookie") {
                        if let Some(parsed) = HttpCookie::parse(raw_cookie) {
                            if !observed_cookies.contains(&parsed) {
                                observed_cookies.push(parsed);
                            }
                        }
                    }

                    responses.push(snapshot);
                }
                Err(e) => {
                    findings.push(HttpFinding {
                        id: "http.https.unavailable".into(),
                        severity: HttpFindingSeverity::Medium,
                        confidence: "Confirmed".into(),
                        title: "HTTPS Service Unavailable".into(),
                        endpoint: https_url,
                        evidence: format!(
                            "Failed to negotiate TLS on port {https_target_port}: {e}"
                        ),
                        recommendation:
                            "Enable and configure TLS encryption on port 443 for secure transport."
                                .into(),
                        timestamp: now_utc,
                    });
                }
            }
        }

        // ---------------------------------------------------------------------
        // Phase 3: Evaluate Header & Cookie Security Properties
        // ---------------------------------------------------------------------
        let mut hsts_enabled = false;
        let mut hsts_include_subdomains = false;
        let mut hsts_preload = false;
        let mut csp_present = false;
        let mut x_content_type_options_nosniff = false;
        let mut x_frame_options = None;
        let mut referrer_policy = None;
        let mut permissions_policy = None;
        let mut server_header = None;
        let mut server_version_disclosed = false;

        // Analyze primary response (prefer HTTPS if available, otherwise latest response)
        let primary_resp = responses.iter().find(|r| r.is_tls).or(responses.last());

        if let Some(resp) = primary_resp {
            let ep = &resp.url;

            // 1. Strict-Transport-Security (HSTS)
            if let Some(hsts) = resp.header("strict-transport-security") {
                if resp.is_tls {
                    hsts_enabled = true;
                    let lower = hsts.to_ascii_lowercase();
                    if lower.contains("includesubdomains") {
                        hsts_include_subdomains = true;
                    } else {
                        findings.push(HttpFinding {
                            id: "http.headers.hsts-missing-subdomains".into(),
                            severity: HttpFindingSeverity::Info,
                            confidence: "Confirmed".into(),
                            title: "HSTS Header Missing includeSubDomains Directive".into(),
                            endpoint: ep.clone(),
                            evidence: format!("Strict-Transport-Security: {hsts}"),
                            recommendation:
                                "Add includeSubDomains directive to HSTS policy to protect all subdomains."
                                    .into(),
                            timestamp: now_utc,
                        });
                    }

                    if lower.contains("preload") {
                        hsts_preload = true;
                    }

                    // Check max-age duration
                    if let Some(max_age_str) = lower.split("max-age=").nth(1) {
                        let digits: String = max_age_str
                            .chars()
                            .take_while(|c| c.is_ascii_digit())
                            .collect();
                        if let Ok(secs) = digits.parse::<u64>() {
                            if secs < 10_368_000 {
                                // Less than 120 days
                                findings.push(HttpFinding {
                                    id: "http.headers.hsts-short-duration".into(),
                                    severity: HttpFindingSeverity::Low,
                                    confidence: "Confirmed".into(),
                                    title: "HSTS max-age Duration Too Short".into(),
                                    endpoint: ep.clone(),
                                    evidence: format!(
                                        "max-age={secs} seconds (less than recommended 10368000s / 120 days)"
                                    ),
                                    recommendation:
                                        "Increase HSTS max-age to at least 31536000 (1 year) for production services."
                                            .into(),
                                    timestamp: now_utc,
                                });
                            }
                        }
                    }
                } else {
                    findings.push(HttpFinding {
                        id: "http.headers.hsts-over-http".into(),
                        severity: HttpFindingSeverity::Low,
                        confidence: "Confirmed".into(),
                        title: "HSTS Header Sent Over Insecure Plaintext HTTP".into(),
                        endpoint: ep.clone(),
                        evidence: format!("Strict-Transport-Security: {hsts}"),
                        recommendation:
                            "RFC 6797 stipulates HSTS headers must only be emitted over secure HTTPS connections."
                                .into(),
                        timestamp: now_utc,
                    });
                }
            } else if resp.is_tls {
                findings.push(HttpFinding {
                    id: "http.headers.missing-hsts".into(),
                    severity: HttpFindingSeverity::Medium,
                    confidence: "Confirmed".into(),
                    title: "Missing HTTP Strict Transport Security (HSTS) Header".into(),
                    endpoint: ep.clone(),
                    evidence:
                        "Strict-Transport-Security header is absent in HTTPS server response."
                            .into(),
                    recommendation:
                        "Configure 'Strict-Transport-Security: max-age=31536000; includeSubDomains' on all HTTPS endpoints."
                            .into(),
                    timestamp: now_utc,
                });
            }

            // 2. Content-Security-Policy (CSP)
            if let Some(csp) = resp.header("content-security-policy") {
                csp_present = true;
                let lower = csp.to_ascii_lowercase();
                if lower.contains("'unsafe-inline'") || lower.contains("'unsafe-eval'") {
                    findings.push(HttpFinding {
                        id: "http.headers.csp-unsafe".into(),
                        severity: HttpFindingSeverity::Low,
                        confidence: "Confirmed".into(),
                        title: "Content Security Policy Contains Unsafe Directives".into(),
                        endpoint: ep.clone(),
                        evidence: format!("CSP includes unsafe execution keyword: {csp}"),
                        recommendation:
                            "Remove 'unsafe-inline' and 'unsafe-eval' directives; use cryptographic nonces or hashes."
                                .into(),
                        timestamp: now_utc,
                    });
                }
            } else {
                findings.push(HttpFinding {
                    id: "http.headers.missing-csp".into(),
                    severity: HttpFindingSeverity::Medium,
                    confidence: "Confirmed".into(),
                    title: "Missing Content-Security-Policy (CSP) Header".into(),
                    endpoint: ep.clone(),
                    evidence: "Content-Security-Policy header is absent.".into(),
                    recommendation:
                        "Implement a strict Content-Security-Policy to mitigate Cross-Site Scripting (XSS) and code injection."
                            .into(),
                    timestamp: now_utc,
                });
            }

            // 3. X-Content-Type-Options
            if let Some(xcto) = resp.header("x-content-type-options") {
                if xcto.trim().eq_ignore_ascii_case("nosniff") {
                    x_content_type_options_nosniff = true;
                } else {
                    findings.push(HttpFinding {
                        id: "http.headers.missing-x-content-type-options".into(),
                        severity: HttpFindingSeverity::Low,
                        confidence: "Confirmed".into(),
                        title: "Invalid X-Content-Type-Options Header".into(),
                        endpoint: ep.clone(),
                        evidence: format!("X-Content-Type-Options: {xcto}"),
                        recommendation:
                            "Set 'X-Content-Type-Options: nosniff' to prevent MIME type sniffing."
                                .into(),
                        timestamp: now_utc,
                    });
                }
            } else {
                findings.push(HttpFinding {
                    id: "http.headers.missing-x-content-type-options".into(),
                    severity: HttpFindingSeverity::Low,
                    confidence: "Confirmed".into(),
                    title: "Missing X-Content-Type-Options Header".into(),
                    endpoint: ep.clone(),
                    evidence: "X-Content-Type-Options header is absent.".into(),
                    recommendation: "Add 'X-Content-Type-Options: nosniff' to response headers."
                        .into(),
                    timestamp: now_utc,
                });
            }

            // 4. X-Frame-Options & CSP frame-ancestors
            let has_frame_ancestors = resp
                .header("content-security-policy")
                .is_some_and(|c| c.to_ascii_lowercase().contains("frame-ancestors"));

            if let Some(xfo) = resp.header("x-frame-options") {
                x_frame_options = Some(xfo.to_string());
                let val = xfo.trim().to_ascii_uppercase();
                if val != "DENY" && val != "SAMEORIGIN" {
                    findings.push(HttpFinding {
                        id: "http.headers.weak-x-frame-options".into(),
                        severity: HttpFindingSeverity::Low,
                        confidence: "Confirmed".into(),
                        title: "Weak X-Frame-Options Configuration".into(),
                        endpoint: ep.clone(),
                        evidence: format!("X-Frame-Options: {xfo}"),
                        recommendation:
                            "Configure 'X-Frame-Options: DENY' or 'SAMEORIGIN' to protect against clickjacking."
                                .into(),
                        timestamp: now_utc,
                    });
                }
            } else if !has_frame_ancestors {
                findings.push(HttpFinding {
                    id: "http.headers.missing-x-frame-options".into(),
                    severity: HttpFindingSeverity::Medium,
                    confidence: "Confirmed".into(),
                    title: "Missing Clickjacking Protection (X-Frame-Options)".into(),
                    endpoint: ep.clone(),
                    evidence:
                        "Neither X-Frame-Options nor CSP frame-ancestors directive was detected."
                            .into(),
                    recommendation:
                        "Configure 'X-Frame-Options: DENY' or CSP 'frame-ancestors: 'none'' to prevent clickjacking."
                            .into(),
                    timestamp: now_utc,
                });
            }

            // 5. Referrer-Policy
            if let Some(rp) = resp.header("referrer-policy") {
                referrer_policy = Some(rp.to_string());
                let lower = rp.trim().to_ascii_lowercase();
                if lower == "unsafe-url" || lower == "no-referrer-when-downgrade" {
                    findings.push(HttpFinding {
                        id: "http.headers.weak-referrer-policy".into(),
                        severity: HttpFindingSeverity::Low,
                        confidence: "Confirmed".into(),
                        title: "Weak Referrer-Policy Configuration".into(),
                        endpoint: ep.clone(),
                        evidence: format!("Referrer-Policy: {rp}"),
                        recommendation:
                            "Configure 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'."
                                .into(),
                        timestamp: now_utc,
                    });
                }
            } else {
                findings.push(HttpFinding {
                    id: "http.headers.missing-referrer-policy".into(),
                    severity: HttpFindingSeverity::Low,
                    confidence: "Confirmed".into(),
                    title: "Missing Referrer-Policy Header".into(),
                    endpoint: ep.clone(),
                    evidence: "Referrer-Policy header is absent.".into(),
                    recommendation:
                        "Set 'Referrer-Policy: strict-origin-when-cross-origin' to prevent unintended referrer leakage."
                            .into(),
                    timestamp: now_utc,
                });
            }

            // 6. Permissions-Policy
            if let Some(pp) = resp.header("permissions-policy") {
                permissions_policy = Some(pp.to_string());
            } else if resp.header("feature-policy").is_none() {
                findings.push(HttpFinding {
                    id: "http.headers.missing-permissions-policy".into(),
                    severity: HttpFindingSeverity::Info,
                    confidence: "Confirmed".into(),
                    title: "Missing Permissions-Policy Header".into(),
                    endpoint: ep.clone(),
                    evidence: "Permissions-Policy header is absent.".into(),
                    recommendation:
                        "Configure Permissions-Policy to restrict unauthorized browser APIs (camera, microphone, geolocation)."
                            .into(),
                    timestamp: now_utc,
                });
            }

            // 7. Server & Framework Version Disclosure
            if let Some(srv) = resp.header("server") {
                server_header = Some(srv.to_string());
                if Self::contains_version_number(srv) {
                    server_version_disclosed = true;
                    findings.push(HttpFinding {
                        id: "http.server.version-disclosed".into(),
                        severity: HttpFindingSeverity::Low,
                        confidence: "Confirmed".into(),
                        title: "Web Server Software Version Disclosed".into(),
                        endpoint: ep.clone(),
                        evidence: format!("Server: {srv}"),
                        recommendation:
                            "Configure server tokens to hide specific software version numbers."
                                .into(),
                        timestamp: now_utc,
                    });
                }
            }

            if let Some(xpb) = resp.header("x-powered-by") {
                findings.push(HttpFinding {
                    id: "http.framework.version-disclosed".into(),
                    severity: HttpFindingSeverity::Low,
                    confidence: "Confirmed".into(),
                    title: "Application Framework Disclosed in X-Powered-By".into(),
                    endpoint: ep.clone(),
                    evidence: format!("X-Powered-By: {xpb}"),
                    recommendation:
                        "Disable X-Powered-By header in application or proxy configuration.".into(),
                    timestamp: now_utc,
                });
            }

            // 8. Insecure Cookies Inspection
            for cookie in &observed_cookies {
                if resp.is_tls && !cookie.has_secure {
                    findings.push(HttpFinding {
                        id: "http.cookie.missing-secure".into(),
                        severity: HttpFindingSeverity::Medium,
                        confidence: "Confirmed".into(),
                        title: format!("Cookie '{}' Missing Secure Attribute", cookie.name),
                        endpoint: ep.clone(),
                        evidence: format!("Set-Cookie name='{}' lacks Secure flag", cookie.name),
                        recommendation:
                            "Set the 'Secure' attribute on all cookies transmitted over HTTPS."
                                .into(),
                        timestamp: now_utc,
                    });
                }

                if !cookie.has_httponly {
                    findings.push(HttpFinding {
                        id: "http.cookie.missing-httponly".into(),
                        severity: HttpFindingSeverity::Medium,
                        confidence: "Confirmed".into(),
                        title: format!("Cookie '{}' Missing HttpOnly Attribute", cookie.name),
                        endpoint: ep.clone(),
                        evidence: format!("Set-Cookie name='{}' lacks HttpOnly flag", cookie.name),
                        recommendation:
                            "Set the 'HttpOnly' attribute to prevent cookie access from JavaScript."
                                .into(),
                        timestamp: now_utc,
                    });
                }

                if cookie.same_site.is_none() {
                    findings.push(HttpFinding {
                        id: "http.cookie.missing-samesite".into(),
                        severity: HttpFindingSeverity::Low,
                        confidence: "Confirmed".into(),
                        title: format!("Cookie '{}' Missing SameSite Attribute", cookie.name),
                        endpoint: ep.clone(),
                        evidence: format!(
                            "Set-Cookie name='{}' lacks SameSite attribute",
                            cookie.name
                        ),
                        recommendation:
                            "Set 'SameSite=Lax' or 'SameSite=Strict' to mitigate Cross-Site Request Forgery (CSRF)."
                                .into(),
                        timestamp: now_utc,
                    });
                }
            }
        }

        let final_url = redirect_chain
            .last()
            .cloned()
            .unwrap_or_else(|| initial_url.clone());

        Ok(HttpPostureAssessment {
            target_host,
            http_port,
            https_port,
            initial_url,
            final_url,
            redirect_chain,
            https_available,
            http_to_https_redirect,
            hsts_enabled,
            hsts_include_subdomains,
            hsts_preload,
            csp_present,
            x_content_type_options_nosniff,
            x_frame_options,
            referrer_policy,
            permissions_policy,
            server_header,
            server_version_disclosed,
            observed_cookies,
            findings,
            responses,
            assessment_timestamp: now_utc,
            error_diagnostic: error_diag,
        })
    }

    /// Connects to the pinned socket address and executes a bounded HTTP request.
    fn execute_single_request(
        pinned: &PinnedTarget,
        port: u16,
        path: &str,
        is_tls: bool,
        config: &HttpAssessConfig,
    ) -> Result<HttpResponseSnapshot, String> {
        let start = Instant::now();
        let target_addr = SocketAddr::new(pinned.pinned_addr.ip(), port);

        let mut tcp_stream = TcpStream::connect_timeout(&target_addr, config.connect_timeout)
            .map_err(|e| format!("TCP connection to {target_addr} failed: {e}"))?;

        let _ = tcp_stream.set_read_timeout(Some(config.read_timeout));
        let _ = tcp_stream.set_write_timeout(Some(config.connect_timeout));

        let host_header = if (is_tls && port == 443) || (!is_tls && port == 80) {
            pinned.sni_hostname.clone()
        } else {
            format!("{}:{}", pinned.sni_hostname, port)
        };

        let request = format!(
            "HEAD {path} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: {}\r\nAccept: */*\r\nConnection: close\r\n\r\n",
            config.user_agent
        );

        let scheme = if is_tls { "https" } else { "http" };
        let url = format!("{scheme}://{host_header}{path}");

        if is_tls {
            let server_name = ServerName::try_from(pinned.sni_hostname.clone())
                .map_err(|e| format!("Invalid SNI hostname '{}': {e}", pinned.sni_hostname))?;

            let verifier = Arc::new(ObservationCertVerifier);
            let client_config = ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .map_err(|e| format!("TLS version configuration error: {e}"))?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();

            let conn = ClientConnection::new(Arc::new(client_config), server_name)
                .map_err(|e| format!("TLS client initialization error: {e}"))?;

            let mut tls_stream = StreamOwned::new(conn, tcp_stream);

            tls_stream
                .write_all(request.as_bytes())
                .map_err(|e| format!("TLS write error: {e}"))?;
            let _ = tls_stream.flush();

            let parsed = Self::read_and_parse_response(
                &mut tls_stream,
                config.max_response_headers_bytes,
                config.max_response_body_bytes,
            )?;

            // If HEAD was rejected with 405 Method Not Allowed, retry with bounded GET
            if parsed.status_code == 405 {
                let get_req = format!(
                    "GET {path} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: {}\r\nAccept: */*\r\nConnection: close\r\n\r\n",
                    config.user_agent
                );
                // Reconnect for GET
                if let Ok(new_tcp) =
                    TcpStream::connect_timeout(&target_addr, config.connect_timeout)
                {
                    let _ = new_tcp.set_read_timeout(Some(config.read_timeout));
                    if let Ok(new_conn) = ClientConnection::new(
                        Arc::new(
                            ClientConfig::builder_with_provider(
                                rustls::crypto::ring::default_provider().into(),
                            )
                            .with_safe_default_protocol_versions()
                            .unwrap()
                            .dangerous()
                            .with_custom_certificate_verifier(Arc::new(ObservationCertVerifier))
                            .with_no_client_auth(),
                        ),
                        ServerName::try_from(pinned.sni_hostname.clone()).unwrap(),
                    ) {
                        let mut new_tls = StreamOwned::new(new_conn, new_tcp);
                        if new_tls.write_all(get_req.as_bytes()).is_ok() {
                            let _ = new_tls.flush();
                            if let Ok(g_parsed) = Self::read_and_parse_response(
                                &mut new_tls,
                                config.max_response_headers_bytes,
                                config.max_response_body_bytes,
                            ) {
                                return Ok(HttpResponseSnapshot {
                                    url,
                                    is_tls,
                                    status_code: g_parsed.status_code,
                                    http_version: g_parsed.proto,
                                    headers: g_parsed.headers,
                                    body_preview: g_parsed.body_preview,
                                    latency_ms: start.elapsed().as_millis() as u64,
                                });
                            }
                        }
                    }
                }
            }

            Ok(HttpResponseSnapshot {
                url,
                is_tls,
                status_code: parsed.status_code,
                http_version: parsed.proto,
                headers: parsed.headers,
                body_preview: parsed.body_preview,
                latency_ms: start.elapsed().as_millis() as u64,
            })
        } else {
            tcp_stream
                .write_all(request.as_bytes())
                .map_err(|e| format!("TCP write error: {e}"))?;
            let _ = tcp_stream.flush();

            let parsed = Self::read_and_parse_response(
                &mut tcp_stream,
                config.max_response_headers_bytes,
                config.max_response_body_bytes,
            )?;

            // If HEAD was rejected with 405 Method Not Allowed, retry with bounded GET
            if parsed.status_code == 405 {
                let get_req = format!(
                    "GET {path} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: {}\r\nAccept: */*\r\nConnection: close\r\n\r\n",
                    config.user_agent
                );
                if let Ok(mut new_tcp) =
                    TcpStream::connect_timeout(&target_addr, config.connect_timeout)
                {
                    let _ = new_tcp.set_read_timeout(Some(config.read_timeout));
                    if new_tcp.write_all(get_req.as_bytes()).is_ok() {
                        let _ = new_tcp.flush();
                        if let Ok(g_parsed) = Self::read_and_parse_response(
                            &mut new_tcp,
                            config.max_response_headers_bytes,
                            config.max_response_body_bytes,
                        ) {
                            return Ok(HttpResponseSnapshot {
                                url,
                                is_tls,
                                status_code: g_parsed.status_code,
                                http_version: g_parsed.proto,
                                headers: g_parsed.headers,
                                body_preview: g_parsed.body_preview,
                                latency_ms: start.elapsed().as_millis() as u64,
                            });
                        }
                    }
                }
            }

            Ok(HttpResponseSnapshot {
                url,
                is_tls,
                status_code: parsed.status_code,
                http_version: parsed.proto,
                headers: parsed.headers,
                body_preview: parsed.body_preview,
                latency_ms: start.elapsed().as_millis() as u64,
            })
        }
    }

    /// Reads bounded response bytes from the stream, splitting into header and body sections.
    fn read_and_parse_response<S: Read>(
        stream: &mut S,
        max_header_bytes: usize,
        max_body_bytes: usize,
    ) -> Result<ParsedHttpResponse, String> {
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 1024];
        let mut header_end_idx = None;

        while buffer.len() < max_header_bytes {
            match stream.read(&mut chunk) {
                Ok(0) => break, // EOF
                Ok(n) => {
                    buffer.extend_from_slice(&chunk[..n]);
                    // Check for header delimiter \r\n\r\n or \n\n
                    if let Some(pos) = Self::find_subsequence(&buffer, b"\r\n\r\n") {
                        header_end_idx = Some((pos, 4));
                        break;
                    } else if let Some(pos) = Self::find_subsequence(&buffer, b"\n\n") {
                        header_end_idx = Some((pos, 2));
                        break;
                    }
                }
                Err(e) => {
                    if !buffer.is_empty() {
                        // Attempt to parse whatever was read before error/timeout
                        break;
                    }
                    return Err(format!("Socket read error: {e}"));
                }
            }
        }

        if buffer.is_empty() {
            return Err("Empty response received from server".into());
        }

        let (header_bytes, body_start_bytes) = if let Some((pos, delim_len)) = header_end_idx {
            (&buffer[..pos], &buffer[pos + delim_len..])
        } else {
            (&buffer[..], &[][..])
        };

        let header_str = String::from_utf8_lossy(header_bytes);
        let mut lines = header_str.lines();

        // Parse status line: HTTP/1.1 200 OK
        let status_line = lines.next().ok_or("Missing HTTP status line")?;
        let mut status_parts = status_line.split_whitespace();
        let proto = status_parts.next().unwrap_or("HTTP/1.1").to_string();
        let status_code: u16 = status_parts
            .next()
            .and_then(|s| s.parse().ok())
            .unwrap_or(200);

        let mut headers = Vec::new();
        for line in lines {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Some((k, v)) = trimmed.split_once(':') {
                headers.push((k.trim().to_string(), v.trim().to_string()));
            }
        }

        // Bounded body preview if any body bytes were received
        let mut body_bytes = body_start_bytes.to_vec();
        if body_bytes.len() < max_body_bytes {
            let mut remaining = vec![0u8; max_body_bytes - body_bytes.len()];
            if let Ok(n) = stream.read(&mut remaining) {
                if n > 0 {
                    body_bytes.extend_from_slice(&remaining[..n]);
                }
            }
        }

        let body_preview = if body_bytes.is_empty() {
            None
        } else {
            Some(String::from_utf8_lossy(&body_bytes).to_string())
        };

        Ok(ParsedHttpResponse {
            status_code,
            proto,
            headers,
            body_preview,
        })
    }

    /// Finds the first index of a byte needle in a haystack.
    fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack
            .windows(needle.len())
            .position(|window| window == needle)
    }

    /// Extracts path and query from a URL.
    fn extract_path_from_url(url: &str) -> String {
        if let Some((_, rest)) = url.split_once("://") {
            if let Some(slash_idx) = rest.find('/') {
                return rest[slash_idx..].to_string();
            }
        } else if url.starts_with('/') {
            return url.to_string();
        }
        "/".to_string()
    }

    /// Tests whether a string contains specific software version numbers.
    fn contains_version_number(s: &str) -> bool {
        // Look for patterns like /1.2, /2.4.52, or space followed by digits.digits
        let bytes = s.as_bytes();
        for i in 0..bytes.len() {
            if (bytes[i] == b'/' || bytes[i] == b' ' || bytes[i] == b'-')
                && i + 1 < bytes.len()
                && bytes[i + 1].is_ascii_digit()
            {
                // Check if followed by dot and digits
                let rest = &s[i + 1..];
                if rest.contains('.') {
                    return true;
                }
            }
        }
        false
    }
}
