//! End-to-end network perimeter assessment engine and unified report model.
//!
//! Orchestrates the complete agentless network auditing workflow:
//! 1. Canonical target normalization and strict CIDR/SSRF scope validation.
//! 2. Target IP resolution and address pinning.
//! 3. Bounded, real-socket TCP port discovery.
//! 4. Safe service identification using confirmed protocol evidence.
//! 5. TLS posture assessment and certificate inspection.
//! 6. HTTP and HTTPS security headers, cookies, and redirect assessment.
//! 7. Unified report compilation with severity-ranked findings and clear architectural disclaimers.

use crate::error::NetworkError;
use crate::http::{
    HttpAssessConfig, HttpFindingSeverity, HttpPostureAssessment, HttpPostureAssessor,
};
use crate::resolver::{resolve_and_pin, DnsResolver};
use crate::scanner::{PortStatus, TcpScanConfig, TcpScanner};
use crate::scope::TargetScope;
use crate::service::{
    IdentificationConfidence, IdentifiedProtocol, ServiceIdentification, ServiceIdentifier,
    ServiceIdentifyConfig,
};
use crate::target::CanonicalTarget;
use crate::tls::{TlsAssessConfig, TlsAssessor, TlsFindingSeverity, TlsPostureAssessment};
use chrono::{DateTime, Utc};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// Severity classification for unified network perimeter findings.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum NetworkFindingSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl From<HttpFindingSeverity> for NetworkFindingSeverity {
    fn from(s: HttpFindingSeverity) -> Self {
        match s {
            HttpFindingSeverity::Critical => Self::Critical,
            HttpFindingSeverity::High => Self::High,
            HttpFindingSeverity::Medium => Self::Medium,
            HttpFindingSeverity::Low => Self::Low,
            HttpFindingSeverity::Info => Self::Info,
        }
    }
}

impl From<TlsFindingSeverity> for NetworkFindingSeverity {
    fn from(s: TlsFindingSeverity) -> Self {
        match s {
            TlsFindingSeverity::Critical => Self::Critical,
            TlsFindingSeverity::High => Self::High,
            TlsFindingSeverity::Medium => Self::Medium,
            TlsFindingSeverity::Low => Self::Low,
            TlsFindingSeverity::Info => Self::Info,
        }
    }
}

/// A unified finding discovered during perimeter network evaluation.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UnifiedNetworkFinding {
    /// Stable finding rule identifier.
    pub id: String,
    /// Severity classification.
    pub severity: NetworkFindingSeverity,
    /// Confidence level ("Confirmed", "Likely", "Tentative").
    pub confidence: String,
    /// Finding category (e.g. "TLS & Cryptography", "HTTP Security Headers", "Network Exposure").
    pub category: String,
    /// Short human-readable title.
    pub title: String,
    /// Affected endpoint (e.g. "https://example.com:443/").
    pub endpoint: String,
    /// Concrete evidence observed on the network.
    pub evidence: String,
    /// Specific remediation guidance.
    pub recommendation: String,
    /// Timestamp when finding was discovered.
    pub timestamp: DateTime<Utc>,
}

/// Discovered service information for an open port.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DiscoveredEndpointService {
    /// Port number.
    pub port: u16,
    /// Reachability status.
    pub status: PortStatus,
    /// Detected protocol.
    pub protocol: IdentifiedProtocol,
    /// Canonical service name (e.g. "HTTP", "HTTPS", "SSH").
    pub service_name: String,
    /// Identification confidence.
    pub confidence: IdentificationConfidence,
    /// Protocol evidence captured.
    pub evidence: Option<String>,
    /// Protocol banner or server greeting, if observed.
    pub banner: Option<String>,
}

/// Comprehensive report produced by the agentless network perimeter assessment.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NetworkAssessmentReport {
    /// Raw target input supplied by operator.
    pub raw_target: String,
    /// Normalized canonical hostname or IP.
    pub canonical_host: String,
    /// Pinned destination IP address (immune to DNS rebinding).
    pub pinned_ip: String,
    /// Scope classification of the destination address.
    pub ip_classification: String,
    /// Total number of ports evaluated.
    pub ports_scanned: usize,
    /// Number of open ports discovered.
    pub open_ports_count: usize,
    /// Details of all evaluated endpoints.
    pub endpoints: Vec<DiscoveredEndpointService>,
    /// TLS posture assessment results, if a TLS endpoint was discovered.
    pub tls_assessment: Option<TlsPostureAssessment>,
    /// HTTP security posture results, if an HTTP or HTTPS endpoint was discovered.
    pub http_assessment: Option<HttpPostureAssessment>,
    /// Severity-ranked collection of all discovered security findings.
    pub findings: Vec<UnifiedNetworkFinding>,
    /// Total assessment runtime in milliseconds.
    pub duration_ms: u64,
    /// Assessment completion timestamp.
    pub completed_at: DateTime<Utc>,
    /// Critical architectural disclaimer distinguishing network assessment from OS auditing.
    pub architecture_disclaimer: String,
}

/// Scan profile presets for perimeter network discovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PerimeterProfile {
    /// Standard conservative web ports (80, 443, 8080, 8443, 22).
    Conservative,
    /// Common perimeter services (20 well-known server ports).
    Standard,
    /// Deep inspection covering common administration, database, and cache services.
    Deep,
}

impl PerimeterProfile {
    /// Returns default ports associated with this profile.
    #[must_use]
    pub fn default_ports(&self) -> Vec<u16> {
        match self {
            Self::Conservative => vec![80, 443, 8080, 8443, 22],
            Self::Standard => vec![
                21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 8000,
                8080, 8443, 8888, 9000,
            ],
            Self::Deep => vec![
                21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587, 993, 995,
                1433, 1521, 2049, 2375, 2376, 3000, 3306, 3389, 5000, 5432, 5900, 6379, 8000, 8080,
                8443, 8888, 9000, 9200, 11211, 27017,
            ],
        }
    }
}

/// Comprehensive configuration for integrated perimeter assessment.
#[derive(Debug, Clone, Default)]
pub struct PerimeterAssessConfig {
    /// TCP discovery parameters.
    pub tcp_config: TcpScanConfig,
    /// Service identification parameters.
    pub service_config: ServiceIdentifyConfig,
    /// TLS evaluation parameters.
    pub tls_config: TlsAssessConfig,
    /// HTTP posture parameters.
    pub http_config: HttpAssessConfig,
}

/// Orchestrator for agentless network perimeter security evaluation.
#[derive(Debug, Default)]
pub struct PerimeterAssessor;

impl PerimeterAssessor {
    /// Runs a complete, unified perimeter assessment across target parsing, TCP discovery,
    /// service identification, TLS evaluation, and HTTP security posture.
    pub fn assess<R: DnsResolver>(
        target_input: &str,
        ports: &[u16],
        scope: &TargetScope,
        resolver: &R,
        config: &PerimeterAssessConfig,
        cancel_token: Option<Arc<AtomicBool>>,
    ) -> Result<NetworkAssessmentReport, NetworkError> {
        let start_time = Instant::now();
        let now_utc = Utc::now();

        // Check cancellation
        if let Some(ref cancel) = cancel_token {
            if cancel.load(Ordering::Relaxed) {
                return Err(NetworkError::TargetParse(
                    "Assessment canceled by operator".into(),
                ));
            }
        }

        // ---------------------------------------------------------------------
        // Step 1: Parse and normalize target
        // ---------------------------------------------------------------------
        let canonical = CanonicalTarget::parse(target_input)?;

        // ---------------------------------------------------------------------
        // Step 2: Resolve and pin destination IP (SSRF & Rebinding Protection)
        // ---------------------------------------------------------------------
        let default_port = ports.first().copied().unwrap_or(80);
        let pinned = resolve_and_pin(&canonical, scope, resolver, default_port)?;

        // ---------------------------------------------------------------------
        // Step 3: Bounded TCP Port Discovery
        // ---------------------------------------------------------------------
        let mut tcp_cfg = config.tcp_config.clone();
        tcp_cfg.ports = ports.to_vec();

        let scan_results = TcpScanner::scan(&pinned, &tcp_cfg, cancel_token.clone())?;

        // ---------------------------------------------------------------------
        // Step 4: Safe Service Identification (Confirmed Protocol Evidence)
        // ---------------------------------------------------------------------
        let service_results = ServiceIdentifier::identify_services(
            &pinned,
            &scan_results,
            &config.service_config,
            cancel_token.clone(),
        )?;

        let mut endpoints = Vec::new();
        let mut open_ports = Vec::new();

        for res in &scan_results {
            if res.status == PortStatus::Open {
                open_ports.push(res.port);
                let ident = service_results
                    .iter()
                    .find(|s| s.port == res.port)
                    .cloned()
                    .unwrap_or_else(|| ServiceIdentification {
                        port: res.port,
                        detected_protocol: IdentifiedProtocol::Unknown,
                        service_name: "Open".into(),
                        confidence: IdentificationConfidence::Inferred,
                        evidence: None,
                        banner: None,
                    });

                endpoints.push(DiscoveredEndpointService {
                    port: res.port,
                    status: res.status,
                    protocol: ident.detected_protocol,
                    service_name: ident.service_name,
                    confidence: ident.confidence,
                    evidence: ident.evidence,
                    banner: ident.banner,
                });
            } else {
                endpoints.push(DiscoveredEndpointService {
                    port: res.port,
                    status: res.status,
                    protocol: IdentifiedProtocol::Unknown,
                    service_name: "Unreachable".into(),
                    confidence: IdentificationConfidence::Inferred,
                    evidence: None,
                    banner: None,
                });
            }
        }

        // ---------------------------------------------------------------------
        // Step 5: TLS Posture Assessment (for TLS/HTTPS endpoints)
        // ---------------------------------------------------------------------
        let tls_port = open_ports
            .iter()
            .find(|&&p| p == 443 || p == 8443)
            .copied()
            .or_else(|| {
                endpoints
                    .iter()
                    .find(|e| {
                        e.status == PortStatus::Open && e.protocol == IdentifiedProtocol::Https
                    })
                    .map(|e| e.port)
            });

        let mut tls_assessment = None;
        if let Some(port) = tls_port {
            if let Ok(report) =
                TlsAssessor::assess(&pinned, port, &config.tls_config, cancel_token.clone())
            {
                tls_assessment = Some(report);
            }
        }

        // ---------------------------------------------------------------------
        // Step 6: HTTP Security Posture Assessment (for Web endpoints)
        // ---------------------------------------------------------------------
        let http_port = open_ports
            .iter()
            .find(|&&p| p == 80 || p == 8080)
            .copied()
            .or_else(|| {
                endpoints
                    .iter()
                    .find(|e| {
                        e.status == PortStatus::Open && e.protocol == IdentifiedProtocol::Http
                    })
                    .map(|e| e.port)
            })
            .unwrap_or(80);

        let https_port = open_ports.iter().find(|&&p| p == 443 || p == 8443).copied();

        let mut http_assessment = None;
        if open_ports.contains(&http_port) || https_port.is_some() {
            let mut http_cfg = config.http_config.clone();
            http_cfg.probe_https = https_port.is_some();

            if let Ok(report) = HttpPostureAssessor::assess(
                &pinned,
                http_port,
                https_port,
                scope,
                resolver,
                &http_cfg,
                cancel_token.as_deref(),
            ) {
                http_assessment = Some(report);
            }
        }

        // ---------------------------------------------------------------------
        // Step 7: Aggregate and Rank Unified Findings
        // ---------------------------------------------------------------------
        let mut unified_findings = Vec::new();

        // Exposure Findings
        for ep in &endpoints {
            if ep.status == PortStatus::Open {
                if ep.port == 21 {
                    unified_findings.push(UnifiedNetworkFinding {
                        id: "network.exposure.ftp".into(),
                        severity: NetworkFindingSeverity::Medium,
                        confidence: "Confirmed".into(),
                        category: "Network Exposure".into(),
                        title: "Insecure FTP Protocol Exposed".into(),
                        endpoint: format!("{}:{}", pinned.sni_hostname, ep.port),
                        evidence: ep
                            .banner
                            .clone()
                            .unwrap_or_else(|| "FTP port 21 is open".into()),
                        recommendation:
                            "Disable unencrypted FTP and migrate to SFTP or TLS-encrypted FTPS."
                                .into(),
                        timestamp: now_utc,
                    });
                } else if ep.port == 23 {
                    unified_findings.push(UnifiedNetworkFinding {
                        id: "network.exposure.telnet".into(),
                        severity: NetworkFindingSeverity::High,
                        confidence: "Confirmed".into(),
                        category: "Network Exposure".into(),
                        title: "Cleartext Telnet Service Exposed".into(),
                        endpoint: format!("{}:{}", pinned.sni_hostname, ep.port),
                        evidence: "Telnet port 23 is open".into(),
                        recommendation:
                            "Immediately disable Telnet and enforce SSH with strong public key authentication."
                                .into(),
                        timestamp: now_utc,
                    });
                }
            }
        }

        // TLS Findings
        if let Some(ref tls) = tls_assessment {
            for f in &tls.findings {
                unified_findings.push(UnifiedNetworkFinding {
                    id: f.id.clone(),
                    severity: NetworkFindingSeverity::from(f.severity),
                    confidence: "Confirmed".into(),
                    category: "TLS & Cryptography".into(),
                    title: f.title.clone(),
                    endpoint: format!("https://{}:{}/", pinned.sni_hostname, tls.target_port),
                    evidence: f.evidence.clone(),
                    recommendation: f.recommendation.clone(),
                    timestamp: now_utc,
                });
            }
        }

        // HTTP Findings
        if let Some(ref http) = http_assessment {
            for f in &http.findings {
                unified_findings.push(UnifiedNetworkFinding {
                    id: f.id.clone(),
                    severity: NetworkFindingSeverity::from(f.severity),
                    confidence: f.confidence.clone(),
                    category: "HTTP Security Headers".into(),
                    title: f.title.clone(),
                    endpoint: f.endpoint.clone(),
                    evidence: f.evidence.clone(),
                    recommendation: f.recommendation.clone(),
                    timestamp: f.timestamp,
                });
            }
        }

        // Sort findings by severity: Critical -> High -> Medium -> Low -> Info
        unified_findings.sort_by(|a, b| a.severity.cmp(&b.severity));

        let duration_ms = start_time.elapsed().as_millis() as u64;

        Ok(NetworkAssessmentReport {
            raw_target: target_input.to_string(),
            canonical_host: canonical.normalized_host,
            pinned_ip: pinned.pinned_addr.ip().to_string(),
            ip_classification: format!("{:?}", pinned.classification),
            ports_scanned: ports.len(),
            open_ports_count: open_ports.len(),
            endpoints,
            tls_assessment,
            http_assessment,
            findings: unified_findings,
            duration_ms,
            completed_at: now_utc,
            architecture_disclaimer:
                "Critical Architectural Distinction: This agentless assessment evaluated externally observable network attributes (open ports, TLS posture, HTTP headers). It cannot and does not determine internal operating system users, permissions, kernel settings, or installed package vulnerabilities. Comprehensive host auditing requires local execution or enrolled OpenAudit agents."
                    .to_string(),
        })
    }
}
