//! # OpenAudit Network
//!
//! Network perimeter scanning foundation providing canonical target parsing,
//! scope authorization, SSRF protection, and pinned DNS resolution.
//!
//! # Examples
//!
//! ```
//! use openaudit_network::{CanonicalTarget, IpCidr};
//! use std::net::IpAddr;
//!
//! let target = CanonicalTarget::parse("https://example.com:8443/health").unwrap();
//! assert_eq!(target.normalized_host, "example.com");
//! assert_eq!(target.port, Some(8443));
//!
//! let cidr = IpCidr::parse("10.20.0.0/16").unwrap();
//! assert!(cidr.contains("10.20.5.99".parse::<IpAddr>().unwrap()));
//! ```

pub mod assessment;
pub mod error;
pub mod http;
pub mod pinned;
pub mod redirect;
pub mod resolver;
pub mod scanner;
pub mod scope;
pub mod service;
pub mod target;
pub mod tls;

pub use assessment::{
    DiscoveredEndpointService, NetworkAssessmentReport, NetworkFindingSeverity,
    PerimeterAssessConfig, PerimeterAssessor, PerimeterProfile, UnifiedNetworkFinding,
};
pub use error::NetworkError;
pub use http::{
    HttpAssessConfig, HttpCookie, HttpFinding, HttpFindingSeverity, HttpPostureAssessment,
    HttpPostureAssessor, HttpResponseSnapshot,
};
pub use pinned::PinnedTarget;
pub use redirect::RedirectValidator;
pub use resolver::{DnsResolver, SystemDnsResolver};
pub use scanner::{PortScanResult, PortStatus, TcpScanConfig, TcpScanner};
pub use scope::{IpCidr, IpClassification, ScopeDecision, TargetScope};
pub use service::{
    IdentificationConfidence, IdentifiedProtocol, ServiceIdentification, ServiceIdentifier,
    ServiceIdentifyConfig,
};
pub use target::{CanonicalTarget, TargetType};
pub use tls::{
    CertificateMetadata, CertificateTrustStatus, CipherSecurityRating, NegotiatedCipherSuite,
    TlsAssessConfig, TlsAssessor, TlsFinding, TlsFindingSeverity, TlsPostureAssessment, TlsVersion,
};
