//! # OpenAudit Network
//!
//! Network perimeter scanning foundation providing canonical target parsing,
//! scope authorization, SSRF protection, and pinned DNS resolution.

pub mod error;
pub mod pinned;
pub mod redirect;
pub mod resolver;
pub mod scanner;
pub mod scope;
pub mod service;
pub mod target;
pub mod tls;

pub use error::NetworkError;
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
