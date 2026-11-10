//! # OpenAudit Core
//!
//! `openaudit-core` defines the foundational domain models, typed identifiers,
//! severity definitions, evidence structures, and error primitives used across
//! the OpenAudit platform.
//!
//! This crate is intentionally decoupled from transport protocols, database drivers,
//! and operating system specific system calls.

#![doc(html_root_url = "https://docs.rs/openaudit-core/0.1.0-alpha.0")]

pub mod asset;
pub mod error;
pub mod evidence;
pub mod finding;
pub mod id;
pub mod protocol;
pub mod scan;
pub mod severity;

pub use asset::{Asset, AssetType, Criticality, Environment};
pub use error::DomainError;
pub use evidence::{Evidence, EvidencePayload, EvidenceType, MAX_EVIDENCE_SIZE_BYTES};
pub use finding::{Finding, FindingStatus, Fingerprint};
pub use id::{AgentId, AssetId, EvidenceId, FindingId, OrganizationId, ScanId, ScanJobId};
pub use scan::{AssessmentType, JobStatus, Scan, ScanJob, ScanStatus, ScanSummary, TriggerType};
pub use severity::Severity;

/// Returns the current version of the OpenAudit core domain library.
///
/// # Examples
///
/// ```
/// use openaudit_core::{version, AssetId, Fingerprint, ScanSummary, Severity};
///
/// assert_eq!(version(), "0.1.0-alpha.0");
///
/// let asset_id = AssetId::new();
/// let fp = Fingerprint::compute(asset_id, "ssh.permit-root-login", "/etc/ssh/sshd_config");
/// assert_eq!(fp.as_str().len(), 64);
///
/// let mut summary = ScanSummary::default();
/// summary.record(Severity::Critical);
/// summary.record(Severity::High);
/// assert_eq!(summary.total(), 2);
/// ```
#[must_use]
pub const fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_not_empty() {
        assert_ne!(version(), "");
    }
}
