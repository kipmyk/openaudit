//! Security finding models and deduplication fingerprinting.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::str::FromStr;

use crate::error::DomainError;
use crate::id::{AssetId, FindingId, OrganizationId};
use crate::severity::Severity;

/// Deterministic 64-character SHA-256 fingerprint for finding deduplication.
///
/// Computed from:
/// `SHA-256(asset_id || ":" || rule_id || ":" || target)`
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Fingerprint(String);

impl Fingerprint {
    /// Computes a deterministic deduplication fingerprint from its composite inputs.
    #[must_use]
    pub fn compute(asset_id: AssetId, rule_id: &str, check_target: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(asset_id.as_uuid().as_bytes());
        hasher.update(b":");
        hasher.update(rule_id.trim().as_bytes());
        hasher.update(b":");
        hasher.update(check_target.trim().as_bytes());
        let result = hasher.finalize();
        Self(format!("{result:x}"))
    }

    /// Creates a [`Fingerprint`] from an already computed 64-char hex string.
    ///
    /// # Errors
    /// Returns [`DomainError::InvalidIdentifier`] if the string is not exactly 64 hex characters.
    pub fn from_hex(hex: impl Into<String>) -> Result<Self, DomainError> {
        let hex = hex.into();
        if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(DomainError::InvalidIdentifier(
                "fingerprint must be a 64-character lowercase hex string".to_string(),
            ));
        }
        Ok(Self(hex.to_ascii_lowercase()))
    }

    /// Returns the hex string representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for Fingerprint {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

/// Lifecycle status of an audit finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    /// The finding is currently observed and unremediated.
    #[default]
    Active,
    /// The finding was remediated or is no longer detected.
    Resolved,
    /// An authorized operator explicitly suppressed or acknowledged the finding.
    Suppressed,
}

/// An identified security issue, misconfiguration, or vulnerability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// Unique identifier for this finding.
    pub id: FindingId,
    /// Owning organization (tenant boundary).
    pub organization_id: OrganizationId,
    /// Target asset where this finding was detected.
    pub asset_id: AssetId,
    /// Deterministic deduplication fingerprint.
    pub fingerprint: Fingerprint,
    /// Machine identifier of the rule that produced this finding (e.g., `ssh-root-login`).
    pub rule_id: String,
    /// Concise summary title.
    pub title: String,
    /// In-depth technical description explaining what was detected and why it matters.
    pub description: String,
    /// Concrete, step-by-step guidance for how an operator can verify and resolve the issue.
    pub remediation: String,
    /// Assessed severity rating.
    pub severity: Severity,
    /// Current lifecycle state.
    pub status: FindingStatus,
    /// Optional Common Weakness Enumeration identifier (e.g., `CWE-306`).
    pub cwe_id: Option<String>,
    /// Timestamp when this issue was first observed.
    pub first_seen_at: DateTime<Utc>,
    /// Timestamp when this issue was most recently verified.
    pub last_seen_at: DateTime<Utc>,
    /// Timestamp when this issue transitioned to `Resolved` (if applicable).
    pub resolved_at: Option<DateTime<Utc>>,
}

impl Finding {
    /// Maximum permitted length for a finding title.
    pub const MAX_TITLE_LENGTH: usize = 512;
    /// Maximum permitted length for a rule identifier.
    pub const MAX_RULE_ID_LENGTH: usize = 128;

    /// Constructs and validates a new active [`Finding`].
    ///
    /// # Errors
    /// Returns [`DomainError::EmptyField`] or [`DomainError::FieldTooLong`] if
    /// field invariants are violated.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        organization_id: OrganizationId,
        asset_id: AssetId,
        rule_id: impl Into<String>,
        check_target: &str,
        title: impl Into<String>,
        description: impl Into<String>,
        remediation: impl Into<String>,
        severity: Severity,
    ) -> Result<Self, DomainError> {
        let rule_id = rule_id.into().trim().to_string();
        if rule_id.is_empty() {
            return Err(DomainError::EmptyField("rule_id"));
        }
        if rule_id.len() > Self::MAX_RULE_ID_LENGTH {
            return Err(DomainError::FieldTooLong {
                field: "rule_id",
                max_length: Self::MAX_RULE_ID_LENGTH,
                actual_length: rule_id.len(),
            });
        }

        let title = title.into().trim().to_string();
        if title.is_empty() {
            return Err(DomainError::EmptyField("title"));
        }
        if title.len() > Self::MAX_TITLE_LENGTH {
            return Err(DomainError::FieldTooLong {
                field: "title",
                max_length: Self::MAX_TITLE_LENGTH,
                actual_length: title.len(),
            });
        }

        let description = description.into().trim().to_string();
        if description.is_empty() {
            return Err(DomainError::EmptyField("description"));
        }

        let remediation = remediation.into().trim().to_string();
        if remediation.is_empty() {
            return Err(DomainError::EmptyField("remediation"));
        }

        let fingerprint = Fingerprint::compute(asset_id, &rule_id, check_target);
        let now = Utc::now();

        Ok(Self {
            id: FindingId::new(),
            organization_id,
            asset_id,
            fingerprint,
            rule_id,
            title,
            description,
            remediation,
            severity,
            status: FindingStatus::Active,
            cwe_id: None,
            first_seen_at: now,
            last_seen_at: now,
            resolved_at: None,
        })
    }

    /// Marks the finding as resolved.
    pub fn resolve(&mut self) {
        self.status = FindingStatus::Resolved;
        self.resolved_at = Some(Utc::now());
    }

    /// Re-activates a previously resolved finding when it is re-detected on a subsequent scan.
    pub fn reactivate(&mut self) {
        self.status = FindingStatus::Active;
        self.resolved_at = None;
        self.last_seen_at = Utc::now();
    }

    /// Suppresses the finding from active alerts.
    pub fn suppress(&mut self) {
        self.status = FindingStatus::Suppressed;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_deterministic_computation() {
        let asset_id = AssetId::new();
        let fp1 = Fingerprint::compute(asset_id, "ssh-permit-root-login", "/etc/ssh/sshd_config");
        let fp2 = Fingerprint::compute(asset_id, "ssh-permit-root-login", "/etc/ssh/sshd_config");
        assert_eq!(fp1, fp2);
        assert_eq!(fp1.as_str().len(), 64);

        // Different asset produces different fingerprint
        let fp3 = Fingerprint::compute(
            AssetId::new(),
            "ssh-permit-root-login",
            "/etc/ssh/sshd_config",
        );
        assert_ne!(fp1, fp3);
    }

    #[test]
    fn test_finding_creation_and_lifecycle() {
        let org_id = OrganizationId::new();
        let asset_id = AssetId::new();
        let mut finding = Finding::new(
            org_id,
            asset_id,
            "ssh-permit-root-login",
            "/etc/ssh/sshd_config",
            "SSH Root Login Enabled",
            "PermitRootLogin is set to yes in sshd_config",
            "Set PermitRootLogin no and reload sshd",
            Severity::High,
        )
        .expect("valid finding");

        assert_eq!(finding.status, FindingStatus::Active);
        assert!(finding.resolved_at.is_none());

        // Resolve
        finding.resolve();
        assert_eq!(finding.status, FindingStatus::Resolved);
        assert!(finding.resolved_at.is_some());

        // Reactivate
        finding.reactivate();
        assert_eq!(finding.status, FindingStatus::Active);
        assert!(finding.resolved_at.is_none());

        // Suppress
        finding.suppress();
        assert_eq!(finding.status, FindingStatus::Suppressed);
    }

    #[test]
    fn test_finding_validation_rejects_empty_fields() {
        let org_id = OrganizationId::new();
        let asset_id = AssetId::new();
        let err = Finding::new(
            org_id,
            asset_id,
            "  ",
            "target",
            "Title",
            "Desc",
            "Remediation",
            Severity::Low,
        )
        .unwrap_err();
        assert_eq!(err, DomainError::EmptyField("rule_id"));
    }
}
