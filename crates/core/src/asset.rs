//! Infrastructure asset models and classifications.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::DomainError;
use crate::id::{AssetId, OrganizationId};

/// Type of monitored infrastructure asset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetType {
    /// A Linux operating system host (monitored via agent or local audit).
    LinuxHost,
    /// An internet-facing web domain or FQDN (monitored via agentless perimeter checks).
    WebDomain,
    /// An explicit IP address or network endpoint.
    IpEndpoint,
}

/// Operational deployment environment of the asset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Environment {
    /// Live production infrastructure.
    #[default]
    Production,
    /// Staging or pre-production verification environment.
    Staging,
    /// Internal development, test, or sandbox environment.
    Development,
}

/// Business and operational criticality rating of an asset.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Criticality {
    /// Low operational impact if compromised or degraded.
    Low = 0,
    /// Standard infrastructure component.
    #[default]
    Medium = 1,
    /// High-value infrastructure, primary customer-facing service, or sensitive data store.
    High = 2,
    /// Mission-critical single point of failure or regulatory boundary.
    Critical = 3,
}

/// A registered infrastructure asset owned by an organization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Asset {
    /// Unique identifier for this asset.
    pub id: AssetId,
    /// Owning organization (tenant boundary).
    pub organization_id: OrganizationId,
    /// Human-friendly display name.
    pub name: String,
    /// Asset category (Linux host, web domain, or IP endpoint).
    pub asset_type: AssetType,
    /// Hostname, FQDN, or authorized IP address.
    pub target_address: String,
    /// Deployment environment.
    pub environment: Environment,
    /// Business criticality rating.
    pub criticality: Criticality,
    /// Arbitrary organizational tags for grouping.
    pub tags: Vec<String>,
    /// Whether this asset is active and included in recurring scans.
    pub is_active: bool,
    /// Timestamp when this asset was registered.
    pub created_at: DateTime<Utc>,
    /// Timestamp when this asset record was last modified.
    pub updated_at: DateTime<Utc>,
}

impl Asset {
    /// Maximum permitted length for an asset name.
    pub const MAX_NAME_LENGTH: usize = 255;
    /// Maximum permitted length for a target address string.
    pub const MAX_TARGET_LENGTH: usize = 512;

    /// Constructs and validates a new [`Asset`].
    ///
    /// # Errors
    /// Returns [`DomainError::EmptyField`] or [`DomainError::FieldTooLong`] if
    /// validation constraints are violated.
    pub fn new(
        organization_id: OrganizationId,
        name: impl Into<String>,
        asset_type: AssetType,
        target_address: impl Into<String>,
    ) -> Result<Self, DomainError> {
        let name = name.into().trim().to_string();
        if name.is_empty() {
            return Err(DomainError::EmptyField("name"));
        }
        if name.len() > Self::MAX_NAME_LENGTH {
            return Err(DomainError::FieldTooLong {
                field: "name",
                max_length: Self::MAX_NAME_LENGTH,
                actual_length: name.len(),
            });
        }

        let target_address = target_address.into().trim().to_string();
        if target_address.is_empty() {
            return Err(DomainError::EmptyField("target_address"));
        }
        if target_address.len() > Self::MAX_TARGET_LENGTH {
            return Err(DomainError::FieldTooLong {
                field: "target_address",
                max_length: Self::MAX_TARGET_LENGTH,
                actual_length: target_address.len(),
            });
        }
        if target_address.contains([' ', '\r', '\n', '\t']) {
            return Err(DomainError::InvalidTargetAddress(
                "target address cannot contain whitespace or control characters".to_string(),
            ));
        }

        let now = Utc::now();
        Ok(Self {
            id: AssetId::new(),
            organization_id,
            name,
            asset_type,
            target_address,
            environment: Environment::default(),
            criticality: Criticality::default(),
            tags: Vec::new(),
            is_active: true,
            created_at: now,
            updated_at: now,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_asset_creation() {
        let org_id = OrganizationId::new();
        let asset = Asset::new(
            org_id,
            "Production Web Server",
            AssetType::LinuxHost,
            "192.0.2.1",
        )
        .expect("valid asset");

        assert_eq!(asset.organization_id, org_id);
        assert_eq!(asset.name, "Production Web Server");
        assert_eq!(asset.asset_type, AssetType::LinuxHost);
        assert_eq!(asset.target_address, "192.0.2.1");
        assert_eq!(asset.environment, Environment::Production);
        assert_eq!(asset.criticality, Criticality::Medium);
        assert!(asset.is_active);
    }

    #[test]
    fn test_asset_name_validation() {
        let org_id = OrganizationId::new();
        let err = Asset::new(org_id, "   ", AssetType::WebDomain, "example.com").unwrap_err();
        assert_eq!(err, DomainError::EmptyField("name"));

        let long_name = "a".repeat(256);
        let err = Asset::new(org_id, long_name, AssetType::WebDomain, "example.com").unwrap_err();
        assert!(matches!(err, DomainError::FieldTooLong { .. }));
    }

    #[test]
    fn test_asset_target_address_whitespace_rejection() {
        let org_id = OrganizationId::new();
        let err = Asset::new(
            org_id,
            "Bad Target",
            AssetType::WebDomain,
            "example.com/ bad path",
        )
        .unwrap_err();
        assert!(matches!(err, DomainError::InvalidTargetAddress(_)));
    }

    #[test]
    fn test_asset_serde_roundtrip() {
        let org_id = OrganizationId::new();
        let asset = Asset::new(
            org_id,
            "API Gateway",
            AssetType::WebDomain,
            "api.example.com",
        )
        .unwrap();

        let json = serde_json::to_string(&asset).expect("serialize");
        let deserialized: Asset = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(asset, deserialized);
    }
}
