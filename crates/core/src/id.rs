//! Strongly typed domain identifier newtypes.
//!
//! Using distinct newtypes prevents logic bugs where IDs of different entities
//! are accidentally swapped or mixed up.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

use crate::error::DomainError;

macro_rules! define_id {
    ($name:ident, $doc:expr) => {
        #[doc = $doc]
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            /// Generates a new random identifier.
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }

            /// Wraps an existing [`Uuid`].
            #[must_use]
            pub const fn from_uuid(uuid: Uuid) -> Self {
                Self(uuid)
            }

            /// Returns a reference to the inner [`Uuid`].
            #[must_use]
            pub const fn as_uuid(&self) -> &Uuid {
                &self.0
            }

            /// Consumes `self` and returns the inner [`Uuid`].
            #[must_use]
            pub const fn into_uuid(self) -> Uuid {
                self.0
            }

            /// Parses a UUID string into this typed identifier.
            ///
            /// # Errors
            /// Returns [`DomainError::InvalidIdentifier`] if `s` is not a valid UUID format.
            pub fn parse(s: &str) -> Result<Self, DomainError> {
                Uuid::parse_str(s)
                    .map(Self)
                    .map_err(|err| DomainError::InvalidIdentifier(format!("{}: {err}", s)))
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl FromStr for $name {
            type Err = DomainError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::parse(s)
            }
        }

        impl From<Uuid> for $name {
            fn from(uuid: Uuid) -> Self {
                Self(uuid)
            }
        }

        impl From<$name> for Uuid {
            fn from(id: $name) -> Self {
                id.0
            }
        }
    };
}

define_id!(
    OrganizationId,
    "Unique identifier for an organization (tenant boundary)."
);
define_id!(
    AssetId,
    "Unique identifier for a monitored infrastructure asset."
);
define_id!(ScanId, "Unique identifier for an audit scan execution.");
define_id!(ScanJobId, "Unique identifier for an atomic scan job.");
define_id!(FindingId, "Unique identifier for a security finding.");
define_id!(EvidenceId, "Unique identifier for an evidence artifact.");
define_id!(
    AgentId,
    "Unique identifier for an enrolled host monitoring agent."
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_id_creation_and_uniqueness() {
        let id1 = AssetId::new();
        let id2 = AssetId::new();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_id_parsing_roundtrip() {
        let original = FindingId::new();
        let s = original.to_string();
        let parsed: FindingId = s.parse().expect("should parse valid uuid string");
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_invalid_id_parsing() {
        let err = ScanId::parse("not-a-valid-uuid").unwrap_err();
        match err {
            DomainError::InvalidIdentifier(msg) => {
                assert!(msg.contains("not-a-valid-uuid"));
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn test_id_json_serde_roundtrip() {
        let org_id = OrganizationId::new();
        let serialized = serde_json::to_string(&org_id).expect("should serialize");
        assert_eq!(serialized, format!("\"{org_id}\""));
        let deserialized: OrganizationId =
            serde_json::from_str(&serialized).expect("should deserialize");
        assert_eq!(org_id, deserialized);
    }
}
