//! Audit profiles defining rule subsets and inspection scopes.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

use crate::error::EngineError;

/// Operational audit profile defining the depth and scope of security rule evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditProfile {
    /// Standard security baseline auditing primary security misconfigurations.
    #[default]
    Baseline,
    /// Comprehensive inspection evaluating all active security posture rules.
    Full,
    /// Hardened profile applying strict system parameters and deep surface auditing.
    Hardened,
}

impl fmt::Display for AuditProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Baseline => write!(f, "baseline"),
            Self::Full => write!(f, "full"),
            Self::Hardened => write!(f, "hardened"),
        }
    }
}

impl FromStr for AuditProfile {
    type Err = EngineError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().trim() {
            "baseline" => Ok(Self::Baseline),
            "full" => Ok(Self::Full),
            "hardened" => Ok(Self::Hardened),
            other => Err(EngineError::Parse(format!(
                "unknown audit profile '{other}'. Supported: baseline, full, hardened"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_profile_parsing_and_display() {
        assert_eq!(
            AuditProfile::from_str("baseline").unwrap(),
            AuditProfile::Baseline
        );
        assert_eq!(AuditProfile::from_str("FULL").unwrap(), AuditProfile::Full);
        assert_eq!(
            AuditProfile::from_str("Hardened").unwrap(),
            AuditProfile::Hardened
        );
        assert!(AuditProfile::from_str("invalid").is_err());

        assert_eq!(AuditProfile::Baseline.to_string(), "baseline");
        assert_eq!(AuditProfile::Full.to_string(), "full");
        assert_eq!(AuditProfile::Hardened.to_string(), "hardened");
    }

    #[test]
    fn test_audit_profile_serde() {
        let profile = AuditProfile::Hardened;
        let json = serde_json::to_string(&profile).expect("serialize");
        assert_eq!(json, "\"hardened\"");
        let deserialized: AuditProfile = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(profile, deserialized);
    }
}
