//! Finding severity classification and ordering.

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt;
use std::str::FromStr;

use crate::error::DomainError;

/// Severity classification for OpenAudit security findings.
///
/// Implements natural ordering where `Critical > High > Medium > Low > Info`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational observations, audit notes, or benign configuration details.
    Info = 0,
    /// Minor deviations from security best practices without direct exploitability.
    Low = 1,
    /// Security weaknesses, deprecated protocols, or reduced defense-in-depth.
    Medium = 2,
    /// Severe misconfigurations, missing critical patches, or exposed administrative surfaces.
    High = 3,
    /// Direct risk of host compromise, unauthenticated remote code execution, or credential loss.
    Critical = 4,
}

impl Severity {
    /// Returns the integer rank of the severity (0 for Info through 4 for Critical).
    #[must_use]
    pub const fn rank(&self) -> u8 {
        *self as u8
    }

    /// Returns a human-readable title-cased representation.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "Info",
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
            Self::Critical => "Critical",
        }
    }
}

impl PartialOrd for Severity {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Severity {
    fn cmp(&self, other: &Self) -> Ordering {
        self.rank().cmp(&other.rank())
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "INFO"),
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

impl FromStr for Severity {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "info" => Ok(Self::Info),
            "low" => Ok(Self::Low),
            "medium" | "med" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "critical" | "crit" => Ok(Self::Critical),
            other => Err(DomainError::EmptyField("severity")).map_err(|_| {
                DomainError::InvalidIdentifier(format!("unrecognized severity level: '{other}'"))
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
        assert_eq!(Severity::Medium, Severity::Medium);
    }

    #[test]
    fn test_severity_sorting() {
        let mut severities = vec![
            Severity::Low,
            Severity::Critical,
            Severity::Info,
            Severity::High,
            Severity::Medium,
        ];
        severities.sort();
        assert_eq!(
            severities,
            vec![
                Severity::Info,
                Severity::Low,
                Severity::Medium,
                Severity::High,
                Severity::Critical,
            ]
        );
    }

    #[test]
    fn test_severity_serde() {
        let json = serde_json::to_string(&Severity::Critical).expect("serialize");
        assert_eq!(json, "\"critical\"");

        let parsed: Severity = serde_json::from_str("\"high\"").expect("deserialize");
        assert_eq!(parsed, Severity::High);
    }

    #[test]
    fn test_severity_from_str_case_insensitive() {
        assert_eq!("CRITICAL".parse::<Severity>().unwrap(), Severity::Critical);
        assert_eq!("high".parse::<Severity>().unwrap(), Severity::High);
        assert_eq!("Medium".parse::<Severity>().unwrap(), Severity::Medium);
        assert_eq!("LOW".parse::<Severity>().unwrap(), Severity::Low);
        assert_eq!("info".parse::<Severity>().unwrap(), Severity::Info);
    }
}
