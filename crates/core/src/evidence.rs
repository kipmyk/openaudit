//! Evidence models and defense-in-depth secret redaction.
//!
//! # Security Invariant
//! Raw, unsanitized strings or structured objects cannot be stored in an [`Evidence`]
//! record. All evidence construction passes through multi-layered sanitization:
//! 1. Structured JSON key inspection (recursively scrubbing credential fields).
//! 2. Regex pattern scrubbing for private keys, tokens, and authorization headers.
//! 3. Hard size limits (512 KB) preventing denial-of-service from response bombs.

use std::fmt;
use std::sync::LazyLock;
use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::error::DomainError;
use crate::id::{EvidenceId, FindingId};

/// Maximum allowable payload size for evidence artifacts (524,288 bytes).
pub const MAX_EVIDENCE_SIZE_BYTES: usize = 512 * 1024;

/// Category of collected technical evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceType {
    /// Excerpt from a system configuration file.
    ConfigExcerpt,
    /// Information about listening sockets or network interfaces.
    SocketState,
    /// HTTP headers or TLS certificate attributes.
    HeaderDump,
    /// Installed package inventory or version information.
    PackageList,
    /// Operating system runtime status or service configuration.
    SystemState,
}

static SENSITIVE_KEY_SUBSTRINGS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "token",
    "authorization",
    "private_key",
    "privatekey",
    "api_key",
    "apikey",
    "access_key",
    "credential",
    "cookie",
    "session",
    "auth_bearer",
];

static REGEX_PRIVATE_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----")
        .expect("valid regex")
});

static REGEX_BEARER_TOKEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(bearer\s+)[A-Za-z0-9\-._~+/]+=*")
        .expect("valid regex")
});

static REGEX_AWS_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bAKIA[0-9A-Z]{16}\b").expect("valid regex")
});

static REGEX_GITHUB_TOKEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bgh[pousr]_[A-Za-z0-9_]{36,}\b").expect("valid regex")
});

static REGEX_KEY_VALUE_SECRET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(password|secret|token|api_key|apikey)\s*[:=]\s*['"]?[^\s';,\r\n]+['"]?"#)
        .expect("valid regex")
});

/// A guaranteed sanitized and size-bounded evidence payload.
///
/// Private inner state ensures unredacted content cannot be instantiated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidencePayload {
    data: serde_json::Value,
    size_bytes: usize,
}

impl EvidencePayload {
    /// Sanitizes and creates a payload from arbitrary text content.
    ///
    /// # Errors
    /// Returns [`DomainError::PayloadTooLarge`] if `text` exceeds [`MAX_EVIDENCE_SIZE_BYTES`].
    pub fn from_text(text: &str) -> Result<Self, DomainError> {
        let bytes = text.as_bytes();
        if bytes.len() > MAX_EVIDENCE_SIZE_BYTES {
            return Err(DomainError::PayloadTooLarge {
                size: bytes.len(),
                limit: MAX_EVIDENCE_SIZE_BYTES,
            });
        }

        let scrubbed_text = scrub_text_content(text);
        let size_bytes = scrubbed_text.len();
        Ok(Self {
            data: serde_json::Value::String(scrubbed_text),
            size_bytes,
        })
    }

    /// Recursively sanitizes and creates a payload from a structured JSON value.
    ///
    /// # Errors
    /// Returns [`DomainError::PayloadTooLarge`] if the serialized JSON exceeds [`MAX_EVIDENCE_SIZE_BYTES`].
    pub fn from_json(mut value: serde_json::Value) -> Result<Self, DomainError> {
        scrub_json_value(&mut value);
        let serialized = serde_json::to_string(&value).map_err(|err| {
            DomainError::Serialization(format!("failed to serialize evidence JSON: {err}"))
        })?;

        if serialized.len() > MAX_EVIDENCE_SIZE_BYTES {
            return Err(DomainError::PayloadTooLarge {
                size: serialized.len(),
                limit: MAX_EVIDENCE_SIZE_BYTES,
            });
        }

        let size_bytes = serialized.len();
        Ok(Self {
            data: value,
            size_bytes,
        })
    }

    /// Returns a reference to the sanitized JSON value.
    #[must_use]
    pub const fn data(&self) -> &serde_json::Value {
        &self.data
    }

    /// Returns the byte size of the sanitized payload.
    #[must_use]
    pub const fn size_bytes(&self) -> usize {
        self.size_bytes
    }
}

/// Recursively scrubs sensitive keys and values from a JSON structure.
fn scrub_json_value(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, val) in map.iter_mut() {
                let lower_key = key.to_ascii_lowercase();
                let is_sensitive_key =
                    SENSITIVE_KEY_SUBSTRINGS.iter().any(|&s| lower_key.contains(s));

                match val {
                    serde_json::Value::Object(_) | serde_json::Value::Array(_) => {
                        scrub_json_value(val);
                    }
                    serde_json::Value::String(_)
                    | serde_json::Value::Number(_)
                    | serde_json::Value::Bool(_) => {
                        if is_sensitive_key {
                            *val = serde_json::Value::String("[REDACTED]".to_string());
                        } else if let serde_json::Value::String(s) = val {
                            *s = scrub_text_content(s);
                        }
                    }
                    serde_json::Value::Null => {}
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr.iter_mut() {
                scrub_json_value(item);
            }
        }
        serde_json::Value::String(s) => {
            *s = scrub_text_content(s);
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {}
    }
}

/// Applies regex pattern scrubbing against recognized secret formats in raw text.
fn scrub_text_content(text: &str) -> String {
    let text = REGEX_PRIVATE_KEY.replace_all(text, "[REDACTED PRIVATE KEY]");
    let text = REGEX_BEARER_TOKEN.replace_all(&text, "${1}[REDACTED]");
    let text = REGEX_AWS_KEY.replace_all(&text, "[REDACTED AWS KEY]");
    let text = REGEX_GITHUB_TOKEN.replace_all(&text, "[REDACTED GITHUB TOKEN]");
    let text = REGEX_KEY_VALUE_SECRET.replace_all(&text, "$1=[REDACTED]");
    text.into_owned()
}

/// Supporting technical evidence attached to an audit finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    /// Unique identifier for this evidence record.
    pub id: EvidenceId,
    /// Associated security finding.
    pub finding_id: FindingId,
    /// Category of evidence.
    pub evidence_type: EvidenceType,
    /// Guaranteed sanitized and size-bounded payload.
    pub payload: EvidencePayload,
    /// Invariant: always true, signifying sanitization passed.
    pub is_redacted: bool,
    /// Timestamp when evidence was recorded.
    pub created_at: DateTime<Utc>,
}

impl Evidence {
    /// Constructs a new [`Evidence`] record.
    ///
    /// Requires an already-validated [`EvidencePayload`], enforcing redaction.
    #[must_use]
    pub fn new(
        finding_id: FindingId,
        evidence_type: EvidenceType,
        payload: EvidencePayload,
    ) -> Self {
        Self {
            id: EvidenceId::new(),
            finding_id,
            evidence_type,
            payload,
            is_redacted: true,
            created_at: Utc::now(),
        }
    }
}

impl fmt::Display for Evidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Evidence({}, type={:?}, bytes={})",
            self.id,
            self.evidence_type,
            self.payload.size_bytes()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_text_redaction_private_key() {
        let raw = "Config before\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0\n-----END RSA PRIVATE KEY-----\nConfig after";
        let payload = EvidencePayload::from_text(raw).expect("valid payload");
        let text = payload.data().as_str().expect("is string");
        assert!(!text.contains("MIIEowIBAAKCAQEA0"));
        assert!(text.contains("[REDACTED PRIVATE KEY]"));
    }

    #[test]
    fn test_text_redaction_bearer_token() {
        let raw = "Authorization: Bearer secret-token-xyz-123456789\nHost: api.example.com";
        let payload = EvidencePayload::from_text(raw).expect("valid payload");
        let text = payload.data().as_str().expect("is string");
        assert!(!text.contains("secret-token-xyz-123456789"));
        assert!(text.contains("Bearer [REDACTED]"));
    }

    #[test]
    fn test_text_redaction_aws_and_github_keys() {
        let raw = "aws_key=AKIAIOSFODNN7EXAMPLE and gh_pat=ghp_ABC123def456GHI789jkl012MNO345pqr678";
        let payload = EvidencePayload::from_text(raw).expect("valid payload");
        let text = payload.data().as_str().expect("is string");
        assert!(!text.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(!text.contains("ghp_ABC123def456GHI789jkl012MNO345pqr678"));
        assert!(text.contains("[REDACTED AWS KEY]"));
        assert!(text.contains("[REDACTED GITHUB TOKEN]"));
    }

    #[test]
    fn test_nested_json_key_redaction() {
        let raw_json = serde_json::json!({
            "service": "database",
            "connection": {
                "host": "db.internal",
                "port": 5432,
                "credentials": {
                    "username": "auditor",
                    "password": "SuperSecretPassword123!",
                    "nested_token": {
                        "api_key": "live-api-key-here"
                    }
                }
            },
            "environment": "production"
        });

        let payload = EvidencePayload::from_json(raw_json).expect("valid json payload");
        let data = payload.data();

        // Safe values are preserved
        assert_eq!(data["service"], "database");
        assert_eq!(data["connection"]["host"], "db.internal");
        assert_eq!(data["connection"]["credentials"]["username"], "auditor");

        // Sensitive fields are redacted
        assert_eq!(data["connection"]["credentials"]["password"], "[REDACTED]");
        assert_eq!(
            data["connection"]["credentials"]["nested_token"]["api_key"],
            "[REDACTED]"
        );
    }

    #[test]
    fn test_json_array_of_sensitive_objects() {
        let raw_json = serde_json::json!([
            {"user": "alice", "auth_token": "token-111"},
            {"user": "bob", "auth_token": "token-222"}
        ]);

        let payload = EvidencePayload::from_json(raw_json).expect("valid array payload");
        let data = payload.data();
        assert_eq!(data[0]["auth_token"], "[REDACTED]");
        assert_eq!(data[1]["auth_token"], "[REDACTED]");
    }

    #[test]
    fn test_evidence_size_limit_rejection() {
        let large_string = "x".repeat(MAX_EVIDENCE_SIZE_BYTES + 1);
        let err = EvidencePayload::from_text(&large_string).unwrap_err();
        match err {
            DomainError::PayloadTooLarge { size, limit } => {
                assert_eq!(size, MAX_EVIDENCE_SIZE_BYTES + 1);
                assert_eq!(limit, MAX_EVIDENCE_SIZE_BYTES);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn test_evidence_record_guarantees_is_redacted() {
        let payload = EvidencePayload::from_text("ssh-rsa AAAAB3NzaC1yc2E...").unwrap();
        let evidence = Evidence::new(FindingId::new(), EvidenceType::ConfigExcerpt, payload);
        assert!(evidence.is_redacted);
        assert_eq!(evidence.evidence_type, EvidenceType::ConfigExcerpt);
    }
}
