//! Typed domain error representations for OpenAudit.

use thiserror::Error;

/// Core domain errors occurring within OpenAudit business logic.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum DomainError {
    /// An identifier string could not be parsed into a valid UUID.
    #[error("invalid identifier: {0}")]
    InvalidIdentifier(String),

    /// A required field was empty or contained only whitespace.
    #[error("required field '{0}' cannot be empty")]
    EmptyField(&'static str),

    /// A string field exceeded its maximum permitted length.
    #[error("field '{field}' exceeds maximum length of {max_length} characters (got {actual_length})")]
    FieldTooLong {
        /// Name of the field.
        field: &'static str,
        /// Maximum allowable character length.
        max_length: usize,
        /// Observed character length.
        actual_length: usize,
    },

    /// The asset target address failed structural validation.
    #[error("invalid target address: {0}")]
    InvalidTargetAddress(String),

    /// Evidence payload exceeded the hard maximum size limit.
    #[error("evidence payload size of {size} bytes exceeds maximum limit of {limit} bytes")]
    PayloadTooLarge {
        /// Observed payload size in bytes.
        size: usize,
        /// Maximum allowable limit in bytes.
        limit: usize,
    },

    /// An invalid lifecycle state transition was attempted.
    #[error("invalid state transition from '{from}' to '{to}'")]
    InvalidStateTransition {
        /// Source state name.
        from: String,
        /// Target state name.
        to: String,
    },

    /// Serialization or deserialization error in domain logic.
    #[error("serialization error: {0}")]
    Serialization(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display_formatting() {
        let err = DomainError::EmptyField("target_address");
        assert_eq!(err.to_string(), "required field 'target_address' cannot be empty");

        let err = DomainError::FieldTooLong {
            field: "name",
            max_length: 64,
            actual_length: 100,
        };
        assert_eq!(
            err.to_string(),
            "field 'name' exceeds maximum length of 64 characters (got 100)"
        );

        let err = DomainError::PayloadTooLarge {
            size: 600_000,
            limit: 524_288,
        };
        assert_eq!(
            err.to_string(),
            "evidence payload size of 600000 bytes exceeds maximum limit of 524288 bytes"
        );
    }
}
