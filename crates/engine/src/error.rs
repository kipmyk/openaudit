//! Error types for the OpenAudit inspection and rule evaluation engine.

use openaudit_core::DomainError;
use thiserror::Error;

/// Specific error conditions encountered during audit collection and rule evaluation.
#[derive(Debug, Error)]
pub enum EngineError {
    /// An I/O error occurred while accessing system state or configuration files.
    #[error("I/O error during audit collection: {0}")]
    Io(#[from] std::io::Error),

    /// A configuration file, socket table, or command output could not be parsed.
    #[error("parse error: {0}")]
    Parse(String),

    /// Execution of a diagnostic subprocess failed.
    #[error("command execution failed: {0}")]
    CommandExecution(String),

    /// A diagnostic subprocess exceeded its allotted execution time limit.
    #[error("command timed out after {0} seconds")]
    CommandTimeout(u64),

    /// Output from a diagnostic command or file exceeded the maximum allowed size.
    #[error(
        "collected output exceeded maximum size limit: {size_bytes} bytes (max: {max_bytes} bytes)"
    )]
    OutputLimitExceeded {
        /// Actual size of the output in bytes.
        size_bytes: usize,
        /// Maximum allowable size in bytes.
        max_bytes: usize,
    },

    /// The requested inspection requires elevated privileges not currently held.
    #[error("insufficient privilege to perform check: {0}")]
    InsufficientPrivilege(String),

    /// The target platform or operating system is unsupported.
    #[error("unsupported platform: {0}")]
    UnsupportedPlatform(String),

    /// The target distribution or version is unsupported.
    #[error("unsupported distribution: {0}")]
    UnsupportedDistribution(String),

    /// A required platform capability is missing on this host.
    #[error("missing platform capability: {0}")]
    MissingCapability(String),

    /// An error originated in the core domain models.
    #[error("domain error: {0}")]
    Core(#[from] DomainError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display_formatting() {
        let err = EngineError::Parse("invalid ssh line".into());
        assert_eq!(err.to_string(), "parse error: invalid ssh line");

        let err = EngineError::CommandTimeout(5);
        assert_eq!(err.to_string(), "command timed out after 5 seconds");

        let err = EngineError::OutputLimitExceeded {
            size_bytes: 600_000,
            max_bytes: 524_288,
        };
        assert_eq!(
            err.to_string(),
            "collected output exceeded maximum size limit: 600000 bytes (max: 524288 bytes)"
        );

        let err = EngineError::UnsupportedPlatform("freebsd".into());
        assert_eq!(err.to_string(), "unsupported platform: freebsd");

        let err = EngineError::UnsupportedDistribution("archlinux".into());
        assert_eq!(err.to_string(), "unsupported distribution: archlinux");

        let err = EngineError::MissingCapability("kernel_sysctl".into());
        assert_eq!(
            err.to_string(),
            "missing platform capability: kernel_sysctl"
        );
    }
}
