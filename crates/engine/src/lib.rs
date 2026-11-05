//! # OpenAudit Engine
//!
//! `openaudit-engine` provides the check execution runner and rule evaluation
//! engine for OpenAudit.
//!
//! It executes both local operating system audits (parsing Linux host state)
//! and external perimeter checks (DNS, TLS, and HTTP security posture).

#![doc(html_root_url = "https://docs.rs/openaudit-engine/0.1.0-alpha.0")]

pub mod error;

pub use error::EngineError;

/// Returns the current version of the OpenAudit inspection engine.
#[must_use]
pub const fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_version_not_empty() {
        assert_ne!(version(), "");
    }
}
