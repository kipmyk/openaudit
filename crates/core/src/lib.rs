//! # OpenAudit Core
//!
//! `openaudit-core` defines the foundational domain models, typed identifiers,
//! severity definitions, evidence structures, and error primitives used across
//! the OpenAudit platform.
//!
//! This crate is intentionally decoupled from transport protocols, database drivers,
//! and operating system specific system calls.

#![doc(html_root_url = "https://docs.rs/openaudit-core/0.1.0-alpha.0")]

/// Returns the current version of the OpenAudit core domain library.
#[must_use]
pub const fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_not_empty() {
        assert!(!version().is_empty());
    }
}
