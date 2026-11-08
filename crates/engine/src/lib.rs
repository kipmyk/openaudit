//! # OpenAudit Engine
//!
//! `openaudit-engine` provides the check execution runner and rule evaluation
//! engine for OpenAudit.
//!
//! It executes both local operating system audits (parsing Linux host state)
//! and external perimeter checks (DNS, TLS, and HTTP security posture).

#![doc(html_root_url = "https://docs.rs/openaudit-engine/0.1.0-alpha.0")]

pub mod collector;
pub mod error;
pub mod platform;
pub mod profile;
pub mod rule;
pub mod runner;

pub use collector::{HostInspectionContext, PrivilegeLevel};
pub use error::EngineError;
pub use platform::{
    default_platform_backend, detect_current_platform, CheckExecutionStatus, CheckStatusRecord,
    LinuxPlatformBackend, MacosPlatformBackend, PlatformBackend, PlatformCapability,
    PlatformDistribution, PlatformFamily, PlatformInfo, PlatformVersion, WindowsPlatformBackend,
};
pub use profile::AuditProfile;
pub use rule::{builtin::default_linux_rules, Rule, RuleFinding};
pub use runner::{AuditEngine, AuditFindingItem, AuditReport};

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
