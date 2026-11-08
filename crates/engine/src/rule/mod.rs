//! Rule evaluation engine and security rule traits.

pub mod builtin;
pub mod macos;
pub mod windows;

pub use builtin::default_linux_rules;
pub use macos::default_macos_rules;
pub use windows::default_windows_rules;

/// Returns all built-in rules across supported platforms.
#[must_use]
pub fn all_builtin_rules() -> Vec<Box<dyn Rule>> {
    let mut rules = default_linux_rules();
    rules.extend(default_windows_rules());
    rules.extend(default_macos_rules());
    rules
}

/// Returns standard built-in rules for the specified platform family.
#[must_use]
pub fn default_rules_for_platform(family: PlatformFamily) -> Vec<Box<dyn Rule>> {
    match family {
        PlatformFamily::Windows => default_windows_rules(),
        PlatformFamily::MacOS => default_macos_rules(),
        PlatformFamily::Linux | PlatformFamily::Unknown => default_linux_rules(),
    }
}

use crate::collector::{HostInspectionContext, PrivilegeLevel};
use crate::platform::{PlatformCapability, PlatformFamily};
use crate::profile::AuditProfile;
use openaudit_core::{EvidenceType, Severity};

const DEFAULT_LINUX_PLATFORMS: &[PlatformFamily] = &[PlatformFamily::Linux];
const EMPTY_CAPABILITIES: &[PlatformCapability] = &[];

/// Structured finding produced by a security rule evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleFinding {
    /// Unique stable identifier of the rule (e.g., "linux.ssh.permit-root-login").
    pub rule_id: &'static str,
    /// Inspected target resource or configuration line (e.g., "`/etc/ssh/sshd_config:PermitRootLogin`").
    pub target: String,
    /// Brief human-readable title describing the violation.
    pub title: String,
    /// Detailed technical explanation of the security risk.
    pub description: String,
    /// Actionable operator remediation guidance.
    pub remediation: String,
    /// Classified severity level.
    pub severity: Severity,
    /// Raw unredacted evidence text to be sanitized via `EvidencePayload`.
    pub evidence_text: String,
    /// Semantic classification of the attached evidence.
    pub evidence_type: EvidenceType,
}

/// Common trait implemented by all security posture evaluation rules.
pub trait Rule: Send + Sync {
    /// Unique identifier for this rule.
    fn id(&self) -> &'static str;

    /// Short human-readable title.
    fn title(&self) -> &'static str;

    /// Comprehensive explanation of the risk.
    fn description(&self) -> &'static str;

    /// Severity classification.
    fn severity(&self) -> Severity;

    /// Concrete remediation instructions.
    fn remediation(&self) -> &'static str;

    /// Privilege level necessary to evaluate this rule.
    fn required_privilege(&self) -> PrivilegeLevel;

    /// Evaluates host inspection telemetry, returning all findings where violations are detected.
    fn evaluate(&self, context: &HostInspectionContext) -> Vec<RuleFinding>;

    /// Target operating system platforms for which this rule is applicable.
    fn target_platforms(&self) -> &[PlatformFamily] {
        DEFAULT_LINUX_PLATFORMS
    }

    /// Platform capabilities required to evaluate this rule.
    fn required_capabilities(&self) -> &[PlatformCapability] {
        EMPTY_CAPABILITIES
    }

    /// Audit profile tier for this rule.
    fn profile(&self) -> AuditProfile {
        AuditProfile::Baseline
    }
}
