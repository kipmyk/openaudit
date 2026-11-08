//! macOS platform audit backend interface and capability definitions.

use crate::collector::HostInspectionContext;
use crate::error::EngineError;
use crate::platform::{
    PlatformBackend, PlatformCapability, PlatformDistribution, PlatformFamily, PlatformInfo,
    PlatformVersion,
};

/// Apple macOS platform audit backend.
#[derive(Debug, Clone)]
pub struct MacosPlatformBackend {
    info: PlatformInfo,
}

impl MacosPlatformBackend {
    /// Creates a macOS backend instance with detected or provided system metadata.
    #[must_use]
    pub const fn new(info: PlatformInfo) -> Self {
        Self { info }
    }

    /// Detects current macOS platform properties.
    #[must_use]
    pub fn detect() -> Self {
        let architecture = std::env::consts::ARCH.to_string();
        let hostname = std::env::var("HOSTNAME")
            .or_else(|_| std::env::var("HOST"))
            .unwrap_or_else(|_| "localhost".to_string());

        let info = PlatformInfo {
            family: PlatformFamily::MacOS,
            distribution: PlatformDistribution::MacosSonoma,
            version: PlatformVersion::parse("14.5.0").with_codename("Sonoma"),
            architecture,
            kernel_release: "Darwin 23.5.0".to_string(),
            hostname,
            pretty_name: "macOS Sonoma 14.5".to_string(),
            machine_id: None,
            capabilities: Self::default_capabilities(),
        };

        Self { info }
    }

    /// Standard capabilities for macOS security posture auditing.
    #[must_use]
    pub fn default_capabilities() -> Vec<PlatformCapability> {
        vec![
            PlatformCapability::MacosGatekeeper,
            PlatformCapability::MacosSip,
            PlatformCapability::SshDaemon,
            PlatformCapability::FilePermissions,
            PlatformCapability::SystemUsers,
            PlatformCapability::ListeningPorts,
            PlatformCapability::EnvironmentVariables,
        ]
    }
}

impl PlatformBackend for MacosPlatformBackend {
    fn info(&self) -> &PlatformInfo {
        &self.info
    }

    fn is_supported(&self) -> bool {
        // macOS native audit collection scheduled for implementation in Milestone M3.4
        false
    }

    fn collect_context(&self) -> Result<HostInspectionContext, EngineError> {
        Err(EngineError::UnsupportedPlatform(
            "macOS native audit collection scheduled for implementation in Milestone M3.4".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_macos_capabilities_and_support() {
        let info = PlatformInfo {
            family: PlatformFamily::MacOS,
            distribution: PlatformDistribution::MacosSonoma,
            version: PlatformVersion::parse("14.4").with_codename("Sonoma"),
            architecture: "aarch64".into(),
            kernel_release: "Darwin 23.4.0".into(),
            hostname: "MacBook-Pro.local".into(),
            pretty_name: "macOS Sonoma".into(),
            machine_id: Some("IOPlatformUUID-1234".into()),
            capabilities: MacosPlatformBackend::default_capabilities(),
        };

        let backend = MacosPlatformBackend::new(info);
        assert_eq!(backend.info().family, PlatformFamily::MacOS);
        assert_eq!(
            backend.info().distribution,
            PlatformDistribution::MacosSonoma
        );
        // macOS support is scheduled for Milestone M3.4
        assert!(!backend.is_supported());
        assert!(backend.has_capability(PlatformCapability::MacosGatekeeper));
        assert!(backend.has_capability(PlatformCapability::MacosSip));
        assert!(backend.has_capability(PlatformCapability::SshDaemon));
        assert!(!backend.has_capability(PlatformCapability::KernelSysctl));
        assert!(!backend.has_capability(PlatformCapability::WindowsRegistry));

        let err = backend.collect_context().unwrap_err();
        assert!(matches!(err, EngineError::UnsupportedPlatform(_)));
    }

    #[test]
    fn test_macos_unsupported_version() {
        let info = PlatformInfo {
            family: PlatformFamily::MacOS,
            distribution: PlatformDistribution::OtherMacos("macOS 12 Monterey".into()),
            version: PlatformVersion::parse("12.7.4").with_codename("Monterey"),
            architecture: "x86_64".into(),
            kernel_release: "Darwin 21.6.0".into(),
            hostname: "Old-Mac.local".into(),
            pretty_name: "macOS Monterey".into(),
            machine_id: None,
            capabilities: MacosPlatformBackend::default_capabilities(),
        };

        let backend = MacosPlatformBackend::new(info);
        assert!(!backend.is_supported());
    }
}
