//! Windows platform audit backend interface and capability definitions.

use crate::collector::HostInspectionContext;
use crate::error::EngineError;
use crate::platform::{
    PlatformBackend, PlatformCapability, PlatformDistribution, PlatformFamily, PlatformInfo,
    PlatformVersion,
};

/// Microsoft Windows platform audit backend.
#[derive(Debug, Clone)]
pub struct WindowsPlatformBackend {
    info: PlatformInfo,
}

impl WindowsPlatformBackend {
    /// Creates a Windows backend instance with detected or provided system metadata.
    #[must_use]
    pub const fn new(info: PlatformInfo) -> Self {
        Self { info }
    }

    /// Detects current Windows platform properties.
    #[must_use]
    pub fn detect() -> Self {
        let architecture = std::env::consts::ARCH.to_string();
        let hostname = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "localhost".to_string());

        let info = PlatformInfo {
            family: PlatformFamily::Windows,
            distribution: PlatformDistribution::Windows11,
            version: PlatformVersion::parse("10.0.22631").with_build("22631"),
            architecture,
            kernel_release: "10.0.22631".to_string(),
            hostname,
            pretty_name: "Microsoft Windows 11 Enterprise".to_string(),
            machine_id: None,
            capabilities: Self::default_capabilities(),
        };

        Self { info }
    }

    /// Standard capabilities for Windows security auditing.
    #[must_use]
    pub fn default_capabilities() -> Vec<PlatformCapability> {
        vec![
            PlatformCapability::WindowsRegistry,
            PlatformCapability::WindowsDefender,
            PlatformCapability::ListeningPorts,
            PlatformCapability::Firewall,
            PlatformCapability::SystemUsers,
            PlatformCapability::EnvironmentVariables,
        ]
    }
}

impl PlatformBackend for WindowsPlatformBackend {
    fn info(&self) -> &PlatformInfo {
        &self.info
    }

    fn is_supported(&self) -> bool {
        // Windows native audit collection scheduled for implementation in Milestone M3.3
        false
    }

    fn collect_context(&self) -> Result<HostInspectionContext, EngineError> {
        Err(EngineError::UnsupportedPlatform(
            "Windows native audit collection scheduled for implementation in Milestone M3.3".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_windows_capabilities_and_support() {
        let info = PlatformInfo {
            family: PlatformFamily::Windows,
            distribution: PlatformDistribution::WindowsServer2022,
            version: PlatformVersion::parse("10.0.20348").with_build("20348"),
            architecture: "x86_64".into(),
            kernel_release: "10.0.20348".into(),
            hostname: "WIN-SERVER-01".into(),
            pretty_name: "Microsoft Windows Server 2022 Standard".into(),
            machine_id: Some("win-guid-1234".into()),
            capabilities: WindowsPlatformBackend::default_capabilities(),
        };

        let backend = WindowsPlatformBackend::new(info);
        assert_eq!(backend.info().family, PlatformFamily::Windows);
        assert_eq!(
            backend.info().distribution,
            PlatformDistribution::WindowsServer2022
        );
        // Windows support is scheduled for Milestone M3.3
        assert!(!backend.is_supported());
        assert!(backend.has_capability(PlatformCapability::WindowsRegistry));
        assert!(backend.has_capability(PlatformCapability::WindowsDefender));
        assert!(!backend.has_capability(PlatformCapability::KernelSysctl));
        assert!(!backend.has_capability(PlatformCapability::SuidSgidBinaries));

        let err = backend.collect_context().unwrap_err();
        assert!(matches!(err, EngineError::UnsupportedPlatform(_)));
    }

    #[test]
    fn test_windows_unsupported_version() {
        let info = PlatformInfo {
            family: PlatformFamily::Windows,
            distribution: PlatformDistribution::OtherWindows("Windows 7".into()),
            version: PlatformVersion::parse("6.1.7601"),
            architecture: "x86_64".into(),
            kernel_release: "6.1.7601".into(),
            hostname: "LEGACY-WIN".into(),
            pretty_name: "Microsoft Windows 7 Professional".into(),
            machine_id: None,
            capabilities: WindowsPlatformBackend::default_capabilities(),
        };

        let backend = WindowsPlatformBackend::new(info);
        assert!(!backend.is_supported());
    }
}
