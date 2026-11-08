//! Cross-platform audit abstraction, platform detection, and capability matrix.

pub mod linux;
pub mod macos;
pub mod windows;

use serde::{Deserialize, Serialize};
use std::fmt;

use crate::collector::{
    FileSystem, HostInspectionContext, PrivilegeLevel, RealCommandRunner, RealFileSystem,
};
use crate::error::EngineError;

pub use linux::LinuxPlatformBackend;
pub use macos::MacosPlatformBackend;
pub use windows::WindowsPlatformBackend;

/// Primary operating system family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformFamily {
    /// Linux distributions (Ubuntu, Debian, Alpine, RHEL, etc.).
    Linux,
    /// Microsoft Windows (Windows 10, 11, Windows Server).
    Windows,
    /// Apple macOS (Darwin kernel).
    MacOS,
    /// Unknown or unsupported operating system.
    Unknown,
}

impl PlatformFamily {
    /// Returns `true` if this is a Linux platform.
    #[must_use]
    pub const fn is_linux(self) -> bool {
        matches!(self, Self::Linux)
    }

    /// Returns `true` if this is a Windows platform.
    #[must_use]
    pub const fn is_windows(self) -> bool {
        matches!(self, Self::Windows)
    }

    /// Returns `true` if this is a macOS platform.
    #[must_use]
    pub const fn is_macos(self) -> bool {
        matches!(self, Self::MacOS)
    }
}

impl fmt::Display for PlatformFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Linux => write!(f, "Linux"),
            Self::Windows => write!(f, "Windows"),
            Self::MacOS => write!(f, "macOS"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Specific operating system distribution or edition.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformDistribution {
    /// Canonical Ubuntu Linux.
    Ubuntu,
    /// Debian GNU/Linux.
    Debian,
    /// Alpine Linux.
    Alpine,
    /// Fedora Linux.
    Fedora,
    /// Red Hat Enterprise Linux.
    Rhel,
    /// `CentOS` Linux / Stream.
    Centos,
    /// Arch Linux.
    Arch,
    /// Other Linux distribution.
    OtherLinux(String),
    /// Microsoft Windows 10.
    Windows10,
    /// Microsoft Windows 11.
    Windows11,
    /// Microsoft Windows Server 2022.
    WindowsServer2022,
    /// Microsoft Windows Server 2025.
    WindowsServer2025,
    /// Other Windows edition.
    OtherWindows(String),
    /// macOS 14 (Sonoma).
    MacosSonoma,
    /// macOS 15 (Sequoia).
    MacosSequoia,
    /// Other macOS release.
    OtherMacos(String),
    /// Unidentified platform distribution.
    Unknown,
}

impl fmt::Display for PlatformDistribution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ubuntu => write!(f, "Ubuntu"),
            Self::Debian => write!(f, "Debian"),
            Self::Alpine => write!(f, "Alpine Linux"),
            Self::Fedora => write!(f, "Fedora"),
            Self::Rhel => write!(f, "Red Hat Enterprise Linux"),
            Self::Centos => write!(f, "CentOS"),
            Self::Arch => write!(f, "Arch Linux"),
            Self::OtherLinux(name) => write!(f, "Linux ({name})"),
            Self::Windows10 => write!(f, "Windows 10"),
            Self::Windows11 => write!(f, "Windows 11"),
            Self::WindowsServer2022 => write!(f, "Windows Server 2022"),
            Self::WindowsServer2025 => write!(f, "Windows Server 2025"),
            Self::OtherWindows(ed) => write!(f, "Windows ({ed})"),
            Self::MacosSonoma => write!(f, "macOS Sonoma (14)"),
            Self::MacosSequoia => write!(f, "macOS Sequoia (15)"),
            Self::OtherMacos(ver) => write!(f, "macOS ({ver})"),
            Self::Unknown => write!(f, "Unknown Distribution"),
        }
    }
}

/// Structured operating system release version.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PlatformVersion {
    /// Major release number.
    pub major: u32,
    /// Minor release number.
    pub minor: u32,
    /// Patch or update level.
    pub patch: u32,
    /// Build identifier or revision string.
    pub build: Option<String>,
    /// Distribution release codename (e.g. "noble", "bookworm").
    pub codename: Option<String>,
    /// Unparsed raw version string.
    pub raw: String,
}

impl PlatformVersion {
    /// Parses a version string into structured numeric parts.
    #[must_use]
    pub fn parse(raw: &str) -> Self {
        let trimmed = raw.trim().trim_matches('"');
        let parts: Vec<&str> = trimmed.split('.').collect();

        let major = parts
            .first()
            .and_then(|p| p.parse::<u32>().ok())
            .unwrap_or(0);
        let minor = parts
            .get(1)
            .and_then(|p| p.parse::<u32>().ok())
            .unwrap_or(0);
        let patch = parts
            .get(2)
            .and_then(|p| p.parse::<u32>().ok())
            .unwrap_or(0);

        Self {
            major,
            minor,
            patch,
            build: None,
            codename: None,
            raw: trimmed.to_string(),
        }
    }

    /// Sets the codename for this version.
    #[must_use]
    pub fn with_codename(mut self, codename: impl Into<String>) -> Self {
        self.codename = Some(codename.into());
        self
    }

    /// Sets the build identifier for this version.
    #[must_use]
    pub fn with_build(mut self, build: impl Into<String>) -> Self {
        self.build = Some(build.into());
        self
    }
}

impl fmt::Display for PlatformVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref codename) = self.codename {
            write!(f, "{} ({})", self.raw, codename)
        } else {
            write!(f, "{}", self.raw)
        }
    }
}

/// Fine-grained platform audit capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformCapability {
    /// Linux kernel sysctl inspection via `/proc/sys`.
    KernelSysctl,
    /// SSH daemon configuration auditing (`sshd_config`).
    SshDaemon,
    /// Host packet filter / firewall auditing (UFW, iptables, nftables, pf, Windows Firewall).
    Firewall,
    /// Listening TCP/UDP network socket inspection.
    ListeningPorts,
    /// Setuid and Setgid binary permission verification.
    SuidSgidBinaries,
    /// Filesystem permission and world-writable directory verification.
    FilePermissions,
    /// Local user accounts, sudoers, and password policy inspection.
    SystemUsers,
    /// Process environment and PATH variable auditing.
    EnvironmentVariables,
    /// Windows Registry security configuration.
    WindowsRegistry,
    /// Windows Defender and endpoint security state.
    WindowsDefender,
    /// macOS Gatekeeper and security assessment.
    MacosGatekeeper,
    /// macOS System Integrity Protection (SIP) status.
    MacosSip,
}

impl fmt::Display for PlatformCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KernelSysctl => write!(f, "kernel_sysctl"),
            Self::SshDaemon => write!(f, "ssh_daemon"),
            Self::Firewall => write!(f, "firewall"),
            Self::ListeningPorts => write!(f, "listening_ports"),
            Self::SuidSgidBinaries => write!(f, "suid_sgid_binaries"),
            Self::FilePermissions => write!(f, "file_permissions"),
            Self::SystemUsers => write!(f, "system_users"),
            Self::EnvironmentVariables => write!(f, "environment_variables"),
            Self::WindowsRegistry => write!(f, "windows_registry"),
            Self::WindowsDefender => write!(f, "windows_defender"),
            Self::MacosGatekeeper => write!(f, "macos_gatekeeper"),
            Self::MacosSip => write!(f, "macos_sip"),
        }
    }
}

/// Execution status of an individual security audit check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckExecutionStatus {
    /// Check was executed and evaluated cleanly.
    Executed {
        /// `true` if no policy violation was detected, `false` if findings were produced.
        passed: bool,
    },
    /// Check is unsupported on this platform family (e.g. Linux check on Windows).
    UnsupportedPlatform {
        /// Target platform family that is unsupported.
        platform: PlatformFamily,
        /// Explanation for lack of support.
        reason: String,
    },
    /// Check is unsupported on this specific OS distribution or version.
    UnsupportedDistribution {
        /// Distribution name and version.
        distribution: String,
        /// Explanation for lack of support.
        reason: String,
    },
    /// Check requires a platform capability absent in this environment.
    MissingCapability {
        /// The missing required capability.
        capability: PlatformCapability,
        /// Contextual reason.
        reason: String,
    },
    /// Current execution privilege level is insufficient to perform the check.
    InsufficientPrivilege {
        /// Minimum required privilege level.
        required: PrivilegeLevel,
        /// Current running privilege level.
        current: PrivilegeLevel,
    },
    /// Target resource or configuration file exists but cannot be accessed.
    Inaccessible {
        /// Path or target name.
        resource: String,
        /// Access error detail.
        reason: String,
    },
    /// Target service or configuration is not installed / not applicable on this system.
    NotApplicable {
        /// Explanation why the check was skipped.
        reason: String,
    },
}

/// Audit check status tracking record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckStatusRecord {
    /// Stable identifier of the rule.
    pub rule_id: String,
    /// Detailed execution status.
    pub status: CheckExecutionStatus,
}

/// Comprehensive platform metadata and capability inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformInfo {
    /// Operating system family.
    pub family: PlatformFamily,
    /// Detected operating system distribution or edition.
    pub distribution: PlatformDistribution,
    /// Operating system release version.
    pub version: PlatformVersion,
    /// Host CPU architecture (e.g., "x86_64", "aarch64").
    pub architecture: String,
    /// Kernel release or OS build string.
    pub kernel_release: String,
    /// Host name.
    pub hostname: String,
    /// Human-friendly operating system name.
    pub pretty_name: String,
    /// Unique machine identifier, if present.
    pub machine_id: Option<String>,
    /// Capabilities verified on this host platform.
    pub capabilities: Vec<PlatformCapability>,
}

/// Trait implemented by platform-specific audit backends.
pub trait PlatformBackend: Send + Sync {
    /// Returns the platform metadata and capability descriptor.
    fn info(&self) -> &PlatformInfo;

    /// Checks whether this platform backend possesses a specific capability.
    fn has_capability(&self, capability: PlatformCapability) -> bool {
        self.info().capabilities.contains(&capability)
    }

    /// Whether this platform distribution and version is officially supported.
    fn is_supported(&self) -> bool;

    /// Collects host telemetry into a `HostInspectionContext`.
    ///
    /// # Errors
    /// Returns an [`EngineError`] if collection fails or platform is unsupported.
    fn collect_context(&self) -> Result<HostInspectionContext, EngineError>;
}

/// Detects the current host platform using filesystem inspection and system constants.
#[must_use]
pub fn detect_current_platform<
    FS: FileSystem + Clone + 'static,
    CR: crate::collector::CommandRunner + Clone + 'static,
>(
    fs: &FS,
    runner: &CR,
) -> Box<dyn PlatformBackend> {
    if fs.exists("/etc/os-release") || fs.exists("/usr/lib/os-release") {
        if let Ok(backend) = LinuxPlatformBackend::detect(fs, runner) {
            return Box::new(backend);
        }
    }

    #[cfg(target_os = "windows")]
    {
        Box::new(WindowsPlatformBackend::detect())
    }

    #[cfg(target_os = "macos")]
    {
        Box::new(MacosPlatformBackend::detect())
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        // Default to Linux backend fallback
        let backend = LinuxPlatformBackend::detect(fs, runner)
            .unwrap_or_else(|_| LinuxPlatformBackend::fallback(fs.clone(), runner.clone()));
        Box::new(backend)
    }
}

/// Creates a platform backend for the default environment.
#[must_use]
pub fn default_platform_backend() -> Box<dyn PlatformBackend> {
    detect_current_platform(&RealFileSystem, &RealCommandRunner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_family_properties() {
        assert!(PlatformFamily::Linux.is_linux());
        assert!(!PlatformFamily::Linux.is_windows());
        assert!(!PlatformFamily::Linux.is_macos());

        assert!(PlatformFamily::Windows.is_windows());
        assert!(!PlatformFamily::Windows.is_linux());

        assert!(PlatformFamily::MacOS.is_macos());
        assert!(!PlatformFamily::MacOS.is_linux());

        assert_eq!(PlatformFamily::Linux.to_string(), "Linux");
        assert_eq!(PlatformFamily::Windows.to_string(), "Windows");
        assert_eq!(PlatformFamily::MacOS.to_string(), "macOS");
    }

    #[test]
    fn test_platform_version_parsing() {
        let v = PlatformVersion::parse("24.04.1");
        assert_eq!(v.major, 24);
        assert_eq!(v.minor, 4);
        assert_eq!(v.patch, 1);
        assert_eq!(v.raw, "24.04.1");

        let v = PlatformVersion::parse("12").with_codename("bookworm");
        assert_eq!(v.major, 12);
        assert_eq!(v.minor, 0);
        assert_eq!(v.codename.as_deref(), Some("bookworm"));
        assert_eq!(v.to_string(), "12 (bookworm)");
    }

    #[test]
    fn test_check_execution_status_serde_roundtrip() {
        let status = CheckExecutionStatus::UnsupportedPlatform {
            platform: PlatformFamily::Windows,
            reason: "Check requires Linux procfs".into(),
        };

        let json = serde_json::to_string(&status).expect("serialize");
        assert!(json.contains("unsupported_platform"));
        let deserialized: CheckExecutionStatus = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(status, deserialized);

        let status_missing = CheckExecutionStatus::MissingCapability {
            capability: PlatformCapability::KernelSysctl,
            reason: "Non-Linux kernel".into(),
        };
        let json_missing = serde_json::to_string(&status_missing).expect("serialize");
        assert!(json_missing.contains("missing_capability"));

        let status_inaccessible = CheckExecutionStatus::Inaccessible {
            resource: "/etc/shadow".into(),
            reason: "Permission denied".into(),
        };
        let json_inacc = serde_json::to_string(&status_inaccessible).expect("serialize");
        assert!(json_inacc.contains("inaccessible"));
    }

    #[derive(Clone)]
    struct MockPlatformFs {
        os_release: Option<String>,
    }

    impl FileSystem for MockPlatformFs {
        fn read_to_string(&self, path: &str) -> Result<String, EngineError> {
            if path == "/etc/os-release" || path == "/usr/lib/os-release" {
                if let Some(ref content) = self.os_release {
                    return Ok(content.clone());
                }
            }
            Err(EngineError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "not found",
            )))
        }

        fn exists(&self, path: &str) -> bool {
            (path == "/etc/os-release" || path == "/usr/lib/os-release")
                && self.os_release.is_some()
        }

        fn file_mode(&self, _path: &str) -> Result<u32, EngineError> {
            Ok(0o644)
        }

        fn read_dir(&self, _path: &str) -> Result<Vec<String>, EngineError> {
            Ok(Vec::new())
        }

        fn read_link(&self, _path: &str) -> Result<String, EngineError> {
            Err(EngineError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "not found",
            )))
        }
    }

    #[derive(Clone)]
    struct MockPlatformRunner;
    impl crate::collector::CommandRunner for MockPlatformRunner {
        fn run(&self, _program: &str, _args: &[&str]) -> Result<String, EngineError> {
            Ok(String::new())
        }
    }

    #[test]
    fn test_detect_current_platform_selects_linux_when_os_release_present() {
        let fs = MockPlatformFs {
            os_release: Some(
                "ID=ubuntu\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04\"\n".into(),
            ),
        };
        let runner = MockPlatformRunner;
        let backend = detect_current_platform(&fs, &runner);

        assert_eq!(backend.info().family, PlatformFamily::Linux);
        assert_eq!(backend.info().distribution, PlatformDistribution::Ubuntu);
        assert!(backend.is_supported());
    }

    #[test]
    fn test_platform_capability_matrix_coverage() {
        let caps = [
            PlatformCapability::KernelSysctl,
            PlatformCapability::SshDaemon,
            PlatformCapability::Firewall,
            PlatformCapability::ListeningPorts,
            PlatformCapability::SuidSgidBinaries,
            PlatformCapability::FilePermissions,
            PlatformCapability::SystemUsers,
            PlatformCapability::EnvironmentVariables,
            PlatformCapability::WindowsRegistry,
            PlatformCapability::WindowsDefender,
            PlatformCapability::MacosGatekeeper,
            PlatformCapability::MacosSip,
        ];

        for cap in caps {
            let display = cap.to_string();
            assert_ne!(display, "");
            let json = serde_json::to_string(&cap).expect("serialize");
            let deserialized: PlatformCapability =
                serde_json::from_str(&json).expect("deserialize");
            assert_eq!(cap, deserialized);
        }
    }

    #[test]
    fn test_platform_info_serialization_roundtrip() {
        let info = PlatformInfo {
            family: PlatformFamily::Linux,
            distribution: PlatformDistribution::Ubuntu,
            version: PlatformVersion::parse("24.04.1").with_codename("noble"),
            architecture: "x86_64".into(),
            kernel_release: "6.8.0-45-generic".into(),
            hostname: "audit-host.internal".into(),
            pretty_name: "Ubuntu 24.04 LTS".into(),
            machine_id: Some("fedcba0987654321".into()),
            capabilities: LinuxPlatformBackend::default_capabilities(),
        };

        let json = serde_json::to_string_pretty(&info).expect("serialize");
        assert!(json.contains("audit-host.internal"));
        assert!(json.contains("fedcba0987654321"));
        assert!(json.contains("kernel_sysctl"));

        let deserialized: PlatformInfo = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(info, deserialized);
    }
}
