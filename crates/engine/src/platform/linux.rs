//! Linux platform audit backend supporting Ubuntu 24.04, Debian 12, Debian 13, and generic Linux.

use crate::collector::env::EnvInfo;
use crate::collector::firewall::FirewallInfo;
use crate::collector::os::OsInfo;
use crate::collector::permissions::FilePermissionInfo;
use crate::collector::ports::{ListeningPort, ListeningUdpPort};
use crate::collector::ssh::SshConfig;
use crate::collector::suid::SuidBinaryCollector;
use crate::collector::sysctl::SysctlInfo;
use crate::collector::users::UsersInfo;
use crate::collector::{
    CommandRunner, FileSystem, HostInspectionContext, PrivilegeLevel, RealCommandRunner,
    RealFileSystem,
};
use crate::error::EngineError;
use crate::platform::{
    PlatformBackend, PlatformCapability, PlatformDistribution, PlatformFamily, PlatformInfo,
    PlatformVersion,
};

/// Linux platform audit backend.
pub struct LinuxPlatformBackend<FS = RealFileSystem, CR = RealCommandRunner> {
    info: PlatformInfo,
    fs: FS,
    runner: CR,
}

impl<FS: std::fmt::Debug, CR: std::fmt::Debug> std::fmt::Debug for LinuxPlatformBackend<FS, CR> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinuxPlatformBackend")
            .field("info", &self.info)
            .field("fs", &self.fs)
            .field("runner", &self.runner)
            .finish()
    }
}

impl<FS: FileSystem + Clone, CR: CommandRunner + Clone> LinuxPlatformBackend<FS, CR> {
    /// Constructs a fallback generic Linux backend with the specified filesystem and command runner.
    #[must_use]
    pub fn fallback(fs: FS, runner: CR) -> Self {
        let info = PlatformInfo {
            family: PlatformFamily::Linux,
            distribution: PlatformDistribution::Unknown,
            version: PlatformVersion::parse("0.0.0"),
            architecture: std::env::consts::ARCH.to_string(),
            kernel_release: "unknown".to_string(),
            hostname: "localhost".to_string(),
            pretty_name: "Generic Linux Host".to_string(),
            machine_id: None,
            capabilities: LinuxPlatformBackend::default_capabilities(),
        };

        Self { info, fs, runner }
    }
}

impl LinuxPlatformBackend<RealFileSystem, RealCommandRunner> {
    /// Constructs a fallback generic Linux backend.
    #[must_use]
    pub fn generic_fallback() -> Self {
        Self::fallback(RealFileSystem, RealCommandRunner)
    }

    /// Returns the standard Linux capabilities.
    #[must_use]
    pub fn default_capabilities() -> Vec<PlatformCapability> {
        vec![
            PlatformCapability::KernelSysctl,
            PlatformCapability::SshDaemon,
            PlatformCapability::Firewall,
            PlatformCapability::ListeningPorts,
            PlatformCapability::SuidSgidBinaries,
            PlatformCapability::FilePermissions,
            PlatformCapability::SystemUsers,
            PlatformCapability::EnvironmentVariables,
        ]
    }
}

impl<FS: FileSystem + Clone, CR: CommandRunner + Clone> LinuxPlatformBackend<FS, CR> {
    /// Detects the Linux platform environment using the provided filesystem and command runner.
    ///
    /// # Errors
    /// Returns [`EngineError`] if reading `/etc/os-release` fails.
    pub fn detect(fs: &FS, runner: &CR) -> Result<Self, EngineError> {
        let content = if fs.exists("/etc/os-release") {
            fs.read_to_string("/etc/os-release")?
        } else if fs.exists("/usr/lib/os-release") {
            fs.read_to_string("/usr/lib/os-release")?
        } else {
            String::new()
        };

        let mut id = String::new();
        let mut version_id = String::new();
        let mut pretty_name = String::new();
        let mut codename = String::new();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Some((k, v)) = line.split_once('=') {
                let key = k.trim();
                let val = v.trim().trim_matches('"').trim_matches('\'');
                match key {
                    "ID" => id = val.to_string(),
                    "VERSION_ID" => version_id = val.to_string(),
                    "PRETTY_NAME" => pretty_name = val.to_string(),
                    "VERSION_CODENAME" => codename = val.to_string(),
                    _ => {}
                }
            }
        }

        let distribution = match id.to_lowercase().as_str() {
            "ubuntu" => PlatformDistribution::Ubuntu,
            "debian" => PlatformDistribution::Debian,
            "alpine" => PlatformDistribution::Alpine,
            "fedora" => PlatformDistribution::Fedora,
            "rhel" => PlatformDistribution::Rhel,
            "centos" => PlatformDistribution::Centos,
            "arch" => PlatformDistribution::Arch,
            "" => PlatformDistribution::Unknown,
            other => PlatformDistribution::OtherLinux(other.to_string()),
        };

        let mut version = PlatformVersion::parse(&version_id);
        if !codename.is_empty() {
            version = version.with_codename(codename);
        }

        if pretty_name.is_empty() {
            pretty_name = if id.is_empty() {
                "Linux Host".to_string()
            } else {
                format!("{id} {version_id}")
            };
        }

        let architecture = std::env::consts::ARCH.to_string();

        let machine_id = if fs.exists("/etc/machine-id") {
            fs.read_to_string("/etc/machine-id")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        } else if fs.exists("/var/lib/dbus/machine-id") {
            fs.read_to_string("/var/lib/dbus/machine-id")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        } else {
            None
        };

        let kernel_release = if fs.exists("/proc/version") {
            fs.read_to_string("/proc/version")
                .unwrap_or_else(|_| "unknown".to_string())
                .lines()
                .next()
                .unwrap_or("unknown")
                .trim()
                .to_string()
        } else {
            "unknown".to_string()
        };

        let hostname = if fs.exists("/etc/hostname") {
            fs.read_to_string("/etc/hostname")
                .unwrap_or_else(|_| "localhost".to_string())
                .trim()
                .to_string()
        } else {
            "localhost".to_string()
        };

        let info = PlatformInfo {
            family: PlatformFamily::Linux,
            distribution,
            version,
            architecture,
            kernel_release,
            hostname,
            pretty_name,
            machine_id,
            capabilities: LinuxPlatformBackend::default_capabilities(),
        };

        Ok(Self {
            info,
            fs: fs.clone(),
            runner: runner.clone(),
        })
    }

    /// Creates an explicit Linux platform backend with given metadata.
    #[must_use]
    pub const fn with_info(info: PlatformInfo, fs: FS, runner: CR) -> Self {
        Self { info, fs, runner }
    }
}

impl<FS: FileSystem + Send + Sync, CR: CommandRunner + Send + Sync> PlatformBackend
    for LinuxPlatformBackend<FS, CR>
{
    fn info(&self) -> &PlatformInfo {
        &self.info
    }

    fn is_supported(&self) -> bool {
        match self.info.distribution {
            PlatformDistribution::Ubuntu => {
                // Ubuntu 24.04 LTS is officially supported and verified in CI container
                self.info.version.major == 24
            }
            PlatformDistribution::Debian => {
                // Debian 12 (Bookworm) and Debian 13 (Trixie) are officially supported
                self.info.version.major == 12 || self.info.version.major == 13
            }
            _ => false,
        }
    }

    fn collect_context(&self) -> Result<HostInspectionContext, EngineError> {
        let os_info = OsInfo::collect(&self.fs).ok();
        let ssh_config = SshConfig::collect(&self.fs).ok();
        let users_info = UsersInfo::collect(&self.fs).ok();
        let listening_ports = ListeningPort::collect(&self.fs).unwrap_or_default();
        let firewall_info = Some(FirewallInfo::collect(&self.runner));
        let file_permissions = FilePermissionInfo::collect_critical(&self.fs).unwrap_or_default();
        let udp_ports = ListeningUdpPort::collect(&self.fs).unwrap_or_default();
        let suid_binaries = SuidBinaryCollector::collect(&self.fs);
        let sysctl = Some(SysctlInfo::collect(&self.fs));
        let path_entries = EnvInfo::collect(&self.fs).path_entries;
        let current_privilege = PrivilegeLevel::current();

        Ok(HostInspectionContext {
            os: os_info,
            ssh: ssh_config,
            users: users_info,
            listening_ports,
            firewall: firewall_info,
            file_permissions,
            udp_ports,
            suid_binaries,
            sysctl,
            path_entries,
            current_privilege,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct MockFs {
        os_release: String,
        hostname: String,
        machine_id: String,
    }

    impl FileSystem for MockFs {
        fn read_to_string(&self, path: &str) -> Result<String, EngineError> {
            match path {
                "/etc/os-release" => Ok(self.os_release.clone()),
                "/etc/hostname" => Ok(self.hostname.clone()),
                "/etc/machine-id" => Ok(self.machine_id.clone()),
                "/proc/version" => Ok("Linux version 6.8.0-45-generic\n".into()),
                _ => Err(EngineError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "not found",
                ))),
            }
        }

        fn exists(&self, path: &str) -> bool {
            path == "/etc/os-release"
                || path == "/etc/hostname"
                || path == "/etc/machine-id"
                || path == "/proc/version"
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
    struct MockRunner;
    impl CommandRunner for MockRunner {
        fn run(&self, _program: &str, _args: &[&str]) -> Result<String, EngineError> {
            Ok("Status: active\n".into())
        }
    }

    #[test]
    fn test_detect_ubuntu_24_04() {
        let fs = MockFs {
            os_release: "ID=ubuntu\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04 LTS\"\nVERSION_CODENAME=noble\n".into(),
            hostname: "ubuntu-server\n".into(),
            machine_id: "a1b2c3d4\n".into(),
        };

        let backend = LinuxPlatformBackend::detect(&fs, &MockRunner).expect("detect");
        assert_eq!(backend.info().family, PlatformFamily::Linux);
        assert_eq!(backend.info().distribution, PlatformDistribution::Ubuntu);
        assert_eq!(backend.info().version.major, 24);
        assert_eq!(backend.info().version.minor, 4);
        assert_eq!(backend.info().version.codename.as_deref(), Some("noble"));
        assert!(backend.is_supported());
        assert!(backend.has_capability(PlatformCapability::KernelSysctl));
        assert!(backend.has_capability(PlatformCapability::SshDaemon));
        assert!(!backend.has_capability(PlatformCapability::WindowsRegistry));
    }

    #[test]
    fn test_detect_debian_12_and_13() {
        let fs_deb12 = MockFs {
            os_release: "ID=debian\nVERSION_ID=\"12\"\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nVERSION_CODENAME=bookworm\n".into(),
            hostname: "debian-node\n".into(),
            machine_id: "deb12-mid\n".into(),
        };

        let backend12 = LinuxPlatformBackend::detect(&fs_deb12, &MockRunner).expect("detect");
        assert_eq!(backend12.info().distribution, PlatformDistribution::Debian);
        assert_eq!(backend12.info().version.major, 12);
        // Debian 12 (Bookworm) is an officially validated M3.2 target
        assert!(backend12.is_supported());

        let fs_deb13 = MockFs {
            os_release: "ID=debian\nVERSION_ID=\"13\"\nPRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\nVERSION_CODENAME=trixie\n".into(),
            hostname: "debian-node-13\n".into(),
            machine_id: "deb13-mid\n".into(),
        };

        let backend13 = LinuxPlatformBackend::detect(&fs_deb13, &MockRunner).expect("detect");
        assert_eq!(backend13.info().distribution, PlatformDistribution::Debian);
        assert_eq!(backend13.info().version.major, 13);
        // Debian 13 (Trixie) is an officially validated M3.2 target
        assert!(backend13.is_supported());

        // Legacy/unvalidated Debian version must fail closed
        let fs_deb11 = MockFs {
            os_release: "ID=debian\nVERSION_ID=\"11\"\nPRETTY_NAME=\"Debian GNU/Linux 11 (bullseye)\"\nVERSION_CODENAME=bullseye\n".into(),
            hostname: "debian-node-11\n".into(),
            machine_id: "deb11-mid\n".into(),
        };
        let backend11 = LinuxPlatformBackend::detect(&fs_deb11, &MockRunner).expect("detect");
        assert_eq!(backend11.info().distribution, PlatformDistribution::Debian);
        assert_eq!(backend11.info().version.major, 11);
        assert!(!backend11.is_supported());
    }

    #[test]
    fn test_unsupported_linux_distribution() {
        let fs_arch = MockFs {
            os_release: "ID=arch\nPRETTY_NAME=\"Arch Linux\"\n".into(),
            hostname: "arch-box\n".into(),
            machine_id: "arch-mid\n".into(),
        };

        let backend = LinuxPlatformBackend::detect(&fs_arch, &MockRunner).expect("detect");
        assert_eq!(backend.info().distribution, PlatformDistribution::Arch);
        // Arch is not an officially supported M3 target distribution
        assert!(!backend.is_supported());

        // Unvalidated Ubuntu release must fail closed
        let fs_ub22 = MockFs {
            os_release: "ID=ubuntu\nVERSION_ID=\"22.04\"\nPRETTY_NAME=\"Ubuntu 22.04 LTS\"\nVERSION_CODENAME=jammy\n".into(),
            hostname: "ubuntu-22\n".into(),
            machine_id: "ub22-mid\n".into(),
        };
        let backend_ub22 = LinuxPlatformBackend::detect(&fs_ub22, &MockRunner).expect("detect");
        assert_eq!(
            backend_ub22.info().distribution,
            PlatformDistribution::Ubuntu
        );
        assert!(!backend_ub22.is_supported());

        // Unvalidated Ubuntu release must fail closed
        let fs_ub22 = MockFs {
            os_release: "ID=ubuntu\nVERSION_ID=\"22.04\"\nPRETTY_NAME=\"Ubuntu 22.04 LTS\"\nVERSION_CODENAME=jammy\n".into(),
            hostname: "ubuntu-22\n".into(),
            machine_id: "ub22-mid\n".into(),
        };
        let backend_ub22 = LinuxPlatformBackend::detect(&fs_ub22, &MockRunner).expect("detect");
        assert_eq!(
            backend_ub22.info().distribution,
            PlatformDistribution::Ubuntu
        );
        assert!(!backend_ub22.is_supported());
    }
}
