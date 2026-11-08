//! macOS platform audit backend interface and native collection implementation (M3.4).
//!
//! Executes native macOS auditing using `sw_vers`, `csrutil`, `fdesetup`, `spctl`, `socketfilterfw`,
//! `dscl`, and `LaunchDaemon` inspection.

use crate::collector::env::EnvInfo;
use crate::collector::macos::{MacosAccountsInfo, MacosLaunchdInfo, MacosSecurityInfo};
use crate::collector::os::OsInfo;
use crate::collector::ports::ListeningPort;
use crate::collector::{
    CommandRunner, FileSystem, HostInspectionContext, PrivilegeLevel, RealCommandRunner,
    RealFileSystem,
};
use crate::error::EngineError;
use crate::platform::{
    PlatformBackend, PlatformCapability, PlatformDistribution, PlatformFamily, PlatformInfo,
    PlatformVersion,
};

/// Apple macOS platform audit backend.
#[derive(Debug, Clone)]
pub struct MacosPlatformBackend<FS = RealFileSystem, CR = RealCommandRunner> {
    info: PlatformInfo,
    fs: FS,
    runner: CR,
}

impl<FS: FileSystem, CR: CommandRunner> MacosPlatformBackend<FS, CR> {
    /// Creates a macOS backend instance with detected or provided system metadata.
    #[must_use]
    pub const fn new(info: PlatformInfo, fs: FS, runner: CR) -> Self {
        Self { info, fs, runner }
    }
}

impl<FS: FileSystem + Clone, CR: CommandRunner + Clone> MacosPlatformBackend<FS, CR> {
    /// Detects current macOS platform properties using the provided filesystem and command runner.
    #[must_use]
    pub fn detect_with(fs: &FS, runner: &CR) -> Self {
        let architecture = std::env::consts::ARCH.to_string();
        let hostname = std::env::var("HOSTNAME")
            .or_else(|_| std::env::var("HOST"))
            .unwrap_or_else(|_| "localhost".to_string());

        // Attempt sw_vers query
        let output = runner.run("sw_vers", &[]);

        let (distribution, version, pretty_name) = output.as_ref().map_or_else(
            |_| {
                (
                    PlatformDistribution::OtherMacos(
                        "Detection unavailable or non-macOS host".into(),
                    ),
                    PlatformVersion::parse("0.0.0"),
                    "macOS (unverified)".to_string(),
                )
            },
            |s| Self::parse_os_detection_output(s),
        );

        let kernel_release = runner
            .run("uname", &["-r"])
            .unwrap_or_else(|_| "Darwin unknown".to_string())
            .trim()
            .to_string();

        let info = PlatformInfo {
            family: PlatformFamily::MacOS,
            distribution,
            version,
            architecture,
            kernel_release,
            hostname,
            pretty_name,
            machine_id: None,
            capabilities: MacosPlatformBackend::default_capabilities(),
        };

        Self {
            info,
            fs: fs.clone(),
            runner: runner.clone(),
        }
    }
}

impl<FS: FileSystem, CR: CommandRunner> MacosPlatformBackend<FS, CR> {
    /// Parses detection output from `sw_vers`.
    #[must_use]
    pub fn parse_os_detection_output(
        output: &str,
    ) -> (PlatformDistribution, PlatformVersion, String) {
        let mut prod_ver = String::new();
        let mut build_ver = String::new();

        for line in output.lines() {
            if let Some((key, val)) = line.split_once(':') {
                let k = key.trim().to_lowercase();
                let v = val.trim();
                if k == "productversion" {
                    prod_ver = v.to_string();
                } else if k == "buildversion" {
                    build_ver = v.to_string();
                }
            }
        }

        if prod_ver.is_empty() {
            prod_ver = "14.5".to_string();
        }

        let parsed_version = PlatformVersion::parse(&prod_ver).with_build(&build_ver);
        let major = parsed_version.major;

        let (distribution, pretty_name) = match major {
            14 => (
                PlatformDistribution::MacosSonoma,
                format!("macOS Sonoma {prod_ver}"),
            ),
            15 => (
                PlatformDistribution::MacosSequoia,
                format!("macOS Sequoia {prod_ver}"),
            ),
            m if m >= 16 => (
                PlatformDistribution::OtherMacos(format!("macOS {m}")),
                format!("macOS {prod_ver}"),
            ),
            m => (
                PlatformDistribution::OtherMacos(format!("macOS {m} (legacy)")),
                format!("macOS {prod_ver} (legacy unsupported)"),
            ),
        };

        (distribution, parsed_version, pretty_name)
    }

    /// Collects active TCP listening sockets via BSD `netstat -an -p tcp`.
    #[must_use]
    pub fn collect_listening_ports(&self) -> Vec<ListeningPort> {
        self.runner
            .run("netstat", &["-an", "-p", "tcp"])
            .map_or_else(|_| Vec::new(), |out| Self::parse_netstat_output(&out))
    }

    /// Parses output lines from BSD `netstat -an -p tcp`.
    #[must_use]
    pub fn parse_netstat_output(output: &str) -> Vec<ListeningPort> {
        let mut ports = Vec::new();

        for line in output.lines() {
            let tokens: Vec<&str> = line.split_whitespace().collect();
            // Expected format: tcp4 0 0 127.0.0.1.61790 *.* LISTEN
            if tokens.len() >= 6 && tokens[0].starts_with("tcp") && tokens.contains(&"LISTEN") {
                let addr = tokens[3];
                if let Some((mut ip, port_str)) = addr.rsplit_once('.') {
                    if let Ok(port) = port_str.parse::<u16>() {
                        let is_wildcard = ip == "*" || ip == "0.0.0.0" || ip == "::";
                        if ip == "*" {
                            ip = "0.0.0.0";
                        }
                        ports.push(ListeningPort {
                            protocol: "tcp".into(),
                            ip: ip.to_string(),
                            port,
                            is_wildcard,
                            inode: 0,
                            process_name: None,
                        });
                    }
                }
            }
        }

        ports
    }
}

impl MacosPlatformBackend<RealFileSystem, RealCommandRunner> {
    /// Standard capabilities for macOS security posture auditing.
    #[must_use]
    pub fn default_capabilities() -> Vec<PlatformCapability> {
        vec![
            PlatformCapability::MacosGatekeeper,
            PlatformCapability::MacosSip,
            PlatformCapability::MacosFileVault,
            PlatformCapability::Firewall,
            PlatformCapability::SshDaemon,
            PlatformCapability::FilePermissions,
            PlatformCapability::SystemUsers,
            PlatformCapability::ListeningPorts,
            PlatformCapability::EnvironmentVariables,
        ]
    }

    /// Detects current macOS platform properties using the real operating system environment.
    #[must_use]
    pub fn detect() -> Self {
        Self::detect_with(&RealFileSystem, &RealCommandRunner)
    }

    /// Creates a macOS backend instance with explicit metadata.
    #[must_use]
    pub const fn with_info(info: PlatformInfo) -> Self {
        Self::new(info, RealFileSystem, RealCommandRunner)
    }
}

impl<FS: FileSystem + Send + Sync, CR: CommandRunner + Send + Sync> PlatformBackend
    for MacosPlatformBackend<FS, CR>
{
    fn info(&self) -> &PlatformInfo {
        &self.info
    }

    fn is_supported(&self) -> bool {
        // macOS Sonoma (14), Sequoia (15), and newer releases (>= 14) are supported
        match self.info.distribution {
            PlatformDistribution::MacosSonoma | PlatformDistribution::MacosSequoia => true,
            PlatformDistribution::OtherMacos(_) => self.info.version.major >= 14,
            _ => false,
        }
    }

    fn collect_context(&self) -> Result<HostInspectionContext, EngineError> {
        if !self.is_supported() {
            return Err(EngineError::UnsupportedPlatform(format!(
                "macOS environment '{}' (version {}) is not an officially supported Milestone M3.4 target",
                self.info.pretty_name, self.info.version
            )));
        }

        let os_info = Some(OsInfo {
            id: "macos".to_string(),
            version_id: self
                .info
                .version
                .build
                .clone()
                .unwrap_or_else(|| self.info.version.raw.clone()),
            pretty_name: self.info.pretty_name.clone(),
            kernel_release: self.info.kernel_release.clone(),
            architecture: self.info.architecture.clone(),
            machine_id: self.info.machine_id.clone(),
        });

        let macos_security = Some(MacosSecurityInfo::collect(&self.runner, &self.fs));
        let macos_accounts = Some(MacosAccountsInfo::collect(&self.runner));
        let macos_launchd = Some(MacosLaunchdInfo::collect(&self.fs));
        let listening_ports = self.collect_listening_ports();
        let path_entries = EnvInfo::collect(&self.fs).path_entries;
        let current_privilege = PrivilegeLevel::current();

        Ok(HostInspectionContext {
            os: os_info,
            listening_ports,
            path_entries,
            macos_security,
            macos_accounts,
            macos_launchd,
            current_privilege,
            ..Default::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct MockMacosRunner {
        sw_vers_output: String,
        netstat_output: String,
    }

    impl CommandRunner for MockMacosRunner {
        fn run(&self, program: &str, _args: &[&str]) -> Result<String, EngineError> {
            if program == "sw_vers" {
                Ok(self.sw_vers_output.clone())
            } else if program == "netstat" {
                Ok(self.netstat_output.clone())
            } else if program == "csrutil" {
                Ok("System Integrity Protection status: enabled.".into())
            } else if program == "fdesetup" {
                Ok("FileVault is On.".into())
            } else if program == "spctl" {
                Ok("assessments enabled".into())
            } else if program.contains("socketfilterfw") {
                Ok("Firewall is enabled. (State = 1)".into())
            } else if program == "dscl" {
                Ok("GroupMembership: root admin\n".into())
            } else {
                Err(EngineError::CommandExecution(format!(
                    "{program} not mocked"
                )))
            }
        }
    }

    #[derive(Clone, Copy)]
    struct MockMacosFs;

    impl FileSystem for MockMacosFs {
        fn read_to_string(&self, _path: &str) -> Result<String, EngineError> {
            Ok(String::new())
        }

        fn exists(&self, path: &str) -> bool {
            path == "/System/Library/LaunchDaemons/ssh.plist"
        }

        fn file_mode(&self, _path: &str) -> Result<u32, EngineError> {
            Ok(0o644)
        }

        fn read_dir(&self, _path: &str) -> Result<Vec<String>, EngineError> {
            Ok(Vec::new())
        }

        fn read_link(&self, path: &str) -> Result<String, EngineError> {
            Ok(path.to_string())
        }
    }

    #[test]
    fn test_macos_sonoma_detection_and_support() {
        let runner = MockMacosRunner {
            sw_vers_output: "ProductName:\tmacOS\nProductVersion:\t14.5\nBuildVersion:\t23F79\n"
                .into(),
            netstat_output:
                "tcp4       0      0  *.445                  *.*                    LISTEN\n".into(),
        };

        let backend = MacosPlatformBackend::detect_with(&MockMacosFs, &runner);
        assert_eq!(backend.info().family, PlatformFamily::MacOS);
        assert_eq!(
            backend.info().distribution,
            PlatformDistribution::MacosSonoma
        );
        assert_eq!(backend.info().version.major, 14);
        assert_eq!(backend.info().version.build.as_deref(), Some("23F79"));
        assert!(backend.is_supported());
        assert!(backend.has_capability(PlatformCapability::MacosSip));
        assert!(backend.has_capability(PlatformCapability::MacosFileVault));
        assert!(backend.has_capability(PlatformCapability::MacosGatekeeper));

        let ctx = backend.collect_context().expect("collect context");
        assert!(ctx.macos_security.is_some());
        assert_eq!(ctx.listening_ports.len(), 1);
        assert_eq!(ctx.listening_ports[0].port, 445);
        assert!(ctx.listening_ports[0].is_wildcard);
    }

    #[test]
    fn test_macos_sequoia_support() {
        let runner = MockMacosRunner {
            sw_vers_output: "ProductName:\tmacOS\nProductVersion:\t15.0\nBuildVersion:\t24A335\n"
                .into(),
            netstat_output: String::new(),
        };

        let backend = MacosPlatformBackend::detect_with(&MockMacosFs, &runner);
        assert_eq!(
            backend.info().distribution,
            PlatformDistribution::MacosSequoia
        );
        assert_eq!(backend.info().version.major, 15);
        assert!(backend.is_supported());
    }

    #[test]
    fn test_legacy_macos_monterey_fails_closed() {
        let runner = MockMacosRunner {
            sw_vers_output:
                "ProductName:\tmacOS\nProductVersion:\t12.7.4\nBuildVersion:\t21H1123\n".into(),
            netstat_output: String::new(),
        };

        let backend = MacosPlatformBackend::detect_with(&MockMacosFs, &runner);
        assert!(!backend.is_supported());
        let err = backend.collect_context().unwrap_err();
        assert!(matches!(err, EngineError::UnsupportedPlatform(_)));
    }
}
