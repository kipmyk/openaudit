//! Windows platform audit backend interface and native collection implementation (M3.3).
//!
//! Executes native Windows auditing using `PowerShell`, `netsh`, `reg.exe`, and Win32 interfaces,
//! evaluating Windows Defender, Windows Firewall, local accounts, and security registry policies.

use crate::collector::env::EnvInfo;
use crate::collector::os::OsInfo;
use crate::collector::ports::ListeningPort;
use crate::collector::windows::{
    WindowsAccountsInfo, WindowsDefenderInfo, WindowsFirewallInfo, WindowsRegistryInfo,
    WindowsServicesInfo,
};
use crate::collector::{
    CommandRunner, FileSystem, HostInspectionContext, PrivilegeLevel, RealCommandRunner,
    RealFileSystem,
};
use crate::error::EngineError;
use crate::platform::{
    PlatformBackend, PlatformCapability, PlatformDistribution, PlatformFamily, PlatformInfo,
    PlatformVersion,
};

/// Microsoft Windows platform audit backend.
#[derive(Debug, Clone)]
pub struct WindowsPlatformBackend<FS = RealFileSystem, CR = RealCommandRunner> {
    info: PlatformInfo,
    fs: FS,
    runner: CR,
}

impl<FS: FileSystem, CR: CommandRunner> WindowsPlatformBackend<FS, CR> {
    /// Creates a Windows backend instance with detected or provided system metadata.
    #[must_use]
    pub const fn new(info: PlatformInfo, fs: FS, runner: CR) -> Self {
        Self { info, fs, runner }
    }
}

impl<FS: FileSystem + Clone, CR: CommandRunner + Clone> WindowsPlatformBackend<FS, CR> {
    /// Detects current Windows platform properties using the provided filesystem and runner.
    #[must_use]
    pub fn detect_with(fs: &FS, runner: &CR) -> Self {
        let architecture = std::env::consts::ARCH.to_string();
        let hostname = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "localhost".to_string());

        // Attempt PowerShell query for Windows version & edition
        let query_script = "(Get-CimInstance Win32_OperatingSystem).Caption; (Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion').CurrentBuildNumber";
        let output = runner.run(
            "powershell.exe",
            &["-NoProfile", "-NonInteractive", "-Command", query_script],
        );

        let (distribution, version, pretty_name) = output.as_ref().map_or_else(
            |_| {
                (
                    PlatformDistribution::OtherWindows(
                        "PowerShell unavailable or non-Windows host".to_string(),
                    ),
                    PlatformVersion::parse("0.0.0"),
                    "Windows (unknown edition)".to_string(),
                )
            },
            |s| Self::parse_os_detection_output(s),
        );

        let kernel_release = version.raw.clone();

        let info = PlatformInfo {
            family: PlatformFamily::Windows,
            distribution,
            version,
            architecture,
            kernel_release,
            hostname,
            pretty_name,
            machine_id: None,
            capabilities: WindowsPlatformBackend::default_capabilities(),
        };

        Self {
            info,
            fs: fs.clone(),
            runner: runner.clone(),
        }
    }
}

impl<FS: FileSystem, CR: CommandRunner> WindowsPlatformBackend<FS, CR> {
    /// Parses detection output from `PowerShell`.
    #[must_use]
    pub fn parse_os_detection_output(
        output: &str,
    ) -> (PlatformDistribution, PlatformVersion, String) {
        let lines: Vec<&str> = output
            .lines()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        let caption = lines.first().copied().unwrap_or("Microsoft Windows");
        let build_str = lines.get(1).copied().unwrap_or("22631");
        let build_num: u64 = build_str.parse().unwrap_or(22631);

        let (distribution, version_str) = if caption.contains("Server 2025")
            || (caption.contains("Server") && build_num >= 26100)
        {
            (
                PlatformDistribution::WindowsServer2025,
                format!("10.0.{build_str}"),
            )
        } else if caption.contains("Server 2022")
            || (caption.contains("Server") && build_num == 20348)
        {
            (
                PlatformDistribution::WindowsServer2022,
                "10.0.20348".to_string(),
            )
        } else if caption.contains("Windows 11") || build_num >= 22000 {
            (PlatformDistribution::Windows11, format!("10.0.{build_str}"))
        } else if caption.contains("Windows 10") || (10240..22000).contains(&build_num) {
            (PlatformDistribution::Windows10, format!("10.0.{build_str}"))
        } else {
            (
                PlatformDistribution::OtherWindows(caption.to_string()),
                format!("10.0.{build_str}"),
            )
        };

        let version = PlatformVersion::parse(&version_str).with_build(build_str);
        (distribution, version, caption.to_string())
    }

    /// Collects active TCP listening sockets via netstat or `PowerShell`.
    #[must_use]
    pub fn collect_listening_ports(&self) -> Vec<ListeningPort> {
        // Query netstat -ano -p tcp
        self.runner
            .run("netstat.exe", &["-ano", "-p", "tcp"])
            .map_or_else(|_| Vec::new(), |output| Self::parse_netstat_output(&output))
    }

    /// Parses output lines from `netstat -ano -p tcp`.
    #[must_use]
    pub fn parse_netstat_output(output: &str) -> Vec<ListeningPort> {
        let mut ports = Vec::new();

        for line in output.lines() {
            let tokens: Vec<&str> = line.split_whitespace().collect();
            // Typical netstat format: TCP 0.0.0.0:445 0.0.0.0:0 LISTENING 4
            if tokens.len() >= 4 && tokens[0].eq_ignore_ascii_case("tcp") {
                let state = tokens.get(3).copied().unwrap_or_default();
                if state.eq_ignore_ascii_case("listening") {
                    let addr = tokens[1];
                    if let Some((ip, port_str)) = addr.rsplit_once(':') {
                        if let Ok(port) = port_str.parse::<u16>() {
                            let is_wildcard = ip == "0.0.0.0" || ip == "[::]" || ip == "::";
                            ports.push(ListeningPort {
                                protocol: "tcp".into(),
                                ip: ip.to_string(),
                                port,
                                is_wildcard,
                                inode: 0,
                                process_name: tokens.get(4).map(|s| (*s).to_string()),
                            });
                        }
                    }
                }
            }
        }

        ports
    }
}

impl WindowsPlatformBackend<RealFileSystem, RealCommandRunner> {
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
            PlatformCapability::FilePermissions,
        ]
    }

    /// Detects the Windows platform using the real operating system environment.
    #[must_use]
    pub fn detect() -> Self {
        Self::detect_with(&RealFileSystem, &RealCommandRunner)
    }

    /// Creates a Windows backend instance with explicit metadata.
    #[must_use]
    pub const fn with_info(info: PlatformInfo) -> Self {
        Self::new(info, RealFileSystem, RealCommandRunner)
    }
}

impl<FS: FileSystem + Send + Sync, CR: CommandRunner + Send + Sync> PlatformBackend
    for WindowsPlatformBackend<FS, CR>
{
    fn info(&self) -> &PlatformInfo {
        &self.info
    }

    fn is_supported(&self) -> bool {
        match self.info.distribution {
            PlatformDistribution::Windows11 => {
                // Windows 11: major 10, build >= 22000
                self.info
                    .version
                    .build
                    .as_deref()
                    .and_then(|b| b.parse::<u64>().ok())
                    .is_some_and(|b| b >= 22000)
            }
            PlatformDistribution::WindowsServer2022 => {
                // Windows Server 2022: build 20348
                self.info
                    .version
                    .build
                    .as_deref()
                    .is_some_and(|b| b == "20348")
            }
            PlatformDistribution::WindowsServer2025 => {
                // Windows Server 2025: build >= 26100
                self.info
                    .version
                    .build
                    .as_deref()
                    .and_then(|b| b.parse::<u64>().ok())
                    .is_some_and(|b| b >= 26100)
            }
            _ => false,
        }
    }

    fn collect_context(&self) -> Result<HostInspectionContext, EngineError> {
        if !self.is_supported() {
            return Err(EngineError::UnsupportedPlatform(format!(
                "Windows environment '{}' (build {:?}) is not an officially supported Milestone M3.3 target",
                self.info.pretty_name, self.info.version.build
            )));
        }

        let os_info = Some(OsInfo {
            id: "windows".to_string(),
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

        let windows_defender = Some(WindowsDefenderInfo::collect(&self.runner));
        let windows_firewall = Some(WindowsFirewallInfo::collect(&self.runner));
        let windows_registry = Some(WindowsRegistryInfo::collect(&self.runner));
        let windows_services = Some(WindowsServicesInfo::collect(&self.runner));
        let windows_accounts = Some(WindowsAccountsInfo::collect(&self.runner));
        let listening_ports = self.collect_listening_ports();
        let path_entries = EnvInfo::collect(&self.fs).path_entries;
        let current_privilege = PrivilegeLevel::current();

        Ok(HostInspectionContext {
            os: os_info,
            ssh: None,
            users: None,
            listening_ports,
            firewall: None,
            file_permissions: Vec::new(),
            udp_ports: Vec::new(),
            suid_binaries: Vec::new(),
            sysctl: None,
            path_entries,
            windows_defender,
            windows_firewall,
            windows_registry,
            windows_services,
            windows_accounts,
            current_privilege,
            ..Default::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct MockWindowsRunner {
        os_output: String,
        netstat_output: String,
    }

    impl CommandRunner for MockWindowsRunner {
        fn run(&self, program: &str, args: &[&str]) -> Result<String, EngineError> {
            if program.contains("powershell") {
                Ok(self.os_output.clone())
            } else if program.contains("netstat") {
                Ok(self.netstat_output.clone())
            } else if program.contains("netsh") {
                Ok("Domain Profile Settings:\n  State ON\nPublic Profile Settings:\n  State ON\nPrivate Profile Settings:\n  State ON\n".into())
            } else if program.contains("reg") {
                Ok(
                    "HKEY_LOCAL_MACHINE\\Software\\Policies\n    EnableLUA    REG_DWORD    0x1\n"
                        .into(),
                )
            } else {
                Err(EngineError::CommandExecution(format!(
                    "{program} not mocked: {args:?}"
                )))
            }
        }
    }

    #[derive(Clone)]
    struct MockWindowsFs;
    impl FileSystem for MockWindowsFs {
        fn read_to_string(&self, _path: &str) -> Result<String, EngineError> {
            Ok(String::new())
        }
        fn exists(&self, _path: &str) -> bool {
            false
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

    #[test]
    fn test_windows_11_detection_and_support() {
        let runner = MockWindowsRunner {
            os_output: "Microsoft Windows 11 Enterprise\n22631\n".into(),
            netstat_output:
                "  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4\n".into(),
        };

        let backend = WindowsPlatformBackend::detect_with(&MockWindowsFs, &runner);
        assert_eq!(backend.info().family, PlatformFamily::Windows);
        assert_eq!(backend.info().distribution, PlatformDistribution::Windows11);
        assert_eq!(backend.info().version.build.as_deref(), Some("22631"));
        assert!(
            backend.is_supported(),
            "Windows 11 build 22631 must be supported in M3.3"
        );
        assert!(backend.has_capability(PlatformCapability::WindowsRegistry));
        assert!(backend.has_capability(PlatformCapability::WindowsDefender));
        assert!(!backend.has_capability(PlatformCapability::KernelSysctl));

        let ctx = backend.collect_context().expect("collect context");
        assert!(ctx.windows_defender.is_some());
        assert!(ctx.windows_firewall.is_some());
        assert_eq!(ctx.listening_ports.len(), 1);
        assert_eq!(ctx.listening_ports[0].port, 445);
    }

    #[test]
    fn test_windows_server_2022_support() {
        let runner = MockWindowsRunner {
            os_output: "Microsoft Windows Server 2022 Datacenter\n20348\n".into(),
            netstat_output: String::new(),
        };

        let backend = WindowsPlatformBackend::detect_with(&MockWindowsFs, &runner);
        assert_eq!(
            backend.info().distribution,
            PlatformDistribution::WindowsServer2022
        );
        assert_eq!(backend.info().version.build.as_deref(), Some("20348"));
        assert!(
            backend.is_supported(),
            "Windows Server 2022 must be supported in M3.3"
        );
    }

    #[test]
    fn test_legacy_windows_10_fails_closed() {
        let runner = MockWindowsRunner {
            os_output: "Microsoft Windows 10 Pro\n19045\n".into(),
            netstat_output: String::new(),
        };

        let backend = WindowsPlatformBackend::detect_with(&MockWindowsFs, &runner);
        assert_eq!(backend.info().distribution, PlatformDistribution::Windows10);
        assert!(
            !backend.is_supported(),
            "Legacy Windows 10 must fail closed in M3.3"
        );

        let err = backend.collect_context().unwrap_err();
        assert!(matches!(err, EngineError::UnsupportedPlatform(_)));
    }
}
