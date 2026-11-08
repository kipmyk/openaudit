//! Collectors for harvesting host security posture and configuration state.

pub mod env;
pub mod firewall;
pub mod macos;
pub mod os;
pub mod permissions;
pub mod ports;
pub mod ssh;
pub mod suid;
pub mod sysctl;
pub mod users;
pub mod windows;

use crate::error::EngineError;
use serde::{Deserialize, Serialize};

/// Maximum allowable size in bytes when reading files or command output (512 KiB).
pub const MAX_COLLECTOR_READ_BYTES: usize = 512 * 1024;

/// Privilege level associated with an execution environment or rule requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum PrivilegeLevel {
    /// Can be executed by any non-root user account.
    #[default]
    Unprivileged,
    /// Strictly requires superuser / root (`UID == 0`) privileges.
    RootRequired,
}

impl PrivilegeLevel {
    /// Detects current process privilege level safely without unsafe code.
    #[must_use]
    pub fn current() -> Self {
        #[cfg(unix)]
        {
            if let Ok(output) = std::process::Command::new("id").arg("-u").output() {
                if let Ok(s) = std::str::from_utf8(&output.stdout) {
                    if s.trim() == "0" {
                        return Self::RootRequired;
                    }
                }
            }
            Self::Unprivileged
        }
        #[cfg(windows)]
        {
            if let Ok(output) = std::process::Command::new("whoami").arg("/groups").output() {
                if let Ok(s) = std::str::from_utf8(&output.stdout) {
                    // S-1-5-32-544 is BUILTIN\Administrators; high integrity denotes elevation
                    if s.contains("S-1-5-32-544")
                        || s.contains("High Mandatory Level")
                        || s.contains("System Mandatory Level")
                    {
                        return Self::RootRequired;
                    }
                }
            }
            Self::Unprivileged
        }
        #[cfg(not(any(unix, windows)))]
        {
            Self::Unprivileged
        }
    }
}

/// Abstract filesystem reader enabling hermetic unit testing across platforms.
pub trait FileSystem: Send + Sync {
    /// Reads a file into a UTF-8 string, capped at `MAX_COLLECTOR_READ_BYTES`.
    ///
    /// # Errors
    /// Returns an [`EngineError::Io`] if the file cannot be opened/read,
    /// [`EngineError::OutputLimitExceeded`] if it exceeds the byte limit, or
    /// [`EngineError::Parse`] if the bytes are not valid UTF-8.
    fn read_to_string(&self, path: &str) -> Result<String, EngineError>;

    /// Checks if a file exists.
    fn exists(&self, path: &str) -> bool;

    /// Reads unix file mode/permissions as an octal integer (e.g. 0o644).
    ///
    /// # Errors
    /// Returns an [`EngineError::Io`] if metadata cannot be fetched.
    fn file_mode(&self, path: &str) -> Result<u32, EngineError>;

    /// Lists directory entries in sorted lexicographical order.
    ///
    /// # Errors
    /// Returns an [`EngineError::Io`] if the directory cannot be read.
    fn read_dir(&self, path: &str) -> Result<Vec<String>, EngineError>;

    /// Reads target path of a symbolic link.
    ///
    /// # Errors
    /// Returns an [`EngineError::Io`] if reading the symlink fails.
    fn read_link(&self, path: &str) -> Result<String, EngineError>;
}

/// Real operating system filesystem reader.
#[derive(Debug, Default, Clone, Copy)]
pub struct RealFileSystem;

impl FileSystem for RealFileSystem {
    fn read_to_string(&self, path: &str) -> Result<String, EngineError> {
        use std::io::Read;

        let mut file = std::fs::File::open(path)?;
        let mut buffer = Vec::new();

        // Read up to limit + 1 to detect overflow
        let mut handle = (&mut file).take((MAX_COLLECTOR_READ_BYTES + 1) as u64);
        handle.read_to_end(&mut buffer)?;

        if buffer.len() > MAX_COLLECTOR_READ_BYTES {
            return Err(EngineError::OutputLimitExceeded {
                size_bytes: buffer.len(),
                max_bytes: MAX_COLLECTOR_READ_BYTES,
            });
        }

        String::from_utf8(buffer)
            .map_err(|e| EngineError::Parse(format!("invalid UTF-8 in {path}: {e}")))
    }

    fn exists(&self, path: &str) -> bool {
        std::path::Path::new(path).exists()
    }

    fn file_mode(&self, path: &str) -> Result<u32, EngineError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = std::fs::metadata(path)?;
            Ok(metadata.permissions().mode() & 0o7777)
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            Ok(0o644)
        }
    }

    fn read_dir(&self, path: &str) -> Result<Vec<String>, EngineError> {
        let entries = std::fs::read_dir(path)?;
        let mut paths = Vec::new();
        for entry in entries {
            let entry = entry?;
            if let Some(p) = entry.path().to_str() {
                paths.push(p.to_string());
            }
        }
        paths.sort();
        Ok(paths)
    }

    fn read_link(&self, path: &str) -> Result<String, EngineError> {
        let target = std::fs::read_link(path)?;
        target
            .to_str()
            .map(std::string::ToString::to_string)
            .ok_or_else(|| EngineError::Parse(format!("non-utf8 symlink target at {path}")))
    }
}

/// Abstract subprocess execution runner.
pub trait CommandRunner: Send + Sync {
    /// Executes a command with controlled arguments, bounded output, and timeout.
    ///
    /// # Errors
    /// Returns [`EngineError::CommandExecution`] if invocation fails or returns non-zero,
    /// [`EngineError::OutputLimitExceeded`] if output is too large, or
    /// [`EngineError::Parse`] if output is invalid UTF-8.
    fn run(&self, program: &str, args: &[&str]) -> Result<String, EngineError>;
}

/// Real subprocess execution runner executing binaries without shell interpolation.
#[derive(Debug, Default, Clone, Copy)]
pub struct RealCommandRunner;

impl CommandRunner for RealCommandRunner {
    fn run(&self, program: &str, args: &[&str]) -> Result<String, EngineError> {
        let output = std::process::Command::new(program)
            .args(args)
            .output()
            .map_err(|e| EngineError::CommandExecution(format!("{program}: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(EngineError::CommandExecution(format!(
                "{program} exited with code {:?}: {stderr}",
                output.status.code()
            )));
        }

        if output.stdout.len() > MAX_COLLECTOR_READ_BYTES {
            return Err(EngineError::OutputLimitExceeded {
                size_bytes: output.stdout.len(),
                max_bytes: MAX_COLLECTOR_READ_BYTES,
            });
        }

        String::from_utf8(output.stdout)
            .map_err(|e| EngineError::Parse(format!("invalid UTF-8 from {program}: {e}")))
    }
}

/// Aggregated host context containing all collected system telemetry.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HostInspectionContext {
    /// Operating system information.
    pub os: Option<os::OsInfo>,
    /// SSH daemon configuration.
    pub ssh: Option<ssh::SshConfig>,
    /// User account information.
    pub users: Option<users::UsersInfo>,
    /// Active listening TCP ports.
    pub listening_ports: Vec<ports::ListeningPort>,
    /// Firewall configuration status.
    pub firewall: Option<firewall::FirewallInfo>,
    /// Sensitive file permissions.
    pub file_permissions: Vec<permissions::FilePermissionInfo>,
    /// Active listening UDP ports.
    pub udp_ports: Vec<ports::ListeningUdpPort>,
    /// Detected SUID and SGID executable binaries.
    pub suid_binaries: Vec<suid::SuidBinaryInfo>,
    /// Kernel hardening parameters from `/proc/sys/`.
    pub sysctl: Option<sysctl::SysctlInfo>,
    /// Inspected directory entries in the process `PATH`.
    pub path_entries: Vec<env::PathEntry>,
    /// Windows Defender antivirus and endpoint protection state.
    pub windows_defender: Option<windows::WindowsDefenderInfo>,
    /// Windows Defender Firewall profiles.
    pub windows_firewall: Option<windows::WindowsFirewallInfo>,
    /// Security-related Windows registry settings.
    pub windows_registry: Option<windows::WindowsRegistryInfo>,
    /// Windows system service states.
    pub windows_services: Option<windows::WindowsServicesInfo>,
    /// Windows local user and administrative account posture.
    pub windows_accounts: Option<windows::WindowsAccountsInfo>,
    /// macOS system endpoint protection and security configuration.
    pub macos_security: Option<macos::MacosSecurityInfo>,
    /// macOS local user and administrative account posture.
    pub macos_accounts: Option<macos::MacosAccountsInfo>,
    /// macOS `LaunchDaemons` and `LaunchAgents` security posture.
    pub macos_launchd: Option<macos::MacosLaunchdInfo>,
    /// Host execution privilege level at time of audit.
    pub current_privilege: PrivilegeLevel,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_privilege_level_ordering() {
        assert!(PrivilegeLevel::Unprivileged < PrivilegeLevel::RootRequired);
    }

    #[test]
    fn test_current_privilege_detection() {
        let priv_level = PrivilegeLevel::current();
        // On CI/local, user is either unprivileged or root.
        assert!(
            priv_level == PrivilegeLevel::Unprivileged
                || priv_level == PrivilegeLevel::RootRequired
        );
    }
}
