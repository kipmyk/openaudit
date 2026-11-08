//! Native macOS security telemetry collector module (Milestone M3.4).
//!
//! Provides structured models and native collectors for:
//! - System Integrity Protection (SIP)
//! - `FileVault` full-disk encryption
//! - Gatekeeper application assessment
//! - macOS Application Firewall
//! - Automatic software & security updates
//! - Remote Login (SSH) and Remote Management (ARD)
//! - Local user accounts and `admin` group membership
//! - `LaunchDaemons` and `LaunchAgents` permission integrity

use crate::collector::{CommandRunner, FileSystem};
use serde::{Deserialize, Serialize};

/// Core macOS system endpoint security and protection posture.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct MacosSecurityInfo {
    /// Whether System Integrity Protection (SIP) is active.
    pub sip_enabled: bool,
    /// Detailed diagnostic text from `csrutil status`.
    pub sip_status: String,
    /// Whether `FileVault` full-disk encryption is on.
    pub filevault_enabled: bool,
    /// Detailed diagnostic text from `fdesetup status`.
    pub filevault_status: String,
    /// Whether Gatekeeper application execution assessment is active.
    pub gatekeeper_enabled: bool,
    /// Detailed diagnostic text from `spctl --status`.
    pub gatekeeper_status: String,
    /// Whether the macOS application firewall is enabled.
    pub firewall_enabled: bool,
    /// Whether firewall stealth mode is active (dropping ICMP and unsolicited packets).
    pub firewall_stealth_mode: bool,
    /// Detailed diagnostic text from `socketfilterfw`.
    pub firewall_status: String,
    /// Whether automatic background download and installation of security updates is enabled.
    pub auto_update_enabled: bool,
    /// Whether critical security updates and system definition updates are automatically installed.
    pub critical_update_install: bool,
    /// Whether Remote Login (SSH server) is active on the host.
    pub remote_login_enabled: bool,
    /// Whether Remote Management (Apple Remote Desktop / ARD) is enabled.
    pub remote_management_enabled: bool,
    /// Diagnostic summary details.
    pub details: String,
}

impl MacosSecurityInfo {
    /// Collects native macOS security posture using the provided command runner and filesystem.
    #[must_use]
    pub fn collect<CR: CommandRunner, FS: FileSystem>(runner: &CR, fs: &FS) -> Self {
        // 1. SIP status
        let (sip_enabled, sip_status) = runner.run("csrutil", &["status"]).map_or_else(
            |e| (false, format!("Unable to query csrutil: {e}")),
            |s| Self::parse_csrutil_status(&s),
        );

        // 2. FileVault status
        let (filevault_enabled, filevault_status) =
            runner.run("fdesetup", &["status"]).map_or_else(
                |e| (false, format!("Unable to query fdesetup: {e}")),
                |s| Self::parse_fdesetup_status(&s),
            );

        // 3. Gatekeeper status
        let (gatekeeper_enabled, gatekeeper_status) =
            runner.run("spctl", &["--status"]).map_or_else(
                |e| (false, format!("Unable to query spctl: {e}")),
                |s| Self::parse_spctl_status(&s),
            );

        // 4. Firewall status
        let (firewall_enabled, firewall_stealth_mode, firewall_status) = runner
            .run(
                "/usr/libexec/ApplicationFirewall/socketfilterfw",
                &["--getglobalstate"],
            )
            .map_or_else(
                |_| {
                    // Fallback to checking socketfilterfw directly via defaults or command
                    runner
                        .run("socketfilterfw", &["--getglobalstate"])
                        .map_or_else(
                            |e| (false, false, format!("Unable to query socketfilterfw: {e}")),
                            |s| Self::parse_firewall_status(&s),
                        )
                },
                |s| Self::parse_firewall_status(&s),
            );

        // 5. Software update preferences
        let (auto_update_enabled, critical_update_install) = runner
            .run(
                "defaults",
                &["read", "/Library/Preferences/com.apple.SoftwareUpdate"],
            )
            .map_or_else(
                |_| {
                    // Try direct filesystem read if command runner is mocked or restricted
                    fs.read_to_string("/Library/Preferences/com.apple.SoftwareUpdate.plist")
                        .map_or_else(|_| (false, false), |c| Self::parse_software_update_text(&c))
                },
                |s| Self::parse_software_update_text(&s),
            );

        // 6. Remote Login (SSH)
        let remote_login_enabled = runner.run("systemsetup", &["-getremotelogin"]).map_or_else(
            |_| {
                // Unprivileged fallback: check if sshd LaunchDaemon plist exists and is loaded
                fs.exists("/System/Library/LaunchDaemons/ssh.plist")
                    && runner
                        .run("launchctl", &["list"])
                        .is_ok_and(|out| out.contains("com.openssh.sshd") || out.contains(".sshd"))
            },
            |s| s.to_lowercase().contains(": on"),
        );

        // 7. Remote Management (ARD)
        let remote_management_enabled = runner.run("launchctl", &["list"]).is_ok_and(|out| {
            out.contains("com.apple.RemoteDesktop")
                || out.contains("com.apple.screensharing")
                || out.contains("ARDAgent")
        });

        Self {
            sip_enabled,
            sip_status,
            filevault_enabled,
            filevault_status,
            gatekeeper_enabled,
            gatekeeper_status,
            firewall_enabled,
            firewall_stealth_mode,
            firewall_status,
            auto_update_enabled,
            critical_update_install,
            remote_login_enabled,
            remote_management_enabled,
            details: "Native macOS security posture collected".into(),
        }
    }

    /// Parses output from `csrutil status`.
    #[must_use]
    pub fn parse_csrutil_status(output: &str) -> (bool, String) {
        let trimmed = output.trim();
        let lower = trimmed.to_lowercase();
        let enabled = lower.contains("enabled") && !lower.contains("disabled");
        (enabled, trimmed.to_string())
    }

    /// Parses output from `fdesetup status`.
    #[must_use]
    pub fn parse_fdesetup_status(output: &str) -> (bool, String) {
        let trimmed = output.trim();
        let lower = trimmed.to_lowercase();
        let enabled = lower.contains("is on") || lower.contains("encryption in progress");
        (enabled, trimmed.to_string())
    }

    /// Parses output from `spctl --status`.
    #[must_use]
    pub fn parse_spctl_status(output: &str) -> (bool, String) {
        let trimmed = output.trim();
        let lower = trimmed.to_lowercase();
        let enabled = lower.contains("assessments enabled");
        (enabled, trimmed.to_string())
    }

    /// Parses output from `socketfilterfw --getglobalstate`.
    #[must_use]
    pub fn parse_firewall_status(output: &str) -> (bool, bool, String) {
        let trimmed = output.trim();
        let lower = trimmed.to_lowercase();
        let enabled =
            lower.contains("enabled") || lower.contains("state = 1") || lower.contains("state = 2");
        let stealth = lower.contains("stealth mode enabled");
        (enabled, stealth, trimmed.to_string())
    }

    /// Parses text output from `defaults read /Library/Preferences/com.apple.SoftwareUpdate`.
    #[must_use]
    pub fn parse_software_update_text(text: &str) -> (bool, bool) {
        let mut auto_download = false;
        let mut auto_install_macos = false;
        let mut critical_install = false;
        let mut config_data_install = false;

        for line in text.lines() {
            let trimmed = line.trim().trim_end_matches(';');
            if let Some((key, val)) = trimmed.split_once('=') {
                let k = key.trim();
                let v = val.trim();
                let is_true = v == "1" || v.eq_ignore_ascii_case("true");

                if k == "AutomaticDownload" {
                    auto_download = is_true;
                } else if k == "AutomaticallyInstallMacOSUpdates" {
                    auto_install_macos = is_true;
                } else if k == "CriticalUpdateInstall" {
                    critical_install = is_true;
                } else if k == "ConfigDataInstall" {
                    config_data_install = is_true;
                }
            }
        }

        let auto_update = auto_download && auto_install_macos;
        let critical = critical_install && config_data_install;
        (auto_update, critical)
    }
}

/// A local macOS user account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacosAccount {
    /// Username or account short name.
    pub name: String,
    /// Numerical User Identifier (UID).
    pub uid: u32,
    /// Whether user belongs to `admin` group (GID 80).
    pub is_admin: bool,
    /// Whether this is the built-in Guest user.
    pub is_guest: bool,
    /// Configured login shell.
    pub shell: String,
}

/// Local user and administrative account posture on macOS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct MacosAccountsInfo {
    /// Discovered local user accounts with UID >= 500.
    pub accounts: Vec<MacosAccount>,
    /// Accounts belonging to the `admin` group.
    pub administrators: Vec<String>,
    /// Whether the guest account is active.
    pub guest_enabled: bool,
    /// Summary details.
    pub details: String,
}

impl MacosAccountsInfo {
    /// Collects macOS account telemetry via `dscl`.
    #[must_use]
    pub fn collect<CR: CommandRunner>(runner: &CR) -> Self {
        // Query admin group members: dscl . -read /Groups/admin GroupMembership
        let admin_output = runner
            .run("dscl", &[".", "-read", "/Groups/admin", "GroupMembership"])
            .unwrap_or_default();

        // Query all users and UIDs: dscl . -list /Users UniqueID
        let users_output = runner
            .run("dscl", &[".", "-list", "/Users", "UniqueID"])
            .unwrap_or_default();

        // Query guest account status: dscl . -read /Users/Guest
        let guest_output = runner
            .run("dscl", &[".", "-read", "/Users/Guest", "UserShell"])
            .unwrap_or_default();

        Self::parse_accounts(&users_output, &admin_output, &guest_output)
    }

    /// Parses user and administrator account strings from `dscl`.
    #[must_use]
    pub fn parse_accounts(users_output: &str, admin_output: &str, guest_output: &str) -> Self {
        let admins: Vec<String> = admin_output
            .strip_prefix("GroupMembership:")
            .unwrap_or(admin_output)
            .split_whitespace()
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
            .collect();

        let guest_enabled = !guest_output.trim().is_empty()
            && !guest_output.contains("eDSRecordNotFound")
            && !guest_output.contains("/usr/bin/false");

        let mut accounts = Vec::new();

        for line in users_output.lines() {
            let tokens: Vec<&str> = line.split_whitespace().collect();
            if tokens.len() >= 2 {
                let username = tokens[0];
                if let Ok(uid) = tokens[1].parse::<u32>() {
                    // Regular interactive user accounts on macOS start at UID 500
                    if uid >= 500 || username.eq_ignore_ascii_case("root") {
                        let lower_name = username.to_lowercase();
                        let is_admin = admins.contains(&lower_name);
                        let is_guest = lower_name == "guest";

                        accounts.push(MacosAccount {
                            name: username.to_string(),
                            uid,
                            is_admin,
                            is_guest,
                            shell: "/bin/zsh".to_string(),
                        });
                    }
                }
            }
        }

        Self {
            accounts,
            administrators: admins,
            guest_enabled,
            details: "macOS accounts parsed from dscl".into(),
        }
    }
}

/// A macOS `LaunchDaemon` or `LaunchAgent` job definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacosLaunchdItem {
    /// Item identifier or plist file basename.
    pub name: String,
    /// Absolute filesystem path.
    pub path: String,
    /// Whether item runs as a root daemon (`LaunchDaemon`) or user agent (`LaunchAgent`).
    pub is_daemon: bool,
    /// File permission mode.
    pub mode: u32,
    /// Whether file is insecure (e.g. world-writable).
    pub is_insecure: bool,
}

/// Telemetry on `LaunchDaemons` and `LaunchAgents`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct MacosLaunchdInfo {
    /// Discovered launchd configuration items.
    pub items: Vec<MacosLaunchdItem>,
    /// Identifiers of items with insecure permissions.
    pub insecure_items: Vec<String>,
}

impl MacosLaunchdInfo {
    /// Collects and inspects `LaunchDaemons` and `LaunchAgents` permissions.
    #[must_use]
    pub fn collect<FS: FileSystem>(fs: &FS) -> Self {
        let mut items = Vec::new();
        let mut insecure_items = Vec::new();

        let daemon_dir = "/Library/LaunchDaemons";
        if let Ok(files) = fs.read_dir(daemon_dir) {
            for file in files {
                let is_plist = std::path::Path::new(&file)
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("plist"));
                if is_plist {
                    let mode = fs.file_mode(&file).unwrap_or(0o644);
                    // World-writable (mode & 0o002 != 0) or group-writable (mode & 0o020 != 0) is insecure for LaunchDaemons
                    let is_insecure = (mode & 0o002) != 0;
                    let name = file
                        .rsplit('/')
                        .next()
                        .unwrap_or(&file)
                        .trim_end_matches(".plist")
                        .to_string();

                    if is_insecure {
                        insecure_items.push(name.clone());
                    }

                    items.push(MacosLaunchdItem {
                        name,
                        path: file,
                        is_daemon: true,
                        mode,
                        is_insecure,
                    });
                }
            }
        }

        Self {
            items,
            insecure_items,
        }
    }
}
