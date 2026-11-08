//! Built-in security audit rules for Apple macOS platforms (M3.4).
//!
//! Evaluates native macOS security posture across:
//! - System Integrity Protection (SIP)
//! - `FileVault` full-disk encryption
//! - Gatekeeper application assessment
//! - macOS Application Firewall
//! - Automatic background security updates
//! - Remote Login (SSH) and Remote Management (ARD) exposure
//! - Built-in Guest account status
//! - `LaunchDaemons` file permissions
//! - Wildcard network file sharing ports (SMB/AFP)
//! - System `PATH` directory permission integrity

use crate::collector::HostInspectionContext;
use crate::collector::PrivilegeLevel;
use crate::platform::{PlatformCapability, PlatformFamily};
use crate::profile::AuditProfile;
use crate::rule::{Rule, RuleFinding};
use openaudit_core::{EvidenceType, Severity};

static MACOS_PLATFORMS: &[PlatformFamily] = &[PlatformFamily::MacOS];
static SIP_CAPS: &[PlatformCapability] = &[PlatformCapability::MacosSip];
static FILEVAULT_CAPS: &[PlatformCapability] = &[PlatformCapability::MacosFileVault];
static GATEKEEPER_CAPS: &[PlatformCapability] = &[PlatformCapability::MacosGatekeeper];
static FIREWALL_CAPS: &[PlatformCapability] = &[PlatformCapability::Firewall];
static USERS_CAPS: &[PlatformCapability] = &[PlatformCapability::SystemUsers];
static PORTS_CAPS: &[PlatformCapability] = &[PlatformCapability::ListeningPorts];
static FS_CAPS: &[PlatformCapability] = &[PlatformCapability::FilePermissions];
static ENV_CAPS: &[PlatformCapability] = &[PlatformCapability::EnvironmentVariables];

// =============================================================================
// 1. System Integrity Protection (SIP) Rule
// =============================================================================

/// Rule detecting disabled macOS System Integrity Protection (SIP).
#[derive(Debug, Default, Clone, Copy)]
pub struct MacosSipDisabledRule;

impl Rule for MacosSipDisabledRule {
    fn id(&self) -> &'static str {
        "macos.sip.disabled"
    }

    fn title(&self) -> &'static str {
        "System Integrity Protection (SIP) Disabled"
    }

    fn description(&self) -> &'static str {
        "System Integrity Protection (rootless) is disabled. SIP prevents unauthorized modification of critical system binaries, directories, and running processes even by the root user."
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn remediation(&self) -> &'static str {
        "Reboot into macOS Recovery Mode, open Terminal from Utilities, and execute 'csrutil enable'. Then reboot back into macOS."
    }

    fn required_privilege(&self) -> PrivilegeLevel {
        PrivilegeLevel::Unprivileged
    }

    fn target_platforms(&self) -> &[PlatformFamily] {
        MACOS_PLATFORMS
    }

    fn required_capabilities(&self) -> &[PlatformCapability] {
        SIP_CAPS
    }

    fn evaluate(&self, context: &HostInspectionContext) -> Vec<RuleFinding> {
        let Some(sec) = context.macos_security.as_ref() else {
            return Vec::new();
        };

        if sec.sip_enabled {
            Vec::new()
        } else {
            vec![RuleFinding {
                rule_id: self.id(),
                target: "SystemIntegrityProtection".into(),
                title: self.title().into(),
                description: self.description().into(),
                remediation: self.remediation().into(),
                severity: self.severity(),
                evidence_text: format!("csrutil: {}", sec.sip_status),
                evidence_type: EvidenceType::SystemState,
            }]
        }
    }
}

// =============================================================================
// 2. FileVault Full-Disk Encryption Rule
// =============================================================================

/// Rule detecting disabled `FileVault` full-disk encryption.
#[derive(Debug, Default, Clone, Copy)]
pub struct MacosFileVaultDisabledRule;

impl Rule for MacosFileVaultDisabledRule {
    fn id(&self) -> &'static str {
        "macos.filevault.disabled"
    }

    fn title(&self) -> &'static str {
        "FileVault Full-Disk Encryption Disabled"
    }

    fn description(&self) -> &'static str {
        "FileVault disk encryption is turned off. If the device is lost, stolen, or booted in target disk mode, unencrypted filesystem contents may be directly extracted."
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn remediation(&self) -> &'static str {
        "Enable FileVault in System Settings > Privacy & Security > FileVault or enforce encryption via Mobile Device Management (MDM)."
    }

    fn required_privilege(&self) -> PrivilegeLevel {
        PrivilegeLevel::Unprivileged
    }

    fn target_platforms(&self) -> &[PlatformFamily] {
        MACOS_PLATFORMS
    }

    fn required_capabilities(&self) -> &[PlatformCapability] {
        FILEVAULT_CAPS
    }

    fn evaluate(&self, context: &HostInspectionContext) -> Vec<RuleFinding> {
        let Some(sec) = context.macos_security.as_ref() else {
            return Vec::new();
        };

        if sec.filevault_enabled {
            Vec::new()
        } else {
            vec![RuleFinding {
                rule_id: self.id(),
                target: "FileVault:DiskEncryption".into(),
                title: self.title().into(),
                description: self.description().into(),
                remediation: self.remediation().into(),
                severity: self.severity(),
                evidence_text: format!("fdesetup: {}", sec.filevault_status),
                evidence_type: EvidenceType::SystemState,
            }]
        }
    }
}

// =============================================================================
// 3. Gatekeeper Assessment Rule
// =============================================================================

/// Rule detecting disabled Gatekeeper assessment.
#[derive(Debug, Default, Clone, Copy)]
pub struct MacosGatekeeperDisabledRule;

impl Rule for MacosGatekeeperDisabledRule {
    fn id(&self) -> &'static str {
        "macos.gatekeeper.disabled"
    }

    fn title(&self) -> &'static str {
        "Gatekeeper Application Assessment Disabled"
    }

    fn description(&self) -> &'static str {
        "Gatekeeper assessment is disabled, allowing unsigned or un-notarized applications to execute without operator warning or security quarantine assessment."
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn remediation(&self) -> &'static str {
        "Enable Gatekeeper by running 'sudo spctl --master-enable' or configuring System Settings > Privacy & Security > Security to allow App Store and identified developers."
    }

    fn required_privilege(&self) -> PrivilegeLevel {
        PrivilegeLevel::Unprivileged
    }

    fn target_platforms(&self) -> &[PlatformFamily] {
        MACOS_PLATFORMS
    }

    fn required_capabilities(&self) -> &[PlatformCapability] {
        GATEKEEPER_CAPS
    }

    fn evaluate(&self, context: &HostInspectionContext) -> Vec<RuleFinding> {
        let Some(sec) = context.macos_security.as_ref() else {
            return Vec::new();
        };

        if sec.gatekeeper_enabled {
            Vec::new()
        } else {
            vec![RuleFinding {
                rule_id: self.id(),
                target: "Gatekeeper:AppAssessment".into(),
                title: self.title().into(),
                description: self.description().into(),
                remediation: self.remediation().into(),
                severity: self.severity(),
                evidence_text: format!("spctl: {}", sec.gatekeeper_status),
                evidence_type: EvidenceType::SystemState,
            }]
        }
    }
}

// =============================================================================
// 4. macOS Application Firewall Rule
// =============================================================================

/// Rule detecting disabled macOS Application Firewall.
#[derive(Debug, Default, Clone, Copy)]
pub struct MacosFirewallDisabledRule;

impl Rule for MacosFirewallDisabledRule {
    fn id(&self) -> &'static str {
        "macos.firewall.disabled"
    }

    fn title(&self) -> &'static str {
        "macOS Application Firewall Disabled"
    }

    fn description(&self) -> &'static str {
        "The built-in macOS socket filter application firewall is disabled, exposing running network services to unsolicited inbound connections."
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn remediation(&self) -> &'static str {
        "Enable the firewall in System Settings > Network > Firewall or execute 'sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on'."
    }

    fn required_privilege(&self) -> PrivilegeLevel {
        PrivilegeLevel::Unprivileged
    }

    fn target_platforms(&self) -> &[PlatformFamily] {
        MACOS_PLATFORMS
    }

    fn required_capabilities(&self) -> &[PlatformCapability] {
        FIREWALL_CAPS
    }

    fn evaluate(&self, context: &HostInspectionContext) -> Vec<RuleFinding> {
        let Some(sec) = context.macos_security.as_ref() else {
            return Vec::new();
        };

        if sec.firewall_enabled {
            Vec::new()
        } else {
            vec![RuleFinding {
                rule_id: self.id(),
                target: "ApplicationFirewall".into(),
                title: self.title().into(),
                description: self.description().into(),
                remediation: self.remediation().into(),
                severity: self.severity(),
                evidence_text: format!("socketfilterfw: {}", sec.firewall_status),
                evidence_type: EvidenceType::SystemState,
            }]
        }
    }
}

// =============================================================================
// 5. Automatic Software Updates Rule
// =============================================================================

/// Rule detecting disabled automatic background security updates.
#[derive(Debug, Default, Clone, Copy)]
pub struct MacosUpdatesAutoDisabledRule;

impl Rule for MacosUpdatesAutoDisabledRule {
    fn id(&self) -> &'static str {
        "macos.updates.auto-disabled"
    }

    fn title(&self) -> &'static str {
        "Automatic Security Updates Disabled"
    }

    fn description(&self) -> &'static str {
        "Automatic background downloads and critical system definition updates are disabled, leaving the system susceptible to unpatched vulnerabilities."
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn remediation(&self) -> &'static str {
        "Enable automatic updates in System Settings > General > Software Update > Automatic Updates, ensuring 'Install Security Responses and system files' is checked."
    }

    fn required_privilege(&self) -> PrivilegeLevel {
        PrivilegeLevel::Unprivileged
    }

    fn target_platforms(&self) -> &[PlatformFamily] {
        MACOS_PLATFORMS
    }

    fn required_capabilities(&self) -> &[PlatformCapability] {
        FS_CAPS
    }

    fn evaluate(&self, context: &HostInspectionContext) -> Vec<RuleFinding> {
        let Some(sec) = context.macos_security.as_ref() else {
            return Vec::new();
        };

        if sec.auto_update_enabled && sec.critical_update_install {
            Vec::new()
        } else {
            vec![RuleFinding {
                rule_id: self.id(),
                target: "SoftwareUpdate:Preferences".into(),
                title: self.title().into(),
                description: self.description().into(),
                remediation: self.remediation().into(),
                severity: self.severity(),
                evidence_text: format!(
                    "AutoUpdateEnabled: {} CriticalUpdateInstall: {}",
                    sec.auto_update_enabled, sec.critical_update_install
                ),
                evidence_type: EvidenceType::ConfigExcerpt,
            }]
        }
    }
}

// =============================================================================
// 6. Remote Login (SSH) Rule
// =============================================================================

/// Rule detecting active Remote Login (SSH server).
#[derive(Debug, Default, Clone, Copy)]
pub struct MacosRemoteLoginEnabledRule;

impl Rule for MacosRemoteLoginEnabledRule {
    fn id(&self) -> &'static str {
        "macos.remote.login-enabled"
    }

    fn title(&self) -> &'static str {
        "Remote Login (SSH) Active"
    }

    fn description(&self) -> &'static str {
        "Remote Login (SSH server) is active on this Mac. Unless required for administrative purposes, SSH listening on local or public interfaces increases attack surface."
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn remediation(&self) -> &'static str {
        "Disable Remote Login in System Settings > General > Sharing > Remote Login, or restrict access to specific authorized user accounts."
    }

    fn profile(&self) -> AuditProfile {
        AuditProfile::Hardened
    }

    fn required_privilege(&self) -> PrivilegeLevel {
        PrivilegeLevel::Unprivileged
    }

    fn target_platforms(&self) -> &[PlatformFamily] {
        MACOS_PLATFORMS
    }

    fn required_capabilities(&self) -> &[PlatformCapability] {
        PORTS_CAPS
    }

    fn evaluate(&self, context: &HostInspectionContext) -> Vec<RuleFinding> {
        let Some(sec) = context.macos_security.as_ref() else {
            return Vec::new();
        };

        let port_22_listening = context
            .listening_ports
            .iter()
            .any(|p| p.port == 22 && (p.is_wildcard || p.ip == "0.0.0.0" || p.ip == "::"));

        if sec.remote_login_enabled || port_22_listening {
            vec![RuleFinding {
                rule_id: self.id(),
                target: "RemoteLogin:SSH".into(),
                title: self.title().into(),
                description: self.description().into(),
                remediation: self.remediation().into(),
                severity: self.severity(),
                evidence_text: format!(
                    "RemoteLoginEnabled: {} Port22Listening: {}",
                    sec.remote_login_enabled, port_22_listening
                ),
                evidence_type: EvidenceType::SystemState,
            }]
        } else {
            Vec::new()
        }
    }
}

// =============================================================================
// 7. Remote Management (ARD) Rule
// =============================================================================

/// Rule detecting active Apple Remote Desktop (ARD) / Screen Sharing.
#[derive(Debug, Default, Clone, Copy)]
pub struct MacosRemoteManagementEnabledRule;

impl Rule for MacosRemoteManagementEnabledRule {
    fn id(&self) -> &'static str {
        "macos.remote.management-enabled"
    }

    fn title(&self) -> &'static str {
        "Remote Management (ARD) Enabled"
    }

    fn description(&self) -> &'static str {
        "Apple Remote Desktop (ARD) agent or Screen Sharing service is running. Remote management agents allow full graphical and command execution control."
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn remediation(&self) -> &'static str {
        "Turn off Remote Management and Screen Sharing in System Settings > General > Sharing if not strictly required."
    }

    fn profile(&self) -> AuditProfile {
        AuditProfile::Hardened
    }

    fn required_privilege(&self) -> PrivilegeLevel {
        PrivilegeLevel::Unprivileged
    }

    fn target_platforms(&self) -> &[PlatformFamily] {
        MACOS_PLATFORMS
    }

    fn required_capabilities(&self) -> &[PlatformCapability] {
        PORTS_CAPS
    }

    fn evaluate(&self, context: &HostInspectionContext) -> Vec<RuleFinding> {
        let Some(sec) = context.macos_security.as_ref() else {
            return Vec::new();
        };

        let vnc_listening = context.listening_ports.iter().any(|p| {
            (p.port == 3283 || p.port == 5900)
                && (p.is_wildcard || p.ip == "0.0.0.0" || p.ip == "::")
        });

        if sec.remote_management_enabled || vnc_listening {
            vec![RuleFinding {
                rule_id: self.id(),
                target: "RemoteManagement:ARD".into(),
                title: self.title().into(),
                description: self.description().into(),
                remediation: self.remediation().into(),
                severity: self.severity(),
                evidence_text: format!(
                    "RemoteManagementService: {} VncPortListening: {}",
                    sec.remote_management_enabled, vnc_listening
                ),
                evidence_type: EvidenceType::SystemState,
            }]
        } else {
            Vec::new()
        }
    }
}

// =============================================================================
// 8. Guest Account Rule
// =============================================================================

/// Rule detecting active built-in Guest user account.
#[derive(Debug, Default, Clone, Copy)]
pub struct MacosGuestAccountEnabledRule;

impl Rule for MacosGuestAccountEnabledRule {
    fn id(&self) -> &'static str {
        "macos.accounts.guest-enabled"
    }

    fn title(&self) -> &'static str {
        "Guest Account Active"
    }

    fn description(&self) -> &'static str {
        "The built-in Guest account is active, allowing unauthenticated physical users to log into the system."
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn remediation(&self) -> &'static str {
        "Disable Guest User in System Settings > Users & Groups > Guest User."
    }

    fn required_privilege(&self) -> PrivilegeLevel {
        PrivilegeLevel::Unprivileged
    }

    fn target_platforms(&self) -> &[PlatformFamily] {
        MACOS_PLATFORMS
    }

    fn required_capabilities(&self) -> &[PlatformCapability] {
        USERS_CAPS
    }

    fn evaluate(&self, context: &HostInspectionContext) -> Vec<RuleFinding> {
        let Some(accounts) = context.macos_accounts.as_ref() else {
            return Vec::new();
        };

        if accounts.guest_enabled {
            vec![RuleFinding {
                rule_id: self.id(),
                target: "UserAccount:Guest".into(),
                title: self.title().into(),
                description: self.description().into(),
                remediation: self.remediation().into(),
                severity: self.severity(),
                evidence_text: "Guest account is active in DirectoryServices (dscl)".into(),
                evidence_type: EvidenceType::SystemState,
            }]
        } else {
            Vec::new()
        }
    }
}

// =============================================================================
// 9. LaunchDaemon Insecure File Permissions Rule
// =============================================================================

/// Rule detecting insecure `LaunchDaemon` file permissions.
#[derive(Debug, Default, Clone, Copy)]
pub struct MacosLaunchdInsecurePermissionsRule;

impl Rule for MacosLaunchdInsecurePermissionsRule {
    fn id(&self) -> &'static str {
        "macos.launchd.insecure-permissions"
    }

    fn title(&self) -> &'static str {
        "Insecure LaunchDaemon File Permissions"
    }

    fn description(&self) -> &'static str {
        "One or more LaunchDaemon plist configuration files in /Library/LaunchDaemons have world-writable or insecure permissions, permitting local privilege escalation to root."
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn remediation(&self) -> &'static str {
        "Ensure all plists in '/Library/LaunchDaemons' are owned by root:wheel and permissions are set to 0644 ('sudo chmod 644 /Library/LaunchDaemons/*.plist')."
    }

    fn required_privilege(&self) -> PrivilegeLevel {
        PrivilegeLevel::Unprivileged
    }

    fn target_platforms(&self) -> &[PlatformFamily] {
        MACOS_PLATFORMS
    }

    fn required_capabilities(&self) -> &[PlatformCapability] {
        FS_CAPS
    }

    fn evaluate(&self, context: &HostInspectionContext) -> Vec<RuleFinding> {
        let Some(launchd) = context.macos_launchd.as_ref() else {
            return Vec::new();
        };

        let mut findings = Vec::new();
        for item in &launchd.items {
            if item.is_insecure {
                findings.push(RuleFinding {
                    rule_id: self.id(),
                    target: item.path.clone(),
                    title: self.title().into(),
                    description: format!(
                        "LaunchDaemon '{}' has insecure permissions (mode 0o{:o})",
                        item.name, item.mode
                    ),
                    remediation: self.remediation().into(),
                    severity: self.severity(),
                    evidence_text: format!("Path: {} Mode: 0o{:o}", item.path, item.mode),
                    evidence_type: EvidenceType::ConfigExcerpt,
                });
            }
        }

        findings
    }
}

// =============================================================================
// 10. Exposed File Sharing Ports Rule
// =============================================================================

/// Rule detecting exposed SMB/AFP file sharing ports.
#[derive(Debug, Default, Clone, Copy)]
pub struct MacosExposedSharingPortsRule;

impl Rule for MacosExposedSharingPortsRule {
    fn id(&self) -> &'static str {
        "macos.ports.exposed-sharing"
    }

    fn title(&self) -> &'static str {
        "Exposed File Sharing Port (SMB 445 / AFP 548)"
    }

    fn description(&self) -> &'static str {
        "macOS File Sharing is listening on a wildcard network interface (0.0.0.0 or ::), exposing files to any system on reachable networks."
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn remediation(&self) -> &'static str {
        "Disable File Sharing in System Settings > General > Sharing > File Sharing, or restrict network interface binding via pf firewall."
    }

    fn required_privilege(&self) -> PrivilegeLevel {
        PrivilegeLevel::Unprivileged
    }

    fn target_platforms(&self) -> &[PlatformFamily] {
        MACOS_PLATFORMS
    }

    fn required_capabilities(&self) -> &[PlatformCapability] {
        PORTS_CAPS
    }

    fn evaluate(&self, context: &HostInspectionContext) -> Vec<RuleFinding> {
        let mut findings = Vec::new();

        for port in &context.listening_ports {
            if (port.port == 445 || port.port == 548)
                && (port.is_wildcard || port.ip == "0.0.0.0" || port.ip == "::")
            {
                findings.push(RuleFinding {
                    rule_id: self.id(),
                    target: format!("{}:{}", port.ip, port.port),
                    title: self.title().into(),
                    description: format!(
                        "File sharing port {} is exposed on wildcard socket ({})",
                        port.port, port.ip
                    ),
                    remediation: self.remediation().into(),
                    severity: self.severity(),
                    evidence_text: format!(
                        "Protocol: {} LocalAddress: {}:{}",
                        port.protocol, port.ip, port.port
                    ),
                    evidence_type: EvidenceType::SocketState,
                });
            }
        }

        findings
    }
}

// =============================================================================
// 11. System PATH Permission Rule
// =============================================================================

/// Rule detecting insecure or world-writable directories in system PATH.
#[derive(Debug, Default, Clone, Copy)]
pub struct MacosInsecureSystemPathRule;

impl Rule for MacosInsecureSystemPathRule {
    fn id(&self) -> &'static str {
        "macos.fs.insecure-system-path"
    }

    fn title(&self) -> &'static str {
        "World-Writable Directory in System PATH"
    }

    fn description(&self) -> &'static str {
        "A directory in the system PATH environment variable is world-writable, allowing non-privileged users to place malicious executable wrappers or trojans."
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn remediation(&self) -> &'static str {
        "Remove the directory from PATH or restore secure permissions ('chmod o-w <directory>')."
    }

    fn required_privilege(&self) -> PrivilegeLevel {
        PrivilegeLevel::Unprivileged
    }

    fn target_platforms(&self) -> &[PlatformFamily] {
        MACOS_PLATFORMS
    }

    fn required_capabilities(&self) -> &[PlatformCapability] {
        ENV_CAPS
    }

    fn evaluate(&self, context: &HostInspectionContext) -> Vec<RuleFinding> {
        let mut findings = Vec::new();

        for entry in &context.path_entries {
            if entry.is_world_writable {
                findings.push(RuleFinding {
                    rule_id: self.id(),
                    target: entry.path.clone(),
                    title: self.title().into(),
                    description: format!(
                        "PATH directory '{}' has world-writable mode 0o{:o}",
                        entry.path, entry.mode
                    ),
                    remediation: self.remediation().into(),
                    severity: self.severity(),
                    evidence_text: format!("Directory: {} Mode: 0o{:o}", entry.path, entry.mode),
                    evidence_type: EvidenceType::ConfigExcerpt,
                });
            }
        }

        findings
    }
}

// =============================================================================
// Default Rule Suite Constructor
// =============================================================================

/// Returns the standard set of 11 native macOS security audit rules.
#[must_use]
pub fn default_macos_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(MacosSipDisabledRule),
        Box::new(MacosFileVaultDisabledRule),
        Box::new(MacosGatekeeperDisabledRule),
        Box::new(MacosFirewallDisabledRule),
        Box::new(MacosUpdatesAutoDisabledRule),
        Box::new(MacosRemoteLoginEnabledRule),
        Box::new(MacosRemoteManagementEnabledRule),
        Box::new(MacosGuestAccountEnabledRule),
        Box::new(MacosLaunchdInsecurePermissionsRule),
        Box::new(MacosExposedSharingPortsRule),
        Box::new(MacosInsecureSystemPathRule),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collector::macos::{
        MacosAccount, MacosAccountsInfo, MacosLaunchdInfo, MacosLaunchdItem, MacosSecurityInfo,
    };

    #[test]
    fn test_macos_sip_and_filevault_rules_evaluation() {
        let rule_sip = MacosSipDisabledRule;
        let rule_fv = MacosFileVaultDisabledRule;

        let ctx_insecure = HostInspectionContext {
            macos_security: Some(MacosSecurityInfo {
                sip_enabled: false,
                sip_status: "System Integrity Protection status: disabled.".into(),
                filevault_enabled: false,
                filevault_status: "FileVault is Off.".into(),
                ..Default::default()
            }),
            ..Default::default()
        };

        let findings_sip = rule_sip.evaluate(&ctx_insecure);
        assert_eq!(findings_sip.len(), 1);
        assert_eq!(findings_sip[0].severity, Severity::Critical);

        let findings_fv = rule_fv.evaluate(&ctx_insecure);
        assert_eq!(findings_fv.len(), 1);
        assert_eq!(findings_fv[0].severity, Severity::High);

        let ctx_secure = HostInspectionContext {
            macos_security: Some(MacosSecurityInfo {
                sip_enabled: true,
                sip_status: "System Integrity Protection status: enabled.".into(),
                filevault_enabled: true,
                filevault_status: "FileVault is On.".into(),
                ..Default::default()
            }),
            ..Default::default()
        };

        assert_eq!(rule_sip.evaluate(&ctx_secure).len(), 0);
        assert_eq!(rule_fv.evaluate(&ctx_secure).len(), 0);
    }

    #[test]
    fn test_macos_guest_and_launchd_rules_evaluation() {
        let rule_guest = MacosGuestAccountEnabledRule;
        let rule_launchd = MacosLaunchdInsecurePermissionsRule;

        let ctx = HostInspectionContext {
            macos_accounts: Some(MacosAccountsInfo {
                accounts: vec![MacosAccount {
                    name: "Guest".into(),
                    uid: 201,
                    is_admin: false,
                    is_guest: true,
                    shell: "/bin/bash".into(),
                }],
                administrators: vec!["root".into()],
                guest_enabled: true,
                details: "Guest active".into(),
            }),
            macos_launchd: Some(MacosLaunchdInfo {
                items: vec![MacosLaunchdItem {
                    name: "com.insecure.daemon".into(),
                    path: "/Library/LaunchDaemons/com.insecure.daemon.plist".into(),
                    is_daemon: true,
                    mode: 0o666,
                    is_insecure: true,
                }],
                insecure_items: vec!["com.insecure.daemon".into()],
            }),
            ..Default::default()
        };

        assert_eq!(rule_guest.evaluate(&ctx).len(), 1);
        assert_eq!(rule_launchd.evaluate(&ctx).len(), 1);
    }
}
