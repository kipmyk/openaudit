//! Built-in security audit rules for Microsoft Windows platforms (M3.3).
//!
//! Provides native security posture evaluation across:
//! - Local user accounts and Administrator group membership
//! - Windows Defender Antivirus and Real-Time Protection
//! - Windows Defender Firewall profiles (Domain, Private, Public)
//! - Security registry keys (UAC, `SMBv1`, LSA protection)
//! - System services (unquoted service paths)
//! - Network port exposures (SMB, RDP)

use crate::collector::HostInspectionContext;
use crate::collector::PrivilegeLevel;
use crate::platform::{PlatformCapability, PlatformFamily};
use crate::profile::AuditProfile;
use crate::rule::{Rule, RuleFinding};
use openaudit_core::{EvidenceType, Severity};

static WINDOWS_PLATFORMS: &[PlatformFamily] = &[PlatformFamily::Windows];
static DEFENDER_CAPS: &[PlatformCapability] = &[PlatformCapability::WindowsDefender];
static FIREWALL_CAPS: &[PlatformCapability] = &[PlatformCapability::Firewall];
static REGISTRY_CAPS: &[PlatformCapability] = &[PlatformCapability::WindowsRegistry];
static USERS_CAPS: &[PlatformCapability] = &[PlatformCapability::SystemUsers];
static PORTS_CAPS: &[PlatformCapability] = &[PlatformCapability::ListeningPorts];
static ENV_CAPS: &[PlatformCapability] = &[PlatformCapability::EnvironmentVariables];

// =============================================================================
// 1. Windows Defender Rules
// =============================================================================

/// Rule flagging disabled Windows Defender Real-Time Protection.
#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsDefenderRealtimeDisabledRule;

impl Rule for WindowsDefenderRealtimeDisabledRule {
    fn id(&self) -> &'static str {
        "windows.defender.realtime-disabled"
    }

    fn title(&self) -> &'static str {
        "Windows Defender Real-Time Protection Disabled"
    }

    fn description(&self) -> &'static str {
        "Windows Defender on-access real-time scanning is disabled, leaving the host vulnerable to immediate malware execution."
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn remediation(&self) -> &'static str {
        "Enable real-time protection in Windows Security or run 'Set-MpPreference -DisableRealtimeMonitoring $false' in an elevated PowerShell session."
    }

    fn required_privilege(&self) -> PrivilegeLevel {
        PrivilegeLevel::Unprivileged
    }

    fn target_platforms(&self) -> &[PlatformFamily] {
        WINDOWS_PLATFORMS
    }

    fn required_capabilities(&self) -> &[PlatformCapability] {
        DEFENDER_CAPS
    }

    fn evaluate(&self, context: &HostInspectionContext) -> Vec<RuleFinding> {
        let Some(defender) = context.windows_defender.as_ref() else {
            return Vec::new();
        };

        if defender.realtime_protection_enabled {
            Vec::new()
        } else {
            vec![RuleFinding {
                rule_id: self.id(),
                target: "WindowsDefender:RealTimeProtection".into(),
                title: self.title().into(),
                description: self.description().into(),
                remediation: self.remediation().into(),
                severity: self.severity(),
                evidence_text: format!(
                    "AntivirusEnabled: {} RealTimeProtectionEnabled: {}",
                    defender.antivirus_enabled, defender.realtime_protection_enabled
                ),
                evidence_type: EvidenceType::SystemState,
            }]
        }
    }
}

/// Rule flagging disabled Windows Defender Antivirus engine.
#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsDefenderAntivirusDisabledRule;

impl Rule for WindowsDefenderAntivirusDisabledRule {
    fn id(&self) -> &'static str {
        "windows.defender.antivirus-disabled"
    }

    fn title(&self) -> &'static str {
        "Windows Defender Antivirus Inactive"
    }

    fn description(&self) -> &'static str {
        "Windows Defender Antivirus is reported inactive or disabled on the host."
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn remediation(&self) -> &'static str {
        "Ensure Windows Defender Antivirus service (WinDefend) is running and no conflicting unverified AV products disabled it."
    }

    fn required_privilege(&self) -> PrivilegeLevel {
        PrivilegeLevel::Unprivileged
    }

    fn target_platforms(&self) -> &[PlatformFamily] {
        WINDOWS_PLATFORMS
    }

    fn required_capabilities(&self) -> &[PlatformCapability] {
        DEFENDER_CAPS
    }

    fn evaluate(&self, context: &HostInspectionContext) -> Vec<RuleFinding> {
        let Some(defender) = context.windows_defender.as_ref() else {
            return Vec::new();
        };

        if defender.antivirus_enabled {
            Vec::new()
        } else {
            vec![RuleFinding {
                rule_id: self.id(),
                target: "WindowsDefender:AntivirusStatus".into(),
                title: self.title().into(),
                description: self.description().into(),
                remediation: self.remediation().into(),
                severity: self.severity(),
                evidence_text: format!("AntivirusEnabled: false Details: {}", defender.details),
                evidence_type: EvidenceType::SystemState,
            }]
        }
    }
}

// =============================================================================
// 2. Windows Defender Firewall Rules
// =============================================================================

/// Rule detecting any disabled Windows Defender Firewall profile (Domain, Private, Public).
#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsFirewallProfileDisabledRule;

impl Rule for WindowsFirewallProfileDisabledRule {
    fn id(&self) -> &'static str {
        "windows.firewall.profile-disabled"
    }

    fn title(&self) -> &'static str {
        "Windows Defender Firewall Profile Disabled"
    }

    fn description(&self) -> &'static str {
        "One or more Windows Defender Firewall profiles (Domain, Private, or Public) are turned off, allowing unfiltered network traffic."
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn remediation(&self) -> &'static str {
        "Enable all firewall profiles via 'netsh advfirewall set allprofiles state on' or 'Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True'."
    }

    fn required_privilege(&self) -> PrivilegeLevel {
        PrivilegeLevel::Unprivileged
    }

    fn target_platforms(&self) -> &[PlatformFamily] {
        WINDOWS_PLATFORMS
    }

    fn required_capabilities(&self) -> &[PlatformCapability] {
        FIREWALL_CAPS
    }

    fn evaluate(&self, context: &HostInspectionContext) -> Vec<RuleFinding> {
        let Some(fw) = context.windows_firewall.as_ref() else {
            return Vec::new();
        };

        let mut findings = Vec::new();
        for profile in &fw.profiles {
            if !profile.enabled {
                findings.push(RuleFinding {
                    rule_id: self.id(),
                    target: format!("FirewallProfile:{}", profile.name),
                    title: format!("Windows Firewall {} Profile Disabled", profile.name),
                    description: format!(
                        "The {} profile in Windows Defender Firewall is inactive.",
                        profile.name
                    ),
                    remediation: self.remediation().into(),
                    severity: self.severity(),
                    evidence_text: format!("Profile: {} State: Off", profile.name),
                    evidence_type: EvidenceType::SystemState,
                });
            }
        }

        findings
    }
}

// =============================================================================
// 3. Windows Security Registry Rules
// =============================================================================

/// Rule detecting disabled User Account Control (UAC) (`EnableLUA == 0`).
#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsUacDisabledRule;

impl Rule for WindowsUacDisabledRule {
    fn id(&self) -> &'static str {
        "windows.registry.uac-disabled"
    }

    fn title(&self) -> &'static str {
        "User Account Control (UAC) Disabled"
    }

    fn description(&self) -> &'static str {
        "User Account Control (EnableLUA) is disabled in the registry. Processes can silently elevate to administrator privilege without prompting."
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn remediation(&self) -> &'static str {
        "Set 'EnableLUA' to 1 in 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' and restart the host."
    }

    fn required_privilege(&self) -> PrivilegeLevel {
        PrivilegeLevel::Unprivileged
    }

    fn target_platforms(&self) -> &[PlatformFamily] {
        WINDOWS_PLATFORMS
    }

    fn required_capabilities(&self) -> &[PlatformCapability] {
        REGISTRY_CAPS
    }

    fn evaluate(&self, context: &HostInspectionContext) -> Vec<RuleFinding> {
        let Some(reg) = context.windows_registry.as_ref() else {
            return Vec::new();
        };

        if reg.uac_enabled == Some(false) {
            vec![RuleFinding {
                rule_id: self.id(),
                target: r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:EnableLUA"
                    .into(),
                title: self.title().into(),
                description: self.description().into(),
                remediation: self.remediation().into(),
                severity: self.severity(),
                evidence_text: "EnableLUA = 0 (UAC Disabled)".into(),
                evidence_type: EvidenceType::ConfigExcerpt,
            }]
        } else {
            Vec::new()
        }
    }
}

/// Rule detecting enabled legacy `SMBv1` protocol.
#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsSmbv1EnabledRule;

impl Rule for WindowsSmbv1EnabledRule {
    fn id(&self) -> &'static str {
        "windows.registry.smbv1-enabled"
    }

    fn title(&self) -> &'static str {
        "Legacy SMBv1 Protocol Enabled"
    }

    fn description(&self) -> &'static str {
        "The legacy, deprecated SMBv1 protocol is enabled in LanmanServer parameters. SMBv1 lacks modern encryption and is vulnerable to remote code execution (e.g. EternalBlue)."
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn remediation(&self) -> &'static str {
        "Disable SMBv1 by setting 'SMB1' to 0 in 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' or running 'Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol'."
    }

    fn required_privilege(&self) -> PrivilegeLevel {
        PrivilegeLevel::Unprivileged
    }

    fn target_platforms(&self) -> &[PlatformFamily] {
        WINDOWS_PLATFORMS
    }

    fn required_capabilities(&self) -> &[PlatformCapability] {
        REGISTRY_CAPS
    }

    fn evaluate(&self, context: &HostInspectionContext) -> Vec<RuleFinding> {
        let Some(reg) = context.windows_registry.as_ref() else {
            return Vec::new();
        };

        if reg.smbv1_enabled == Some(true) {
            vec![RuleFinding {
                rule_id: self.id(),
                target: r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters:SMB1"
                    .into(),
                title: self.title().into(),
                description: self.description().into(),
                remediation: self.remediation().into(),
                severity: self.severity(),
                evidence_text: "SMB1 = 1 (SMBv1 Enabled)".into(),
                evidence_type: EvidenceType::ConfigExcerpt,
            }]
        } else {
            Vec::new()
        }
    }
}

/// Rule detecting disabled Local Security Authority (LSA) `RunAsPPL` protection.
#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsLsaProtectionDisabledRule;

impl Rule for WindowsLsaProtectionDisabledRule {
    fn id(&self) -> &'static str {
        "windows.registry.lsa-protection-disabled"
    }

    fn title(&self) -> &'static str {
        "LSA Credential Guard (RunAsPPL) Disabled"
    }

    fn description(&self) -> &'static str {
        "Local Security Authority (LSASS) process protection (RunAsPPL) is not enabled, leaving system memory vulnerable to credential dumping attacks."
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn remediation(&self) -> &'static str {
        "Enable LSA protection by configuring 'RunAsPPL' DWORD to 1 or 2 under 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa'."
    }

    fn required_privilege(&self) -> PrivilegeLevel {
        PrivilegeLevel::Unprivileged
    }

    fn target_platforms(&self) -> &[PlatformFamily] {
        WINDOWS_PLATFORMS
    }

    fn required_capabilities(&self) -> &[PlatformCapability] {
        REGISTRY_CAPS
    }

    fn profile(&self) -> AuditProfile {
        AuditProfile::Hardened
    }

    fn evaluate(&self, context: &HostInspectionContext) -> Vec<RuleFinding> {
        let Some(reg) = context.windows_registry.as_ref() else {
            return Vec::new();
        };

        if reg.lsa_protection_enabled == Some(false) {
            vec![RuleFinding {
                rule_id: self.id(),
                target: r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa:RunAsPPL".into(),
                title: self.title().into(),
                description: self.description().into(),
                remediation: self.remediation().into(),
                severity: self.severity(),
                evidence_text: "RunAsPPL = 0 (LSA Protection Disabled)".into(),
                evidence_type: EvidenceType::ConfigExcerpt,
            }]
        } else {
            Vec::new()
        }
    }
}

// =============================================================================
// 4. Windows Services Rules
// =============================================================================

/// Rule detecting unquoted service paths containing spaces.
#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsUnquotedServicePathRule;

impl Rule for WindowsUnquotedServicePathRule {
    fn id(&self) -> &'static str {
        "windows.services.unquoted-path"
    }

    fn title(&self) -> &'static str {
        "Unquoted Windows Service Executable Path"
    }

    fn description(&self) -> &'static str {
        "A system service binary path contains spaces and is not enclosed in quotation marks, permitting local privilege escalation via binary interception."
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn remediation(&self) -> &'static str {
        "Wrap the ImagePath value in double quotes in 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\<service_name>'."
    }

    fn required_privilege(&self) -> PrivilegeLevel {
        PrivilegeLevel::Unprivileged
    }

    fn target_platforms(&self) -> &[PlatformFamily] {
        WINDOWS_PLATFORMS
    }

    fn required_capabilities(&self) -> &[PlatformCapability] {
        REGISTRY_CAPS
    }

    fn evaluate(&self, context: &HostInspectionContext) -> Vec<RuleFinding> {
        let Some(services) = context.windows_services.as_ref() else {
            return Vec::new();
        };

        services
            .services
            .iter()
            .filter(|s| s.is_unquoted_path)
            .map(|s| RuleFinding {
                rule_id: self.id(),
                target: format!("Service:{}:ImagePath", s.name),
                title: format!("Service '{}' Has Unquoted Binary Path", s.name),
                description: format!(
                    "Service '{}' ({}) executes unquoted path '{}'.",
                    s.name, s.display_name, s.binary_path
                ),
                remediation: self.remediation().into(),
                severity: self.severity(),
                evidence_text: format!("Name: {} Path: {}", s.name, s.binary_path),
                evidence_type: EvidenceType::ConfigExcerpt,
            })
            .collect()
    }
}

// =============================================================================
// 5. Windows Accounts Rules
// =============================================================================

/// Rule detecting enabled built-in Guest account.
#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsGuestAccountEnabledRule;

impl Rule for WindowsGuestAccountEnabledRule {
    fn id(&self) -> &'static str {
        "windows.accounts.guest-enabled"
    }

    fn title(&self) -> &'static str {
        "Built-in Guest Account Enabled"
    }

    fn description(&self) -> &'static str {
        "The built-in Windows Guest account is enabled, permitting unauthenticated or passwordless access to local resources."
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn remediation(&self) -> &'static str {
        "Disable the guest account using 'net user guest /active:no' or 'Disable-LocalUser -Name Guest'."
    }

    fn required_privilege(&self) -> PrivilegeLevel {
        PrivilegeLevel::Unprivileged
    }

    fn target_platforms(&self) -> &[PlatformFamily] {
        WINDOWS_PLATFORMS
    }

    fn required_capabilities(&self) -> &[PlatformCapability] {
        USERS_CAPS
    }

    fn evaluate(&self, context: &HostInspectionContext) -> Vec<RuleFinding> {
        let Some(accounts) = context.windows_accounts.as_ref() else {
            return Vec::new();
        };

        if accounts.guest_enabled {
            vec![RuleFinding {
                rule_id: self.id(),
                target: "Account:Guest".into(),
                title: self.title().into(),
                description: self.description().into(),
                remediation: self.remediation().into(),
                severity: self.severity(),
                evidence_text: "Guest account status: Enabled".into(),
                evidence_type: EvidenceType::SystemState,
            }]
        } else {
            Vec::new()
        }
    }
}

/// Rule detecting accounts with no password required.
#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsEmptyPasswordAccountRule;

impl Rule for WindowsEmptyPasswordAccountRule {
    fn id(&self) -> &'static str {
        "windows.accounts.empty-password"
    }

    fn title(&self) -> &'static str {
        "Local Account Without Password Requirement"
    }

    fn description(&self) -> &'static str {
        "A local user account is configured without requiring a password, permitting blank password authentication."
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn remediation(&self) -> &'static str {
        "Enforce password requirement with 'Set-LocalUser -Name <user> -PasswordNeverExpires $false' and assign a strong password."
    }

    fn required_privilege(&self) -> PrivilegeLevel {
        PrivilegeLevel::Unprivileged
    }

    fn target_platforms(&self) -> &[PlatformFamily] {
        WINDOWS_PLATFORMS
    }

    fn required_capabilities(&self) -> &[PlatformCapability] {
        USERS_CAPS
    }

    fn evaluate(&self, context: &HostInspectionContext) -> Vec<RuleFinding> {
        let Some(accounts) = context.windows_accounts.as_ref() else {
            return Vec::new();
        };

        accounts
            .empty_password_accounts
            .iter()
            .map(|name| RuleFinding {
                rule_id: self.id(),
                target: format!("Account:{name}:PasswordRequired"),
                title: format!("Account '{name}' Does Not Require Password"),
                description: format!("User account '{name}' has PasswordRequired set to false."),
                remediation: self.remediation().into(),
                severity: self.severity(),
                evidence_text: format!("Account: {name} PasswordRequired: false"),
                evidence_type: EvidenceType::SystemState,
            })
            .collect()
    }
}

// =============================================================================
// 6. Windows Port Exposure Rules
// =============================================================================

/// Rule detecting exposed SMB port 445 on wildcard interfaces.
#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsExposedSmbPortRule;

impl Rule for WindowsExposedSmbPortRule {
    fn id(&self) -> &'static str {
        "windows.ports.exposed-smb"
    }

    fn title(&self) -> &'static str {
        "SMB File Sharing Exposed on All Interfaces"
    }

    fn description(&self) -> &'static str {
        "TCP port 445 (Server Message Block) is listening on a wildcard address (0.0.0.0 or ::), exposing Windows file sharing to untrusted network segments."
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn remediation(&self) -> &'static str {
        "Restrict SMB port 445 via Windows Defender Firewall or bind file sharing to specific internal network adapters."
    }

    fn required_privilege(&self) -> PrivilegeLevel {
        PrivilegeLevel::Unprivileged
    }

    fn target_platforms(&self) -> &[PlatformFamily] {
        WINDOWS_PLATFORMS
    }

    fn required_capabilities(&self) -> &[PlatformCapability] {
        PORTS_CAPS
    }

    fn evaluate(&self, context: &HostInspectionContext) -> Vec<RuleFinding> {
        let mut findings = Vec::new();

        for port in &context.listening_ports {
            if port.port == 445 && port.is_wildcard {
                findings.push(RuleFinding {
                    rule_id: self.id(),
                    target: format!("{}:445", port.ip),
                    title: self.title().into(),
                    description: self.description().into(),
                    remediation: self.remediation().into(),
                    severity: self.severity(),
                    evidence_text: format!("TCP {}:445 listening", port.ip),
                    evidence_type: EvidenceType::SystemState,
                });
            }
        }

        findings
    }
}

/// Rule detecting exposed Remote Desktop (RDP) port 3389.
#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsExposedRdpPortRule;

impl Rule for WindowsExposedRdpPortRule {
    fn id(&self) -> &'static str {
        "windows.ports.exposed-rdp"
    }

    fn title(&self) -> &'static str {
        "Remote Desktop (RDP) Exposed on Wildcard Address"
    }

    fn description(&self) -> &'static str {
        "TCP port 3389 (Remote Desktop Protocol) is bound to 0.0.0.0 or ::. Direct RDP exposure invites brute force and credential stuffing attacks."
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn remediation(&self) -> &'static str {
        "Enforce Network Level Authentication (NLA), place RDP behind a VPN, and restrict port 3389 inbound firewall access."
    }

    fn required_privilege(&self) -> PrivilegeLevel {
        PrivilegeLevel::Unprivileged
    }

    fn target_platforms(&self) -> &[PlatformFamily] {
        WINDOWS_PLATFORMS
    }

    fn required_capabilities(&self) -> &[PlatformCapability] {
        PORTS_CAPS
    }

    fn evaluate(&self, context: &HostInspectionContext) -> Vec<RuleFinding> {
        let mut findings = Vec::new();

        for port in &context.listening_ports {
            if port.port == 3389 && port.is_wildcard {
                findings.push(RuleFinding {
                    rule_id: self.id(),
                    target: format!("{}:3389", port.ip),
                    title: self.title().into(),
                    description: self.description().into(),
                    remediation: self.remediation().into(),
                    severity: self.severity(),
                    evidence_text: format!("TCP {}:3389 listening", port.ip),
                    evidence_type: EvidenceType::SystemState,
                });
            }
        }

        findings
    }
}

// =============================================================================
// 7. Windows Environment & Path Rules
// =============================================================================

/// Rule detecting writable or insecure directories in system PATH on Windows.
#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsWritablePathEntryRule;

impl Rule for WindowsWritablePathEntryRule {
    fn id(&self) -> &'static str {
        "windows.fs.writable-system-path"
    }

    fn title(&self) -> &'static str {
        "Insecure Writable Directory in System PATH"
    }

    fn description(&self) -> &'static str {
        "An entry in the system PATH environment variable is writable by unprivileged users, permitting DLL or binary hijacking."
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn remediation(&self) -> &'static str {
        "Remove the unprivileged write permissions on the directory or remove it from the system-wide PATH variable."
    }

    fn required_privilege(&self) -> PrivilegeLevel {
        PrivilegeLevel::Unprivileged
    }

    fn target_platforms(&self) -> &[PlatformFamily] {
        WINDOWS_PLATFORMS
    }

    fn required_capabilities(&self) -> &[PlatformCapability] {
        ENV_CAPS
    }

    fn evaluate(&self, context: &HostInspectionContext) -> Vec<RuleFinding> {
        context
            .path_entries
            .iter()
            .filter(|p| p.is_world_writable)
            .map(|p| RuleFinding {
                rule_id: self.id(),
                target: p.path.clone(),
                title: format!("PATH Directory '{}' Is World-Writable", p.path),
                description: format!(
                    "Directory '{}' listed in PATH allows non-administrative write access.",
                    p.path
                ),
                remediation: self.remediation().into(),
                severity: self.severity(),
                evidence_text: format!("Path: {} Writable: true", p.path),
                evidence_type: EvidenceType::SystemState,
            })
            .collect()
    }
}

/// Returns a collection of all standard built-in Windows security audit rules.
#[must_use]
pub fn default_windows_rules() -> Vec<Box<dyn Rule>> {
    vec![
        // Windows Defender
        Box::new(WindowsDefenderRealtimeDisabledRule),
        Box::new(WindowsDefenderAntivirusDisabledRule),
        // Firewall
        Box::new(WindowsFirewallProfileDisabledRule),
        // Registry Hardening
        Box::new(WindowsUacDisabledRule),
        Box::new(WindowsSmbv1EnabledRule),
        Box::new(WindowsLsaProtectionDisabledRule),
        // Services
        Box::new(WindowsUnquotedServicePathRule),
        // Accounts
        Box::new(WindowsGuestAccountEnabledRule),
        Box::new(WindowsEmptyPasswordAccountRule),
        // Port Exposures
        Box::new(WindowsExposedSmbPortRule),
        Box::new(WindowsExposedRdpPortRule),
        // Environment & Filesystem
        Box::new(WindowsWritablePathEntryRule),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collector::ports::ListeningPort;
    use crate::collector::windows::*;

    #[test]
    fn test_windows_defender_rules_evaluation() {
        let rule_rt = WindowsDefenderRealtimeDisabledRule;
        let rule_av = WindowsDefenderAntivirusDisabledRule;

        let ctx_insecure = HostInspectionContext {
            windows_defender: Some(WindowsDefenderInfo {
                antivirus_enabled: false,
                realtime_protection_enabled: false,
                details: "Inactive".into(),
                ..Default::default()
            }),
            ..Default::default()
        };

        let findings_rt = rule_rt.evaluate(&ctx_insecure);
        assert_eq!(findings_rt.len(), 1);
        assert_eq!(findings_rt[0].severity, Severity::Critical);

        let findings_av = rule_av.evaluate(&ctx_insecure);
        assert_eq!(findings_av.len(), 1);
        assert_eq!(findings_av[0].severity, Severity::High);

        let ctx_secure = HostInspectionContext {
            windows_defender: Some(WindowsDefenderInfo {
                antivirus_enabled: true,
                realtime_protection_enabled: true,
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(rule_rt.evaluate(&ctx_secure).len(), 0);
        assert_eq!(rule_av.evaluate(&ctx_secure).len(), 0);
    }

    #[test]
    fn test_windows_firewall_rule_evaluation() {
        let rule = WindowsFirewallProfileDisabledRule;
        let ctx = HostInspectionContext {
            windows_firewall: Some(WindowsFirewallInfo {
                profiles: vec![
                    WindowsFirewallProfile {
                        name: "Domain".into(),
                        enabled: true,
                        default_inbound_action: "BlockInbound".into(),
                        default_outbound_action: "AllowOutbound".into(),
                    },
                    WindowsFirewallProfile {
                        name: "Public".into(),
                        enabled: false,
                        default_inbound_action: "AllowInbound".into(),
                        default_outbound_action: "AllowOutbound".into(),
                    },
                ],
                all_profiles_enabled: false,
                details: "2 profiles".into(),
            }),
            ..Default::default()
        };

        let findings = rule.evaluate(&ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].target, "FirewallProfile:Public");
    }

    #[test]
    fn test_windows_registry_rules_evaluation() {
        let rule_uac = WindowsUacDisabledRule;
        let rule_smb = WindowsSmbv1EnabledRule;
        let rule_lsa = WindowsLsaProtectionDisabledRule;

        let ctx = HostInspectionContext {
            windows_registry: Some(WindowsRegistryInfo {
                uac_enabled: Some(false),
                smbv1_enabled: Some(true),
                lsa_protection_enabled: Some(false),
                wdigest_use_logon_credential: Some(true),
                entries: Vec::new(),
            }),
            ..Default::default()
        };

        assert_eq!(rule_uac.evaluate(&ctx).len(), 1);
        assert_eq!(rule_smb.evaluate(&ctx).len(), 1);
        assert_eq!(rule_lsa.evaluate(&ctx).len(), 1);
    }

    #[test]
    fn test_windows_ports_rules_evaluation() {
        let rule_smb = WindowsExposedSmbPortRule;
        let rule_rdp = WindowsExposedRdpPortRule;

        let ctx = HostInspectionContext {
            listening_ports: vec![
                ListeningPort {
                    protocol: "tcp".into(),
                    ip: "0.0.0.0".into(),
                    port: 445,
                    is_wildcard: true,
                    inode: 0,
                    process_name: Some("System".into()),
                },
                ListeningPort {
                    protocol: "tcp".into(),
                    ip: "127.0.0.1".into(),
                    port: 3389,
                    is_wildcard: false,
                    inode: 0,
                    process_name: Some("TermService".into()),
                },
            ],
            ..Default::default()
        };

        assert_eq!(rule_smb.evaluate(&ctx).len(), 1);
        // RDP is loopback (not wildcard), so no finding
        assert_eq!(rule_rdp.evaluate(&ctx).len(), 0);
    }
}
