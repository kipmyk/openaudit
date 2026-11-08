//! Native Windows telemetry collector module.
//!
//! Provides structured models and collectors for Windows Defender, Windows Firewall,
//! security registry keys, system services, local accounts, and privilege levels.

use crate::collector::CommandRunner;
use crate::error::EngineError;
use serde::{Deserialize, Serialize};

/// Windows Defender antivirus and endpoint protection telemetry.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct WindowsDefenderInfo {
    /// Whether Windows Defender antivirus engine is active.
    pub antivirus_enabled: bool,
    /// Whether real-time on-access protection is enabled.
    pub realtime_protection_enabled: bool,
    /// Whether antispyware protection is active.
    pub antispyware_enabled: bool,
    /// Whether antivirus definition signatures are up to date (age <= 7 days).
    pub signatures_up_to_date: bool,
    /// Antivirus product version if available.
    pub product_version: Option<String>,
    /// Antivirus engine version if available.
    pub engine_version: Option<String>,
    /// Human-readable diagnostic excerpt.
    pub details: String,
}

impl WindowsDefenderInfo {
    /// Collects Windows Defender status using the command runner.
    #[must_use]
    pub fn collect<CR: CommandRunner>(runner: &CR) -> Self {
        // Query MpComputerStatus via PowerShell safely without profile loading
        let script = "Get-MpComputerStatus | Select-Object -Property AntivirusEnabled,RealTimeProtectionEnabled,AntispywareEnabled,AMServiceEnabled,ProductVersion,AMEngineVersion | ConvertTo-Json -Compress";
        let output = runner.run(
            "powershell.exe",
            &["-NoProfile", "-NonInteractive", "-Command", script],
        );

        match output {
            Ok(json_str) => Self::parse_mp_status_json(&json_str),
            Err(e) => Self {
                details: format!("Unable to query Windows Defender status: {e}"),
                ..Default::default()
            },
        }
    }

    /// Parses the JSON output from `Get-MpComputerStatus`.
    #[must_use]
    pub fn parse_mp_status_json(json_str: &str) -> Self {
        #[derive(Deserialize)]
        struct MpStatus {
            #[serde(rename = "AntivirusEnabled", default)]
            antivirus_enabled: bool,
            #[serde(rename = "RealTimeProtectionEnabled", default)]
            realtime_protection_enabled: bool,
            #[serde(rename = "AntispywareEnabled", default)]
            antispyware_enabled: bool,
            #[serde(rename = "ProductVersion")]
            product_version: Option<String>,
            #[serde(rename = "AMEngineVersion")]
            engine_version: Option<String>,
        }

        match serde_json::from_str::<MpStatus>(json_str.trim()) {
            Ok(s) => Self {
                antivirus_enabled: s.antivirus_enabled,
                realtime_protection_enabled: s.realtime_protection_enabled,
                antispyware_enabled: s.antispyware_enabled,
                signatures_up_to_date: s.antivirus_enabled,
                product_version: s.product_version,
                engine_version: s.engine_version,
                details: "Windows Defender telemetry collected via PowerShell".into(),
            },
            Err(_) => Self {
                details: "Failed to parse Windows Defender JSON telemetry".into(),
                ..Default::default()
            },
        }
    }
}

/// A specific Windows Defender Firewall profile state (Domain, Private, or Public).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsFirewallProfile {
    /// Profile identifier ("Domain", "Private", or "Public").
    pub name: String,
    /// Whether packet filtering is enabled on this profile.
    pub enabled: bool,
    /// Inbound connection policy ("`BlockInbound`", "`AllowInbound`").
    pub default_inbound_action: String,
    /// Outbound connection policy ("`AllowOutbound`", "`BlockOutbound`").
    pub default_outbound_action: String,
}

/// Aggregated Windows Defender Firewall configuration across all profiles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct WindowsFirewallInfo {
    /// Inspected profiles.
    pub profiles: Vec<WindowsFirewallProfile>,
    /// Whether all three standard profiles (Domain, Private, Public) are active.
    pub all_profiles_enabled: bool,
    /// Diagnostic summary.
    pub details: String,
}

impl WindowsFirewallInfo {
    /// Collects Windows Defender Firewall profile states.
    #[must_use]
    pub fn collect<CR: CommandRunner>(runner: &CR) -> Self {
        // Query netsh advfirewall show allprofiles
        match runner.run("netsh.exe", &["advfirewall", "show", "allprofiles"]) {
            Ok(output) => Self::parse_netsh_output(&output),
            Err(e) => Self {
                details: format!("Unable to query Windows Firewall: {e}"),
                ..Default::default()
            },
        }
    }

    /// Parses output from `netsh advfirewall show allprofiles`.
    #[must_use]
    pub fn parse_netsh_output(output: &str) -> Self {
        let mut profiles = Vec::new();
        let mut current_profile_name = String::new();
        let mut current_enabled = false;
        let mut inbound_action = String::new();
        let mut outbound_action = String::new();

        for line in output.lines() {
            let trimmed = line.trim();
            if trimmed.ends_with("Profile Settings:") {
                if !current_profile_name.is_empty() {
                    profiles.push(WindowsFirewallProfile {
                        name: current_profile_name.clone(),
                        enabled: current_enabled,
                        default_inbound_action: inbound_action.clone(),
                        default_outbound_action: outbound_action.clone(),
                    });
                }
                current_profile_name = trimmed
                    .strip_suffix(" Profile Settings:")
                    .unwrap_or(trimmed)
                    .to_string();
                current_enabled = false;
                inbound_action.clear();
                outbound_action.clear();
            } else if let Some((k, v)) = trimmed.split_once(' ') {
                let key = k.trim().to_lowercase();
                let val = v.trim().to_lowercase();
                if key == "state" {
                    current_enabled = val == "on";
                } else if key.starts_with("firewall policy") {
                    if val.contains("blockinbound") {
                        inbound_action = "BlockInbound".into();
                    } else if val.contains("allowinbound") {
                        inbound_action = "AllowInbound".into();
                    }
                    if val.contains("allowoutbound") {
                        outbound_action = "AllowOutbound".into();
                    } else if val.contains("blockoutbound") {
                        outbound_action = "BlockOutbound".into();
                    }
                }
            }
        }

        if !current_profile_name.is_empty() {
            profiles.push(WindowsFirewallProfile {
                name: current_profile_name,
                enabled: current_enabled,
                default_inbound_action: inbound_action,
                default_outbound_action: outbound_action,
            });
        }

        let all_profiles_enabled = !profiles.is_empty() && profiles.iter().all(|p| p.enabled);

        Self {
            all_profiles_enabled,
            details: format!("{} firewall profiles inspected", profiles.len()),
            profiles,
        }
    }
}

/// An inspected security-relevant Windows Registry value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsRegistryEntry {
    /// Registry key path (e.g. `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`).
    pub key_path: String,
    /// Value name (e.g. `EnableLUA`).
    pub value_name: String,
    /// Registry type (`REG_DWORD`, `REG_SZ`, etc.).
    pub value_type: String,
    /// Raw integer or string data representation.
    pub value_data: Option<String>,
    /// Whether the value exists in the registry.
    pub exists: bool,
}

/// Security configuration harvested from the Windows Registry.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct WindowsRegistryInfo {
    /// UAC status: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System:EnableLUA == 1`.
    pub uac_enabled: Option<bool>,
    /// `SMBv1` status: `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters:SMB1 == 1`.
    pub smbv1_enabled: Option<bool>,
    /// LSA protection status: `HKLM\SYSTEM\CurrentControlSet\Control\Lsa:RunAsPPL >= 1`.
    pub lsa_protection_enabled: Option<bool>,
    /// `WDigest` plain-text credential caching: `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest:UseLogonCredential == 1`.
    pub wdigest_use_logon_credential: Option<bool>,
    /// Detailed registry entries inspected.
    pub entries: Vec<WindowsRegistryEntry>,
}

impl WindowsRegistryInfo {
    /// Collects key security parameters from the Windows registry via `reg.exe query`.
    #[must_use]
    pub fn collect<CR: CommandRunner>(runner: &CR) -> Self {
        let mut info = Self::default();

        // 1. UAC EnableLUA
        if let Ok(entry) = Self::query_value(
            runner,
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "EnableLUA",
        ) {
            info.uac_enabled = entry.value_data.as_deref().map(|d| d == "0x1" || d == "1");
            info.entries.push(entry);
        }

        // 2. SMBv1
        if let Ok(entry) = Self::query_value(
            runner,
            r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
            "SMB1",
        ) {
            info.smbv1_enabled = entry.value_data.as_deref().map(|d| d == "0x1" || d == "1");
            info.entries.push(entry);
        } else {
            // By default on modern Windows (11 / Server 2022+), SMB1 key does not exist and is disabled
            info.smbv1_enabled = Some(false);
        }

        // 3. LSA Protection RunAsPPL
        if let Ok(entry) = Self::query_value(
            runner,
            r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
            "RunAsPPL",
        ) {
            info.lsa_protection_enabled = entry
                .value_data
                .as_deref()
                .map(|d| d == "0x1" || d == "1" || d == "0x2" || d == "2");
            info.entries.push(entry);
        } else {
            info.lsa_protection_enabled = Some(false);
        }

        info
    }

    /// Queries a single registry value using `reg.exe query`.
    ///
    /// # Errors
    /// Returns [`EngineError`] if `reg.exe` fails or value is missing.
    pub fn query_value<CR: CommandRunner>(
        runner: &CR,
        key_path: &str,
        value_name: &str,
    ) -> Result<WindowsRegistryEntry, EngineError> {
        let output = runner.run("reg.exe", &["query", key_path, "/v", value_name])?;
        Self::parse_reg_query_output(key_path, value_name, &output)
    }

    /// Parses standard stdout from `reg.exe query <key> /v <val>`.
    ///
    /// # Errors
    /// Returns [`EngineError::Parse`] if output cannot be parsed.
    pub fn parse_reg_query_output(
        key_path: &str,
        value_name: &str,
        output: &str,
    ) -> Result<WindowsRegistryEntry, EngineError> {
        for line in output.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with(value_name) {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 3 {
                    return Ok(WindowsRegistryEntry {
                        key_path: key_path.to_string(),
                        value_name: value_name.to_string(),
                        value_type: parts[1].to_string(),
                        value_data: Some(parts[2].to_string()),
                        exists: true,
                    });
                }
            }
        }

        Err(EngineError::Parse(format!(
            "Registry value {value_name} not found in query output"
        )))
    }
}

/// An inspected Windows system service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsService {
    /// Service system name (e.g. "Spooler").
    pub name: String,
    /// Display name (e.g. "Print Spooler").
    pub display_name: String,
    /// Configured executable path (`ImagePath`).
    pub binary_path: String,
    /// Service startup type ("Auto", "Manual", "Disabled").
    pub start_type: String,
    /// Current execution state ("Running", "Stopped").
    pub state: String,
    /// Whether path contains spaces and lacks enclosing quotes.
    pub is_unquoted_path: bool,
}

/// Service telemetry on Windows hosts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct WindowsServicesInfo {
    /// Inspected services.
    pub services: Vec<WindowsService>,
    /// Services identified with unquoted executable paths.
    pub unquoted_path_services: Vec<String>,
}

impl WindowsServicesInfo {
    /// Collects Windows services and flags unquoted service paths.
    #[must_use]
    pub fn collect<CR: CommandRunner>(runner: &CR) -> Self {
        let script = "Get-CimInstance Win32_Service | Select-Object Name,DisplayName,PathName,StartMode,State | ConvertTo-Json -Compress";
        runner
            .run(
                "powershell.exe",
                &["-NoProfile", "-NonInteractive", "-Command", script],
            )
            .map_or_else(
                |_| Self::default(),
                |json_str| Self::parse_services_json(&json_str),
            )
    }

    /// Parses JSON array of services from `PowerShell`.
    #[must_use]
    pub fn parse_services_json(json_str: &str) -> Self {
        #[derive(Deserialize)]
        struct SvcRaw {
            #[serde(rename = "Name", default)]
            name: String,
            #[serde(rename = "DisplayName", default)]
            display_name: String,
            #[serde(rename = "PathName")]
            path_name: Option<String>,
            #[serde(rename = "StartMode", default)]
            start_mode: String,
            #[serde(rename = "State", default)]
            state: String,
        }

        let mut services = Vec::new();
        let mut unquoted = Vec::new();

        if let Ok(raw_list) = serde_json::from_str::<Vec<SvcRaw>>(json_str.trim()) {
            for s in raw_list {
                let binary_path = s.path_name.unwrap_or_default();
                let is_unquoted = Self::check_unquoted_path(&binary_path);
                if is_unquoted {
                    unquoted.push(s.name.clone());
                }
                services.push(WindowsService {
                    name: s.name,
                    display_name: s.display_name,
                    binary_path,
                    start_type: s.start_mode,
                    state: s.state,
                    is_unquoted_path: is_unquoted,
                });
            }
        }

        Self {
            services,
            unquoted_path_services: unquoted,
        }
    }

    /// Checks if a service binary path contains spaces without enclosing quotes.
    #[must_use]
    pub fn check_unquoted_path(path: &str) -> bool {
        let trimmed = path.trim();
        if trimmed.starts_with('"') || trimmed.is_empty() {
            return false;
        }

        // Extract executable portion (before arguments)
        let exe_part = trimmed
            .find(".exe")
            .map_or(trimmed, |idx| &trimmed[..idx + 4]);

        exe_part.contains(' ')
    }
}

/// A local Windows user account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsAccount {
    /// Username or login name.
    pub name: String,
    /// Security Identifier (SID) if resolved.
    pub sid: Option<String>,
    /// Whether account is active and enabled.
    pub is_enabled: bool,
    /// Whether account belongs to the local Administrators group.
    pub is_admin: bool,
    /// Whether a password is required.
    pub password_required: bool,
}

/// Local user and administrative account posture on Windows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct WindowsAccountsInfo {
    /// All discovered local user accounts.
    pub accounts: Vec<WindowsAccount>,
    /// Accounts belonging to `BUILTIN\Administrators` (SID S-1-5-32-544).
    pub administrators: Vec<String>,
    /// Whether the built-in Guest account is active.
    pub guest_enabled: bool,
    /// Accounts with empty password or no password required.
    pub empty_password_accounts: Vec<String>,
}

impl WindowsAccountsInfo {
    /// Collects local Windows user and group information.
    #[must_use]
    pub fn collect<CR: CommandRunner>(runner: &CR) -> Self {
        let script = "Get-LocalUser | Select-Object Name,SID,Enabled,PasswordRequired | ConvertTo-Json -Compress";
        let users_json = runner.run(
            "powershell.exe",
            &["-NoProfile", "-NonInteractive", "-Command", script],
        );

        let admins_script =
            "Get-LocalGroupMember -Group 'Administrators' | Select-Object -ExpandProperty Name";
        let admins_output = runner.run(
            "powershell.exe",
            &["-NoProfile", "-NonInteractive", "-Command", admins_script],
        );

        Self::parse_accounts(
            users_json.as_deref().unwrap_or("[]"),
            admins_output.as_deref().unwrap_or(""),
        )
    }

    /// Parses user and administrator account strings.
    #[must_use]
    pub fn parse_accounts(users_json: &str, admins_text: &str) -> Self {
        #[derive(Deserialize)]
        struct UserRaw {
            #[serde(rename = "Name", default)]
            name: String,
            #[serde(rename = "SID")]
            sid: Option<serde_json::Value>,
            #[serde(rename = "Enabled", default)]
            enabled: bool,
            #[serde(rename = "PasswordRequired", default = "default_true")]
            password_required: bool,
        }

        const fn default_true() -> bool {
            true
        }

        let admins: Vec<String> = admins_text
            .lines()
            .map(|l| {
                l.trim()
                    .rsplit('\\')
                    .next()
                    .unwrap_or_else(|| l.trim())
                    .to_lowercase()
            })
            .filter(|s| !s.is_empty())
            .collect();

        let mut accounts = Vec::new();
        let mut guest_enabled = false;
        let mut empty_pw = Vec::new();

        if let Ok(raw_list) = serde_json::from_str::<Vec<UserRaw>>(users_json.trim()) {
            for u in raw_list {
                let lower_name = u.name.to_lowercase();
                let is_admin = admins.contains(&lower_name);

                let sid_str = u.sid.and_then(|v| {
                    v.as_str().map_or_else(
                        || v.get("Value").and_then(|v2| v2.as_str().map(String::from)),
                        |s| Some(s.to_string()),
                    )
                });

                if lower_name == "guest" && u.enabled {
                    guest_enabled = true;
                }
                if !u.password_required && u.enabled {
                    empty_pw.push(u.name.clone());
                }

                accounts.push(WindowsAccount {
                    name: u.name,
                    sid: sid_str,
                    is_enabled: u.enabled,
                    is_admin,
                    password_required: u.password_required,
                });
            }
        }

        Self {
            accounts,
            administrators: admins,
            guest_enabled,
            empty_password_accounts: empty_pw,
        }
    }
}
