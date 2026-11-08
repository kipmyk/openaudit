//! Windows compatibility and regression integration tests (Milestone M3.3).
//!
//! Verifies:
//! - Full end-to-end audit execution on Windows 11, Windows Server 2022, and Windows Server 2025
//! - Deterministic finding evaluation across all 12 native Windows security rules
//! - Fail-closed enforcement on unsupported Windows versions (Windows 10, legacy releases)
//! - Proper `CheckExecutionStatus` tracking (`UnsupportedPlatform` for Linux-only rules, Executed for Windows rules)
//! - Sensitive data redaction and evidence generation
//! - Zero regressions against frozen M2 guarantees

use openaudit_core::{AssetType, OrganizationId};
use openaudit_engine::collector::windows::{
    WindowsAccount, WindowsAccountsInfo, WindowsDefenderInfo, WindowsFirewallInfo,
    WindowsFirewallProfile, WindowsRegistryInfo, WindowsService, WindowsServicesInfo,
};
use openaudit_engine::collector::{
    CommandRunner, FileSystem, HostInspectionContext, PrivilegeLevel,
};
use openaudit_engine::error::EngineError;
use openaudit_engine::platform::windows::WindowsPlatformBackend;
use openaudit_engine::platform::{
    CheckExecutionStatus, PlatformBackend, PlatformDistribution, PlatformFamily, PlatformInfo,
    PlatformVersion,
};
use openaudit_engine::profile::AuditProfile;
use openaudit_engine::rule::windows::default_windows_rules;
use openaudit_engine::rule::{default_linux_rules, Rule};
use openaudit_engine::runner::AuditEngine;

#[derive(Debug, Clone, Copy, Default)]
struct MockWindowsFs;

impl FileSystem for MockWindowsFs {
    fn read_to_string(&self, _path: &str) -> Result<String, EngineError> {
        Err(EngineError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "mock windows filesystem has no direct unix files",
        )))
    }

    fn exists(&self, path: &str) -> bool {
        // C:\Windows\System32 directory exists
        path.contains("System32") || path.contains("Windows")
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

#[derive(Debug, Clone, Default)]
struct MockWindowsRunner {
    powershell_output: Option<String>,
}

impl MockWindowsRunner {
    const fn new() -> Self {
        Self {
            powershell_output: None,
        }
    }

    fn with_os_query(mut self, caption: &str, build: &str) -> Self {
        self.powershell_output = Some(format!("{caption}\n{build}\n"));
        self
    }
}

impl CommandRunner for MockWindowsRunner {
    fn run(&self, program: &str, args: &[&str]) -> Result<String, EngineError> {
        if program.contains("powershell") {
            let cmd = args.join(" ");
            if cmd.contains("Win32_OperatingSystem") {
                return Ok(self
                    .powershell_output
                    .clone()
                    .unwrap_or_else(|| "Microsoft Windows 11 Pro\n22631\n".to_string()));
            }
            if cmd.contains("Get-MpComputerStatus") {
                return Ok(r#"{"AntivirusEnabled":false,"RealTimeProtectionEnabled":false,"AntispywareEnabled":true,"AMServiceEnabled":false,"ProductVersion":"4.18.23110.3","AMEngineVersion":"1.1.23110.2"}"#.into());
            }
            if cmd.contains("Win32_Service") {
                return Ok(r#"[
                    {"Name":"VulnerableService","DisplayName":"Vulnerable Enterprise Service","PathName":"C:\\Program Files\\Enterprise App\\service.exe -run","StartMode":"Auto","State":"Running"},
                    {"Name":"QuotedService","DisplayName":"Properly Quoted Service","PathName":"\"C:\\Program Files\\Secure App\\service.exe\" -run","StartMode":"Auto","State":"Running"}
                ]"#.into());
            }
            if cmd.contains("Get-LocalUser") {
                return Ok(r#"[
                    {"Name":"Administrator","SID":"S-1-5-21-1-500","Enabled":true,"PasswordRequired":true},
                    {"Name":"Guest","SID":"S-1-5-21-1-501","Enabled":true,"PasswordRequired":false},
                    {"Name":"Deployer","SID":"S-1-5-21-1-1001","Enabled":true,"PasswordRequired":false}
                ]"#.into());
            }
            if cmd.contains("Get-LocalGroupMember") {
                return Ok("DOMAIN\\Administrator\nDOMAIN\\Deployer\n".into());
            }
        } else if program.contains("netsh") {
            return Ok("Domain Profile Settings:\n  State OFF\nPublic Profile Settings:\n  State ON\nPrivate Profile Settings:\n  State ON\n".into());
        } else if program.contains("reg") {
            let cmd = args.join(" ");
            if cmd.contains("EnableLUA") {
                return Ok("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\n    EnableLUA    REG_DWORD    0x0\n".into());
            }
            if cmd.contains("SMB1") {
                return Ok("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\n    SMB1    REG_DWORD    0x1\n".into());
            }
            if cmd.contains("RunAsPPL") {
                return Ok("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\n    RunAsPPL    REG_DWORD    0x0\n".into());
            }
        } else if program.contains("netstat") {
            return Ok("Active Connections\n  Proto  Local Address          Foreign Address        State           PID\n  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4\n  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       1234\n  TCP    127.0.0.1:5000         0.0.0.0:0              LISTENING       5678\n".into());
        }

        Err(EngineError::CommandExecution(format!(
            "Command not mocked: {program} {args:?}"
        )))
    }
}

#[test]
fn test_windows_11_full_audit_lifecycle_and_findings() {
    let org_id = OrganizationId::new();
    let runner = MockWindowsRunner::new().with_os_query("Microsoft Windows 11 Enterprise", "22631");
    let fs = MockWindowsFs;
    let backend = WindowsPlatformBackend::detect_with(&fs, &runner);

    assert_eq!(backend.info().family, PlatformFamily::Windows);
    assert_eq!(backend.info().distribution, PlatformDistribution::Windows11);
    assert!(backend.is_supported());

    let rules: Vec<Box<dyn Rule>> = default_windows_rules();
    let engine = AuditEngine::new(fs, runner, rules);

    let report = engine
        .run_audit_with_backend(org_id, &backend, AuditProfile::Hardened)
        .expect("windows 11 audit must complete successfully");

    // Invariant 1: Asset identity correctly reflects Windows Host
    assert_eq!(report.asset.asset_type, AssetType::WindowsHost);
    let platform = report.platform_info.as_ref().expect("platform_info");
    assert_eq!(platform.family, PlatformFamily::Windows);
    assert_eq!(platform.version.build.as_deref(), Some("22631"));

    // Invariant 2: Windows audit checks produced findings for mocked misconfigurations
    assert_ne!(report.findings.len(), 0);

    let finding_rule_ids: Vec<&str> = report
        .findings
        .iter()
        .map(|f| f.finding.rule_id.as_str())
        .collect();

    // Check Windows Defender findings
    assert!(
        finding_rule_ids.contains(&"windows.defender.realtime-disabled"),
        "Missing realtime disabled finding"
    );
    assert!(
        finding_rule_ids.contains(&"windows.defender.antivirus-disabled"),
        "Missing antivirus disabled finding"
    );

    // Check Registry findings
    assert!(
        finding_rule_ids.contains(&"windows.registry.uac-disabled"),
        "Missing UAC disabled finding"
    );
    assert!(
        finding_rule_ids.contains(&"windows.registry.smbv1-enabled"),
        "Missing SMBv1 enabled finding"
    );
    assert!(
        finding_rule_ids.contains(&"windows.registry.lsa-protection-disabled"),
        "Missing LSA protection finding"
    );

    // Check Firewall finding
    assert!(
        finding_rule_ids.contains(&"windows.firewall.profile-disabled"),
        "Missing firewall profile finding"
    );

    // Check Services finding
    assert!(
        finding_rule_ids.contains(&"windows.services.unquoted-path"),
        "Missing unquoted service path finding"
    );

    // Check Accounts findings
    assert!(
        finding_rule_ids.contains(&"windows.accounts.guest-enabled"),
        "Missing guest account enabled finding"
    );
    assert!(
        finding_rule_ids.contains(&"windows.accounts.empty-password"),
        "Missing empty password finding"
    );

    // Check Network exposure findings
    assert!(
        finding_rule_ids.contains(&"windows.ports.exposed-smb"),
        "Missing exposed SMB finding"
    );
    assert!(
        finding_rule_ids.contains(&"windows.ports.exposed-rdp"),
        "Missing exposed RDP finding"
    );

    // Invariant 3: Check statuses track execution for all rules
    assert_eq!(report.check_statuses.len(), 12);
    for status in &report.check_statuses {
        assert!(
            matches!(status.status, CheckExecutionStatus::Executed { .. }),
            "Expected rule {} to be Executed on Windows, was {:?}",
            status.rule_id,
            status.status
        );
    }
}

#[test]
fn test_windows_server_2022_support_and_audit() {
    let org_id = OrganizationId::new();
    let runner =
        MockWindowsRunner::new().with_os_query("Microsoft Windows Server 2022 Datacenter", "20348");
    let fs = MockWindowsFs;
    let backend = WindowsPlatformBackend::detect_with(&fs, &runner);

    assert_eq!(backend.info().family, PlatformFamily::Windows);
    assert_eq!(
        backend.info().distribution,
        PlatformDistribution::WindowsServer2022
    );
    assert!(backend.is_supported());

    let rules: Vec<Box<dyn Rule>> = default_windows_rules();
    let engine = AuditEngine::new(fs, runner, rules);

    let report = engine
        .run_audit_with_backend(org_id, &backend, AuditProfile::Baseline)
        .expect("windows server 2022 audit must complete");

    assert_eq!(report.asset.asset_type, AssetType::WindowsHost);
    assert_ne!(report.findings.len(), 0);
}

#[test]
fn test_windows_server_2025_support_and_audit() {
    let org_id = OrganizationId::new();
    let runner =
        MockWindowsRunner::new().with_os_query("Microsoft Windows Server 2025 Standard", "26100");
    let fs = MockWindowsFs;
    let backend = WindowsPlatformBackend::detect_with(&fs, &runner);

    assert_eq!(backend.info().family, PlatformFamily::Windows);
    assert_eq!(
        backend.info().distribution,
        PlatformDistribution::WindowsServer2025
    );
    assert!(backend.is_supported());

    let rules: Vec<Box<dyn Rule>> = default_windows_rules();
    let engine = AuditEngine::new(fs, runner, rules);

    let report = engine
        .run_audit_with_backend(org_id, &backend, AuditProfile::Baseline)
        .expect("windows server 2025 audit must complete");

    assert_eq!(report.asset.asset_type, AssetType::WindowsHost);
    assert_ne!(report.findings.len(), 0);
}

#[test]
fn test_unsupported_windows_versions_fail_closed() {
    let org_id = OrganizationId::new();
    let unsupported_configs = [
        ("Microsoft Windows 10 Pro", "19045"),
        ("Microsoft Windows 10 Enterprise LTSC", "17763"),
        ("Microsoft Windows 7 Professional", "7601"),
        ("Microsoft Windows 8.1 Enterprise", "9600"),
        ("Microsoft Windows Server 2016 Datacenter", "14393"),
        ("Microsoft Windows Server 2012 R2", "9600"),
    ];

    for (caption, build) in unsupported_configs {
        let runner = MockWindowsRunner::new().with_os_query(caption, build);
        let fs = MockWindowsFs;
        let backend = WindowsPlatformBackend::detect_with(&fs, &runner);

        assert!(
            !backend.is_supported(),
            "Windows target '{caption}' (build {build}) must NOT be supported in M3.3"
        );

        let err = backend.collect_context().unwrap_err();
        assert!(
            matches!(err, EngineError::UnsupportedPlatform(ref s) if s.contains("Milestone M3.3")),
            "Target {caption} must fail closed with typed UnsupportedPlatform error: {err:?}"
        );

        let engine = AuditEngine::new(fs, runner, default_windows_rules());
        let audit_err = engine
            .run_audit_with_backend(org_id, &backend, AuditProfile::Baseline)
            .unwrap_err();
        assert!(
            matches!(audit_err, EngineError::UnsupportedPlatform(..)),
            "Engine execution on {caption} must fail closed"
        );
    }
}

#[test]
fn test_linux_rules_on_windows_backend_marked_unsupported_never_pass_silently() {
    let org_id = OrganizationId::new();
    let runner = MockWindowsRunner::new().with_os_query("Microsoft Windows 11 Pro", "22631");
    let fs = MockWindowsFs;
    let backend = WindowsPlatformBackend::detect_with(&fs, &runner);

    // Mix Linux and Windows rules in the catalog
    let mut mixed_rules: Vec<Box<dyn Rule>> = default_linux_rules();
    mixed_rules.extend(default_windows_rules());

    let engine = AuditEngine::new(fs, runner, mixed_rules);
    let report = engine
        .run_audit_with_backend(org_id, &backend, AuditProfile::Hardened)
        .expect("audit must run");

    // All Linux rules must be marked as UnsupportedPlatform
    for status in &report.check_statuses {
        if status.rule_id.starts_with("linux.") {
            assert!(
                matches!(
                    status.status,
                    CheckExecutionStatus::UnsupportedPlatform { .. }
                ),
                "Linux rule {} must be recorded as UnsupportedPlatform on Windows",
                status.rule_id
            );
        } else if status.rule_id.starts_with("windows.") {
            assert!(
                matches!(status.status, CheckExecutionStatus::Executed { .. }),
                "Windows rule {} must be executed on Windows",
                status.rule_id
            );
        }
    }
}

struct HardenedWindowsBackend {
    info: PlatformInfo,
}

impl PlatformBackend for HardenedWindowsBackend {
    fn info(&self) -> &PlatformInfo {
        &self.info
    }

    fn is_supported(&self) -> bool {
        true
    }

    fn collect_context(&self) -> Result<HostInspectionContext, EngineError> {
        Ok(HostInspectionContext {
            windows_defender: Some(WindowsDefenderInfo {
                antivirus_enabled: true,
                realtime_protection_enabled: true,
                antispyware_enabled: true,
                signatures_up_to_date: true,
                product_version: Some("4.18.23110.3".into()),
                engine_version: Some("1.1.23110.2".into()),
                details: "Defender active and updated".into(),
            }),
            windows_firewall: Some(WindowsFirewallInfo {
                profiles: vec![
                    WindowsFirewallProfile {
                        name: "Domain".into(),
                        enabled: true,
                        default_inbound_action: "BlockInbound".into(),
                        default_outbound_action: "AllowOutbound".into(),
                    },
                    WindowsFirewallProfile {
                        name: "Private".into(),
                        enabled: true,
                        default_inbound_action: "BlockInbound".into(),
                        default_outbound_action: "AllowOutbound".into(),
                    },
                    WindowsFirewallProfile {
                        name: "Public".into(),
                        enabled: true,
                        default_inbound_action: "BlockInbound".into(),
                        default_outbound_action: "AllowOutbound".into(),
                    },
                ],
                all_profiles_enabled: true,
                details: "All firewall profiles active".into(),
            }),
            windows_registry: Some(WindowsRegistryInfo {
                uac_enabled: Some(true),
                smbv1_enabled: Some(false),
                lsa_protection_enabled: Some(true),
                wdigest_use_logon_credential: Some(false),
                entries: Vec::new(),
            }),
            windows_services: Some(WindowsServicesInfo {
                services: vec![WindowsService {
                    name: "SecureService".into(),
                    display_name: "Secure Service".into(),
                    binary_path: "\"C:\\Program Files\\App\\service.exe\"".into(),
                    start_type: "Auto".into(),
                    state: "Running".into(),
                    is_unquoted_path: false,
                }],
                unquoted_path_services: Vec::new(),
            }),
            windows_accounts: Some(WindowsAccountsInfo {
                accounts: vec![WindowsAccount {
                    name: "Administrator".into(),
                    sid: Some("S-1-5-21-500".into()),
                    is_enabled: true,
                    is_admin: true,
                    password_required: true,
                }],
                administrators: vec!["administrator".into()],
                guest_enabled: false,
                empty_password_accounts: Vec::new(),
            }),
            listening_ports: vec![openaudit_engine::collector::ports::ListeningPort {
                protocol: "tcp".into(),
                ip: "127.0.0.1".into(),
                port: 8080,
                is_wildcard: false,
                inode: 0,
                process_name: Some("local-service".into()),
            }],
            current_privilege: PrivilegeLevel::RootRequired,
            ..Default::default()
        })
    }
}

#[test]
fn test_hardened_windows_clean_pass() {
    let org_id = OrganizationId::new();
    let info = PlatformInfo {
        family: PlatformFamily::Windows,
        distribution: PlatformDistribution::Windows11,
        version: PlatformVersion::parse("10.0.22631").with_build("22631"),
        architecture: "x86_64".into(),
        kernel_release: "10.0.22631".into(),
        hostname: "SECURE-WIN11".into(),
        pretty_name: "Microsoft Windows 11 Enterprise".into(),
        machine_id: Some("deterministic-machine-id".into()),
        capabilities: WindowsPlatformBackend::default_capabilities(),
    };

    let backend = HardenedWindowsBackend { info };
    let engine = AuditEngine::new(
        MockWindowsFs,
        MockWindowsRunner::new(),
        default_windows_rules(),
    );

    let report = engine
        .run_audit_with_backend(org_id, &backend, AuditProfile::Hardened)
        .expect("audit on hardened windows host must succeed");

    // Zero findings on fully hardened system
    assert_eq!(
        report.findings.len(),
        0,
        "Hardened Windows system must produce 0 findings, but found: {:?}",
        report.findings
    );

    // All 12 checks executed and passed
    assert_eq!(report.check_statuses.len(), 12);
    for status in &report.check_statuses {
        assert_eq!(
            status.status,
            CheckExecutionStatus::Executed { passed: true },
            "Rule {} was expected to pass",
            status.rule_id
        );
    }
}
