//! Platform abstraction regression and compatibility verification suite for OpenAudit M3.1.
//!
//! Demonstrates that integrating the Linux auditing engine through the new platform
//! abstraction maintains full fidelity and compatibility with M2 rules, evidence semantics,
//! and finding deduplication, while providing explicit fail-closed behavior for unreleased platforms.

use openaudit_core::OrganizationId;
use openaudit_engine::collector::{CommandRunner, FileSystem, PrivilegeLevel};
use openaudit_engine::error::EngineError;
use openaudit_engine::platform::{
    detect_current_platform, CheckExecutionStatus, LinuxPlatformBackend, MacosPlatformBackend,
    PlatformBackend, PlatformCapability, PlatformDistribution, PlatformFamily, PlatformInfo,
    PlatformVersion, WindowsPlatformBackend,
};
use openaudit_engine::profile::AuditProfile;
use openaudit_engine::rule::builtin::default_linux_rules;
use openaudit_engine::AuditEngine;

#[derive(Debug, Clone)]
struct RegressionMockFs {
    os_release: String,
    sshd_config: String,
    shadow: String,
    passwd: String,
    sysctl_forward: String,
}

impl Default for RegressionMockFs {
    fn default() -> Self {
        Self {
            os_release: "ID=ubuntu\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04 LTS\"\nVERSION_CODENAME=noble\n".into(),
            sshd_config: "PermitRootLogin yes\nPasswordAuthentication yes\nX11Forwarding no\n".into(),
            shadow: "root:*:19000:0:99999:7:::\ninsecure_user::19000:0:99999:7:::\n".into(),
            passwd: "root:x:0:0::/root:/bin/bash\ninsecure_user:x:1001:1001::/home/insecure_user:/bin/bash\n".into(),
            sysctl_forward: "1\n".into(),
        }
    }
}

impl FileSystem for RegressionMockFs {
    fn read_to_string(&self, path: &str) -> Result<String, EngineError> {
        match path {
            "/etc/os-release" | "/usr/lib/os-release" => Ok(self.os_release.clone()),
            "/etc/ssh/sshd_config" => Ok(self.sshd_config.clone()),
            "/etc/shadow" => Ok(self.shadow.clone()),
            "/etc/passwd" => Ok(self.passwd.clone()),
            "/proc/sys/net/ipv4/ip_forward" => Ok(self.sysctl_forward.clone()),
            "/etc/hostname" => Ok("ubuntu-verified\n".into()),
            "/etc/machine-id" => Ok("1234567890abcdef1234567890abcdef\n".into()),
            _ => Err(EngineError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("file not found in mock: {path}"),
            ))),
        }
    }

    fn exists(&self, path: &str) -> bool {
        matches!(
            path,
            "/etc/os-release"
                | "/usr/lib/os-release"
                | "/etc/ssh/sshd_config"
                | "/etc/shadow"
                | "/etc/passwd"
                | "/proc/sys/net/ipv4/ip_forward"
                | "/etc/hostname"
                | "/etc/machine-id"
        )
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

#[derive(Debug, Clone, Copy)]
struct RegressionMockRunner {
    firewall_inactive: bool,
}

impl CommandRunner for RegressionMockRunner {
    fn run(&self, program: &str, _args: &[&str]) -> Result<String, EngineError> {
        if program == "ufw" {
            if self.firewall_inactive {
                Ok("Status: inactive\n".into())
            } else {
                Ok("Status: active\n".into())
            }
        } else {
            Err(EngineError::CommandExecution(format!(
                "command not mocked: {program}"
            )))
        }
    }
}

#[test]
fn test_m2_linux_regression_through_platform_abstraction() {
    let org_id = OrganizationId::new();
    let fs = RegressionMockFs::default();
    let runner = RegressionMockRunner {
        firewall_inactive: true,
    };

    let backend = LinuxPlatformBackend::detect(&fs, &runner).expect("detect platform");
    assert_eq!(backend.info().family, PlatformFamily::Linux);
    assert_eq!(backend.info().distribution, PlatformDistribution::Ubuntu);
    assert_eq!(backend.info().version.major, 24);
    assert!(backend.is_supported());

    let engine = AuditEngine::new(fs, runner, default_linux_rules());
    let report = engine
        .run_audit_with_backend(org_id, &backend, AuditProfile::Baseline)
        .expect("audit execution must succeed");

    // Invariant 1: Asset metadata synthesized properly
    assert_eq!(report.asset.organization_id, org_id);
    assert_eq!(
        report.asset.asset_type,
        openaudit_core::asset::AssetType::LinuxHost
    );

    // Invariant 2: Platform info preserved in report
    let platform = report.platform_info.as_ref().expect("platform_info");
    assert_eq!(platform.family, PlatformFamily::Linux);
    assert_eq!(platform.distribution, PlatformDistribution::Ubuntu);
    assert_eq!(
        platform.machine_id.as_deref(),
        Some("1234567890abcdef1234567890abcdef")
    );

    // Invariant 3: Expected M2 security findings detected
    let finding_rule_ids: Vec<&str> = report
        .findings
        .iter()
        .map(|item| item.finding.rule_id.as_str())
        .collect();

    assert!(
        finding_rule_ids.contains(&"linux.ssh.permit-root-login"),
        "M2 rule linux.ssh.permit-root-login must produce a finding"
    );
    assert!(
        finding_rule_ids.contains(&"linux.ssh.password-authentication"),
        "M2 rule linux.ssh.password-authentication must produce a finding"
    );
    assert!(
        finding_rule_ids.contains(&"linux.firewall.inactive"),
        "M2 rule linux.firewall.inactive must produce a finding"
    );
    assert!(
        finding_rule_ids.contains(&"linux.kernel.ip-forwarding-enabled"),
        "M2 rule linux.kernel.ip-forwarding-enabled must produce a finding"
    );

    // Invariant 4: Privilege contract enforcement
    if report.current_privilege == PrivilegeLevel::RootRequired {
        assert!(
            finding_rule_ids.contains(&"linux.users.empty-password"),
            "M2 rule linux.users.empty-password must produce a finding when running with root privilege"
        );
    } else {
        let empty_pw_status = report
            .check_statuses
            .iter()
            .find(|s| s.rule_id == "linux.users.empty-password")
            .expect("empty-password check status");
        assert_eq!(
            empty_pw_status.status,
            CheckExecutionStatus::InsufficientPrivilege {
                required: PrivilegeLevel::RootRequired,
                current: PrivilegeLevel::Unprivileged,
            }
        );
    }

    // Invariant 5: Every finding has an attached, redacted evidence item
    for item in &report.findings {
        assert!(
            item.evidence.is_redacted,
            "evidence must be redacted according to M2 specification"
        );
        assert_eq!(item.finding.id, item.evidence.finding_id);
        assert_eq!(item.finding.organization_id, org_id);
    }

    // Invariant 6: Check statuses track execution of all evaluated rules
    assert_ne!(report.check_statuses.len(), 0);
    let ssh_status = report
        .check_statuses
        .iter()
        .find(|s| s.rule_id == "linux.ssh.permit-root-login")
        .expect("ssh check status");
    assert_eq!(
        ssh_status.status,
        CheckExecutionStatus::Executed { passed: false }
    );
}

#[test]
fn test_unsupported_platform_backends_fail_closed_without_simulation() {
    let win_backend = WindowsPlatformBackend::detect();
    assert_eq!(win_backend.info().family, PlatformFamily::Windows);
    assert!(!win_backend.is_supported());

    let win_err = win_backend.collect_context().unwrap_err();
    assert!(
        matches!(win_err, EngineError::UnsupportedPlatform(ref s) if s.contains("Milestone M3.3")),
        "Windows backend must fail closed with explicit milestone scheduling error: {win_err:?}"
    );

    // Unsupported legacy macOS version must fail closed
    let unsupported_mac_info = PlatformInfo {
        family: PlatformFamily::MacOS,
        distribution: PlatformDistribution::OtherMacos("macOS 12 Monterey".into()),
        version: PlatformVersion::parse("12.7.4"),
        architecture: "x86_64".into(),
        kernel_release: "Darwin 21.6.0".into(),
        hostname: "old-mac".into(),
        pretty_name: "macOS Monterey".into(),
        machine_id: None,
        capabilities: MacosPlatformBackend::default_capabilities(),
    };
    let mac_backend = MacosPlatformBackend::with_info(unsupported_mac_info);
    assert_eq!(mac_backend.info().family, PlatformFamily::MacOS);
    assert!(!mac_backend.is_supported());

    let mac_err = mac_backend.collect_context().unwrap_err();
    assert!(
        matches!(mac_err, EngineError::UnsupportedPlatform(ref s) if s.contains("Milestone M3.4")),
        "macOS backend must fail closed with explicit milestone scheduling error: {mac_err:?}"
    );
}

#[test]
fn test_platform_capability_matching_and_filtering() {
    let fs = RegressionMockFs::default();
    let runner = RegressionMockRunner {
        firewall_inactive: false,
    };
    let backend = detect_current_platform(&fs, &runner);

    assert!(backend.has_capability(PlatformCapability::KernelSysctl));
    assert!(backend.has_capability(PlatformCapability::SshDaemon));
    assert!(backend.has_capability(PlatformCapability::Firewall));
    assert!(backend.has_capability(PlatformCapability::ListeningPorts));
    assert!(backend.has_capability(PlatformCapability::SuidSgidBinaries));
    assert!(backend.has_capability(PlatformCapability::FilePermissions));
    assert!(backend.has_capability(PlatformCapability::SystemUsers));
    assert!(backend.has_capability(PlatformCapability::EnvironmentVariables));

    assert!(!backend.has_capability(PlatformCapability::WindowsRegistry));
    assert!(!backend.has_capability(PlatformCapability::WindowsDefender));
    assert!(!backend.has_capability(PlatformCapability::MacosGatekeeper));
    assert!(!backend.has_capability(PlatformCapability::MacosSip));
}

/// Comprehensive regression test verifying rule accounting semantics across all platform scopes:
/// 1. Rules applicable to current OS and included in profile.
/// 2. Rules applicable to current OS but excluded by selected profile.
/// 3. Rules unsupported on current OS.
/// 4. Total registered rules partitioned by operating system (11 macOS, 20 Linux, 12 Windows = 43 total).
/// 5. Guarantees profile-excluded rules are NEVER counted as platform-unsupported rules.
#[test]
#[allow(clippy::too_many_lines)]
fn test_rule_accounting_semantics_partitioning_and_profile_invariants() {
    let org_id = OrganizationId::from_seed(b"openaudit:rule-accounting-regression");
    let engine = AuditEngine::default();
    let rules = engine.rules();
    assert_eq!(
        rules.len(),
        43,
        "Engine must register exactly 43 total rules"
    );

    // Partition verification: 11 macOS, 20 Linux, 12 Windows
    let macos_rules: Vec<_> = rules
        .iter()
        .filter(|r| r.target_platforms().contains(&PlatformFamily::MacOS))
        .collect();
    let linux_rules: Vec<_> = rules
        .iter()
        .filter(|r| r.target_platforms().contains(&PlatformFamily::Linux))
        .collect();
    let windows_rules: Vec<_> = rules
        .iter()
        .filter(|r| r.target_platforms().contains(&PlatformFamily::Windows))
        .collect();

    assert_eq!(macos_rules.len(), 11, "Must contain exactly 11 macOS rules");
    assert_eq!(linux_rules.len(), 20, "Must contain exactly 20 Linux rules");
    assert_eq!(
        windows_rules.len(),
        12,
        "Must contain exactly 12 Windows rules"
    );
    assert_eq!(
        macos_rules.len() + linux_rules.len() + windows_rules.len(),
        43
    );

    // Profile partition per platform
    let mac_baseline = macos_rules
        .iter()
        .filter(|r| r.profile() == AuditProfile::Baseline)
        .count();
    let mac_hardened = macos_rules
        .iter()
        .filter(|r| r.profile() == AuditProfile::Hardened)
        .count();
    assert_eq!(mac_baseline, 9, "9 macOS baseline rules");
    assert_eq!(mac_hardened, 2, "2 macOS hardened-only rules");

    let linux_baseline = linux_rules
        .iter()
        .filter(|r| r.profile() == AuditProfile::Baseline)
        .count();
    assert_eq!(linux_baseline, 20, "20 Linux baseline rules");

    let win_baseline = windows_rules
        .iter()
        .filter(|r| r.profile() == AuditProfile::Baseline)
        .count();
    let win_hardened = windows_rules
        .iter()
        .filter(|r| r.profile() == AuditProfile::Hardened)
        .count();
    assert_eq!(win_baseline, 11, "11 Windows baseline rules");
    assert_eq!(win_hardened, 1, "1 Windows hardened-only rule");

    // Run on current host under Baseline profile
    let baseline_report = engine
        .run_audit_with_profile(org_id, AuditProfile::Baseline)
        .expect("Baseline audit must succeed");

    #[cfg(target_os = "macos")]
    {
        let unsupported_count = baseline_report
            .check_statuses
            .iter()
            .filter(|s| matches!(s.status, CheckExecutionStatus::UnsupportedPlatform { .. }))
            .count();
        let excluded_count = baseline_report
            .check_statuses
            .iter()
            .filter(|s| matches!(s.status, CheckExecutionStatus::NotApplicable { .. }))
            .count();
        let executed_count = baseline_report
            .check_statuses
            .iter()
            .filter(|s| matches!(s.status, CheckExecutionStatus::Executed { .. }))
            .count();

        // On macOS: exactly 32 rules are unsupported (20 Linux + 12 Windows)
        assert_eq!(
            unsupported_count, 32,
            "Unsupported count must equal non-macOS rules"
        );
        // On macOS Baseline: exactly 2 rules excluded by profile (macOS hardened rules)
        assert_eq!(
            excluded_count, 2,
            "Profile-excluded count must equal macOS hardened-only rules"
        );
        // On macOS Baseline: exactly 9 rules executed
        assert_eq!(
            executed_count, 9,
            "Executed count must equal macOS baseline rules"
        );
        // Sum invariant
        assert_eq!(unsupported_count + excluded_count + executed_count, 43);

        // Verify that profile-excluded rules are NOT marked UnsupportedPlatform
        for status in &baseline_report.check_statuses {
            if status.rule_id == "macos.remote.login-enabled"
                || status.rule_id == "macos.remote.management-enabled"
            {
                assert!(
                    matches!(status.status, CheckExecutionStatus::NotApplicable { .. }),
                    "macOS hardened rule {} must be NotApplicable, NOT UnsupportedPlatform",
                    status.rule_id
                );
            }
        }
    }
}
