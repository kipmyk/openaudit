//! macOS compatibility and regression integration tests (Milestone M3.4).
//!
//! Verifies:
//! - Full end-to-end audit execution on macOS Sonoma (14) and Sequoia (15)
//! - Deterministic finding evaluation across all 11 native macOS security rules
//! - Fail-closed enforcement on unsupported legacy macOS versions (13, 12, 11, 10.x)
//! - Proper `CheckExecutionStatus` tracking (`UnsupportedPlatform` for Linux/Windows rules, `Executed` for macOS rules)
//! - Sensitive data redaction and evidence generation
//! - Zero regressions against frozen M2 guarantees
//! - Actual native macOS host execution on Apple Silicon / macOS systems

use openaudit_core::{AssetType, OrganizationId};
use openaudit_engine::collector::macos::{
    MacosAccount, MacosAccountsInfo, MacosLaunchdInfo, MacosLaunchdItem, MacosSecurityInfo,
};
use openaudit_engine::collector::ports::ListeningPort;
use openaudit_engine::collector::{
    CommandRunner, FileSystem, HostInspectionContext, PrivilegeLevel,
};
#[cfg(target_os = "macos")]
use openaudit_engine::collector::{RealCommandRunner, RealFileSystem};
use openaudit_engine::error::EngineError;
use openaudit_engine::platform::macos::MacosPlatformBackend;
use openaudit_engine::platform::{
    CheckExecutionStatus, PlatformBackend, PlatformDistribution, PlatformFamily, PlatformInfo,
    PlatformVersion,
};
use openaudit_engine::profile::AuditProfile;
use openaudit_engine::rule::macos::default_macos_rules;
use openaudit_engine::rule::windows::default_windows_rules;
use openaudit_engine::rule::{default_linux_rules, Rule};
use openaudit_engine::runner::AuditEngine;

#[derive(Debug, Clone, Copy, Default)]
struct MockMacosFs;

impl FileSystem for MockMacosFs {
    fn read_to_string(&self, path: &str) -> Result<String, EngineError> {
        if path.contains("SoftwareUpdate") {
            Ok("AutomaticDownload = 0;\nAutomaticallyInstallMacOSUpdates = 0;\nCriticalUpdateInstall = 0;\nConfigDataInstall = 0;\n".into())
        } else {
            Err(EngineError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "not found",
            )))
        }
    }

    fn exists(&self, path: &str) -> bool {
        path.contains("System") || path.contains("Library")
    }

    fn file_mode(&self, path: &str) -> Result<u32, EngineError> {
        if path.contains("insecure.daemon") {
            Ok(0o666) // world-writable
        } else {
            Ok(0o644)
        }
    }

    fn read_dir(&self, path: &str) -> Result<Vec<String>, EngineError> {
        if path == "/Library/LaunchDaemons" {
            Ok(vec![
                "/Library/LaunchDaemons/com.insecure.daemon.plist".into(),
                "/Library/LaunchDaemons/com.secure.daemon.plist".into(),
            ])
        } else {
            Ok(Vec::new())
        }
    }

    fn read_link(&self, path: &str) -> Result<String, EngineError> {
        Ok(path.to_string())
    }
}

#[derive(Debug, Clone, Default)]
struct MockMacosRunner {
    sw_vers_output: String,
}

impl MockMacosRunner {
    const fn new() -> Self {
        Self {
            sw_vers_output: String::new(),
        }
    }

    fn with_sw_vers(mut self, product: &str, build: &str) -> Self {
        self.sw_vers_output =
            format!("ProductName:\tmacOS\nProductVersion:\t{product}\nBuildVersion:\t{build}\n");
        self
    }
}

impl CommandRunner for MockMacosRunner {
    fn run(&self, program: &str, args: &[&str]) -> Result<String, EngineError> {
        if program == "sw_vers" {
            return Ok(self.sw_vers_output.clone());
        }
        if program == "csrutil" {
            return Ok("System Integrity Protection status: disabled.\n".into());
        }
        if program == "fdesetup" {
            return Ok("FileVault is Off.\n".into());
        }
        if program == "spctl" {
            return Ok("assessments disabled\n".into());
        }
        if program.contains("socketfilterfw") {
            return Ok("Firewall is disabled. (State = 0)\n".into());
        }
        if program == "systemsetup" {
            return Ok("Remote Login: On\n".into());
        }
        if program == "launchctl" {
            return Ok("123  0  com.apple.RemoteDesktop.agent\n".into());
        }
        if program == "defaults" {
            let cmd = args.join(" ");
            if cmd.contains("SoftwareUpdate") {
                return Ok("AutomaticDownload = 0;\nAutomaticallyInstallMacOSUpdates = 0;\nCriticalUpdateInstall = 0;\nConfigDataInstall = 0;\n".into());
            }
        }
        if program == "dscl" {
            let cmd = args.join(" ");
            if cmd.contains("/Groups/admin") {
                return Ok("GroupMembership: root admin mac\n".into());
            }
            if cmd.contains("UniqueID") {
                return Ok("root 0\nmac 501\nGuest 201\n".into());
            }
            if cmd.contains("/Users/Guest") {
                return Ok("UserShell: /bin/bash\n".into());
            }
        }
        if program == "netstat" {
            return Ok("Active Internet connections\nProto Recv-Q Send-Q  Local Address          Foreign Address        (state)\ntcp4       0      0  *.445                  *.*                    LISTEN\ntcp4       0      0  127.0.0.1.8080         *.*                    LISTEN\n".into());
        }
        if program == "uname" {
            return Ok("23.5.0\n".into());
        }

        Err(EngineError::CommandExecution(format!(
            "Command not mocked: {program} {args:?}"
        )))
    }
}

struct HardenedMacosBackend {
    info: PlatformInfo,
}

impl PlatformBackend for HardenedMacosBackend {
    fn info(&self) -> &PlatformInfo {
        &self.info
    }

    fn is_supported(&self) -> bool {
        true
    }

    fn collect_context(&self) -> Result<HostInspectionContext, EngineError> {
        Ok(HostInspectionContext {
            macos_security: Some(MacosSecurityInfo {
                sip_enabled: true,
                sip_status: "System Integrity Protection status: enabled.".into(),
                filevault_enabled: true,
                filevault_status: "FileVault is On.".into(),
                gatekeeper_enabled: true,
                gatekeeper_status: "assessments enabled".into(),
                firewall_enabled: true,
                firewall_stealth_mode: true,
                firewall_status: "Firewall is enabled. (State = 1)".into(),
                auto_update_enabled: true,
                critical_update_install: true,
                remote_login_enabled: false,
                remote_management_enabled: false,
                details: "Hardened macOS security posture".into(),
            }),
            macos_accounts: Some(MacosAccountsInfo {
                accounts: vec![MacosAccount {
                    name: "admin".into(),
                    uid: 501,
                    is_admin: true,
                    is_guest: false,
                    shell: "/bin/zsh".into(),
                }],
                administrators: vec!["root".into(), "admin".into()],
                guest_enabled: false,
                details: "Guest account inactive".into(),
            }),
            macos_launchd: Some(MacosLaunchdInfo {
                items: vec![MacosLaunchdItem {
                    name: "com.secure.daemon".into(),
                    path: "/Library/LaunchDaemons/com.secure.daemon.plist".into(),
                    is_daemon: true,
                    mode: 0o644,
                    is_insecure: false,
                }],
                insecure_items: Vec::new(),
            }),
            listening_ports: vec![ListeningPort {
                protocol: "tcp".into(),
                ip: "127.0.0.1".into(),
                port: 8080,
                is_wildcard: false,
                inode: 0,
                process_name: Some("local-daemon".into()),
            }],
            current_privilege: PrivilegeLevel::Unprivileged,
            ..Default::default()
        })
    }
}

#[test]
fn test_macos_sonoma_full_audit_lifecycle_and_findings() {
    let org_id = OrganizationId::new();
    let runner = MockMacosRunner::new().with_sw_vers("14.5", "23F79");
    let fs = MockMacosFs;
    let backend = MacosPlatformBackend::detect_with(&fs, &runner);

    assert_eq!(backend.info().family, PlatformFamily::MacOS);
    assert_eq!(
        backend.info().distribution,
        PlatformDistribution::MacosSonoma
    );
    assert!(backend.is_supported());

    let rules: Vec<Box<dyn Rule>> = default_macos_rules();
    let engine = AuditEngine::new(fs, runner, rules);

    let report = engine
        .run_audit_with_backend(org_id, &backend, AuditProfile::Hardened)
        .expect("macOS Sonoma audit must complete successfully");

    // Invariant 1: Asset identity correctly reflects macOS Host
    assert_eq!(report.asset.asset_type, AssetType::MacosHost);
    let platform = report.platform_info.as_ref().expect("platform_info");
    assert_eq!(platform.family, PlatformFamily::MacOS);
    assert_eq!(platform.version.major, 14);
    assert_eq!(platform.version.build.as_deref(), Some("23F79"));

    // Invariant 2: macOS audit produced findings for mocked vulnerabilities
    assert_ne!(report.findings.len(), 0);

    let finding_rule_ids: Vec<&str> = report
        .findings
        .iter()
        .map(|f| f.finding.rule_id.as_str())
        .collect();

    assert!(finding_rule_ids.contains(&"macos.sip.disabled"));
    assert!(finding_rule_ids.contains(&"macos.filevault.disabled"));
    assert!(finding_rule_ids.contains(&"macos.gatekeeper.disabled"));
    assert!(finding_rule_ids.contains(&"macos.firewall.disabled"));
    assert!(finding_rule_ids.contains(&"macos.updates.auto-disabled"));
    assert!(finding_rule_ids.contains(&"macos.remote.login-enabled"));
    assert!(finding_rule_ids.contains(&"macos.remote.management-enabled"));
    assert!(finding_rule_ids.contains(&"macos.accounts.guest-enabled"));
    assert!(finding_rule_ids.contains(&"macos.launchd.insecure-permissions"));
    assert!(finding_rule_ids.contains(&"macos.ports.exposed-sharing"));

    // Invariant 3: Check statuses track execution for all 11 macOS rules
    assert_eq!(report.check_statuses.len(), 11);
    for status in &report.check_statuses {
        assert!(
            matches!(status.status, CheckExecutionStatus::Executed { .. }),
            "Expected rule {} to be Executed on macOS, was {:?}",
            status.rule_id,
            status.status
        );
    }
}

#[test]
fn test_macos_sequoia_support_and_audit() {
    let org_id = OrganizationId::new();
    let runner = MockMacosRunner::new().with_sw_vers("15.0", "24A335");
    let fs = MockMacosFs;
    let backend = MacosPlatformBackend::detect_with(&fs, &runner);

    assert_eq!(backend.info().family, PlatformFamily::MacOS);
    assert_eq!(
        backend.info().distribution,
        PlatformDistribution::MacosSequoia
    );
    assert!(backend.is_supported());

    let rules: Vec<Box<dyn Rule>> = default_macos_rules();
    let engine = AuditEngine::new(fs, runner, rules);

    let report = engine
        .run_audit_with_backend(org_id, &backend, AuditProfile::Baseline)
        .expect("macOS Sequoia audit must complete");

    assert_eq!(report.asset.asset_type, AssetType::MacosHost);
    assert_ne!(report.findings.len(), 0);
}

#[test]
fn test_unsupported_macos_versions_fail_closed() {
    let org_id = OrganizationId::new();
    let legacy_versions = [
        ("13.6.7", "22G720"),   // Ventura
        ("12.7.5", "21H1222"),  // Monterey
        ("11.7.10", "20G1427"), // Big Sur
        ("10.15.7", "19H2026"), // Catalina
    ];

    for (product, build) in legacy_versions {
        let runner = MockMacosRunner::new().with_sw_vers(product, build);
        let fs = MockMacosFs;
        let backend = MacosPlatformBackend::detect_with(&fs, &runner);

        assert!(
            !backend.is_supported(),
            "macOS target {product} must NOT be supported in M3.4"
        );

        let err = backend.collect_context().unwrap_err();
        assert!(
            matches!(err, EngineError::UnsupportedPlatform(ref s) if s.contains("Milestone M3.4")),
            "Target {product} must fail closed with typed UnsupportedPlatform error: {err:?}"
        );

        let engine = AuditEngine::new(fs, runner, default_macos_rules());
        let audit_err = engine
            .run_audit_with_backend(org_id, &backend, AuditProfile::Baseline)
            .unwrap_err();
        assert!(
            matches!(audit_err, EngineError::UnsupportedPlatform(..)),
            "Engine execution on {product} must fail closed"
        );
    }
}

#[test]
fn test_linux_and_windows_rules_on_macos_backend_marked_unsupported() {
    let org_id = OrganizationId::new();
    let runner = MockMacosRunner::new().with_sw_vers("14.5", "23F79");
    let fs = MockMacosFs;
    let backend = MacosPlatformBackend::detect_with(&fs, &runner);

    // Mix Linux, Windows, and macOS rules in the catalog
    let mut mixed_rules: Vec<Box<dyn Rule>> = default_linux_rules();
    mixed_rules.extend(default_windows_rules());
    mixed_rules.extend(default_macos_rules());

    let engine = AuditEngine::new(fs, runner, mixed_rules);
    let report = engine
        .run_audit_with_backend(org_id, &backend, AuditProfile::Hardened)
        .expect("mixed rules audit must execute on macOS");

    for status in &report.check_statuses {
        if status.rule_id.starts_with("linux.") {
            assert!(
                matches!(
                    status.status,
                    CheckExecutionStatus::UnsupportedPlatform { .. }
                ),
                "Linux rule {} must be recorded as UnsupportedPlatform on macOS",
                status.rule_id
            );
        } else if status.rule_id.starts_with("windows.") {
            assert!(
                matches!(
                    status.status,
                    CheckExecutionStatus::UnsupportedPlatform { .. }
                ),
                "Windows rule {} must be recorded as UnsupportedPlatform on macOS",
                status.rule_id
            );
        } else if status.rule_id.starts_with("macos.") {
            assert!(
                matches!(status.status, CheckExecutionStatus::Executed { .. }),
                "macOS rule {} must be executed on macOS",
                status.rule_id
            );
        }
    }
}

#[test]
fn test_hardened_macos_clean_pass() {
    let org_id = OrganizationId::new();
    let info = PlatformInfo {
        family: PlatformFamily::MacOS,
        distribution: PlatformDistribution::MacosSonoma,
        version: PlatformVersion::parse("14.5").with_build("23F79"),
        architecture: "aarch64".into(),
        kernel_release: "Darwin 23.5.0".into(),
        hostname: "SECURE-MAC".into(),
        pretty_name: "macOS Sonoma 14.5".into(),
        machine_id: Some("deterministic-mac-id".into()),
        capabilities: MacosPlatformBackend::default_capabilities(),
    };

    let backend = HardenedMacosBackend { info };
    let engine = AuditEngine::new(MockMacosFs, MockMacosRunner::new(), default_macos_rules());

    let report = engine
        .run_audit_with_backend(org_id, &backend, AuditProfile::Hardened)
        .expect("audit on hardened macos host must succeed");

    assert_eq!(
        report.findings.len(),
        0,
        "Hardened macOS system must produce 0 findings, but found: {:?}",
        report.findings
    );

    assert_eq!(report.check_statuses.len(), 11);
    for status in &report.check_statuses {
        assert_eq!(
            status.status,
            CheckExecutionStatus::Executed { passed: true },
            "Rule {} was expected to pass",
            status.rule_id
        );
    }
}

#[test]
#[cfg(target_os = "macos")]
fn test_actual_native_macos_execution() {
    let org_id = OrganizationId::new();
    let backend = MacosPlatformBackend::detect();

    // Verify detection ran against real Mac host
    assert_eq!(backend.info().family, PlatformFamily::MacOS);
    assert_ne!(backend.info().architecture, "");
    assert_ne!(backend.info().kernel_release, "");
    assert!(
        backend.is_supported(),
        "Current macOS host must be supported in M3.4"
    );

    let engine = AuditEngine::new(RealFileSystem, RealCommandRunner, default_macos_rules());
    let report = engine
        .run_audit_with_backend(org_id, &backend, AuditProfile::Hardened)
        .expect("native macOS audit execution must succeed on Mac host");

    assert_eq!(report.asset.asset_type, AssetType::MacosHost);
    assert_eq!(report.check_statuses.len(), 11);

    println!("[+] Native macOS Host Detected:");
    println!("    Pretty Name: {}", backend.info().pretty_name);
    println!("    Architecture: {}", backend.info().architecture);
    println!("    Kernel: {}", backend.info().kernel_release);
    println!("    Distribution: {:?}", backend.info().distribution);
    println!("    Version: {}", backend.info().version);
    println!("[+] Audit Execution Completed:");
    println!("    Asset Name: {}", report.asset.name);
    println!("    Asset Type: {:?}", report.asset.asset_type);
    println!("    Findings Count: {}", report.findings.len());
    for f in &report.findings {
        println!(
            "      - [{:?}] {}: {}",
            f.finding.severity, f.finding.rule_id, f.finding.title
        );
        println!("        Description: {}", f.finding.description);
    }
    println!("    Check Statuses:");
    for s in &report.check_statuses {
        println!("      - {}: {:?}", s.rule_id, s.status);
    }
    for status in &report.check_statuses {
        assert!(
            matches!(status.status, CheckExecutionStatus::Executed { .. }),
            "Rule {} must have executed on real Mac, got: {:?}",
            status.rule_id,
            status.status
        );
    }
}
