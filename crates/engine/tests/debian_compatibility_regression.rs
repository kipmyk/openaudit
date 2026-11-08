//! Debian 12 (Bookworm) and Debian 13 (Trixie) Linux reference backend compatibility
//! and multi-distribution verification suite for OpenAudit M3.2.
//!
//! Verifies that the shared audit engine executes with identical semantics, finding consistency,
//! capability tracking, and evidence formatting across Ubuntu 24.04, Debian 12, and Debian 13,
//! while failing closed on unvalidated distributions and legacy releases.

use openaudit_core::OrganizationId;
use openaudit_engine::collector::firewall::FirewallKind;
use openaudit_engine::collector::{CommandRunner, FileSystem};
use openaudit_engine::error::EngineError;
use openaudit_engine::platform::{
    CheckExecutionStatus, LinuxPlatformBackend, PlatformBackend, PlatformCapability,
    PlatformDistribution, PlatformFamily,
};
use openaudit_engine::profile::AuditProfile;
use openaudit_engine::rule::builtin::default_linux_rules;
use openaudit_engine::AuditEngine;

#[derive(Debug, Clone)]
struct MockDebianFs {
    os_release: String,
    hostname: String,
    machine_id: String,
    sshd_config: String,
    sshd_dropin: Option<String>,
    shadow: String,
    passwd: String,
    group: String,
    sudoers: String,
    ip_forward: String,
    dmesg_restrict: String,
    aslr: String,
}

impl MockDebianFs {
    fn debian_12_bookworm() -> Self {
        Self {
            os_release: "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nNAME=\"Debian GNU/Linux\"\nVERSION_ID=\"12\"\nVERSION=\"12 (bookworm)\"\nVERSION_CODENAME=bookworm\nID=debian\n".into(),
            hostname: "debian12-prod-node\n".into(),
            machine_id: "deb12-b00kw0rm-000000000000000000\n".into(),
            sshd_config: "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin yes\nPasswordAuthentication yes\n".into(),
            sshd_dropin: Some("X11Forwarding no\nMaxAuthTries 4\n".into()),
            shadow: "root:*:19000:0:99999:7:::\ninsecure_user::19000:0:99999:7:::\n".into(),
            passwd: "root:x:0:0::/root:/bin/bash\ninsecure_user:x:1001:1001::/home/insecure_user:/bin/bash\n".into(),
            group: "root:x:0:\nsudo:x:27:insecure_user\n".into(),
            sudoers: "root ALL=(ALL:ALL) ALL\n%sudo ALL=(ALL:ALL) NOPASSWD: ALL\n".into(),
            ip_forward: "1\n".into(),
            dmesg_restrict: "0\n".into(),
            aslr: "2\n".into(),
        }
    }

    fn debian_13_trixie() -> Self {
        Self {
            os_release: "PRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\nNAME=\"Debian GNU/Linux\"\nVERSION_ID=\"13\"\nVERSION=\"13 (trixie)\"\nVERSION_CODENAME=trixie\nID=debian\n".into(),
            hostname: "debian13-test-node\n".into(),
            machine_id: "deb13-tr1x1e-00000000000000000000\n".into(),
            sshd_config: "PermitRootLogin yes\nPasswordAuthentication yes\nX11Forwarding no\n".into(),
            sshd_dropin: None,
            shadow: "root:*:19000:0:99999:7:::\n".into(),
            passwd: "root:x:0:0::/root:/bin/bash\n".into(),
            group: "root:x:0:\nsudo:x:27:\n".into(),
            sudoers: "root ALL=(ALL:ALL) ALL\n".into(),
            ip_forward: "0\n".into(),
            dmesg_restrict: "1\n".into(),
            aslr: "2\n".into(),
        }
    }
}

impl FileSystem for MockDebianFs {
    fn read_to_string(&self, path: &str) -> Result<String, EngineError> {
        match path {
            "/etc/os-release" | "/usr/lib/os-release" => Ok(self.os_release.clone()),
            "/etc/hostname" => Ok(self.hostname.clone()),
            "/etc/machine-id" => Ok(self.machine_id.clone()),
            "/etc/ssh/sshd_config" => Ok(self.sshd_config.clone()),
            "/etc/ssh/sshd_config.d/01-hardening.conf" => {
                self.sshd_dropin.clone().ok_or_else(|| {
                    EngineError::Io(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "no dropin",
                    ))
                })
            }
            "/etc/shadow" => Ok(self.shadow.clone()),
            "/etc/passwd" => Ok(self.passwd.clone()),
            "/etc/group" => Ok(self.group.clone()),
            "/etc/sudoers" => Ok(self.sudoers.clone()),
            "/proc/sys/net/ipv4/ip_forward" => Ok(self.ip_forward.clone()),
            "/proc/sys/kernel/dmesg_restrict" => Ok(self.dmesg_restrict.clone()),
            "/proc/sys/kernel/randomize_va_space" => Ok(self.aslr.clone()),
            _ => Err(EngineError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("path not found in MockDebianFs: {path}"),
            ))),
        }
    }

    fn exists(&self, path: &str) -> bool {
        match path {
            "/etc/os-release"
            | "/usr/lib/os-release"
            | "/etc/hostname"
            | "/etc/machine-id"
            | "/etc/ssh/sshd_config"
            | "/etc/shadow"
            | "/etc/passwd"
            | "/etc/group"
            | "/etc/sudoers"
            | "/proc/sys/net/ipv4/ip_forward"
            | "/proc/sys/kernel/dmesg_restrict"
            | "/proc/sys/kernel/randomize_va_space" => true,
            "/etc/ssh/sshd_config.d" | "/etc/ssh/sshd_config.d/01-hardening.conf" => {
                self.sshd_dropin.is_some()
            }
            _ => false,
        }
    }

    fn file_mode(&self, _path: &str) -> Result<u32, EngineError> {
        Ok(0o644)
    }

    fn read_dir(&self, path: &str) -> Result<Vec<String>, EngineError> {
        if path == "/etc/ssh/sshd_config.d" && self.sshd_dropin.is_some() {
            Ok(vec!["/etc/ssh/sshd_config.d/01-hardening.conf".to_string()])
        } else {
            Ok(Vec::new())
        }
    }

    fn read_link(&self, _path: &str) -> Result<String, EngineError> {
        Err(EngineError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "not found",
        )))
    }
}

#[derive(Debug, Clone, Copy)]
enum MockFirewallMode {
    NftablesActive,
    IptablesActive,
    Inactive,
}

#[derive(Debug, Clone, Copy)]
struct MockDebianRunner {
    firewall: MockFirewallMode,
}

impl CommandRunner for MockDebianRunner {
    fn run(&self, program: &str, args: &[&str]) -> Result<String, EngineError> {
        match (program, args) {
            // Debian 12/13 standard nftables backend
            ("nft", ["list", "ruleset"]) => match self.firewall {
                MockFirewallMode::NftablesActive => Ok(
                    "table inet filter {\n    chain input {\n        type filter hook input priority filter; policy drop;\n    }\n}\n"
                        .into(),
                ),
                _ => Ok(String::new()),
            },
            // Legacy iptables backend
            ("iptables", ["-L", "-n"]) => match self.firewall {
                MockFirewallMode::IptablesActive => Ok(
                    "Chain INPUT (policy DROP)\ntarget     prot opt source               destination\n"
                        .into(),
                ),
                _ => Ok("Chain INPUT (policy ACCEPT)\n".into()),
            },
            // UFW is typically absent on minimal Debian
            ("ufw", ["status"]) => Err(EngineError::CommandExecution(
                "ufw: command not found".into(),
            )),
            _ => Err(EngineError::CommandExecution(format!(
                "unmocked command: {program} {args:?}"
            ))),
        }
    }
}

#[test]
fn test_debian_12_bookworm_baseline_audit_execution() {
    let org_id = OrganizationId::new();
    let fs = MockDebianFs::debian_12_bookworm();
    let runner = MockDebianRunner {
        firewall: MockFirewallMode::NftablesActive,
    };

    let backend = LinuxPlatformBackend::detect(&fs, &runner).expect("detect Debian 12");
    assert_eq!(backend.info().family, PlatformFamily::Linux);
    assert_eq!(backend.info().distribution, PlatformDistribution::Debian);
    assert_eq!(backend.info().version.major, 12);
    assert_eq!(backend.info().version.codename.as_deref(), Some("bookworm"));
    assert!(
        backend.is_supported(),
        "Debian 12 must be officially supported in M3.2"
    );

    // Capabilities must be available
    assert!(backend.has_capability(PlatformCapability::KernelSysctl));
    assert!(backend.has_capability(PlatformCapability::SshDaemon));
    assert!(backend.has_capability(PlatformCapability::Firewall));
    assert!(backend.has_capability(PlatformCapability::ListeningPorts));
    assert!(backend.has_capability(PlatformCapability::SuidSgidBinaries));
    assert!(backend.has_capability(PlatformCapability::FilePermissions));
    assert!(backend.has_capability(PlatformCapability::SystemUsers));
    assert!(backend.has_capability(PlatformCapability::EnvironmentVariables));

    let engine = AuditEngine::new(fs, runner, default_linux_rules());
    let report = engine
        .run_audit_with_backend(org_id, &backend, AuditProfile::Baseline)
        .expect("audit execution must succeed on Debian 12");

    assert_eq!(report.asset.organization_id, org_id);
    let platform = report.platform_info.as_ref().expect("platform info");
    assert_eq!(platform.distribution, PlatformDistribution::Debian);
    assert_eq!(platform.version.major, 12);
    assert_eq!(platform.hostname, "debian12-prod-node");

    // Verify findings detected matching the mock state
    let rule_ids: Vec<&str> = report
        .findings
        .iter()
        .map(|f| f.finding.rule_id.as_str())
        .collect();

    assert!(rule_ids.contains(&"linux.ssh.permit-root-login"));
    assert!(rule_ids.contains(&"linux.ssh.password-authentication"));
    assert!(rule_ids.contains(&"linux.users.sudoers-nopasswd"));
    assert!(rule_ids.contains(&"linux.users.unauthorized-sudo-group-member"));
    assert!(rule_ids.contains(&"linux.kernel.ip-forwarding-enabled"));

    // Firewall was active (nftables), so firewall.inactive must NOT be in findings
    assert!(!rule_ids.contains(&"linux.firewall.inactive"));

    // Check statuses must be fully recorded
    assert_ne!(report.check_statuses.len(), 0);
    let ssh_status = report
        .check_statuses
        .iter()
        .find(|s| s.rule_id == "linux.ssh.permit-root-login")
        .expect("ssh status");
    assert_eq!(
        ssh_status.status,
        CheckExecutionStatus::Executed { passed: false }
    );
}

#[test]
fn test_debian_13_trixie_baseline_audit_execution() {
    let org_id = OrganizationId::new();
    let fs = MockDebianFs::debian_13_trixie();
    let runner = MockDebianRunner {
        firewall: MockFirewallMode::Inactive,
    };

    let backend = LinuxPlatformBackend::detect(&fs, &runner).expect("detect Debian 13");
    assert_eq!(backend.info().family, PlatformFamily::Linux);
    assert_eq!(backend.info().distribution, PlatformDistribution::Debian);
    assert_eq!(backend.info().version.major, 13);
    assert_eq!(backend.info().version.codename.as_deref(), Some("trixie"));
    assert!(
        backend.is_supported(),
        "Debian 13 must be officially supported in M3.2"
    );

    let engine = AuditEngine::new(fs, runner, default_linux_rules());
    let report = engine
        .run_audit_with_backend(org_id, &backend, AuditProfile::Baseline)
        .expect("audit execution must succeed on Debian 13");

    let platform = report.platform_info.as_ref().expect("platform info");
    assert_eq!(platform.distribution, PlatformDistribution::Debian);
    assert_eq!(platform.version.major, 13);

    // Inactive firewall on Debian 13 must trigger the firewall finding
    assert!(report
        .findings
        .iter()
        .any(|f| f.finding.rule_id == "linux.firewall.inactive"));
}

#[test]
fn test_debian_nftables_and_iptables_firewall_parity() {
    let fs = MockDebianFs::debian_12_bookworm();

    // 1. Nftables active
    let runner_nft = MockDebianRunner {
        firewall: MockFirewallMode::NftablesActive,
    };
    let backend_nft = LinuxPlatformBackend::detect(&fs, &runner_nft).expect("detect");
    let ctx_nft = backend_nft.collect_context().expect("context");
    let fw_nft = ctx_nft.firewall.expect("firewall info");
    assert!(fw_nft.is_active);
    assert_eq!(fw_nft.kind, FirewallKind::Nftables);

    // 2. Iptables active
    let runner_ipt = MockDebianRunner {
        firewall: MockFirewallMode::IptablesActive,
    };
    let backend_ipt = LinuxPlatformBackend::detect(&fs, &runner_ipt).expect("detect");
    let ctx_ipt = backend_ipt.collect_context().expect("context");
    let fw_ipt = ctx_ipt.firewall.expect("firewall info");
    assert!(fw_ipt.is_active);
    assert_eq!(fw_ipt.kind, FirewallKind::Iptables);

    // 3. Inactive
    let runner_none = MockDebianRunner {
        firewall: MockFirewallMode::Inactive,
    };
    let backend_none = LinuxPlatformBackend::detect(&fs, &runner_none).expect("detect");
    let ctx_none = backend_none.collect_context().expect("context");
    let fw_none = ctx_none.firewall.expect("firewall info");
    assert!(!fw_none.is_active);
    assert_eq!(fw_none.kind, FirewallKind::None);
}

#[test]
fn test_unsupported_debian_and_linux_versions_fail_closed() {
    let runner = MockDebianRunner {
        firewall: MockFirewallMode::Inactive,
    };

    // Debian 11 (Bullseye) - not in M3.2 target matrix
    let fs_deb11 = MockDebianFs {
        os_release:
            "ID=debian\nVERSION_ID=\"11\"\nPRETTY_NAME=\"Debian GNU/Linux 11 (bullseye)\"\n".into(),
        hostname: "deb11\n".into(),
        machine_id: "deb11-mid\n".into(),
        ..MockDebianFs::debian_12_bookworm()
    };
    let backend_deb11 = LinuxPlatformBackend::detect(&fs_deb11, &runner).expect("detect");
    assert_eq!(
        backend_deb11.info().distribution,
        PlatformDistribution::Debian
    );
    assert!(!backend_deb11.is_supported());

    // Debian 10 (Buster)
    let fs_deb10 = MockDebianFs {
        os_release: "ID=debian\nVERSION_ID=\"10\"\nPRETTY_NAME=\"Debian GNU/Linux 10 (buster)\"\n"
            .into(),
        hostname: "deb10\n".into(),
        machine_id: "deb10-mid\n".into(),
        ..MockDebianFs::debian_12_bookworm()
    };
    let backend_deb10 = LinuxPlatformBackend::detect(&fs_deb10, &runner).expect("detect");
    assert_eq!(
        backend_deb10.info().distribution,
        PlatformDistribution::Debian
    );
    assert!(!backend_deb10.is_supported());

    // Alpine Linux - non-glibc, scheduled for future milestone
    let fs_alpine = MockDebianFs {
        os_release: "ID=alpine\nVERSION_ID=\"3.20.0\"\nPRETTY_NAME=\"Alpine Linux v3.20\"\n".into(),
        hostname: "alpine-box\n".into(),
        machine_id: "alpine-mid\n".into(),
        ..MockDebianFs::debian_12_bookworm()
    };
    let backend_alpine = LinuxPlatformBackend::detect(&fs_alpine, &runner).expect("detect");
    assert_eq!(
        backend_alpine.info().distribution,
        PlatformDistribution::Alpine
    );
    assert!(!backend_alpine.is_supported());

    // RHEL 9
    let fs_rhel = MockDebianFs {
        os_release: "ID=rhel\nVERSION_ID=\"9.4\"\nPRETTY_NAME=\"Red Hat Enterprise Linux 9.4\"\n"
            .into(),
        hostname: "rhel-node\n".into(),
        machine_id: "rhel-mid\n".into(),
        ..MockDebianFs::debian_12_bookworm()
    };
    let backend_rhel = LinuxPlatformBackend::detect(&fs_rhel, &runner).expect("detect");
    assert_eq!(backend_rhel.info().distribution, PlatformDistribution::Rhel);
    assert!(!backend_rhel.is_supported());
}

#[test]
fn test_all_20_rules_parity_between_ubuntu_and_debian() {
    let org_id = OrganizationId::new();

    // Common system state applied to both Ubuntu 24.04 and Debian 12
    let mut fs_deb = MockDebianFs::debian_12_bookworm();
    fs_deb.ip_forward = "1\n".into();
    fs_deb.dmesg_restrict = "0\n".into();
    fs_deb.aslr = "0\n".into();

    let runner_deb = MockDebianRunner {
        firewall: MockFirewallMode::Inactive,
    };
    let backend_deb = LinuxPlatformBackend::detect(&fs_deb, &runner_deb).expect("detect Debian");

    let engine_deb = AuditEngine::new(fs_deb.clone(), runner_deb, default_linux_rules());
    let report_deb = engine_deb
        .run_audit_with_backend(org_id, &backend_deb, AuditProfile::Hardened)
        .expect("Debian hardened audit");

    // Same state on Ubuntu
    let mut fs_ub = fs_deb;
    fs_ub.os_release = "ID=ubuntu\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04 LTS\"\nVERSION_CODENAME=noble\n".into();
    let backend_ub = LinuxPlatformBackend::detect(&fs_ub, &runner_deb).expect("detect Ubuntu");

    let engine_ub = AuditEngine::new(fs_ub, runner_deb, default_linux_rules());
    let report_ub = engine_ub
        .run_audit_with_backend(org_id, &backend_ub, AuditProfile::Hardened)
        .expect("Ubuntu hardened audit");

    // Compare findings across Ubuntu 24.04 and Debian 12: must have identical findings & rule coverage
    let deb_findings: Vec<(&str, openaudit_core::Severity)> = report_deb
        .findings
        .iter()
        .map(|f| (f.finding.rule_id.as_str(), f.finding.severity))
        .collect();

    let ub_findings: Vec<(&str, openaudit_core::Severity)> = report_ub
        .findings
        .iter()
        .map(|f| (f.finding.rule_id.as_str(), f.finding.severity))
        .collect();

    assert_eq!(
        deb_findings, ub_findings,
        "Rule evaluation semantics and severities must be 100% identical between Ubuntu and Debian"
    );

    // Assert total count of evaluated checks matches the 20 built-in rules
    assert_eq!(report_deb.check_statuses.len(), 20);
    assert_eq!(report_ub.check_statuses.len(), 20);
}
