//! Built-in security rules for local Linux host auditing.

use crate::collector::firewall::FirewallStatus;
use crate::collector::{HostInspectionContext, PrivilegeLevel};
use crate::platform::PlatformCapability;
use crate::rule::{Rule, RuleFinding};
use openaudit_core::{EvidenceType, Severity};

static SSH_CAPS: &[PlatformCapability] = &[PlatformCapability::SshDaemon];
static FIREWALL_CAPS: &[PlatformCapability] = &[PlatformCapability::Firewall];
static PORT_CAPS: &[PlatformCapability] = &[PlatformCapability::ListeningPorts];
static FS_CAPS: &[PlatformCapability] = &[PlatformCapability::FilePermissions];
static SUID_CAPS: &[PlatformCapability] = &[PlatformCapability::SuidSgidBinaries];
static USER_CAPS: &[PlatformCapability] = &[PlatformCapability::SystemUsers];
static KERNEL_CAPS: &[PlatformCapability] = &[PlatformCapability::KernelSysctl];
static ENV_CAPS: &[PlatformCapability] = &[PlatformCapability::EnvironmentVariables];

/// Rule flagging direct root login via SSH (`PermitRootLogin yes`).
#[derive(Debug, Default, Clone, Copy)]
pub struct SshPermitRootLoginRule;

impl Rule for SshPermitRootLoginRule {
    fn id(&self) -> &'static str {
        "linux.ssh.permit-root-login"
    }

    fn title(&self) -> &'static str {
        "SSH Root Login Permitted"
    }

    fn description(&self) -> &'static str {
        "The SSH daemon permits direct remote login as root. Direct root logins bypass accountability and expose systems to brute-force attacks."
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn remediation(&self) -> &'static str {
        "Set 'PermitRootLogin prohibit-password' or 'PermitRootLogin no' in /etc/ssh/sshd_config and restart sshd."
    }

    fn required_privilege(&self) -> PrivilegeLevel {
        PrivilegeLevel::Unprivileged
    }

    fn required_capabilities(&self) -> &[PlatformCapability] {
        SSH_CAPS
    }

    fn evaluate(&self, context: &HostInspectionContext) -> Vec<RuleFinding> {
        let Some(ssh) = context.ssh.as_ref() else {
            return Vec::new();
        };
        let Some(val) = ssh.permit_root_login.as_deref() else {
            return Vec::new();
        };

        if val == "yes" {
            vec![RuleFinding {
                rule_id: self.id(),
                target: "/etc/ssh/sshd_config:PermitRootLogin".into(),
                title: self.title().into(),
                description: self.description().into(),
                remediation: self.remediation().into(),
                severity: self.severity(),
                evidence_text: format!("PermitRootLogin {val}"),
                evidence_type: EvidenceType::ConfigExcerpt,
            }]
        } else {
            Vec::new()
        }
    }
}

/// Rule flagging password authentication over SSH when cryptographic keys should be enforced.
#[derive(Debug, Default, Clone, Copy)]
pub struct SshPasswordAuthRule;

impl Rule for SshPasswordAuthRule {
    fn id(&self) -> &'static str {
        "linux.ssh.password-authentication"
    }

    fn title(&self) -> &'static str {
        "SSH Password Authentication Enabled"
    }

    fn description(&self) -> &'static str {
        "The SSH daemon allows password-based authentication, exposing the system to credential stuffing and brute-force attacks."
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn remediation(&self) -> &'static str {
        "Configure SSH public key authentication and set 'PasswordAuthentication no' in /etc/ssh/sshd_config."
    }

    fn required_privilege(&self) -> PrivilegeLevel {
        PrivilegeLevel::Unprivileged
    }

    fn required_capabilities(&self) -> &[PlatformCapability] {
        SSH_CAPS
    }

    fn evaluate(&self, context: &HostInspectionContext) -> Vec<RuleFinding> {
        let Some(ssh) = context.ssh.as_ref() else {
            return Vec::new();
        };

        // OpenSSH defaults PasswordAuthentication to yes when absent from configuration
        let pw_auth = ssh.password_authentication.unwrap_or(true);

        if pw_auth {
            let evidence = if ssh.password_authentication == Some(true) {
                "PasswordAuthentication yes".into()
            } else {
                "PasswordAuthentication omitted (OpenSSH upstream default: yes)".into()
            };

            vec![RuleFinding {
                rule_id: self.id(),
                target: "/etc/ssh/sshd_config:PasswordAuthentication".into(),
                title: self.title().into(),
                description: self.description().into(),
                remediation: self.remediation().into(),
                severity: self.severity(),
                evidence_text: evidence,
                evidence_type: EvidenceType::ConfigExcerpt,
            }]
        } else {
            Vec::new()
        }
    }
}

/// Rule detecting non-root user accounts configured with UID 0 (superuser backdoor).
#[derive(Debug, Default, Clone, Copy)]
pub struct DuplicateRootUidRule;

impl Rule for DuplicateRootUidRule {
    fn id(&self) -> &'static str {
        "linux.users.duplicate-root-uid"
    }

    fn title(&self) -> &'static str {
        "Unauthorized Account with Root UID 0 Detected"
    }

    fn description(&self) -> &'static str {
        "An account other than 'root' possesses UID 0. Any account with UID 0 holds unrestricted superuser privileges and is commonly associated with stealth backdoors."
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn remediation(&self) -> &'static str {
        "Audit and remove or reassign the non-root account with UID 0 from /etc/passwd immediately."
    }

    fn required_privilege(&self) -> PrivilegeLevel {
        PrivilegeLevel::Unprivileged
    }

    fn required_capabilities(&self) -> &[PlatformCapability] {
        USER_CAPS
    }

    fn evaluate(&self, context: &HostInspectionContext) -> Vec<RuleFinding> {
        let Some(users) = context.users.as_ref() else {
            return Vec::new();
        };

        users
            .root_uid_accounts()
            .into_iter()
            .filter(|u| u.username != "root")
            .map(|bad| RuleFinding {
                rule_id: self.id(),
                target: format!("/etc/passwd:{}", bad.username),
                title: self.title().into(),
                description: format!(
                    "Account '{}' possesses UID 0 giving it full root capabilities.",
                    bad.username
                ),
                remediation: self.remediation().into(),
                severity: self.severity(),
                evidence_text: format!(
                    "{}:x:0:{}:{}:{}:{}",
                    bad.username, bad.gid, bad.comment, bad.home, bad.shell
                ),
                evidence_type: EvidenceType::ConfigExcerpt,
            })
            .collect()
    }
}

/// Rule flagging internal database ports listening on wildcard (public) interfaces.
#[derive(Debug, Default, Clone, Copy)]
pub struct ExposedDatabasePortRule;

impl Rule for ExposedDatabasePortRule {
    fn id(&self) -> &'static str {
        "linux.ports.database-publicly-exposed"
    }

    fn title(&self) -> &'static str {
        "Internal Database Exposed on Public Interface"
    }

    fn description(&self) -> &'static str {
        "A database service (MySQL, PostgreSQL, Redis, MongoDB) is listening on a wildcard address (0.0.0.0 or ::), allowing connections from external networks."
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn remediation(&self) -> &'static str {
        "Bind the database server to 127.0.0.1 or an isolated private internal network interface."
    }

    fn required_privilege(&self) -> PrivilegeLevel {
        PrivilegeLevel::Unprivileged
    }

    fn required_capabilities(&self) -> &[PlatformCapability] {
        PORT_CAPS
    }

    fn evaluate(&self, context: &HostInspectionContext) -> Vec<RuleFinding> {
        let known_db_ports = [
            (3306, "MySQL"),
            (5432, "PostgreSQL"),
            (6379, "Redis"),
            (27017, "MongoDB"),
        ];

        let known_db_processes = [
            ("redis-server", "Redis"),
            ("mysqld", "MySQL"),
            ("mariadbd", "MariaDB"),
            ("postgres", "PostgreSQL"),
            ("mongod", "MongoDB"),
        ];

        let mut findings = Vec::new();
        for port_info in &context.listening_ports {
            if port_info.is_wildcard {
                let mut matched_db = None;

                for (db_port, db_name) in known_db_ports {
                    if port_info.port == db_port {
                        matched_db = Some(db_name);
                        break;
                    }
                }

                if matched_db.is_none() {
                    if let Some(ref proc) = port_info.process_name {
                        for (proc_name, db_name) in known_db_processes {
                            if proc == proc_name {
                                matched_db = Some(db_name);
                                break;
                            }
                        }
                    }
                }

                if let Some(db_name) = matched_db {
                    let proc_desc = port_info
                        .process_name
                        .as_deref()
                        .map_or(String::new(), |p| format!(" (process '{p}')"));

                    findings.push(RuleFinding {
                        rule_id: self.id(),
                        target: format!("{}:{}", port_info.ip, port_info.port),
                        title: format!("{db_name} Database Exposed on Wildcard Interface"),
                        description: format!(
                            "{db_name}{proc_desc} (port {}) is bound to wildcard address '{}'.",
                            port_info.port, port_info.ip
                        ),
                        remediation: self.remediation().into(),
                        severity: self.severity(),
                        evidence_text: format!(
                            "{} {}:{} LISTEN (inode: {}){}",
                            port_info.protocol,
                            port_info.ip,
                            port_info.port,
                            port_info.inode,
                            proc_desc
                        ),
                        evidence_type: EvidenceType::SocketState,
                    });
                }
            }
        }

        findings
    }
}

/// Rule detecting an inactive or missing host firewall.
#[derive(Debug, Default, Clone, Copy)]
pub struct FirewallInactiveRule;

impl Rule for FirewallInactiveRule {
    fn id(&self) -> &'static str {
        "linux.firewall.inactive"
    }

    fn title(&self) -> &'static str {
        "Host Firewall Is Inactive"
    }

    fn description(&self) -> &'static str {
        "No active host firewall packet filtering (ufw, nftables, iptables) was detected on this system."
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn remediation(&self) -> &'static str {
        "Enable and configure a host firewall (e.g., 'ufw enable' on Ubuntu/Debian or configure nftables/iptables)."
    }

    fn required_privilege(&self) -> PrivilegeLevel {
        PrivilegeLevel::Unprivileged
    }

    fn required_capabilities(&self) -> &[PlatformCapability] {
        FIREWALL_CAPS
    }

    fn evaluate(&self, context: &HostInspectionContext) -> Vec<RuleFinding> {
        let Some(fw) = context.firewall.as_ref() else {
            return Vec::new();
        };

        if fw.status == FirewallStatus::Inactive {
            vec![RuleFinding {
                rule_id: self.id(),
                target: "host:firewall".into(),
                title: self.title().into(),
                description: self.description().into(),
                remediation: self.remediation().into(),
                severity: self.severity(),
                evidence_text: fw.details.clone(),
                evidence_type: EvidenceType::SystemState,
            }]
        } else {
            Vec::new()
        }
    }
}

/// Rule flagging insecure permissions on sensitive system configuration files.
#[derive(Debug, Default, Clone, Copy)]
pub struct SensitiveFilePermissionsRule;

impl Rule for SensitiveFilePermissionsRule {
    fn id(&self) -> &'static str {
        "linux.fs.sensitive-file-permissions"
    }

    fn title(&self) -> &'static str {
        "Insecure Permissions on Critical System File"
    }

    fn description(&self) -> &'static str {
        "A critical system configuration file has world-writable or unauthorized world-readable permissions, permitting tampering or sensitive credential disclosure."
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn remediation(&self) -> &'static str {
        "Set strict permissions on the file (e.g. 'chmod 0640 /etc/shadow' or 'chmod 0440 /etc/sudoers')."
    }

    fn required_privilege(&self) -> PrivilegeLevel {
        PrivilegeLevel::Unprivileged
    }

    fn required_capabilities(&self) -> &[PlatformCapability] {
        FS_CAPS
    }

    fn evaluate(&self, context: &HostInspectionContext) -> Vec<RuleFinding> {
        let mut findings = Vec::new();

        for file in &context.file_permissions {
            if file.is_world_writable {
                findings.push(RuleFinding {
                    rule_id: self.id(),
                    target: file.path.clone(),
                    title: format!("Critical File '{}' Is World-Writable", file.path),
                    description: format!(
                        "File '{}' has permission mode {:o}, allowing any local user to modify it.",
                        file.path, file.mode
                    ),
                    remediation: self.remediation().into(),
                    severity: self.severity(),
                    evidence_text: format!("Path: {} Mode: 0o{:o}", file.path, file.mode),
                    evidence_type: EvidenceType::SystemState,
                });
            }

            // /etc/shadow should never be world-readable
            if file.path == "/etc/shadow" && file.is_world_readable {
                findings.push(RuleFinding {
                    rule_id: self.id(),
                    target: file.path.clone(),
                    title: "Shadow Password File Is World-Readable".into(),
                    description: "Password hash hashes in /etc/shadow are readable by all unprivileged users.".into(),
                    remediation: "Run 'chmod 0640 /etc/shadow' immediately.".into(),
                    severity: Severity::Critical,
                    evidence_text: format!("Path: {} Mode: 0o{:o}", file.path, file.mode),
                    evidence_type: EvidenceType::SystemState,
                });
            }
        }

        findings
    }
}

/// Rule detecting accounts with empty password hashes in /etc/shadow.
#[derive(Debug, Default, Clone, Copy)]
pub struct EmptyPasswordRule;

impl Rule for EmptyPasswordRule {
    fn id(&self) -> &'static str {
        "linux.users.empty-password"
    }

    fn title(&self) -> &'static str {
        "User Account with Empty Password Hash"
    }

    fn description(&self) -> &'static str {
        "An account exists in /etc/shadow with an empty password hash field, permitting password authentication without entering a password."
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn remediation(&self) -> &'static str {
        "Set a strong password with 'passwd <username>' or disable the account with 'passwd -l <username>'."
    }

    fn required_privilege(&self) -> PrivilegeLevel {
        PrivilegeLevel::RootRequired
    }

    fn required_capabilities(&self) -> &[PlatformCapability] {
        USER_CAPS
    }

    fn evaluate(&self, context: &HostInspectionContext) -> Vec<RuleFinding> {
        let Some(users) = context.users.as_ref() else {
            return Vec::new();
        };

        users
            .empty_password_accounts
            .iter()
            .map(|username| RuleFinding {
                rule_id: self.id(),
                target: format!("/etc/shadow:{username}"),
                title: format!("Account '{username}' Has No Password Set"),
                description: format!(
                    "The password field for account '{username}' in /etc/shadow is empty."
                ),
                remediation: self.remediation().into(),
                severity: self.severity(),
                evidence_text: format!("{username}::19000:0:99999:7:::"),
                evidence_type: EvidenceType::ConfigExcerpt,
            })
            .collect()
    }
}

/// Returns a collection of all standard built-in Linux audit rules.
#[must_use]
pub fn default_linux_rules() -> Vec<Box<dyn Rule>> {
    vec![
        // SSH configuration
        Box::new(SshPermitRootLoginRule),
        Box::new(SshPasswordAuthRule),
        Box::new(SshX11ForwardingRule),
        Box::new(SshMaxAuthTriesRule),
        // Users & authentication
        Box::new(DuplicateRootUidRule),
        Box::new(EmptyPasswordRule),
        Box::new(ServiceAccountInteractiveShellRule),
        Box::new(SudoersNopasswdRule),
        Box::new(SudoGroupMemberRule),
        // Network exposure
        Box::new(ExposedDatabasePortRule),
        Box::new(SshWildcardExposureRule),
        Box::new(DnsPubliclyExposedRule),
        // Firewall
        Box::new(FirewallInactiveRule),
        // Filesystem & privileges
        Box::new(SensitiveFilePermissionsRule),
        Box::new(UnexpectedSuidBinaryRule),
        Box::new(UnexpectedSgidBinaryRule),
        Box::new(WritablePathEntryRule),
        // Kernel hardening
        Box::new(KernelDmesgUnrestrictedRule),
        Box::new(KernelIpForwardingRule),
        Box::new(KernelAslrDisabledRule),
    ]
}

/// SUID binaries allowed by the default Ubuntu/Debian baseline.
pub const SUID_ALLOWLIST: &[&str] = &[
    "/usr/bin/sudo",
    "/usr/bin/sudoedit",
    "/bin/sudo",
    "/bin/sudoedit",
    "/usr/bin/su",
    "/bin/su",
    "/usr/bin/newgrp",
    "/bin/newgrp",
    "/usr/bin/chsh",
    "/bin/chsh",
    "/usr/bin/chfn",
    "/bin/chfn",
    "/usr/bin/passwd",
    "/bin/passwd",
    "/usr/bin/gpasswd",
    "/bin/gpasswd",
    "/usr/bin/sg",
    "/bin/sg",
    "/usr/bin/mount",
    "/bin/mount",
    "/usr/bin/umount",
    "/bin/umount",
    "/bin/ping",
    "/bin/ping6",
    "/usr/bin/pkexec",
    "/usr/lib/openssh/ssh-keysign",
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
    "/usr/sbin/pam_extraauth",
    "/sbin/pam_extraauth",
];

/// SGID binaries allowed by the default Ubuntu/Debian baseline.
pub const SGID_ALLOWLIST: &[&str] = &[
    "/usr/bin/crontab",
    "/bin/crontab",
    "/usr/bin/wall",
    "/bin/wall",
    "/usr/bin/bsd-write",
    "/bin/bsd-write",
    "/usr/bin/write",
    "/bin/write",
    "/usr/bin/expiry",
    "/bin/expiry",
    "/usr/bin/chage",
    "/bin/chage",
    "/usr/bin/ssh-agent",
    "/bin/ssh-agent",
    "/sbin/unix_chkpwd",
    "/usr/sbin/unix_chkpwd",
    "/sbin/pam_extrausers_chkpwd",
    "/usr/sbin/pam_extrausers_chkpwd",
];

/// Rule flagging X11 forwarding enabled in SSH (`X11Forwarding yes`).
#[derive(Debug, Default, Clone, Copy)]
pub struct SshX11ForwardingRule;

impl Rule for SshX11ForwardingRule {
    fn id(&self) -> &'static str {
        "linux.ssh.x11-forwarding"
    }

    fn title(&self) -> &'static str {
        "SSH X11 Forwarding Enabled"
    }

    fn description(&self) -> &'static str {
        "X11 protocol forwarding allows remote clients to access graphical display interfaces, potentially allowing session hijacking and local privilege escalation."
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn remediation(&self) -> &'static str {
        "Set 'X11Forwarding no' in /etc/ssh/sshd_config unless explicitly required."
    }

    fn required_privilege(&self) -> PrivilegeLevel {
        PrivilegeLevel::Unprivileged
    }

    fn required_capabilities(&self) -> &[PlatformCapability] {
        SSH_CAPS
    }

    fn evaluate(&self, context: &HostInspectionContext) -> Vec<RuleFinding> {
        let Some(ssh) = context.ssh.as_ref() else {
            return Vec::new();
        };

        if ssh.x11_forwarding == Some(true) {
            vec![RuleFinding {
                rule_id: self.id(),
                target: "/etc/ssh/sshd_config:X11Forwarding".into(),
                title: self.title().into(),
                description: self.description().into(),
                remediation: self.remediation().into(),
                severity: self.severity(),
                evidence_text: "X11Forwarding yes".into(),
                evidence_type: EvidenceType::ConfigExcerpt,
            }]
        } else {
            Vec::new()
        }
    }
}

/// Rule flagging high or unconfigured `MaxAuthTries` in SSH configuration.
#[derive(Debug, Default, Clone, Copy)]
pub struct SshMaxAuthTriesRule;

impl Rule for SshMaxAuthTriesRule {
    fn id(&self) -> &'static str {
        "linux.ssh.max-auth-tries"
    }

    fn title(&self) -> &'static str {
        "SSH MaxAuthTries Value Exceeds Security Baseline"
    }

    fn description(&self) -> &'static str {
        "The SSH daemon allows 6 or more authentication attempts per connection, increasing susceptibility to brute-force credential guessing."
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn remediation(&self) -> &'static str {
        "Set 'MaxAuthTries 4' or lower in /etc/ssh/sshd_config."
    }

    fn required_privilege(&self) -> PrivilegeLevel {
        PrivilegeLevel::Unprivileged
    }

    fn required_capabilities(&self) -> &[PlatformCapability] {
        SSH_CAPS
    }

    fn evaluate(&self, context: &HostInspectionContext) -> Vec<RuleFinding> {
        let Some(ssh) = context.ssh.as_ref() else {
            return Vec::new();
        };

        // OpenSSH upstream default is 6 when omitted
        let tries = ssh.max_auth_tries.unwrap_or(6);

        if tries >= 6 {
            let evidence = ssh.max_auth_tries.map_or_else(
                || "MaxAuthTries omitted (OpenSSH upstream default: 6)".into(),
                |n| format!("MaxAuthTries {n}"),
            );

            vec![RuleFinding {
                rule_id: self.id(),
                target: "/etc/ssh/sshd_config:MaxAuthTries".into(),
                title: self.title().into(),
                description: self.description().into(),
                remediation: self.remediation().into(),
                severity: self.severity(),
                evidence_text: evidence,
                evidence_type: EvidenceType::ConfigExcerpt,
            }]
        } else {
            Vec::new()
        }
    }
}

/// Rule detecting system service accounts configured with interactive login shells.
#[derive(Debug, Default, Clone, Copy)]
pub struct ServiceAccountInteractiveShellRule;

impl Rule for ServiceAccountInteractiveShellRule {
    fn id(&self) -> &'static str {
        "linux.users.service-account-interactive-shell"
    }

    fn title(&self) -> &'static str {
        "Service Account Configured with Interactive Login Shell"
    }

    fn description(&self) -> &'static str {
        "A system service account (UID < 1000) possesses an interactive shell like /bin/bash or /bin/sh instead of /usr/sbin/nologin."
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn remediation(&self) -> &'static str {
        "Set service account shell to /usr/sbin/nologin or /bin/false using 'usermod -s /usr/sbin/nologin <user>'."
    }

    fn required_privilege(&self) -> PrivilegeLevel {
        PrivilegeLevel::Unprivileged
    }

    fn required_capabilities(&self) -> &[PlatformCapability] {
        USER_CAPS
    }

    fn evaluate(&self, context: &HostInspectionContext) -> Vec<RuleFinding> {
        let Some(users) = context.users.as_ref() else {
            return Vec::new();
        };

        users
            .interactive_service_accounts
            .iter()
            .map(|username| RuleFinding {
                rule_id: self.id(),
                target: format!("/etc/passwd:{username}"),
                title: format!("Service Account '{username}' Has Interactive Shell"),
                description: format!(
                    "Service account '{username}' has an interactive shell configured, creating an unnecessary login attack surface."
                ),
                remediation: self.remediation().into(),
                severity: self.severity(),
                evidence_text: format!("username: {username}"),
                evidence_type: EvidenceType::ConfigExcerpt,
            })
            .collect()
    }
}

/// Rule detecting accounts configured with passwordless sudo (`NOPASSWD`).
#[derive(Debug, Default, Clone, Copy)]
pub struct SudoersNopasswdRule;

impl Rule for SudoersNopasswdRule {
    fn id(&self) -> &'static str {
        "linux.users.sudoers-nopasswd"
    }

    fn title(&self) -> &'static str {
        "Passwordless Sudo Privileges Granted"
    }

    fn description(&self) -> &'static str {
        "One or more users or groups are granted NOPASSWD in sudoers configuration, allowing privilege escalation to root without password verification."
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn remediation(&self) -> &'static str {
        "Require password authentication for sudo executions by removing 'NOPASSWD:' from /etc/sudoers and /etc/sudoers.d/*."
    }

    fn required_privilege(&self) -> PrivilegeLevel {
        PrivilegeLevel::Unprivileged
    }

    fn required_capabilities(&self) -> &[PlatformCapability] {
        USER_CAPS
    }

    fn evaluate(&self, context: &HostInspectionContext) -> Vec<RuleFinding> {
        let Some(users) = context.users.as_ref() else {
            return Vec::new();
        };

        users
            .nopasswd_sudo_users
            .iter()
            .map(|user| RuleFinding {
                rule_id: self.id(),
                target: format!("sudoers:{user}"),
                title: format!("User '{user}' Granted NOPASSWD Privileges"),
                description: format!(
                    "User '{user}' is configured with passwordless sudo access in sudoers."
                ),
                remediation: self.remediation().into(),
                severity: self.severity(),
                evidence_text: format!("{user} ALL=(ALL) NOPASSWD:..."),
                evidence_type: EvidenceType::ConfigExcerpt,
            })
            .collect()
    }
}

/// Rule alerting on non-root user accounts belonging to privileged sudo or wheel groups.
#[derive(Debug, Default, Clone, Copy)]
pub struct SudoGroupMemberRule;

impl Rule for SudoGroupMemberRule {
    fn id(&self) -> &'static str {
        "linux.users.unauthorized-sudo-group-member"
    }

    fn title(&self) -> &'static str {
        "User Account in Privileged Sudo Group"
    }

    fn description(&self) -> &'static str {
        "A user account belongs to the 'sudo' or 'wheel' group, granting full administrative root access."
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn remediation(&self) -> &'static str {
        "Review whether this account legitimately requires sudo access, or remove it with 'gpasswd -d <user> sudo'."
    }

    fn required_privilege(&self) -> PrivilegeLevel {
        PrivilegeLevel::Unprivileged
    }

    fn required_capabilities(&self) -> &[PlatformCapability] {
        USER_CAPS
    }

    fn evaluate(&self, context: &HostInspectionContext) -> Vec<RuleFinding> {
        let Some(users) = context.users.as_ref() else {
            return Vec::new();
        };

        users
            .sudo_group_members
            .iter()
            .filter(|u| *u != "root")
            .map(|user| RuleFinding {
                rule_id: self.id(),
                target: format!("/etc/group:sudo:{user}"),
                title: format!("Account '{user}' Is Member of Sudo Group"),
                description: format!(
                    "Account '{user}' has administrative privileges via group membership."
                ),
                remediation: self.remediation().into(),
                severity: self.severity(),
                evidence_text: format!("group member: {user}"),
                evidence_type: EvidenceType::ConfigExcerpt,
            })
            .collect()
    }
}

/// Rule noting SSH daemon listening on a public/wildcard interface.
#[derive(Debug, Default, Clone, Copy)]
pub struct SshWildcardExposureRule;

impl Rule for SshWildcardExposureRule {
    fn id(&self) -> &'static str {
        "linux.ports.ssh-wildcard-exposure"
    }

    fn title(&self) -> &'static str {
        "SSH Daemon Listening on Wildcard Interface"
    }

    fn description(&self) -> &'static str {
        "The SSH daemon is listening on all network interfaces (0.0.0.0 or ::). Ensure strong key authentication and firewall restrictions are in place."
    }

    fn severity(&self) -> Severity {
        Severity::Info
    }

    fn remediation(&self) -> &'static str {
        "If public access is not required, bind SSH to a private network interface or VPN address in /etc/ssh/sshd_config."
    }

    fn required_privilege(&self) -> PrivilegeLevel {
        PrivilegeLevel::Unprivileged
    }

    fn required_capabilities(&self) -> &[PlatformCapability] {
        PORT_CAPS
    }

    fn evaluate(&self, context: &HostInspectionContext) -> Vec<RuleFinding> {
        let mut findings = Vec::new();
        for port_info in &context.listening_ports {
            if port_info.port == 22 && port_info.is_wildcard {
                findings.push(RuleFinding {
                    rule_id: self.id(),
                    target: format!("{}:22", port_info.ip),
                    title: self.title().into(),
                    description: format!(
                        "SSH daemon (port 22) is bound to wildcard address '{}'.",
                        port_info.ip
                    ),
                    remediation: self.remediation().into(),
                    severity: self.severity(),
                    evidence_text: format!("{} {}:22 LISTEN", port_info.protocol, port_info.ip),
                    evidence_type: EvidenceType::SocketState,
                });
            }
        }
        findings
    }
}

/// Rule detecting DNS service listening on a wildcard UDP interface.
#[derive(Debug, Default, Clone, Copy)]
pub struct DnsPubliclyExposedRule;

impl Rule for DnsPubliclyExposedRule {
    fn id(&self) -> &'static str {
        "linux.ports.dns-publicly-exposed"
    }

    fn title(&self) -> &'static str {
        "DNS Service Exposed on Wildcard UDP Interface"
    }

    fn description(&self) -> &'static str {
        "A DNS server (port 53) is bound to a wildcard address (0.0.0.0 or ::), exposing it to potential DNS amplification attacks or unauthorized queries."
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn remediation(&self) -> &'static str {
        "Bind the DNS resolver to 127.0.0.1 or restrict incoming queries to trusted local subnets."
    }

    fn required_privilege(&self) -> PrivilegeLevel {
        PrivilegeLevel::Unprivileged
    }

    fn required_capabilities(&self) -> &[PlatformCapability] {
        PORT_CAPS
    }

    fn evaluate(&self, context: &HostInspectionContext) -> Vec<RuleFinding> {
        let mut findings = Vec::new();
        for port in &context.udp_ports {
            if port.port == 53 && port.is_wildcard {
                findings.push(RuleFinding {
                    rule_id: self.id(),
                    target: format!("{}:53/udp", port.ip),
                    title: self.title().into(),
                    description: format!(
                        "DNS service (port 53/udp) is bound to wildcard address '{}'.",
                        port.ip
                    ),
                    remediation: self.remediation().into(),
                    severity: self.severity(),
                    evidence_text: format!("{} {}:53", port.protocol, port.ip),
                    evidence_type: EvidenceType::SocketState,
                });
            }
        }
        findings
    }
}

/// Rule detecting SUID-root binaries outside the standard operating system baseline.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnexpectedSuidBinaryRule;

impl Rule for UnexpectedSuidBinaryRule {
    fn id(&self) -> &'static str {
        "linux.fs.unexpected-suid-binary"
    }

    fn title(&self) -> &'static str {
        "Unexpected SUID-Root Executable Detected"
    }

    fn description(&self) -> &'static str {
        "A binary with the SUID bit set was found outside the standard system allowlist. SUID binaries run with root privileges and are common privilege escalation vectors."
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn remediation(&self) -> &'static str {
        "Remove the SUID bit using 'chmod u-s <path>' or remove the unauthorized binary."
    }

    fn required_privilege(&self) -> PrivilegeLevel {
        PrivilegeLevel::Unprivileged
    }

    fn required_capabilities(&self) -> &[PlatformCapability] {
        SUID_CAPS
    }

    fn evaluate(&self, context: &HostInspectionContext) -> Vec<RuleFinding> {
        let mut findings = Vec::new();
        for binary in &context.suid_binaries {
            if binary.is_suid && !SUID_ALLOWLIST.contains(&binary.path.as_str()) {
                findings.push(RuleFinding {
                    rule_id: self.id(),
                    target: binary.path.clone(),
                    title: format!("Unexpected SUID Binary '{}'", binary.path),
                    description: format!(
                        "Executable '{}' has SUID permission (0o{:o}) and is not in the system allowlist.",
                        binary.path, binary.mode
                    ),
                    remediation: self.remediation().into(),
                    severity: self.severity(),
                    evidence_text: format!("Path: {} Mode: 0o{:o}", binary.path, binary.mode),
                    evidence_type: EvidenceType::SystemState,
                });
            }
        }
        findings
    }
}

/// Rule detecting SGID binaries outside the standard operating system baseline.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnexpectedSgidBinaryRule;

impl Rule for UnexpectedSgidBinaryRule {
    fn id(&self) -> &'static str {
        "linux.fs.unexpected-sgid-binary"
    }

    fn title(&self) -> &'static str {
        "Unexpected SGID Executable Detected"
    }

    fn description(&self) -> &'static str {
        "A binary with the SGID bit set was found outside the standard system allowlist. SGID binaries run with elevated group privileges."
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn remediation(&self) -> &'static str {
        "Remove the SGID bit using 'chmod g-s <path>' or remove the unauthorized binary."
    }

    fn required_privilege(&self) -> PrivilegeLevel {
        PrivilegeLevel::Unprivileged
    }

    fn required_capabilities(&self) -> &[PlatformCapability] {
        SUID_CAPS
    }

    fn evaluate(&self, context: &HostInspectionContext) -> Vec<RuleFinding> {
        let mut findings = Vec::new();
        for binary in &context.suid_binaries {
            if binary.is_sgid && !SGID_ALLOWLIST.contains(&binary.path.as_str()) {
                findings.push(RuleFinding {
                    rule_id: self.id(),
                    target: binary.path.clone(),
                    title: format!("Unexpected SGID Binary '{}'", binary.path),
                    description: format!(
                        "Executable '{}' has SGID permission (0o{:o}) and is not in the system allowlist.",
                        binary.path, binary.mode
                    ),
                    remediation: self.remediation().into(),
                    severity: self.severity(),
                    evidence_text: format!("Path: {} Mode: 0o{:o}", binary.path, binary.mode),
                    evidence_type: EvidenceType::SystemState,
                });
            }
        }
        findings
    }
}

/// Rule detecting world-writable directories in the system `PATH`.
#[derive(Debug, Default, Clone, Copy)]
pub struct WritablePathEntryRule;

impl Rule for WritablePathEntryRule {
    fn id(&self) -> &'static str {
        "linux.users.writable-path-entry"
    }

    fn title(&self) -> &'static str {
        "World-Writable Directory in PATH Environment Variable"
    }

    fn description(&self) -> &'static str {
        "A directory in the system PATH environment variable is world-writable, allowing any local user to place malicious binaries that may be executed by privileged users."
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn remediation(&self) -> &'static str {
        "Remove world-write permissions using 'chmod 0755 <directory>' or remove the directory from PATH."
    }

    fn required_privilege(&self) -> PrivilegeLevel {
        PrivilegeLevel::Unprivileged
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
                    title: format!("Directory '{}' in PATH Is World-Writable", entry.path),
                    description: format!(
                        "Directory '{}' (mode 0o{:o}) can be written to by any local user.",
                        entry.path, entry.mode
                    ),
                    remediation: self.remediation().into(),
                    severity: self.severity(),
                    evidence_text: format!("Path: {} Mode: 0o{:o}", entry.path, entry.mode),
                    evidence_type: EvidenceType::SystemState,
                });
            }
        }
        findings
    }
}

/// Rule detecting unrestricted kernel dmesg access (`kernel.dmesg_restrict = 0`).
#[derive(Debug, Default, Clone, Copy)]
pub struct KernelDmesgUnrestrictedRule;

impl Rule for KernelDmesgUnrestrictedRule {
    fn id(&self) -> &'static str {
        "linux.kernel.dmesg-unrestricted"
    }

    fn title(&self) -> &'static str {
        "Unrestricted Kernel Ring Buffer (dmesg) Access"
    }

    fn description(&self) -> &'static str {
        "Unprivileged users can read kernel logs via dmesg, potentially exposing kernel addresses and facilitating exploit development."
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn remediation(&self) -> &'static str {
        "Set 'kernel.dmesg_restrict = 1' in /etc/sysctl.conf and run 'sysctl -p'."
    }

    fn required_privilege(&self) -> PrivilegeLevel {
        PrivilegeLevel::Unprivileged
    }

    fn required_capabilities(&self) -> &[PlatformCapability] {
        KERNEL_CAPS
    }

    fn evaluate(&self, context: &HostInspectionContext) -> Vec<RuleFinding> {
        let Some(sysctl) = context.sysctl.as_ref() else {
            return Vec::new();
        };

        if sysctl.dmesg_restrict == Some(0) {
            vec![RuleFinding {
                rule_id: self.id(),
                target: "sysctl:kernel.dmesg_restrict".into(),
                title: self.title().into(),
                description: self.description().into(),
                remediation: self.remediation().into(),
                severity: self.severity(),
                evidence_text: "kernel.dmesg_restrict = 0".into(),
                evidence_type: EvidenceType::SystemState,
            }]
        } else {
            Vec::new()
        }
    }
}

/// Rule detecting IP forwarding enabled on host (`net.ipv4.ip_forward = 1`).
#[derive(Debug, Default, Clone, Copy)]
pub struct KernelIpForwardingRule;

impl Rule for KernelIpForwardingRule {
    fn id(&self) -> &'static str {
        "linux.kernel.ip-forwarding-enabled"
    }

    fn title(&self) -> &'static str {
        "Kernel IPv4 Packet Forwarding Enabled"
    }

    fn description(&self) -> &'static str {
        "The kernel is configured to forward IPv4 packets between interfaces, effectively acting as a router. This should be disabled unless the host is a dedicated router or gateway."
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn remediation(&self) -> &'static str {
        "Set 'net.ipv4.ip_forward = 0' in /etc/sysctl.conf and reload with 'sysctl -p'."
    }

    fn required_privilege(&self) -> PrivilegeLevel {
        PrivilegeLevel::Unprivileged
    }

    fn required_capabilities(&self) -> &[PlatformCapability] {
        KERNEL_CAPS
    }

    fn evaluate(&self, context: &HostInspectionContext) -> Vec<RuleFinding> {
        let Some(sysctl) = context.sysctl.as_ref() else {
            return Vec::new();
        };

        if sysctl.ip_forward == Some(1) {
            vec![RuleFinding {
                rule_id: self.id(),
                target: "sysctl:net.ipv4.ip_forward".into(),
                title: self.title().into(),
                description: self.description().into(),
                remediation: self.remediation().into(),
                severity: self.severity(),
                evidence_text: "net.ipv4.ip_forward = 1".into(),
                evidence_type: EvidenceType::SystemState,
            }]
        } else {
            Vec::new()
        }
    }
}

/// Rule detecting Address Space Layout Randomization (ASLR) disabled (`kernel.randomize_va_space = 0`).
#[derive(Debug, Default, Clone, Copy)]
pub struct KernelAslrDisabledRule;

impl Rule for KernelAslrDisabledRule {
    fn id(&self) -> &'static str {
        "linux.kernel.aslr-disabled"
    }

    fn title(&self) -> &'static str {
        "Address Space Layout Randomization (ASLR) Disabled"
    }

    fn description(&self) -> &'static str {
        "Memory randomization (ASLR) is disabled, making exploitation of memory corruption bugs trivial and predictable."
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn remediation(&self) -> &'static str {
        "Set 'kernel.randomize_va_space = 2' in /etc/sysctl.conf and reload with 'sysctl -p'."
    }

    fn required_privilege(&self) -> PrivilegeLevel {
        PrivilegeLevel::Unprivileged
    }

    fn required_capabilities(&self) -> &[PlatformCapability] {
        KERNEL_CAPS
    }

    fn evaluate(&self, context: &HostInspectionContext) -> Vec<RuleFinding> {
        let Some(sysctl) = context.sysctl.as_ref() else {
            return Vec::new();
        };

        if sysctl.randomize_va_space == Some(0) {
            vec![RuleFinding {
                rule_id: self.id(),
                target: "sysctl:kernel.randomize_va_space".into(),
                title: self.title().into(),
                description: self.description().into(),
                remediation: self.remediation().into(),
                severity: self.severity(),
                evidence_text: "kernel.randomize_va_space = 0".into(),
                evidence_type: EvidenceType::SystemState,
            }]
        } else {
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collector::env::PathEntry;
    use crate::collector::firewall::{FirewallInfo, FirewallKind, FirewallStatus};
    use crate::collector::permissions::FilePermissionInfo;
    use crate::collector::ports::{ListeningPort, ListeningUdpPort};
    use crate::collector::ssh::SshConfig;
    use crate::collector::suid::SuidBinaryInfo;
    use crate::collector::sysctl::SysctlInfo;
    use crate::collector::users::{UserAccount, UsersInfo};

    #[test]
    fn test_ssh_permit_root_login_eval() {
        let rule = SshPermitRootLoginRule;

        // Safe
        let safe_context = HostInspectionContext {
            ssh: Some(SshConfig {
                permit_root_login: Some("no".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(rule.evaluate(&safe_context), []);

        // Dangerous
        let danger_context = HostInspectionContext {
            ssh: Some(SshConfig {
                permit_root_login: Some("yes".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let findings = rule.evaluate(&danger_context);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].rule_id, "linux.ssh.permit-root-login");
    }

    #[test]
    fn test_duplicate_root_uid_eval() {
        let rule = DuplicateRootUidRule;
        let context = HostInspectionContext {
            users: Some(UsersInfo {
                accounts: vec![
                    UserAccount {
                        username: "root".into(),
                        uid: 0,
                        gid: 0,
                        comment: "root".into(),
                        home: "/root".into(),
                        shell: "/bin/bash".into(),
                    },
                    UserAccount {
                        username: "backdoor".into(),
                        uid: 0,
                        gid: 0,
                        comment: "evil".into(),
                        home: "/root".into(),
                        shell: "/bin/bash".into(),
                    },
                ],
                empty_password_accounts: Vec::new(),
                ..Default::default()
            }),
            ..Default::default()
        };

        let findings = rule.evaluate(&context);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].target, "/etc/passwd:backdoor");
    }

    #[test]
    fn test_exposed_database_port_multi_finding_eval() {
        let rule = ExposedDatabasePortRule;
        let context = HostInspectionContext {
            listening_ports: vec![
                ListeningPort {
                    protocol: "tcp".into(),
                    ip: "127.0.0.1".into(),
                    port: 5432,
                    is_wildcard: false,
                    inode: 1234,
                    process_name: None,
                },
                ListeningPort {
                    protocol: "tcp".into(),
                    ip: "0.0.0.0".into(),
                    port: 6379,
                    is_wildcard: true,
                    inode: 5678,
                    process_name: None,
                },
                ListeningPort {
                    protocol: "tcp6".into(),
                    ip: "::".into(),
                    port: 3306,
                    is_wildcard: true,
                    inode: 9101,
                    process_name: None,
                },
            ],
            ..Default::default()
        };

        let findings = rule.evaluate(&context);
        assert_eq!(findings.len(), 2, "must report both exposed databases");
    }

    #[test]
    fn test_exposed_database_by_process_name_eval() {
        let rule = ExposedDatabasePortRule;
        let context = HostInspectionContext {
            listening_ports: vec![ListeningPort {
                protocol: "tcp".into(),
                ip: "0.0.0.0".into(),
                port: 6380, // non-standard port
                is_wildcard: true,
                inode: 9999,
                process_name: Some("redis-server".into()),
            }],
            ..Default::default()
        };

        let findings = rule.evaluate(&context);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("Redis"));
    }

    #[test]
    fn test_empty_password_eval() {
        let rule = EmptyPasswordRule;
        let context = HostInspectionContext {
            users: Some(UsersInfo {
                accounts: Vec::new(),
                empty_password_accounts: vec!["alice".into()],
                ..Default::default()
            }),
            ..Default::default()
        };

        let findings = rule.evaluate(&context);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].target, "/etc/shadow:alice");
    }

    #[test]
    fn test_firewall_inactive_eval() {
        let rule = FirewallInactiveRule;
        let context = HostInspectionContext {
            firewall: Some(FirewallInfo {
                kind: FirewallKind::Ufw,
                status: FirewallStatus::Inactive,
                is_active: false,
                details: "Status: inactive".into(),
            }),
            ..Default::default()
        };

        let findings = rule.evaluate(&context);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn test_sensitive_file_permissions_multi_finding_eval() {
        let rule = SensitiveFilePermissionsRule;
        let context = HostInspectionContext {
            file_permissions: vec![
                FilePermissionInfo {
                    path: "/etc/shadow".into(),
                    exists: true,
                    mode: 0o644,
                    is_world_writable: false,
                    is_world_readable: true,
                },
                FilePermissionInfo {
                    path: "/etc/passwd".into(),
                    exists: true,
                    mode: 0o666,
                    is_world_writable: true,
                    is_world_readable: true,
                },
            ],
            ..Default::default()
        };

        let findings = rule.evaluate(&context);
        assert_eq!(
            findings.len(),
            2,
            "must report both shadow and passwd violations"
        );
    }

    #[test]
    fn test_ssh_x11_forwarding_eval() {
        let rule = SshX11ForwardingRule;
        let safe_ctx = HostInspectionContext {
            ssh: Some(SshConfig {
                x11_forwarding: Some(false),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(rule.evaluate(&safe_ctx), []);

        let danger_ctx = HostInspectionContext {
            ssh: Some(SshConfig {
                x11_forwarding: Some(true),
                ..Default::default()
            }),
            ..Default::default()
        };
        let findings = rule.evaluate(&danger_ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Low);
    }

    #[test]
    fn test_ssh_max_auth_tries_eval() {
        let rule = SshMaxAuthTriesRule;
        let safe_ctx = HostInspectionContext {
            ssh: Some(SshConfig {
                max_auth_tries: Some(4),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(rule.evaluate(&safe_ctx), []);

        let danger_ctx = HostInspectionContext {
            ssh: Some(SshConfig {
                max_auth_tries: Some(10),
                ..Default::default()
            }),
            ..Default::default()
        };
        let findings = rule.evaluate(&danger_ctx);
        assert_eq!(findings.len(), 1);

        // Omitted defaults to 6 (vulnerable)
        let omitted_ctx = HostInspectionContext {
            ssh: Some(SshConfig {
                max_auth_tries: None,
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(rule.evaluate(&omitted_ctx).len(), 1);
    }

    #[test]
    fn test_service_account_shell_eval() {
        let rule = ServiceAccountInteractiveShellRule;
        let ctx = HostInspectionContext {
            users: Some(UsersInfo {
                interactive_service_accounts: vec!["www-data".into()],
                ..Default::default()
            }),
            ..Default::default()
        };
        let findings = rule.evaluate(&ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn test_sudoers_nopasswd_eval() {
        let rule = SudoersNopasswdRule;
        let ctx = HostInspectionContext {
            users: Some(UsersInfo {
                nopasswd_sudo_users: vec!["alice".into()],
                ..Default::default()
            }),
            ..Default::default()
        };
        let findings = rule.evaluate(&ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn test_sudo_group_member_eval() {
        let rule = SudoGroupMemberRule;
        let ctx = HostInspectionContext {
            users: Some(UsersInfo {
                sudo_group_members: vec!["root".into(), "alice".into()],
                ..Default::default()
            }),
            ..Default::default()
        };
        let findings = rule.evaluate(&ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].target, "/etc/group:sudo:alice");
    }

    #[test]
    fn test_ssh_wildcard_exposure_eval() {
        let rule = SshWildcardExposureRule;
        let ctx = HostInspectionContext {
            listening_ports: vec![ListeningPort {
                protocol: "tcp".into(),
                ip: "0.0.0.0".into(),
                port: 22,
                is_wildcard: true,
                inode: 1234,
                process_name: None,
            }],
            ..Default::default()
        };
        let findings = rule.evaluate(&ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
    }

    #[test]
    fn test_dns_publicly_exposed_eval() {
        let rule = DnsPubliclyExposedRule;
        let ctx = HostInspectionContext {
            udp_ports: vec![ListeningUdpPort {
                protocol: "udp".into(),
                ip: "0.0.0.0".into(),
                port: 53,
                is_wildcard: true,
                inode: 5566,
                process_name: None,
            }],
            ..Default::default()
        };
        let findings = rule.evaluate(&ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn test_unexpected_suid_binary_eval() {
        let rule = UnexpectedSuidBinaryRule;
        let ctx = HostInspectionContext {
            suid_binaries: vec![
                SuidBinaryInfo {
                    path: "/usr/bin/passwd".into(), // allowed
                    mode: 0o4755,
                    is_suid: true,
                    is_sgid: false,
                },
                SuidBinaryInfo {
                    path: "/tmp/setuid-bash".into(), // unexpected
                    mode: 0o4755,
                    is_suid: true,
                    is_sgid: false,
                },
            ],
            ..Default::default()
        };
        let findings = rule.evaluate(&ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].target, "/tmp/setuid-bash");
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn test_unexpected_sgid_binary_eval() {
        let rule = UnexpectedSgidBinaryRule;
        let ctx = HostInspectionContext {
            suid_binaries: vec![
                SuidBinaryInfo {
                    path: "/usr/bin/crontab".into(), // allowed
                    mode: 0o2755,
                    is_suid: false,
                    is_sgid: true,
                },
                SuidBinaryInfo {
                    path: "/tmp/shadow-reader".into(), // unexpected
                    mode: 0o2755,
                    is_suid: false,
                    is_sgid: true,
                },
            ],
            ..Default::default()
        };
        let findings = rule.evaluate(&ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].target, "/tmp/shadow-reader");
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn test_writable_path_entry_eval() {
        let rule = WritablePathEntryRule;
        let ctx = HostInspectionContext {
            path_entries: vec![
                PathEntry {
                    path: "/usr/bin".into(),
                    exists: true,
                    mode: 0o755,
                    is_world_writable: false,
                },
                PathEntry {
                    path: "/tmp/evil".into(),
                    exists: true,
                    mode: 0o777,
                    is_world_writable: true,
                },
            ],
            ..Default::default()
        };
        let findings = rule.evaluate(&ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].target, "/tmp/evil");
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn test_kernel_sysctl_rules_eval() {
        let dmesg_rule = KernelDmesgUnrestrictedRule;
        let ip_forward_rule = KernelIpForwardingRule;
        let aslr_rule = KernelAslrDisabledRule;

        let safe_ctx = HostInspectionContext {
            sysctl: Some(SysctlInfo {
                dmesg_restrict: Some(1),
                ip_forward: Some(0),
                randomize_va_space: Some(2),
            }),
            ..Default::default()
        };
        assert_eq!(dmesg_rule.evaluate(&safe_ctx), []);
        assert_eq!(ip_forward_rule.evaluate(&safe_ctx), []);
        assert_eq!(aslr_rule.evaluate(&safe_ctx), []);

        let danger_ctx = HostInspectionContext {
            sysctl: Some(SysctlInfo {
                dmesg_restrict: Some(0),
                ip_forward: Some(1),
                randomize_va_space: Some(0),
            }),
            ..Default::default()
        };
        assert_eq!(dmesg_rule.evaluate(&danger_ctx).len(), 1);
        assert_eq!(ip_forward_rule.evaluate(&danger_ctx).len(), 1);
        assert_eq!(aslr_rule.evaluate(&danger_ctx).len(), 1);
    }
}
