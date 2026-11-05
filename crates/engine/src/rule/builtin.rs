//! Built-in security rules for local Linux host auditing.

use crate::collector::{HostInspectionContext, PrivilegeLevel};
use crate::rule::{Rule, RuleFinding};
use openaudit_core::{EvidenceType, Severity};

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

    fn evaluate(&self, context: &HostInspectionContext) -> Option<RuleFinding> {
        let ssh = context.ssh.as_ref()?;
        let val = ssh.permit_root_login.as_deref()?;

        if val == "yes" {
            Some(RuleFinding {
                rule_id: self.id(),
                target: "/etc/ssh/sshd_config:PermitRootLogin".into(),
                title: self.title().into(),
                description: self.description().into(),
                remediation: self.remediation().into(),
                severity: self.severity(),
                evidence_text: format!("PermitRootLogin {val}"),
                evidence_type: EvidenceType::ConfigExcerpt,
            })
        } else {
            None
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

    fn evaluate(&self, context: &HostInspectionContext) -> Option<RuleFinding> {
        let ssh = context.ssh.as_ref()?;
        let pw_auth = ssh.password_authentication?;

        if pw_auth {
            Some(RuleFinding {
                rule_id: self.id(),
                target: "/etc/ssh/sshd_config:PasswordAuthentication".into(),
                title: self.title().into(),
                description: self.description().into(),
                remediation: self.remediation().into(),
                severity: self.severity(),
                evidence_text: "PasswordAuthentication yes".into(),
                evidence_type: EvidenceType::ConfigExcerpt,
            })
        } else {
            None
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

    fn evaluate(&self, context: &HostInspectionContext) -> Option<RuleFinding> {
        let users = context.users.as_ref()?;
        let bad_accounts: Vec<_> = users
            .root_uid_accounts()
            .into_iter()
            .filter(|u| u.username != "root")
            .collect();

        bad_accounts.first().map(|bad| RuleFinding {
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

    fn evaluate(&self, context: &HostInspectionContext) -> Option<RuleFinding> {
        let known_db_ports = [
            (3306, "MySQL"),
            (5432, "PostgreSQL"),
            (6379, "Redis"),
            (27017, "MongoDB"),
        ];

        for port_info in &context.listening_ports {
            if port_info.is_wildcard {
                for (db_port, db_name) in known_db_ports {
                    if port_info.port == db_port {
                        return Some(RuleFinding {
                            rule_id: self.id(),
                            target: format!("{}:{}", port_info.ip, port_info.port),
                            title: format!("{db_name} Database Exposed on Wildcard Interface"),
                            description: format!(
                                "{db_name} (port {db_port}) is bound to wildcard address '{}'.",
                                port_info.ip
                            ),
                            remediation: self.remediation().into(),
                            severity: self.severity(),
                            evidence_text: format!(
                                "{} {}:{} LISTEN (inode: {})",
                                port_info.protocol, port_info.ip, port_info.port, port_info.inode
                            ),
                            evidence_type: EvidenceType::SocketState,
                        });
                    }
                }
            }
        }

        None
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

    fn evaluate(&self, context: &HostInspectionContext) -> Option<RuleFinding> {
        let fw = context.firewall.as_ref()?;
        if fw.is_active {
            None
        } else {
            Some(RuleFinding {
                rule_id: self.id(),
                target: "host:firewall".into(),
                title: self.title().into(),
                description: self.description().into(),
                remediation: self.remediation().into(),
                severity: self.severity(),
                evidence_text: fw.details.clone(),
                evidence_type: EvidenceType::SystemState,
            })
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

    fn evaluate(&self, context: &HostInspectionContext) -> Option<RuleFinding> {
        for file in &context.file_permissions {
            if file.is_world_writable {
                return Some(RuleFinding {
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
                return Some(RuleFinding {
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

        None
    }
}

/// Returns a collection of all standard built-in Linux audit rules.
#[must_use]
pub fn default_linux_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(SshPermitRootLoginRule),
        Box::new(SshPasswordAuthRule),
        Box::new(DuplicateRootUidRule),
        Box::new(ExposedDatabasePortRule),
        Box::new(FirewallInactiveRule),
        Box::new(SensitiveFilePermissionsRule),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collector::firewall::{FirewallInfo, FirewallKind};
    use crate::collector::permissions::FilePermissionInfo;
    use crate::collector::ports::ListeningPort;
    use crate::collector::ssh::SshConfig;
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
        assert!(rule.evaluate(&safe_context).is_none());

        // Dangerous
        let danger_context = HostInspectionContext {
            ssh: Some(SshConfig {
                permit_root_login: Some("yes".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let finding = rule
            .evaluate(&danger_context)
            .expect("should trigger finding");
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.rule_id, "linux.ssh.permit-root-login");
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
            }),
            ..Default::default()
        };

        let finding = rule
            .evaluate(&context)
            .expect("should catch backdoor UID 0");
        assert_eq!(finding.severity, Severity::Critical);
        assert_eq!(finding.target, "/etc/passwd:backdoor");
    }

    #[test]
    fn test_exposed_database_port_eval() {
        let rule = ExposedDatabasePortRule;
        let context = HostInspectionContext {
            listening_ports: vec![
                ListeningPort {
                    protocol: "tcp".into(),
                    ip: "127.0.0.1".into(),
                    port: 5432,
                    is_wildcard: false,
                    inode: 1234,
                },
                ListeningPort {
                    protocol: "tcp".into(),
                    ip: "0.0.0.0".into(),
                    port: 6379,
                    is_wildcard: true,
                    inode: 5678,
                },
            ],
            ..Default::default()
        };

        let finding = rule
            .evaluate(&context)
            .expect("should flag exposed Redis on 0.0.0.0:6379");
        assert_eq!(finding.severity, Severity::High);
        assert!(finding.title.contains("Redis"));
    }

    #[test]
    fn test_firewall_inactive_eval() {
        let rule = FirewallInactiveRule;
        let context = HostInspectionContext {
            firewall: Some(FirewallInfo {
                kind: FirewallKind::Ufw,
                is_active: false,
                details: "Status: inactive".into(),
            }),
            ..Default::default()
        };

        let finding = rule
            .evaluate(&context)
            .expect("should flag inactive firewall");
        assert_eq!(finding.severity, Severity::High);
    }

    #[test]
    fn test_sensitive_file_permissions_eval() {
        let rule = SensitiveFilePermissionsRule;
        let context = HostInspectionContext {
            file_permissions: vec![FilePermissionInfo {
                path: "/etc/shadow".into(),
                exists: true,
                mode: 0o666,
                is_world_writable: true,
                is_world_readable: true,
            }],
            ..Default::default()
        };

        let finding = rule
            .evaluate(&context)
            .expect("should flag world-writable shadow file");
        assert_eq!(finding.severity, Severity::Critical);
    }
}
