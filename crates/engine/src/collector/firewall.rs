//! Host firewall configuration and status collector.

use crate::collector::CommandRunner;
use serde::{Deserialize, Serialize};

/// Primary host packet filtering backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum FirewallKind {
    /// Ubuntu Uncomplicated Firewall (`ufw`).
    Ufw,
    /// Netfilter table packet filtering (`nftables`).
    Nftables,
    /// Legacy IP packet filter administration (`iptables`).
    Iptables,
    /// No supported firewall tool detected.
    #[default]
    None,
}

/// Definitive determination of host firewall enforcement state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum FirewallStatus {
    /// Packet filtering rules are actively enforced.
    Active,
    /// Host packet filtering is confirmed inactive or ruleset is empty.
    #[default]
    Inactive,
    /// Firewall state cannot be reliably determined (e.g. unprivileged user permissions).
    Inconclusive,
}

/// Host firewall state and configuration details.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallInfo {
    /// Primary active firewall system.
    pub kind: FirewallKind,
    /// Evaluated inspection status.
    pub status: FirewallStatus,
    /// Whether packet filtering rules are actively enforced.
    pub is_active: bool,
    /// Diagnostic summary or status output excerpt.
    pub details: String,
}

impl Default for FirewallInfo {
    fn default() -> Self {
        Self {
            kind: FirewallKind::None,
            status: FirewallStatus::Inactive,
            is_active: false,
            details: "No active firewall detected".into(),
        }
    }
}

impl FirewallInfo {
    /// Inspects host firewall state across all supported backends.
    pub fn collect<CR: CommandRunner>(runner: &CR) -> Self {
        let mut permission_denied = false;

        // 1. Try ufw status
        match runner.run("ufw", &["status"]) {
            Ok(output) => {
                if output.to_lowercase().contains("status: active") {
                    return Self {
                        kind: FirewallKind::Ufw,
                        status: FirewallStatus::Active,
                        is_active: true,
                        details: output.lines().take(3).collect::<Vec<_>>().join(" "),
                    };
                }
            }
            Err(e) => {
                let s = e.to_string().to_lowercase();
                if s.contains("root") || s.contains("permission") || s.contains("not permitted") {
                    permission_denied = true;
                }
            }
        }

        // 2. Try nft list ruleset
        match runner.run("nft", &["list", "ruleset"]) {
            Ok(output) => {
                let has_filtering = output.contains("policy drop")
                    || output.contains("drop")
                    || output.contains("reject");
                if has_filtering {
                    return Self {
                        kind: FirewallKind::Nftables,
                        status: FirewallStatus::Active,
                        is_active: true,
                        details: "nftables ruleset present".into(),
                    };
                }
            }
            Err(e) => {
                let s = e.to_string().to_lowercase();
                if s.contains("permission")
                    || s.contains("not permitted")
                    || s.contains("operation not supported")
                {
                    permission_denied = true;
                }
            }
        }

        // 3. Try iptables -L -n
        match runner.run("iptables", &["-L", "-n"]) {
            Ok(output) => {
                let is_filtering = output.contains("Chain INPUT")
                    && !output.contains("Chain INPUT (policy ACCEPT)");
                if is_filtering {
                    return Self {
                        kind: FirewallKind::Iptables,
                        status: FirewallStatus::Active,
                        is_active: true,
                        details: "iptables configured with active filtering".into(),
                    };
                }
            }
            Err(e) => {
                let s = e.to_string().to_lowercase();
                if s.contains("permission") || s.contains("not permitted") {
                    permission_denied = true;
                }
            }
        }

        // If no active backend was confirmed, distinguish between inconclusive and inactive
        if permission_denied {
            Self {
                kind: FirewallKind::None,
                status: FirewallStatus::Inconclusive,
                is_active: false,
                details: "Firewall inspection requires superuser privileges".into(),
            }
        } else {
            Self {
                kind: FirewallKind::None,
                status: FirewallStatus::Inactive,
                is_active: false,
                details: "No active firewall detected".into(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::EngineError;

    struct MockCommandRunner {
        program: &'static str,
        output: &'static str,
        success: bool,
    }

    impl CommandRunner for MockCommandRunner {
        fn run(&self, program: &str, _args: &[&str]) -> Result<String, EngineError> {
            if self.success && program == self.program {
                Ok(self.output.to_string())
            } else {
                Err(EngineError::CommandExecution("command not found".into()))
            }
        }
    }

    #[test]
    fn test_ufw_active_detection() {
        let runner = MockCommandRunner {
            program: "ufw",
            output: "Status: active\nLogging: on (low)\nDefault: deny (incoming)",
            success: true,
        };

        let fw = FirewallInfo::collect(&runner);
        assert_eq!(fw.kind, FirewallKind::Ufw);
        assert!(fw.is_active);
    }

    #[test]
    fn test_ufw_inactive_detection() {
        let runner = MockCommandRunner {
            program: "ufw",
            output: "Status: inactive\n",
            success: true,
        };

        let fw = FirewallInfo::collect(&runner);
        assert_eq!(fw.status, FirewallStatus::Inactive);
        assert!(!fw.is_active);
    }

    #[test]
    fn test_unprivileged_firewall_is_inconclusive() {
        struct UnprivilegedRunner;
        impl CommandRunner for UnprivilegedRunner {
            fn run(&self, _program: &str, _args: &[&str]) -> Result<String, EngineError> {
                Err(EngineError::CommandExecution(
                    "nft: Operation not permitted".into(),
                ))
            }
        }

        let fw = FirewallInfo::collect(&UnprivilegedRunner);
        assert_eq!(fw.status, FirewallStatus::Inconclusive);
        assert!(!fw.is_active);
    }
}
