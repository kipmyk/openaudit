//! Host firewall configuration and status collector.

use crate::collector::CommandRunner;
use serde::{Deserialize, Serialize};

/// Type of firewall system detected on the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FirewallKind {
    /// Ubuntu Uncomplicated Firewall (`ufw`).
    Ufw,
    /// Netfilter table packet filtering (`nftables`).
    Nftables,
    /// Legacy IP packet filter administration (`iptables`).
    Iptables,
    /// No supported firewall tool detected.
    None,
}

/// Host firewall state and configuration details.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallInfo {
    /// Primary active firewall system.
    pub kind: FirewallKind,
    /// Whether packet filtering rules are actively enforced.
    pub is_active: bool,
    /// Diagnostic summary or status output excerpt.
    pub details: String,
}

impl Default for FirewallInfo {
    fn default() -> Self {
        Self {
            kind: FirewallKind::None,
            is_active: false,
            details: "No active firewall detected".into(),
        }
    }
}

impl FirewallInfo {
    /// Inspects host firewall state using the provided command runner.
    pub fn collect<CR: CommandRunner>(runner: &CR) -> Self {
        // 1. Try ufw status
        if let Ok(output) = runner.run("ufw", &["status"]) {
            let is_active = output.to_lowercase().contains("status: active");
            return Self {
                kind: FirewallKind::Ufw,
                is_active,
                details: output.lines().take(3).collect::<Vec<_>>().join(" "),
            };
        }

        // 2. Try nft list ruleset
        if let Ok(output) = runner.run("nft", &["list", "ruleset"]) {
            let is_active = !output.trim().is_empty();
            return Self {
                kind: FirewallKind::Nftables,
                is_active,
                details: if is_active {
                    "nftables ruleset present".into()
                } else {
                    "nftables ruleset empty".into()
                },
            };
        }

        // 3. Try iptables -L -n
        if let Ok(output) = runner.run("iptables", &["-L", "-n"]) {
            let is_active =
                output.contains("Chain INPUT") && !output.contains("Chain INPUT (policy ACCEPT)");
            return Self {
                kind: FirewallKind::Iptables,
                is_active,
                details: "iptables configured".into(),
            };
        }

        Self::default()
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
        assert_eq!(fw.kind, FirewallKind::Ufw);
        assert!(!fw.is_active);
    }
}
