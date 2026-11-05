//! SSH daemon configuration collector and parser.

use crate::collector::FileSystem;
use crate::error::EngineError;
use serde::{Deserialize, Serialize};

/// Parsed SSH daemon configuration parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SshConfig {
    /// Value of `PermitRootLogin` (e.g., "yes", "no", "prohibit-password", "without-password").
    pub permit_root_login: Option<String>,
    /// Value of `PasswordAuthentication` (true for "yes", false for "no").
    pub password_authentication: Option<bool>,
    /// Value of `PubkeyAuthentication` (true for "yes", false for "no").
    pub pubkey_authentication: Option<bool>,
    /// Value of `X11Forwarding` (true for "yes", false for "no").
    pub x11_forwarding: Option<bool>,
    /// Value of `MaxAuthTries`.
    pub max_auth_tries: Option<u32>,
    /// Listening SSH port (default typically 22).
    pub port: Option<u16>,
    /// Relevant configuration lines for evidence attachment.
    pub raw_excerpt: String,
}

impl SshConfig {
    /// Collects and parses `/etc/ssh/sshd_config`.
    ///
    /// # Errors
    /// Returns an [`EngineError`] if reading `/etc/ssh/sshd_config` fails.
    pub fn collect<FS: FileSystem>(fs: &FS) -> Result<Self, EngineError> {
        let path = "/etc/ssh/sshd_config";
        if !fs.exists(path) {
            return Ok(Self::default());
        }

        let content = fs.read_to_string(path)?;
        Self::parse(&content)
    }

    /// Parses sshd_config text into structured `SshConfig`.
    ///
    /// # Errors
    /// This function is infallible currently, returning `Ok(Self)`.
    pub fn parse(content: &str) -> Result<Self, EngineError> {
        let mut config = Self::default();
        let mut excerpt_lines = Vec::new();

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            // sshd_config directives are whitespace-separated or equal-sign separated
            let parts: Vec<&str> = if let Some((k, v)) = trimmed.split_once('=') {
                vec![k.trim(), v.trim()]
            } else {
                trimmed.split_whitespace().collect()
            };

            if parts.len() < 2 {
                continue;
            }

            let key = parts[0].to_lowercase();
            let val = parts[1];

            match key.as_str() {
                "permitrootlogin" => {
                    config.permit_root_login = Some(val.to_lowercase());
                    excerpt_lines.push(format!("PermitRootLogin {val}"));
                }
                "passwordauthentication" => {
                    let is_yes = val.eq_ignore_ascii_case("yes");
                    config.password_authentication = Some(is_yes);
                    excerpt_lines.push(format!("PasswordAuthentication {val}"));
                }
                "pubkeyauthentication" => {
                    let is_yes = val.eq_ignore_ascii_case("yes");
                    config.pubkey_authentication = Some(is_yes);
                    excerpt_lines.push(format!("PubkeyAuthentication {val}"));
                }
                "x11forwarding" => {
                    let is_yes = val.eq_ignore_ascii_case("yes");
                    config.x11_forwarding = Some(is_yes);
                    excerpt_lines.push(format!("X11Forwarding {val}"));
                }
                "maxauthtries" => {
                    if let Ok(num) = val.parse::<u32>() {
                        config.max_auth_tries = Some(num);
                        excerpt_lines.push(format!("MaxAuthTries {val}"));
                    }
                }
                "port" => {
                    if let Ok(num) = val.parse::<u16>() {
                        config.port = Some(num);
                        excerpt_lines.push(format!("Port {val}"));
                    }
                }
                _ => {}
            }
        }

        config.raw_excerpt = excerpt_lines.join("\n");
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sshd_config() {
        let sample = r"
# Package generated configuration file
Port 2222
Protocol 2
PermitRootLogin yes
PasswordAuthentication yes
X11Forwarding no
MaxAuthTries 4
";
        let config = SshConfig::parse(sample).expect("valid parse");
        assert_eq!(config.port, Some(2222));
        assert_eq!(config.permit_root_login.as_deref(), Some("yes"));
        assert_eq!(config.password_authentication, Some(true));
        assert_eq!(config.x11_forwarding, Some(false));
        assert_eq!(config.max_auth_tries, Some(4));
        assert!(config.raw_excerpt.contains("PermitRootLogin yes"));
    }

    #[test]
    fn test_parse_empty_and_commented_config() {
        let sample = "# All comments\n# PermitRootLogin no\n";
        let config = SshConfig::parse(sample).expect("valid parse");
        assert_eq!(config.permit_root_login, None);
        assert!(config.raw_excerpt.is_empty());
    }
}
