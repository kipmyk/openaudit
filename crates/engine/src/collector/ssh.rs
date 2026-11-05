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
    /// Collects and parses `/etc/ssh/sshd_config`, recursively following `Include` directives.
    ///
    /// # Errors
    /// Returns an [`EngineError`] if reading `/etc/ssh/sshd_config` fails.
    pub fn collect<FS: FileSystem>(fs: &FS) -> Result<Self, EngineError> {
        let path = "/etc/ssh/sshd_config";
        if !fs.exists(path) {
            return Ok(Self::default());
        }

        let mut config = Self::default();
        let mut excerpt_lines = Vec::new();
        Self::parse_file(fs, path, &mut config, &mut excerpt_lines)?;
        config.raw_excerpt = excerpt_lines.join("\n");
        Ok(config)
    }

    /// Recursively parses an sshd configuration file.
    fn parse_file<FS: FileSystem>(
        fs: &FS,
        path: &str,
        config: &mut Self,
        excerpt_lines: &mut Vec<String>,
    ) -> Result<(), EngineError> {
        if !fs.exists(path) {
            return Ok(());
        }
        let content = fs.read_to_string(path)?;
        Self::parse_content(fs, &content, config, excerpt_lines);
        Ok(())
    }

    /// Parses sshd configuration lines adhering strictly to `OpenSSH` first-match semantics.
    fn parse_content<FS: FileSystem>(
        fs: &FS,
        content: &str,
        config: &mut Self,
        excerpt_lines: &mut Vec<String>,
    ) {
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
                "include" => {
                    // OpenSSH Include directive: handles drop-ins e.g. /etc/ssh/sshd_config.d/*.conf
                    let inc_pattern = val;
                    if let Some(dir) = inc_pattern.strip_suffix("/*.conf") {
                        if fs.exists(dir) {
                            if let Ok(entries) = fs.read_dir(dir) {
                                for entry in entries {
                                    if std::path::Path::new(&entry)
                                        .extension()
                                        .is_some_and(|ext| ext.eq_ignore_ascii_case("conf"))
                                    {
                                        let _ = Self::parse_file(fs, &entry, config, excerpt_lines);
                                    }
                                }
                            }
                        }
                    } else if fs.exists(inc_pattern) {
                        let _ = Self::parse_file(fs, inc_pattern, config, excerpt_lines);
                    }
                }
                "permitrootlogin" if config.permit_root_login.is_none() => {
                    // OpenSSH standard: for each directive, the first obtained value wins
                    config.permit_root_login = Some(val.to_lowercase());
                    excerpt_lines.push(format!("PermitRootLogin {val}"));
                }
                "passwordauthentication" if config.password_authentication.is_none() => {
                    // OpenSSH standard: for each directive, the first obtained value wins
                    let is_yes = val.eq_ignore_ascii_case("yes");
                    config.password_authentication = Some(is_yes);
                    excerpt_lines.push(format!("PasswordAuthentication {val}"));
                }
                "pubkeyauthentication" if config.pubkey_authentication.is_none() => {
                    let is_yes = val.eq_ignore_ascii_case("yes");
                    config.pubkey_authentication = Some(is_yes);
                    excerpt_lines.push(format!("PubkeyAuthentication {val}"));
                }
                "x11forwarding" if config.x11_forwarding.is_none() => {
                    let is_yes = val.eq_ignore_ascii_case("yes");
                    config.x11_forwarding = Some(is_yes);
                    excerpt_lines.push(format!("X11Forwarding {val}"));
                }
                "maxauthtries" if config.max_auth_tries.is_none() => {
                    if let Ok(num) = val.parse::<u32>() {
                        config.max_auth_tries = Some(num);
                        excerpt_lines.push(format!("MaxAuthTries {val}"));
                    }
                }
                "port" if config.port.is_none() => {
                    if let Ok(num) = val.parse::<u16>() {
                        config.port = Some(num);
                        excerpt_lines.push(format!("Port {val}"));
                    }
                }
                _ => {}
            }
        }
    }

    /// Parses standalone sshd_config text into structured `SshConfig` using first-match semantics.
    ///
    /// # Errors
    /// This function is infallible currently, returning `Ok(Self)`.
    pub fn parse(content: &str) -> Result<Self, EngineError> {
        let mut config = Self::default();
        let mut excerpt_lines = Vec::new();

        Self::parse_content(&NoopSshFs, content, &mut config, &mut excerpt_lines);
        config.raw_excerpt = excerpt_lines.join("\n");
        Ok(config)
    }
}

struct NoopSshFs;
impl FileSystem for NoopSshFs {
    fn read_to_string(&self, _path: &str) -> Result<String, EngineError> {
        Err(EngineError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "not found",
        )))
    }
    fn exists(&self, _path: &str) -> bool {
        false
    }
    fn file_mode(&self, _path: &str) -> Result<u32, EngineError> {
        Ok(0)
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
        assert_eq!(config.raw_excerpt, "");
    }

    #[test]
    fn test_ssh_first_match_semantics() {
        // In OpenSSH, first match wins
        let sample_first_yes = "PermitRootLogin yes\nPermitRootLogin no\n";
        let config1 = SshConfig::parse(sample_first_yes).expect("parse");
        assert_eq!(config1.permit_root_login.as_deref(), Some("yes"));

        let sample_first_no = "PermitRootLogin no\nPermitRootLogin yes\n";
        let config2 = SshConfig::parse(sample_first_no).expect("parse");
        assert_eq!(config2.permit_root_login.as_deref(), Some("no"));
    }

    #[test]
    fn test_ssh_include_dropin_resolution() {
        struct MockDropInFs;
        impl FileSystem for MockDropInFs {
            fn read_to_string(&self, path: &str) -> Result<String, EngineError> {
                match path {
                    "/etc/ssh/sshd_config" => {
                        Ok("Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin no\n".into())
                    }
                    "/etc/ssh/sshd_config.d/50-cloud.conf" => Ok("PermitRootLogin yes\n".into()),
                    _ => Err(EngineError::Io(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "not found",
                    ))),
                }
            }

            fn exists(&self, path: &str) -> bool {
                path == "/etc/ssh/sshd_config"
                    || path == "/etc/ssh/sshd_config.d"
                    || path == "/etc/ssh/sshd_config.d/50-cloud.conf"
            }

            fn file_mode(&self, _path: &str) -> Result<u32, EngineError> {
                Ok(0o644)
            }

            fn read_dir(&self, path: &str) -> Result<Vec<String>, EngineError> {
                if path == "/etc/ssh/sshd_config.d" {
                    Ok(vec!["/etc/ssh/sshd_config.d/50-cloud.conf".into()])
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

        let config = SshConfig::collect(&MockDropInFs).expect("collect with include");
        assert_eq!(
            config.permit_root_login.as_deref(),
            Some("yes"),
            "drop-in Included file should override later main config directive"
        );
    }
}
