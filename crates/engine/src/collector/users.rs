//! User accounts collector and `/etc/passwd` parser.

use crate::collector::FileSystem;
use crate::error::EngineError;
use serde::{Deserialize, Serialize};

/// Represents an account entry parsed from `/etc/passwd`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserAccount {
    /// Username or login name.
    pub username: String,
    /// User ID number.
    pub uid: u32,
    /// Group ID number.
    pub gid: u32,
    /// User description / GECOS field.
    pub comment: String,
    /// User home directory.
    pub home: String,
    /// Login shell.
    pub shell: String,
}

/// Aggregated user account telemetry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct UsersInfo {
    /// All parsed user accounts.
    pub accounts: Vec<UserAccount>,
    /// Accounts discovered with empty password hashes in /etc/shadow.
    pub empty_password_accounts: Vec<String>,
}

impl UsersInfo {
    /// Collects user accounts from `/etc/passwd` and `/etc/shadow`.
    ///
    /// # Errors
    /// Returns an [`EngineError`] if reading `/etc/passwd` fails.
    pub fn collect<FS: FileSystem>(fs: &FS) -> Result<Self, EngineError> {
        let mut info = if fs.exists("/etc/passwd") {
            let content = fs.read_to_string("/etc/passwd")?;
            Self::parse(&content)?
        } else {
            Self::default()
        };

        if fs.exists("/etc/shadow") {
            if let Ok(shadow_content) = fs.read_to_string("/etc/shadow") {
                info.empty_password_accounts = Self::parse_shadow_empty_passwords(&shadow_content);
            }
        }

        Ok(info)
    }

    /// Extracts usernames with empty password hash entries in `/etc/shadow`.
    #[must_use]
    pub fn parse_shadow_empty_passwords(content: &str) -> Vec<String> {
        let mut bad = Vec::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 2 {
                let username = parts[0];
                let hash = parts[1];
                if hash.is_empty() {
                    bad.push(username.to_string());
                }
            }
        }
        bad
    }

    /// Parses `/etc/passwd` formatted text.
    ///
    /// # Errors
    /// This function is currently infallible, returning `Ok(Self)`.
    pub fn parse(content: &str) -> Result<Self, EngineError> {
        let mut accounts = Vec::new();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() < 7 {
                continue;
            }

            let Ok(uid) = parts[2].parse::<u32>() else {
                continue;
            };

            let Ok(gid) = parts[3].parse::<u32>() else {
                continue;
            };

            accounts.push(UserAccount {
                username: parts[0].to_string(),
                uid,
                gid,
                comment: parts[4].to_string(),
                home: parts[5].to_string(),
                shell: parts[6].to_string(),
            });
        }

        Ok(Self {
            accounts,
            empty_password_accounts: Vec::new(),
        })
    }

    /// Returns all accounts possessing UID 0 (root privileges).
    #[must_use]
    pub fn root_uid_accounts(&self) -> Vec<&UserAccount> {
        self.accounts.iter().filter(|u| u.uid == 0).collect()
    }

    /// Returns interactive human accounts (UID >= 1000 with a valid login shell).
    #[must_use]
    pub fn interactive_accounts(&self) -> Vec<&UserAccount> {
        self.accounts
            .iter()
            .filter(|u| {
                u.uid >= 1000
                    && !u.shell.ends_with("nologin")
                    && !u.shell.ends_with("false")
                    && !u.shell.is_empty()
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_passwd_and_detect_backdoor_root() {
        let sample = r"
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
toor:x:0:0:backdoor:/root:/bin/bash
alice:x:1000:1000:Alice Admin:/home/alice:/bin/bash
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
";
        let users = UsersInfo::parse(sample).expect("valid parse");
        assert_eq!(users.accounts.len(), 5);

        let root_accounts = users.root_uid_accounts();
        assert_eq!(root_accounts.len(), 2);
        assert_eq!(root_accounts[0].username, "root");
        assert_eq!(root_accounts[1].username, "toor");

        let interactive = users.interactive_accounts();
        assert_eq!(interactive.len(), 1);
        assert_eq!(interactive[0].username, "alice");
    }
}
