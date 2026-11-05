//! File permissions collector for security-critical system files.

use crate::collector::FileSystem;
use crate::error::EngineError;
use serde::{Deserialize, Serialize};

/// Target configuration files inspected for permission hygiene.
pub const CRITICAL_PATHS: &[&str] = &[
    "/etc/shadow",
    "/etc/passwd",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
];

/// Permission metadata for an inspected file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilePermissionInfo {
    /// Absolute path to the file.
    pub path: String,
    /// Whether the file exists on the filesystem.
    pub exists: bool,
    /// Unix permission mode in octal (e.g., 0o644).
    pub mode: u32,
    /// Whether the file is world-writable (mode & 0o002 != 0).
    pub is_world_writable: bool,
    /// Whether the file is world-readable (mode & 0o004 != 0).
    pub is_world_readable: bool,
}

impl FilePermissionInfo {
    /// Inspects the standard list of critical security files.
    ///
    /// # Errors
    /// Returns an [`EngineError`] if reading filesystem metadata fails.
    pub fn collect_critical<FS: FileSystem>(fs: &FS) -> Result<Vec<Self>, EngineError> {
        let mut results = Vec::new();

        for path in CRITICAL_PATHS {
            if fs.exists(path) {
                let mode = fs.file_mode(path).unwrap_or(0);
                results.push(Self {
                    path: (*path).to_string(),
                    exists: true,
                    mode,
                    is_world_writable: (mode & 0o002) != 0,
                    is_world_readable: (mode & 0o004) != 0,
                });
            }
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockPermFs {
        path: &'static str,
        mode: u32,
    }

    impl FileSystem for MockPermFs {
        fn read_to_string(&self, _path: &str) -> Result<String, EngineError> {
            Ok(String::new())
        }

        fn exists(&self, path: &str) -> bool {
            path == self.path
        }

        fn file_mode(&self, path: &str) -> Result<u32, EngineError> {
            if path == self.path {
                Ok(self.mode)
            } else {
                Err(EngineError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "not found",
                )))
            }
        }
    }

    #[test]
    fn test_world_writable_detection() {
        let fs = MockPermFs {
            path: "/etc/shadow",
            mode: 0o666, // world writable!
        };

        let perms = FilePermissionInfo::collect_critical(&fs).expect("collection succeeds");
        assert_eq!(perms.len(), 1);
        assert_eq!(perms[0].path, "/etc/shadow");
        assert!(perms[0].is_world_writable);
        assert!(perms[0].is_world_readable);
    }

    #[test]
    fn test_secure_permissions() {
        let fs = MockPermFs {
            path: "/etc/shadow",
            mode: 0o600, // secure
        };

        let perms = FilePermissionInfo::collect_critical(&fs).expect("collection succeeds");
        assert_eq!(perms.len(), 1);
        assert!(!perms[0].is_world_writable);
        assert!(!perms[0].is_world_readable);
    }
}
