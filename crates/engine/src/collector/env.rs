//! Environment variables collector inspecting security-sensitive variables like `PATH`.

use crate::collector::FileSystem;
use serde::{Deserialize, Serialize};

/// Represents an inspected directory entry in the `PATH` environment variable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathEntry {
    /// Directory path.
    pub path: String,
    /// Whether the directory exists on disk.
    pub exists: bool,
    /// Unix permission mode.
    pub mode: u32,
    /// Whether the directory is world-writable (mode & 0o002 != 0).
    pub is_world_writable: bool,
}

/// Aggregated environment telemetry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct EnvInfo {
    /// Inspected directories present in `PATH`.
    pub path_entries: Vec<PathEntry>,
}

impl EnvInfo {
    /// Collects and inspects `PATH` directories using the provided filesystem abstraction.
    #[must_use]
    pub fn collect<FS: FileSystem>(fs: &FS) -> Self {
        let path_var = std::env::var("PATH").unwrap_or_default();
        Self::parse_path_var(fs, &path_var)
    }

    /// Parses a PATH string delimited by `:` and inspects each directory component.
    #[must_use]
    pub fn parse_path_var<FS: FileSystem>(fs: &FS, path_var: &str) -> Self {
        let mut entries = Vec::new();
        for dir in path_var.split(':') {
            let dir = dir.trim();
            if dir.is_empty() {
                continue;
            }
            let exists = fs.exists(dir);
            let mode = if exists {
                fs.file_mode(dir).unwrap_or(0)
            } else {
                0
            };
            entries.push(PathEntry {
                path: dir.to_string(),
                exists,
                mode,
                is_world_writable: exists && (mode & 0o002 != 0),
            });
        }
        Self {
            path_entries: entries,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::EngineError;

    struct MockEnvFs {
        writable_path: &'static str,
    }

    impl FileSystem for MockEnvFs {
        fn read_to_string(&self, _: &str) -> Result<String, EngineError> {
            Ok(String::new())
        }
        fn exists(&self, path: &str) -> bool {
            path == "/bin" || path == "/usr/bin" || path == self.writable_path
        }
        fn file_mode(&self, path: &str) -> Result<u32, EngineError> {
            if path == self.writable_path {
                Ok(0o777)
            } else {
                Ok(0o755)
            }
        }
        fn read_dir(&self, _: &str) -> Result<Vec<String>, EngineError> {
            Ok(Vec::new())
        }
        fn read_link(&self, _: &str) -> Result<String, EngineError> {
            Err(EngineError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "not found",
            )))
        }
    }

    #[test]
    fn test_parse_path_var_detects_world_writable_dir() {
        let fs = MockEnvFs {
            writable_path: "/tmp/evil",
        };
        let env_info = EnvInfo::parse_path_var(&fs, "/bin:/tmp/evil:/usr/bin");
        assert_eq!(env_info.path_entries.len(), 3);
        assert!(!env_info.path_entries[0].is_world_writable);
        assert!(env_info.path_entries[1].is_world_writable);
        assert!(!env_info.path_entries[2].is_world_writable);
    }

    #[test]
    fn test_parse_path_var_hardened() {
        let fs = MockEnvFs {
            writable_path: "/nonexistent",
        };
        let env_info = EnvInfo::parse_path_var(&fs, "/bin:/usr/bin");
        assert_eq!(env_info.path_entries.len(), 2);
        assert!(!env_info.path_entries[0].is_world_writable);
        assert!(!env_info.path_entries[1].is_world_writable);
    }
}
