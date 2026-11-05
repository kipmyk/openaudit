//! SUID and SGID binary scanner inspecting standard system directories.

use crate::collector::FileSystem;
use serde::{Deserialize, Serialize};

/// Standard directories inspected for SUID/SGID binaries.
pub const SUID_SCAN_DIRS: &[&str] = &[
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
    "/tmp",
    "/var/tmp",
];

/// Information about a detected SUID or SGID executable file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuidBinaryInfo {
    /// Full path to the binary.
    pub path: String,
    /// Unix permission mode.
    pub mode: u32,
    /// Has SUID bit (mode & 0o4000 != 0).
    pub is_suid: bool,
    /// Has SGID bit (mode & 0o2000 != 0).
    pub is_sgid: bool,
}

/// SUID/SGID collector scanning known directories.
#[derive(Debug, Default, Clone, Copy)]
pub struct SuidBinaryCollector;

impl SuidBinaryCollector {
    /// Scans standard executable directories for SUID or SGID binaries.
    #[allow(clippy::similar_names)]
    #[must_use]
    pub fn collect<FS: FileSystem>(fs: &FS) -> Vec<SuidBinaryInfo> {
        let mut results = Vec::new();
        for &dir in SUID_SCAN_DIRS {
            if !fs.exists(dir) {
                continue;
            }
            if let Ok(entries) = fs.read_dir(dir) {
                for entry in entries {
                    if let Ok(mode) = fs.file_mode(&entry) {
                        let is_suid = (mode & 0o4000) != 0;
                        let is_sgid = (mode & 0o2000) != 0;
                        if is_suid || is_sgid {
                            results.push(SuidBinaryInfo {
                                path: entry,
                                mode,
                                is_suid,
                                is_sgid,
                            });
                        }
                    }
                }
            }
        }
        results.sort_by(|a, b| a.path.cmp(&b.path));
        results.dedup_by(|a, b| a.path == b.path);
        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::EngineError;

    struct MockSuidFs;
    impl FileSystem for MockSuidFs {
        fn read_to_string(&self, _: &str) -> Result<String, EngineError> {
            Ok(String::new())
        }
        fn exists(&self, path: &str) -> bool {
            path == "/usr/bin" || path == "/tmp"
        }
        fn file_mode(&self, path: &str) -> Result<u32, EngineError> {
            match path {
                "/usr/bin/passwd" | "/tmp/setuid-bash" => Ok(0o4755),
                "/tmp/shadow-reader" => Ok(0o2755),
                _ => Ok(0o755),
            }
        }
        fn read_dir(&self, path: &str) -> Result<Vec<String>, EngineError> {
            match path {
                "/usr/bin" => Ok(vec!["/usr/bin/passwd".into(), "/usr/bin/ls".into()]),
                "/tmp" => Ok(vec![
                    "/tmp/setuid-bash".into(),
                    "/tmp/shadow-reader".into(),
                    "/tmp/normal.txt".into(),
                ]),
                _ => Ok(Vec::new()),
            }
        }
        fn read_link(&self, _: &str) -> Result<String, EngineError> {
            Err(EngineError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "not found",
            )))
        }
    }

    #[test]
    fn test_suid_collector_finds_binaries() {
        let binaries = SuidBinaryCollector::collect(&MockSuidFs);
        assert_eq!(binaries.len(), 3);

        assert!(binaries
            .iter()
            .any(|b| b.is_suid && b.path == "/tmp/setuid-bash"));
        assert!(binaries
            .iter()
            .any(|b| b.is_suid && b.path == "/usr/bin/passwd"));
        assert!(binaries
            .iter()
            .any(|b| b.is_sgid && b.path == "/tmp/shadow-reader"));
    }
}
