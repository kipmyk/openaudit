//! Operating system metadata collector.

use crate::collector::FileSystem;
use crate::error::EngineError;
use serde::{Deserialize, Serialize};

/// Operating system identification and kernel metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsInfo {
    /// Distribution or OS identifier (e.g., "ubuntu", "debian", "alpine", "arch").
    pub id: String,
    /// OS release version (e.g., "24.04", "12").
    pub version_id: String,
    /// Human-friendly operating system name (e.g., "Ubuntu 24.04 LTS").
    pub pretty_name: String,
    /// Kernel release name/version (e.g., "6.8.0-45-generic").
    pub kernel_release: String,
    /// Host CPU architecture (e.g., "x86_64", "aarch64").
    pub architecture: String,
}

impl OsInfo {
    /// Collects operating system information using the provided filesystem abstraction.
    ///
    /// # Errors
    /// Returns an [`EngineError`] if reading `/etc/os-release` fails.
    pub fn collect<FS: FileSystem>(fs: &FS) -> Result<Self, EngineError> {
        let content = if fs.exists("/etc/os-release") {
            fs.read_to_string("/etc/os-release")?
        } else if fs.exists("/usr/lib/os-release") {
            fs.read_to_string("/usr/lib/os-release")?
        } else {
            // Fallback for non-Linux or bare systems
            String::new()
        };

        let mut id = String::new();
        let mut version_id = String::new();
        let mut pretty_name = String::new();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Some((k, v)) = line.split_once('=') {
                let key = k.trim();
                let val = v.trim().trim_matches('"').trim_matches('\'');
                match key {
                    "ID" => id = val.to_string(),
                    "VERSION_ID" => version_id = val.to_string(),
                    "PRETTY_NAME" => pretty_name = val.to_string(),
                    _ => {}
                }
            }
        }

        if id.is_empty() {
            id = std::env::consts::OS.to_string();
        }
        if pretty_name.is_empty() {
            pretty_name.clone_from(&id);
        }

        let architecture = std::env::consts::ARCH.to_string();

        let kernel_release = if fs.exists("/proc/version") {
            fs.read_to_string("/proc/version")
                .unwrap_or_else(|_| "unknown".to_string())
                .lines()
                .next()
                .unwrap_or("unknown")
                .trim()
                .to_string()
        } else {
            "unknown".to_string()
        };

        Ok(Self {
            id,
            version_id,
            pretty_name,
            kernel_release,
            architecture,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockOsFs {
        os_release: &'static str,
        proc_version: &'static str,
    }

    impl FileSystem for MockOsFs {
        fn read_to_string(&self, path: &str) -> Result<String, EngineError> {
            match path {
                "/etc/os-release" => Ok(self.os_release.to_string()),
                "/proc/version" => Ok(self.proc_version.to_string()),
                _ => Err(EngineError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "file not found",
                ))),
            }
        }

        fn exists(&self, path: &str) -> bool {
            path == "/etc/os-release" || path == "/proc/version"
        }

        fn file_mode(&self, _path: &str) -> Result<u32, EngineError> {
            Ok(0o644)
        }
    }

    #[test]
    fn test_parse_ubuntu_os_release() {
        let fs = MockOsFs {
            os_release: r#"
NAME="Ubuntu"
VERSION="24.04 LTS (Noble Numbat)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 24.04 LTS"
VERSION_ID="24.04"
"#,
            proc_version: "Linux version 6.8.0-45-generic (buildd@lcy02-amd64-074)",
        };

        let os_info = OsInfo::collect(&fs).expect("should parse os info");
        assert_eq!(os_info.id, "ubuntu");
        assert_eq!(os_info.version_id, "24.04");
        assert_eq!(os_info.pretty_name, "Ubuntu 24.04 LTS");
        assert_eq!(
            os_info.kernel_release,
            "Linux version 6.8.0-45-generic (buildd@lcy02-amd64-074)"
        );
    }
}
