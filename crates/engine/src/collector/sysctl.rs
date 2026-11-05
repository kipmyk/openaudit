//! Sysctl kernel parameter collector reading selected `/proc/sys/` entries.
//!
//! All reads are strictly read-only. No sysctl parameters are written.
//! Values are read as plain text files via the [`FileSystem`] abstraction,
//! enabling hermetic testing without touching real kernel parameters.

use crate::collector::FileSystem;
use serde::{Deserialize, Serialize};

/// Collected kernel hardening parameter values from `/proc/sys/`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SysctlInfo {
    /// `kernel.dmesg_restrict` — 0 = world-readable dmesg, 1 = root-only.
    pub dmesg_restrict: Option<u32>,
    /// `net.ipv4.ip_forward` — 0 = disabled, 1 = enabled (routing/NAT).
    pub ip_forward: Option<u32>,
    /// `kernel.randomize_va_space` — 0 = ASLR disabled, 1 = conservative, 2 = full.
    pub randomize_va_space: Option<u32>,
}

impl SysctlInfo {
    /// Collects selected kernel hardening parameters from `/proc/sys/`.
    ///
    /// Individual read failures are silently skipped — the corresponding field
    /// is set to `None`, which the rule evaluator treats as "unknown".
    #[must_use]
    pub fn collect<FS: FileSystem>(fs: &FS) -> Self {
        Self {
            dmesg_restrict: read_u32(fs, "/proc/sys/kernel/dmesg_restrict"),
            ip_forward: read_u32(fs, "/proc/sys/net/ipv4/ip_forward"),
            randomize_va_space: read_u32(fs, "/proc/sys/kernel/randomize_va_space"),
        }
    }
}

/// Reads a single-line unsigned integer from a `/proc/sys/` path.
fn read_u32<FS: FileSystem>(fs: &FS, path: &str) -> Option<u32> {
    fs.read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::EngineError;

    struct MockSysctlFs {
        dmesg: &'static str,
        ip_forward: &'static str,
        aslr: &'static str,
    }

    impl FileSystem for MockSysctlFs {
        fn read_to_string(&self, path: &str) -> Result<String, EngineError> {
            match path {
                "/proc/sys/kernel/dmesg_restrict" => Ok(self.dmesg.to_string()),
                "/proc/sys/net/ipv4/ip_forward" => Ok(self.ip_forward.to_string()),
                "/proc/sys/kernel/randomize_va_space" => Ok(self.aslr.to_string()),
                _ => Err(EngineError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "not found",
                ))),
            }
        }
        fn exists(&self, _: &str) -> bool {
            true
        }
        fn file_mode(&self, _: &str) -> Result<u32, EngineError> {
            Ok(0o644)
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
    fn test_sysctl_hardened() {
        let fs = MockSysctlFs {
            dmesg: "1\n",
            ip_forward: "0\n",
            aslr: "2\n",
        };
        let info = SysctlInfo::collect(&fs);
        assert_eq!(info.dmesg_restrict, Some(1));
        assert_eq!(info.ip_forward, Some(0));
        assert_eq!(info.randomize_va_space, Some(2));
    }

    #[test]
    fn test_sysctl_insecure() {
        let fs = MockSysctlFs {
            dmesg: "0\n",
            ip_forward: "1\n",
            aslr: "0\n",
        };
        let info = SysctlInfo::collect(&fs);
        assert_eq!(info.dmesg_restrict, Some(0));
        assert_eq!(info.ip_forward, Some(1));
        assert_eq!(info.randomize_va_space, Some(0));
    }

    #[test]
    fn test_sysctl_missing_fields_are_none() {
        struct AbsentFs;
        impl FileSystem for AbsentFs {
            fn read_to_string(&self, _: &str) -> Result<String, EngineError> {
                Err(EngineError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "absent",
                )))
            }
            fn exists(&self, _: &str) -> bool {
                false
            }
            fn file_mode(&self, _: &str) -> Result<u32, EngineError> {
                Ok(0)
            }
            fn read_dir(&self, _: &str) -> Result<Vec<String>, EngineError> {
                Ok(Vec::new())
            }
            fn read_link(&self, _: &str) -> Result<String, EngineError> {
                Err(EngineError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "absent",
                )))
            }
        }
        let info = SysctlInfo::collect(&AbsentFs);
        assert_eq!(info.dmesg_restrict, None);
        assert_eq!(info.ip_forward, None);
        assert_eq!(info.randomize_va_space, None);
    }
}

