//! Listening network ports collector parsing `/proc/net/tcp` and `/proc/net/tcp6`.

use crate::collector::FileSystem;
use crate::error::EngineError;
use serde::{Deserialize, Serialize};

/// Represents an active listening TCP socket on the host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListeningPort {
    /// Transport protocol (e.g., "tcp", "tcp6").
    pub protocol: String,
    /// Bound local IP address (e.g., "0.0.0.0", "127.0.0.1", "::").
    pub ip: String,
    /// Bound listening port.
    pub port: u16,
    /// Whether the port is bound to a wildcard interface ("0.0.0.0" or "::").
    pub is_wildcard: bool,
    /// Socket inode identifier.
    pub inode: u64,
    /// Associated process name parsed from `/proc/<pid>/comm`, if available.
    pub process_name: Option<String>,
}

impl ListeningPort {
    /// Collects all listening TCP sockets from `/proc/net/tcp` and `/proc/net/tcp6`.
    ///
    /// # Errors
    /// Returns an [`EngineError`] if reading `/proc/net/tcp` or parsing fails.
    pub fn collect<FS: FileSystem>(fs: &FS) -> Result<Vec<Self>, EngineError> {
        let mut ports = Vec::new();

        if fs.exists("/proc/net/tcp") {
            let content = fs.read_to_string("/proc/net/tcp")?;
            ports.extend(Self::parse_tcp(&content, false)?);
        }

        if fs.exists("/proc/net/tcp6") {
            let content = fs.read_to_string("/proc/net/tcp6")?;
            ports.extend(Self::parse_tcp(&content, true)?);
        }

        if fs.exists("/proc") {
            Self::correlate_processes(fs, &mut ports);
        }

        Ok(ports)
    }

    /// Correlates socket inodes with process names by scanning `/proc/<pid>/fd/*`.
    fn correlate_processes<FS: FileSystem>(fs: &FS, ports: &mut [Self]) {
        let Ok(entries) = fs.read_dir("/proc") else {
            return;
        };

        let mut inode_to_process = std::collections::HashMap::new();

        for entry in entries {
            let Some(dir_name) = entry.rsplit('/').next() else {
                continue;
            };

            if !dir_name.chars().all(|c| c.is_ascii_digit()) {
                continue;
            }

            let comm_path = format!("{entry}/comm");
            let Ok(comm) = fs.read_to_string(&comm_path) else {
                continue;
            };
            let proc_name = comm.trim().to_string();

            let fd_dir = format!("{entry}/fd");
            let Ok(fds) = fs.read_dir(&fd_dir) else {
                continue;
            };

            for fd in fds {
                if let Ok(target) = fs.read_link(&fd) {
                    if let Some(inode_str) = target
                        .strip_prefix("socket:[")
                        .and_then(|s| s.strip_suffix(']'))
                    {
                        if let Ok(inode) = inode_str.parse::<u64>() {
                            inode_to_process.insert(inode, proc_name.clone());
                        }
                    }
                }
            }
        }

        for port in ports {
            if let Some(proc_name) = inode_to_process.get(&port.inode) {
                port.process_name = Some(proc_name.clone());
            }
        }
    }

    /// Parses `/proc/net/tcp` or `/proc/net/tcp6` file contents.
    ///
    /// # Errors
    /// Returns an [`EngineError`] if parsing socket lines fails.
    pub fn parse_tcp(content: &str, is_ipv6: bool) -> Result<Vec<Self>, EngineError> {
        let mut list = Vec::new();

        for line in content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 10 {
                continue;
            }

            // fields[0] = sl, fields[1] = local_addr, fields[2] = rem_addr, fields[3] = st
            let addr_str = fields[1];
            let st = fields[3];

            // State 0A is TCP_LISTEN
            if st != "0A" {
                continue;
            }

            let inode = fields
                .get(9)
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);

            if let Some((hex_ip, hex_port)) = addr_str.split_once(':') {
                if let Ok(port) = u16::from_str_radix(hex_port, 16) {
                    let (ip, is_wildcard) = if is_ipv6 {
                        parse_hex_ipv6(hex_ip)
                    } else {
                        parse_hex_ipv4(hex_ip)
                    };

                    list.push(Self {
                        protocol: if is_ipv6 { "tcp6".into() } else { "tcp".into() },
                        ip,
                        port,
                        is_wildcard,
                        inode,
                        process_name: None,
                    });
                }
            }
        }

        Ok(list)
    }
}

/// Parses 8-character little-endian hexadecimal IPv4 address into dotted-decimal string.
fn parse_hex_ipv4(hex: &str) -> (String, bool) {
    if hex.len() != 8 {
        return (hex.to_string(), false);
    }

    u32::from_str_radix(hex, 16).map_or_else(
        |_| (hex.to_string(), false),
        |num| {
            // Linux /proc/net/tcp stores in host byte order (little endian on x86/arm)
            let bytes = num.to_le_bytes();
            let ip = format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]);
            let is_wildcard = ip == "0.0.0.0";
            (ip, is_wildcard)
        },
    )
}

/// Parses 32-character hexadecimal IPv6 address.
fn parse_hex_ipv6(hex: &str) -> (String, bool) {
    if hex == "00000000000000000000000000000000" {
        ("::".to_string(), true)
    } else if hex == "00000000000000000000000001000000" {
        ("::1".to_string(), false)
    } else {
        (hex.to_string(), false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_proc_net_tcp() {
        let sample = r"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 48291 1 0000000000000000 100 0 0 10 0
   1: 0100007F:1538 00000000:0000 0A 00000000:00000000 00:00000000 00000000   100        0 51920 1 0000000000000000 100 0 0 10 0
   2: 0100007F:1538 0100007F:DE8A 01 00000000:00000000 00:00000000 00000000   100        0 52001 1 0000000000000000 100 0 0 10 0
";
        let ports = ListeningPort::parse_tcp(sample, false).expect("valid parse");
        assert_eq!(ports.len(), 2);

        // First port is 0.0.0.0:22 (SSH listening on wildcard)
        assert_eq!(ports[0].protocol, "tcp");
        assert_eq!(ports[0].ip, "0.0.0.0");
        assert_eq!(ports[0].port, 22);
        assert!(ports[0].is_wildcard);
        assert_eq!(ports[0].inode, 48291);

        // Second port is 127.0.0.1:5432 (Postgres on localhost)
        assert_eq!(ports[1].protocol, "tcp");
        assert_eq!(ports[1].ip, "127.0.0.1");
        assert_eq!(ports[1].port, 5432);
        assert!(!ports[1].is_wildcard);
        assert_eq!(ports[1].inode, 51920);
    }
}
