//! DNS resolution and validation of all returned A/AAAA addresses.
//!
//! Guarantees:
//! - Validates EVERY returned address from DNS answers against `TargetScope`.
//! - Fails closed if ANY returned address is prohibited (prevents dual-homed SSRF bypass).
//! - Returns verified addresses to be pinned for subsequent TCP/TLS socket connections.

use crate::error::NetworkError;
use crate::pinned::PinnedTarget;
use crate::scope::TargetScope;
use crate::target::{CanonicalTarget, TargetType};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

/// Abstraction for DNS resolution to allow deterministic testing and mocking.
pub trait DnsResolver: Send + Sync {
    /// Resolves a hostname to a list of IP addresses.
    fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, NetworkError>;
}

/// System resolver backed by standard library libc / getaddrinfo.
#[derive(Debug, Default, Clone)]
pub struct SystemDnsResolver;

impl DnsResolver for SystemDnsResolver {
    fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, NetworkError> {
        let addrs: Vec<IpAddr> = format!("{host}:80")
            .to_socket_addrs()
            .map_err(|e| {
                NetworkError::DnsResolution(format!("DNS resolution failed for '{host}': {e}"))
            })?
            .map(|sa| sa.ip())
            .collect();

        if addrs.is_empty() {
            return Err(NetworkError::DnsResolution(format!(
                "No IP addresses returned for host '{host}'"
            )));
        }

        Ok(addrs)
    }
}

/// Mock resolver for unit tests and DNS rebinding simulations.
#[derive(Debug, Default, Clone)]
pub struct MockDnsResolver {
    records: std::collections::HashMap<String, Vec<IpAddr>>,
}

impl MockDnsResolver {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, host: &str, addrs: Vec<IpAddr>) {
        self.records.insert(host.to_ascii_lowercase(), addrs);
    }
}

impl DnsResolver for MockDnsResolver {
    fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, NetworkError> {
        let key = host.to_ascii_lowercase();
        self.records
            .get(&key)
            .cloned()
            .ok_or_else(|| NetworkError::DnsResolution(format!("NXDOMAIN for mock host '{host}'")))
    }
}

/// Resolves, validates, and pins a target against an authorized scope.
///
/// 1. If target is already an IP address, validates it against `TargetScope` and pins it.
/// 2. If target is a hostname, resolves all A/AAAA records via `resolver`.
/// 3. Validates EVERY returned address. If ANY address is prohibited, fails closed.
/// 4. Pins the primary valid address with the default port for secure socket connection.
pub fn resolve_and_pin<R: DnsResolver>(
    target: &CanonicalTarget,
    scope: &TargetScope,
    resolver: &R,
    default_port: u16,
) -> Result<PinnedTarget, NetworkError> {
    let port = target.port.unwrap_or(default_port);

    match &target.target_type {
        TargetType::Ipv4(v4) => {
            let ip = IpAddr::V4(*v4);
            let classification = scope.validate_destination(ip)?;
            let pinned_addr = SocketAddr::new(ip, port);
            Ok(PinnedTarget {
                canonical_target: target.clone(),
                pinned_addr,
                sni_hostname: target.normalized_host.clone(),
                classification,
            })
        }
        TargetType::Ipv6(v6) => {
            let ip = IpAddr::V6(*v6);
            let classification = scope.validate_destination(ip)?;
            let pinned_addr = SocketAddr::new(ip, port);
            Ok(PinnedTarget {
                canonical_target: target.clone(),
                pinned_addr,
                sni_hostname: target.normalized_host.clone(),
                classification,
            })
        }
        TargetType::Hostname(host) => {
            // Resolve all A / AAAA records
            let addrs = resolver.resolve(host)?;

            // Validate EVERY returned address. If ANY is out of scope or prohibited, fail closed!
            let mut validated_classifications = Vec::with_capacity(addrs.len());
            for &addr in &addrs {
                let classification = scope.validate_destination(addr).map_err(|e| {
                    NetworkError::SsrfViolation(format!(
                        "Host '{host}' returned prohibited IP {addr}: {e}"
                    ))
                })?;
                validated_classifications.push(classification);
            }

            // Pin the first validated address
            let primary_ip = addrs[0];
            let primary_classification = validated_classifications[0];
            let pinned_addr = SocketAddr::new(primary_ip, port);

            Ok(PinnedTarget {
                canonical_target: target.clone(),
                pinned_addr,
                sni_hostname: host.clone(),
                classification: primary_classification,
            })
        }
    }
}
