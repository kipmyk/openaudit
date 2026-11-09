//! Authorized target scope and SSRF-safe destination policy evaluation.
//!
//! Enforces explicit, CIDR-based authorization for private enterprise networks,
//! separate controls for loopback and link-local destinations, and unconditional
//! defense against cloud metadata endpoints (even if overlapping CIDRs are provided).

use crate::error::NetworkError;
use std::collections::HashSet;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Comprehensive classification of an IP address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpClassification {
    /// Routable public internet address.
    Public,
    /// RFC 1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) or IPv6 ULA (fc00::/7).
    PrivateRfc1918,
    /// Loopback address (127.0.0.0/8 or ::1).
    Loopback,
    /// Non-metadata link-local address (169.254.0.0/16 or fe80::/10).
    LinkLocal,
    /// Cloud instance metadata endpoint (169.254.169.254, [fd00:ec2::254]).
    CloudMetadata,
    /// Reserved or special-use address (CGNAT 100.64.0.0/10, documentation RFC 5737, multicast, broadcast).
    SpecialUseOrReserved,
}

/// An explicitly parsed and normalized IP CIDR block (IPv4 or IPv6).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IpCidr {
    /// IPv4 CIDR block with prefix length 0..=32.
    V4 { network: Ipv4Addr, prefix_len: u8 },
    /// IPv6 CIDR block with prefix length 0..=128.
    V6 { network: Ipv6Addr, prefix_len: u8 },
}

impl IpCidr {
    /// Parses and normalizes a CIDR string (e.g. `10.20.0.0/16`, `192.168.1.0/24`, `fd12:3456::/64`).
    ///
    /// Clears any host bits outside the prefix length to ensure canonical network masking.
    pub fn parse(input: &str) -> Result<Self, NetworkError> {
        let trimmed = input.trim();
        let (ip_str, prefix_str) = trimmed.split_once('/').ok_or_else(|| {
            NetworkError::TargetParse(format!(
                "Malformed CIDR '{trimmed}': missing '/' prefix separator (e.g. 10.20.0.0/16)"
            ))
        })?;

        if let Ok(ipv4) = ip_str.parse::<Ipv4Addr>() {
            let prefix_len = prefix_str.parse::<u8>().map_err(|_| {
                NetworkError::TargetParse(format!("Invalid CIDR prefix length: '{prefix_str}'"))
            })?;
            if prefix_len > 32 {
                return Err(NetworkError::TargetParse(format!(
                    "IPv4 CIDR prefix /{prefix_len} exceeds maximum /32"
                )));
            }

            let mask = if prefix_len == 0 {
                0u32
            } else {
                !((1u32 << (32 - prefix_len)) - 1)
            };
            let net_u32 = u32::from(ipv4) & mask;
            let network = Ipv4Addr::from(net_u32);

            Ok(Self::V4 {
                network,
                prefix_len,
            })
        } else if let Ok(ipv6) = ip_str.parse::<Ipv6Addr>() {
            let prefix_len = prefix_str.parse::<u8>().map_err(|_| {
                NetworkError::TargetParse(format!("Invalid CIDR prefix length: '{prefix_str}'"))
            })?;
            if prefix_len > 128 {
                return Err(NetworkError::TargetParse(format!(
                    "IPv6 CIDR prefix /{prefix_len} exceeds maximum /128"
                )));
            }

            let mask = if prefix_len == 0 {
                0u128
            } else {
                !((1u128 << (128 - prefix_len)) - 1)
            };
            let net_u128 = u128::from(ipv6) & mask;
            let network = Ipv6Addr::from(net_u128);

            Ok(Self::V6 {
                network,
                prefix_len,
            })
        } else {
            Err(NetworkError::TargetParse(format!(
                "Malformed IP address in CIDR: '{ip_str}'"
            )))
        }
    }

    /// Evaluates whether an IP address is contained within this CIDR block.
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self, ip) {
            (
                Self::V4 {
                    network,
                    prefix_len,
                },
                IpAddr::V4(v4),
            ) => {
                let mask = if *prefix_len == 0 {
                    0u32
                } else {
                    !((1u32 << (32 - *prefix_len)) - 1)
                };
                (u32::from(v4) & mask) == (u32::from(*network) & mask)
            }
            (
                Self::V6 {
                    network,
                    prefix_len,
                },
                IpAddr::V6(v6),
            ) => {
                let mask = if *prefix_len == 0 {
                    0u128
                } else {
                    !((1u128 << (128 - *prefix_len)) - 1)
                };
                (u128::from(v6) & mask) == (u128::from(*network) & mask)
            }
            _ => false,
        }
    }
}

impl fmt::Display for IpCidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V4 {
                network,
                prefix_len,
            } => write!(f, "{network}/{prefix_len}"),
            Self::V6 {
                network,
                prefix_len,
            } => write!(f, "{network}/{prefix_len}"),
        }
    }
}

/// The policy decision for a destination IP under a declared target scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeDecision {
    /// Address is permitted under the declared scope.
    Allowed(IpClassification),
    /// Address violates the declared scope or SSRF protections.
    Prohibited {
        classification: IpClassification,
        reason: &'static str,
    },
}

/// Explicit configuration defining what network destinations an operator is authorized to assess.
#[derive(Debug, Clone)]
pub struct TargetScope {
    /// Allow routable public targets (default: true).
    pub allow_public: bool,
    /// Explicit authorized private CIDR ranges (RFC 1918 / IPv6 ULA).
    pub authorized_cidrs: Vec<IpCidr>,
    /// Allow loopback testing (default: false, requires deliberate --allow-loopback).
    pub allow_loopback: bool,
    /// Allow link-local assessment (default: false, requires deliberate --allow-link-local).
    pub allow_link_local: bool,
    /// Allow documentation and testnet ranges (RFC 5737: 192.0.2.0/24, etc.).
    pub allow_testnets: bool,
    /// Explicit authorized individual IP addresses.
    pub explicit_allowed_ips: HashSet<IpAddr>,
}

impl Default for TargetScope {
    fn default() -> Self {
        Self {
            allow_public: true,
            authorized_cidrs: Vec::new(),
            allow_loopback: false,
            allow_link_local: false,
            allow_testnets: false,
            explicit_allowed_ips: HashSet::new(),
        }
    }
}

impl TargetScope {
    /// Scope tailored for local lab testing with an authorized private CIDR.
    #[must_use]
    pub fn local_lab_with_cidr(cidr: IpCidr) -> Self {
        Self {
            allow_public: true,
            authorized_cidrs: vec![cidr],
            allow_loopback: true,
            allow_link_local: false,
            allow_testnets: true,
            explicit_allowed_ips: HashSet::new(),
        }
    }

    /// Authorizes an additional CIDR range.
    pub fn add_authorized_cidr(&mut self, cidr: IpCidr) {
        if !self.authorized_cidrs.contains(&cidr) {
            self.authorized_cidrs.push(cidr);
        }
    }

    /// Evaluates an IP address against this scope and returns a typed policy decision.
    pub fn evaluate(&self, ip: IpAddr) -> ScopeDecision {
        let classification = classify_ip(ip);

        // 1. Cloud Metadata is UNCONDITIONALLY PROHIBITED.
        // Even if an operator supplies 0.0.0.0/0 or 169.254.0.0/16, metadata is NEVER allowed.
        if classification == IpClassification::CloudMetadata {
            return ScopeDecision::Prohibited {
                classification,
                reason: "Destination is a Cloud Metadata Service (SSRF prohibited)",
            };
        }

        // 2. Check explicit individual IP whitelist
        if self.explicit_allowed_ips.contains(&ip) {
            return ScopeDecision::Allowed(classification);
        }

        // 3. Evaluate according to scope rules
        match classification {
            IpClassification::Public => {
                if self.allow_public {
                    ScopeDecision::Allowed(classification)
                } else {
                    ScopeDecision::Prohibited {
                        classification,
                        reason: "Public IP addresses outside declared scope",
                    }
                }
            }
            IpClassification::PrivateRfc1918 => {
                // Must fall within an explicitly authorized CIDR!
                if self.authorized_cidrs.iter().any(|c| c.contains(ip)) {
                    ScopeDecision::Allowed(classification)
                } else {
                    ScopeDecision::Prohibited {
                        classification,
                        reason: "Private RFC 1918 / ULA address outside explicitly authorized CIDR scope (--allow-cidr)",
                    }
                }
            }
            IpClassification::Loopback => {
                if self.allow_loopback {
                    ScopeDecision::Allowed(classification)
                } else {
                    ScopeDecision::Prohibited {
                        classification,
                        reason: "Loopback address requires deliberate local-lab authorization (--allow-loopback)",
                    }
                }
            }
            IpClassification::LinkLocal => {
                if self.allow_link_local {
                    ScopeDecision::Allowed(classification)
                } else {
                    ScopeDecision::Prohibited {
                        classification,
                        reason: "Link-local address requires explicit authorization (--allow-link-local)",
                    }
                }
            }
            IpClassification::SpecialUseOrReserved => {
                if self.allow_testnets && is_documentation_testnet(ip) {
                    ScopeDecision::Allowed(classification)
                } else {
                    ScopeDecision::Prohibited {
                        classification,
                        reason: "Special-use, multicast, or reserved address not permitted for perimeter scanning",
                    }
                }
            }
            IpClassification::CloudMetadata => unreachable!(),
        }
    }

    /// Validates an address and returns `Ok(classification)` or `Err(NetworkError)`.
    pub fn validate_destination(&self, ip: IpAddr) -> Result<IpClassification, NetworkError> {
        match self.evaluate(ip) {
            ScopeDecision::Allowed(cls) => Ok(cls),
            ScopeDecision::Prohibited {
                classification: _,
                reason,
            } => Err(NetworkError::SsrfViolation(format!("{ip}: {reason}"))),
        }
    }
}

/// Classifies any IPv4 or IPv6 address according to standards and security boundaries.
#[must_use]
pub fn classify_ip(ip: IpAddr) -> IpClassification {
    match ip {
        IpAddr::V4(v4) => classify_ipv4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                classify_ipv4(v4)
            } else {
                classify_ipv6(v6)
            }
        }
    }
}

fn classify_ipv4(ip: Ipv4Addr) -> IpClassification {
    let octets = ip.octets();

    // 1. Cloud metadata: 169.254.169.254
    if octets == [169, 254, 169, 254] {
        return IpClassification::CloudMetadata;
    }

    // 2. Loopback: 127.0.0.0/8
    if octets[0] == 127 {
        return IpClassification::Loopback;
    }

    // 3. Link-local: 169.254.0.0/16
    if octets[0] == 169 && octets[1] == 254 {
        return IpClassification::LinkLocal;
    }

    // 4. RFC 1918 Private ranges:
    if octets[0] == 10
        || (octets[0] == 172 && (16..=31).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 168)
    {
        return IpClassification::PrivateRfc1918;
    }

    // 5. Special-use or reserved:
    if octets[0] == 0
        || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
        || is_documentation_ipv4(octets)
        || (octets[0] == 198 && (18..=19).contains(&octets[1]))
        || octets[0] >= 224
    {
        return IpClassification::SpecialUseOrReserved;
    }

    IpClassification::Public
}

fn classify_ipv6(ip: Ipv6Addr) -> IpClassification {
    let segments = ip.segments();

    // 1. AWS IPv6 metadata: [fd00:ec2::254]
    if segments[0] == 0xfd00
        && segments[1] == 0xec2
        && segments[2] == 0
        && segments[3] == 0
        && segments[4] == 0
        && segments[5] == 0
        && segments[6] == 0
        && segments[7] == 0x0254
    {
        return IpClassification::CloudMetadata;
    }

    // 2. Loopback: ::1
    if ip.is_loopback() {
        return IpClassification::Loopback;
    }

    // 3. Link-local: fe80::/10 (fe80:: to febf::)
    if (segments[0] & 0xffc0) == 0xfe80 {
        return IpClassification::LinkLocal;
    }

    // 4. Unique Local Addresses (ULA): fc00::/7 (fc00:: to fdff::)
    if (segments[0] & 0xfe00) == 0xfc00 {
        return IpClassification::PrivateRfc1918;
    }

    // 5. Documentation (RFC 3849): 2001:db8::/32
    if segments[0] == 0x2001 && segments[1] == 0x0db8 {
        return IpClassification::SpecialUseOrReserved;
    }

    // 6. Multicast: ff00::/8
    if (segments[0] & 0xff00) == 0xff00 {
        return IpClassification::SpecialUseOrReserved;
    }

    // 7. Unspecified: ::
    if ip.is_unspecified() {
        return IpClassification::SpecialUseOrReserved;
    }

    IpClassification::Public
}

fn is_documentation_ipv4(octets: [u8; 4]) -> bool {
    (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
}

fn is_documentation_testnet(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_documentation_ipv4(v4.octets()),
        IpAddr::V6(v6) => {
            let segs = v6.segments();
            segs[0] == 0x2001 && segs[1] == 0x0db8
        }
    }
}
